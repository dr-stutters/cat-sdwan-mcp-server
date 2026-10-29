"""W62 #134 configuration-group lifecycle: catsdwan_create_config_group, catsdwan_delete_config_group.
catsdwan_associate_config_group (W21, tools/features.py) adds devices and catsdwan_deploy_config_group (W8)
pushes a group.

Tiers: create stores on the Manager only (write). Delete is write for a group with no devices; with
dissociate=true on a group that has devices it is dangerous (those devices stop being managed by any group).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    FromResult,
    NotFound,
    Plan,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configgroups import (
    GROUP_PROFILE_TYPES,
    copy_payload,
    deploy_pending,
    group_body,
    group_profiles,
    parcel_tree,
    parse_profile_ref,
    profile_body,
)
from cat_sdwan_mcp.configuration import (
    ASSOCIATE_PATH,
    CONFIG_GROUP_PATH,
    CONFIG_GROUPS_PATH,
    PROFILE_PATH,
    path,
    resolve_group,
)
from cat_sdwan_mcp.features import PARCEL_LIST_PATH, PARCEL_PATH, PROFILE_LIST_PATH, parcel_url
from cat_sdwan_mcp.policygroups import created_id, devices_body, name_problem
from cat_sdwan_mcp.tools.changes import _pending_blockers, dangerous_blockers
from cat_sdwan_mcp.tools.configuration import _associated, _groups
from cat_sdwan_mcp.tools.features import _group_profiles, _listed_profiles

GroupRef = Annotated[str, Field(description="Configuration group name or id (catsdwan_list_config_groups)")]


async def _group_detail(app: SdwanApp, found: dict[str, Any]) -> dict[str, Any]:
    """The group record with its profiles (the list read can leave them out)."""
    if group_profiles(found):
        return found
    try:
        detail = await app.api.get(path(CONFIG_GROUP_PATH, id=str(found.get("id"))))
    except (UpstreamError, NotFound):
        return found
    return detail if isinstance(detail, dict) and detail.get("profiles") else found


async def _profile_tree(app: SdwanApp, ptype: str, pid: str) -> list[dict[str, Any]]:
    return parcel_tree(await app.api.get(path(PROFILE_PATH, type=ptype, id=pid)))


async def _copy_parcels(app: SdwanApp, ptype: str, src: str, dst: str, tree: list[dict[str, Any]]) -> int:
    """Copy every parcel (and its subparcels) of profile `src` into `dst`; the number copied."""
    n = 0
    for p in tree:
        body = await app.api.get(
            parcel_url(PARCEL_PATH, ptype=ptype, parcel_type=p["type"], profile=src, parcel=p["id"])
        )
        answer = await app.api.post(
            parcel_url(PARCEL_LIST_PATH, ptype=ptype, parcel_type=p["type"], profile=dst), copy_payload(body)
        )
        n += 1
        new_parent = created_id(answer)
        for s in p["subparcels"]:
            if not new_parent:
                raise UpstreamError(
                    f"the copy of parcel {p['name']} returned no id, so its subparcels can't follow"
                )
            src_parent = parcel_url(
                PARCEL_PATH, ptype=ptype, parcel_type=p["type"], profile=src, parcel=p["id"]
            )
            dst_parent = parcel_url(
                PARCEL_PATH, ptype=ptype, parcel_type=p["type"], profile=dst, parcel=new_parent
            )
            sub = await app.api.get(f"{src_parent}/{s['type']}/{path('{id}', id=s['id'])}")
            await app.api.post(f"{dst_parent}/{s['type']}", copy_payload(sub))
            n += 1
    return n


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create SD-WAN configuration group")
    async def catsdwan_create_config_group(
        ctx: Context,
        name: Annotated[str, Field(description='New configuration group name (no spaces or & < > ! ")')],
        profiles: Annotated[
            dict[str, str] | None,
            Field(
                description="Feature profile per type (system, transport, service, cli): an existing "
                "profile's name or id, or 'new:<name>' for a new empty one. Overrides clone_from per type"
            ),
        ] = None,
        clone_from: Annotated[
            str | None,
            Field(
                description="Configuration group to copy: its profiles for every type `profiles` leaves out"
            ),
        ] = None,
        deep: Annotated[
            bool,
            Field(
                description="With clone_from: copy each cloned profile into a new '<name>-<type>' profile "
                "with all its parcels, instead of sharing the source's profiles"
            ),
        ] = False,
        description: Annotated[str, Field(description="Description")] = "",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a configuration group (POST /v1/config-group {name, description, solution: sdwan,
        profiles}) for a new site type, from existing feature profiles, new empty ones (POST
        /v1/feature-profile/sdwan/<type> first) or a clone of another group (shared profiles, or deep=true
        copies them with their parcels). Preview-first: each profile with its source, and the parcels a deep
        clone copies. Blocked for a name in use or refused, an unknown type or profile, a new profile name in
        use. A failed step takes back the profiles it created. Nothing reaches a device: next
        catsdwan_set_feature_parcel, catsdwan_associate_config_group, catsdwan_deploy_config_group."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        pool = [p for p in await _listed_profiles(app) if p.get("type") in GROUP_PROFILE_TYPES]
        shared = _group_profiles(groups)
        gname = name.strip()
        blockers: list[str] = []
        warnings: list[str] = []
        if why := name_problem(name):
            blockers.append(f"{name!r}: {why}")
        if any(str(g.get("name", "")).lower() == gname.lower() for g in groups):
            blockers.append(f"a configuration group named {gname} exists already")
        # {type: {action: existing | new | copy, name, id?, source?, tree?}}
        plan_rows: dict[str, dict[str, Any]] = {}
        source_name = None
        if clone_from:
            src = await _group_detail(app, resolve_group(groups, clone_from))
            source_name = str(src.get("name"))
            for p in group_profiles(src):
                t = str(p.get("type"))
                if t not in GROUP_PROFILE_TYPES or t in (profiles or {}):
                    continue
                if deep:
                    tree = await _profile_tree(app, t, p["id"])
                    plan_rows[t] = {
                        "action": "copy",
                        "name": f"{gname}-{t}",
                        "source": {"name": p["name"], "id": p["id"]},
                        "tree": tree,
                    }
                else:
                    plan_rows[t] = {"action": "existing", "name": p["name"], "id": p["id"]}
            if not group_profiles(src):
                blockers.append(f"configuration group {source_name} has no feature profiles to clone")
        elif deep:
            blockers.append("deep=true needs clone_from")
        for t, ref in (profiles or {}).items():
            if t not in GROUP_PROFILE_TYPES:
                blockers.append(
                    f"{t!r} is not a configuration-group profile type ({', '.join(GROUP_PROFILE_TYPES)})"
                )
                continue
            kind, value = parse_profile_ref(ref)
            if kind == "new":
                plan_rows[t] = {"action": "new", "name": value}
                continue
            want = value.lower()
            found = [
                p
                for p in pool
                if p["type"] == t and want in (p["id"].lower(), str(p.get("name") or "").lower())
            ]
            if len(found) == 1:
                plan_rows[t] = {"action": "existing", "name": found[0]["name"], "id": found[0]["id"]}
            elif found:
                blockers.append(f"{value!r} matches several {t} profiles: give the id")
            else:
                other = [p for p in pool if want in (p["id"].lower(), str(p.get("name") or "").lower())]
                hint = f" (it is a {other[0]['type']} profile)" if other else ""
                blockers.append(f"no {t} feature profile is named {value!r}{hint}; 'new:<name>' creates one")
        taken = {str(p.get("name") or "").lower() for p in pool}
        new_names: list[str] = []
        for t, row in plan_rows.items():
            if row["action"] == "existing":
                if users := shared.get(str(row["id"]), {}).get("groups"):
                    warnings.append(
                        f"{t} profile {row['name']} is shared with {', '.join(users)}: a parcel change there "
                        "reaches every group using it"
                    )
                continue
            if why := name_problem(row["name"]):
                blockers.append(f"new {t} profile {row['name']!r}: {why}")
            elif row["name"].lower() in taken or row["name"].lower() in new_names:
                blockers.append(f"a feature profile named {row['name']} exists already")
            new_names.append(row["name"].lower())
        if not plan_rows:
            blockers.append("no feature profile: give `profiles` or `clone_from`")
        for t, why in (
            ("system", "devices need it for their variables (CFGRP0012) and a deploy"),
            ("transport", "edges need a WAN VPN to join the fabric"),
        ):
            if plan_rows and t not in plan_rows:
                warnings.append(f"no {t} profile: {why}")
        ordered = [(t, plan_rows[t]) for t in GROUP_PROFILE_TYPES if t in plan_rows]
        creates = [t for t, r in ordered if r["action"] != "existing"]
        parcels = sum(
            len(r["tree"]) + sum(len(p["subparcels"]) for p in r["tree"]) for _, r in ordered if r.get("tree")
        )
        requests = [
            *(f"POST {path(PROFILE_LIST_PATH, type=t)} {{name: {plan_rows[t]['name']}}}" for t in creates),
            *(
                [
                    f"GET + POST {parcels} parcel(s) into the copied profiles "
                    "(.../<parcelType>[/{{parent}}/<subType>])"
                ]
                if parcels
                else []
            ),
            f"POST {CONFIG_GROUPS_PATH}",
        ]
        body = group_body(
            gname, description, [r.get("id") or f"<new {t} profile {r['name']}>" for t, r in ordered]
        )

        def shown(t: str, r: dict[str, Any]) -> dict[str, Any]:
            row: dict[str, Any] = {"type": t, "name": r["name"], "action": r["action"]}
            if r.get("id"):
                row["id"] = r["id"]
            if r.get("source"):
                row["copied_from"] = r["source"]["name"]
                row["parcels"] = [
                    f"{p['name']} ({p['type']})"
                    + (f" + {len(p['subparcels'])} subparcel(s)" if p["subparcels"] else "")
                    for p in r["tree"]
                ]
            return row

        all_new = bool(ordered) and all(r["action"] != "existing" for _, r in ordered)
        plan = Plan(
            f"Create configuration group {gname} with {len(ordered)} profile(s)"
            + (f", {len(creates)} of them new" if creates else ""),
            details={
                "name": gname,
                **({"clone_from": source_name, "deep": deep} if source_name else {}),
                "profiles": [shown(t, r) for t, r in ordered],
                "requests": requests,
                "body": body,
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the group on the Manager only: no device has it until it is associated "
                "(catsdwan_associate_config_group) and deployed (catsdwan_deploy_config_group).",
                *(
                    [
                        f"Creates {len(creates)} feature profile(s): "
                        + ", ".join(plan_rows[t]["name"] for t in creates)
                    ]
                    if creates
                    else []
                ),
                *(
                    [
                        "A deep clone copies parcel values as the Manager returns them (secrets stay "
                        "encrypted); check them with catsdwan_get_feature_parcel before a deploy."
                    ]
                    if parcels
                    else []
                ),
            ],
            fingerprint={
                "groups": sorted(str(g.get("name")) for g in groups),
                "profiles": sorted(p["id"] for p in pool),
                "plan": [[t, r["action"], r["name"], r.get("id")] for t, r in ordered],
            },
            blockers=blockers,
            blast_radius=0,
            undo=Undo(
                "catsdwan_delete_config_group", {"group": FromResult("id"), "delete_profiles": all_new}
            ),
        )

        async def apply() -> Any:
            ids: dict[str, str] = {}
            made: list[tuple[str, str, str]] = []  # (type, id, name) of the profiles created here
            copied = 0
            try:
                for t, r in ordered:
                    if r["action"] == "existing":
                        ids[t] = str(r["id"])
                        continue
                    answer = await app.api.post(
                        path(PROFILE_LIST_PATH, type=t), profile_body(r["name"], description)
                    )
                    pid = created_id(answer)
                    if not pid:
                        raise UpstreamError(f"the Manager created {t} profile {r['name']} but returned no id")
                    made.append((t, pid, r["name"]))
                    ids[t] = pid
                    if r["action"] == "copy":
                        copied += await _copy_parcels(app, t, r["source"]["id"], pid, r["tree"])
                answer = await app.api.post(
                    CONFIG_GROUPS_PATH, group_body(gname, description, [ids[t] for t, _ in ordered])
                )
            except UpstreamError as e:
                back = await asyncio.gather(
                    *(app.api.delete(path(PROFILE_PATH, type=t, id=i)) for t, i, _ in made),
                    return_exceptions=True,
                )
                left = [n for (_, _, n), b in zip(made, back, strict=True) if isinstance(b, BaseException)]
                note = f"; took back the new profile(s) {', '.join(n for _, _, n in made)}" if made else ""
                if left:
                    note += f"; still on the Manager, delete by hand: {', '.join(left)}"
                raise UpstreamError(f"{e}{note}", getattr(e, "status_code", None)) from e
            gid = created_id(answer)
            return {
                "created": gname,
                "id": gid,
                "profiles": {t: {"id": ids[t], "name": r["name"], "action": r["action"]} for t, r in ordered},
                **({"parcels_copied": copied} if copied else {}),
                "next": "catsdwan_set_feature_parcel for the new profiles' parcels, "
                "catsdwan_associate_config_group(group, add=[...]), catsdwan_set_device_variables, then "
                "catsdwan_deploy_config_group",
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_create_config_group",
            args={
                "name": name,
                "profiles": profiles,
                "clone_from": clone_from,
                "deep": deep,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete SD-WAN configuration group", destructive=True)
    async def catsdwan_delete_config_group(
        ctx: Context,
        group: GroupRef,
        dissociate: Annotated[
            bool,
            Field(
                description="Dissociate the group's devices first (DELETE .../device/associate; dangerous: "
                "they keep their running configuration but no group manages them); without it a group with "
                "devices is refused"
            ),
        ] = False,
        delete_profiles: Annotated[
            bool,
            Field(
                description="Also delete the group's feature profiles and their parcels "
                "(deleteProfiles=true); blocked when another configuration group uses one"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a configuration group (DELETE /v1/config-group/{id}[?deleteProfiles=true]). Preview-first:
        its profiles and devices. Refused while devices are associated: run
        catsdwan_associate_config_group(remove=...) first, or pass dissociate=true (dangerous tier: the
        devices keep their running configuration but leave Manager management). Blocked while a deploy of
        the group or an action on its devices is still running, and for delete_profiles when another group
        shares a profile. Nothing is pushed to a device."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        found = await _group_detail(app, resolve_group(groups, group))
        gid, gname = str(found.get("id")), str(found.get("name"))
        blockers: list[str] = []
        warnings: list[str] = []
        try:
            devices = await _associated(app, gid)
        except UpstreamError as e:
            devices = []
            blockers.append(f"the group's devices were not read: {str(e)[:200]}")
        hosts = [str(d.get("host") or d.get("chassis")) for d in devices]
        profiles = group_profiles(found)
        reasons: list[str] = []
        if devices and not dissociate:
            blockers.append(
                f"{len(devices)} device(s) are associated ({', '.join(hosts)}): remove them first "
                "(catsdwan_associate_config_group(remove=...)) or pass dissociate=true"
            )
        elif devices:
            reasons.append(f"dissociates {len(devices)} device(s) from the group ({', '.join(hosts)})")
            blockers += dangerous_blockers(ctx, app, reasons)
        if state := deploy_pending(found):
            blockers.append(f"the group's deploy is still running ({state}): wait for it to finish")
        if devices:
            busy, unchecked = await _pending_blockers(app, devices)
            blockers += busy
            warnings += unchecked
        if delete_profiles:
            used = _group_profiles([g for g in groups if str(g.get("id")) != gid])
            for p in profiles:
                if others := used.get(p["id"], {}).get("groups"):
                    blockers.append(f"profile {p['name']} is used by configuration group {', '.join(others)}")
        requests = [
            *([f"DELETE {ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"] if devices else []),
            f"DELETE {CONFIG_GROUP_PATH}" + ("?deleteProfiles=true" if delete_profiles else ""),
        ]
        plan = Plan(
            f"Delete configuration group {gname}"
            + (f" after dissociating {len(devices)} device(s)" if devices else "")
            + (" and its profiles" if delete_profiles else ""),
            details={
                "group": gname,
                "id": gid,
                "profiles": [{"name": p["name"], "type": p["type"]} for p in profiles],
                "devices": hosts,
                "delete_profiles": delete_profiles,
                "tier": "dangerous" if reasons else "write",
                "requests": requests,
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Nothing is pushed: a device that ran the group keeps its running configuration.",
                *(
                    [
                        "The devices leave the group: no configuration group or template manages them until "
                        "they join one."
                    ]
                    if devices
                    else []
                ),
                *(["The group's feature profiles and their parcels are deleted."] if delete_profiles else []),
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "devices": sorted(str(d.get("chassis")) for d in devices),
            },
            blockers=blockers,
            blast_radius=len(devices),
            undo="not reversible in one call: create the group again (catsdwan_create_config_group"
            + ("" if delete_profiles else f" with its profiles {', '.join(str(p['name']) for p in profiles)}")
            + "), associate its devices and set their variables again, then deploy",
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            if devices:
                await app.api.delete(
                    path(ASSOCIATE_PATH, id=gid), json=devices_body([str(d.get("chassis")) for d in devices])
                )
                done["dissociated"] = hosts
            await app.api.delete(
                path(CONFIG_GROUP_PATH, id=gid),
                params={"deleteProfiles": "true"} if delete_profiles else None,
            )
            done["deleted"] = gname
            if delete_profiles:
                done["profiles_deleted"] = [p["name"] for p in profiles]
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_delete_config_group",
            args={"group": group, "dissociate": dissociate, "delete_profiles": delete_profiles},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
