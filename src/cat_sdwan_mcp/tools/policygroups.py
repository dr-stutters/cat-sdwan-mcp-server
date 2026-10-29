"""#94 policy-group lifecycle: catsdwan_create_policy_group, catsdwan_associate_policy_group,
catsdwan_delete_policy_group. catsdwan_deploy_policy_group (W21, tools/features.py) pushes a group.

Tiers: all three store on the Manager only (write): nothing reaches a device until
catsdwan_deploy_policy_group. A dissociated device keeps the policy it runs until another policy group is
deployed to it.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    FromResult,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp.changes import device_brief
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import POLICY_GROUPS_PATH, associated, path, resolve_group
from cat_sdwan_mcp.features import POLICY_ASSOCIATE_PATH, POLICY_GROUP_PATH
from cat_sdwan_mcp.inventory import load_inventory
from cat_sdwan_mcp.policygroups import (
    POLICY_GROUP_TYPES,
    create_body,
    created_id,
    devices_body,
    duplicate_types,
    group_profiles,
    name_problem,
)
from cat_sdwan_mcp.tools.changes import _resolve_devices
from cat_sdwan_mcp.tools.configuration import _groups
from cat_sdwan_mcp.tools.features import _listed_profiles, _names

GroupRef = Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")]


async def policy_profiles(app: SdwanApp) -> list[dict[str, Any]]:
    """Every feature profile a policy group can hold, as {id, name, type}."""
    return [p for p in await _listed_profiles(app) if p.get("type") in POLICY_GROUP_TYPES]


def pick_profiles(pool: list[dict[str, Any]], refs: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """(the profiles `refs` name, by id or exact name, case-insensitive; the refs that matched nothing or
    several)."""
    out: list[dict[str, Any]] = []
    problems: list[str] = []
    for ref in refs:
        want = ref.strip().lower()
        found = [p for p in pool if want in (p["id"].lower(), str(p.get("name") or "").lower())]
        if len(found) == 1:
            if found[0] not in out:
                out.append(found[0])
        elif found:
            listed = ", ".join(f"{p['name']} ({p['type']}, {p['id']})" for p in found)
            problems.append(f"{ref!r} matches several profiles: {listed}: give the id")
        else:
            problems.append(f"no policy feature profile ({', '.join(POLICY_GROUP_TYPES)}) is named {ref!r}")
    return out, problems


async def group_devices(app: SdwanApp, gid: str) -> list[dict[str, Any]]:
    return associated(await app.api.get(path(POLICY_ASSOCIATE_PATH, id=gid)))


async def all_memberships(app: SdwanApp, groups: list[dict[str, Any]]) -> tuple[dict[str, str], list[str]]:
    """({chassis: policy group name} for every associated device, read problems)."""
    got = await asyncio.gather(
        *(group_devices(app, str(g.get("id"))) for g in groups), return_exceptions=True
    )
    out: dict[str, str] = {}
    warnings: list[str] = []
    for g, devs in zip(groups, got, strict=True):
        if isinstance(devs, UpstreamError):
            warnings.append(f"policy group {g.get('name')}: devices not read: {str(devs)[:200]}")
            continue
        if isinstance(devs, BaseException):
            raise devs
        for d in devs:
            out[str(d.get("chassis"))] = str(g.get("name"))
    return out, warnings


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create SD-WAN policy group")
    async def catsdwan_create_policy_group(
        ctx: Context,
        name: Annotated[str, Field(description='New policy group name (no spaces or & < > ! ")')],
        profiles: Annotated[
            list[str] | None,
            Field(
                description="Feature profiles by name or id: policy-object, application-priority, "
                "embedded-security, dns-security, sig-security (one per type). The Manager's policy-object "
                "profile is added when none is given"
            ),
        ] = None,
        description: Annotated[str, Field(description="Description")] = "",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a policy group (POST /v1/policy-group {name, description, solution: sdwan, profiles}): the
        20.12+ home of application priority, NGFW / IPS / URL filtering (embedded security), DNS and SIG
        security for configuration-group devices. Preview-first: the profiles with their types. Blocked for a
        name in use or not accepted, an unknown profile, two profiles of one type. Nothing reaches a device:
        next catsdwan_associate_policy_group, then catsdwan_deploy_policy_group."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, POLICY_GROUPS_PATH)
        pool = await policy_profiles(app)
        chosen, blockers = pick_profiles(pool, profiles or [])
        warnings: list[str] = []
        if why := name_problem(name):
            blockers.append(f"{name!r}: {why}")
        if any(str(g.get("name", "")).lower() == name.strip().lower() for g in groups):
            blockers.append(f"a policy group named {name} exists already")
        if not any(p["type"] == "policy-object" for p in chosen):
            objects = [p for p in pool if p["type"] == "policy-object"]
            if len(objects) == 1:
                chosen.insert(0, objects[0])
                warnings.append(
                    f"added the Manager's policy-object profile {objects[0]['name']} (shared lists: apps, "
                    "prefixes, zones, identities, SGTs)"
                )
            elif objects:
                warnings.append(
                    "several policy-object profiles exist: name one in `profiles` if the group needs lists"
                )
        if dup := duplicate_types(chosen):
            blockers.append(f"a policy group holds one profile per type: {', '.join(dup)} given twice")
        if not chosen:
            blockers.append("no feature profile: give at least one in `profiles`")
        body = create_body(name.strip(), description, [p["id"] for p in chosen])
        plan = Plan(
            f"Create policy group {name.strip()} with {len(chosen)} profile(s)",
            details={
                "name": name.strip(),
                "profiles": [{"name": p["name"], "type": p["type"], "id": p["id"]} for p in chosen],
                "request": f"POST {POLICY_GROUPS_PATH}",
                "body": body,
                "undo": "catsdwan_delete_policy_group",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the group on the Manager only: no device has it until it is associated "
                "(catsdwan_associate_policy_group) and deployed (catsdwan_deploy_policy_group)."
            ],
            fingerprint={"groups": sorted(str(g.get("name")) for g in groups), "profiles": body["profiles"]},
            blockers=blockers,
            blast_radius=0,
            undo=Undo("catsdwan_delete_policy_group", {"group": FromResult("id")}),
        )

        async def apply() -> Any:
            answer = await app.api.post(POLICY_GROUPS_PATH, body)
            return {
                "created": name.strip(),
                "id": created_id(answer),
                "profiles": [p["name"] for p in chosen],
                "next": "catsdwan_associate_policy_group(group, add=[...]), then "
                "catsdwan_deploy_policy_group",
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_create_policy_group",
            args={"name": name, "profiles": profiles, "description": description},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Associate devices with SD-WAN policy group")
    async def catsdwan_associate_policy_group(
        ctx: Context,
        group: GroupRef,
        add: Annotated[
            list[str] | None, Field(description="Devices to associate (host name, system IP or chassis)")
        ] = None,
        remove: Annotated[list[str] | None, Field(description="Devices to dissociate from the group")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add devices to or remove them from a policy group (POST / DELETE
        /v1/policy-group/{id}/device/associate {devices: [{id: <chassis>}]}). Preview-first: the group's
        devices before and after. Blocked for a device on a device template (policy groups are for
        configuration-group devices), one in no configuration group, one in another policy group (a device
        has one), already in (add) or not in (remove) this group. Nothing is pushed: an added device gets the
        policy with catsdwan_deploy_policy_group; a removed one keeps what it runs. Dissociate every device
        before catsdwan_delete_policy_group (the Manager refuses with PLGRP0003)."""
        if not add and not remove:
            raise InvalidRequest("Give devices to `add` or `remove`.")
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, POLICY_GROUPS_PATH)
        found = resolve_group(groups, group, "policy group")
        gid, gname = str(found.get("id")), str(found.get("name"))
        inv = await load_inventory(app)
        adds = _resolve_devices(inv, add or [])
        removes = _resolve_devices(inv, remove or [])
        member_of, warnings = await all_memberships(app, groups)
        current = [c for c, g in member_of.items() if g == gname]
        blockers: list[str] = []
        if {str(r["chassis"]) for r in adds} & {str(r["chassis"]) for r in removes}:
            blockers.append("a device can't be both added and removed")
        for r in adds:
            host = r.get("host") or r.get("chassis")
            other = member_of.get(str(r["chassis"]))
            if other == gname:
                blockers.append(f"{host} is already in policy group {gname}")
            elif other:
                blockers.append(f"{host} is in policy group {other}: remove it from there first")
            elif r.get("config_mode") == "template":
                blockers.append(
                    f"{host} is on device template {r.get('config') or '?'}: policy groups are for "
                    "configuration-group devices"
                )
            elif r.get("config_mode") != "configuration group":
                blockers.append(
                    f"{host} is in no configuration group ({r.get('config_mode') or 'unknown mode'}): "
                    "associate it with one first (catsdwan_associate_config_group)"
                )
        for r in removes:
            if member_of.get(str(r["chassis"])) != gname:
                blockers.append(f"{r.get('host') or r.get('chassis')} is not in policy group {gname}")
        by_chassis = {str(r.get("chassis")): r for r in inv.rows}
        before = sorted(str(by_chassis.get(c, {}).get("host") or c) for c in current)
        after = sorted((set(before) - set(_names(removes))) | set(_names(adds)))
        plan = Plan(
            f"Policy group {gname}: add {len(adds)}, remove {len(removes)} device(s)",
            details={
                "group": gname,
                "add": [device_brief(r) for r in adds],
                "remove": [device_brief(r) for r in removes],
                "devices_before": before,
                "devices_after": after,
                "requests": [
                    *([f"POST {POLICY_ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"] if adds else []),
                    *(
                        [f"DELETE {POLICY_ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"]
                        if removes
                        else []
                    ),
                ],
                "undo": "the same call with add and remove swapped",
                **({"warnings": warnings + list(inv.warnings)} if warnings or inv.warnings else {}),
            },
            side_effects=[
                "Nothing is pushed to a device. An added device gets the group's policy with "
                "catsdwan_deploy_policy_group.",
                *(
                    [
                        "A removed device keeps the policy it runs; the Manager no longer manages "
                        "it as part of the group."
                    ]
                    if removes
                    else []
                ),
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "devices": sorted(current),
            },
            blockers=blockers,
            blast_radius=len(adds) + len(removes),
            undo=Undo(
                "catsdwan_associate_policy_group",
                {"group": gname, "add": _names(removes) or None, "remove": _names(adds) or None},
            ),
        )

        async def apply() -> Any:
            url = path(POLICY_ASSOCIATE_PATH, id=gid)
            done: dict[str, Any] = {}
            if adds:
                await app.api.post(url, devices_body([str(r["chassis"]) for r in adds]))
                done["added"] = _names(adds)
            if removes:
                await app.api.delete(url, json=devices_body([str(r["chassis"]) for r in removes]))
                done["removed"] = _names(removes)
            done["devices_now"] = [
                str(d.get("host") or d.get("chassis")) for d in await group_devices(app, gid)
            ]
            if adds:
                done["next"] = "catsdwan_deploy_policy_group(group, devices) for each added device"
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_associate_policy_group",
            args={"group": group, "add": add, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete SD-WAN policy group", destructive=True)
    async def catsdwan_delete_policy_group(
        ctx: Context,
        group: GroupRef,
        dissociate: Annotated[
            bool,
            Field(
                description="Dissociate the group's devices first (DELETE .../device/associate); without it "
                "a group with devices is refused (PLGRP0003)"
            ),
        ] = False,
        delete_profiles: Annotated[
            bool,
            Field(
                description="Also delete the group's own feature profiles (deleteProfiles=true); never the "
                "shared policy-object profile or a profile another policy group uses"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a policy group (DELETE /v1/policy-group/{id}). Preview-first: its profiles and devices.
        The Manager refuses while a device is associated (PLGRP0003): dissociate them with
        catsdwan_associate_policy_group(remove=...) or pass dissociate=true (one DELETE of the associations
        first). A dissociated device keeps the policy it runs. delete_profiles=true also deletes its
        profiles; blocked when one is a policy-object profile or used by another policy group."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, POLICY_GROUPS_PATH)
        found = resolve_group(groups, group, "policy group")
        gid, gname = str(found.get("id")), str(found.get("name"))
        blockers: list[str] = []
        try:
            devices = await group_devices(app, gid)
        except UpstreamError as e:
            devices = []
            blockers.append(f"the policy group's devices were not read: {str(e)[:200]}")
        try:
            detail = await app.api.get(path(POLICY_GROUP_PATH, id=gid))
        except (UpstreamError, NotFound):
            detail = found
        profiles = group_profiles(detail if isinstance(detail, dict) and detail.get("profiles") else found)
        hosts = [str(d.get("host") or d.get("chassis")) for d in devices]
        if devices and not dissociate:
            blockers.append(
                f"{len(devices)} device(s) are associated ({', '.join(hosts)}): the Manager refuses the "
                "delete (PLGRP0003). Dissociate them first, or pass dissociate=true"
            )
        if delete_profiles:
            shared = {str(p.get("id")) for g in groups if str(g.get("id")) != gid for p in group_profiles(g)}
            for p in profiles:
                if p["type"] == "policy-object":
                    blockers.append(
                        f"delete_profiles would delete the shared policy-object profile {p['name']}"
                    )
                elif p["id"] in shared:
                    blockers.append(f"profile {p['name']} is used by another policy group")
        requests = [
            *([f"DELETE {POLICY_ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"] if devices else []),
            f"DELETE {POLICY_GROUP_PATH}" + ("?deleteProfiles=true" if delete_profiles else ""),
        ]
        plan = Plan(
            f"Delete policy group {gname}"
            + (f" after dissociating {len(devices)} device(s)" if devices else ""),
            details={
                "group": gname,
                "profiles": [{"name": p["name"], "type": p["type"]} for p in profiles],
                "devices": hosts,
                "delete_profiles": delete_profiles,
                "requests": requests,
                "undo": "none: create it again (catsdwan_create_policy_group), associate and deploy",
            },
            undo=(
                "not reversible: the deleted profiles are gone; build them again, then "
                "catsdwan_create_policy_group, associate and deploy"
                if delete_profiles
                else Undo(
                    "catsdwan_create_policy_group",
                    {
                        "name": gname,
                        "profiles": [p["name"] for p in profiles],
                        "description": str(found.get("description") or ""),
                    },
                )
            ),
            side_effects=[
                "Nothing is pushed: a device that ran the group keeps its policy until another policy group "
                "is deployed to it.",
                *(
                    ["The group's own feature profiles and their parcels are deleted."]
                    if delete_profiles
                    else []
                ),
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "devices": sorted(str(d.get("chassis")) for d in devices),
            },
            blockers=blockers,
            blast_radius=len(devices),
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            if devices:
                await app.api.delete(
                    path(POLICY_ASSOCIATE_PATH, id=gid),
                    json=devices_body([str(d.get("chassis")) for d in devices]),
                )
                done["dissociated"] = hosts
            await app.api.delete(
                path(POLICY_GROUP_PATH, id=gid),
                params={"deleteProfiles": "true"} if delete_profiles else None,
            )
            done["deleted"] = gname
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_delete_policy_group",
            args={"group": group, "dissociate": dissociate, "delete_profiles": delete_profiles},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
