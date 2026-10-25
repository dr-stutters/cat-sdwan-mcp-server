"""W47 edge firewall: catsdwan_get_firewall_policy (read), catsdwan_set_security_object and
catsdwan_set_firewall_policy (always dangerous, preview-first).

Both writes store on the Manager only: a device gets the change with catsdwan_deploy_policy_group, and each
preview counts the devices of the policy groups the change reaches (`blast_radius`). They are dangerous
because a firewall change, once deployed, can cut a branch off; with writes on but MCP_ENABLE_DANGEROUS off
they are listed and their preview says why it is refused.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import POLICY_GROUPS_PATH, path, resolve_group
from cat_sdwan_mcp.edgefirewall import (
    ACTIONS,
    LITERAL_MATCHES,
    NGFW_LIST_PATH,
    NGFW_PATH,
    OBJECT_TYPES,
    PO_ITEM_PATH,
    PO_LIST_PATH,
    PO_SCHEMA_PATH,
    REF_MATCHES,
    SEC_POLICY_LIST_PATH,
    SEC_POLICY_PATH,
    SEC_PROFILES_PATH,
    SEC_SCHEMA_PATH,
    assembly_item,
    by_name,
    describe_rules,
    literal_prefix_problems,
    merge_assembly,
    ngfw_body,
    object_body,
    object_entries,
    object_values,
    parcels,
    policy_body,
    request_schema,
    schema_problems,
    sgt_table,
    zone_pairs_of,
)
from cat_sdwan_mcp.features import POLICY_GROUP_PATH
from cat_sdwan_mcp.policygroups import created_id, group_profiles, update_body
from cat_sdwan_mcp.serviceinsertion import vpn_problem
from cat_sdwan_mcp.servicevpns import vpn_context, zone_values, zone_vpn_problems
from cat_sdwan_mcp.tools.changes import dangerous_blockers, dangerous_tool
from cat_sdwan_mcp.tools.configuration import _groups
from cat_sdwan_mcp.tools.policygroups import group_devices, policy_profiles
from cat_sdwan_mcp.tools.policyvpns import zone_vpns
from cat_sdwan_mcp.trustsec import ISE_CREDENTIALS_PATH, ISE_SGT_PATH, configured

# A policy-object list type per rule kind (apps are the Manager's app lists).
LIST_TYPES = {**OBJECT_TYPES, "app": "app-list"}
ISE_MISSING = (
    "no ISE on the Manager: identity and SGT rules match nothing until ISE and pxGrid are connected "
    "(catsdwan_set_ise_integration)"
)
NEXT = "catsdwan_deploy_policy_group(group, devices=[one edge]), then catsdwan_security_status"
TIER_REASON = "an edge firewall change (W47): deployed, it can block a branch's traffic"


class FirewallRule(BaseModel):
    """One NGFW rule (a sequence, in order). Empty matches mean any."""

    name: str = Field(min_length=1, max_length=64, description="Rule name")
    action: Literal["drop", "pass", "inspect"] = Field(description="drop, pass, or inspect (stateful)")
    source_prefixes: list[str] = Field(default_factory=list, description="Source IPv4 prefixes")
    destination_prefixes: list[str] = Field(default_factory=list, description="Destination IPv4 prefixes")
    source_objects: list[str] = Field(
        default_factory=list, description="Source IPv4 prefix lists by name (kind 'prefix')"
    )
    destination_objects: list[str] = Field(
        default_factory=list, description="Destination IPv4 prefix lists by name (kind 'prefix')"
    )
    identities: list[str] = Field(
        default_factory=list,
        description="Identity lists by name (kind 'identity': ISE users and AD groups over pxGrid)",
    )
    source_sgts: list[str] = Field(default_factory=list, description="Source SGT lists by name (kind 'sgt')")
    destination_sgts: list[str] = Field(
        default_factory=list, description="Destination SGT lists by name (kind 'sgt')"
    )
    apps: list[str] = Field(default_factory=list, description="App lists by name (e.g. 'webex_apps')")
    protocols: list[str] = Field(default_factory=list, description="Protocol names (tcp, udp, icmp, ...)")
    log: bool = Field(default=False, description="Log matches")


class ZonePair(BaseModel):
    source: str = Field(description="Source zone (a security-zone object by name)")
    destination: str = Field(description="Destination zone (a security-zone object by name)")


# --- reads ---------------------------------------------------------------------------------------


async def object_profile(app: SdwanApp, ref: str | None = None) -> dict[str, Any]:
    """The policy-object profile `ref` names, or the Manager's only one."""
    pool = [p for p in await policy_profiles(app) if p["type"] == "policy-object"]
    if ref:
        want = ref.strip().lower()
        found = [p for p in pool if want in (p["id"].lower(), str(p.get("name") or "").lower())]
    else:
        found = pool
    if len(found) == 1:
        return found[0]
    names = ", ".join(str(p.get("name")) for p in pool) or "none"
    if not found:
        raise NotFound(
            f"No policy-object profile {'named ' + repr(ref) if ref else 'on the Manager'}: {names}."
        )
    raise InvalidRequest(f"Several policy-object profiles ({names}): name one in `profile`.")


async def list_objects(app: SdwanApp, profile_id: str, list_type: str) -> list[dict[str, Any]]:
    return parcels(await app.api.get(path(PO_LIST_PATH, profile=profile_id, list_type=list_type)))


async def _schema(app: SdwanApp, url: str, kind: str) -> tuple[dict[str, Any], str | None]:
    try:
        body = await app.api.get(url, {"schemaType": kind})
    except UpstreamError as e:
        return {}, f"not checked against the Manager's schema (GET {url.split('?')[0]}: {str(e)[:150]})"
    s = request_schema(body)
    return s, None if s else "not checked: the Manager returned no schema"


async def _group_detail(app: SdwanApp, found: dict[str, Any]) -> dict[str, Any]:
    try:
        body = await app.api.get(path(POLICY_GROUP_PATH, id=str(found.get("id"))))
    except UpstreamError:
        return found
    return body if isinstance(body, dict) and body.get("profiles") is not None else found


async def reach(
    app: SdwanApp, groups: list[dict[str, Any]], profile_id: str | None, extra: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """The policy groups holding a profile (plus `extra`), each with its devices, and read problems."""
    using = [g for g in groups if profile_id and any(p["id"] == profile_id for p in group_profiles(g))]
    if extra is not None and all(str(g.get("id")) != str(extra.get("id")) for g in using):
        using.append(extra)
    got = await asyncio.gather(*(group_devices(app, str(g.get("id"))) for g in using), return_exceptions=True)
    out, warnings = [], []
    for g, devs in zip(using, got, strict=True):
        if isinstance(devs, UpstreamError):
            warnings.append(f"policy group {g.get('name')}: devices not read: {str(devs)[:200]}")
            devs = []
        elif isinstance(devs, BaseException):
            raise devs
        out.append(
            {"group": g.get("name"), "devices": [str(d.get("host") or d.get("chassis")) for d in devs]}
        )
    return out, warnings


async def _ise_configured(app: SdwanApp) -> bool | None:
    try:
        return configured(await app.api.get(ISE_CREDENTIALS_PATH))
    except UpstreamError:
        return None


def _devices(reached: list[dict[str, Any]]) -> list[str]:
    return sorted({d for r in reached for d in r["devices"]})


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN edge firewall policy")
    async def catsdwan_get_firewall_policy(
        ctx: Context,
        group: Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")],
    ) -> dict[str, Any]:
        """The zone-based and identity firewall a policy group gives its edges (20.18 NGFW in the group's
        embedded-security profile): each NGFW policy's rules in order in plain words (zones, prefixes,
        identity lists of ISE users and groups, SGT lists, app lists resolved to their names), the default
        action, the zone pairs it is bound to, and the security objects (zones, identities, SGTs, prefix
        lists) with their values. Live state on one edge (zone-pair counters, drops):
        catsdwan_security_status. Change it with catsdwan_set_security_object and
        catsdwan_set_firewall_policy."""
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, POLICY_GROUPS_PATH), group, "policy group")
        detail = await _group_detail(app, found)
        profs = group_profiles(detail)
        out: dict[str, Any] = {"group": found.get("name"), "profiles": profs}
        warnings: list[str] = []
        names: dict[str, str] = {}
        po = next((p for p in profs if p["type"] == "policy-object"), None)
        if po:
            objects: dict[str, Any] = {}
            got = await asyncio.gather(
                *(list_objects(app, po["id"], t) for t in LIST_TYPES.values()), return_exceptions=True
            )
            for (kind, t), rows in zip(LIST_TYPES.items(), got, strict=True):
                if isinstance(rows, UpstreamError):
                    warnings.append(f"{t} lists not read: {str(rows)[:150]}")
                    continue
                if isinstance(rows, BaseException):
                    raise rows
                names.update({r["id"]: str(r.get("name")) for r in rows})
                if kind != "app" and rows:
                    objects[kind] = {str(r.get("name")): object_values(kind, r["data"]) for r in rows}
            out["objects"] = objects
        sec = [p for p in profs if p["type"] == "embedded-security"]
        if not sec:
            out["verdict"] = (
                f"Policy group {found.get('name')} has no embedded-security profile: it gives its edges no "
                "firewall (catsdwan_set_firewall_policy adds one)."
            )
        policies = []
        for p in sec:
            try:
                ngfws, pol = await asyncio.gather(
                    app.api.get(path(NGFW_LIST_PATH, id=p["id"])),
                    app.api.get(path(SEC_POLICY_LIST_PATH, id=p["id"])),
                )
            except UpstreamError as e:
                warnings.append(f"profile {p['name']}: not read: {str(e)[:200]}")
                continue
            pol_rows = parcels(pol)
            pairs = [t for r in pol_rows for t in zone_pairs_of(r["data"])]
            for n in parcels(ngfws):
                policies.append(
                    {
                        "profile": p["name"],
                        "name": n.get("name"),
                        "id": n["id"],
                        "rules": describe_rules(n["data"], names),
                        "zone_pairs": [
                            f"{names.get(s, s)} -> {names.get(d, d)}" for rid, s, d in pairs if rid == n["id"]
                        ]
                        or "none: not bound to a zone pair, so it filters nothing",
                    }
                )
        out["firewall_policies"] = policies
        if sec and not policies:
            out["verdict"] = "The embedded-security profile holds no NGFW policy."
        if warnings:
            out["warnings"] = warnings
        return out

    @dangerous_tool(reg, title="Set SD-WAN security object")
    async def catsdwan_set_security_object(
        ctx: Context,
        kind: Annotated[
            Literal["zone", "identity", "sgt", "prefix"],
            Field(
                description="zone (VPNs or interfaces), identity (ISE users and user groups), sgt (SGT "
                "names and tags), prefix (IPv4 prefixes)"
            ),
        ],
        name: Annotated[
            str, Field(description="Object name (max 32; a zone not untrusted/self/default/service)")
        ],
        values: Annotated[
            list[str] | None,
            Field(
                description="zone: VPNs ('10' or the LAN VPN parcel name 'mcp-w8-vpn10'; stored as the "
                "parcel name, which the controller needs) or interfaces ('GigabitEthernet3'), not both; "
                "identity: 'user:alice' or 'group:<domain>/Users/Sales'; sgt: 'Employees:4' or a tag or "
                "ISE SGT name; prefix: '192.0.2.0/24'. Replaces the object's values"
            ),
        ] = None,
        description: Annotated[str, Field(description="Description")] = "",
        profile: Annotated[
            str | None, Field(description="Policy-object profile (default: the Manager's only one)")
        ] = None,
        remove: Annotated[bool, Field(description="Delete the object instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, replace or delete a security object in the policy-object profile (POST / PUT / DELETE
        /v1/feature-profile/sdwan/policy-object/{id}/<security-zone|security-identity|
        security-scalablegrouptag|security-data-ip-prefix>): what firewall rules match on. Preview-first:
        old -> new values, the body checked against the Manager's own schema
        (.../policy-object/<type>/schema) with every problem at once, the policy groups and devices the
        profile reaches. Identity and SGT objects match only once the Manager has ISE with pxGrid
        (catsdwan_set_ise_integration). Stores only: deploy with catsdwan_deploy_policy_group. Dangerous."""
        if not remove and not values:
            raise InvalidRequest("Give `values`, or remove=true.")
        app: SdwanApp = get_client(ctx)
        list_type = OBJECT_TYPES[kind]
        po = await object_profile(app, profile)
        existing_rows = await list_objects(app, po["id"], list_type)
        existing = by_name(existing_rows, name)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON])
        warnings: list[str] = []
        body: dict[str, Any] | None = None
        if remove:
            if not existing:
                blockers.append(f"no {kind} object named {name} in {po['name']}")
        else:
            sgts: dict[str, str] = {}
            if kind == "sgt":
                try:
                    sgts = sgt_table(await app.api.get(ISE_SGT_PATH))
                except UpstreamError as e:
                    warnings.append(f"ISE SGTs not read (names need ':<tag>'): {str(e)[:150]}")
            vals = list(values or [])
            vpn_names: list[str] = []
            if kind == "zone":
                # #126: the 20.18 controller looks a zone's VPN up by LAN VPN parcel name (a number fails the
                # deploy with GNGRP0013), so VPN ids / VPN names / segment names become the parcel name(s).
                try:
                    vctx = await vpn_context(app, None)
                except UpstreamError as e:
                    vctx = {}
                    warnings.append(f"LAN VPN parcels not read (VPN names not resolved): {str(e)[:150]}")
                if vctx:
                    zv = zone_values(vals, vctx)
                    vals, vpn_names = zv["values"], zv["vpn_names"]
                    blockers += [f"{name}: {b}" for b in zv["blockers"]]
                    warnings += zv["warnings"]
                else:
                    blockers += [
                        f"{name}: VPN {v.strip()} can't be turned into its LAN VPN parcel name (the "
                        "controller refuses a VPN number in a zone): give the parcel name, or retry once the "
                        "configuration groups can be read"
                        for v in vals
                        if v.strip().isdigit() and vpn_problem(int(v.strip())) is None
                    ]
            entries, problems = object_entries(kind, vals, sgts, vpn_names)
            blockers += [f"{name}: {p}" for p in problems]
            body = object_body(name.strip(), description, entries)
            schema, why = await _schema(
                app, path(PO_SCHEMA_PATH, list_type=list_type), "put" if existing else "post"
            )
            if why:
                warnings.append(why)
            blockers += schema_problems(schema, body)
            if kind in ("identity", "sgt") and await _ise_configured(app) is False:
                warnings.append(
                    "no ISE on the Manager: identity and SGT matches have no source until ISE and pxGrid "
                    "are connected (catsdwan_set_ise_integration)"
                )
        groups = await _groups(app, POLICY_GROUPS_PATH)
        details_groups = await asyncio.gather(*(_group_detail(app, g) for g in groups))
        reached, read_warn = await reach(app, list(details_groups), po["id"])
        warnings += read_warn
        before = object_values(kind, existing["data"]) if existing else None
        url_list = path(PO_LIST_PATH, profile=po["id"], list_type=list_type)
        if remove:
            request = f"DELETE {PO_ITEM_PATH}"
            summary = f"Delete {kind} object {name}"
        elif existing:
            request = f"PUT {PO_ITEM_PATH}"
            summary = f"Replace {kind} object {name}"
        else:
            request = f"POST {PO_LIST_PATH}"
            summary = f"Create {kind} object {name}"
        plan = Plan(
            f"{summary} in {po['name']}",
            details={
                "tier": "dangerous",
                "profile": po["name"],
                "kind": kind,
                "list_type": list_type,
                "before": before,
                "after": None if remove else object_values(kind, (body or {}).get("data", {})),
                "request": request,
                **({"body": body} if body else {}),
                "reaches": reached,
                "undo": "the same call with the old values" if existing else "the same call with remove=true",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the object on the Manager only: the edges of the policy groups using the profile get "
                "it with catsdwan_deploy_policy_group."
                + (" A rule that references a deleted object is refused by the Manager." if remove else "")
            ],
            fingerprint={
                "object": existing["raw"].get("lastUpdatedOn") if existing else None,
                "names": sorted(str(r.get("name")) for r in existing_rows),
            },
            blockers=blockers,
            blast_radius=len(_devices(reached)),
        )

        async def apply() -> Any:
            if remove and existing:
                await app.api.delete(
                    path(PO_ITEM_PATH, profile=po["id"], list_type=list_type, parcel=existing["id"])
                )
                return {"deleted": name, "kind": kind}
            if existing:
                await app.api.put(
                    path(PO_ITEM_PATH, profile=po["id"], list_type=list_type, parcel=existing["id"]), body
                )
                pid: str | None = existing["id"]
            else:
                pid = created_id(await app.api.post(url_list, body))
            return {
                "saved": name,
                "kind": kind,
                "id": pid,
                "values": object_values(kind, (body or {}).get("data", {})),
                "next": "reference it in catsdwan_set_firewall_policy, then catsdwan_deploy_policy_group",
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_security_object",
            args={
                "kind": kind,
                "name": name,
                "values": values,
                "description": description,
                "profile": profile,
                "remove": remove,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @dangerous_tool(reg, title="Set SD-WAN edge firewall policy")
    async def catsdwan_set_firewall_policy(
        ctx: Context,
        group: Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")],
        name: Annotated[str, Field(description="NGFW policy name (created, or replaced when it exists)")],
        rules: Annotated[
            list[FirewallRule] | None,
            Field(description="Rules in order; the first match decides. Empty: only the default action"),
        ] = None,
        zone_pairs: Annotated[
            list[ZonePair] | None,
            Field(description="Zone pairs the policy filters (security-zone objects by name)"),
        ] = None,
        default_action: Annotated[
            Literal["drop", "pass"], Field(description="What a flow matching no rule gets")
        ] = "drop",
        profile: Annotated[
            str | None,
            Field(
                description="Embedded-security profile name: default the group's, or a new "
                "'<group>-security' added to the group"
            ),
        ] = None,
        description: Annotated[str, Field(description="Description")] = "",
        remove: Annotated[
            bool, Field(description="Remove this NGFW policy and its zone pairs instead")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Write a policy group's zone-based / identity firewall (20.18 NGFW): an NGFW policy (POST / PUT
        .../embedded-security/{id}/unified/ngfirewall: rules in order with drop, pass or inspect, matching
        prefixes, prefix lists, identity lists of ISE users and groups, SGT lists, app lists, protocols) and
        its zone pairs in the profile's security policy (.../embedded-security/{id}/policy). The group gets an
        embedded-security profile when it has none (POST .../embedded-security, PUT /v1/policy-group/{id}).
        Preview-first: the rules in plain words, before and after, every object name resolved (an unknown
        zone or list is a blocker), the bodies checked against the Manager's schema when it gives one, the
        policy groups and devices reached. Stores only: deploy with catsdwan_deploy_policy_group (one edge
        first). remove=true takes the policy out of the security policy and deletes it. Dangerous."""
        app: SdwanApp = get_client(ctx)
        rule_rows = [r.model_dump() for r in rules or []]
        pairs_in = [(p.source, p.destination) for p in zone_pairs or []]
        groups = await _groups(app, POLICY_GROUPS_PATH)
        found = resolve_group(groups, group, "policy group")
        detail = await _group_detail(app, found)
        gname = str(found.get("name"))
        profs = group_profiles(detail)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON])
        warnings: list[str] = []

        # The embedded-security profile: the group's, a named one, or a new one.
        sec_in_group = [p for p in profs if p["type"] == "embedded-security"]
        all_sec = [p for p in await policy_profiles(app) if p["type"] == "embedded-security"]
        sec: dict[str, Any] | None = None
        attach = False
        new_profile_name: str | None = None
        if profile:
            sec = by_name([{**p, "id": p["id"]} for p in all_sec], profile)
            if sec is None:
                new_profile_name = profile.strip()
                if sec_in_group:
                    blockers.append(
                        f"{gname} already has embedded-security profile {sec_in_group[0]['name']} (one per "
                        f"group): leave `profile` out to use it, not a new profile {new_profile_name}"
                    )
            elif all(p["id"] != sec["id"] for p in sec_in_group):
                attach = True
                if sec_in_group:
                    blockers.append(
                        f"{gname} already has embedded-security profile {sec_in_group[0]['name']} (one per "
                        "group): leave `profile` out to use it"
                    )
        elif sec_in_group:
            sec = sec_in_group[0]
        else:
            new_profile_name = f"{gname}-security"
        if new_profile_name and remove:
            blockers.append(f"{gname} has no embedded-security profile with an NGFW policy to remove")
        po = next((p for p in profs if p["type"] == "policy-object"), None)
        if po is None and not remove:
            blockers.append(f"{gname} has no policy-object profile: its rules have no zones or lists to use")

        # Existing NGFW policy and security policy parcels.
        existing_ngfw: dict[str, Any] | None = None
        sec_policy: dict[str, Any] | None = None
        if sec:
            try:
                ngfws, pol = await asyncio.gather(
                    app.api.get(path(NGFW_LIST_PATH, id=sec["id"])),
                    app.api.get(path(SEC_POLICY_LIST_PATH, id=sec["id"])),
                )
                existing_ngfw = by_name(parcels(ngfws), name)
                pol_rows = parcels(pol)
                sec_policy = pol_rows[0] if pol_rows else None
                if len(pol_rows) > 1:
                    warnings.append(
                        f"{sec['name']} holds {len(pol_rows)} security policies: the first is used"
                    )
            except UpstreamError as e:
                blockers.append(f"profile {sec['name']} was not read: {str(e)[:200]}")
        if remove and sec and not existing_ngfw:
            blockers.append(f"no NGFW policy named {name} in {sec['name']}")

        # Names -> ids for zones and every list the rules use.
        refs: dict[str, dict[str, str]] = {k: {} for k in LIST_TYPES}
        id_names: dict[str, str] = {}
        zone_rows: list[dict[str, Any]] = []
        unresolved = False
        if po:
            want: dict[str, set[str]] = {k: set() for k in LIST_TYPES}
            if not remove:
                want["zone"] = {n for pair in pairs_in for n in pair}
                for r in rule_rows:
                    for field_name, (_, kind) in REF_MATCHES.items():
                        want[kind] |= set(r.get(field_name) or [])
            # Zones always: the preview names the zone pairs before and after.
            kinds = ["zone"] + [k for k, v in want.items() if v and k != "zone"]
            got = await asyncio.gather(
                *(list_objects(app, po["id"], LIST_TYPES[k]) for k in kinds), return_exceptions=True
            )
            for k, rows in zip(kinds, got, strict=True):
                if isinstance(rows, UpstreamError):
                    blockers.append(f"{LIST_TYPES[k]} lists were not read: {str(rows)[:150]}")
                    unresolved = True
                    continue
                if isinstance(rows, BaseException):
                    raise rows
                if k == "zone":
                    zone_rows = rows
                    id_names.update({r["id"]: str(r.get("name")) for r in rows})
                for n in sorted(want[k]):
                    hit = by_name(rows, n)
                    if hit:
                        refs[k][n] = hit["id"]
                        id_names[hit["id"]] = str(hit.get("name"))
                    else:
                        unresolved = True
                        known = ", ".join(sorted(str(r.get("name")) for r in rows)[:15]) or "none"
                        blockers.append(
                            f"no {k} object named {n!r} in {po['name']} (known: {known}); "
                            + (
                                "create it with catsdwan_set_security_object"
                                if k != "app"
                                else "use an app list"
                            )
                        )

        # Rules and zone pairs.
        if not remove:
            seen: set[str] = set()
            for r in rule_rows:
                if r["name"] in seen:
                    blockers.append(f"rule name {r['name']} is used twice")
                seen.add(r["name"])
                if r["action"] not in ACTIONS:
                    blockers.append(f"rule {r['name']}: action {r['action']}")
                for field_name in LITERAL_MATCHES:
                    blockers += [
                        f"rule {r['name']}: {p}" for p in literal_prefix_problems(r.get(field_name) or [])
                    ]
            if not pairs_in:
                blockers.append("give at least one zone pair: an NGFW policy filters nothing without one")
            # #118: each VPN of a paired zone must be a LAN VPN parcel in every device's configuration group.
            used = zone_vpns(
                zone_rows, {refs["zone"][n] for pair in pairs_in for n in pair if n in refs["zone"]}
            )
            if used:
                try:
                    members = [str(d.get("chassis")) for d in await group_devices(app, str(found.get("id")))]
                    vctx = await vpn_context(app, members)
                    blockers += zone_vpn_problems(used, vctx)
                    warnings += list(vctx.get("warnings") or [])
                except UpstreamError as e:
                    warnings.append(f"zone VPNs not checked against the configuration groups: {str(e)[:150]}")
            if len(set(pairs_in)) != len(pairs_in):
                blockers.append("a zone pair is given twice")
            if (
                any(
                    r.get("identities") or r.get("source_sgts") or r.get("destination_sgts")
                    for r in rule_rows
                )
                and await _ise_configured(app) is False
            ):
                warnings.append(ISE_MISSING)

        body: dict[str, Any] | None = None
        if not remove and po and not unresolved:
            body = ngfw_body(name.strip(), description, default_action, rule_rows, refs)
            if sec or new_profile_name:
                schema, why = await _schema(
                    app, path(SEC_SCHEMA_PATH.replace("{parcel_type}", "unified/ngfirewall")), "post"
                )
                if why:
                    warnings.append(f"NGFW policy {why}")
                blockers += [f"NGFW policy: {p}" for p in schema_problems(schema, body)]
        zone_pairs_words = [f"{s} -> {d}" for s, d in pairs_in]
        pair_ids = [(refs["zone"].get(s, s), refs["zone"].get(d, d)) for s, d in pairs_in]
        policy_data_before = sec_policy["data"] if sec_policy else {}
        before = None
        if existing_ngfw:
            names_all = {**id_names}
            before = {
                "rules": describe_rules(existing_ngfw["data"], names_all),
                "zone_pairs": [
                    f"{names_all.get(s, s)} -> {names_all.get(d, d)}"
                    for _, s, d in zone_pairs_of(policy_data_before, existing_ngfw["id"])
                ],
            }

        requests: list[str] = []
        if new_profile_name:
            requests += [f"POST {SEC_PROFILES_PATH} {{name: {new_profile_name}}}", f"PUT {POLICY_GROUP_PATH}"]
        elif attach:
            requests.append(f"PUT {POLICY_GROUP_PATH} (add profile {sec['name'] if sec else '?'})")
        if remove:
            requests += [f"PUT {SEC_POLICY_PATH} (zone pairs of {name} removed)", f"DELETE {NGFW_PATH}"]
        else:
            requests.append(f"{'PUT ' + NGFW_PATH if existing_ngfw else 'POST ' + NGFW_LIST_PATH}")
            requests.append(f"{'PUT ' + SEC_POLICY_PATH if sec_policy else 'POST ' + SEC_POLICY_LIST_PATH}")
        details_groups = list(await asyncio.gather(*(_group_detail(app, g) for g in groups)))
        reached, read_warn = await reach(app, details_groups, sec["id"] if sec else None, detail)
        warnings += read_warn
        plan = Plan(
            ("Remove" if remove else "Replace" if existing_ngfw else "Create")
            + f" NGFW policy {name} in policy group {gname}",
            details={
                "tier": "dangerous",
                "group": gname,
                "profile": (sec or {}).get("name") or f"{new_profile_name} (new)",
                "before": before,
                "after": None
                if remove
                else {
                    "rules": describe_rules(body["data"], id_names)
                    if body
                    else [r["name"] for r in rule_rows],
                    "zone_pairs": zone_pairs_words,
                },
                "requests": requests,
                **({"body": body} if body else {}),
                "reaches": reached,
                "undo": "remove=true"
                if not existing_ngfw
                else "the same call with the old rules and zone pairs",
                "next": NEXT,
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the policy on the Manager only: the group's edges filter with it after "
                "catsdwan_deploy_policy_group. A zone-based firewall drops what no rule passes, so deploy to "
                "one edge first and check catsdwan_security_status."
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "ngfw": existing_ngfw["raw"].get("lastUpdatedOn") if existing_ngfw else None,
                "policy": sec_policy["raw"].get("lastUpdatedOn") if sec_policy else None,
                "refs": refs,
            },
            blockers=blockers,
            blast_radius=len(_devices(reached)),
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            sec_id = sec["id"] if sec else None
            if new_profile_name:
                sec_id = created_id(
                    await app.api.post(
                        SEC_PROFILES_PATH, {"name": new_profile_name, "description": f"{gname} edge security"}
                    )
                )
                if not sec_id:
                    raise UpstreamError("The Manager created the embedded-security profile without an id.")
                done["profile_created"] = new_profile_name
            if new_profile_name or attach:
                ids = [p["id"] for p in profs] + [str(sec_id)]
                await app.api.put(path(POLICY_GROUP_PATH, id=str(found.get("id"))), update_body(detail, ids))
                done["profile_added_to_group"] = gname
            if sec_id is None:
                raise UpstreamError("No embedded-security profile to write to.")
            if remove and existing_ngfw:
                if sec_policy:
                    data = merge_assembly(sec_policy["data"], existing_ngfw["id"], None)
                    url = path(SEC_POLICY_PATH, id=sec_id, parcel=sec_policy["id"])
                    if data["assembly"]:
                        await app.api.put(url, policy_body(str(sec_policy.get("name")), data))
                    else:
                        await app.api.delete(url)
                await app.api.delete(path(NGFW_PATH, id=sec_id, parcel=existing_ngfw["id"]))
                done["removed"] = name
                return done
            if existing_ngfw:
                await app.api.put(path(NGFW_PATH, id=sec_id, parcel=existing_ngfw["id"]), body)
                ngfw_id: str | None = existing_ngfw["id"]
            else:
                ngfw_id = created_id(await app.api.post(path(NGFW_LIST_PATH, id=sec_id), body))
            if not ngfw_id:
                raise UpstreamError("The Manager stored the NGFW policy without an id: bind it in the GUI.")
            item = assembly_item(ngfw_id, pair_ids)
            if sec_policy:
                data = merge_assembly(sec_policy["data"], ngfw_id, item)
                await app.api.put(
                    path(SEC_POLICY_PATH, id=sec_id, parcel=sec_policy["id"]),
                    policy_body(str(sec_policy.get("name")), data),
                )
            else:
                await app.api.post(
                    path(SEC_POLICY_LIST_PATH, id=sec_id),
                    policy_body(f"{gname}-policy", {"assembly": [item], "settings": {}}),
                )
            done.update(saved=name, id=ngfw_id, zone_pairs=zone_pairs_words)
            done["next"] = (
                "catsdwan_deploy_policy_group(group, devices=[one edge]), then catsdwan_security_status"
            )
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_firewall_policy",
            args={
                "group": group,
                "name": name,
                "rules": rule_rows,
                "zone_pairs": [list(p) for p in pairs_in],
                "default_action": default_action,
                "profile": profile,
                "description": description,
                "remove": remove,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
