"""W45 WAN-edge containment in two paths (owner decision 2026-10-24, "akin to a real-world deployment"):

- Main path, ISE quarantine SGT: catsdwan_set_containment_baseline puts a standing rule on the edges once
  (sequences mcp-quarantine-* in the group's NGFW policies: drop from and to the Quarantine SGT except the
  remediation prefixes; previewed, stored, then deployed in a change window). A host is then contained on ISE
  (ise_apply_anc with an ANC policy whose authorization result assigns the Quarantine SGT; CoA), with no
  Manager change per incident. It needs TrustSec on the edges (W42's enforcement part): the edge must learn
  the host's SGT (inline tagging, SXP or pxGrid) and have its environment data from ISE; the baseline's
  preview and catsdwan_containment_status say per edge what is missing.
- Fallback, a host with no ISE session: catsdwan_contain_at_edge writes one device-specific variable (a slot
  of the baseline's mcp-contain-slots prefix list) on the edge where the host sits and deploys that edge only.
  No parcel of the group and no other device's variables change, so no other edge's intended config changes.
  The record mcp-contain-<ip> (a prefix list no rule references) holds the edge, the slot, the expiry and the
  reason; catsdwan_containment_status shows it (expired ones flagged) and catsdwan_release_at_edge removes
  exactly it and restores the inert slot value.

All writes are always dangerous and preview-first; none touches a sequence, object or variable it did not
create. The prompt catsdwan_contain_host walks both paths.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import json
import time
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    Tier,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
    tool_ref,
)
from cat_sdwan_mcp.changes import device_brief, merge_variables
from cat_sdwan_mcp.client import SdwanApp, last_hours
from cat_sdwan_mcp.configuration import POLICY_GROUPS_PATH, device_variable_lists, path, resolve_group
from cat_sdwan_mcp.containment import (
    INERT,
    MAX_HOURS,
    QUARANTINE_OBJECT,
    SLOT_OBJECT,
    SLOT_RULES,
    SLOT_VARS,
    SLOTS,
    baseline_rules,
    baseline_state,
    contained_at,
    expiry,
    host_ip,
    host_zones,
    is_expired,
    is_slot_object,
    moved_devices,
    ngfw_put_body,
    parse_record,
    pick_slot,
    quarantine_tag_problems,
    record_description,
    record_ip,
    record_name,
    remediation_problems,
    sequence,
    slot_entries,
    slot_values,
    with_baseline,
    without_baseline,
)
from cat_sdwan_mcp.edgefirewall import (
    NGFW_LIST_PATH,
    NGFW_PATH,
    PO_ITEM_PATH,
    PO_LIST_PATH,
    PO_SCHEMA_PATH,
    SEC_POLICY_LIST_PATH,
    by_name,
    describe_rules,
    g,
    object_body,
    object_entries,
    object_values,
    parcels,
    schema_problems,
    sgt_table,
    zone_pairs_of,
)
from cat_sdwan_mcp.events import AUDIT_PATH, audit_row, is_session_noise
from cat_sdwan_mcp.fabric import device_rows, fan_out, reachable, site_ips
from cat_sdwan_mcp.features import POLICY_DEPLOY_PATH
from cat_sdwan_mcp.findhost import ARP_PATH, TRANSPORT_VPNS, match_arp
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve
from cat_sdwan_mcp.policygroups import created_id, group_profiles
from cat_sdwan_mcp.sgtpath import INTERFACE_TRUSTSEC_PATH
from cat_sdwan_mcp.tools.changes import (
    _pending_blockers,
    _reachability_blockers,
    _started,
    dangerous_blockers,
    dangerous_tool,
)
from cat_sdwan_mcp.tools.configuration import _groups
from cat_sdwan_mcp.tools.edgefirewall import (
    _devices,
    _group_detail,
    _schema,
    list_objects,
    object_profile,
    reach,
)
from cat_sdwan_mcp.tools.policygroups import all_memberships, group_devices
from cat_sdwan_mcp.trustsec import EDGE_PATHS, ISE_SGT_PATH, environment, rows_of, unsupported

PG_VARIABLES_PATH = "/dataservice/v1/policy-group/{id}/device/variables"
MAX_EDGES = 25  # edges whose ARP / TrustSec tables are read
TIER_REASON = "WAN-edge containment (W45): deployed, it cuts a host off at its edge"
BASELINE_REASON = (
    "the containment baseline (W45): deployed, it drops quarantined hosts on every edge of the group"
)
OPTIONAL = "skipped if that server is not connected: say so in one line and go on"
TRUSTSEC_NEEDED = (
    "SGT rules match only where the edge knows the host's SGT: TrustSec propagation (inline tagging from the "
    "access switch, SXP from ISE, or pxGrid) and the edge's environment data from ISE (W42)"
)

HostIp = Annotated[str, Field(description="The host's IPv4 address (e.g. 10.61.200.15)")]
GroupRef = Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")]
EdgeRef = Annotated[
    str | None,
    Field(
        description="The host's edge (host name, system IP or chassis); default: located from the edges' "
        "ARP tables (catsdwan_find_host)"
    ),
]
SiteRef = Annotated[str | None, Field(description="Only look for the host at this site (site id or name)")]
VpnRef = Annotated[
    int | None,
    Field(ge=1, le=65530, description="The host's service VPN; default: the VPN its ARP entry is in"),
]
Deploy = Annotated[
    bool,
    Field(
        description="After storing, deploy the policy group to the host's edge only (default true); "
        "false stores"
    ),
]
Wait = Annotated[bool, Field(description="Wait for the deploy to report success or failure")]


def _internal(vpn: Any) -> bool:
    s = str(vpn or "")
    return s.startswith("__") or s in ("65528", "65529", "65530")


def _host(row: dict[str, Any] | None) -> str | None:
    return str(row.get("host") or row.get("system_ip") or row.get("chassis")) if row else None


def _by_chassis(inv: Inventory) -> dict[str, dict[str, Any]]:
    return {str(r["chassis"]): r for r in inv.rows if r.get("chassis")}


# --- reads ---------------------------------------------------------------------------------------


async def locate(
    app: SdwanApp, inv: Inventory, ip: str, edge: str | None, site: str | None, vpn: int | None
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str], list[str]]:
    """(the host's edge row, where it sits {vpn, interface, mac, seen_in}, blockers, warnings) from the
    edges' live ARP tables (W44's source); a given edge is checked rather than searched for."""
    blockers: list[str] = []
    warnings: list[str] = []
    if edge:
        row = resolve(inv, edge)
        if row.get("role") != "edge":
            return None, {}, [f"{edge!r} is not a WAN edge"], []
        candidates = [row] if row in reachable(inv, "edge") else []
        if not candidates:
            warnings.append(f"{row.get('host') or edge} is not reachable: its ARP table was not read")
    else:
        row = None
        candidates = sorted(reachable(inv, "edge"), key=lambda r: str(r.get("host") or r.get("system_ip")))
        if site:
            ips = site_ips(inv, site)
            candidates = [r for r in candidates if str(r.get("system_ip")) in ips]
        if len(candidates) > MAX_EDGES:
            warnings.append(
                f"{len(candidates)} edges: only the first {MAX_EDGES} ARP tables were read (give `site` or "
                "`edge`)"
            )
            candidates = candidates[:MAX_EDGES]
    got = await fan_out(candidates, lambda r: device_rows(app, ARP_PATH, str(r["system_ip"])))
    hits: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for r, res in zip(candidates, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"{r.get('host')}: ARP read failed: {str(res)[:200]}")
            continue
        for h in match_arp(res, "ip", ip):
            v = str(h.get("vpn"))
            if v in TRANSPORT_VPNS or _internal(v) or h.get("entry") == "the edge's own address":
                continue
            if vpn is not None and v != str(vpn):
                continue
            hits.append((r, h))
    if edge:
        assert row is not None
        mine = [h for r, h in hits if r is row]
        if len({str(h.get("vpn")) for h in mine}) > 1:
            listed = ", ".join(sorted({str(h.get("vpn")) for h in mine}))
            blockers.append(f"{ip} is in several VPNs on {row.get('host')} ({listed}): give `vpn`")
        if mine:
            return row, mine[0], blockers, warnings
        if vpn is None:
            blockers.append(
                f"{ip} is not in {row.get('host')}'s ARP table in a service VPN: give `vpn` to contain it "
                "there anyway"
            )
        else:
            warnings.append(f"{ip} is not in {row.get('host')}'s ARP table: contained in VPN {vpn} as given")
        return row, {"vpn": str(vpn) if vpn is not None else None, "seen_in": "given"}, blockers, warnings
    edges = {str(r.get("host") or r.get("system_ip")) for r, _ in hits}
    if not hits:
        where = f" at site {site}" if site else ""
        blockers.append(
            f"{ip} is in no service-VPN ARP table on the edges read{where}: locate it with "
            "catsdwan_find_host, then give `edge` (and `vpn`)"
        )
        return None, {}, blockers, warnings
    if len(edges) > 1:
        blockers.append(
            f"{ip} is in the ARP tables of several edges ({', '.join(sorted(edges))}): give `edge` "
            "(and `vpn` when VPNs overlap)"
        )
        return None, {}, blockers, warnings
    vpns = {str(h.get("vpn")) for _, h in hits}
    if len(vpns) > 1:
        blockers.append(
            f"{ip} is in several VPNs on {', '.join(edges)} ({', '.join(sorted(vpns))}): give `vpn`"
        )
    r, h = hits[0]
    return r, h, blockers, warnings


async def edge_group(
    app: SdwanApp, groups: list[dict[str, Any]], row: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    """The policy group the edge is associated with (by chassis), and read problems."""
    members, warnings = await all_memberships(app, groups)
    name = members.get(str(row.get("chassis")))
    found = next((g for g in groups if str(g.get("name")) == name), None) if name else None
    return found, warnings


async def group_firewall(app: SdwanApp, detail: dict[str, Any]) -> dict[str, Any]:
    """The group's embedded-security profile, NGFW policies, security policies and the policy objects the
    containment uses: {profile, po, ngfws, policies, zones, prefix_lists, sgt_lists, names}."""
    profs = group_profiles(detail)
    sec = next((p for p in profs if p["type"] == "embedded-security"), None)
    po = next((p for p in profs if p["type"] == "policy-object"), None)
    out: dict[str, Any] = {
        "profile": sec,
        "po": po,
        "ngfws": [],
        "policies": [],
        "zones": [],
        "prefix_lists": [],
        "sgt_lists": [],
        "names": {},
    }
    if sec:
        ngfws, pol = await asyncio.gather(
            app.api.get(path(NGFW_LIST_PATH, id=sec["id"])),
            app.api.get(path(SEC_POLICY_LIST_PATH, id=sec["id"])),
        )
        out["ngfws"], out["policies"] = parcels(ngfws), parcels(pol)
    if po:
        out["zones"], out["prefix_lists"], out["sgt_lists"] = await asyncio.gather(
            list_objects(app, po["id"], "security-zone"),
            list_objects(app, po["id"], "security-data-ip-prefix"),
            list_objects(app, po["id"], "security-scalablegrouptag"),
        )
        for key in ("zones", "prefix_lists", "sgt_lists"):
            out["names"].update({z["id"]: str(z.get("name")) for z in out[key]})
    return out


def _pairs(fwl: dict[str, Any], ngfw_id: str) -> list[tuple[str, str]]:
    return [(s, d) for r in fwl["policies"] for rid, s, d in zone_pairs_of(r["data"], ngfw_id)]


def _words(pairs: list[tuple[str, str]], names: dict[str, str]) -> list[str]:
    return [f"{names.get(s, s)} -> {names.get(d, d)}" for s, d in pairs]


async def pg_variables(
    app: SdwanApp, gid: str, chassis: list[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """{chassis: [{name, value?}]} of a policy group's device variables (all devices, or `chassis`)."""
    params = {"device-id": ",".join(chassis)} if chassis else None
    return device_variable_lists(await app.api.get(path(PG_VARIABLES_PATH, id=gid), params))


def _variables_body(group: dict[str, Any], devices: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "solution": group.get("solution") or "sdwan",
        "devices": [{"device-id": c, "variables": v} for c, v in devices.items()],
    }


def readiness(tables: dict[str, list[dict[str, Any]]], missing_tables: list[str]) -> dict[str, Any]:
    """Whether one edge can enforce SGT rules: its environment data from ISE, and a way to learn a host's
    SGT (IP-to-SGT bindings, an SXP connection up, or inline tagging on an interface)."""
    env = environment(rows_of(tables.get("environment", [])))
    bindings = rows_of(tables.get("sgt_map", []))
    sxp_up = sum(
        1
        for r in tables.get("sxp", [])
        if any(str(r.get(k, "")).strip().lower() == "on" for k in ("speaker-state", "listener-state"))
    )
    inline = [r for r in tables.get("inline", []) if r.get("if-name")]
    missing = []
    if not (env or {}).get("downloaded"):
        missing.append("no TrustSec environment data from ISE (the edge has no SGT names or SGACLs)")
    if not (bindings or sxp_up or inline):
        missing.append(
            "no way to learn a host's SGT: no IP-to-SGT binding, no SXP connection up, no inline tagging "
            "(cts manual) on an interface"
        )
    out: dict[str, Any] = {
        "environment_downloaded": (env or {}).get("downloaded", False),
        "sgt_bindings": len(bindings),
        "sxp_up": sxp_up,
        "inline_interfaces": [str(r.get("if-name")) for r in inline],
        "ready": not missing,
    }
    if missing:
        out["missing"] = missing
    if missing_tables:
        out["not_supported"] = missing_tables
    return out


TRUSTSEC_TABLES = {
    "environment": EDGE_PATHS["environment"],
    "sgt_map": EDGE_PATHS["sgt_map"],
    "sxp": EDGE_PATHS["sxp"],
    "inline": INTERFACE_TRUSTSEC_PATH,
}


async def trustsec_readiness(app: SdwanApp, rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """({edge: readiness}, warnings) for up to MAX_EDGES reachable edges."""
    warnings: list[str] = []
    if len(rows) > MAX_EDGES:
        warnings.append(f"TrustSec read on the first {MAX_EDGES} of {len(rows)} edges only")
        rows = rows[:MAX_EDGES]

    async def one(r: dict[str, Any]) -> dict[str, Any]:
        keys = list(TRUSTSEC_TABLES)
        got = await asyncio.gather(
            *(device_rows(app, TRUSTSEC_TABLES[k], str(r["system_ip"])) for k in keys), return_exceptions=True
        )
        tables: dict[str, list[dict[str, Any]]] = {}
        missing: list[str] = []
        for k, res in zip(keys, got, strict=True):
            if isinstance(res, UpstreamError):
                if unsupported(str(res)):
                    missing.append(k)
                else:
                    warnings.append(f"{_host(r)}: {k} not read: {str(res)[:150]}")
                tables[k] = []
            elif isinstance(res, BaseException):
                raise res
            else:
                tables[k] = res
        return readiness(tables, missing)

    results = await asyncio.gather(*(one(r) for r in rows))
    return {str(_host(r)): res for r, res in zip(rows, results, strict=True)}, warnings


async def manager_audit(app: SdwanApp, since_ms: int, words: set[str]) -> list[dict[str, Any]] | str:
    """The Manager's audit entries since `since_ms` that name one of `words` (the change just made)."""
    try:
        result = await app.query(AUDIT_PATH, last_hours(1), limit=200)
    except UpstreamError as e:
        return f"not read: {str(e)[:150]} (catsdwan_audit_log(changes_only=true, since_hours=1))"
    rows = []
    for a in result.rows:
        try:
            t = int(a.get("entry_time") or 0)
        except (TypeError, ValueError):
            t = 0
        text = json.dumps(a, default=str)
        if t >= since_ms - 60_000 and not is_session_noise(a) and any(w and w in text for w in words):
            rows.append(audit_row(a))
    return (
        rows[:8] or "none yet (the Manager may log it a little later): catsdwan_audit_log(changes_only=true)"
    )


async def _deploy(
    app: SdwanApp, ctx: Context, gid: str, gname: str, rows: list[dict[str, Any]], wait: bool
) -> dict[str, Any]:
    body = {"devices": [{"id": str(r["chassis"])} for r in rows]}
    answer = await app.api.post(path(POLICY_DEPLOY_PATH, id=gid), body)
    names = ", ".join(str(_host(r)) for r in rows)
    return await _started(app, ctx, answer, wait, f"deploy of policy group {gname} to {names}")


async def _deploy_blockers(app: SdwanApp, row: dict[str, Any]) -> tuple[list[str], list[str]]:
    blockers = []
    if row.get("config_mode") == "template":
        blockers.append(
            f"{row.get('host')} is on device template {row.get('config') or '?'}: edge firewall rules "
            "live in policy groups, for configuration-group devices"
        )
    if not row.get("chassis"):
        blockers.append(f"{row.get('host')} has no chassis number: the Manager can't deploy to it")
    blockers += _reachability_blockers([row])
    busy, warnings = await _pending_blockers(app, [row])
    return blockers + busy, warnings


def _by_name(variables: list[dict[str, Any]]) -> dict[str, Any]:
    return {str(v.get("name")): v.get("value") for v in variables}


def _record_view(rec_obj: dict[str, Any]) -> dict[str, Any]:
    desc = (rec_obj.get("raw") or {}).get("payload", {}).get("description")
    fields = parse_record(desc)
    ip = record_ip(rec_obj.get("name"))
    return {
        "ip": ip,
        "record": rec_obj.get("name"),
        **{
            k: fields[k]
            for k in ("edge", "chassis", "group", "slot", "vpn", "expires", "reason")
            if k in fields
        },
        "expired": is_expired(fields.get("expires")),
    }


def register(reg: ToolRegistrar) -> None:
    # --- the standing baseline (main path + the fallback's slots) --------------------------------

    @dangerous_tool(reg, title="Set the SD-WAN containment baseline")
    async def catsdwan_set_containment_baseline(
        ctx: Context,
        group: GroupRef,
        quarantine_sgt: Annotated[
            str | None,
            Field(
                description="The Quarantine SGT ISE's ANC result assigns: '<name>:<tag>' (e.g. "
                "'Quarantined_Systems:255'), a tag or an ISE SGT name; adds the mcp-quarantine-* rules"
            ),
        ] = None,
        remediation: Annotated[
            list[str] | None,
            Field(
                description="IPv4 prefixes contained hosts may still reach (remediation server, DNS; at most "
                "16); default none"
            ),
        ] = None,
        edge_slots: Annotated[
            bool,
            Field(
                description="Also add the per-device edge slots (mcp-contain-slots-*) the no-ISE fallback "
                "catsdwan_contain_at_edge uses (default true)"
            ),
        ] = True,
        remove: Annotated[bool, Field(description="Take the baseline's rules out instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Check or set the standing containment rules of a policy group's edge firewall (W45, set once in a
        change window, not per incident). At the top of each NGFW policy bound to a zone pair:
        mcp-quarantine-allow-out/-in (pass the Quarantine SGT to and from `remediation`) and
        mcp-quarantine-out/-in (drop from and to the SGT list mcp-quarantine-sgt, logged): ISE then
        contains a host with ise_apply_anc alone. With edge_slots: mcp-contain-slots-allow-out/-in and
        -out/-in matching the prefix list mcp-contain-slots, whose four entries are per-device variables
        {{mcp_contain_1..4}} holding inert documentation addresses (192.0.2.241-244/32) on every device until
        catsdwan_contain_at_edge writes one edge's slot. Every other rule keeps its order. Preview-first: each
        NGFW policy's rules before and after, the objects created, the devices the deploy reaches, and per
        edge whether TrustSec can enforce SGT rules (environment data from ISE; SGT learned by binding, SXP or
        inline tagging): without it the quarantine rules match nothing there. In place already: the preview
        says so. Confirm stores the objects and rules and fills the inert slot values; deploy with
        catsdwan_deploy_policy_group. remove=true takes the rules out (blocked while a slot holds a host).
        Dangerous."""
        app: SdwanApp = get_client(ctx)
        fix = [r.strip() for r in remediation or [] if r and r.strip()]
        quarantine = bool(quarantine_sgt and quarantine_sgt.strip())
        if not remove and not quarantine and not edge_slots:
            raise InvalidRequest("Give quarantine_sgt, or edge_slots=true, or remove=true.")
        all_groups = await _groups(app, POLICY_GROUPS_PATH)
        found = resolve_group(all_groups, group, "policy group")
        gname, gid = str(found.get("name")), str(found.get("id"))
        detail = await _group_detail(app, found)
        blockers = dangerous_blockers(ctx, app, [BASELINE_REASON])
        blockers += remediation_problems(fix)
        warnings: list[str] = []
        fwl = await group_firewall(app, detail)
        if fwl["profile"] is None or not fwl["ngfws"]:
            blockers.append(
                f"policy group {gname} has no NGFW policy, so its edges have no firewall to hold the "
                "baseline. "
                "Add one first: catsdwan_set_security_object(kind='zone', values=[<service VPN>]) and "
                "catsdwan_set_firewall_policy(group, zone_pairs=[...], default_action='pass')"
            )
        if fwl["po"] is None:
            blockers.append(f"policy group {gname} has no policy-object profile for the baseline's objects")

        # Objects: the Quarantine SGT list and the slot prefix list (created when missing, never others').
        sgt_obj = by_name(fwl["sgt_lists"], QUARANTINE_OBJECT)
        slot_obj = by_name(fwl["prefix_lists"], SLOT_OBJECT)
        sgt_body: dict[str, Any] | None = None
        slot_body: dict[str, Any] | None = None
        objects: dict[str, Any] = {}
        if not remove and quarantine:
            sgts: dict[str, str] = {}
            try:
                sgts = sgt_table(await app.api.get(ISE_SGT_PATH))
            except UpstreamError as e:
                warnings.append(f"ISE SGTs not read on the Manager (give '<name>:<tag>'): {str(e)[:150]}")
            entries, problems = object_entries("sgt", [str(quarantine_sgt)], sgts)
            blockers += [f"quarantine_sgt: {p}" for p in problems]
            if len(entries) != 1:
                blockers.append("quarantine_sgt: give exactly one SGT")
            blockers += [f"quarantine_sgt: {p}" for p in quarantine_tag_problems(entries)]
            body = object_body(
                QUARANTINE_OBJECT, "mcp containment baseline: the Quarantine SGT ISE ANC assigns", entries
            )
            new_vals = object_values("sgt", body["data"])
            old_vals = object_values("sgt", sgt_obj["data"]) if sgt_obj else None
            objects[QUARANTINE_OBJECT] = {"before": old_vals, "after": new_vals}
            if old_vals != new_vals:
                sgt_body = body
                schema, why = await _schema(
                    app,
                    path(PO_SCHEMA_PATH, list_type="security-scalablegrouptag"),
                    "put" if sgt_obj else "post",
                )
                if why:
                    warnings.append(why)
                blockers += schema_problems(schema, body)
        if not remove and edge_slots:
            if slot_obj and not is_slot_object(slot_obj["data"]):
                blockers.append(
                    f"a prefix list named {SLOT_OBJECT} exists with other entries: not this tool's; rename it"
                )
            objects[SLOT_OBJECT] = {
                "entries": ["{{" + v + "}}" for v in SLOT_VARS],
                "state": "in place" if slot_obj else "created",
            }
            if not slot_obj:
                slot_body = object_body(
                    SLOT_OBJECT,
                    "mcp containment baseline: per-device slots for catsdwan_contain_at_edge",
                    slot_entries(),
                )
                schema, why = await _schema(
                    app, path(PO_SCHEMA_PATH, list_type="security-data-ip-prefix"), "post"
                )
                if why:
                    warnings.append(why)
                blockers += schema_problems(schema, slot_body)

        def refs(sgt_id: str, slot_id: str) -> dict[str, dict[str, str]]:
            return {"sgt": {QUARANTINE_OBJECT: sgt_id}, "prefix": {SLOT_OBJECT: slot_id}}

        names = dict(fwl["names"])
        sgt_ref = sgt_obj["id"] if sgt_obj else f"<new {QUARANTINE_OBJECT}>"
        slot_ref = slot_obj["id"] if slot_obj else f"<new {SLOT_OBJECT}>"
        names.setdefault(sgt_ref, QUARANTINE_OBJECT)
        names.setdefault(slot_ref, SLOT_OBJECT)
        rules = baseline_rules(
            slots=edge_slots and not remove, quarantine=quarantine and not remove, remediation=fix
        )

        def changed_data(n: dict[str, Any], sgt_id: str, slot_id: str) -> tuple[dict[str, Any], list[str]]:
            if remove:
                return without_baseline(n["data"])
            return with_baseline(n["data"], [sequence(r, refs(sgt_id, slot_id)) for r in rules])

        changes: list[dict[str, Any]] = []
        unbound: list[str] = []
        for n in fwl["ngfws"]:
            pairs = _pairs(fwl, n["id"])
            if not pairs:
                unbound.append(str(n.get("name")))
                continue
            new, old = changed_data(n, sgt_ref, slot_ref)
            if new == n["data"]:
                continue
            changes.append(
                {
                    "row": n,
                    "new": new,
                    "view": {
                        "ngfw_policy": n.get("name"),
                        "zone_pairs": _words(pairs, fwl["names"]),
                        **({"replaces" if not remove else "removes": old} if old else {}),
                        "before": describe_rules(n["data"], names),
                        "after": describe_rules(new, names),
                    },
                }
            )

        if fwl["ngfws"] and len(unbound) == len(fwl["ngfws"]):
            blockers.append(
                f"no NGFW policy of {gname} is bound to a zone pair (it filters nothing): bind one with "
                "catsdwan_set_firewall_policy(zone_pairs=...)"
            )

        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        members: list[dict[str, Any]] = []
        try:
            members = await group_devices(app, gid)
        except UpstreamError as e:
            warnings.append(f"policy group devices not read: {str(e)[:200]}")
        drops_slots = any(
            baseline_state(c["row"]["data"])["edge_slots"] and not baseline_state(c["new"])["edge_slots"]
            for c in changes
        )
        drops_quarantine = [
            str(c["view"]["ngfw_policy"])
            for c in changes
            if baseline_state(c["row"]["data"])["quarantine"] and not baseline_state(c["new"])["quarantine"]
        ]
        if drops_quarantine and not remove:
            warnings.append(
                f"no quarantine_sgt given: the mcp-quarantine-* rules of {', '.join(drops_quarantine)} "
                "are taken out (give quarantine_sgt to keep them)"
            )
        if drops_slots:
            try:
                held = {
                    str(_host(chassis_rows.get(c)) or c): contained_at(slot_values(v))
                    for c, v in (await pg_variables(app, gid)).items()
                }
                held = {k: v for k, v in held.items() if v}
                if held:
                    blockers.append(
                        f"edge slots hold contained hosts ({held}) and this takes the slot rules out: "
                        "release them first (catsdwan_release_at_edge), or contain them through ISE"
                    )
            except UpstreamError as e:
                warnings.append(f"device variables not read: {str(e)[:150]}")

        # Who gets it, and can they enforce SGT rules.
        details_all = list(await asyncio.gather(*(_group_detail(app, g) for g in all_groups)))
        reached, read_warn = await reach(app, details_all, (fwl["profile"] or {}).get("id"), extra=detail)
        warnings += read_warn
        trustsec: dict[str, Any] = {}
        if quarantine and not remove:
            rows = [
                r
                for d in members
                if (r := chassis_rows.get(str(d.get("chassis")))) and r in reachable(inv, "edge")
            ]
            trustsec, ts_warn = await trustsec_readiness(app, rows)
            warnings += ts_warn
            not_ready = [e for e, r in trustsec.items() if not r["ready"]]
            if not_ready:
                warnings.append(
                    f"TrustSec is not ready on {', '.join(not_ready)}: the quarantine rules match nothing "
                    "there "
                    f"until it is ({TRUSTSEC_NEEDED}); the fallback catsdwan_contain_at_edge still works"
                )
        in_place = not changes and sgt_body is None and slot_body is None
        devices = _devices(reached)
        requests = (
            ([f"{'PUT' if sgt_obj else 'POST'} {PO_LIST_PATH} ({QUARANTINE_OBJECT})"] if sgt_body else [])
            + ([f"POST {PO_LIST_PATH} ({SLOT_OBJECT})"] if slot_body else [])
            + [f"PUT {NGFW_PATH} ({c['view']['ngfw_policy']})" for c in changes]
            + (
                [f"PUT {PG_VARIABLES_PATH} (each policy group: unset mcp_contain_* get their inert value)"]
                if edge_slots and not remove
                else []
            )
        )
        what = "Remove the containment baseline from" if remove else "Set the containment baseline in"
        plan = Plan(
            f"The containment baseline is in place in {gname}: nothing to change"
            if in_place and not remove
            else f"No containment baseline in {gname}: nothing to remove"
            if remove and not changes
            else f"{what} policy group {gname} ({len(changes)} NGFW policy(ies))",
            details={
                "tier": "dangerous",
                "group": gname,
                "profile": (fwl["profile"] or {}).get("name"),
                "rules": [r["name"] for r in rules] if not remove else [],
                "remediation": fix,
                "objects": objects,
                "policies": [c["view"] for c in changes],
                **({"unbound_policies_left_alone": unbound} if unbound else {}),
                "requests": requests,
                "inert_slot_values": INERT if edge_slots and not remove else {},
                "reaches": reached,
                **({"trustsec": trustsec} if trustsec else {}),
                "needs": TRUSTSEC_NEEDED if quarantine and not remove else None,
                "next": f"catsdwan_deploy_policy_group(group='{gname}', devices=[every edge of the group]) "
                "in a change window, then catsdwan_containment_status(group)",
                "undo": f"catsdwan_set_containment_baseline(group='{gname}', remove=true)",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores on the Manager only. Once deployed, every edge of the group(s) above drops traffic "
                "from and to the Quarantine SGT (except remediation) and from and to its own slot hosts; "
                "with every slot inert, the slot rules match only unused documentation addresses.",
                *(
                    [
                        f"{SLOT_OBJECT} lives in the shared policy-object profile: in EVERY policy group, "
                        "devices whose mcp_contain_* variables are unset get the inert values (values only, "
                        "nothing deployed; checked after each write, stopped if another device's values "
                        "moved); the result's inert_slots_filled names them."
                    ]
                    if edge_slots
                    else []
                ),
            ]
            if not remove
            else ["Once deployed, the edges no longer drop quarantined hosts."],
            fingerprint={
                "group": [detail.get("lastUpdatedOn"), detail.get("version")],
                "ngfw": {c["row"]["id"]: c["row"]["raw"].get("lastUpdatedOn") for c in changes},
                "objects": [
                    (sgt_obj or {}).get("raw", {}).get("lastUpdatedOn"),
                    (slot_obj or {}).get("raw", {}).get("lastUpdatedOn"),
                ],
            },
            blockers=blockers,
            blast_radius=len(devices),
        )

        async def apply() -> Any:
            po_id = fwl["po"]["id"]
            sgt_id = sgt_obj["id"] if sgt_obj else ""
            slot_id = slot_obj["id"] if slot_obj else ""
            out: dict[str, Any] = {"group": gname}
            if sgt_body is not None:
                url = path(PO_LIST_PATH, profile=po_id, list_type="security-scalablegrouptag")
                if sgt_obj:
                    await app.api.put(
                        path(
                            PO_ITEM_PATH, profile=po_id, list_type="security-scalablegrouptag", parcel=sgt_id
                        ),
                        sgt_body,
                    )
                else:
                    sgt_id = created_id(await app.api.post(url, sgt_body)) or ""
                    if not sgt_id:
                        found_obj = by_name(
                            await list_objects(app, po_id, "security-scalablegrouptag"), QUARANTINE_OBJECT
                        )
                        sgt_id = found_obj["id"] if found_obj else ""
                out["stored_objects"] = [QUARANTINE_OBJECT]
            if slot_body is not None:
                url = path(PO_LIST_PATH, profile=po_id, list_type="security-data-ip-prefix")
                slot_id = created_id(await app.api.post(url, slot_body)) or ""
                if not slot_id:
                    found_obj = by_name(
                        await list_objects(app, po_id, "security-data-ip-prefix"), SLOT_OBJECT
                    )
                    slot_id = found_obj["id"] if found_obj else ""
                out.setdefault("stored_objects", []).append(SLOT_OBJECT)
            if not remove and ((quarantine and not sgt_id) or (edge_slots and not slot_id)):
                raise UpstreamError("the Manager returned no id for a new object: nothing else was changed")
            sec_id = fwl["profile"]["id"]
            for c in changes:
                data, _ = changed_data(c["row"], sgt_id, slot_id)
                await app.api.put(
                    path(NGFW_PATH, id=sec_id, parcel=c["row"]["id"]), ngfw_put_body(c["row"], data)
                )
            out["policies"] = [c["view"]["ngfw_policy"] for c in changes]
            if edge_slots and not remove:
                filled: dict[str, list[str]] = {}
                problems: list[str] = []
                for grp in all_groups:
                    try:
                        cur = await pg_variables(app, str(grp.get("id")))
                    except UpstreamError as e:
                        problems.append(f"{grp.get('name')}: variables not read: {str(e)[:150]}")
                        continue
                    todo: dict[str, list[dict[str, Any]]] = {}
                    for ch, variables in cur.items():
                        vals = slot_values(variables)
                        unset = {s: INERT[s] for s, v in vals.items() if v in (None, "")}
                        if unset:
                            todo[ch] = merge_variables(variables, unset)[0]
                    if todo:
                        await app.api.put(
                            path(PG_VARIABLES_PATH, id=str(grp.get("id"))), _variables_body(grp, todo)
                        )
                        filled[str(grp.get("name"))] = [str(_host(chassis_rows.get(c)) or c) for c in todo]
                        # Safety stop: the devices not in this PUT must keep their values.
                        rest = {c: _by_name(v) for c, v in cur.items() if c not in todo}
                        moved = moved_devices(rest, await pg_variables(app, str(grp.get("id"))))
                        if moved:
                            names = ", ".join(str(_host(chassis_rows.get(c)) or c) for c in moved)
                            raise UpstreamError(
                                f"after the inert-value write in policy group {grp.get('name')}, the "
                                f"variables of {names} differ from before: stopped (nothing is deployed by "
                                f"this tool). Filled so far: {filled}. Check with catsdwan_get_config_group "
                                "/ catsdwan_containment_status before any deploy"
                            )
                out["inert_slots_filled"] = filled
                if problems:
                    out["warnings"] = problems
            out["next"] = (
                f"catsdwan_deploy_policy_group(group='{gname}', devices=[...]) to every edge of the group "
                "in a change window (preview first), then catsdwan_containment_status(group)"
            )
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_containment_baseline",
            args={
                "group": group,
                "quarantine_sgt": quarantine_sgt,
                "remediation": fix,
                "edge_slots": edge_slots,
                "remove": remove,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    # --- fallback: one edge's slot -----------------------------------------------------------------

    @dangerous_tool(reg, title="Contain a host at its SD-WAN edge only")
    async def catsdwan_contain_at_edge(
        ctx: Context,
        ip: HostIp,
        reason: Annotated[
            str,
            Field(min_length=1, max_length=200, description="Why (ticket or alert); kept in the record"),
        ],
        hours: Annotated[
            int, Field(ge=1, le=MAX_HOURS, description="Time box: the record's expiry, in hours (default 24)")
        ] = 24,
        site: SiteRef = None,
        edge: EdgeRef = None,
        vpn: VpnRef = None,
        deploy: Deploy = True,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Fallback containment for a host with NO ISE session (with one, use ISE ANC: the prompt
        catsdwan_contain_host): drop it at the one edge where it sits and nowhere else. Locates the host from
        the edges' live ARP tables (or the `edge` given), then writes ONE device variable of that edge, a free
        slot {{mcp_contain_N}} of the standing baseline's prefix list mcp-contain-slots (matched by the
        mcp-contain-slots-* drop rules), and deploys the policy group to that edge only. No parcel of the
        group and no other device's variables change, so no other edge's intended config changes; the preview
        names the single device and lists every other device of the group as unchanged. The record
        mcp-contain-<ip> (a prefix list no rule references) holds the edge, slot, VPN, expiry (`hours`) and
        reason: catsdwan_containment_status shows it and flags it once expired (nothing releases it by
        itself). The result names the Manager's audit entries. Blocked when the group has no baseline slot
        rules on the host's VPN (catsdwan_set_containment_baseline, deployed), all 4 slots of the edge are in
        use, or the host is contained at another edge. Undo: catsdwan_release_at_edge. Dangerous."""
        try:
            addr = host_ip(ip)
        except ValueError as e:
            raise InvalidRequest(str(e)) from None
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON])
        row, where, loc_block, warnings = await locate(app, inv, addr, edge, site, vpn)
        blockers += loc_block
        warnings = list(inv.warnings) + warnings
        host_vpn = str(vpn) if vpn is not None else (str(where["vpn"]) if where.get("vpn") else None)
        if host_vpn is not None and (host_vpn in TRANSPORT_VPNS or _internal(host_vpn)):
            blockers.append(
                f"VPN {host_vpn} is a transport, management or internal VPN: containment is for hosts in a "
                "service VPN (dropping there could cut the edge's own management path)"
            )
        fabric = [r for r in inv.rows if str(r.get("system_ip") or "") == addr]
        if fabric:
            blockers.append(
                f"{addr} is the system IP of {fabric[0].get('host') or 'a fabric device'}: "
                "not a host to contain"
            )
        groups = await _groups(app, POLICY_GROUPS_PATH)
        host_name = _host(row)
        chassis = str((row or {}).get("chassis") or "")

        group: dict[str, Any] | None = None
        detail: dict[str, Any] = {}
        fwl: dict[str, Any] = {"ngfws": [], "prefix_lists": [], "po": None, "names": {}}
        covering: list[dict[str, Any]] = []
        current: list[dict[str, Any]] = []
        others_before: dict[str, dict[str, Any]] = {}
        merged: list[dict[str, Any]] = []
        slot: str | None = None
        already = False
        rec_obj: dict[str, Any] | None = None
        members: list[str] = []
        if row is not None:
            group, read_warn = await edge_group(app, groups, row)
            warnings += read_warn
            if group is None:
                blockers.append(
                    f"{host_name} is in no policy group: the fallback needs the group's baseline "
                    "(catsdwan_associate_policy_group, then catsdwan_set_containment_baseline)"
                )
        gname = str(group.get("name")) if group else None
        if group is not None and row is not None:
            detail = await _group_detail(app, group)
            try:
                fwl = await group_firewall(app, detail)
            except UpstreamError as e:
                blockers.append(f"policy group {gname}: firewall not read: {str(e)[:200]}")
            zones = host_zones(fwl.get("zones", []), host_vpn, where.get("interface"))
            for n in fwl["ngfws"]:
                pairs = _pairs(fwl, n["id"])
                if baseline_state(n["data"])["edge_slots"] and any(
                    s in zones or d in zones for s, d in pairs
                ):
                    covering.append(
                        {"ngfw_policy": n.get("name"), "zone_pairs": _words(pairs, fwl["names"]), "row": n}
                    )
            slot_obj = by_name(fwl["prefix_lists"], SLOT_OBJECT)
            if not covering or not slot_obj or not is_slot_object(slot_obj["data"]):
                blockers.append(
                    f"policy group {gname} has no standing edge slot (the {SLOT_OBJECT} list and the "
                    f"{SLOT_RULES[2]}/-in rules in an NGFW policy whose zone pairs reach VPN "
                    f"{host_vpn or '?'}). Set it once: catsdwan_set_containment_baseline(group='{gname}'), "
                    "deploy it to the group's "
                    "edges, then contain here; only this edge changes per incident"
                )
            try:
                every = await pg_variables(app, str(group["id"]))
                current = every.get(chassis, [])
                others_before = {c: _by_name(v) for c, v in every.items() if c != chassis}
            except UpstreamError as e:
                blockers.append(f"{host_name}'s variables in {gname} not read: {str(e)[:200]}")
            values = slot_values(current)
            if not values and not any("standing edge slot" in b for b in blockers):
                blockers.append(
                    f"{host_name} has no {SLOT_VARS[0]}..{SLOT_VARS[-1]} variables in {gname}: the baseline "
                    "was "
                    "not stored for it (run catsdwan_set_containment_baseline again)"
                )
            slot, already = pick_slot(values, addr)
            if values and slot is None:
                blockers.append(
                    f"all {SLOTS} slots of {host_name} hold hosts ({contained_at(values)}): release one "
                    "(catsdwan_release_at_edge) or contain this host through ISE"
                )
            if slot:
                merged, _, _ = merge_variables(current, {slot: f"{addr}/32"})
            rec_obj = by_name(fwl["prefix_lists"], record_name(addr))
            if rec_obj:
                rec = parse_record((rec_obj["raw"].get("payload") or {}).get("description"))
                if not rec:
                    blockers.append(
                        f"a prefix list named {record_name(addr)} exists that is not a containment record"
                    )
                elif rec.get("chassis") and rec["chassis"] != chassis:
                    blockers.append(
                        f"{addr} is already contained at {rec.get('edge')}: release it there first "
                        f"(catsdwan_release_at_edge(ip='{addr}'))"
                    )
            try:
                assoc = await group_devices(app, str(group["id"]))
                members = [str(d.get("host") or d.get("chassis")) for d in assoc]
                mine = next((d for d in assoc if str(d.get("chassis")) == chassis), {})
                if mine.get("group_up_to_date") is False:
                    warnings.append(
                        f"{host_name} is not up to date with policy group {gname}: the deploy also pushes "
                        "the group's other stored changes to it (catsdwan_deploy_policy_group's preview "
                        "shows them)"
                    )
            except UpstreamError as e:
                warnings.append(f"policy group devices not read: {str(e)[:200]}")
        if deploy and row is not None:
            more, busy_warn = await _deploy_blockers(app, row)
            blockers += more
            warnings += busy_warn
        if not deploy:
            warnings.append("deploy=false: stored only; the edge drops nothing until deployed")

        expires = expiry(hours)
        rname = record_name(addr)
        rec_body = object_body(
            rname,
            record_description(
                edge=str(host_name),
                chassis=chassis,
                group=str(gname),
                slot=str(slot),
                vpn=host_vpn,
                expires=expires,
                reason=reason,
            ),
            [{"ipPrefix": g(f"{addr}/32")}],
        )
        if fwl.get("po"):
            schema, why = await _schema(
                app, path(PO_SCHEMA_PATH, list_type="security-data-ip-prefix"), "put" if rec_obj else "post"
            )
            if why:
                warnings.append(why)
            blockers += schema_problems(schema, rec_body)
        others = [m for m in members if m != host_name]
        old_value = next((v.get("value") for v in current if v.get("name") == slot), None)
        requests = [
            f"{'PUT' if rec_obj else 'POST'} {PO_LIST_PATH} ({rname}: record, referenced by no rule)",
            f"PUT {PG_VARIABLES_PATH} {{devices: [{{device-id: <{host_name} chassis>, variables}}]}} "
            "(this device "
            "only)",
        ] + ([f"POST {POLICY_DEPLOY_PATH} {{devices: [{{id: <{host_name} chassis>}}]}}"] if deploy else [])
        plan = Plan(
            f"Contain {addr} at {host_name or '?'} only"
            + (f" (site {row.get('site_id')}, VPN {host_vpn}, slot {slot})" if row else "")
            + f" until {expires}",
            details={
                "tier": "dangerous",
                "ip": addr,
                "reason": reason,
                "device": device_brief(row) if row else None,
                "where": {k: v for k, v in {**where, "vpn": host_vpn}.items() if v not in (None, "")},
                "group": gname,
                "slot": {"variable": slot, "from": old_value, "to": f"{addr}/32", "already_held": already},
                "record": {
                    "name": rname,
                    "state": "replaced (expiry renewed)" if rec_obj else "created",
                    "description": rec_body["description"],
                },
                "expires": expires,
                "enforced_by": [{k: v for k, v in c.items() if k != "row"} for c in covering],
                "proof": {
                    "devices_changed": [host_name] if host_name else [],
                    "group_parcels_changed": [],
                    "other_devices": {
                        m: "unchanged: same parcels and variables, nothing new at its next deploy"
                        for m in others
                    },
                    "why": "the only stored changes are this device's slot variable and an unreferenced "
                    "record",
                },
                "requests": requests,
                "deployed_to": [host_name] if deploy and host_name else [],
                "audit": "the result names the Manager's audit entries for the variables write and the "
                "deploy; "
                "the MCP audit log has this call's 'applied' event",
                "undo": f"catsdwan_release_at_edge(ip='{addr}')",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                f"Once deployed, {host_name or 'the edge'} drops every flow from and to {addr} (logged), "
                "except "
                "the baseline's remediation prefixes. No other edge changes.",
                f"Nothing releases it at {expires} by itself: catsdwan_containment_status flags it expired.",
            ],
            fingerprint={
                "group": [detail.get("lastUpdatedOn"), detail.get("version")] if detail else None,
                "variables": current,
                "other_devices_variables": others_before,
                "record": (rec_obj or {}).get("raw", {}).get("lastUpdatedOn") if rec_obj else None,
                "ngfw": {c["row"]["id"]: c["row"]["raw"].get("lastUpdatedOn") for c in covering},
                "edge": chassis,
            },
            blockers=blockers,
            blast_radius=1 if deploy and row else 0,
        )

        async def apply() -> Any:
            assert row is not None and group is not None and slot is not None
            started = int(time.time() * 1000)
            po_id = fwl["po"]["id"]
            if rec_obj:
                await app.api.put(
                    path(
                        PO_ITEM_PATH, profile=po_id, list_type="security-data-ip-prefix", parcel=rec_obj["id"]
                    ),
                    rec_body,
                )
            else:
                await app.api.post(
                    path(PO_LIST_PATH, profile=po_id, list_type="security-data-ip-prefix"), rec_body
                )
            await app.api.put(
                path(PG_VARIABLES_PATH, id=str(group["id"])), _variables_body(group, {chassis: merged})
            )
            # Safety stop: the write must not have changed any other device's variables.
            after = await pg_variables(app, str(group["id"]))
            moved = moved_devices(others_before, after)
            if moved:
                names = ", ".join(str(_host(_by_chassis(inv).get(c)) or c) for c in moved)
                raise UpstreamError(
                    f"after the variables write, the variables of {names} differ from before: nothing "
                    "was deployed. Check with catsdwan_containment_status; undo with "
                    f"catsdwan_release_at_edge(ip='{addr}')"
                )
            out: dict[str, Any] = {
                "contained": addr,
                "edge": host_name,
                "vpn": host_vpn,
                "group": gname,
                "slot": slot,
                "record": rname,
                "expires": expires,
                "reason": reason,
            }
            if deploy:
                out["deploy"] = await _deploy(app, ctx, str(group["id"]), str(gname), [row], wait)
            else:
                out["next"] = f"catsdwan_deploy_policy_group(group='{gname}', devices=['{host_name}'])"
            out["audit"] = {
                "manager": await manager_audit(
                    app, started, {str(gname), str(row.get("system_ip")), chassis}
                ),
                "mcp": "event 'applied' for catsdwan_contain_at_edge in the MCP audit log (MCP_AUDIT_LOG)",
            }
            out["release_with"] = f"catsdwan_release_at_edge(ip='{addr}')"
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_contain_at_edge",
            args={
                "ip": ip,
                "reason": reason,
                "hours": hours,
                "site": site,
                "edge": edge,
                "vpn": vpn,
                "deploy": deploy,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @dangerous_tool(reg, title="Release a host contained at its SD-WAN edge")
    async def catsdwan_release_at_edge(
        ctx: Context,
        ip: HostIp,
        deploy: Deploy = True,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Undo catsdwan_contain_at_edge: put the inert value back into exactly the slot variable(s) holding
        this host (every policy group's devices are searched, so a slot without a record is found too),
        delete exactly its record mcp-contain-<ip>, and deploy the group to that edge only. No other slot,
        variable, rule or object changes. Preview-first: the device, the slot from -> to, the record.
        Idempotent: a host that is not contained changes nothing. A host quarantined through ISE is released
        on ISE (ise_clear_anc), not here. Dangerous."""
        try:
            addr = host_ip(ip)
        except ValueError as e:
            raise InvalidRequest(str(e)) from None
        app: SdwanApp = get_client(ctx)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON.replace("cuts a host off", "lets a host back")])
        warnings: list[str] = []
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        groups = await _groups(app, POLICY_GROUPS_PATH)
        rname = record_name(addr)
        rec_obj: dict[str, Any] | None = None
        po_id: str | None = None
        details = list(await asyncio.gather(*(_group_detail(app, g) for g in groups)))
        po_ids = list(
            dict.fromkeys(p["id"] for d in details for p in group_profiles(d) if p["type"] == "policy-object")
        )
        if not po_ids:
            try:
                po_ids = [(await object_profile(app))["id"]]
            except (NotFound, InvalidRequest, UpstreamError) as e:
                warnings.append(f"records not read: {str(e)[:150]}")
        for pid in po_ids:
            try:
                rec_obj = by_name(await list_objects(app, pid, "security-data-ip-prefix"), rname)
            except UpstreamError as e:
                warnings.append(f"records not read in profile {pid}: {str(e)[:150]}")
                continue
            if rec_obj:
                po_id = pid
                break
        if rec_obj and not parse_record((rec_obj["raw"].get("payload") or {}).get("description")):
            warnings.append(f"{rname} is not a containment record: left alone")
            rec_obj = None

        holders: list[dict[str, Any]] = []
        group_vars: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for grp in groups:
            try:
                cur = await pg_variables(app, str(grp.get("id")))
            except UpstreamError as e:
                warnings.append(f"policy group {grp.get('name')}: variables not read: {str(e)[:150]}")
                continue
            group_vars[str(grp.get("id"))] = cur
            for ch, variables in cur.items():
                slots = [s for s, h in contained_at(slot_values(variables)).items() if h == addr]
                if slots:
                    holders.append(
                        {
                            "group": grp,
                            "chassis": ch,
                            "row": chassis_rows.get(ch),
                            "slots": slots,
                            "before": variables,
                            "after": merge_variables(variables, {s: INERT[s] for s in slots})[0],
                        }
                    )
        contained = bool(holders or rec_obj)
        if rec_obj and not holders:
            warnings.append(f"record {rname} but no slot holds {addr}: only the record is deleted")
        targets = [h for h in holders if h["row"] is not None]
        for h in holders:
            if h["row"] is None:
                warnings.append(f"{h['chassis']} is not in the inventory: its slot is reset, not deployed")
        if deploy and contained:
            for h in targets:
                more, busy_warn = await _deploy_blockers(app, h["row"])
                blockers += more
                warnings += busy_warn
        names = [str(_host(h["row"]) or h["chassis"]) for h in holders]
        # Every other device of the holders' groups, as read now: the safety stop compares against it.
        held_in: dict[str, set[str]] = {}
        for h in holders:
            held_in.setdefault(str(h["group"].get("id")), set()).add(h["chassis"])
        others_before = {
            gid: {c: _by_name(v) for c, v in group_vars.get(gid, {}).items() if c not in held}
            for gid, held in held_in.items()
        }
        requests = [
            f"PUT {PG_VARIABLES_PATH} ({n}: {', '.join(h['slots'])} back to inert)"
            for n, h in zip(names, holders, strict=True)
        ] + ([f"DELETE {PO_ITEM_PATH} ({rname})"] if rec_obj else [])
        if deploy and targets:
            requests.append(
                f"POST {POLICY_DEPLOY_PATH} ({', '.join(str(_host(h['row'])) for h in targets)} only)"
            )
        plan = Plan(
            f"Release {addr} at {', '.join(names) or 'no edge'}"
            + (f": reset {sum(len(h['slots']) for h in holders)} slot(s)" if holders else "")
            + (f", delete record {rname}" if rec_obj else "")
            if contained
            else f"{addr} is not contained at any edge (no record {rname}, no slot holds it): "
            "nothing to change",
            details={
                "tier": "dangerous",
                "ip": addr,
                "was_contained": contained,
                "slots": [
                    {
                        "device": n,
                        "group": h["group"].get("name"),
                        "slots": {s: {"from": f"{addr}/32", "to": INERT[s]} for s in h["slots"]},
                    }
                    for n, h in zip(names, holders, strict=True)
                ],
                "record": _record_view(rec_obj) if rec_obj else None,
                "requests": requests,
                "deployed_to": [str(_host(h["row"])) for h in targets] if deploy else [],
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[f"Once deployed, {', '.join(names) or 'the edge'} forwards {addr}'s traffic again."]
            if holders
            else [],
            fingerprint={
                "variables": {h["chassis"]: h["before"] for h in holders},
                "other_devices_variables": others_before,
                "record": (rec_obj or {}).get("raw", {}).get("lastUpdatedOn") if rec_obj else None,
            },
            blockers=blockers if contained else [],
            blast_radius=len(targets) if deploy and contained else 0,
        )

        async def apply() -> Any:
            started = int(time.time() * 1000)
            by_group: dict[str, list[dict[str, Any]]] = {}
            for h in holders:
                by_group.setdefault(str(h["group"].get("id")), []).append(h)
            for gid, hs in by_group.items():
                await app.api.put(
                    path(PG_VARIABLES_PATH, id=gid),
                    _variables_body(hs[0]["group"], {h["chassis"]: h["after"] for h in hs}),
                )
                # Safety stop: the write must not have changed any other device's variables.
                moved = moved_devices(others_before.get(gid, {}), await pg_variables(app, gid))
                if moved:
                    who = ", ".join(str(_host(chassis_rows.get(c)) or c) for c in moved)
                    raise UpstreamError(
                        f"after the variables write in policy group {hs[0]['group'].get('name')}, the "
                        f"variables of {who} differ from before: nothing was deployed and the record is "
                        "kept. Check with catsdwan_containment_status"
                    )
            if rec_obj and po_id:
                await app.api.delete(
                    path(
                        PO_ITEM_PATH, profile=po_id, list_type="security-data-ip-prefix", parcel=rec_obj["id"]
                    )
                )
            out: dict[str, Any] = {"ip": addr, "released": contained, "edges": names}
            if deploy:
                deploys = []
                for gid, hs in by_group.items():
                    rows = [h["row"] for h in hs if h["row"] is not None]
                    if rows:
                        deploys.append(
                            await _deploy(app, ctx, gid, str(hs[0]["group"].get("name")), rows, wait)
                        )
                if deploys:
                    out["deploy"] = deploys[0] if len(deploys) == 1 else deploys
            elif holders:
                out["next"] = "catsdwan_deploy_policy_group(group, devices=[the edge])"
            if contained:
                words = {str(h["group"].get("name")) for h in holders} | {h["chassis"] for h in holders}
                out["audit"] = {
                    "manager": await manager_audit(app, started, words | {rname}),
                    "mcp": "event 'applied' for catsdwan_release_at_edge in the MCP audit log "
                    "(MCP_AUDIT_LOG)",
                }
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_release_at_edge",
            args={"ip": ip, "deploy": deploy, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="SD-WAN contained hosts and containment baseline")
    async def catsdwan_containment_status(
        ctx: Context,
        group: Annotated[str | None, Field(description="Only this policy group (name or id)")] = None,
        trustsec: Annotated[
            bool,
            Field(description="Also read each reachable edge's TrustSec state (can it enforce SGT rules?)"),
        ] = False,
    ) -> dict[str, Any]:
        """Who is contained at an SD-WAN edge, and is the standing baseline in place. `contained`: one row per
        host from its record mcp-contain-<ip> (edge, slot, VPN, reason, expiry, `expired`) and the slot that
        holds it, with `state` enforced-when-deployed / record only / slot only (no record) and the release
        call. `expired` lists the hosts past their time box (nothing releases them by itself).
        `baseline`: per policy group, each NGFW policy with quarantine and edge-slot rules present or not, and
        the zone pairs; trustsec=true adds per edge whether it can enforce SGT rules (environment data from
        ISE; SGT learned by binding, SXP or inline tagging), the main path's prerequisite. ISE-quarantined
        hosts are on ISE: ise_list_anc_endpoints."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        all_groups = await _groups(app, POLICY_GROUPS_PATH)
        groups = [resolve_group(all_groups, group, "policy group")] if group else all_groups
        details = list(await asyncio.gather(*(_group_detail(app, g) for g in groups)))
        warnings: list[str] = []
        baseline: list[dict[str, Any]] = []
        slots_held: dict[str, dict[str, Any]] = {}
        records: dict[str, dict[str, Any]] = {}
        for grp, d in zip(groups, details, strict=True):
            try:
                fwl = await group_firewall(app, d)
            except UpstreamError as e:
                warnings.append(f"policy group {grp.get('name')}: firewall not read: {str(e)[:150]}")
                continue
            for r in fwl["prefix_lists"]:
                if record_ip(r.get("name")):
                    records[str(r.get("name"))] = r
            entry: dict[str, Any] = {
                "group": grp.get("name"),
                "policies": [
                    {
                        "ngfw_policy": n.get("name"),
                        **baseline_state(n["data"]),
                        "zone_pairs": _words(_pairs(fwl, n["id"]), fwl["names"]) or "none (filters nothing)",
                    }
                    for n in fwl["ngfws"]
                ],
                "objects": {
                    QUARANTINE_OBJECT: next(
                        (
                            object_values("sgt", o["data"])
                            for o in fwl["sgt_lists"]
                            if o.get("name") == QUARANTINE_OBJECT
                        ),
                        None,
                    ),
                    SLOT_OBJECT: any(o.get("name") == SLOT_OBJECT for o in fwl["prefix_lists"]),
                },
            }
            if not fwl["ngfws"]:
                entry["verdict"] = "no NGFW policy: no baseline (catsdwan_set_firewall_policy first)"
            try:
                for ch, variables in (await pg_variables(app, str(grp.get("id")))).items():
                    for s, h in contained_at(slot_values(variables)).items():
                        slots_held[h] = {
                            "device": _host(chassis_rows.get(ch)) or ch,
                            "group": grp.get("name"),
                            "slot": s,
                        }
            except UpstreamError as e:
                warnings.append(f"policy group {grp.get('name')}: variables not read: {str(e)[:150]}")
            if trustsec:
                try:
                    members = await group_devices(app, str(grp.get("id")))
                except UpstreamError as e:
                    warnings.append(f"policy group {grp.get('name')}: devices not read: {str(e)[:150]}")
                    members = []
                rows = [
                    r
                    for m in members
                    if (r := chassis_rows.get(str(m.get("chassis")))) and r in reachable(inv, "edge")
                ]
                entry["trustsec"], ts_warn = await trustsec_readiness(app, rows)
                warnings += ts_warn
            baseline.append(entry)
        contained = []
        for _name, r in sorted(records.items()):
            view = _record_view(r)
            held = slots_held.get(str(view["ip"]))
            view["state"] = (
                "enforced once deployed (slot holds it)" if held else "record only: no slot holds it"
            )
            if held:
                view["held_by"] = held
            view["release"] = f"catsdwan_release_at_edge(ip='{view['ip']}')"
            contained.append(view)
        for h, held in sorted(slots_held.items()):
            if record_name(h) not in records:
                contained.append(
                    {
                        "ip": h,
                        "state": "slot only: no record (expiry unknown)",
                        "held_by": held,
                        "release": f"catsdwan_release_at_edge(ip='{h}')",
                    }
                )
        out: dict[str, Any] = {
            "contained": contained,
            "expired": [c["ip"] for c in contained if c.get("expired")],
            "baseline": baseline,
            "ise_quarantine": "hosts quarantined through ISE ANC: ise_list_anc_endpoints",
        }
        if warnings:
            out["warnings"] = warnings
        return out

    # --- the workflow ------------------------------------------------------------------------------

    @reg.prompt(
        title="Contain a host (ISE quarantine SGT, or its SD-WAN edge)",
        uses=["catsdwan", "ise"],
        tier=Tier.DANGEROUS,
        example={"host": "10.61.100.10", "reason": "INC-1 beaconing", "hours": "24"},
    )
    def catsdwan_contain_host(
        host: Annotated[str, Field(description="The host's IP address (or MAC, when ISE knows it)")],
        reason: Annotated[str, Field(description="Why: ticket, alert or incident id")],
        anc_policy: Annotated[
            str, Field(description="ISE ANC policy that assigns the Quarantine SGT (blank = find it)")
        ] = "",
        hours: Annotated[str, Field(description="Time box for the edge fallback, in hours")] = "24",
    ) -> str:
        """Contain one host the way a real deployment does: through ISE (ANC policy -> Quarantine SGT -> the
        standing SGT rule on the SD-WAN edges, no per-incident Manager change) when the host has an ISE
        session, else at the one edge where it sits (device-scoped, time-boxed, audited); then verify the
        drop and say how to release."""
        anc = f'policy="{anc_policy.strip()}"' if anc_policy.strip() else "policy=<the policy from step 3>"
        return f"""Contain {host} (reason: {reason}). Every write below is PREVIEW-FIRST: show the preview,
name the devices it reaches, and wait for the user's approval before confirming. Never confirm on your own.

1. Locate it: {tool_ref("catsdwan_find_host")} with host="{host}": its edge, site, VPN, interface and MAC.
   Several edges or none: stop and ask.
2. The standing baseline (once per policy group, NOT per incident): {tool_ref("catsdwan_containment_status")}
   with group=<the edge's policy group>, trustsec=true. Needed: the edge's NGFW policy on the host's VPN holds
   the mcp-quarantine-* rules (main path) and the mcp-contain-slots-* rules (fallback), deployed. Missing:
   {tool_ref("catsdwan_set_containment_baseline")} (quarantine_sgt=<ISE's Quarantine SGT name:tag>,
   remediation=[remediation server, DNS]) is a change for EVERY edge of the group: say so, and only with the
   user's go-ahead for a change window, then {tool_ref("catsdwan_deploy_policy_group")} to the group's edges.
   The main path needs TrustSec on the edge (W42's enforcement part): `trustsec.<edge>.ready` true
   (environment data from ISE, and the edge learns the SGT by an IP-to-SGT binding, SXP or inline tagging).
   Not ready: the quarantine rule matches nothing there; say so plainly and use the fallback (step 5).
3. Does ISE know the host? (ISE, {OPTIONAL}; not connected = fallback) {tool_ref("ise_find_session")} with
   the IP or MAC, then {tool_ref("ise_endpoint_360")}: an active session, its NAD, authorization profile and
   current SGT. No active session: go to step 5.
4. Main path, ISE ANC: {tool_ref("ise_list_anc_policies")} -> the ANC policy whose authorization rule
   (Session:ANCPolicy equals <policy>) returns the Quarantine SGT; none: stop and say what ISE needs (an ANC
   policy with {tool_ref("ise_create_anc_policy")} and that authorization rule first in the policy set; build
   it only if the user asks). Then {tool_ref("ise_apply_anc")} with the MAC, {anc} (preview, approve: ISE
   sends CoA and the host re-authenticates). Verify, in order:
   a. ISE: {tool_ref("ise_find_session")} again: the new session carries the Quarantine SGT.
   b. The edge has the new tag: {tool_ref("catsdwan_trustsec")} with device=<edge>: the IP-to-SGT binding for
      {host} shows the Quarantine tag (learned by SXP, pxGrid or the access switch), or
      {tool_ref("catsdwan_trustsec_path")} from the host's edge to a peer edge with source_ip="{host}": the
      source SGT is the Quarantine tag. Still the old SGT or none: TrustSec does not bring the tag to the edge
      (no SXP/pxGrid binding, no inline tagging): say so, keep the ANC, and add the fallback (step 5).
   c. Traffic is dropped: {tool_ref("catsdwan_security_status")} with device=<edge>: drops on the zone pair
      for mcp-quarantine-out/-in grow while the host sends; {tool_ref("catsdwan_ping")} from the edge to a
      peer host still works (only the quarantined host is cut off).
   Release: {tool_ref("ise_clear_anc")} with the MAC (preview, approve; CoA), then check the SGT is back.
5. Fallback, no ISE session (or no TrustSec on the edge): {tool_ref("catsdwan_contain_at_edge")} with
   ip="{host}", reason="{reason}", hours={hours.strip() or "24"}, edge=<the edge from step 1>. Show from the
   preview: the ONE device, the slot variable from -> to, the record and its expiry, and `proof.other_devices`
   (every other edge of the group unchanged). Approve, confirm, then verify:
   {tool_ref("catsdwan_get_device_config")} with device=<edge>, diff=true (the object-group holds
   {host}/32), {tool_ref("catsdwan_security_status")} (drops for mcp-contain-slots-out/-in), and the result's
   `audit` entries ({tool_ref("catsdwan_audit_log")} with changes_only=true when they are not there yet).
   Release: {tool_ref("catsdwan_release_at_edge")} with ip="{host}" (preview, approve). It does NOT expire by
   itself: tell the user the expiry and that {tool_ref("catsdwan_containment_status")} lists expired hosts.

Report, ONE line first: contained by ISE (Quarantine SGT seen on <edge>, drops counted) / contained at <edge>
until <expiry> (fallback, why) / NOT contained (what is missing: ISE ANC policy, TrustSec on the edge, the
baseline). Then the evidence per step, how to release, and what the user still has to do (for example:
TrustSec on the edges, an ANC policy on ISE)."""
