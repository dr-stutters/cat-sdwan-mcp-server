"""W45 WAN-edge containment in two paths (owner decisions 2026-10-24 "akin to a real-world deployment" and
2026-10-25 "Per-edge CLI ACL"):

- Main path, ISE quarantine SGT: catsdwan_set_containment_baseline puts a standing rule on the edges once
  (sequences mcp-quarantine-* in the policy group's NGFW policies: drop from and to the Quarantine SGT except
  the remediation prefixes; previewed, stored, then deployed in a change window). A host is then contained on
  ISE (ise_apply_anc with an ANC policy whose authorization result assigns the Quarantine SGT; CoA), with no
  Manager change per incident. It needs TrustSec on the edges (W42's enforcement part): the edge must learn
  the host's SGT (inline tagging, SXP or pxGrid) and have its environment data from ISE; the baseline's
  preview and catsdwan_containment_status say per edge what is missing.
- Fallback, a host with no ISE session: a per-edge CLI ACL. catsdwan_set_containment_acl puts the standing
  ACL `mcp-contain` in a configuration group's CLI add-on once (four slot entries `deny ip host
  {{mcp_contain_N}} any`, each with a remark {{mcp_contain_N_note}}, applied inbound on the service-side
  interfaces; every device holds neutral values). catsdwan_contain_at_edge then writes one slot of the edge
  where the host sits (address + note with the expiry and reason) and deploys that edge only: no parcel and
  no other device's variables change, so no other edge's intended config changes.
  catsdwan_containment_status shows the slots (expired ones flagged) and catsdwan_release_at_edge puts the
  neutral values back. (The first design, variables in a policy-object prefix list, is refused by 20.18:
  PPARC0012, #126.)

All writes are always dangerous and preview-first; none touches a sequence, CLI line or variable it did not
create. The prompt catsdwan_contain_host walks both paths.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import json
import time
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    Tier,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    preview_or_apply,
    tool_ref,
)
from cat_sdwan_mcp.changes import DEPLOY_PATH, device_brief, merge_variables, text_hash
from cat_sdwan_mcp.client import SdwanApp, _as_list, last_hours
from cat_sdwan_mcp.configuration import (
    CONFIG_GROUPS_PATH,
    POLICY_GROUPS_PATH,
    PROFILE_PATH,
    VARIABLES_PATH,
    device_variable_lists,
    path,
    resolve_group,
)
from cat_sdwan_mcp.containment import (
    ACL_NAME,
    INERT,
    MAX_HOURS,
    NOTE_FREE,
    NOTE_VARS,
    QUARANTINE_OBJECT,
    SLOT_VARS,
    SLOTS,
    acl_block,
    acl_state,
    baseline_rules,
    baseline_state,
    contained_at,
    expiry,
    host_ip,
    interface_problems,
    is_expired,
    moved_devices,
    neutral,
    ngfw_put_body,
    note,
    note_values,
    parse_note,
    pick_slot,
    quarantine_tag_problems,
    remediation_problems,
    resolve_interfaces,
    sequence,
    slot_values,
    with_acl,
    with_baseline,
    without_acl,
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
from cat_sdwan_mcp.features import PARCEL_PATH, as_dict, cli_diff, parcel_url, parcels_of
from cat_sdwan_mcp.findhost import ARP_PATH, TRANSPORT_VPNS, match_arp
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve
from cat_sdwan_mcp.policygroups import created_id, group_profiles
from cat_sdwan_mcp.servicevpns import vpn_context, zone_vpn_problems
from cat_sdwan_mcp.sgtpath import INTERFACE_TRUSTSEC_PATH
from cat_sdwan_mcp.tools.changes import (
    _pending_blockers,
    _reachability_blockers,
    _started,
    dangerous_blockers,
    dangerous_tool,
)
from cat_sdwan_mcp.tools.configuration import _associated, _groups
from cat_sdwan_mcp.tools.edgefirewall import _devices, _group_detail, _schema, list_objects, reach
from cat_sdwan_mcp.tools.policygroups import group_devices
from cat_sdwan_mcp.tools.policyvpns import zone_vpns
from cat_sdwan_mcp.trustsec import EDGE_PATHS, ISE_SGT_PATH, environment, rows_of, unsupported

CLI_PARCEL_SHAPE = PARCEL_PATH.format(
    type="cli", profile="{profileId}", parcel_type="config", parcel="{parcelId}"
)
MAX_EDGES = 25  # edges whose ARP / TrustSec tables are read
TIER_REASON = "WAN-edge containment (W45): deployed, it cuts a host off at its edge"
BASELINE_REASON = (
    "the containment baseline (W45): deployed, it drops quarantined hosts on every edge of the group"
)
ACL_REASON = (
    "the containment ACL (W45): a CLI add-on change for every device of the configuration group(s) once "
    "deployed"
)
OPTIONAL = "skipped if that server is not connected: say so in one line and go on"
TRUSTSEC_NEEDED = (
    "SGT rules match only where the edge knows the host's SGT: TrustSec propagation (inline tagging from the "
    "access switch, SXP from ISE, or pxGrid) and the edge's environment data from ISE (W42)"
)
UNPROVEN = (
    "Not yet proven live on 20.18.3.1 / IOS XE 17.18: that the Manager keeps an `interface` stanza in the "
    "CLI add-on for an interface a feature parcel also configures (the l65 VPN 10 conversion moved Gi3 to "
    "mcp-w8-vpn10-lan; `vrf definition 10` in both merged cleanly), and that the rendering keeps the ACL's "
    "sequence numbers. The deploy preview (catsdwan_deploy_config_group) shows both before anything is "
    "pushed."
)

HostIp = Annotated[str, Field(description="The host's IPv4 address (e.g. 10.61.200.15)")]
GroupRef = Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")]
ConfigGroupRef = Annotated[
    str, Field(description="Configuration group name or id (catsdwan_list_config_groups)")
]
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
        description="After storing, deploy the configuration group to the host's edge only (default true); "
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


async def group_firewall(app: SdwanApp, detail: dict[str, Any]) -> dict[str, Any]:
    """The group's embedded-security profile, NGFW policies, security policies and the policy objects the
    baseline uses: {profile, po, ngfws, policies, zones, sgt_lists, names}."""
    profs = group_profiles(detail)
    sec = next((p for p in profs if p["type"] == "embedded-security"), None)
    po = next((p for p in profs if p["type"] == "policy-object"), None)
    out: dict[str, Any] = {
        "profile": sec,
        "po": po,
        "ngfws": [],
        "policies": [],
        "zones": [],
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
        out["zones"], out["sgt_lists"] = await asyncio.gather(
            list_objects(app, po["id"], "security-zone"),
            list_objects(app, po["id"], "security-scalablegrouptag"),
        )
        for key in ("zones", "sgt_lists"):
            out["names"].update({z["id"]: str(z.get("name")) for z in out[key]})
    return out


def _pairs(fwl: dict[str, Any], ngfw_id: str) -> list[tuple[str, str]]:
    return [(s, d) for r in fwl["policies"] for rid, s, d in zone_pairs_of(r["data"], ngfw_id)]


def _words(pairs: list[tuple[str, str]], names: dict[str, str]) -> list[str]:
    return [f"{names.get(s, s)} -> {names.get(d, d)}" for s, d in pairs]


# --- the configuration group's CLI add-on and variables -----------------------------------------


def _cli_text(data: dict[str, Any]) -> str | None:
    v = data.get("config")
    if isinstance(v, dict) and isinstance(v.get("value"), str):
        return str(v["value"])
    return v if isinstance(v, str) else None


def _with_text(data: dict[str, Any], text: str) -> dict[str, Any]:
    out = dict(data)
    old = data.get("config")
    out["config"] = {**old, "value": text} if isinstance(old, dict) else text
    return out


async def cli_addon(app: SdwanApp, group: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """The configuration group's CLI add-on parcel {profile, id, name, description, data, text, updated,
    acl}, and read problems. With several CLI parcels, the one holding the containment ACL (else the
    first)."""
    found: list[dict[str, Any]] = []
    problems: list[str] = []
    for prof in _as_list(group.get("profiles")):
        if not isinstance(prof, dict) or str(prof.get("type")) != "cli" or not prof.get("id"):
            continue
        try:
            detail = await app.api.get(path(PROFILE_PATH, type="cli", id=str(prof["id"])))
            for p in parcels_of(detail):
                if p["type"] != "config":
                    continue
                url = parcel_url(
                    PARCEL_PATH, ptype="cli", parcel_type="config", profile=str(prof["id"]), parcel=p["id"]
                )
                body = await app.api.get(url)
                payload = as_dict(as_dict(body).get("payload"))
                data = as_dict(payload.get("data"))
                text = _cli_text(data)
                if text is None:
                    continue
                found.append(
                    {
                        "profile": {"id": str(prof["id"]), "name": prof.get("name")},
                        "id": p["id"],
                        "name": payload.get("name") or p["name"],
                        "description": payload.get("description") or "",
                        "data": data,
                        "text": text,
                        "updated": as_dict(body).get("lastUpdatedOn"),
                        "acl": acl_state(text),
                    }
                )
        except UpstreamError as e:
            problems.append(f"CLI profile {prof.get('name')}: not read: {str(e)[:150]}")
    if not found:
        return None, problems
    return next((f for f in found if f["acl"]), found[0]), problems


async def cli_put(app: SdwanApp, addon: dict[str, Any], text: str) -> None:
    url = parcel_url(
        PARCEL_PATH, ptype="cli", parcel_type="config", profile=addon["profile"]["id"], parcel=addon["id"]
    )
    body = {
        "name": addon["name"],
        "description": addon["description"],
        "data": _with_text(addon["data"], text),
    }
    await app.api.put(url, body)


async def cg_variables(
    app: SdwanApp, gid: str, chassis: list[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """{chassis: [{name, value?}]} of a configuration group's device variables (all devices, or `chassis`)."""
    params = {"device-id": ",".join(chassis)} if chassis else None
    return device_variable_lists(await app.api.get(path(VARIABLES_PATH, id=gid), params))


def _variables_body(group: dict[str, Any], devices: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "solution": group.get("solution") or "sdwan",
        "devices": [{"device-id": c, "variables": v} for c, v in devices.items()],
    }


async def memberships(
    app: SdwanApp, groups: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """({group id: associated devices}, read problems) for every configuration group."""
    got = await asyncio.gather(*(_associated(app, str(g["id"])) for g in groups), return_exceptions=True)
    out: dict[str, list[dict[str, Any]]] = {}
    warnings: list[str] = []
    for grp, res in zip(groups, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"configuration group {grp.get('name')}: devices not read: {str(res)[:150]}")
            continue
        if isinstance(res, BaseException):
            raise res
        out[str(grp["id"])] = res
    return out, warnings


def _users_of(groups: list[dict[str, Any]], profile_id: str) -> list[dict[str, Any]]:
    """The configuration groups that use a profile (a CLI add-on can be shared)."""
    return [
        g
        for g in groups
        if any(str(p.get("id")) == profile_id for p in _as_list(g.get("profiles")) if isinstance(p, dict))
    ]


async def all_slots(
    app: SdwanApp, groups: list[dict[str, Any]], members: dict[str, list[dict[str, Any]]]
) -> tuple[dict[str, dict[str, list[dict[str, Any]]]], list[str]]:
    """({group id: {chassis: variables}}, read problems) for every configuration group with devices."""
    todo = [g for g in groups if members.get(str(g["id"]))]
    got = await asyncio.gather(
        *(
            cg_variables(app, str(g["id"]), [str(d.get("chassis")) for d in members[str(g["id"])]])
            for g in todo
        ),
        return_exceptions=True,
    )
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}
    warnings: list[str] = []
    for grp, res in zip(todo, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"configuration group {grp.get('name')}: variables not read: {str(res)[:150]}")
            continue
        if isinstance(res, BaseException):
            raise res
        out[str(grp["id"])] = res
    return out, warnings


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
    answer = await app.api.post(path(DEPLOY_PATH, id=gid), body)
    names = ", ".join(str(_host(r)) for r in rows)
    return await _started(app, ctx, answer, wait, f"deploy of configuration group {gname} to {names}")


async def _deploy_blockers(
    app: SdwanApp, row: dict[str, Any], assoc: dict[str, Any] | None
) -> tuple[list[str], list[str]]:
    blockers = []
    if row.get("config_mode") == "template":
        blockers.append(
            f"{row.get('host')} is on device template {row.get('config') or '?'}: the containment ACL lives "
            "in a configuration group's CLI add-on"
        )
    if not row.get("chassis"):
        blockers.append(f"{row.get('host')} has no chassis number: the Manager can't deploy to it")
    if assoc and assoc.get("deployable") is False:
        blockers.append(
            f"{row.get('host')}: the Manager says it is not deployable ({assoc.get('config_status')})"
        )
    blockers += _reachability_blockers([row])
    busy, warnings = await _pending_blockers(app, [row])
    return blockers + busy, warnings


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _by_name(variables: list[dict[str, Any]]) -> dict[str, Any]:
    return {str(v.get("name")): v.get("value") for v in variables}


def _unset_neutral(variables: list[dict[str, Any]]) -> dict[str, str]:
    """The neutral values of the slot and note variables a device lists but has no value for."""
    have = _by_name(variables)
    return {k: v for k, v in neutral().items() if k in have and have[k] in (None, "")}


def _slot_rows(variables: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """{host: {slot, expires?, reason?, expired}} of the hosts one device's slots hold."""
    notes = note_values(variables)
    out = {}
    for s, h in contained_at(slot_values(variables)).items():
        rec = parse_note(notes.get(s))
        out[h] = {"slot": s, **rec, "expired": is_expired(rec.get("expires"))}
    return out


def register(reg: ToolRegistrar) -> None:
    # --- the standing quarantine baseline (main path) --------------------------------------------

    @dangerous_tool(reg, title="Set the SD-WAN containment baseline")
    async def catsdwan_set_containment_baseline(
        ctx: Context,
        group: GroupRef,
        quarantine_sgt: Annotated[
            str | None,
            Field(
                description="The Quarantine SGT ISE's ANC result assigns: '<name>:<tag>' (e.g. "
                "'Quarantined_Systems:255'), a tag or an ISE SGT name"
            ),
        ] = None,
        remediation: Annotated[
            list[str] | None,
            Field(
                description="IPv4 prefixes contained hosts may still reach (remediation server, DNS; at most "
                "16); default none"
            ),
        ] = None,
        remove: Annotated[bool, Field(description="Take the baseline's rules out instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Check or set the standing quarantine rules of a policy group's edge firewall (W45 main path, set
        once in a change window, not per incident). At the top of each NGFW policy bound to a zone pair:
        mcp-quarantine-allow-out/-in (pass the Quarantine SGT to and from `remediation`) and
        mcp-quarantine-out/-in (drop from and to the SGT list mcp-quarantine-sgt, logged): ISE then contains a
        host with ise_apply_anc alone. Every other rule keeps its order. Preview-first: each NGFW policy's
        rules before and after, the SGT object, the devices the deploy reaches, and per edge whether TrustSec
        can enforce SGT rules (environment data from ISE; SGT learned by binding, SXP or inline tagging):
        without it the quarantine rules match nothing there. In place already: the preview says so. Confirm
        stores the object and rules; deploy with catsdwan_deploy_policy_group. remove=true takes the rules
        out. The no-ISE fallback is a per-edge CLI ACL instead: catsdwan_set_containment_acl. Dangerous."""
        app: SdwanApp = get_client(ctx)
        fix = [r.strip() for r in remediation or [] if r and r.strip()]
        quarantine = bool(quarantine_sgt and quarantine_sgt.strip())
        if not remove and not quarantine:
            raise InvalidRequest(
                "Give quarantine_sgt, or remove=true (the no-ISE fallback is catsdwan_set_containment_acl)."
            )
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
        # #118: the baseline rides on the NGFW's zone pairs; their VPNs must be LAN VPN parcels in each edge's
        # configuration group, or the controller refuses the deploy that would put the baseline in effect.
        if not remove:
            pair_zones = {z for r in fwl["policies"] for _, s, d in zone_pairs_of(r["data"]) for z in (s, d)}
            if used := zone_vpns(fwl["zones"], pair_zones):
                try:
                    vctx = await vpn_context(
                        app, [str(d.get("chassis")) for d in await group_devices(app, gid)]
                    )
                    blockers += zone_vpn_problems(used, vctx)
                    warnings += list(vctx.get("warnings") or [])
                except UpstreamError as e:
                    warnings.append(f"zone VPNs not checked against the configuration groups: {str(e)[:150]}")

        # The Quarantine SGT list (created when missing, never another object).
        sgt_obj = by_name(fwl["sgt_lists"], QUARANTINE_OBJECT)
        sgt_body: dict[str, Any] | None = None
        objects: dict[str, Any] = {}
        if not remove:
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

        names = dict(fwl["names"])
        sgt_ref = sgt_obj["id"] if sgt_obj else f"<new {QUARANTINE_OBJECT}>"
        names.setdefault(sgt_ref, QUARANTINE_OBJECT)
        rules = baseline_rules(remediation=fix) if not remove else []

        def changed_data(n: dict[str, Any], sgt_id: str) -> tuple[dict[str, Any], list[str]]:
            if remove:
                return without_baseline(n["data"])
            refs = {"sgt": {QUARANTINE_OBJECT: sgt_id}}
            return with_baseline(n["data"], [sequence(r, refs) for r in rules])

        changes: list[dict[str, Any]] = []
        unbound: list[str] = []
        for n in fwl["ngfws"]:
            pairs = _pairs(fwl, n["id"])
            if not pairs:
                unbound.append(str(n.get("name")))
                continue
            new, old = changed_data(n, sgt_ref)
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

        # Who gets it, and can they enforce SGT rules.
        details_all = list(await asyncio.gather(*(_group_detail(app, g) for g in all_groups)))
        reached, read_warn = await reach(app, details_all, (fwl["profile"] or {}).get("id"), extra=detail)
        warnings += read_warn
        trustsec: dict[str, Any] = {}
        if not remove:
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
                    f"there until it is ({TRUSTSEC_NEEDED}); the fallback catsdwan_contain_at_edge (per-edge "
                    "CLI ACL) still works"
                )
        in_place = not changes and sgt_body is None
        devices = _devices(reached)
        requests = (
            [f"{'PUT' if sgt_obj else 'POST'} {PO_LIST_PATH} ({QUARANTINE_OBJECT})"] if sgt_body else []
        ) + [f"PUT {NGFW_PATH} ({c['view']['ngfw_policy']})" for c in changes]
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
                "rules": [r["name"] for r in rules],
                "remediation": fix,
                "objects": objects,
                "policies": [c["view"] for c in changes],
                **({"unbound_policies_left_alone": unbound} if unbound else {}),
                "requests": requests,
                "reaches": reached,
                **({"trustsec": trustsec} if trustsec else {}),
                "needs": TRUSTSEC_NEEDED if not remove else None,
                "next": f"catsdwan_deploy_policy_group(group='{gname}', devices=[every edge of the group]) "
                "in a change window, then catsdwan_containment_status(group)",
                "undo": f"catsdwan_set_containment_baseline(group='{gname}', remove=true)",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores on the Manager only. Once deployed, every edge of the group(s) above drops traffic "
                "from and to the Quarantine SGT (except remediation)."
            ]
            if not remove
            else ["Once deployed, the edges no longer drop quarantined hosts."],
            fingerprint={
                "group": [detail.get("lastUpdatedOn"), detail.get("version")],
                "ngfw": {c["row"]["id"]: c["row"]["raw"].get("lastUpdatedOn") for c in changes},
                "objects": [(sgt_obj or {}).get("raw", {}).get("lastUpdatedOn")],
            },
            blockers=blockers,
            blast_radius=len(devices),
            undo=Undo("catsdwan_set_containment_baseline", {"group": gname, "remove": True})
            if not remove
            else f"catsdwan_set_containment_baseline(group='{gname}', remediation=<the prefixes it had>) "
            "puts the baseline back",
        )

        async def apply() -> Any:
            po_id = fwl["po"]["id"]
            sgt_id = sgt_obj["id"] if sgt_obj else ""
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
            if not remove and not sgt_id:
                raise UpstreamError("the Manager returned no id for a new object: nothing else was changed")
            sec_id = fwl["profile"]["id"]
            for c in changes:
                data, _ = changed_data(c["row"], sgt_id)
                await app.api.put(
                    path(NGFW_PATH, id=sec_id, parcel=c["row"]["id"]), ngfw_put_body(c["row"], data)
                )
            out["policies"] = [c["view"]["ngfw_policy"] for c in changes]
            out["next"] = (
                f"catsdwan_deploy_policy_group(group='{gname}', devices=[...]) to every edge of the group "
                "in a change window (preview first), then catsdwan_containment_status(group)"
            )
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_containment_baseline",
            args={"group": group, "quarantine_sgt": quarantine_sgt, "remediation": fix, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    # --- the fallback's standing ACL (configuration group CLI add-on) -----------------------------

    @dangerous_tool(reg, title="Set the SD-WAN containment ACL")
    async def catsdwan_set_containment_acl(
        ctx: Context,
        group: ConfigGroupRef,
        interfaces: Annotated[
            list[str] | None,
            Field(
                description="The service-side (e.g. VPN 10) interfaces where the edges' LAN traffic enters, "
                "as "
                "the CLI names them ('GigabitEthernet3'), or a variable the CLI add-on already uses for a "
                "per-device interface ('{{fw_if}}'); at most 8"
            ),
        ] = None,
        remediation: Annotated[
            list[str] | None,
            Field(
                description="IPv4 prefixes contained hosts may still reach (remediation server, DNS; at most "
                "16): permitted before the slots"
            ),
        ] = None,
        remove: Annotated[bool, Field(description="Take the containment ACL out of the CLI add-on")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Check or set the standing per-edge containment ACL in a configuration group's CLI add-on (W45
        fallback for hosts with no ISE session; set once in a change window, not per incident). IOS XE
        17.18 lines: `ip access-list extended mcp-contain` with the remediation permits (seq 10..), four slots
        (`110 remark {{mcp_contain_1_note}}` / `111 deny ip host {{mcp_contain_1}} any` .. slot 4) and `1000
        permit ip any any`, applied `ip access-group mcp-contain in` on each of `interfaces`. Every device
        gets neutral values (192.0.2.241-244, note 'mcp-contain slot free'), so the ACL permits everything
        until catsdwan_contain_at_edge writes one edge's slot. Every other CLI line keeps its place; an
        earlier block of this tool is replaced as a whole. Preview-first: the CLI lines added or removed
        (secrets masked), the configuration groups using the add-on and their devices, the neutral values.
        Confirm stores the parcel and the neutral values (checked after each write, stopped if another
        device's values moved); deploy with catsdwan_deploy_config_group, one edge at a time. remove=true
        takes the block out (blocked while a slot holds a host). Dangerous."""
        app: SdwanApp = get_client(ctx)
        fix = [r.strip() for r in remediation or [] if r and r.strip()]
        ifs = [i.strip() for i in interfaces or [] if i and i.strip()]
        if not remove and not ifs:
            raise InvalidRequest("Give `interfaces` (where the edges' LAN traffic enters), or remove=true.")
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        found = resolve_group(groups, group)
        gname = str(found.get("name"))
        blockers = dangerous_blockers(ctx, app, [ACL_REASON])
        blockers += remediation_problems(fix)
        warnings: list[str] = []
        addon, problems = await cli_addon(app, found)
        warnings += problems
        if addon is None:
            blockers.append(
                f"configuration group {gname} has no CLI add-on (a 'cli' feature profile with a config "
                "parcel) to hold the ACL: add one to the group first"
            )
        text = addon["text"] if addon else ""
        current = addon["acl"] if addon else None
        if current and not current["intact"]:
            warnings.append(
                f"the {ACL_NAME} ACL in {addon['name'] if addon else '?'} is not exactly what this tool "
                "writes "
                "(edited by hand?): it is replaced as a whole"
            )
        if remove:
            new_text = without_acl(text)
        else:
            blockers += interface_problems(ifs, text)
            new_text = with_acl(text, acl_block(fix, ifs))
        changed = addon is not None and new_text != text
        users = _users_of(groups, addon["profile"]["id"]) if addon else [found]
        members, read_warn = await memberships(app, users)
        warnings += read_warn
        slots, read_warn = await all_slots(app, users, members)
        warnings += read_warn
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        held: dict[str, list[str]] = {}
        for vals in slots.values():
            for ch, variables in vals.items():
                if rows := _slot_rows(variables):
                    held[str(_host(chassis_rows.get(ch)) or ch)] = sorted(rows)
        # Devices listing slot variables with no value (joined the group later, or a fill that did not
        # finish): a deploy to them fails until they hold the neutral values, so an ACL in place still fills.
        unset_devices = sorted(
            str(_host(chassis_rows.get(ch)) or ch)
            for vals in slots.values()
            for ch, variables in vals.items()
            if _unset_neutral(variables)
        )
        fill_only = not remove and not changed and addon is not None and bool(unset_devices)
        if held and remove:
            blockers.append(
                f"slots hold contained hosts ({held}) and this takes the ACL out: release them first "
                "(catsdwan_release_at_edge)"
            )
        elif held and changed:
            warnings.append(
                f"slots hold contained hosts ({held}): they stay contained; check that the interfaces still "
                "cover where they sit"
            )
        reached: list[dict[str, Any]] = [
            {
                "group": g.get("name"),
                "devices": [str(d.get("host") or d.get("chassis")) for d in members.get(str(g["id"]), [])],
            }
            for g in users
        ]
        devices = sorted({d for r in reached for d in r["devices"]})
        if len(users) > 1:
            warnings.append(
                f"the CLI add-on {addon['profile']['name'] if addon else '?'} is shared by "
                f"{', '.join(str(g.get('name')) for g in users)}: all of them get the ACL"
            )
        requests = []
        if fill_only:
            requests.append(
                f"PUT {VARIABLES_PATH} (unset mcp_contain_* variables of {', '.join(unset_devices)} get "
                "their neutral values, checked after each write)"
            )
        if changed and addon:
            requests.append(f"PUT {CLI_PARCEL_SHAPE} ({addon['name']})")
            if not remove:
                requests.append(
                    f"PUT {VARIABLES_PATH} (each configuration group above: unset mcp_contain_* variables "
                    "get "
                    "their neutral values, checked after each write)"
                )
        plan = Plan(
            f"The containment ACL is in place in {gname}: fill the neutral slot values of "
            f"{', '.join(unset_devices)}"
            if fill_only
            else f"The containment ACL is in place in {gname}: nothing to change"
            if not changed and not remove
            else f"No containment ACL in {gname}: nothing to remove"
            if not changed
            else f"{'Remove' if remove else 'Set'} the containment ACL {ACL_NAME} in the CLI add-on of "
            f"configuration group {gname}",
            details={
                "tier": "dangerous",
                "group": gname,
                "cli_addon": {"profile": addon["profile"]["name"], "parcel": addon["name"]}
                if addon
                else None,
                "interfaces": ifs,
                "remediation": fix,
                **({"acl": acl_block(fix, ifs).splitlines()} if not remove else {}),
                "cli_changes": cli_diff(text, new_text) if changed else [],
                "neutral_values": neutral() if not remove else {},
                **({"unset_values": unset_devices} if unset_devices and not remove else {}),
                "reaches": reached,
                "requests": requests,
                "not_yet_proven": UNPROVEN,
                "next": f"catsdwan_deploy_config_group(group='{gname}', devices=[one edge]) for each edge in "
                "a "
                "change window (its preview shows the rendered ACL), then catsdwan_containment_status",
                "undo": f"catsdwan_set_containment_acl(group='{gname}', remove=true)"
                if not remove
                else "catsdwan_set_containment_acl with the interfaces and remediation shown before",
                **({"before": {k: current[k] for k in ("interfaces", "remediation")}} if current else {}),
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                f"Stores on the Manager only. Once deployed, every device of the group(s) above applies ACL "
                f"{ACL_NAME} inbound on {', '.join(ifs)}; with neutral slots its denies match only "
                "192.0.2.241-244, so it permits everything else.",
                "Every device of those groups gets the neutral mcp_contain_* values (values only, nothing "
                "deployed; checked after each write, stopped if another device's values moved).",
            ]
            if not remove
            else ["Once deployed, the edges no longer have the containment ACL."],
            fingerprint={
                "parcel": [addon["updated"], text_hash(text)] if addon else None,
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "held": held,
                "unset": unset_devices,
            },
            blockers=blockers,
            blast_radius=len(devices) if changed else len(unset_devices) if fill_only else 0,
            # back to the ACL read before the change, or out again when there was none
            undo=Undo(
                "catsdwan_set_containment_acl",
                {"group": gname, "interfaces": current["interfaces"], "remediation": current["remediation"]},
            )
            if current
            else Undo("catsdwan_set_containment_acl", {"group": gname, "remove": True})
            if not remove
            else "nothing to put back: there was no containment ACL",
        )

        async def apply() -> Any:
            out: dict[str, Any] = {"group": gname}
            if not (changed or fill_only) or addon is None:
                return {**out, "stored": "nothing (in place)"}
            if changed:
                await cli_put(app, addon, new_text)
                out["stored"] = f"CLI add-on {addon['name']}"
                out["cli_changes"] = cli_diff(text, new_text)
            if not remove:
                filled: dict[str, list[str]] = {}
                missing: list[str] = []
                for grp in users:
                    gid = str(grp["id"])
                    chs = [str(d.get("chassis")) for d in members.get(gid, [])]
                    if not chs:
                        continue
                    cur = await cg_variables(app, gid, chs)
                    todo: dict[str, list[dict[str, Any]]] = {}
                    for ch, variables in cur.items():
                        unset = _unset_neutral(variables)
                        if not slot_values(variables):
                            missing.append(str(_host(chassis_rows.get(ch)) or ch))
                        if unset:
                            todo[ch] = merge_variables(variables, unset)[0]
                    if not todo:
                        continue
                    await app.api.put(path(VARIABLES_PATH, id=gid), _variables_body(grp, todo))
                    filled[str(grp.get("name"))] = [str(_host(chassis_rows.get(c)) or c) for c in todo]
                    # Safety stop: the devices not in this PUT must keep their values.
                    rest = {c: _by_name(v) for c, v in cur.items() if c not in todo}
                    moved = moved_devices(rest, await cg_variables(app, gid, chs))
                    if moved:
                        names = ", ".join(str(_host(chassis_rows.get(c)) or c) for c in moved)
                        raise UpstreamError(
                            f"after the neutral-value write in configuration group {grp.get('name')}, the "
                            f"variables of {names} differ from before: stopped (nothing is deployed by this "
                            f"tool). Filled so far: {filled}. Check with catsdwan_get_config_group / "
                            "catsdwan_containment_status before any deploy"
                        )
                out["neutral_filled"] = filled
                if missing:
                    out["warnings"] = [
                        f"the Manager lists no mcp_contain_* variables for {', '.join(missing)} yet: run "
                        "this "
                        "again before a deploy (a deploy with unset variables fails)"
                    ]
            out["next"] = (
                f"catsdwan_deploy_config_group(group='{gname}', devices=[one edge]) per edge in a change "
                "window (preview first), then catsdwan_containment_status"
            )
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_containment_acl",
            args={"group": group, "interfaces": ifs, "remediation": fix, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    # --- fallback: one edge's slot ------------------------------------------------------------------

    @dangerous_tool(reg, title="Contain a host at its SD-WAN edge only")
    async def catsdwan_contain_at_edge(
        ctx: Context,
        ip: HostIp,
        reason: Annotated[
            str,
            Field(min_length=1, max_length=200, description="Why (ticket or alert); kept in the slot's note"),
        ],
        hours: Annotated[
            int, Field(ge=1, le=MAX_HOURS, description="Time box: the note's expiry, in hours (default 24)")
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
        the edges' live ARP tables (or the `edge` given), then writes ONE device's slot of the standing
        containment ACL (catsdwan_set_containment_acl): {{mcp_contain_N}} = the host, so the edge renders
        `deny ip host <ip> any` inbound on its LAN interfaces, and {{mcp_contain_N_note}} = 'mcp-contain until
        <expiry> <reason>' (the record, as the entry's remark). Then deploys the configuration group to that
        edge only. No parcel and no other device's variables change, so no other edge's intended config
        changes; the preview names the single device and lists every other device of the group as unchanged,
        and confirm re-reads every device's variables after the write and stops before the deploy if another
        device's values moved. Nothing releases it at the expiry by itself: catsdwan_containment_status flags
        it. The result names the Manager's audit entries. Blocked when the group has no containment ACL,
        the host sits on an interface the ACL is not applied on, all 4 slots of the edge are in use, or the
        host is contained at another edge. Undo: catsdwan_release_at_edge. Dangerous."""
        try:
            addr = host_ip(ip)
        except ValueError as e:
            raise InvalidRequest(str(e)) from None
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
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
        host_name = _host(row)
        chassis = str((row or {}).get("chassis") or "")
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        members, read_warn = await memberships(app, groups)
        warnings += read_warn
        slots_all, read_warn = await all_slots(app, groups, members)
        warnings += read_warn
        for g in groups:
            for ch, variables in slots_all.get(str(g["id"]), {}).items():
                if ch != chassis and addr in _slot_rows(variables):
                    blockers.append(
                        f"{addr} is already contained at {_host(chassis_rows.get(ch)) or ch}: release it "
                        "there "
                        f"first (catsdwan_release_at_edge(ip='{addr}'))"
                    )
        group = (
            next(
                (
                    g
                    for g in groups
                    if any(str(d.get("chassis")) == chassis for d in members.get(str(g["id"]), []))
                ),
                None,
            )
            if row is not None
            else None
        )
        if row is not None and group is None:
            blockers.append(
                f"{host_name} is in no configuration group: the per-edge ACL lives in a configuration "
                "group's "
                "CLI add-on (catsdwan_associate_config_group, then catsdwan_set_containment_acl)"
            )
        gname = str(group.get("name")) if group else None
        gid = str(group["id"]) if group else ""
        expires = expiry(hours)
        note_text = note(expires, reason)
        addon: dict[str, Any] | None = None
        acl: dict[str, Any] | None = None
        current: list[dict[str, Any]] = []
        others_before: dict[str, dict[str, Any]] = {}
        merged: list[dict[str, Any]] = []
        slot: str | None = None
        already = False
        applied_on: list[str] = []
        assoc: dict[str, Any] | None = None
        if group is not None and row is not None:
            assoc = next((d for d in members.get(gid, []) if str(d.get("chassis")) == chassis), None)
            addon, problems = await cli_addon(app, group)
            warnings += problems
            acl = addon["acl"] if addon else None
            if not acl or not acl["slots"]:
                blockers.append(
                    f"configuration group {gname} has no standing containment ACL ({ACL_NAME} in its CLI "
                    f"add-on). Set it once: catsdwan_set_containment_acl(group='{gname}', interfaces=[<LAN "
                    "interfaces>]), deploy it to the group's edges in a change window, then contain here; "
                    "only "
                    "this edge changes per incident"
                )
            elif not acl["intact"]:
                warnings.append(
                    f"the {ACL_NAME} ACL in {gname}'s CLI add-on is not exactly what "
                    "catsdwan_set_containment_acl "
                    "writes (edited by hand?): check the deploy preview"
                )
            every = slots_all.get(gid)
            if every is None:
                blockers.append(f"{host_name}'s variables in {gname} not read")
            else:
                current = every.get(chassis, [])
                others_before = {c: _by_name(v) for c, v in every.items() if c != chassis}
            values = slot_values(current)
            if acl and acl["slots"] and every is not None and not values:
                blockers.append(
                    f"{host_name} has no {SLOT_VARS[0]}..{SLOT_VARS[-1]} variables in {gname}: the ACL's "
                    "neutral values were not stored for it (run catsdwan_set_containment_acl again)"
                )
            slot, already = pick_slot(values, addr)
            if values and slot is None:
                blockers.append(
                    f"all {SLOTS} slots of {host_name} hold hosts ({contained_at(values)}): release one "
                    "(catsdwan_release_at_edge) or contain this host through ISE"
                )
            unset = sorted(k for k in _unset_neutral(current) if not slot or k not in (slot, NOTE_VARS[slot]))
            if acl and acl["slots"] and unset:
                blockers.append(
                    f"{host_name} has slot variables with no value in {gname} ({', '.join(unset)}): a deploy "
                    "to it fails until they hold the neutral values: "
                    f"catsdwan_set_containment_acl(group='{gname}', interfaces={acl['interfaces']!r}) "
                    "fills them"
                )
            if slot:
                merged, _, unknown = merge_variables(current, {slot: addr, NOTE_VARS[slot]: note_text})
                if unknown:
                    blockers.append(
                        f"{host_name} has no variable {', '.join(unknown)} in {gname}: run "
                        "catsdwan_set_containment_acl again"
                    )
            if acl:
                applied_on = resolve_interfaces(acl["interfaces"], current)
                iface = str(where.get("interface") or "")
                if iface and iface.lower() not in {a.lower() for a in applied_on}:
                    blockers.append(
                        f"{addr} sits on {host_name} {iface}, but the ACL is applied on "
                        f"{', '.join(applied_on) or 'no interface'} there, so it would not see the host's "
                        f"traffic: add {iface} with catsdwan_set_containment_acl(group='{gname}', "
                        "interfaces=[...])"
                    )
                elif not iface:
                    warnings.append(
                        f"{addr} was not located on an interface (edge/VPN given, or routed behind a next "
                        "hop): "
                        f"its traffic must enter {host_name} on {', '.join(applied_on)} for the ACL to drop "
                        "it"
                    )
            if assoc and assoc.get("group_up_to_date") is False:
                warnings.append(
                    f"{host_name} is not up to date with configuration group {gname}: the deploy also pushes "
                    "the group's other stored changes to it (catsdwan_deploy_config_group's preview shows "
                    "them)"
                )
        if deploy and row is not None:
            more, busy_warn = await _deploy_blockers(app, row, assoc)
            blockers += more
            warnings += busy_warn
        if not deploy:
            warnings.append("deploy=false: stored only; the edge drops nothing until deployed")
        old = _by_name(current)
        seq = 100 + 10 * (SLOT_VARS.index(slot) + 1) if slot else None
        others = [
            str(d.get("host") or d.get("chassis"))
            for d in members.get(gid, [])
            if str(d.get("chassis")) != chassis
        ]
        requests = [
            f"PUT {VARIABLES_PATH} {{devices: [{{device-id: <{host_name} chassis>, variables}}]}} (this "
            "device "
            "only)",
        ] + ([f"POST {DEPLOY_PATH} {{devices: [{{id: <{host_name} chassis>}}]}}"] if deploy else [])
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
                "slot": {
                    "variable": slot,
                    "from": old.get(slot) if slot else None,
                    "to": addr,
                    "already_held": already,
                },
                "record": {
                    "variable": NOTE_VARS[slot] if slot else None,
                    "from": old.get(NOTE_VARS[slot]) if slot else None,
                    "to": note_text,
                },
                "expires": expires,
                "acl_entries": [f"{seq} remark {note_text}", f"{seq + 1} deny ip host {addr} any"]
                if seq
                else [],
                "applied_on": {"acl": ACL_NAME, "direction": "in", "interfaces": applied_on},
                "proof": {
                    "devices_changed": [host_name] if host_name else [],
                    "group_parcels_changed": [],
                    "other_devices": {
                        m: "unchanged: same parcels and variables, nothing new at its next deploy"
                        for m in others
                    },
                    "why": "the only stored change is this device's slot and note variables; the CLI add-on "
                    "and every other device's variables stay as they are (checked again after the write)",
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
                f"Once deployed, {host_name or 'the edge'} drops every packet from {addr} entering on "
                f"{', '.join(applied_on) or 'its LAN interfaces'} (ACL {ACL_NAME}), except to the "
                "remediation "
                "prefixes. No other edge changes.",
                f"Nothing releases it at {expires} by itself: catsdwan_containment_status flags it expired.",
            ],
            fingerprint={
                "group": [group.get("lastUpdatedOn"), group.get("version")] if group else None,
                "parcel": [addon["updated"], _digest(addon["text"])] if addon else None,
                "variables": current,
                "other_devices_variables": others_before,
                "edge": chassis,
            },
            blockers=blockers,
            blast_radius=1 if deploy and row else 0,
            undo=Undo("catsdwan_release_at_edge", {"ip": addr, "deploy": deploy}),
        )

        async def apply() -> Any:
            assert row is not None and group is not None and slot is not None
            started = int(time.time() * 1000)
            await app.api.put(path(VARIABLES_PATH, id=gid), _variables_body(group, {chassis: merged}))
            # Safety stop: the write must not have changed any other device's variables.
            after = await cg_variables(app, gid, [chassis, *others_before])
            moved = moved_devices(others_before, after)
            if moved:
                names = ", ".join(str(_host(chassis_rows.get(c)) or c) for c in moved)
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
                "note": note_text,
                "expires": expires,
                "reason": reason,
            }
            if deploy:
                out["deploy"] = await _deploy(app, ctx, gid, str(gname), [row], wait)
            else:
                out["next"] = f"catsdwan_deploy_config_group(group='{gname}', devices=['{host_name}'])"
            out["audit"] = {
                "manager": await manager_audit(
                    app, started, {str(gname), str(row.get("system_ip")), chassis}
                ),
                "mcp": "event 'applied' for catsdwan_contain_at_edge in the MCP audit log (MCP_AUDIT_LOG)",
            }
            out["verify"] = (
                f"catsdwan_get_device_config(device='{host_name}', diff=true): `{seq} deny ip host {addr} "
                "any` in "
                f"{ACL_NAME}; on the edge `show ip access-lists {ACL_NAME}` counts the drops"
            )
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
        """Undo catsdwan_contain_at_edge: put the neutral values back into exactly the slot(s) holding this
        host and their notes (every configuration group's devices are searched), and deploy the group to that
        edge only. No other slot, variable or CLI line changes; confirm re-reads the other devices' variables
        after the write and stops before the deploy if any moved. Preview-first: the device, the slot from ->
        to, the record (note) it clears. Idempotent: a host that is not contained changes nothing. A host
        quarantined through ISE is released on ISE (ise_clear_anc), not here. Dangerous."""
        try:
            addr = host_ip(ip)
        except ValueError as e:
            raise InvalidRequest(str(e)) from None
        app: SdwanApp = get_client(ctx)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON.replace("cuts a host off", "lets a host back")])
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        warnings: list[str] = list(inv.warnings)
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        members, read_warn = await memberships(app, groups)
        warnings += read_warn
        slots_all, read_warn = await all_slots(app, groups, members)
        warnings += read_warn
        holders: list[dict[str, Any]] = []
        for grp in groups:
            gid = str(grp["id"])
            for ch, variables in slots_all.get(gid, {}).items():
                slots = [s for s, h in contained_at(slot_values(variables)).items() if h == addr]
                if not slots:
                    continue
                notes = note_values(variables)
                holders.append(
                    {
                        "group": grp,
                        "chassis": ch,
                        "row": chassis_rows.get(ch),
                        "assoc": next((d for d in members.get(gid, []) if str(d.get("chassis")) == ch), None),
                        "slots": slots,
                        "records": {s: notes.get(s) for s in slots},
                        "before": variables,
                        "after": merge_variables(variables, neutral(slots))[0],
                    }
                )
        contained = bool(holders)
        targets = [h for h in holders if h["row"] is not None]
        for h in holders:
            if h["row"] is None:
                warnings.append(f"{h['chassis']} is not in the inventory: its slot is reset, not deployed")
        if deploy and contained:
            for h in targets:
                more, busy_warn = await _deploy_blockers(app, h["row"], h["assoc"])
                blockers += more
                warnings += busy_warn
        names = [str(_host(h["row"]) or h["chassis"]) for h in holders]
        # Every other device of the holders' groups, as read now: the safety stop compares against it.
        held_in: dict[str, set[str]] = {}
        for h in holders:
            held_in.setdefault(str(h["group"]["id"]), set()).add(h["chassis"])
        others_before = {
            gid: {c: _by_name(v) for c, v in slots_all.get(gid, {}).items() if c not in held}
            for gid, held in held_in.items()
        }
        requests = [
            f"PUT {VARIABLES_PATH} ({n}: {', '.join(h['slots'])} and their notes back to neutral)"
            for n, h in zip(names, holders, strict=True)
        ]
        if deploy and targets:
            requests.append(f"POST {DEPLOY_PATH} ({', '.join(str(_host(h['row'])) for h in targets)} only)")
        plan = Plan(
            f"Release {addr} at {', '.join(names)}: reset {sum(len(h['slots']) for h in holders)} slot(s)"
            if contained
            else f"{addr} is not contained at any edge (no slot holds it): nothing to change",
            details={
                "tier": "dangerous",
                "ip": addr,
                "was_contained": contained,
                "slots": [
                    {
                        "device": n,
                        "group": h["group"].get("name"),
                        "slots": {
                            s: {
                                "from": addr,
                                "to": INERT[s],
                                "record": h["records"].get(s),
                                "record_to": NOTE_FREE,
                            }
                            for s in h["slots"]
                        },
                    }
                    for n, h in zip(names, holders, strict=True)
                ],
                "requests": requests,
                "deployed_to": [str(_host(h["row"])) for h in targets] if deploy else [],
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[f"Once deployed, {', '.join(names)} forwards {addr}'s traffic again."]
            if holders
            else [],
            fingerprint={
                "variables": {h["chassis"]: h["before"] for h in holders},
                "other_devices_variables": others_before,
            },
            blockers=blockers if contained else [],
            blast_radius=len(targets) if deploy and contained else 0,
            undo=Undo(
                "catsdwan_contain_at_edge",
                {
                    "ip": addr,
                    "edge": names[0],
                    "reason": f"contain {addr} again (undo of a release)",
                    "deploy": deploy,
                },
            )
            if len(names) == 1
            else f"catsdwan_contain_at_edge(ip='{addr}', edge=<each of {', '.join(names)}>, reason=...) "
            "contains it again",
        )

        async def apply() -> Any:
            started = int(time.time() * 1000)
            by_group: dict[str, list[dict[str, Any]]] = {}
            for h in holders:
                by_group.setdefault(str(h["group"]["id"]), []).append(h)
            for gid, hs in by_group.items():
                await app.api.put(
                    path(VARIABLES_PATH, id=gid),
                    _variables_body(hs[0]["group"], {h["chassis"]: h["after"] for h in hs}),
                )
                # Safety stop: the write must not have changed any other device's variables.
                chs = [h["chassis"] for h in hs] + list(others_before.get(gid, {}))
                moved = moved_devices(others_before.get(gid, {}), await cg_variables(app, gid, chs))
                if moved:
                    who = ", ".join(str(_host(chassis_rows.get(c)) or c) for c in moved)
                    raise UpstreamError(
                        f"after the variables write in configuration group {hs[0]['group'].get('name')}, the "
                        f"variables of {who} differ from before: nothing was deployed. Check with "
                        "catsdwan_containment_status"
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
                out["next"] = "catsdwan_deploy_config_group(group, devices=[the edge])"
            if contained:
                words = {str(h["group"].get("name")) for h in holders} | {h["chassis"] for h in holders}
                out["audit"] = {
                    "manager": await manager_audit(app, started, words),
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
        group: Annotated[
            str | None, Field(description="Only this configuration or policy group (name or id)")
        ] = None,
        trustsec: Annotated[
            bool,
            Field(description="Also read each reachable edge's TrustSec state (can it enforce SGT rules?)"),
        ] = False,
    ) -> dict[str, Any]:
        """Who is contained at an SD-WAN edge, and are the standing pieces in place. `contained`: one row per
        host a device's slot holds (device, configuration group, slot, expiry and reason from the slot's note,
        `expired`, `deployed`: whether the device is up to date with its group, and the release call).
        `expired` lists the hosts past their time box (nothing releases them by itself). `edge_acl`: per
        configuration group, the containment ACL in its CLI add-on (interfaces, remediation, intact) and per
        device where it is applied and its free slots. `baseline`: per policy group, each NGFW policy with the
        quarantine rules present or not, and the zone pairs; trustsec=true adds per edge whether it can
        enforce SGT rules (environment data from ISE; SGT learned by binding, SXP or inline tagging), the main
        path's prerequisite. ISE-quarantined hosts are on ISE: ise_list_anc_endpoints."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        chassis_rows = _by_chassis(inv)
        cgroups = await _groups(app, CONFIG_GROUPS_PATH)
        pgroups = await _groups(app, POLICY_GROUPS_PATH)
        if group:
            want = group.strip().lower()

            def named(g: dict[str, Any]) -> bool:
                return want in (str(g.get("id", "")).lower(), str(g.get("name", "")).lower())

            cgroups, pgroups = [g for g in cgroups if named(g)], [g for g in pgroups if named(g)]
            if not cgroups and not pgroups:
                raise InvalidRequest(f"No configuration or policy group is named {group!r}.")
        warnings: list[str] = []
        members, read_warn = await memberships(app, cgroups)
        warnings += read_warn
        slots_all, read_warn = await all_slots(app, cgroups, members)
        warnings += read_warn
        edge_acl: list[dict[str, Any]] = []
        contained: list[dict[str, Any]] = []
        for grp in cgroups:
            gid = str(grp["id"])
            addon, problems = await cli_addon(app, grp)
            warnings += problems
            acl = addon["acl"] if addon else None
            entry: dict[str, Any] = {
                "group": grp.get("name"),
                "cli_addon": addon["name"] if addon else None,
                "acl": {k: acl[k] for k in ("interfaces", "remediation", "intact")}
                if acl
                else f"none (catsdwan_set_containment_acl(group='{grp.get('name')}', interfaces=[...]))",
            }
            up = {str(d.get("chassis")): d.get("group_up_to_date") for d in members.get(gid, [])}
            devices: dict[str, Any] = {}
            for ch, variables in slots_all.get(gid, {}).items():
                host = str(_host(chassis_rows.get(ch)) or ch)
                rows = _slot_rows(variables)
                if acl:
                    devices[host] = {
                        "applied_on": resolve_interfaces(acl["interfaces"], variables),
                        "free_slots": len(slot_values(variables)) - len(rows),
                    }
                for h, r in rows.items():
                    contained.append(
                        {
                            "ip": h,
                            "device": host,
                            "group": grp.get("name"),
                            **r,
                            "deployed": up.get(ch),
                            "release": f"catsdwan_release_at_edge(ip='{h}')",
                        }
                    )
            if devices:
                entry["devices"] = devices
            edge_acl.append(entry)

        baseline: list[dict[str, Any]] = []
        details = list(await asyncio.gather(*(_group_detail(app, g) for g in pgroups)))
        for grp, d in zip(pgroups, details, strict=True):
            try:
                fwl = await group_firewall(app, d)
            except UpstreamError as e:
                warnings.append(f"policy group {grp.get('name')}: firewall not read: {str(e)[:150]}")
                continue
            pentry: dict[str, Any] = {
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
                    )
                },
            }
            if not fwl["ngfws"]:
                pentry["verdict"] = "no NGFW policy: no baseline (catsdwan_set_firewall_policy first)"
            if trustsec:
                try:
                    pmembers = await group_devices(app, str(grp.get("id")))
                except UpstreamError as e:
                    warnings.append(f"policy group {grp.get('name')}: devices not read: {str(e)[:150]}")
                    pmembers = []
                edge_rows = [
                    er
                    for m in pmembers
                    if (er := chassis_rows.get(str(m.get("chassis")))) and er in reachable(inv, "edge")
                ]
                pentry["trustsec"], ts_warn = await trustsec_readiness(app, edge_rows)
                warnings += ts_warn
            baseline.append(pentry)
        contained.sort(key=lambda c: (str(c["ip"]), str(c["device"])))
        out: dict[str, Any] = {
            "contained": contained,
            "expired": [c["ip"] for c in contained if c.get("expired")],
            "edge_acl": edge_acl,
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
2. The standing pieces (once, NOT per incident): {tool_ref("catsdwan_containment_status")} with
   group=<the edge's group>, trustsec=true. Main path: the edge's NGFW policy on the host's VPN holds the
   mcp-quarantine-* rules, deployed; missing: {tool_ref("catsdwan_set_containment_baseline")}
   (quarantine_sgt=<ISE's Quarantine SGT name:tag>, remediation=[remediation server, DNS]), then
   {tool_ref("catsdwan_deploy_policy_group")}. Fallback: `edge_acl` shows the containment ACL in the edge's
   configuration group, applied on the interface the host sits on; missing:
   {tool_ref("catsdwan_set_containment_acl")} (interfaces=[the LAN interfaces], remediation=[...]), then
   {tool_ref("catsdwan_deploy_config_group")} one edge at a time. Either is a change for
   EVERY edge of the group: say so, and only with the user's go-ahead for a change window.
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
   preview: the ONE device, the slot variable from -> to, the note (record) with its expiry, the ACL entry
   and the interfaces it is applied on, and `proof.other_devices` (every other edge of the group unchanged).
   Approve, confirm, then verify: {tool_ref("catsdwan_get_device_config")} with device=<edge>, diff=true
   (ACL mcp-contain holds `deny ip host {host} any`), traffic from the host fails ({tool_ref("catsdwan_ping")}
   from the edge to a peer host still works), and the result's `audit` entries
   ({tool_ref("catsdwan_audit_log")} with changes_only=true when they are not there yet).
   Release: {tool_ref("catsdwan_release_at_edge")} with ip="{host}" (preview, approve). It does NOT expire by
   itself: tell the user the expiry and that {tool_ref("catsdwan_containment_status")} lists expired hosts.

Report, ONE line first: contained by ISE (Quarantine SGT seen on <edge>, drops counted) / contained at <edge>
until <expiry> (fallback, why) / NOT contained (what is missing: ISE ANC policy, TrustSec on the edge, the
baseline or the containment ACL). Then the evidence per step, how to release, and what the user still has
to do (for example: TrustSec on the edges, an ANC policy on ISE, the containment ACL)."""
