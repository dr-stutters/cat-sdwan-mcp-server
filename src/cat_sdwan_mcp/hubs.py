"""Hub detection for change tiering (#102) when CATSDWAN_HUB_DEVICES is unset.

CATSDWAN_HUB_DEVICES is authoritative: when it is set nothing here runs. Without it a deploy or attach to a
hub used to tier 'write' (the Wave 7 live run deployed to the lab hub that way). A validated design names its
hubs, so the fallback reads the evidence the Manager already holds, fail-safe
(a heuristic hub is dangerous tier):

1. A hub-and-spoke topology (centralised policy definitions): a device at a site in a hub site list is a hub.
   GET /dataservice/template/policy/definition/hubandspoke (summary rows; 20.18.3 recorded: `data` [] in the
   lab, which has none), GET .../hubandspoke/{definitionId} ({definition: {subDefinitions: [{spokes:
   [{siteList, hubs: [{siteList}]}]}]}}, Cisco's documented shape), GET /dataservice/template/policy/list/site
   ({listId, entries: [{siteId}]}, ranges '100-199').
2. BFD: the Manager's state database (GET /dataservice/data/device/state/BFDSessions; 20.18.3 recorded: per
   session `vdevice-name` = the local system IP, `system-ip` = the remote edge, `site-id` = the remote site),
   or each reachable edge live when that API is missing. An edge whose sessions reach every other site of the
   fabric (at least two) is a hub. When every edge's do (a full mesh), BFD cannot tell: the status is
   'unknown' (#167: the lab's DC edge was called 'not a hub' and tiered write).
3. OMP, only for a full mesh: the service-VPN routes the first reachable controller holds (GET
   /dataservice/device/omp/routes/received?deviceId=<controller>; 20.18.3 recorded: `vpn-id`, `prefix`,
   `originator`, `status`, one row per TLOC). An edge that alone originates most (more than half) of the
   service-VPN prefixes, with at least two other originating edges, is a hub by heuristic: the DC site every
   branch's shared prefixes come from (CVD: the data centre is the hub even without a hub-and-spoke policy).

When neither can be read, or a device has no BFD sessions, its hub status is 'unknown' and the preview says so
(the tier stays as the other rules make it).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from cat_sdwan_mcp._core import UpstreamError
from cat_sdwan_mcp.changes import split_list, tier_reasons
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.control import OMP_ROUTES_PATH
from cat_sdwan_mcp.dataplane import BFD_SESSIONS_PATH, BULK_BFD
from cat_sdwan_mcp.fabric import device_rows, fan_out, reachable
from cat_sdwan_mcp.inventory import Inventory
from cat_sdwan_mcp.policy import LIST_TYPE_PATH, _refs, by_id, in_site_list, parse_definition, rows

HUB_SPOKE_PATH = "/dataservice/template/policy/definition/hubandspoke"
HUB_SPOKE_DEF_PATH = HUB_SPOKE_PATH + "/{id}"
BULK_CAP = 5000  # BFD sessions read from the state database
LIVE_CAP = 50  # edges read live when the state database API is missing
DEF_CAP = 20  # hub-and-spoke definitions read
SET_HINT = "set CATSDWAN_HUB_DEVICES"
FULL_MESH = "unknown: the fabric's BFD is a full mesh, so BFD cannot tell"
TRANSPORT_VPNS = ("0", "512")
MIN_SERVICE_ROUTES = 3  # fewer service-VPN prefixes than this say nothing about a hub


@dataclass
class HubCheck:
    """Heuristic hubs (chassis -> reason), each device's hub status in words, and what could not be read."""

    hubs: dict[str, str] = field(default_factory=dict)
    status: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# --- pure helpers ----------------------------------------------------------------------------------


def hub_site_lists(definition: dict[str, Any]) -> list[str]:
    """The hub site-list ids of one hub-and-spoke definition record."""
    defn = parse_definition(definition.get("definition"))
    out: list[str] = []
    for sub in _as_list(defn.get("subDefinitions")):
        for spoke in _as_list(sub.get("spokes") if isinstance(sub, dict) else None):
            for h in _as_list(spoke.get("hubs") if isinstance(spoke, dict) else None):
                if isinstance(h, dict):
                    out += [x for x in _refs(h.get("siteList")) if x not in out]
    return out


def policy_hubs(
    targets: list[dict[str, Any]], definitions: list[dict[str, Any]], lists: dict[str, dict[str, Any]]
) -> dict[str, str]:
    """chassis -> reason for each target at a hub site of a hub-and-spoke topology."""
    out: dict[str, str] = {}
    for d in definitions:
        for ref in hub_site_lists(d):
            lst = lists.get(ref)
            for r in targets:
                site = str(r.get("site_id") or "")
                if site and str(r["chassis"]) not in out and in_site_list(site, lst):
                    name = (lst or {}).get("name") or ref
                    out[str(r["chassis"])] = (
                        f"site {site} is a hub site (list {name}) of hub-and-spoke topology "
                        f"{d.get('name') or d.get('definitionId') or '?'}"
                    )
    return out


def bfd_view(
    sessions: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, str]]:
    """From BFD sessions: (system IP -> hub reason, system IP -> not-a-hub reason) for every local edge.

    An edge is a hub when its sessions reach every other site seen in the fabric's BFD (at least two) and not
    every edge's do (a full mesh has no hub)."""
    own = {
        str(e["system_ip"]): str(e.get("site_id")) for e in edges if e.get("system_ip") and e.get("site_id")
    }
    peers: dict[str, set[str]] = defaultdict(set)
    count: dict[str, int] = defaultdict(int)
    for s in sessions:
        local = str(s.get("vdevice-name") or "")
        if not local:
            continue
        count[local] += 1
        if s.get("site-id") not in (None, ""):
            peers[local].add(str(s["site-id"]))
    sites = {own[x] for x in count if x in own} | {p for ps in peers.values() for p in ps}
    most = max(count.values(), default=0)
    hubs: dict[str, str] = {}
    not_hubs: dict[str, str] = {}
    for local in count:
        others = sites - {own.get(local, "")}
        reached = peers[local] & others
        if len(others) < 2:
            not_hubs[local] = f"unknown: BFD shows only {len(others)} other site(s)"
        elif reached >= others:
            n = count[local]
            hubs[local] = f"BFD sessions to all {len(others)} other sites ({n} sessions" + (
                ", the most of any edge)" if n == most else ")"
            )
        else:
            not_hubs[local] = f"not a hub: BFD sessions to {len(reached)} of {len(others)} other sites"
    if hubs and not not_hubs:  # every edge reaches every site: a full mesh, where BFD cannot tell (#167)
        not_hubs = dict.fromkeys(hubs, FULL_MESH)
        hubs = {}
    return hubs, not_hubs


def omp_view(routes: list[dict[str, Any]], source: str) -> tuple[dict[str, str], dict[str, str]]:
    """From the OMP routes a controller holds: (system IP -> hub reason, system IP -> what OMP shows) for
    every originator of service-VPN prefixes.

    A hub is the sole originator of more than half of the service-VPN prefixes (VPN 0 and 512 and invalid
    routes left out) while at least two other edges originate some: a DC site every branch's shared prefixes
    come from. Too few prefixes or originators prove nothing."""
    origins: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in routes:
        vpn, prefix, origin = (str(r.get(k, "")) for k in ("vpn-id", "prefix", "originator"))
        if (
            prefix in ("", "None")
            or origin in ("", "None")
            or vpn in TRANSPORT_VPNS
            or "Inv" in str(r.get("status", "")).split()
        ):
            continue
        origins[(vpn, prefix)].add(origin)
    total = len(origins)
    sole: dict[str, int] = defaultdict(int)
    for owners in origins.values():
        if len(owners) == 1:
            sole[next(iter(owners))] += 1
    every = {o for owners in origins.values() for o in owners}
    seen = {o: f"OMP: sole originator of {sole.get(o, 0)} of {total} service routes" for o in every}
    if total < MIN_SERVICE_ROUTES or len(every) < 3:
        return {}, seen
    hubs = {
        o: f"sole originator of {n} of {total} service routes in OMP on {source}; BFD is a full mesh"
        for o, n in sole.items()
        if 2 * n > total
    }
    return hubs, seen


# --- reads -----------------------------------------------------------------------------------------


async def _policy_evidence(app: SdwanApp, targets: list[dict[str, Any]]) -> tuple[dict[str, str], str | None]:
    """Hubs from hub-and-spoke topologies, or (empty, why not read)."""
    try:
        summary = rows(await app.api.get(HUB_SPOKE_PATH))
        ids = [str(i) for d in summary if (i := d.get("definitionId") or d.get("id"))]
        if not ids:
            return {}, None
        defs = []
        for def_id in ids[:DEF_CAP]:
            body = await app.api.get(path(HUB_SPOKE_DEF_PATH, id=def_id))
            if isinstance(body, dict):
                defs.append(body)
        lists = by_id(rows(await app.api.get(path(LIST_TYPE_PATH, type="site"))))
    except UpstreamError as e:
        return {}, f"hub-and-spoke topologies not read ({str(e)[:160]})"
    return policy_hubs(targets, defs, lists), None


async def _omp_evidence(app: SdwanApp, inv: Inventory) -> tuple[dict[str, str], dict[str, str], str | None]:
    """omp_view() from the first reachable controller, or (empty, empty, why not read)."""
    controllers = reachable(inv, "controller")
    if not controllers:
        return {}, {}, "no reachable controller to read OMP routes from"
    ctl = controllers[0]
    try:
        routes = await device_rows(app, OMP_ROUTES_PATH.format(direction="received"), str(ctl["system_ip"]))
    except UpstreamError as e:
        return {}, {}, f"OMP routes not read from {ctl.get('host')} ({str(e)[:140]})"
    hubs, seen = omp_view(routes, str(ctl.get("host") or ctl["system_ip"]))
    return hubs, seen, None


async def _bfd_sessions(
    app: SdwanApp, inv: Inventory
) -> tuple[list[dict[str, Any]] | None, str | None, str | None]:
    """Every edge's BFD sessions (state database, else live per reachable edge): (rows or None, why not read,
    why incomplete). Incomplete rows can only prove a hub: a 'not a hub' from them is reported unknown."""
    try:
        got, more = await app.bulk_state(BULK_BFD, limit=BULK_CAP)
        return got, None, (f"BFD state database cut at {BULK_CAP} sessions" if more else None)
    except UpstreamError as e:
        bulk_error = str(e)[:140]
    edges = reachable(inv, "edge")
    if len(edges) > LIVE_CAP:
        return (
            None,
            f"BFD state database not read ({bulk_error}) and {len(edges)} edges are too many to ask live",
            None,
        )
    res = await fan_out(edges, lambda d: device_rows(app, BFD_SESSIONS_PATH, str(d["system_ip"])))
    ok = [x for x in res if not isinstance(x, UpstreamError)]
    if not ok:
        return None, f"BFD sessions not read ({bulk_error})", None
    return [b for x in ok for b in x], None, None


async def detect_hubs(app: SdwanApp, inv: Inventory, devices: list[dict[str, Any]]) -> HubCheck:
    """Heuristic hub status of the edges in `devices`; nothing when CATSDWAN_HUB_DEVICES is set."""
    out = HubCheck()
    targets = [r for r in devices if r.get("role") == "edge" and r.get("chassis")]
    if split_list(app.settings.hub_devices) or not targets:
        return out
    by_policy, policy_error = await _policy_evidence(app, targets)
    sessions, bfd_error, partial = await _bfd_sessions(app, inv)
    hubs, not_hubs = bfd_view(sessions or [], [r for r in inv.rows if r.get("role") == "edge"])
    by_omp: dict[str, str] = {}
    omp_seen: dict[str, str] = {}
    omp_error: str | None = None
    if any(not_hubs.get(str(r.get("system_ip") or "")) == FULL_MESH for r in targets):
        by_omp, omp_seen, omp_error = await _omp_evidence(app, inv)
    for r in targets:
        c, ip = str(r["chassis"]), str(r.get("system_ip") or "")
        host = str(r.get("host") or c)
        if c in by_policy:
            why = by_policy[c]
        elif ip in hubs:
            why = hubs[ip]
        elif ip in by_omp:
            why = by_omp[ip]
        else:
            seen = not_hubs.get(ip)
            if seen and partial:  # a cut-off read can miss this edge's sessions to some sites
                seen = f"unknown: {partial}"
            if seen and not seen.startswith("unknown"):
                out.status[host] = seen
                continue
            missing = [x for x in (policy_error, bfd_error) if x]
            if seen:
                missing.append(seen.removeprefix("unknown: "))
                if seen == FULL_MESH:
                    missing.append(omp_error or omp_seen.get(ip) or "OMP: originates no service routes")
            elif not bfd_error:
                missing.append(f"no BFD sessions recorded for {host}")
            out.status[host] = "unknown"
            out.warnings.append(f"hub status of {host} unknown: {'; '.join(missing)}; {SET_HINT}")
            continue
        out.hubs[c] = why
        out.status[host] = f"hub by heuristic ({why})"
    return out


async def change_tier(
    app: SdwanApp, inv: Inventory, rows_: list[dict[str, Any]]
) -> tuple[list[str], HubCheck]:
    """tier_reasons() plus heuristic hubs: (reasons, the hub check for the preview)."""
    check = await detect_hubs(app, inv, rows_)
    reasons = tier_reasons(rows_, app.settings.hub_devices, app.settings.protected_sites)
    for r in rows_:
        why = check.hubs.get(str(r.get("chassis")))
        if why:
            reasons.append(f"{r.get('host') or r.get('chassis')} is a hub by heuristic ({why}); {SET_HINT}")
    return reasons, check
