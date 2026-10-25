"""#118: how a policy group names a service VPN, and the precheck the 20.18 controller applies at deploy.

Root cause (live, 20.18.3.1, 2026-10-24, w8-live; cat-sdwan #118): the controller compiles a policy group per
device and matches a traffic policy's `data.target.vpn` values against the **names of the LAN VPN parcels**
(the parcel's own `payload.name`, e.g. `mcp-w8-vpn10`) in the service profiles of the device's configuration
group. A VPN id (`"10"`), the parcel's `data.name` (the VRF description, e.g. `Discovered_VPN_10`) and a
segment name (GET /dataservice/segment) are all refused with "Please configure the VPN's <value>, in your
configuration-groups for the currently associated and deployed devices, before using them in policy-groups".
A VPN configured only in a CLI add-on profile (`vrf definition 10`) is refused the same way: it has no LAN
VPN parcel. The 20.18 GUI's traffic-policy VPN(s) picker offers exactly the LAN VPN parcel names (and
segment names). Cisco's API example for the parcel also shows a name: target.vpn ["test_vpn"].
Security zones are different: their `vpn` entry is a VPN number (Cisco's catalystwan SDK model:
"0-65530 single number"); the controller still needs a LAN VPN parcel with that vpnId in each device's group.

Shapes (recorded 20.18.3.1, read only, 2026-10-25): GET /v1/config-group -> [{id, name, profiles: [{id, name,
type: service|cli|transport|system, ...}], ...}]; GET /v1/feature-profile/sdwan/service/{id}/lan/vpn ->
{header, data: [{parcelId, parcelType: "lan/vpn", payload: {name, description, data: {name: {global
"Discovered_VPN_10"}, vpnId: {global 10}, ...}}}]}; GET /dataservice/segment -> {header, data:
[{segmentName, segmentId: "10", solution, id, referenceCount}]}.
"""

from __future__ import annotations

import asyncio
from typing import Any

from cat_sdwan_mcp._core import UpstreamError
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import ASSOCIATE_PATH, CONFIG_GROUPS_PATH, associated, path
from cat_sdwan_mcp.serviceinsertion import LAN_VPN_LIST_PATH, vpn_parcels, vpn_problem

SEGMENT_PATH = "/dataservice/segment"
CONTROLLER_ERROR = (
    "Please configure the VPN's {vpn} in your configuration-groups ... before using them in policy-groups"
)


def segment_rows(body: Any) -> list[dict[str, Any]]:
    """[{name, vpn}] from GET /dataservice/segment."""
    rows = body.get("data") if isinstance(body, dict) else body
    out = []
    for r in _as_list(rows):
        if isinstance(r, dict) and r.get("segmentName") is not None:
            out.append({"name": str(r["segmentName"]), "vpn": str(r.get("segmentId") or "")})
    return out


def _vid(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def group_index(
    groups: list[dict[str, Any]], parcels_by_profile: dict[str, list[dict[str, Any]]]
) -> dict[str, list[dict[str, Any]]]:
    """{configuration group name: [{vpn, name, profile, vpn_name}]}: the LAN VPN parcels of each group's
    service profiles."""
    out: dict[str, list[dict[str, Any]]] = {}
    for gr in groups:
        rows: list[dict[str, Any]] = []
        for p in _as_list(gr.get("profiles")):
            if not (isinstance(p, dict) and p.get("type") == "service" and p.get("id")):
                continue
            for v in parcels_by_profile.get(str(p["id"]), []):
                rows.append(
                    {
                        "vpn": _vid(v.get("vpn")),
                        "name": v.get("name"),
                        "profile": p.get("name"),
                        "vpn_name": v.get("vpn_name"),
                    }
                )
        out[str(gr.get("name"))] = rows
    return out


def fix_text(vpn: int, group: str) -> str:
    return (
        f"convert VPN {vpn} to a LAN VPN parcel in {group}: a service profile with a LAN VPN parcel (vpnId "
        f"{vpn}, OMP advertise connected + static so the VPN's routes stay in OMP) and its LAN interfaces as "
        "Ethernet parcels under it, taken out of any CLI add-on profile (catsdwan_set_feature_parcel, or the "
        f"GUI); deploy {group} (catsdwan_deploy_config_group, one edge first), then retry"
    )


def _missing(vpn: int, group: str, hosts: list[str]) -> str:
    on = f" ({', '.join(hosts)})" if hosts else ""
    return (
        f"VPN {vpn} has no LAN VPN parcel in configuration group {group}{on}, so the controller refuses the "
        f'policy group ("{CONTROLLER_ERROR.format(vpn=vpn)}"); VPN {vpn} may be only CLI-profile '
        f"configuration there. Fix: {fix_text(vpn, group)}"
    )


def _scope(ctx: dict[str, Any]) -> tuple[dict[str, list[str]], bool, list[str]]:
    """({group: hosts}, strict, warnings). strict: the devices' own groups, each must hold the VPN. Not
    strict (no device placed in a group yet): every group, and one holding it is enough."""
    scope: dict[str, list[str]] = ctx.get("scope") or {}
    if scope:
        return scope, True, []
    every: dict[str, list[str]] = {g: [] for g in ctx.get("index") or {}}
    warn = (
        ["no device of the policy group is in a configuration group the Manager listed: VPNs resolved "
         "against every configuration group; the controller checks each device's own group at deploy"]
        if ctx.get("devices_given")
        else []
    )  # fmt: skip
    return every, False, warn


def resolve_vpns(refs: list[Any], ctx: dict[str, Any]) -> dict[str, Any]:
    """VPN references (ids like 10 / '10', LAN VPN parcel names, the parcel's VPN name, segment names) ->
    {names: the LAN VPN parcel names to write, ids: the VPN ids, rows: per reference, blockers, warnings}.
    Every device's configuration group must have a LAN VPN parcel for each VPN; when groups name it
    differently, all names are written (each device matches its own)."""
    index: dict[str, list[dict[str, Any]]] = ctx.get("index") or {}
    segments: list[dict[str, Any]] = ctx.get("segments") or []
    scope, strict, warnings = _scope(ctx)
    warnings = warnings + list(ctx.get("warnings") or [])
    blockers: list[str] = []
    names: list[str] = []
    ids: list[int] = []
    rows: list[dict[str, Any]] = []
    every = [v for vs in index.values() for v in vs]
    for ref in refs:
        given = str(ref).strip()
        if not given:
            continue
        vid = _vid(given)
        how = "VPN id"
        if vid is None:
            low = given.lower()
            hit = next((v for v in every if str(v.get("name") or "").lower() == low), None)
            how = "LAN VPN parcel name"
            if hit is None:
                hit = next((v for v in every if str(v.get("vpn_name") or "").lower() == low), None)
                how = "the parcel's VPN name (data.name)"
            if hit is not None:
                vid = hit["vpn"]
            else:
                seg = next((s for s in segments if s["name"].lower() == low), None)
                if seg is not None and _vid(seg["vpn"]) is not None:
                    vid = _vid(seg["vpn"])
                    how = "segment name"
            if vid is None:
                known = sorted({str(v["name"]) for v in every if v.get("name")})
                blockers.append(
                    f"VPN {given!r} is no VPN id, LAN VPN parcel name or segment name (LAN VPN parcels: "
                    f"{', '.join(known) or 'none'})"
                )
                rows.append({"given": given, "resolved": None})
                continue
            if how != "LAN VPN parcel name":
                warnings.append(
                    f"{given!r} is a {how}, which the controller does not match: resolved to VPN {vid}'s "
                    "LAN VPN parcel name"
                )
        if (p := vpn_problem(vid)) is not None:
            blockers.append(p)
            rows.append({"given": given, "resolved": None})
            continue
        found: list[str] = []
        per_group: dict[str, list[str]] = {}
        for gname, hosts in scope.items():
            hits = [str(v["name"]) for v in index.get(gname, []) if v.get("vpn") == vid and v.get("name")]
            if not hits:
                if strict:
                    blockers.append(_missing(vid, gname, hosts))
                continue
            if len(hits) > 1:
                warnings.append(f"configuration group {gname} has {len(hits)} LAN VPN parcels for VPN {vid}")
            per_group[gname] = hits
            found += [h for h in hits if h not in found]
        if not strict and not found:
            blockers.append(
                f"VPN {vid} has no LAN VPN parcel in any configuration group, so the controller refuses a "
                f"policy group that uses it. Fix: {fix_text(vid, 'the configuration group of each edge')}"
            )
        rows.append({"given": given, "vpn": vid, "how": how, "parcel_names": found, "groups": per_group})
        if vid not in ids:
            ids.append(vid)
        names += [n for n in found if n not in names]
    return {"names": names, "ids": ids, "rows": rows, "blockers": blockers, "warnings": warnings}


def target_problems(values: list[str], ctx: dict[str, Any]) -> list[str]:
    """Why a stored traffic policy's target VPN values fail the controller's match, per device group: each
    group must hold a LAN VPN parcel with that exact name."""
    index: dict[str, list[dict[str, Any]]] = ctx.get("index") or {}
    scope, strict, _ = _scope(ctx)
    if not strict:
        return []
    out = []
    for val in values:
        for gname, hosts in scope.items():
            parcels = index.get(gname, [])
            if any(str(v.get("name")) == val for v in parcels):
                continue
            vid = _vid(val)
            if vid is None:
                hit = next(
                    (v for vs in index.values() for v in vs if val.lower() in
                     (str(v.get("vpn_name") or "").lower(), str(v.get("name") or "").lower())),
                    None,
                )  # fmt: skip
                vid = hit["vpn"] if hit else None
            if vid is None:
                seg = next((s for s in ctx.get("segments") or [] if s["name"] == val), None)
                vid = _vid(seg["vpn"]) if seg else None
            mine = [str(v["name"]) for v in parcels if vid is not None and v.get("vpn") == vid]
            on = f" ({', '.join(hosts)})" if hosts else ""
            if mine:
                out.append(
                    f"target VPN {val!r} is not a LAN VPN parcel name in configuration group {gname}{on}: "
                    f"the controller matches parcel names; use {', '.join(repr(m) for m in mine)} "
                    "(catsdwan_set_service_steering resolves a VPN id to it)"
                )
            elif vid is not None:
                out.append(_missing(vid, gname, hosts))
            else:
                out.append(f"target VPN {val!r} matches no LAN VPN parcel in configuration group {gname}{on}")
    return out


def vpn_ids_by_name(ctx: dict[str, Any]) -> dict[str, int]:
    """{LAN VPN parcel name, or the segment name: VPN id} over every configuration group (to read stored
    targets back as VPN ids)."""
    out: dict[str, int] = {}
    for s in ctx.get("segments") or []:
        if (v := _vid(s["vpn"])) is not None:
            out[s["name"]] = v
    for vs in (ctx.get("index") or {}).values():
        for v in vs:
            if v.get("name") and v.get("vpn") is not None:
                out[str(v["name"])] = int(v["vpn"])
    return out


def zone_vpn_problems(zone_vpns: dict[str, list[int]], ctx: dict[str, Any]) -> list[str]:
    """{zone name: [VPN ids]} -> blockers for a VPN with no LAN VPN parcel in a device's group."""
    index: dict[str, list[dict[str, Any]]] = ctx.get("index") or {}
    scope, strict, _ = _scope(ctx)
    if not strict:
        return []
    out = []
    for zone, vids in zone_vpns.items():
        for vid in vids:
            for gname, hosts in scope.items():
                if not any(v.get("vpn") == vid for v in index.get(gname, [])):
                    out.append(f"zone {zone}: {_missing(vid, gname, hosts)}")
    return out


def zone_vpn_ids(data: dict[str, Any]) -> list[int]:
    """The VPN numbers a security-zone object holds."""
    out = []
    for e in _as_list(data.get("entries")):
        if isinstance(e, dict) and isinstance(e.get("vpn"), dict):
            v = _vid(e["vpn"].get("value"))
            if v is not None:
                out.append(v)
    return out


def zone_value_ids(values: list[str], ctx: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Zone values with LAN VPN parcel names / segment names turned into VPN ids (a zone entry is a VPN
    number); interface names and ids are kept. (values, notes)."""
    every = [v for vs in (ctx.get("index") or {}).values() for v in vs]
    segments = ctx.get("segments") or []
    out, notes = [], []
    for raw in values:
        val = str(raw).strip()
        low = val.lower()
        hit = next(
            (
                v
                for v in every
                if low in (str(v.get("name") or "").lower(), str(v.get("vpn_name") or "").lower())
            ),
            None,
        )
        vid = hit["vpn"] if hit and hit.get("vpn") is not None else None
        if vid is None:
            seg = next((s for s in segments if s["name"].lower() == low), None)
            vid = _vid(seg["vpn"]) if seg else None
        if vid is not None and _vid(val) is None:
            notes.append(f"{val!r} -> VPN {vid} (a zone holds VPN numbers)")
            out.append(str(vid))
        else:
            out.append(val)
    return out, notes


# --- reads -----------------------------------------------------------------------------------------


async def vpn_context(app: SdwanApp, chassis: list[str] | None) -> dict[str, Any]:
    """What resolve_vpns needs: {index: {group: LAN VPN parcels}, scope: {group of the devices: hosts},
    segments, warnings, devices_given}. `chassis` None or [] = no device scope (every group is listed in
    index; resolve against all of them)."""
    warnings: list[str] = []
    body = await app.api.get(CONFIG_GROUPS_PATH)
    groups = [
        g for g in _as_list(body.get("data") if isinstance(body, dict) else body) if isinstance(g, dict)
    ]
    profile_ids = sorted(
        {
            str(p["id"])
            for g in groups
            for p in _as_list(g.get("profiles"))
            if isinstance(p, dict) and p.get("type") == "service" and p.get("id")
        }
    )
    got = await asyncio.gather(
        *(app.api.get(path(LAN_VPN_LIST_PATH, profile=pid)) for pid in profile_ids), return_exceptions=True
    )
    parcels: dict[str, list[dict[str, Any]]] = {}
    for pid, res in zip(profile_ids, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"service profile {pid}: LAN VPN parcels not read: {str(res)[:150]}")
            continue
        if isinstance(res, BaseException):
            raise res
        parcels[pid] = vpn_parcels(res)
    index = group_index(groups, parcels)
    scope: dict[str, list[str]] = {}
    if chassis:
        want = {str(c) for c in chassis}
        assoc = await asyncio.gather(
            *(app.api.get(path(ASSOCIATE_PATH, id=str(g.get("id")))) for g in groups), return_exceptions=True
        )
        placed: set[str] = set()
        for g, res in zip(groups, assoc, strict=True):
            if isinstance(res, UpstreamError):
                warnings.append(f"configuration group {g.get('name')}: devices not read: {str(res)[:150]}")
                continue
            if isinstance(res, BaseException):
                raise res
            mine = [d for d in associated(res) if str(d.get("chassis")) in want]
            if mine:
                scope[str(g.get("name"))] = [str(d.get("host") or d.get("chassis")) for d in mine]
                placed |= {str(d.get("chassis")) for d in mine}
        if left := sorted(want - placed):
            warnings.append(
                f"{len(left)} device(s) are in no configuration group the Manager listed: not checked"
            )
    segments: list[dict[str, Any]] = []
    try:
        segments = segment_rows(await app.api.get(SEGMENT_PATH))
    except UpstreamError as e:
        warnings.append(f"segments not read (segment names not resolved): {str(e)[:150]}")
    return {
        "index": index,
        "scope": scope,
        "segments": segments,
        "warnings": warnings,
        "devices_given": chassis is not None,
    }
