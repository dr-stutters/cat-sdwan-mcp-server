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
Security zones are matched the same way (live, 20.18.3.1, 2026-10-25, w8-live; cat-sdwan #126): a zone entry
`vpn: "10"` makes the policy-group deploy fail with HTTP 500 GNGRP0013 "Vpn Id for vpn name 10 not found.
Please make sure vpn names have been defined in Config Group and Deployed"; `vpn: "mcp-w8-vpn10"` (the LAN VPN
parcel name) deploys and renders `zone security mcp-w8-lan / vpn 10` on the edge. (Cisco's catalystwan SDK
model says "0-65530 single number"; the 20.18 controller does not take one.) VPN 0 and 512 have no LAN VPN
parcel and stay numbers (unproven on the controller).

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
        ["no device of the policy group is associated with a configuration group yet (or the policy group "
         "has no device): VPNs resolved against every configuration group; the controller checks each "
         "device's own group at deploy"]
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


def target_problems(
    values: list[str],
    ctx: dict[str, Any],
    what: str = "target VPN",
    fixer: str = "catsdwan_set_service_steering",
) -> list[str]:
    """Why stored VPN values (a traffic policy's targets, a zone's VPNs) fail the controller's match, per
    device group: each group must hold a LAN VPN parcel with that exact name."""
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
                    f"{what} {val!r} is not a LAN VPN parcel name in configuration group {gname}{on}: "
                    f"the controller matches parcel names; use {', '.join(repr(m) for m in mine)} "
                    f"({fixer} resolves a VPN id to it)"
                )
            elif vid is not None:
                out.append(_missing(vid, gname, hosts))
            else:
                out.append(f"{what} {val!r} matches no LAN VPN parcel in configuration group {gname}{on}")
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


def zone_vpn_problems(zone_vpns: dict[str, list[str]], ctx: dict[str, Any]) -> list[str]:
    """{zone name: [stored VPN values]} -> blockers, per device group: each service VPN of a zone must be the
    name of a LAN VPN parcel in that group (#126: the controller refuses a VPN number with GNGRP0013). VPN 0
    and 512 are not checked (transport / management: WAN-side parcels, never LAN VPN parcels)."""
    out = []
    for zone, values in zone_vpns.items():
        for val in values:
            vid = _vid(val)
            if vid is not None and vpn_problem(vid) is not None:
                continue
            out += [
                f"zone {zone}: {p}"
                for p in target_problems([val], ctx, "VPN", "catsdwan_set_security_object(kind='zone')")
            ]
    return out


def zone_vpn_values(data: dict[str, Any]) -> list[str]:
    """The VPN values a security-zone object holds, as stored (LAN VPN parcel names; VPN 0 / 512 numbers)."""
    out = []
    for e in _as_list(data.get("entries")):
        if isinstance(e, dict) and isinstance(e.get("vpn"), dict):
            v = e["vpn"].get("value")
            if v is not None and str(v).strip():
                out.append(str(v).strip())
    return out


def _known_name(val: str, ctx: dict[str, Any]) -> bool:
    low = val.lower()
    every = [v for vs in (ctx.get("index") or {}).values() for v in vs]
    return any(
        low in (str(v.get("name") or "").lower(), str(v.get("vpn_name") or "").lower()) for v in every
    ) or any(s["name"].lower() == low for s in ctx.get("segments") or [])


def zone_values(values: list[str], ctx: dict[str, Any]) -> dict[str, Any]:
    """A zone's values -> what its entries hold (#126): VPN ids, LAN VPN parcel names, the parcel's VPN name
    and segment names become the LAN VPN parcel name(s) (servicevpns.resolve_vpns); VPN 0 / 512 stay
    numbers; anything else is an interface. {values, vpn_names: the values that are VPN entries, rows,
    blockers, warnings}."""
    out: list[str] = []
    vpn_names: list[str] = []
    rows: list[dict[str, Any]] = []
    blockers: list[str] = []
    warnings: list[str] = []
    for raw in values:
        val = str(raw).strip()
        if not val:
            continue
        vid = _vid(val)
        if vid is not None and vpn_problem(vid) is not None:
            warnings.append(
                f"VPN {vid} is a transport / management VPN with no LAN VPN parcel: kept as the number "
                "(unproven on the 20.18 controller, which looks service VPNs up by parcel name)"
            )
            out.append(val)
            vpn_names.append(val)
            continue
        if vid is None and not _known_name(val, ctx):
            out.append(val)  # an interface name (the Manager's schema checks its pattern)
            continue
        r = resolve_vpns([val], ctx)
        blockers += r["blockers"]
        warnings += [w for w in r["warnings"] if w not in warnings]
        rows += r["rows"]
        if len(r["names"]) > 1:
            warnings.append(
                f"configuration groups name VPN {r['ids'][0]} differently ({', '.join(r['names'])}): the "
                "zone holds every name; the controller resolves each name per device (check the deploy "
                "preview)"
            )
        for n in r["names"]:
            if n not in out:
                out.append(n)
                vpn_names.append(n)
    return {"values": out, "vpn_names": vpn_names, "rows": rows, "blockers": blockers, "warnings": warnings}


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
