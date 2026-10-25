"""#118: the controller's VPN precheck for a policy group, as catsdwan_deploy_policy_group, the W47 firewall
policy and the W45 baseline run it before anything is sent. Not a tool module (no register)."""

import asyncio
from typing import Any

from cat_sdwan_mcp._core import UpstreamError
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.edgefirewall import SEC_POLICY_LIST_PATH, parcels, zone_pairs_of
from cat_sdwan_mcp.policygroups import group_profiles
from cat_sdwan_mcp.serviceinsertion import target_of
from cat_sdwan_mcp.servicevpns import target_problems, zone_vpn_ids, zone_vpn_problems


def zone_vpns(zone_rows: list[dict[str, Any]], zone_ids: set[str]) -> dict[str, list[int]]:
    """{zone name: [VPN ids]} for the zones in `zone_ids` (rows from the policy-object security-zone list)."""
    out: dict[str, list[int]] = {}
    for z in zone_rows:
        if z["id"] in zone_ids and (vids := zone_vpn_ids(z["data"])):
            out[str(z.get("name"))] = vids
    return out


async def group_vpn_problems(
    app: SdwanApp, detail: dict[str, Any], vctx: dict[str, Any], *, targets: bool = True
) -> tuple[list[str], dict[str, Any], list[str]]:
    """(blockers, what was checked, read warnings) for a policy group's stored content: every traffic policy
    target must be a LAN VPN parcel name in each device's configuration group, every VPN of a zone the
    security policy binds must have a LAN VPN parcel there."""
    from cat_sdwan_mcp.tools.edgefirewall import list_objects
    from cat_sdwan_mcp.tools.serviceinsertion import traffic_policies

    blockers: list[str] = []
    warnings: list[str] = []
    checked: dict[str, Any] = {"configuration_groups": vctx.get("scope") or {}}
    profs = group_profiles(detail)
    for p in profs:
        if not targets or p["type"] != "application-priority":
            continue
        try:
            pols = await traffic_policies(app, p["id"])
        except UpstreamError as e:
            warnings.append(f"profile {p['name']}: traffic policies not read: {str(e)[:150]}")
            continue
        for tp in pols:
            vals = target_of(tp["data"])["vpns"]
            checked.setdefault("traffic_policy_targets", {})[str(tp["name"])] = vals
            blockers += [f"traffic policy {tp['name']}: {x}" for x in target_problems(vals, vctx)]
    sec = next((p for p in profs if p["type"] == "embedded-security"), None)
    po = next((p for p in profs if p["type"] == "policy-object"), None)
    if sec and po:
        try:
            pol, zones = await asyncio.gather(
                app.api.get(path(SEC_POLICY_LIST_PATH, id=sec["id"])),
                list_objects(app, po["id"], "security-zone"),
            )
        except UpstreamError as e:
            warnings.append(f"security policy or zones not read: {str(e)[:150]}")
        else:
            ids = {z for r in parcels(pol) for _, s, d in zone_pairs_of(r["data"]) for z in (s, d)}
            used = zone_vpns(zones, ids)
            if used:
                checked["zone_vpns"] = used
            blockers += zone_vpn_problems(used, vctx)
    return blockers, checked, warnings
