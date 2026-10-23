"""W24 TrustSec and integrations: an edge's TrustSec state (environment data from ISE, PAC, SGT bindings,
SGACLs and their counters, SXP, pxGrid-learned bindings, 802.1X) and the Manager's ISE / pxGrid connection and
partner integrations (Catalyst Center SD-Access).

Recorded on 20.18.3.1 (no ISE configured): the edge's environment data is one record stuck in
`env-download-in-progress` with no server and device SGT 0 (last update the epoch); the other edge tables
answer with no rows; `device/policy/iptosgtbindings` answers 400 DEV0001 'Invalid data type
CEdgeIptoSgtbindings' (not supported on a C8000V on this release). On the Manager, `/ise/credentials` and
`/ise/credentials/pxgrid` answer `{}`, `/ise/connect` 400 ISEERRORR0016 and the ISE SGT list 400
ISEERRORR0025 ('ISE is not configured'); `/partner` answers `[]`.
"""

from __future__ import annotations

from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.inventory import iso

EDGE_PATHS: dict[str, str] = {
    "environment": "/dataservice/device/environmentData",
    "environment_servers": "/dataservice/device/environmentData/radiusServer",
    "pac": "/dataservice/device/ctsPac",
    "sgt_map": "/dataservice/device/roleBasedSgtMap",
    "permissions": "/dataservice/device/roleBasedPermissions",
    "counters": "/dataservice/device/roleBasedCounters",
    "sxp": "/dataservice/device/sxpConnections",
    "pxgrid_ip_sgt": "/dataservice/device/policy/iptosgtbindings",
    "pxgrid_ip_user": "/dataservice/device/policy/iptouserbindings",
    "pxgrid_status": "/dataservice/device/policy/pxgridstatus",
    "pxgrid_sessions": "/dataservice/device/policy/pxgridusersessions",
    "dot1x_clients": "/dataservice/device/dot1x/clients",
    "dot1x_interfaces": "/dataservice/device/dot1x/interfaces",
    "dot1x_radius": "/dataservice/device/dot1x/radius",
}

ISE_CONNECT_PATH = "/dataservice/ise/connect"
ISE_CREDENTIALS_PATH = "/dataservice/ise/credentials"
ISE_PXGRID_PATH = "/dataservice/ise/credentials/pxgrid"
ISE_SGT_PATH = "/dataservice/template/policy/ise/identity/sgt"
PARTNER_PATH = "/dataservice/partner"
DNAC_SITES_PATH = "/dataservice/partner/dnac/sda/site/{id}"
DNAC_DEVICES_PATH = "/dataservice/partner/dnac/sda/device/{id}"
DNAC_VPN_PATH = "/dataservice/partner/dnac/sda/vpn"

MASK = "********"
_NOISE = ("vdevice-name", "vdevice-host-name", "vdevice-dataKey", "lastupdated")
_OPAQUE = ("pac-opaque",)
ENV_DONE = ("env-download-complete", "complete", "completed", "downloaded")


def rows_of(data: Any) -> list[dict[str, Any]]:
    out = []
    for r in _as_list(data):
        if isinstance(r, dict):
            rec = {
                k: (MASK if k in _OPAQUE and v else v)
                for k, v in r.items()
                if k not in _NOISE and v not in (None, "")
            }
            if rec:
                out.append(rec)
    return out


def unsupported(error: str) -> bool:
    """The Manager's answer for a table this edge model or release does not have."""
    return "Invalid data type" in error


def environment(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    r = rows[0]
    last = str(r.get("last-updated-time") or "")
    refresh = str(r.get("next-refresh-time") or "")
    out: dict[str, Any] = {
        "status": r.get("status"),
        "device_sgt": r.get("device-sgt"),
        "servers": r.get("total-num-servers"),
        "last_updated": None if last.startswith("1970-01-01") else last or None,
        "next_refresh": None if refresh.startswith("1970-01-01") else refresh or None,
        "lifetime": r.get("life-time"),
    }
    out = {k: v for k, v in out.items() if v not in (None, "")}
    out["downloaded"] = str(r.get("status", "")).lower() in ENV_DONE
    if not out["downloaded"]:
        out["meaning"] = (
            "the edge has no TrustSec environment data from ISE"
            + (" (no RADIUS server to download it from)" if not r.get("total-num-servers") else "")
            + ": it has no SGT names or SGACLs from ISE"
        )
    return out


def sgt_row(r: dict[str, Any]) -> dict[str, Any]:
    out = {"ip": r.get("ip"), "vrf": r.get("vrf-name"), "sgt": r.get("sgt"), "learned_from": r.get("source")}
    return {k: v for k, v in out.items() if v not in (None, "")}


def permission_row(r: dict[str, Any], counters: dict[tuple[Any, Any], dict[str, Any]]) -> dict[str, Any]:
    key = (r.get("src-sgt"), r.get("dst-sgt"))
    c = counters.get(key, {})
    out = {
        "source_sgt": r.get("src-sgt"),
        "destination_sgt": r.get("dst-sgt"),
        "sgacl": r.get("sgacl-name"),
        "monitor_mode": r.get("monitor-mode"),
        "permitted": c.get("total-permit-count"),
        "denied": c.get("total-deny-count"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def counter_index(rows: list[dict[str, Any]]) -> dict[tuple[Any, Any], dict[str, Any]]:
    return {(r.get("src-sgt"), r.get("dst-sgt")): r for r in rows}


def sxp_row(r: dict[str, Any]) -> dict[str, Any]:
    out = {
        "peer": r.get("peer-ip"),
        "source": r.get("source-ip"),
        "vrf": r.get("vrf-name"),
        "mode": r.get("local-mode"),
        "speaker": r.get("speaker-state"),
        "listener": r.get("listener-state"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


# --- the Manager's integrations -------------------------------------------------------------------


def configured(body: Any) -> bool:
    """/ise/credentials answers `{}` (or no data) when ISE is not configured."""
    data = body.get("data", body) if isinstance(body, dict) else body
    if isinstance(data, list):
        return any(isinstance(d, dict) and d for d in data)
    return isinstance(data, dict) and any(v not in (None, "", [], {}) for v in data.values())


def partners(body: Any) -> list[dict[str, Any]]:
    """GET /partner flattened to {type, id, name, ...}: the body is a list of partners or of
    {partnerType, partners: [...]} groups (no partner registered in the lab, so both are accepted)."""
    out: list[dict[str, Any]] = []
    for item in _as_list(body.get("data", body) if isinstance(body, dict) else body):
        if not isinstance(item, dict):
            continue
        inner = item.get("partners") or item.get("data")
        if isinstance(inner, list):
            for p in inner:
                if isinstance(p, dict):
                    out.append(partner_row(p, item.get("partnerType") or item.get("type")))
        else:
            out.append(partner_row(item, None))
    return out


def partner_row(p: dict[str, Any], kind: Any) -> dict[str, Any]:
    out = {
        "type": p.get("partnerType") or p.get("type") or kind,
        "id": p.get("partnerId") or p.get("nmsId") or p.get("id"),
        "name": p.get("name") or p.get("partnerName"),
        "description": p.get("description"),
        "registered": iso(p.get("createdOn")) if p.get("createdOn") else None,
        "devices": p.get("deviceCount") or p.get("devices"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def is_dnac(p: dict[str, Any]) -> bool:
    return str(p.get("type", "")).lower() in ("dnac", "catalyst-center", "catalystcenter")
