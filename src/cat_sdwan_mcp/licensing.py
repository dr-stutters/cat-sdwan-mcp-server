"""W28 licensing reads: the Manager's Smart Licensing state, licences per device (MSLA) and an edge's view.

Recorded on 20.18.3.1 (no Smart Account sync configured): `/v1/smart-licensing/user-settings`
{"isPresentCredentials": false}, `/association` {"association": []}, `/ea/fetch-sync-status` {};
`/v1/licensing/devices` {"devices": [...]} lists every WAN edge slot (25, the unjoined ones with hostName
"-"), each "Out Of Compliance" / "Unassigned" with no licence; `/msla/devices` only the three joined edges,
`/msla/licenses` [], `/msla/licenses/compliance` {"status": "Out Of Compliance", "complianceStatus":
[{reason}]}, `/msla/monitoring/licensedDeviceCount` {"totalDevices": 3, "licensedDevice": 0}. The C8000V
edges answer `device/license/usage` and `/registration` with no rows (licensing is managed from the Manager in
controller mode). `/v1/smart-licensing/sync` is a POST (a sync), so it is never called here.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from cat_sdwan_mcp.client import _as_list

USER_SETTINGS_PATH = "/dataservice/v1/smart-licensing/user-settings"
ASSOCIATION_PATH = "/dataservice/v1/smart-licensing/association"
SYNC_STATUS_PATH = "/dataservice/v1/smart-licensing/ea/fetch-sync-status"
DEVICES_PATH = "/dataservice/v1/licensing/devices"
MSLA_LICENSES_PATH = "/dataservice/msla/licenses"
MSLA_COMPLIANCE_PATH = "/dataservice/msla/licenses/compliance"
MSLA_COUNT_PATH = "/dataservice/msla/monitoring/licensedDeviceCount"
EDGE_USAGE_PATH = "/dataservice/device/license/usage"
EDGE_REGISTRATION_PATH = "/dataservice/device/license/registration"

_NONE = ("", "-", None)


def _val(v: Any) -> Any:
    return None if v in _NONE else v


def device_row(d: dict[str, Any]) -> dict[str, Any]:
    licences = []
    for lic in _as_list(d.get("licenses")):
        if isinstance(lic, dict):
            licences.append(
                lic.get("licenseName")
                or lic.get("displayName")
                or lic.get("name")
                or lic.get("tag")
                or str(lic)
            )
        elif lic:
            licences.append(str(lic))
    row = {
        "host": _val(d.get("hostName")),
        "system_ip": _val(d.get("configuredSystemIP")),
        "site_id": _val(d.get("site-id")),
        "model": _val(d.get("deviceModel")),
        "chassis": _val(d.get("uuid") or d.get("UUID")),
        "compliance": _val(d.get("complianceStatus") or d.get("compliance_status")),
        "reason": _val(d.get("inCompliantReason") or d.get("reason")),
        "licences": licences,
        "hsec": _val(d.get("hsecLicenseStatus")),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def compliance(body: Any) -> dict[str, Any]:
    data = body.get("data", body) if isinstance(body, dict) else {}
    if not isinstance(data, dict):
        return {}
    reasons = sorted(
        {
            str(c.get("reason"))
            for c in _as_list(data.get("complianceStatus"))
            if isinstance(c, dict) and c.get("reason")
        }
    )
    out: dict[str, Any] = {"status": data.get("status")}
    if reasons:
        out["reasons"] = reasons
    return {k: v for k, v in out.items() if v is not None}


def counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(r.get("compliance") or "unknown") for r in rows).most_common())


def smart_account(settings: Any, association: Any, sync: Any) -> dict[str, Any]:
    creds = settings.get("isPresentCredentials") if isinstance(settings, dict) else None
    assoc = association.get("association") if isinstance(association, dict) else association
    accounts = [a for a in _as_list(assoc) if a]
    out: dict[str, Any] = {
        "credentials": bool(creds) if creds is not None else "unknown",
        "virtual_accounts": accounts or "none associated",
    }
    if isinstance(sync, dict) and sync:
        out["sync_status"] = sync
    out["configured"] = bool(creds) and bool(accounts)
    return out
