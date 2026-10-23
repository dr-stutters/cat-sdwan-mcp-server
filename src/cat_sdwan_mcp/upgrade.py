"""W27 controller upgrades: the Manager's controllers-upgrade workflow (20.18+), which upgrades the
validators, then the controllers, then the Manager to one version from its software repository (or CCO).

Recorded on 20.18.3.1 (no image in the repository): `GET /v1/controllers-upgrade/available-versions`
answers {"availableVersions": []} for imageType upgrade and patch; `version-compliance-info?version=20.18.3.1`
gives the minimum controller, validator and device versions and non-compliant counts (all 0). The schedule
body follows the OpenAPI document's examples: {action: controllers_upgrade | controllers_patch_upgrade,
targetVersion, imageLocation, isScheduleNow, schedule: {Validator|Controller|Manager: {actionStartDate
"Sep 30 2026", actionStartTime "12:00:00 AM", timeZone}}}; cancel is PUT .../cancel {processId}.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cat_sdwan_mcp.client import _as_list

VERSIONS_PATH = "/dataservice/v1/controllers-upgrade/available-versions"
COMPLIANCE_PATH = "/dataservice/v1/controllers-upgrade/version-compliance-info"
UPGRADE_PATH = "/dataservice/v1/controllers-upgrade"
STATUS_PATH = "/dataservice/v1/controllers-upgrade/status"
CANCEL_PATH = "/dataservice/v1/controllers-upgrade/cancel"

ACTIONS = {"upgrade": "controllers_upgrade", "patch": "controllers_patch_upgrade"}
ORDER = ("Validator", "Controller", "Manager")
ROLE_TYPE = {"validator": "Validator", "controller": "Controller", "manager": "Manager"}
BACKUP_MAX_HOURS = 24


def versions(body: Any) -> list[dict[str, Any]]:
    rows = body.get("availableVersions") if isinstance(body, dict) else body
    out = []
    for v in _as_list(rows):
        if isinstance(v, dict) and v.get("version"):
            row = {
                "version": str(v["version"]),
                "location": v.get("location"),
                "tag": v.get("tag"),
                "for": v.get("compatibleControllerTypes") or v.get("imageType"),
            }
            out.append({k: x for k, x in row.items() if x not in (None, "", [])})
    return out


def compliance(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    keys = {
        "minimumControllerCompatibleVersion": "minimum_controller",
        "minimumValidatorCompatibleVersion": "minimum_validator",
        "minimumDeviceCompatibleVersion": "minimum_edge",
        "nonCompliantControllersCount": "non_compliant_controllers",
        "nonCompliantValidatorsCount": "non_compliant_validators",
        "nonCompliantDeviceCount": "non_compliant_edges",
        "nearNonCompliantDeviceCount": "near_non_compliant_edges",
    }
    out: dict[str, Any] = {label: body[k] for k, label in keys.items() if k in body}
    devices = []
    for t in _as_list(body.get("tenantDetails")):
        if isinstance(t, dict):
            devices += [d for d in _as_list(t.get("nonCompliantDevices")) if d]
    if devices:
        out["non_compliant_devices"] = devices[:50]
    return out


def compliance_problems(c: dict[str, Any], version: str) -> tuple[list[str], list[str]]:
    """Blockers and warnings from the compliance check. Only the edges block: the workflow does not upgrade
    them, so an edge older than the target supports drops out of the fabric. Controllers and validators
    counted as non-compliant are the ones this workflow upgrades (20.18.3 counts them against the target), so
    they are shown, never blocking."""
    blockers, warnings = [], []
    n = c.get("non_compliant_edges")
    if isinstance(n, int) and n > 0:
        blockers.append(
            f"{n} edge(s) run a release older than {version} supports (minimum {c.get('minimum_edge')}): "
            "upgrade them first (edge upgrades), or remove them"
        )
    near = c.get("near_non_compliant_edges")
    if isinstance(near, int) and near > 0:
        warnings.append(
            f"{near} edge(s) are near the minimum release {version} supports ({c.get('minimum_edge')}): plan "
            "their upgrade next"
        )
    return blockers, warnings


def schedule_body(start: datetime, timezone: str, types: tuple[str, ...] = ORDER) -> dict[str, Any]:
    """The Manager's schedule shape: the same start for every controller type (the workflow runs them in
    order: validators, controllers, then the Manager)."""
    one = {
        "actionStartDate": start.strftime("%b %d %Y"),
        "actionStartTime": start.strftime("%I:%M:%S %p"),
        "timeZone": timezone,
    }
    return {t: dict(one) for t in types}


def process_id(body: Any) -> str | None:
    for rec in (body, body.get("data") if isinstance(body, dict) else None):
        if isinstance(rec, dict):
            for k in ("processId", "id"):
                if isinstance(rec.get(k), str) and rec[k]:
                    return str(rec[k])
    return None
