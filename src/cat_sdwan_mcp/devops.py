"""Device operations (W12): reboot, the software repository, upgrades and the Manager's action list.

Pure helpers; the tools are in tools/devops.py. Sources (20.18.3.1):
- GET /dataservice/device/action/software: the software repository {versionId, versionName,
  controllerVersionName, versionType, versionURL, availableFiles, updatedOn} (recorded: EMPTY in the lab).
- GET /dataservice/device/action/software/images: the image files {versionId, availableFiles, versionName,
  versionType, imageType, fileSizeStr, checksumValidity, controllerVersionName, arch, ...} (recorded: EMPTY).
- GET /dataservice/device/software?deviceId=: what one device has installed {version, active, default}
  (recorded for hub1 and br1).
- GET /dataservice/device/reboothistory?deviceId=: a device's reloads (recorded for br1 and br2).
- GET /dataservice/device/action/list: the action types the Manager knows, [{name, isCancelEnabled,
  isParallelExecutionEnabled}] (recorded: 202 rows).
- GET /dataservice/device/action/status/tasks: {runningTasks: [...]} (recorded: empty); a task's rows come
  from GET /dataservice/device/action/status/{processId} (W8).
- POST /dataservice/device/action/reboot {action: "reboot", deviceType, devices: [{deviceIP, deviceId}]}
  -> {id: "reboot-<ts>"} (spec: request example external, response schema TaskId).
- POST /dataservice/device/action/install (spec schema ProcessInstallReq) {action: "install", deviceType,
  devices: [{deviceIP, deviceId}], input: {data: [{family, version, versionId}], versionType, vEdgeVPN,
  vSmartVPN, reboot, sync}} -> {id}.
- POST /dataservice/device/action/changepartition {action: "changepartition", deviceType, devices: [{version,
  deviceIP, deviceId}]} -> {id} (Cisco's documented shape; the spec's example is external).
"""

from __future__ import annotations

import re
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.inventory import iso

SOFTWARE_REPO_PATH = "/dataservice/device/action/software"
SOFTWARE_IMAGES_PATH = "/dataservice/device/action/software/images"
REBOOT_ACTION_PATH = "/dataservice/device/action/reboot"
INSTALL_PATH = "/dataservice/device/action/install"
CHANGE_PARTITION_PATH = "/dataservice/device/action/changepartition"
ACTION_LIST_PATH = "/dataservice/device/action/list"

MIN_FREE_MB = 1024  # below this an install is refused (a C8000V image is about 0.8-1 GB)
WARN_FREE_MB = 2048


def rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data") if isinstance(body, dict) and "data" in body else body
    return [r for r in _as_list(data) if isinstance(r, dict)]


# --- versions ------------------------------------------------------------------------------------


def numbers(version: Any) -> tuple[int, ...]:
    """'17.18.02.0.4112' -> (17, 18, 2, 0, 4112); '20.18.3.1' -> (20, 18, 3, 1); text parts are dropped."""
    out = []
    for part in re.split(r"[.\-_ ]", str(version or "")):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


def train(version: Any) -> tuple[int, int] | None:
    """The release train a version belongs to, comparable across edges and the Manager: IOS XE 17.x goes with
    Manager 20.x (17.18 with 20.18), from 26.x both carry the same number."""
    n = numbers(version)
    if len(n) < 2:
        return None
    major = 20 if n[0] == 17 else n[0]
    return major, n[1]


def train_text(t: tuple[int, int] | None) -> str:
    if t is None:
        return "?"
    return f"{t[0]}.{t[1]}" + (f" (IOS XE 17.{t[1]})" if t[0] == 20 else "")


def newer_than(version: Any, ceiling: Any) -> bool:
    a, b = train(version), train(ceiling)
    return a is not None and b is not None and a > b


def same_version(a: Any, b: Any) -> bool:
    """'17.18.02.0.4112' and '17.18.02' are the same build line; compared on the numbers both carry."""
    x, y = numbers(a), numbers(b)
    if not x or not y:
        return str(a).strip().lower() == str(b).strip().lower()
    n = min(len(x), len(y))
    return x[:n] == y[:n] and n >= 3


def disk_mb(text: Any) -> float | None:
    """'3341M' -> 3341.0, '5.2G' -> 5324.8, '812K' -> 0.79; None when unreadable."""
    m = re.fullmatch(r"\s*([\d.]+)\s*([KMGT]?)i?B?\s*", str(text or ""), re.IGNORECASE)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2).upper()
    return value * {"": 1 / 1024 / 1024, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}[unit]


# --- repository ----------------------------------------------------------------------------------


def repo_row(r: dict[str, Any]) -> dict[str, Any]:
    row = {
        "version": r.get("versionName"),
        "type": r.get("versionTypeName") or r.get("versionType"),
        "needs_controllers": r.get("controllerVersionName"),
        "files": r.get("availableFiles"),
        "family": r.get("platformFamily") or r.get("family"),
        "size": r.get("fileSizeStr"),
        "checksum": r.get("checksumValidity"),
        "image_type": r.get("imageType"),
        "location": "remote server" if r.get("versionURL") else None,
        "updated": iso(r.get("updatedOn")),
        "id": r.get("versionId"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def find_version(repo: list[dict[str, Any]], version: str) -> tuple[dict[str, Any] | None, list[str]]:
    """The repository row for `version` (exact name, or the one build a shorter version names), and the
    repository's versions for a 'not found' message."""
    names = [str(r.get("versionName")) for r in repo if r.get("versionName")]
    exact = [r for r in repo if str(r.get("versionName", "")).lower() == version.strip().lower()]
    if exact:
        return exact[0], names
    close = [r for r in repo if same_version(r.get("versionName"), version)]
    return (close[0] if len(close) == 1 else None), names


def installed(rows_: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for s in rows_:
        if not s.get("version"):
            continue
        out.append(
            {
                "version": s.get("version"),
                "active": str(s.get("active")).lower() == "true",
                "default": str(s.get("default")).lower() == "true",
            }
        )
    return out


# --- request bodies ------------------------------------------------------------------------------


def device_type(row: dict[str, Any]) -> str:
    """The Manager's deviceType for an action: vedge for edges, controller for controllers and validators."""
    return "vedge" if row.get("role") == "edge" else "controller"


def targets(rows_: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{"deviceIP": str(r["system_ip"]), "deviceId": str(r["chassis"])} for r in rows_]


def reboot_body(rows_: list[dict[str, Any]]) -> dict[str, Any]:
    return {"action": "reboot", "deviceType": device_type(rows_[0]), "devices": targets(rows_)}


def install_body(
    rows_: list[dict[str, Any]], repo: dict[str, Any], family: str, activate: bool
) -> dict[str, Any]:
    return {
        "action": "install",
        "input": {
            "vEdgeVPN": 0,
            "vSmartVPN": 0,
            "data": [
                {
                    "family": family,
                    "version": repo.get("versionName"),
                    **({"versionId": repo["versionId"]} if repo.get("versionId") else {}),
                }
            ],
            "versionType": repo.get("versionType") or "vmanage",
            "reboot": activate,
            "sync": True,
        },
        "devices": targets(rows_),
        "deviceType": "vedge",
    }


def change_partition_body(rows_: list[dict[str, Any]], version: str) -> dict[str, Any]:
    return {
        "action": "changepartition",
        "devices": [{"version": version, **t} for t in targets(rows_)],
        "deviceType": "vedge",
    }


def family_of(row: dict[str, Any]) -> str | None:
    """A platform family guessed from the device model ('vedge-C8000V' -> 'c8000v') when the repository row
    carries none (unverified: the lab repository is empty)."""
    model = str(row.get("model") or "").lower().removeprefix("vedge-")
    return model or None


# --- dual-edge sites -----------------------------------------------------------------------------


def dual_edge_blockers(picked: list[dict[str, Any]], all_rows: list[dict[str, Any]], what: str) -> list[str]:
    """Two edges of the same site in one run take the whole site down: refused."""
    by_site: dict[str, list[str]] = {}
    for r in picked:
        if r.get("role") == "edge" and r.get("site_id") not in (None, ""):
            by_site.setdefault(str(r["site_id"]), []).append(str(r.get("host") or r.get("chassis")))
    out = []
    for site, hosts in sorted(by_site.items()):
        if len(hosts) < 2:
            continue
        total = sum(1 for r in all_rows if r.get("role") == "edge" and str(r.get("site_id")) == site)
        whole = " (every edge there)" if total == len(hosts) else ""
        out.append(
            f"{', '.join(hosts)} are edges of the same site {site}{whole}: {what} one edge per site per run, "
            "check it is back, then the other"
        )
    return out


# --- the action list -----------------------------------------------------------------------------


def task_row(t: dict[str, Any]) -> dict[str, Any]:
    row = {
        "process_id": t.get("processId") or t.get("id"),
        "action": t.get("name") or t.get("action"),
        "status": t.get("status"),
        "started": iso(t.get("startTime") or t.get("start_time")),
        "user": t.get("userSessionUserName") or t.get("user"),
        "from": t.get("userSessionIP"),
        "tenant": t.get("tenantName"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def started_ms(t: dict[str, Any]) -> int:
    v = t.get("startTime") or t.get("start_time")
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return 0


def action_type_row(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": a.get("name"),
        "cancellable": a.get("isCancelEnabled") is True,
        "parallel": a.get("isParallelExecutionEnabled") is True,
    }
