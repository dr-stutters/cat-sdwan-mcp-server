"""W25 Manager operations: the Manager's own health (cluster nodes and services, resource use, statistics
processing, disaster recovery) and its database backups.

Recorded on 20.18.3.1 (one node, no DR, no backup yet): `clusterManagement/health/status` answers two records
for the one node ({"deviceIP": "localhost"} and the service flags), `health/details` reports status "error"
with reporters " null" while `health/summary` says normal with 0 devices down (the details row is shown, not
trusted for the verdict), `clusterManagement/list` nests the nodes as data[0].data[].configJson,
`vManageResourceUtilization` gives memory as "11.03 GB" strings, `server/info` answers the misspelt
"Achitecture", `/disasterrecovery/status` {"drStatus": {"drenabled": false, ...}} (`/drstatus` answers 400
DR0001 without DR), `/backup/list` {"backupList": []} and `/schedule/list` {"scheduleList": []}.
"""

from __future__ import annotations

import re
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.inventory import iso

HEALTH_STATUS_PATH = "/dataservice/clusterManagement/health/status"
HEALTH_DETAILS_PATH = "/dataservice/clusterManagement/health/details"
HEALTH_SUMMARY_PATH = "/dataservice/clusterManagement/health/summary"
CLUSTER_LIST_PATH = "/dataservice/clusterManagement/list"
RESOURCES_PATH = "/dataservice/management/vManageResourceUtilization"
SERVER_INFO_PATH = "/dataservice/server/info"
STATS_SETTINGS_PATH = "/dataservice/statistics/settings/status"
DR_STATUS_PATH = "/dataservice/disasterrecovery/status"
DR_HISTORY_PATH = "/dataservice/disasterrecovery/history"
BACKUP_LIST_PATH = "/dataservice/backup/list"
BACKUP_EXPORT_PATH = "/dataservice/backup/export"
BACKUP_INFO_PATH = "/dataservice/backup/backupinfo/{id}"
SCHEDULE_LIST_PATH = "/dataservice/schedule/list"

BACKUP_DONE = {"ALL_SUCCESS"}
BACKUP_FAILED = {
    "FAILURE",
    "CONFIG_DB_BACKUP_FAILED",
    "STATS_DB_EXPORT_FAILED",
    "CONFIG_DB_CONSISTENCY_CHECK_FAILED",
}
BACKUP_RUNNING = {
    "SCHEDULED",
    "IN_PROGRESS",
    "CONFIG_DB_BACKUP_SUCCESS",
    "STATS_DB_EXPORT_SUCCESS",
    "LEADER_SUCCESS",
}
TASK_NAME_RE = re.compile(r"^[a-zA-Z0-9 _\-\\/]+$")
_UNITS = {"KB": 1 / 1024 / 1024, "MB": 1 / 1024, "GB": 1.0, "TB": 1024.0}


def data_rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data", body) if isinstance(body, dict) else body
    return [r for r in _as_list(data) if isinstance(r, dict)]


def services(body: Any) -> list[dict[str, Any]]:
    """Per node: the services up and down (the records of one node are merged by deviceIP)."""
    nodes: dict[str, dict[str, Any]] = {}
    for r in data_rows(body):
        node = nodes.setdefault(str(r.get("deviceIP") or "?"), {})
        node.update({k: v for k, v in r.items() if k != "deviceIP"})
    out = []
    for ip, flags in nodes.items():
        up = sorted(k for k, v in flags.items() if v is True)
        down = sorted(k for k, v in flags.items() if v is False)
        out.append({"node": ip, "services_up": up, **({"services_down": down} if down else {})})
    return out


def cluster_nodes(body: Any) -> list[dict[str, Any]]:
    """GET /clusterManagement/list: data[].data[].configJson (the 20.18 shape) or flat node records."""
    out = []
    for group in data_rows(body):
        inner = group.get("data")
        for n in inner if isinstance(inner, list) else [group]:
            cfg = n.get("configJson", n) if isinstance(n, dict) else {}
            if not isinstance(cfg, dict):
                continue
            row = {
                "host": cfg.get("host-name"),
                "address": cfg.get("deviceIP"),
                "state": cfg.get("state"),
                "persona": cfg.get("persona"),
            }
            out.append({k: v for k, v in row.items() if v not in (None, "")})
    return out


def detail_rows(body: Any) -> list[dict[str, Any]]:
    out = []
    for r in data_rows(body):
        row = {
            "host": r.get("host-name"),
            "system_ip": r.get("system-ip"),
            "status": r.get("status"),
            "reporters": (str(r.get("reporters")).strip() or None)
            if r.get("reporters") is not None
            else None,
        }
        out.append({k: v for k, v in row.items() if v not in (None, "", "null")})
    return out


def summary_rows(body: Any) -> list[dict[str, Any]]:
    out = []
    for r in data_rows(body):
        row = {"name": r.get("name"), "status": r.get("status"), "count": r.get("count")}
        problems = [
            f"{s.get('name')}: {s.get('message')} {s.get('count')}"
            for s in _as_list(r.get("statusList"))
            if isinstance(s, dict) and s.get("count")
        ]
        if problems:
            row["problems"] = problems
        out.append({k: v for k, v in row.items() if v not in (None, "")})
    return out


def _gb(v: Any) -> float | None:
    m = re.fullmatch(r"\s*([\d.]+)\s*([KMGT]B)\s*", str(v or ""))
    return round(float(m.group(1)) * _UNITS[m.group(2)], 2) if m else None


def resources(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    out: dict[str, Any] = {}
    for label, prefix in (("jvm_memory", "jvmMemory"), ("third_party_memory", "thirPartionMemory")):
        alloc, used = _gb(body.get(f"{prefix}Allocated")), _gb(body.get(f"{prefix}Consumed"))
        if alloc and used is not None:
            out[label] = {
                "used": body.get(f"{prefix}Consumed"),
                "allocated": body.get(f"{prefix}Allocated"),
                "used_percent": round(100 * used / alloc, 1),
            }
    for k, label in (
        ("neo4jMemoryConsumed", "configuration_db_memory"),
        ("clickhouseMemoryConsumed", "olap_db_memory"),
    ):
        if body.get(k):
            out[label] = body[k]
    procs = [p for p in _as_list(body.get("process")) if p]
    if procs:
        out["processes"] = procs[:20]
    return out


def server_info(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    names = {"Achitecture": "architecture", "Architecture": "architecture", "Available processors": "cpus"}
    return {names.get(str(k), str(k)): v for k, v in body.items()}


def statistics_processing(body: Any) -> dict[str, Any]:
    rows = data_rows(body)
    off = sorted(str(r.get("displayName") or r.get("indexName")) for r in rows if r.get("status") != "enable")
    out: dict[str, Any] = {"indexes": len(rows), "enabled": len(rows) - len(off)}
    if off:
        out["not_enabled"] = off
    return out


def dr_state(status: Any) -> dict[str, Any]:
    dr = status.get("drStatus") if isinstance(status, dict) else None
    if not isinstance(dr, dict):
        return {"configured": "unknown"}
    out: dict[str, Any] = {"configured": bool(dr.get("drenabled"))}
    if dr.get("drenabled"):
        out.update({k: v for k, v in dr.items() if k != "drenabled"})
    return out


# --- backups -----------------------------------------------------------------------------------------


def backup_rows(body: Any) -> list[dict[str, Any]]:
    rows = body.get("backupList", body.get("data")) if isinstance(body, dict) else body
    out = [backup_row(r) for r in _as_list(rows) if isinstance(r, dict)]
    out.sort(key=lambda r: str(r.get("created") or ""), reverse=True)
    return out


def backup_row(r: dict[str, Any]) -> dict[str, Any]:
    dest_raw = r.get("destination")
    dest: dict[str, Any] = dest_raw if isinstance(dest_raw, dict) else {}
    row = {
        "id": r.get("localBackupInfoId"),
        "task": r.get("taskName"),
        "type": r.get("backupType"),
        "state": r.get("backupState"),
        "created": iso(r.get("createTime")),
        "file": r.get("downloadURL") or dest.get("filePath") or dest.get("fileName"),
        "source": r.get("srcIpAddress"),
        "task_id": r.get("taskId"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def backup_state(row: dict[str, Any]) -> str:
    return str(row.get("state") or "").upper()


def schedule_rows(body: Any) -> list[dict[str, Any]]:
    rows = body.get("scheduleList", body.get("data")) if isinstance(body, dict) else body
    return [r for r in _as_list(rows) if isinstance(r, dict)]


def export_id(body: Any) -> str | None:
    """The new backup's id from the POST /backup/export answer (the documented response is a stub, so the
    usual keys are searched, also one level down in `data`)."""
    for rec in (body, body.get("data") if isinstance(body, dict) else None):
        if isinstance(rec, dict):
            for k in ("localBackupInfoId", "backupInfoId", "id", "taskId"):
                if isinstance(rec.get(k), str) and rec[k]:
                    return str(rec[k])
    return None
