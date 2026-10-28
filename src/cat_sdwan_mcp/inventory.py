"""Inventory (W2): the Manager's device list joined with its certificate inventory, device resolution, the
real-time device reads and the device health rows.

Sources (recorded on 20.18.3.1):
- GET /dataservice/device: every device that has joined, with live state (`reachability`, `status`,
  `uptime-date`, `board-serial`; `uuid` is the chassis number).
- GET /dataservice/system/device/vedges: every WAN edge slot from the serial file, joined or not
  (`chasisNumber` [sic], `serialNumber`, `validity` valid|invalid|staging, `vedgeCertificateState`,
  `configOperationMode`, `managed-by` "Config-Group <name>" | "Unmanaged", `template` when one is attached).
- GET /dataservice/system/device/controllers: the controllers with their certificates (`expirationDate`,
  `expirationDateLong`, `certInstallStatus`; `serialNumber` is the certificate serial on a controller).
- Real-time reads GET /dataservice/device/<what>?deviceId=<system-ip>: the Manager asks the device over its
  control connection, so a down device answers with an error (reported per section, never fatal).
- GET /dataservice/health/devices: {header, total_devices, devices: [...]}, `health` green|yellow|red with
  the Manager's `reason`. Where it is missing (404), health is computed from /dataservice/device and
  /dataservice/device/counters (control connections vs expected, BFD, OMP).
"""

from __future__ import annotations

import asyncio
import difflib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest, NotFound, UpstreamError
from cat_sdwan_mcp.client import ROLE, SdwanApp, _as_list

STATUS_PATH = "/dataservice/device/system/status"
INTERFACE_PATH = "/dataservice/device/interface"
SOFTWARE_PATH = "/dataservice/device/software"
REBOOT_PATH = "/dataservice/device/reboothistory"
HEALTH_PATH = "/dataservice/health/devices"
COUNTERS_PATH = "/dataservice/device/counters"

ROLE_ORDER = {"manager": 0, "controller": 1, "validator": 2, "edge": 3}
HEALTH = {"green": "good", "yellow": "fair", "red": "poor"}
HEALTH_ORDER = {"poor": 0, "fair": 1, "good": 2}
LOAD_HINT = 70.0  # CPU / memory % named as a likely reason on a fair or poor device (the Manager gives none)
CERT_WARN_DAYS = 30


def role_of(rec: dict[str, Any]) -> str | None:
    p = rec.get("personality") or rec.get("device-type") or rec.get("deviceType")
    return ROLE.get(str(p), str(p)) if p else None


def iso(ms: Any) -> str | None:
    """An epoch in milliseconds (the Manager's `*-date` fields) as UTC ISO 8601."""
    if isinstance(ms, str) and ms.isdigit():
        ms = int(ms)
    if not isinstance(ms, int | float) or isinstance(ms, bool) or ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def config_mode(rec: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """(mode, name): "configuration group" + the group, "template" + the device template, or "cli".

    20.18 reports a configuration-group device as configOperationMode "cli" with managed-by
    "Config-Group <name>" ("Config-Group <name>, Policy-Group <policy group>" once a policy group is
    associated too, recorded 2026-10-28); a template-attached device is configOperationMode "vmanage"
    (`template` names it; not recorded yet)."""
    if not rec:
        return None, None
    managed = _managed_parts(rec)[0]
    if managed.lower().startswith("config-group"):
        name = managed.split(" ", 1)[1].strip() if " " in managed else None
        return "configuration group", name or None
    mode = str(rec.get("configOperationMode") or "").strip().lower()
    if mode == "vmanage":
        name = rec.get("template")
        if not name and managed and managed.lower() != "unmanaged":
            name = managed.removeprefix("Template").strip() or managed
        return "template", str(name) if name else None
    if mode == "cli":
        return "cli", None
    return mode or None, None


def _managed_parts(rec: dict[str, Any]) -> tuple[str, str | None]:
    """(the managed-by text without its policy group, the policy group's name or None)."""
    managed = str(rec.get("managed-by") or "").strip()
    head, sep, tail = managed.partition(", Policy-Group")
    if not sep:
        head, sep, tail = managed.partition(",Policy-Group")
    return head.strip(), (tail.strip() or None) if sep else None


def policy_group_of(rec: dict[str, Any] | None) -> str | None:
    """The policy group the Manager's `managed-by` names for a device (None when there is none)."""
    return _managed_parts(rec)[1] if rec else None


def _key(v: Any) -> str | None:
    s = str(v).strip().lower() if v not in (None, "") else ""
    return s if s and s not in ("na", "none") else None


@dataclass
class Inventory:
    """Joined rows plus what could not be read (the certificate inventories are optional)."""

    rows: list[dict[str, Any]]
    unjoined: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def device_row(d: dict[str, Any], cert: dict[str, Any] | None) -> dict[str, Any]:
    """One /dataservice/device row, joined with its vedges/controllers record when there is one."""
    mode, name = config_mode(cert)
    row: dict[str, Any] = {
        "host": d.get("host-name"),
        "role": role_of(d),
        "system_ip": d.get("system-ip"),
        "site_id": d.get("site-id"),
        "site_name": d.get("site-name"),
        "model": d.get("device-model"),
        "version": d.get("version"),
        "reachability": d.get("reachability"),
        "status": d.get("status"),
        "state": d.get("state_description") or d.get("state"),
        "up_since": iso(d.get("uptime-date")),
        "control_connections": d.get("controlConnections"),
        "board_serial": d.get("board-serial"),
        "chassis": d.get("uuid") or (cert or {}).get("chasisNumber"),
        "certificate": (cert or {}).get("validity") or d.get("validity"),
        "certificate_state": (cert or {}).get("vedgeCertificateState")
        or (cert or {}).get("certInstallStatus"),
        "config_mode": mode,
        "config": name,
        "policy_group": policy_group_of(cert),
        "config_status": (cert or {}).get("configStatusMessage"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def unjoined_row(v: dict[str, Any]) -> dict[str, Any]:
    """A vedges slot missing from /dataservice/device (never joined, or gone): chassis, serial and
    certificate. A software edge's serialNumber before it joins is its one-time token (a secret): left out."""
    mode, name = config_mode(v)
    state = str(v.get("vedgeCertificateState") or "").lower()
    token = state in ("tokengenerated", "bootstrapconfiggenerated") or v.get("hardwareVedge") is False
    row: dict[str, Any] = {
        "host": v.get("host-name"),
        "role": role_of(v) or "edge",
        "system_ip": v.get("system-ip"),
        "site_id": v.get("site-id"),
        "model": v.get("deviceModel"),
        "reachability": "not joined",
        "chassis": v.get("chasisNumber") or v.get("uuid"),
        "board_serial": None if token else v.get("serialNumber"),
        "token": "********" if token and v.get("serialNumber") else None,
        "certificate": v.get("validity"),
        "certificate_state": v.get("vedgeCertificateState"),
        "config_mode": mode,
        "config": name,
    }
    return {k: x for k, x in row.items() if x not in (None, "", [])}


def join_inventory(
    devices: list[dict[str, Any]],
    vedges: list[dict[str, Any]] | None,
    controllers: list[dict[str, Any]] | None,
) -> Inventory:
    by_chassis: dict[str, dict[str, Any]] = {}
    by_ip: dict[str, dict[str, Any]] = {}
    for rec in [*(vedges or []), *(controllers or [])]:
        for k in (rec.get("chasisNumber"), rec.get("uuid")):
            if key := _key(k):
                by_chassis.setdefault(key, rec)
        if key := _key(rec.get("system-ip")):
            by_ip.setdefault(key, rec)
    used: set[int] = set()
    rows = []
    for d in devices:
        cert = by_chassis.get(_key(d.get("uuid")) or "") or by_ip.get(_key(d.get("system-ip")) or "")
        if cert is not None:
            used.add(id(cert))
        rows.append(device_row(d, cert))
    unjoined = [unjoined_row(v) for v in vedges or [] if id(v) not in used]
    return Inventory(rows, unjoined)


async def load_inventory(app: SdwanApp) -> Inventory:
    """/dataservice/device joined with the vedges and controllers inventories (read concurrently; either of
    those failing leaves the certificate and configuration columns empty and says so)."""
    got_all = await asyncio.gather(app.devices(), app.vedges(), app.controllers(), return_exceptions=True)
    devices, vedges, controllers = got_all
    if isinstance(devices, BaseException):
        raise devices
    warnings: list[str] = []
    extra: list[list[dict[str, Any]] | None] = []
    for what, got in (("WAN edge", vedges), ("controller", controllers)):
        if isinstance(got, UpstreamError):
            warnings.append(f"the {what} certificate inventory could not be read: {str(got)[:200]}")
            extra.append(None)
        elif isinstance(got, BaseException):
            raise got
        else:
            extra.append(got)
    inv = join_inventory(devices, extra[0], extra[1])
    inv.warnings = warnings
    return inv


def sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            ROLE_ORDER.get(str(r.get("role")), 9),
            str(r.get("host") or ""),
            str(r.get("chassis")),
        ),
    )


def matches_site(row: dict[str, Any], site: str | None) -> bool:
    if not site:
        return True
    want = site.strip().lower()
    return want in (str(row.get("site_id", "")).lower(), str(row.get("site_name", "")).lower())


# --- resolution ----------------------------------------------------------------------------------


def resolve(inv: Inventory, ref: str) -> dict[str, Any]:
    """A device by host name, system IP, chassis number or serial (exact, case-insensitive), then a unique
    host-name prefix; otherwise NotFound with the closest names."""
    want = ref.strip().lower()
    if not want:
        raise InvalidRequest("Give a device host name, system IP, chassis number or serial number.")
    pool = [*inv.rows, *inv.unjoined]
    keys = ("host", "system_ip", "chassis", "board_serial")
    found = [r for r in pool if any(_key(r.get(k)) == want for k in keys)]
    if not found:
        found = [r for r in inv.rows if str(r.get("host", "")).lower().startswith(want)]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        names = ", ".join(
            f"{r.get('host') or r.get('chassis')} ({r.get('system_ip', '-')})" for r in found[:10]
        )
        raise InvalidRequest(f"{ref!r} matches {len(found)} devices: {names}. Use the system IP or chassis.")
    known = [str(r[k]) for r in inv.rows for k in ("host", "system_ip") if r.get(k)]
    close = difflib.get_close_matches(ref.strip(), known, n=5, cutoff=0.5)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    raise NotFound(
        f"No device matches {ref!r} (host name, system IP, chassis or serial).{hint} "
        "catsdwan_list_devices lists them."
    )


# --- real-time reads -----------------------------------------------------------------------------


def _strip(v: Any, prefix: str) -> Any:
    return v.removeprefix(prefix) if isinstance(v, str) else v


def _prefix_len(mask: Any) -> int | None:
    try:
        return sum(bin(int(o)).count("1") for o in str(mask).split("."))
    except ValueError:
        return None


def system_status(rows: list[dict[str, Any]]) -> dict[str, Any]:
    s = rows[0] if rows else {}
    idle = _num(s.get("cpu_idle"))
    used, total = _num(s.get("mem_used")), _num(s.get("mem_total"))
    loads = [s.get(k) for k in ("min1_avg", "min5_avg", "min15_avg")]
    out: dict[str, Any] = {
        "cpu_used_percent": round(100 - idle, 1) if idle is not None else None,
        "load_1_5_15": " / ".join(str(x) for x in loads) if all(loads) else None,
        "memory_used_percent": round(100 * used / total, 1) if used is not None and total else None,
        "memory_total_mb": round(total / 1024) if total else None,
        "disk_used_percent": _num(s.get("disk_use")),
        "disk_free": s.get("disk_avail"),
        "uptime": s.get("uptime"),
        "state": " ".join(x for x in (s.get("state"), s.get("state_description")) if x) or None,
        "reboot_reason": s.get("reboot_reason"),
        "chassis_serial": s.get("chassis-serial-number"),
        "model": s.get("model"),
        "version": s.get("version"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def interfaces(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i in rows:
        ip, plen = i.get("ip-address"), _prefix_len(i.get("ipv4-subnet-mask"))
        row = {
            "name": i.get("ifname"),
            "vpn": i.get("vpn-id"),
            "admin": _strip(i.get("if-admin-status"), "if-state-"),
            "oper": {"ready": "up"}.get(s, s)
            if isinstance(s := _strip(i.get("if-oper-status"), "if-oper-state-"), str)
            else s,
            "ip": f"{ip}/{plen}" if ip and ip != "0.0.0.0" and plen is not None else None,
            "description": i.get("description"),
            "mac": i.get("hwaddr"),
            "speed_mbps": i.get("speed-mbps"),
        }
        out.append({k: v for k, v in row.items() if v not in (None, "")})
    return sorted(
        out, key=lambda r: (int(r["vpn"]) if str(r.get("vpn", "")).isdigit() else 0, r.get("name", ""))
    )


def software(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "version": s.get("version"),
            "active": str(s.get("active")).lower() == "true",
            "default": str(s.get("default")).lower() == "true",
        }
        for s in rows
        if s.get("version")
    ]


def reboots(rows: list[dict[str, Any]], keep: int = 5) -> list[dict[str, Any]]:
    rows = sorted(rows, key=lambda r: _num(r.get("reload-time-date")) or 0, reverse=True)
    out = []
    for r in rows[:keep]:
        row = {
            "time": r.get("reload-time") or iso(r.get("reload-time-date")),
            "reason": r.get("reload-desc"),
            "category": _strip(r.get("reload-category"), "rc-"),
            "severity": r.get("reload-severity"),
        }
        out.append({k: v for k, v in row.items() if v not in (None, "")})
    return out


Shaper = Callable[[list[dict[str, Any]]], Any]
REALTIME: tuple[tuple[str, str, Shaper], ...] = (
    ("system", STATUS_PATH, system_status),
    ("interfaces", INTERFACE_PATH, interfaces),
    ("software", SOFTWARE_PATH, software),
    ("reboots", REBOOT_PATH, reboots),
)


async def realtime(app: SdwanApp, system_ip: str) -> dict[str, Any]:
    """The four real-time reads, concurrently; each failure becomes {"error": ...} for its section."""

    async def one(path: str) -> list[dict[str, Any]]:
        data = await app.get_data(path, {"deviceId": system_ip})
        return [r for r in _as_list(data) if isinstance(r, dict)]

    got = await asyncio.gather(*(one(path) for _, path, _ in REALTIME), return_exceptions=True)
    out: dict[str, Any] = {}
    for (name, path, shape), res in zip(REALTIME, got, strict=True):
        if isinstance(res, UpstreamError):
            out[name] = {"error": f"GET {path} failed: {str(res)[:300]}"}
        elif isinstance(res, BaseException):
            raise res
        else:
            out[name] = shape(res)
    return out


# --- health --------------------------------------------------------------------------------------


def _ratio(up: Any, total: Any) -> str | None:
    return f"{up}/{total}" if isinstance(up, int) and isinstance(total, int) and total else None


def _short(up: Any, total: Any) -> bool:
    return isinstance(up, int) and isinstance(total, int) and up < total


def health_row(d: dict[str, Any]) -> dict[str, Any]:
    """One /health/devices record: the Manager's verdict, its reason, and what is visibly short."""
    health = HEALTH.get(str(d.get("health")).lower(), d.get("health"))
    reasons: list[str] = []
    if reason := str(d.get("reason") or "").strip().rstrip("."):
        reasons.append(reason)
    if str(d.get("reachability", "")).lower() not in ("", "reachable"):
        reasons.append(f"reachability {d.get('reachability')}")
    for label, up, total in (
        ("control connections up", "control_connections_up", "control_connections"),
        ("controller (vSmart) connections", "vsmart_control_connections", "expected_vsmart_connections"),
        ("BFD sessions up", "bfd_sessions_up", "bfd_sessions"),
        ("TLOCs up", "up_tloc_num", "total_tloc_num"),
        ("OMP peers up", "omp_peers_up", "omp_peers"),
    ):
        if _short(d.get(up), d.get(total)):
            reasons.append(f"{label} {d.get(up)}/{d.get(total)}")
    if health in ("fair", "poor"):
        for label, key in (("CPU load", "cpu_load"), ("memory", "memory_utilization")):
            v = _num(d.get(key))
            if v is not None and v >= LOAD_HINT:
                reasons.append(f"{label} {v:g}%")
    row = {
        "host": d.get("name") or d.get("host_name"),
        "role": role_of(d),
        "system_ip": d.get("system_ip") or d.get("local_system_ip"),
        "site_id": d.get("site_id"),
        "site_name": d.get("site_name"),
        "health": health,
        "reason": "; ".join(reasons) or None,
        "reachability": d.get("reachability"),
        "cpu_percent": d.get("cpu_load"),
        "memory_percent": d.get("memory_utilization"),
        "control": _ratio(d.get("control_connections_up"), d.get("control_connections")),
        "bfd": _ratio(d.get("bfd_sessions_up"), d.get("bfd_sessions")),
        "tlocs": _ratio(d.get("up_tloc_num"), d.get("total_tloc_num")),
        "version": d.get("software_version"),
        "config_group": d.get("configGroupName"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def computed_health_row(d: dict[str, Any], counters: dict[str, Any] | None) -> dict[str, Any]:
    """Health from /dataservice/device + /dataservice/device/counters (no /health/devices on this Manager):
    poor when unreachable or short of control connections, fair when BFD sessions or OMP peers are down."""
    c = counters or {}
    reasons: list[str] = []
    health = "good"
    if str(d.get("reachability", "")).lower() != "reachable":
        health = "poor"
        reasons.append(f"reachability {d.get('reachability') or 'unknown'}")
    up, want = c.get("number-vsmart-control-connections"), c.get("expectedControlConnections")
    if _short(up, want):
        health = "poor"
        reasons.append(f"controller connections {up}/{want}")
    for label, key in (("BFD sessions down", "bfdSessionsDown"), ("OMP peers down", "ompPeersDown")):
        if isinstance(c.get(key), int) and c[key] > 0:
            health = "fair" if health == "good" else health
            reasons.append(f"{label}: {c[key]}")
    row = {
        "host": d.get("host-name"),
        "role": role_of(d),
        "system_ip": d.get("system-ip"),
        "site_id": d.get("site-id"),
        "site_name": d.get("site-name"),
        "health": health,
        "reason": "; ".join(reasons) or None,
        "reachability": d.get("reachability"),
        "control": _ratio(up, want),
        "version": d.get("version"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def sort_health(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            HEALTH_ORDER.get(str(r.get("health")), 3),
            ROLE_ORDER.get(str(r.get("role")), 9),
            str(r.get("host") or ""),
        ),
    )


# --- controllers ---------------------------------------------------------------------------------


def controller_row(c: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    expires_ms = _num(c.get("expirationDateLong"))
    now = time.time() if now is None else now
    days = int((expires_ms / 1000 - now) // 86400) if expires_ms else None
    row = {
        "host": c.get("host-name"),
        "role": role_of(c),
        "system_ip": c.get("system-ip"),
        "site_id": c.get("site-id"),
        "version": c.get("version"),
        "reachability": c.get("reachability"),
        "certificate": c.get("validity"),
        "certificate_status": c.get("certInstallStatus"),
        "certificate_serial": c.get("serialNumber"),
        "certificate_expires": c.get("expirationDate") if c.get("expirationDate") != "NA" else None,
        "days_left": days,
        "expiration_status": c.get("expirationStatus"),
        "state": c.get("state"),
        "device_ip": c.get("deviceIP"),
    }
    return {k: v for k, v in row.items() if v not in (None, "", "NA")}
