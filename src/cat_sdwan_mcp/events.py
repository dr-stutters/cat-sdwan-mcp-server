"""Alarms, events and the audit log (W5), and the merged timeline of recent activity.

Sources (recorded on 20.18.3.1; the query body is the statistics one, see client.last_hours):
- POST /dataservice/alarms: `entry_time`, `type`/`rulename`, `rule_name_display`, `severity` (Critical, Major,
  Medium, Minor), `message`, `active`, `cleared_time` (0 when not cleared), `acknowledged`, `system_ip`,
  `host_name`, `site_id`, `values` [{system-ip, host-name, color, site-id, ...}]. A '..._up' alarm is the
  inactive event that clears its '..._down' partner (cleared_time stays 0 on it).
- POST /dataservice/event: `entry_time`, `host_name`, `system_ip`, `eventname`, `component`, `severity_level`
  (critical, major, minor), `details` ("k=v; k=v"). The Manager ignored `size` (717 rows for 50).
- POST /dataservice/auditlog (GET answers 400 'must not be null'): `entry_time`, `loguser`, `logusersrcip`,
  `logmodule`, `logfeature`, `logmessage`, `logdeviceid` (a system IP or empty), `auditdetails` (a JSON array
  of strings, some of them JSON config bodies).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.control import clean, explain
from cat_sdwan_mcp.inventory import iso

ALARMS_PATH = "/dataservice/alarms"
EVENTS_PATH = "/dataservice/event"
AUDIT_PATH = "/dataservice/auditlog"
REJECT_EVENTS = ("vbond-reject-vedge-connection", "control-connection-auth-fail")
SEVERITY_RANK = {"critical": 0, "major": 1, "medium": 2, "minor": 3}
# Session noise in the audit log: logins, logouts, JWT creation. `changes_only` drops these.
SESSION_RE = re.compile(
    r"authentication (succeeded|failed)|login and create jwt|invalidated session|logged (in|out)|logout",
    re.IGNORECASE,
)
DETAILS_CHARS = 1000


def _ms(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _sev(v: Any) -> str:
    return str(v or "").strip().lower()


def at_least(severity: str | None, wanted: str | None) -> bool:
    """True when `severity` is `wanted` or worse (critical > major > medium > minor)."""
    if not wanted:
        return True
    return SEVERITY_RANK.get(_sev(severity), 9) <= SEVERITY_RANK.get(_sev(wanted), 9)


# --- alarms --------------------------------------------------------------------------------------


def alarm_devices(a: dict[str, Any]) -> list[str]:
    """'host (system-ip)' for every device the alarm names (values first, then devices)."""
    out: list[str] = []
    reporter = {"host-name": a.get("host_name"), "system-ip": a.get("system_ip")}
    for v in [*(a.get("values") or []), *(a.get("devices") or []), reporter]:
        if not isinstance(v, dict):
            continue
        host, ip = v.get("host-name"), v.get("system-ip")
        name = f"{host} ({ip})" if host and ip else str(host or ip or "")
        if name and not any(name == o or (ip and str(ip) in o) for o in out):
            out.append(name)
    return out


def alarm_ips(a: dict[str, Any]) -> set[str]:
    ips = {str(a["system_ip"])} if a.get("system_ip") else set()
    for v in [*(a.get("values") or []), *(a.get("devices") or [])]:
        if isinstance(v, dict) and v.get("system-ip"):
            ips.add(str(v["system-ip"]))
    return ips


def alarm_sites(a: dict[str, Any]) -> set[str]:
    sites = {str(a["site_id"])} if a.get("site_id") not in (None, "") else set()
    for v in a.get("values") or []:
        if isinstance(v, dict) and v.get("site-id") not in (None, ""):
            sites.add(str(v["site-id"]))
    return sites


def alarm_state(a: dict[str, Any]) -> str:
    """active, cleared, or info (an inactive alarm never raised: the '..._up' that clears another)."""
    if a.get("active") is True or str(a.get("active")).lower() == "true":
        return "active"
    return "cleared" if _ms(a.get("cleared_time")) > 0 else "info"


def alarm_row(a: dict[str, Any]) -> dict[str, Any]:
    state = alarm_state(a)
    return clean(
        {
            "time": iso(a.get("entry_time")),
            "severity": a.get("severity"),
            "alarm": a.get("rule_name_display") or a.get("type"),
            "type": a.get("type"),
            "state": state,
            "cleared": iso(a.get("cleared_time")) if state == "cleared" else None,
            "message": a.get("message"),
            "devices": alarm_devices(a) or None,
            "site_id": a.get("site_id") or next(iter(sorted(alarm_sites(a))), None),
            "component": a.get("component"),
            "acknowledged": True if a.get("acknowledged") is True else None,
            "id": a.get("uuid"),
        }
    )


def by_type(alarms: list[dict[str, Any]]) -> dict[str, str]:
    """'Control_Node_Down': '1 active, 2 cleared' per alarm type, most frequent first."""
    counts: dict[str, Counter[str]] = {}
    for a in alarms:
        name = str(a.get("rule_name_display") or a.get("type"))
        counts.setdefault(name, Counter())[alarm_state(a)] += 1
    ordered = sorted(counts.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    return {
        name: ", ".join(f"{n} {s}" for s in ("active", "cleared", "info") if (n := c[s]))
        for name, c in ordered
    }


def sort_alarms(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Newest first (raw alarms; shape afterwards)."""
    return sorted(rows, key=lambda a: _ms(a.get("entry_time")), reverse=True)


# --- events --------------------------------------------------------------------------------------


def event_row(e: dict[str, Any]) -> dict[str, Any]:
    return clean(
        {
            "time": iso(e.get("entry_time")),
            "host": e.get("host_name"),
            "system_ip": e.get("system_ip"),
            "event": e.get("eventname"),
            "component": e.get("component"),
            "severity": e.get("severity_level"),
            "details": e.get("details"),
        }
    )


def parse_details(details: Any) -> dict[str, str]:
    """An event's `details` ("host-name=validator; uuid=...; reason=ERR_BID_NOT_VERIFIED") as a dict."""
    out: dict[str, str] = {}
    for part in str(details or "").split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def rejection_row(e: dict[str, Any]) -> dict[str, Any]:
    """A join rejection (vbond-reject-vedge-connection, control-connection-auth-fail) with the reason
    explained: the validator names the edge by chassis (`uuid`), since it has no system IP yet."""
    d = parse_details(e.get("details"))
    peer = d.get("peer-system-ip")
    return clean(
        {
            "time": iso(e.get("entry_time")),
            "seen_by": e.get("host_name"),
            "event": e.get("eventname"),
            "chassis": d.get("uuid"),
            "peer_type": d.get("peer-type"),
            "peer_system_ip": peer if peer not in ("::", "0.0.0.0") else None,
            "colour": d.get("local-color") if e.get("eventname") != "vbond-reject-vedge-connection" else None,
            "reason": explain(d.get("reason")),
        }
    )


# --- audit log -----------------------------------------------------------------------------------


def audit_details(raw: Any) -> str | None:
    """`auditdetails` (a JSON array of strings, some of them JSON bodies) as text, secrets masked, capped."""
    if raw in (None, "", "[]"):
        return None
    try:
        items = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        items = [raw]
    parts = []
    for item in items if isinstance(items, list) else [items]:
        try:
            body = json.loads(item) if isinstance(item, str) and item.lstrip()[:1] in "{[" else item
        except ValueError:
            body = item
        text = body if isinstance(body, str) else json.dumps(mask_secrets(body), separators=(",", ":"))
        parts.append(text.strip())
    out = " | ".join(p for p in parts if p)
    return (out[:DETAILS_CHARS] + "...") if len(out) > DETAILS_CHARS else out or None


def is_session_noise(a: dict[str, Any]) -> bool:
    return bool(SESSION_RE.search(str(a.get("logmessage") or "")))


def audit_row(
    a: dict[str, Any], hosts: dict[str, str] | None = None, *, details: bool = False
) -> dict[str, Any]:
    device = a.get("logdeviceid")
    return clean(
        {
            "time": iso(a.get("entry_time")),
            "user": a.get("loguser"),
            "source_ip": a.get("logusersrcip"),
            "module": a.get("logmodule"),
            "feature": a.get("logfeature"),
            "message": a.get("logmessage"),
            "device": (hosts or {}).get(str(device)) or device,
            "details": (a.get("logdetails") or audit_details(a.get("auditdetails"))) if details else None,
        }
    )


def audit_mentions(a: dict[str, Any], ips: set[str], names: set[str]) -> bool:
    """The audit line is about one of these devices: its device id, or the message names it."""
    if str(a.get("logdeviceid") or "") in ips:
        return True
    text = f"{a.get('logmessage') or ''} {a.get('auditdetails') or ''}"
    return any(re.search(rf"(?<![\w.-]){re.escape(n)}(?![\w-]|\.\d)", text) for n in ips | names if n)


# --- the merged timeline -------------------------------------------------------------------------


def timeline_line(source: str, rec: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """One catsdwan_recent_activity line from an alarm, event or audit record (epoch ms kept for sorting)."""
    if source == "alarm":
        state = alarm_state(rec)
        what = f"{rec.get('rule_name_display') or rec.get('type')}: {rec.get('message')}"
        if state == "cleared":
            what += f" (cleared {iso(rec.get('cleared_time'))})"
        elif state == "active":
            what += " (active)"
        device = ", ".join(alarm_devices(rec)) or (f"site {rec['site_id']}" if rec.get("site_id") else None)
        severity = rec.get("severity")
    elif source == "event":
        what = f"{rec.get('eventname')}: {rec.get('details')}"
        device = rec.get("host_name") or rec.get("system_ip")
        severity = rec.get("severity_level")
    else:
        what = f"{rec.get('loguser')} [{rec.get('logmodule')}]: {rec.get('logmessage')}"
        dev = rec.get("logdeviceid")
        device = (hosts or {}).get(str(dev)) or dev
        severity = None
    return {
        "_ms": _ms(rec.get("entry_time")),
        **clean(
            {
                "time": iso(rec.get("entry_time")),
                "source": source,
                "severity": _sev(severity) or None,
                "device": device,
                "what": str(what)[:400],
            }
        ),
    }
