"""Configuration history (W20): the running configurations the Manager stored for a device over time.

Pure helpers; the tool is in tools/confighistory.py. Sources (recorded on 20.18.3.1):
- GET /dataservice/device/history/config?deviceId=<system IP>&query=<JSON>: the spec marks both required.
  WITH a `query` the Manager ignores `deviceId` and returns every device's history, so the query carries a
  `system_ip` rule; `fields` keeps the configuration text out of the list and `size` is honoured.
  {header, pageInfo {startTime, endTime, count}, data: [{entry_time (ms), config_id, config_mode ("cli",
  "cli/ztp", ...), system_ip, device_type, device_uuid}]}, newest first (`sort` on entry_time asc reverses
  it). Without `fields`: also `configuration` (CLI text), `configuration_xml` and `configuration_diff`
  (the NETCONF change as XML). Without `query`: only that device's rows, no text, no time filter.
- GET /dataservice/device/history/config/{config_id}: {data: [[{entry_time, config_mode, system_ip,
  configuration, configuration_xml, configuration_diff, config_id, device_type}]]} (a list in a list); an
  unknown id answers 200 {data: [[]]}.
- GET /dataservice/device/history/config/diff/list?config_id1=&config_id2=: NOT a diff: [{config_1: text},
  {config_2: text}], the two configurations (config_1 without its leading "config" line). An unknown id
  answers 400 INVALID_QUERY "One of the configuration is missing". The diff is computed
  here (W7's block diff).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest
from cat_sdwan_mcp.client import _as_list, rule
from cat_sdwan_mcp.inventory import iso

HISTORY_PATH = "/dataservice/device/history/config"
VERSION_PATH = HISTORY_PATH + "/{id}"
DIFF_PATH = HISTORY_PATH + "/diff/list"
LIST_FIELDS = ["entry_time", "config_id", "config_mode", "system_ip", "device_type"]

MODE_NOTE = {
    "cli": "stored from the device's running configuration (a change on the device, or the first sync)",
    "cli/ztp": "stored after the Manager pushed a configuration (configuration group or template deploy)",
}


def history_query(system_ip: str, hours: int, size: int) -> str:
    """The `query` parameter: the device's rows (the Manager ignores deviceId once a query is given) in the
    last `hours`, without the configuration text."""
    body = {
        "query": {
            "condition": "AND",
            "rules": [
                rule("entry_time", [hours], type_="date", operator="last_n_hours"),
                rule("system_ip", [system_ip]),
            ],
        },
        "fields": LIST_FIELDS,
        "size": size,
    }
    return json.dumps(body, separators=(",", ":"))


def history_rows(body: Any, system_ip: str) -> list[dict[str, Any]]:
    """The device's versions, newest first: {index (0 = newest), config_id, time, mode, note}. Rows of other
    devices are dropped (should the Manager ever ignore the system_ip rule as it ignores deviceId)."""
    rows = body.get("data") if isinstance(body, dict) else body
    keep = [
        r
        for r in _as_list(rows)
        if isinstance(r, dict) and r.get("config_id") and str(r.get("system_ip") or system_ip) == system_ip
    ]
    keep.sort(key=lambda r: _ms(r.get("entry_time")) or 0, reverse=True)
    out = []
    for i, r in enumerate(keep):
        mode = str(r.get("config_mode") or "")
        row = {
            "index": i,
            "config_id": str(r["config_id"]),
            "time": iso(r.get("entry_time")),
            "entry_time": _ms(r.get("entry_time")),
            "mode": mode or None,
            "note": MODE_NOTE.get(mode),
        }
        out.append({k: v for k, v in row.items() if v is not None})
    return out


def _ms(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float):
        return int(v)
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


def parse_when(text: str) -> int:
    """An ISO 8601 time ('2026-10-22T21:00:00Z', a date, or with an offset) or epoch milliseconds -> ms."""
    t = text.strip()
    if t.isdigit():
        return int(t)
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError as e:
        raise InvalidRequest(
            f"`at` {text!r} is not an ISO 8601 time (e.g. '2026-10-22T21:00:00Z') or epoch milliseconds."
        ) from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp() * 1000)


def pick_version(rows: list[dict[str, Any]], ref: str) -> dict[str, Any]:
    """A version by config id, index ('0' = newest), 'latest' or 'previous'."""
    want = ref.strip().lower()
    if not rows:
        raise InvalidRequest("The device has no stored configurations in the window: widen since_hours.")
    if want in ("latest", "newest", "current"):
        return rows[0]
    if want in ("previous", "prev"):
        if len(rows) < 2:
            raise InvalidRequest("Only one stored configuration in the window: there is no previous one.")
        return rows[1]
    if want.lstrip("-").isdigit():
        i = int(want)
        if 0 <= i < len(rows):
            return rows[i]
        raise InvalidRequest(f"Version index {i} is out of range: the window has {len(rows)} (0 = newest).")
    for r in rows:
        if r["config_id"].lower() == want:
            return r
    ids = ", ".join(f"{r['index']}={r['config_id']}" for r in rows[:10])
    raise InvalidRequest(f"{ref!r} is not one of this device's stored configurations in the window ({ids}).")


def version_at(rows: list[dict[str, Any]], at_ms: int) -> dict[str, Any] | None:
    """The version in effect at `at_ms`: the newest stored at or before it."""
    for r in rows:  # newest first
        if (r.get("entry_time") or 0) <= at_ms:
            return r
    return None


def version_text(body: Any) -> dict[str, Any] | None:
    """The one row of GET /history/config/{id} ({data: [[row]]}; tolerates [row] and a bare row)."""
    data = body.get("data") if isinstance(body, dict) else body
    for _ in range(3):
        if isinstance(data, list):
            data = data[0] if data else None
        else:
            break
    return data if isinstance(data, dict) else None


def diff_texts(body: Any) -> tuple[str | None, str | None]:
    """(config_1, config_2) from the diff/list answer [{config_1: text}, {config_2: text}]."""
    one = two = None
    for item in _as_list(body.get("data") if isinstance(body, dict) else body):
        if isinstance(item, dict):
            if isinstance(item.get("config_1"), str):
                one = item["config_1"]
            if isinstance(item.get("config_2"), str):
                two = item["config_2"]
    return one, two
