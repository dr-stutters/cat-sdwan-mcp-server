"""Site, tunnel and interface health (W22): the Manager's own health model, interface statistics and a site
topology.

Pure helpers; the tools are in tools/health.py. Sources (recorded on 20.18.3.1):
- GET /dataservice/statistics/sitehealth/common?last_n_hours=&includeDetails=true: {header, data: [{site_id,
  site_name, site_health, devices_health, tunnels_health, apps_health (good|fair|poor|no_data),
  devices_health_score, tunnels_health_score, apps_health_score (0-10, -1 = no data), apps_usage,
  tunnel_summary {poor_tunnel_count, fair_tunnel_count, good_tunnel_count}, device_detail: [{host_name,
  device-model, system-ip, configGroupName, policyGroupName, ...}], device_count}]}.
  The controllers' site is a site too.
- GET /dataservice/statistics/sitehealth/topology?last_n_hours=: {data: [{entry_time, poor_site_count,
  fair_site_count, good_site_count}]} per 30 minutes.
- GET /dataservice/health/devices/overview: {good, fair, poor} device counts.
- GET /dataservice/network/status: {data: [{type vSmart|vbond|vEdge|omp|control|bfd, name, count, statusList:
  [{status error|warning|normal|new|up|down, count}]}]}.
- GET /dataservice/statistics/tunnelhealth/overview/{type}?last_n_hours=&site=&limit=: {total {good, fair,
  poor}, detail {good: [...], fair: [...], poor: [...]}}, each tunnel {name "<host>:<colour>-<host>:<colour>",
  local_system_ip, local_color, remote_system_ip, remote_color, latency, jitter, loss_percentage, vqoe_score,
  tx_octets, rx_octets, state, health_score, health}; `type` (the GUI's sort: health, latency,
  loss_percentage, jitter) does not filter.
- GET /dataservice/statistics/tunnelhealth/history?last_n_hours=&site=&limit=: [{name, local/remote system IP
  and colour, health, health_score, summary {latency, jitter, loss_percentage, vqoe_score, state}, history:
  [{entry_time, health good|fair|poor|n/a, health_score, data {latency, jitter, loss_percentage, ...}}]}] per
  30 minutes.
- POST /dataservice/statistics/interface/aggregation {query, aggregation: {field: [vdevice_name, interface],
  metrics: [...]}}: one row per interface with the metrics and `count` (samples). One metric per property: an
  avg and a max of the same property in one body answers 500 REST0001. No pageInfo.
- GET /dataservice/statistics/interface/ccapacity/distribution?site-id=: {data: [{vdevice_name, interface,
  range, avg/min/max_up/down_capacity_percentage, bw_up, bw_down, count}]} (the WAN circuits of the site).
- POST /dataservice/statistics/qos: empty in the lab (no QoS policy), so per-queue drops are read raw and
  summed here (field names not recorded).
- GET /dataservice/topology/device/site/{siteId}: {site_name, data: [{host_name, system_ip, device-model,
  site_id, configured_on, intent {type config-group|..., name, featureprofiles: [...]}}]}.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cat_sdwan_mcp.client import _as_list, last_hours, rule
from cat_sdwan_mcp.dataplane import _num
from cat_sdwan_mcp.inventory import iso

SITEHEALTH_PATH = "/dataservice/statistics/sitehealth/common"
SITEHEALTH_TREND_PATH = "/dataservice/statistics/sitehealth/topology"
DEVICE_HEALTH_OVERVIEW_PATH = "/dataservice/health/devices/overview"
NETWORK_STATUS_PATH = "/dataservice/network/status"
TUNNEL_OVERVIEW_PATH = "/dataservice/statistics/tunnelhealth/overview/{type}"
TUNNEL_HISTORY_PATH = "/dataservice/statistics/tunnelhealth/history"
INTERFACE_AGG_PATH = "/dataservice/statistics/interface/aggregation"
CAPACITY_PATH = "/dataservice/statistics/interface/ccapacity/distribution"
QOS_PATH = "/dataservice/statistics/qos"
SITE_TOPOLOGY_PATH = "/dataservice/topology/device/site/{id}"

HEALTH_ORDER = {"poor": 0, "fair": 1, "good": 2, "no_data": 3, "n/a": 3}
COMPONENTS = ("devices", "tunnels", "apps")


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


INTERFACE_METRICS = [
    ("rx_kbps", "avg"),
    ("tx_kbps", "avg"),
    ("rx_pps", "max"),
    ("rx_errors", "sum"),
    ("tx_errors", "sum"),
    ("rx_drops", "sum"),
    ("tx_drops", "sum"),
    ("down_capacity_percentage", "max"),
    ("up_capacity_percentage", "max"),
    ("bw_down", "max"),
    ("bw_up", "max"),
]


def _health(v: Any) -> str:
    s = str(v or "").strip().lower()
    return s or "no_data"


def _score(v: Any) -> float | None:
    n = _num(v)
    return None if n is None or n < 0 else round(n, 2)


# --- site health ---------------------------------------------------------------------------------


def site_verdict(r: dict[str, Any]) -> str:
    """'<health>: <why>' from the worst component and its score (the Manager's own model, not recomputed)."""
    overall = _health(r.get("site_health"))
    bad = [
        (c, _health(r.get(f"{c}_health")), _score(r.get(f"{c}_health_score")))
        for c in COMPONENTS
        if _health(r.get(f"{c}_health")) in ("poor", "fair")
    ]
    bad.sort(key=lambda x: HEALTH_ORDER.get(x[1], 3))
    if bad:
        why = "; ".join(f"{c} {h}" + (f" (score {s}/10)" if s is not None else "") for c, h, s in bad)
        summary = _dict(r.get("tunnel_summary"))
        poor, fair = summary.get("poor_tunnel_count") or 0, summary.get("fair_tunnel_count") or 0
        if poor or fair:
            why += f"; {poor} poor and {fair} fair tunnel(s)"
        return f"{overall}: {why}"
    if overall == "good":
        return "good"
    return f"{overall}: no component reports a problem (no data yet?)"


def site_row(r: dict[str, Any]) -> dict[str, Any]:
    summary = _dict(r.get("tunnel_summary"))
    devices = [d for d in _as_list(r.get("device_detail")) if isinstance(d, dict)]
    row = {
        "site_id": str(r.get("site_id")) if r.get("site_id") is not None else None,
        "site_name": r.get("site_name"),
        "health": _health(r.get("site_health")),
        "verdict": site_verdict(r),
        "devices_health": _health(r.get("devices_health")),
        "tunnels_health": _health(r.get("tunnels_health")),
        "apps_health": _health(r.get("apps_health")),
        "devices_score": _score(r.get("devices_health_score")),
        "tunnels_score": _score(r.get("tunnels_health_score")),
        "apps_score": _score(r.get("apps_health_score")),
        "tunnels": (
            f"{summary.get('good_tunnel_count', 0)} good, {summary.get('fair_tunnel_count', 0)} fair, "
            f"{summary.get('poor_tunnel_count', 0)} poor"
            if summary
            else None
        ),
        "device_names": ", ".join(str(d.get("host_name") or d.get("system-ip")) for d in devices) or None,
        "config_groups": ", ".join(
            sorted({str(d["configGroupName"]) for d in devices if d.get("configGroupName")})
        )
        or None,
    }
    return {k: v for k, v in row.items() if v is not None}


def site_rows(body: Any) -> list[dict[str, Any]]:
    rows = body.get("data") if isinstance(body, dict) else body
    out = [site_row(r) for r in _as_list(rows) if isinstance(r, dict)]
    out.sort(key=lambda r: (HEALTH_ORDER.get(r["health"], 3), str(r.get("site_id"))))
    return out


def site_trend(body: Any) -> list[dict[str, Any]]:
    """The intervals in which any site was fair or poor: {time, poor, fair, good}."""
    rows = body.get("data") if isinstance(body, dict) else body
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        poor, fair = int(r.get("poor_site_count") or 0), int(r.get("fair_site_count") or 0)
        if poor or fair:
            out.append(
                {
                    "time": iso(r.get("entry_time")),
                    "poor": poor,
                    "fair": fair,
                    "good": int(r.get("good_site_count") or 0),
                }
            )
    return out


def network_status(body: Any) -> dict[str, Any]:
    """{type: {status: count}} with only the non-zero statuses (and the total count)."""
    rows = body.get("data") if isinstance(body, dict) else body
    out: dict[str, Any] = {}
    for r in _as_list(rows):
        if not isinstance(r, dict) or not r.get("type"):
            continue
        counts = {
            str(s.get("status")): s.get("count")
            for s in _as_list(r.get("statusList"))
            if isinstance(s, dict) and s.get("count")
        }
        out[str(r.get("name") or r["type"])] = {"total": r.get("count"), **counts}
    return out


# --- tunnel health -------------------------------------------------------------------------------


def tunnel_row(t: dict[str, Any], hosts: dict[str, str]) -> dict[str, Any]:
    local, remote = str(t.get("local_system_ip") or ""), str(t.get("remote_system_ip") or "")
    row = {
        "tunnel": t.get("name"),
        "health": _health(t.get("health")),
        "score": _score(t.get("health_score")),
        "local": hosts.get(local, local) or None,
        "local_colour": t.get("local_color"),
        "remote": hosts.get(remote, remote) or None,
        "remote_colour": t.get("remote_color"),
        "loss_pct": _round(t.get("loss_percentage")),
        "latency_ms": _round(t.get("latency")),
        "jitter_ms": _round(t.get("jitter")),
        "vqoe": _round(t.get("vqoe_score")),
        "state": t.get("state"),
        "local_system_ip": local or None,
        "remote_system_ip": remote or None,
    }
    return {k: v for k, v in row.items() if v is not None}


def _round(v: Any) -> float | None:
    n = _num(v)
    return None if n is None else round(n, 3)


def overview_tunnels(body: Any, hosts: dict[str, str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """({good, fair, poor} totals, tunnel rows worst first)."""
    b = body if isinstance(body, dict) else {}
    detail = _dict(b.get("detail"))
    rows = [
        tunnel_row(t, hosts)
        for bucket in ("poor", "fair", "good")
        for t in _as_list(detail.get(bucket))
        if isinstance(t, dict)
    ]
    rows.sort(
        key=lambda r: (HEALTH_ORDER.get(r["health"], 3), r.get("score") or 0, -(r.get("loss_pct") or 0))
    )
    totals = _dict(b.get("total"))
    return dict(totals), rows


def bad_periods(history: list[Any], bucket_ms: int = 30 * 60 * 1000) -> list[dict[str, Any]]:
    """Runs of consecutive fair/poor intervals: {from, to, worst, max_loss_pct, max_latency_ms}."""
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for h in sorted((x for x in history if isinstance(x, dict)), key=lambda x: x.get("entry_time") or 0):
        health = _health(h.get("health"))
        if health not in ("poor", "fair"):
            cur = None
            continue
        data = _dict(h.get("data"))
        t = int(h.get("entry_time") or 0)
        loss, lat = _num(data.get("loss_percentage")), _num(data.get("latency"))
        if cur is None:
            cur = {
                "from_ms": t,
                "to_ms": t + bucket_ms,
                "worst": health,
                "max_loss_pct": loss,
                "max_latency_ms": lat,
            }
            out.append(cur)
        else:
            cur["to_ms"] = t + bucket_ms
            if health == "poor":
                cur["worst"] = "poor"
            for k, v in (("max_loss_pct", loss), ("max_latency_ms", lat)):
                if v is not None and (cur[k] is None or v > cur[k]):
                    cur[k] = v
    return [
        {
            "from": iso(p["from_ms"]),
            "to": iso(p["to_ms"]),
            "worst": p["worst"],
            **({"max_loss_pct": round(p["max_loss_pct"], 3)} if p["max_loss_pct"] is not None else {}),
            **({"max_latency_ms": round(p["max_latency_ms"], 1)} if p["max_latency_ms"] is not None else {}),
        }
        for p in out
    ]


def history_rows(body: Any, hosts: dict[str, str]) -> list[dict[str, Any]]:
    """Per tunnel: health now, the window's averages and its bad periods; tunnels with bad periods first."""
    out = []
    for t in _as_list(body.get("data") if isinstance(body, dict) else body):
        if not isinstance(t, dict):
            continue
        summary = _dict(t.get("summary"))
        row = tunnel_row(
            {**summary, **{k: v for k, v in t.items() if k not in ("summary", "history")}}, hosts
        )
        row["bad_periods"] = bad_periods(_as_list(t.get("history")))
        out.append(row)
    out.sort(key=lambda r: (not r["bad_periods"], HEALTH_ORDER.get(r["health"], 3), str(r.get("tunnel"))))
    return out


# --- interface statistics ------------------------------------------------------------------------


def interface_body(system_ip: str, hours: int, interface: str | None) -> dict[str, Any]:
    rules = [rule("vdevice_name", [system_ip])]
    if interface:
        rules.append(rule("interface", [interface]))
    return {
        "query": last_hours(hours, *rules),
        "aggregation": {
            "field": [
                {"property": "vdevice_name", "sequence": 1, "size": 10},
                {"property": "interface", "sequence": 2, "size": 500},
            ],
            "metrics": [{"property": p, "type": t} for p, t in INTERFACE_METRICS],
        },
    }


def interface_rows(body: Any) -> list[dict[str, Any]]:
    """One row per interface: average rx/tx kbps, peak rx pps, errors and drops summed, peak use of the
    configured bandwidth (%), the bandwidth (kbps); busiest first."""
    rows = body.get("data") if isinstance(body, dict) else body
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict) or not r.get("interface"):
            continue
        row = {
            "interface": r.get("interface"),
            "rx_kbps": _round(r.get("rx_kbps")),
            "tx_kbps": _round(r.get("tx_kbps")),
            "peak_rx_pps": _round(r.get("rx_pps")),
            "errors": int((_num(r.get("rx_errors")) or 0) + (_num(r.get("tx_errors")) or 0)),
            "drops": int((_num(r.get("rx_drops")) or 0) + (_num(r.get("tx_drops")) or 0)),
            "peak_down_pct": _round(r.get("down_capacity_percentage")),
            "peak_up_pct": _round(r.get("up_capacity_percentage")),
            "bw_down_kbps": _round(r.get("bw_down")),
            "bw_up_kbps": _round(r.get("bw_up")),
            "samples": r.get("count"),
        }
        out.append({k: v for k, v in row.items() if v is not None})
    out.sort(key=lambda r: -((r.get("rx_kbps") or 0) + (r.get("tx_kbps") or 0)))
    return out


def interface_flags(rows: list[dict[str, Any]], busy_pct: float) -> list[str]:
    out = []
    for r in rows:
        peak = max(r.get("peak_down_pct") or 0, r.get("peak_up_pct") or 0)
        if peak >= busy_pct:
            out.append(f"{r['interface']} peaked at {peak}% of its configured bandwidth")
        if r.get("errors"):
            out.append(f"{r['interface']} counted {r['errors']} errors")
        if r.get("drops"):
            out.append(f"{r['interface']} counted {r['drops']} drops")
    return out


def capacity_rows(body: Any, system_ip: str) -> list[dict[str, Any]]:
    rows = body.get("data") if isinstance(body, dict) else body
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict) or str(r.get("vdevice_name") or system_ip) != system_ip:
            continue
        row = {
            "interface": r.get("interface"),
            "avg_down_pct": _round(r.get("avg_down_capacity_percentage")),
            "max_down_pct": _round(r.get("max_down_capacity_percentage")),
            "avg_up_pct": _round(r.get("avg_up_capacity_percentage")),
            "max_up_pct": _round(r.get("max_up_capacity_percentage")),
            "bw_down_kbps": r.get("bw_down"),
            "bw_up_kbps": r.get("bw_up"),
            "range": r.get("range"),
        }
        out.append({k: v for k, v in row.items() if v is not None})
    return out


def qos_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Raw QoS statistics summed per (interface, queue): every numeric field whose name has 'drop' (field
    names not recorded: the lab has no QoS policy)."""
    acc: dict[tuple[str, str], dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in rows:
        key = (
            str(r.get("interface") or r.get("if_name") or "?"),
            str(r.get("queue") or r.get("qos_queue_id") or r.get("queue_id") or "?"),
        )
        for k, v in r.items():
            n = _num(v)
            if "drop" in k.lower() and n is not None:
                acc[key][k] += n
    return [
        {"interface": i, "queue": q, **{k: int(v) for k, v in sorted(d.items())}}
        for (i, q), d in sorted(acc.items())
    ]


# --- topology ------------------------------------------------------------------------------------


def site_links(tunnels: list[dict[str, Any]], site_of: dict[str, str]) -> list[dict[str, Any]]:
    """Site pairs joined by tunnels: tunnels (counted once per direction pair), how many are up, health
    counts, worst loss and latency."""
    acc: dict[tuple[str, str], dict[str, Any]] = {}
    for t in tunnels:
        a = site_of.get(str(t.get("local_system_ip")))
        b = site_of.get(str(t.get("remote_system_ip")))
        if not a or not b or a == b:
            continue
        key = (a, b) if a <= b else (b, a)
        row = acc.setdefault(
            key, {"sites": f"{key[0]} <-> {key[1]}", "tunnels": 0, "up": 0, "good": 0, "fair": 0, "poor": 0}
        )
        row["tunnels"] += 1
        row["up"] += str(t.get("state", "")).lower() == "up"
        h = _health(t.get("health"))
        if h in ("good", "fair", "poor"):
            row[h] += 1
        for k, src in (("worst_loss_pct", "loss_pct"), ("worst_latency_ms", "latency_ms")):
            v = t.get(src)
            if isinstance(v, int | float) and v > row.get(k, -1):
                row[k] = v
    out = list(acc.values())
    out.sort(key=lambda r: (-r["poor"], -r["fair"], r["sites"]))
    return out


def site_intent(body: Any) -> dict[str, dict[str, Any]]:
    """{system IP: {config: '<type> <name>', profiles: [...]}} from /topology/device/site/{id}."""
    rows = body.get("data") if isinstance(body, dict) else body
    out: dict[str, dict[str, Any]] = {}
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        intent = _dict(r.get("intent"))
        profiles = [
            str(p.get("profileName")) for p in _as_list(intent.get("featureprofiles")) if isinstance(p, dict)
        ]
        ip = str(r.get("system_ip") or r.get("configuredSystemIP") or "")
        if ip:
            row = {
                "intent": f"{intent.get('type')} {intent.get('name')}" if intent.get("name") else None,
                "profiles": profiles or None,
            }
            out[ip] = {k: v for k, v in row.items() if v is not None}
    return out
