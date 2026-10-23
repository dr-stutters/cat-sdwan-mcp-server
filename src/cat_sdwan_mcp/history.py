"""SLA history and reports (W13): app-route statistics per hour or day, the periods each tunnel missed its
SLA, DPI application usage and the site report.

Pure helpers; the tools are in tools/history.py. Sources (20.18.3.1):
- POST /dataservice/statistics/approute/aggregation {"query": {last_n_hours + rules}, "aggregation": {"field":
  [{"property": "name", "sequence": 1, "size": n}], "histogram": {"property": "entry_time", "type": "hour",
  "interval": 1, "order": "asc"}, "metrics": [{"property": "latency", "type": "avg"}, {"property":
  "loss_percentage", "type": "avg"}, {"property": "jitter", "type": "avg"}]}} -> {header, entryTimeList, data:
  [{entry_time (bucket start, ms), name ("<local system IP>:<colour>-<remote system IP>:<colour>"), latency,
  loss_percentage, jitter (averages), count (samples)}]}: one row per tunnel per bucket (recorded: 96 rows, 24
  tunnels x 4 hourly buckets in a 6-hour query on a fabric up for 4 hours). No pageInfo.
- POST /dataservice/statistics/dpi/aggregation: the same query and aggregation form over the DPI index
  (fields application, family, octets, packets; recorded raw query empty: application visibility is not
  enabled in the lab, so the aggregation's answer shape is the approute one by analogy, not recorded).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.dataplane import _num, sla_verdict
from cat_sdwan_mcp.inventory import iso

APPROUTE_AGG_PATH = "/dataservice/statistics/approute/aggregation"
DPI_AGG_PATH = "/dataservice/statistics/dpi/aggregation"
HOUR_MS = 3600 * 1000
DAY_MS = 24 * HOUR_MS
TUNNEL_SIZE = 500  # tunnels per aggregation (the Manager's `size` of the name field)

_NAME = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(.+?)-(\d{1,3}(?:\.\d{1,3}){3}):(.+)$")

DPI_OFF = (
    "No DPI statistics{scope} in the last {hours} h. Application visibility is most likely not enabled on "
    "the edges (the lab has none): enable it in a localised policy (Application visibility, attached with "
    "the device template) or the policy group's Application Priority profile, then allow up to 30 minutes "
    "for the first statistics. Until then catsdwan_app_route_stats and the interface counters are the best "
    "answer to 'what is using the link'."
)


def histogram_body(
    query: dict[str, Any], kind: str = "hour", interval: int = 1, size: int = TUNNEL_SIZE
) -> dict[str, Any]:
    return {
        "query": query,
        "aggregation": {
            "field": [{"property": "name", "sequence": 1, "size": size}],
            "histogram": {"property": "entry_time", "type": kind, "interval": interval, "order": "asc"},
            "metrics": [
                {"property": "latency", "type": "avg"},
                {"property": "loss_percentage", "type": "avg"},
                {"property": "jitter", "type": "avg"},
            ],
        },
    }


def dpi_body(query: dict[str, Any], field: str, size: int) -> dict[str, Any]:
    return {
        "query": query,
        "aggregation": {
            "field": [{"property": field, "sequence": 1, "size": size}],
            "metrics": [{"property": "octets", "type": "sum"}, {"property": "packets", "type": "sum"}],
        },
    }


def granularity(days: int, wanted: str) -> tuple[str, int]:
    """('hour' | 'day', bucket length in ms): hourly up to 3 days, daily beyond (auto)."""
    kind = wanted if wanted in ("hour", "day") else ("hour" if days <= 3 else "day")
    return kind, HOUR_MS if kind == "hour" else DAY_MS


def parse_tunnel(name: Any) -> tuple[str, str, str, str] | None:
    """'10.0.0.2:biz-internet-10.0.0.1:mpls' -> ('10.0.0.2', 'biz-internet', '10.0.0.1', 'mpls')."""
    m = _NAME.match(str(name or ""))
    return (m.group(1), m.group(2), m.group(3), m.group(4)) if m else None


def rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data") if isinstance(body, dict) else body
    return [r for r in _as_list(data) if isinstance(r, dict)]


def series(data: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """{tunnel name: buckets oldest first}, each bucket {ms, latency_ms, loss_percent, jitter_ms, samples}."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in data:
        name = r.get("name")
        ms = _num(r.get("entry_time"))
        if not name or ms is None:
            continue
        out[str(name)].append(
            {
                "ms": int(ms),
                "latency_ms": _num(r.get("latency")),
                "loss_percent": _num(r.get("loss_percentage")),
                "jitter_ms": _num(r.get("jitter")),
                "samples": r.get("count"),
            }
        )
    for buckets in out.values():
        buckets.sort(key=lambda b: b["ms"])
    return dict(out)


def miss_periods(buckets: list[dict[str, Any]], sla: dict[str, Any], step_ms: int) -> list[dict[str, Any]]:
    """Consecutive buckets that missed the SLA class, merged: {start, end, buckets, worst}."""
    out: list[dict[str, Any]] = []
    for b in buckets:
        verdict = sla_verdict(b, sla)
        if not verdict.startswith("misses"):
            continue
        last = out[-1] if out else None
        if last is not None and b["ms"] - last["_end"] <= step_ms:
            last["_end"] = b["ms"]
            last["buckets"] += 1
            last["_why"].append(verdict.removeprefix("misses: "))
            continue
        out.append(
            {"_start": b["ms"], "_end": b["ms"], "buckets": 1, "_why": [verdict.removeprefix("misses: ")]}
        )
    return [
        {
            "start": iso(p["_start"]),
            "end": iso(p["_end"] + step_ms),
            "buckets": p["buckets"],
            "worst": _worst(p["_why"]),
        }
        for p in out
    ]


def _worst(reasons: list[str]) -> str:
    """The reason with the largest number in it ('latency 320 ms > 150 ms' over 'latency 180 ms > 150 ms')."""

    def size(text: str) -> float:
        nums = [float(x) for x in re.findall(r"[\d.]+", text.split(">")[0])]
        return max(nums) if nums else 0.0

    return max(reasons, key=size) if reasons else ""


def _avg(values: list[float | None]) -> float | None:
    got = [v for v in values if isinstance(v, int | float)]
    return round(sum(got) / len(got), 2) if got else None


def tunnel_summary(
    name: str,
    buckets: list[dict[str, Any]],
    sla: dict[str, Any] | None,
    step_ms: int,
    hosts: dict[str, str] | None = None,
) -> dict[str, Any]:
    parsed = parse_tunnel(name)
    local, lcol, remote, rcol = parsed if parsed else (None, None, None, None)
    worst = max(buckets, key=lambda b: b.get("latency_ms") or 0) if buckets else {}
    row: dict[str, Any] = {
        "tunnel": name,
        "host": (hosts or {}).get(str(local), local),
        "local_colour": lcol,
        "remote": (hosts or {}).get(str(remote), remote),
        "remote_colour": rcol,
        "buckets": len(buckets),
        "loss_percent": _avg([b.get("loss_percent") for b in buckets]),
        "latency_ms": _avg([b.get("latency_ms") for b in buckets]),
        "jitter_ms": _avg([b.get("jitter_ms") for b in buckets]),
        "worst_latency_ms": worst.get("latency_ms"),
        "worst_at": iso(worst.get("ms")),
    }
    if sla is not None:
        periods = miss_periods(buckets, sla, step_ms)
        row["missed_buckets"] = sum(p["buckets"] for p in periods)
        row["miss_periods"] = periods
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def sort_summaries(out: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        out,
        key=lambda r: (-(r.get("missed_buckets") or 0), -(r.get("latency_ms") or 0), str(r.get("tunnel"))),
    )


# --- per transport ---------------------------------------------------------------------------------


def per_colour(
    data: dict[str, list[dict[str, Any]]], sla: dict[str, Any] | None, times: list[int]
) -> dict[str, dict[str, Any]]:
    """Per local colour: availability (share of buckets in which at least one of its tunnels passed
    traffic, i.e. loss under 100%), average loss/latency/jitter, and the share of tunnel-buckets that missed
    the SLA."""
    by_colour: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for name, buckets in data.items():
        parsed = parse_tunnel(name)
        if parsed:
            by_colour[parsed[1]] += buckets
    total = len(times)
    out = {}
    for colour, buckets in sorted(by_colour.items()):
        up = {b["ms"] for b in buckets if (b.get("loss_percent") or 0) < 100}
        row: dict[str, Any] = {
            "availability_percent": round(100 * len(up & set(times)) / total, 1) if total else None,
            "buckets_without_traffic": total - len(up & set(times)) if total else None,
            "loss_percent": _avg([b.get("loss_percent") for b in buckets]),
            "latency_ms": _avg([b.get("latency_ms") for b in buckets]),
            "jitter_ms": _avg([b.get("jitter_ms") for b in buckets]),
        }
        if sla is not None and buckets:
            missed = sum(1 for b in buckets if sla_verdict(b, sla).startswith("misses"))
            row["sla_missed_percent"] = round(100 * missed / len(buckets), 1)
        out[colour] = {k: v for k, v in row.items() if v is not None}
    return out


def colour_verdict(row: dict[str, Any]) -> str:
    avail = row.get("availability_percent")
    missed = row.get("sla_missed_percent")
    if avail is not None and avail < 99:
        return f"degraded: available {avail}% of the time"
    if missed is not None and missed >= 10:
        return f"degraded: missed the SLA in {missed}% of the samples"
    return "healthy"


# --- DPI ---------------------------------------------------------------------------------------------


def usage_rows(data: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    """{name, bytes, packets, share_percent} from a DPI aggregation, biggest first."""
    total = sum(_num(r.get("octets")) or 0 for r in data)
    out = []
    for r in data:
        octets = _num(r.get("octets")) or 0
        out.append(
            {
                field: r.get(field) or r.get("name") or "unknown",
                "bytes": int(octets),
                "packets": int(_num(r.get("packets")) or 0),
                "share_percent": round(100 * octets / total, 1) if total else None,
            }
        )
    return sorted(out, key=lambda r: -r["bytes"])


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
