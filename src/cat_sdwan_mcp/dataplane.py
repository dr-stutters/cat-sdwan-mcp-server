"""Data plane and application-aware routing (W4): BFD sessions, tunnel counters, app-route statistics and
the SLA classes.

Sources (recorded on 20.18.3.1 unless marked):
- GET /dataservice/device/bfd/sessions?deviceId=: one row per tunnel (`local-color`, `color` = the remote
  colour, `system-ip` = the remote edge, `site-id`, `state`, `uptime(-date)`, `transitions`, `src-ip/port`,
  `dst-ip/port`, `proto`, `detect-multiplier`, `tx-interval`); /bfd/summary: `bfd-sessions-total/up/max/flap`.
- GET /dataservice/data/device/state/BFDSessions (bulk, name unverified, not recorded): the same for every
  edge from the state database.
- GET /dataservice/device/tunnel/statistics?deviceId=: per tunnel `tx_pkts`, `tx_octets`, `rx_pkts`,
  `rx_octets`, `tunnel-mtu`, `tcp-mss-adjust` (counters since the tunnel came up; no drop counter).
- POST /dataservice/statistics/approute {"query": {last_n_hours + rules on vdevice_name, local_color,
  remote_system_ip}, "size": n}: one row per tunnel per 10-minute statistics cycle (`latency`, `jitter`,
  `loss_percentage`, `vqoe_score`, `state`, `sla_class_names`, `entry_time`), aggregated per tunnel here.
- GET /dataservice/device/app-route/statistics?deviceId=: the device's own app-route buckets right now (one
  row per tunnel and bucket `index`, with `mean-loss`, `mean-latency`, `mean-jitter`, `sla-class-index`).
- GET /dataservice/template/policy/list/sla: the SLA classes (`entries` [{loss, latency, jitter}]),
  /template/policy/definition/approute and /template/policy/vsmart: which app-route policy uses each class
  and whether it is activated.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from cat_sdwan_mcp.control import clean
from cat_sdwan_mcp.inventory import iso

BFD_SESSIONS_PATH = "/dataservice/device/bfd/sessions"
BFD_SUMMARY_PATH = "/dataservice/device/bfd/summary"
BULK_BFD = "BFDSessions"
TUNNEL_PATH = "/dataservice/device/tunnel/statistics"
APPROUTE_STATS_PATH = "/dataservice/statistics/approute"
APPROUTE_RT_PATH = "/dataservice/device/app-route/statistics"
SLA_LIST_PATH = "/dataservice/template/policy/list/sla"
APPROUTE_DEF_PATH = "/dataservice/template/policy/definition/approute"
VSMART_POLICY_PATH = "/dataservice/template/policy/vsmart"
ALL_TUNNELS = "__all_tunnels__"  # the implicit SLA class every tunnel belongs to


def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f


def _int(v: Any) -> int | None:
    f = _num(v)
    return int(f) if f is not None else None


def _ep(ip: Any, port: Any) -> str | None:
    if not ip:
        return None
    return f"{ip}:{port}" if port not in (None, "", 0, "0") else str(ip)


def is_up(row: dict[str, Any]) -> bool:
    return str(row.get("state", "")).lower() == "up"


# --- BFD -----------------------------------------------------------------------------------------


def bfd_row(b: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    remote = b.get("system-ip")
    return clean(
        {
            "host": b.get("vdevice-host-name") or (hosts or {}).get(str(b.get("vdevice-name"))),
            "system_ip": b.get("vdevice-name"),
            "local_colour": b.get("local-color"),
            "remote": (hosts or {}).get(str(remote)),
            "remote_system_ip": remote,
            "remote_colour": b.get("color"),
            "site_id": b.get("site-id"),
            "state": b.get("state"),
            "uptime": b.get("uptime"),
            "up_since": iso(b.get("uptime-date")),
            "transitions": b.get("transitions"),
            "source": _ep(b.get("src-ip"), b.get("src-port")),
            "destination": _ep(b.get("dst-ip"), b.get("dst-port")),
            "encap": b.get("proto"),
            "detect_multiplier": _int(b.get("detect-multiplier")),
            "hello_ms": _int(b.get("tx-interval")),
        }
    )


def bfd_summary(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    s = rows[0]
    return clean(
        {
            "total": _int(s.get("bfd-sessions-total")),
            "up": _int(s.get("bfd-sessions-up")),
            "max": _int(s.get("bfd-sessions-max")),
            "flaps": _int(s.get("bfd-sessions-flap")),
        }
    )


def colour_pairs(rows: list[dict[str, Any]]) -> dict[str, str]:
    """'mpls -> mpls': 'up/total' per local/remote colour pair."""
    total: dict[str, int] = defaultdict(int)
    up: dict[str, int] = defaultdict(int)
    for r in rows:
        key = f"{r.get('local_colour')} -> {r.get('remote_colour')}"
        total[key] += 1
        up[key] += is_up(r)
    return {k: f"{up[k]}/{total[k]} up" for k in sorted(total)}


def sort_sessions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            is_up(r),
            str(r.get("host") or r.get("system_ip") or ""),
            str(r.get("remote") or r.get("remote_system_ip") or ""),
            str(r.get("local_colour") or ""),
            str(r.get("remote_colour") or ""),
        ),
    )


def colour_matches(row: dict[str, Any], colour: str | None) -> bool:
    if not colour:
        return True
    want = colour.strip().lower()
    return want in (str(row.get("local_colour", "")).lower(), str(row.get("remote_colour", "")).lower())


def remote_matches(row: dict[str, Any], remote: str | None) -> bool:
    if not remote:
        return True
    want = remote.strip().lower()
    return want in (str(row.get("remote", "")).lower(), str(row.get("remote_system_ip", "")).lower())


# --- tunnels -------------------------------------------------------------------------------------


def tunnel_row(t: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    remote = t.get("system-ip")
    return clean(
        {
            "host": t.get("vdevice-host-name"),
            "local_colour": t.get("local-color"),
            "remote": (hosts or {}).get(str(remote)),
            "remote_system_ip": remote,
            "remote_colour": t.get("remote-color"),
            "protocol": t.get("tunnel-protocol"),
            "source": _ep(t.get("source-ip"), t.get("source-port")),
            "destination": _ep(t.get("dest-ip"), t.get("dest-port")),
            "tx_packets": _int(t.get("tx_pkts")),
            "rx_packets": _int(t.get("rx_pkts")),
            "tx_bytes": _int(t.get("tx_octets")),
            "rx_bytes": _int(t.get("rx_octets")),
            "mtu": _int(t.get("tunnel-mtu")),
            "tcp_mss": _int(t.get("tcp-mss-adjust")),
        }
    )


# --- app-route statistics ------------------------------------------------------------------------


def _stats(values: list[float]) -> tuple[float | None, float | None, float | None]:
    if not values:
        return None, None, None
    return round(sum(values) / len(values), 2), min(values), max(values)


def aggregate_approute(
    rows: list[dict[str, Any]], hosts: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Statistics rows (one per tunnel per cycle) -> one row per tunnel: samples, loss % (avg, max), latency
    and jitter in ms (avg, min, max), the last state and the SLA classes the Manager says it met last."""
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        key = (
            str(r.get("vdevice_name") or r.get("local_system_ip")),
            str(r.get("local_color")),
            str(r.get("remote_system_ip")),
            str(r.get("remote_color")),
        )
        groups[key].append(r)
    out = []
    for (local, lcol, remote, rcol), samples in groups.items():
        samples.sort(key=lambda s: _num(s.get("entry_time")) or 0)
        last = samples[-1]
        loss = [v for s in samples if (v := _num(s.get("loss_percentage"))) is not None]
        lat = [v for s in samples if (v := _num(s.get("latency"))) is not None]
        jit = [v for s in samples if (v := _num(s.get("jitter"))) is not None]
        vqoe = [v for s in samples if (v := _num(s.get("vqoe_score"))) is not None]
        loss_avg, _, loss_max = _stats(loss)
        lat_avg, lat_min, lat_max = _stats(lat)
        jit_avg, jit_min, jit_max = _stats(jit)
        classes = [c for c in str(last.get("sla_class_names") or "").split(",") if c and c != ALL_TUNNELS]
        out.append(
            clean(
                {
                    "host": last.get("host_name") or (hosts or {}).get(local),
                    "system_ip": local,
                    "local_colour": lcol,
                    "remote": (hosts or {}).get(remote),
                    "remote_system_ip": remote,
                    "remote_colour": rcol,
                    "samples": len(samples),
                    "loss_percent": loss_avg,
                    "loss_max": loss_max,
                    "latency_ms": lat_avg,
                    "latency_min": lat_min,
                    "latency_max": lat_max,
                    "jitter_ms": jit_avg,
                    "jitter_min": jit_min,
                    "jitter_max": jit_max,
                    "vqoe": _stats(vqoe)[0],
                    "state": last.get("state"),
                    "sla_classes": classes or None,
                    "last_seen": iso(last.get("entry_time")),
                }
            )
        )
    return out


def aggregate_realtime(
    rows: list[dict[str, Any]], hosts: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """device/app-route/statistics (one row per tunnel and bucket) -> one row per tunnel with the device's
    own means and the buckets' totals."""
    groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        key = tuple(str(r.get(k)) for k in ("src-ip", "dst-ip", "local-color", "remote-color", "proto"))
        groups[key].append(r)  # type: ignore[index]
    out = []
    for buckets in groups.values():
        b = buckets[0]
        remote = b.get("remote-system-ip")
        latency = [v for x in buckets if (v := _num(x.get("average-latency"))) is not None]
        out.append(
            clean(
                {
                    "host": b.get("vdevice-host-name"),
                    "system_ip": b.get("vdevice-name"),
                    "local_colour": b.get("local-color"),
                    "remote": (hosts or {}).get(str(remote)),
                    "remote_system_ip": remote,
                    "remote_colour": b.get("remote-color"),
                    "loss_percent": _num(b.get("mean-loss")),
                    "latency_ms": _num(b.get("mean-latency")),
                    "jitter_ms": _num(b.get("mean-jitter")),
                    "latency_max": max(latency) if latency else None,
                    "buckets": len(buckets),
                    "probe_packets": sum(_int(x.get("total-packets")) or 0 for x in buckets),
                    "lost_packets": sum(_int(x.get("loss")) or 0 for x in buckets),
                    "sla_class_index": b.get("sla-class-index"),
                    "source": _ep(b.get("src-ip"), b.get("src-port")),
                    "destination": _ep(b.get("dst-ip"), b.get("dst-port")),
                }
            )
        )
    return out


def sort_worst(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Worst tunnels first: not up, then loss, latency and jitter (descending)."""
    return sorted(
        rows,
        key=lambda r: (
            "state" in r and not is_up(r),
            r.get("loss_percent") or 0,
            r.get("latency_ms") or 0,
            r.get("jitter_ms") or 0,
        ),
        reverse=True,
    )


def sla_verdict(row: dict[str, Any], sla: dict[str, Any]) -> str:
    """'meets' or 'misses: loss 3.1% > 2%, ...' for one tunnel against one SLA class (averages)."""
    misses = []
    for metric, key, unit in (
        ("loss", "loss_percent", "%"),
        ("latency", "latency_ms", " ms"),
        ("jitter", "jitter_ms", " ms"),
    ):
        limit, value = sla.get(f"{metric}_max"), row.get(key)
        if isinstance(limit, int | float) and isinstance(value, int | float) and value > limit:
            misses.append(f"{metric} {value:g}{unit} > {limit:g}{unit}")
    if not any(isinstance(row.get(k), int | float) for k in ("loss_percent", "latency_ms", "jitter_ms")):
        return "no data"
    return "misses: " + ", ".join(misses) if misses else "meets"


# --- SLA classes ---------------------------------------------------------------------------------


def _policy_definitions(policy: dict[str, Any]) -> set[str]:
    raw = policy.get("policyDefinition")
    try:
        body = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return set()
    if not isinstance(body, dict):
        return set()
    return {str(a.get("definitionId")) for a in body.get("assembly") or [] if isinstance(a, dict)}


def sla_rows(
    lists: list[dict[str, Any]],
    definitions: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """SLA classes with their thresholds, and the app-route policies (and centralized policies, activated or
    not) that use them."""
    defs = {str(d.get("definitionId")): d for d in definitions or []}
    used_in: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in policies or []:
        for def_id in _policy_definitions(p):
            used_in[def_id].append(p)
    out = []
    for s in lists:
        e = (s.get("entries") or [{}])[0]
        approute = [str(r.get("id")) for r in s.get("references") or [] if isinstance(r, dict)]
        names = [str(defs[i].get("name")) if i in defs else i for i in approute]
        central = [
            f"{p.get('policyName')} ({'' if _truthy(p.get('isPolicyActivated')) else 'not '}activated)"
            for i in approute
            for p in used_in.get(i, [])
        ]
        out.append(
            clean(
                {
                    "name": s.get("name"),
                    "loss_max": _num(e.get("loss")),
                    "latency_max": _num(e.get("latency")),
                    "jitter_max": _num(e.get("jitter")),
                    "app_probe_class": e.get("appProbeClass"),
                    "fallback": e.get("fallbackBestTunnel"),
                    "description": s.get("description"),
                    "default": bool(s.get("readOnly")),
                    "owner": s.get("owner"),
                    "references": s.get("referenceCount"),
                    "app_route_policies": names or None,
                    "centralized_policies": sorted(set(central)) or None,
                    "updated": iso(s.get("lastUpdated")),
                }
            )
        )
    return sorted(out, key=lambda r: (r.get("default", False), str(r.get("name", "")).lower()))


def _truthy(v: Any) -> bool:
    return v is True or str(v).lower() == "true"
