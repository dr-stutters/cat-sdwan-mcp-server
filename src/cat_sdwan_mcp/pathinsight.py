"""Network Wide Path Insight (W19): pure helpers; the tools are in tools/pathinsight.py.

Sources (20.18.3.1):
- GET /dataservice/stream/device/nwpi/traceHistory[?traceModel=&startTime=&endTime=] (recorded: the Manager's
  built-in demo trace 16 'nwpi_demo_example1'): {data: [{trace-id, entry_time, type: trace-history, createdBy,
  data: {summary: {source-site, vpn-id, vpn-list, src-pfx, src-pfx-len, dst-pfx, dst-pfx-len, app, protocol,
  dscp, duration, trace-name, state, ...}, devices: [{device-ip, local-system-ip, site-id, uuid, state,
  message, version, ...}], readout, flowTimeRange, ...}}]}.
- GET /stream/device/nwpi/tasks/taskHistory (recorded, empty; spec: taskId, taskName, events, sites, state,
  startTime, duration, stopTime).
- GET /stream/device/nwpi/traceFinFlowWithQuery?traceId=&timestamp=<entry_time> (recorded on the demo trace;
  not in the OpenAPI document, used by the Manager's UI): {data: [{type: hops-of-flow, data: {flow_id,
  flow_key, src_ip, src_port, dst_ip, dst_port, protocol, vpn_id, app_name, app_group, domain_name,
  upstream_hop_list / downstream_hop_list: [{hop_index, local_edge, local_color, remote_edge, remote_color,
  encap, local_drop_rate, local_drop_causes: [{display_name, per_cause_drop_stats}], remote_drop_rate,
  wan_drop_rate, latency, jitter, qos_congested, sla_violated, ...}], upstream_device_list /
  downstream_device_list: [{device_name, device_system_ip, up_fwd_decision, down_fwd_decision,
  up_actual_path: {Type, Local Color, Remote Color, Encap, Interface, Remote System IP}, ...}], policy_keys,
  sla_violated, qos_congested, path_changed, asymmetry_detected, server_no_response, tcp_flow_reset,
  security_alert, urlf_blocking, nat_translated, ...}}]}. GET .../traceFinFlowCount -> {total_flow_count}.
- GET /stream/device/nwpi/preloadinfo (recorded): {devices: [{host-name, system-ip, local-system-ip, deviceId,
  uuid, site-id, version, device-model}], interfaces: [{vdevice-name, ifname, ip-address, vpn-id}], models}.
- POST /stream/device/nwpi/trace/start (spec): body {source-site, duration (minutes), vpn-id | vpn-list,
  device-list: [{local-system-ip, deviceId, uuid, version}], src-pfx / dst-pfx ('a.b.c.d/len'), app,
  protocol, dscp, src-port, dst-port, art-vis, app-vis, qos-mon, source-site-version, traceModel
  SDWAN_MANUAL, local-drop-rate-threshold, wan-drop-rate-threshold, trace-name} (the shape the UI sends);
  answer {action, trace-id, trace-name, state, entry_time, expire-time, traces: [{device-ip, status,
  message}]}. POST /stream/device/nwpi/trace/stop/{traceId} -> {action, state: stopping, message, traces}.
  With Data Stream off the start answers 200 {state: enable_datastream, message: 'Data Stream is disabled...'}
  and no trace id (live 2026-10-24).
- GET /settings/configuration/vmanagedatastream (live): {data: [{}]} when Data Stream was never set up, else
  {data: [{enable, ipType, serverHostName, vpn}]}.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.inventory import iso

TRACE_START_PATH = "/dataservice/stream/device/nwpi/trace/start"
TRACE_STOP_PATH = "/dataservice/stream/device/nwpi/trace/stop/{trace_id}"
TRACE_HISTORY_PATH = "/dataservice/stream/device/nwpi/traceHistory"
TASK_HISTORY_PATH = "/dataservice/stream/device/nwpi/tasks/taskHistory"
TASK_TRACES_PATH = "/dataservice/stream/device/nwpi/tasks/{task_id}/traces"
FIN_FLOWS_PATH = "/dataservice/stream/device/nwpi/traceFinFlowWithQuery"
FIN_FLOW_COUNT_PATH = "/dataservice/stream/device/nwpi/traceFinFlowCount"
DATASTREAM_PATH = "/dataservice/settings/configuration/vmanagedatastream"
PRELOAD_PATH = "/dataservice/stream/device/nwpi/preloadinfo"

NA = ("N/A", "", None, "UNKNOWN_INTERFACE", "INVALID")
NO_VALUE = 2147483647  # the Manager's 'not measured'
FLAGS = {
    "sla_violated": "the app-route SLA was violated",
    "qos_congested": "QoS congestion (queue drops)",
    "path_changed": "the flow moved to another path during the trace",
    "asymmetry_detected": "upstream and downstream took different paths",
    "wan_color_asym": "upstream and downstream used different colours",
    "server_no_response": "the server did not answer",
    "tcp_flow_reset": "the TCP flow was reset",
    "security_alert": "a security alert (IPS, file, firewall) hit the flow",
    "urlf_blocking": "URL filtering blocked it",
    "nat_translated": "NAT translated the flow",
    "policy_bypassed": "policy was bypassed",
    "big_drop": "heavy drops on an edge",
    "big_wan_drop": "heavy drops on the WAN",
}


def _dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _v(x: Any) -> Any:
    return None if x in NA else x


def _num(x: Any) -> float | None:
    try:
        f = float(x)
    except (TypeError, ValueError):
        return None
    return None if f >= NO_VALUE else f


def prefix(value: str | None) -> str | None:
    """'10.61.201.10' -> '10.61.201.10/32'; a prefix is normalised; None stays None."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as e:
        raise ValueError(f"{value!r} is not an IP address or prefix") from e


# The trace start's protocol filter takes the IP protocol number as a string, and only TCP and UDP: "6" and
# "17" start a trace, "1" and "ICMP" answer 'Validation Error: Invalid Protocol(1)' / '(ICMP)' (live 20.18.3,
# 2026-10-24). ICMP is traced by leaving the protocol out and filtering on the addresses.
PROTOCOLS = {"tcp": "6", "6": "6", "udp": "17", "17": "17"}


def protocol_number(value: str | None) -> str | None:
    """'tcp' / '6' -> '6', 'udp' / '17' -> '17', None -> None; anything else is refused."""
    if value is None or not str(value).strip():
        return None
    want = str(value).strip().lower()
    if want in PROTOCOLS:
        return PROTOCOLS[want]
    if want in ("icmp", "1"):
        raise ValueError(
            "The Manager's path insight protocol filter takes TCP (6) or UDP (17) only ('Invalid "
            "Protocol(1)' for ICMP): leave protocol out and filter on source/destination to trace ICMP"
        )
    raise ValueError(f"protocol {value!r}: path insight filters on tcp (6) or udp (17) only")


def datastream_target(body: Any) -> str | None:
    """'systemIp in VPN 0' from the Data Stream setting: where the edges upload their flow records."""
    for r in _as_list(body.get("data")) if isinstance(body, dict) else []:
        if isinstance(r, dict) and r.get("enable") in (True, "true"):
            host = r.get("serverHostName") or r.get("ipType") or "?"
            return f"{host} in VPN {r.get('vpn', '?')}"
    return None


def short_version(v: Any) -> str | None:
    """'17.18.02.0.4112' -> '17.18'."""
    parts = str(v or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 and parts[0].isdigit() else None


def device_entry(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "local-system-ip": row.get("system_ip"),
        "deviceId": row.get("system_ip"),
        "uuid": row.get("chassis"),
        "version": row.get("version"),
    }


def start_body(
    *,
    site: str,
    devices: list[dict[str, Any]],
    vpns: list[int],
    duration: int,
    source: str | None,
    destination: str | None,
    app: str | None,
    protocol: str | None,
    dscp: int | None,
    name: str,
) -> dict[str, Any]:
    versions = sorted({v for d in devices if (v := short_version(d.get("version")))})
    body: dict[str, Any] = {
        "source-site": site,
        "duration": str(duration),
        "trace-name": name,
        "device-list": [device_entry(d) for d in devices],
        "art-vis": "true",
        "app-vis": "true",
        "qos-mon": "true",
        "traceModel": "SDWAN_MANUAL",
        "local-drop-rate-threshold": 5,
        "wan-drop-rate-threshold": 5,
    }
    if versions:
        body["source-site-version"] = versions[0]
    if len(vpns) == 1:
        body["vpn-id"] = str(vpns[0])
    else:
        body["vpn-list"] = [str(v) for v in vpns]
    for key, value in (
        ("src-pfx", source),
        ("dst-pfx", destination),
        ("app", app),
        ("protocol", protocol),
        ("dscp", None if dscp is None else str(dscp)),
    ):
        if value:
            body[key] = value
    return body


def trace_id_of(answer: Any) -> tuple[str | None, int | None]:
    """(trace-id, entry_time) from the start answer."""
    if not isinstance(answer, dict):
        return None, None
    tid = answer.get("trace-id")
    ts = answer.get("entry_time")
    return (str(tid) if tid not in (None, "") else None), (int(ts) if isinstance(ts, int | float) else None)


def start_problems(answer: Any) -> list[str]:
    """Per-device start failures and the overall action, in words."""
    if not isinstance(answer, dict):
        return ["the Manager's answer to the trace start was not understood"]
    out = []
    if str(answer.get("action", "success")).lower() != "success":
        out.append(str(answer.get("message") or answer.get("action")))
    for t in _as_list(answer.get("traces")):
        if isinstance(t, dict) and str(t.get("status", t.get("action", "success"))).lower() not in (
            "success",
            "",
        ):
            out.append(f"{t.get('device-ip')}: {t.get('message') or t.get('status')}")
    return out


def datastream_enabled(body: Any) -> bool:
    """Whether the Manager's Data Stream setting is on (path insight needs it)."""
    rows = _as_list(body.get("data")) if isinstance(body, dict) else []
    return any(isinstance(r, dict) and r.get("enable") in (True, "true") for r in rows)


def start_refusal(answer: Any) -> str:
    """Why the Manager started no trace, from an answer without a trace id."""
    if isinstance(answer, dict) and (answer.get("message") or answer.get("state")):
        return str(answer.get("message") or answer.get("state"))
    return f"no trace id in the answer {answer!r}"


# --- traces ---------------------------------------------------------------------------------------


def _filter(s: dict[str, Any]) -> str | None:
    parts = []
    for label, key, length in (("from", "src-pfx", "src-pfx-len"), ("to", "dst-pfx", "dst-pfx-len")):
        if _v(s.get(key)):
            ln = _v(s.get(length))
            parts.append(f"{label} {s[key]}" + (f"/{ln}" if ln and "/" not in str(s[key]) else ""))
    for label, key in (("app", "app"), ("app group", "app-grp"), ("protocol", "protocol"), ("dscp", "dscp")):
        if _v(s.get(key)):
            parts.append(f"{label} {s[key]}")
    return ", ".join(parts) or None


def trace_row(r: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    hosts = hosts or {}
    data = _dict(r.get("data"))
    s = _dict(data.get("summary"))
    devices = [d for d in _as_list(data.get("devices")) if isinstance(d, dict)]
    vpn = _v(s.get("vpn-list")) or _v(s.get("vpn-id"))
    row = {
        "trace_id": r.get("trace-id"),
        "name": _v(s.get("trace-name")),
        "started": iso(r.get("entry_time")),
        "timestamp": r.get("entry_time"),
        "state": _v(s.get("state")),
        "site": _v(s.get("source-site")),
        "vpn": vpn,
        "filter": _filter(s),
        "duration_min": _v(s.get("duration")),
        "devices": ", ".join(
            f"{hosts.get(str(d.get('local-system-ip')), d.get('local-system-ip'))} ({d.get('state')})"
            for d in devices
        )
        or None,
        "created_by": r.get("createdBy"),
        "message": _v(s.get("message")),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def task_row(t: dict[str, Any]) -> dict[str, Any]:
    row = {
        "task_id": t.get("taskId"),
        "name": t.get("taskName"),
        "state": t.get("state"),
        "events": ", ".join(str(e) for e in _as_list(t.get("events"))) or None,
        "sites": ", ".join(str(s) for s in _as_list(t.get("sites"))) or None,
        "started": iso(t.get("startTime") or t.get("entry_time")),
        "stopped": iso(t.get("stopTime")),
        "duration_min": t.get("duration"),
        "has_traces": t.get("traces"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


# --- flows ----------------------------------------------------------------------------------------


def _edge(name: Any) -> str | None:
    """'(Gi5)vm5' -> 'vm5 (Gi5)'."""
    s = _v(name)
    if not isinstance(s, str):
        return None
    if s.startswith("(") and ")" in s:
        iface, host = s[1:].split(")", 1)
        return f"{host} ({iface})" if host else iface
    if s.endswith(")") and "(" in s and not s.startswith("("):
        host, iface = s[:-1].split("(", 1)
        return f"{host.strip()} ({iface})"
    return s


def hop_row(h: dict[str, Any]) -> dict[str, Any]:
    causes = [
        f"{c.get('display_name') or c.get('cause')} x{c.get('per_cause_drop_stats')}"
        for c in _as_list(h.get("local_drop_causes")) + _as_list(h.get("remote_drop_causes"))
        if isinstance(c, dict)
    ]
    local, remote, wan = (_num(h.get(k)) for k in ("local_drop_rate", "remote_drop_rate", "wan_drop_rate"))
    row = {
        "hop": h.get("hop_index"),
        "from": _edge(h.get("local_edge")),
        "to": _edge(h.get("remote_edge")),
        "colour": "/".join(c for c in (_v(h.get("local_color")), _v(h.get("remote_color"))) if c) or None,
        "encap": _v(h.get("encap")),
        "local_drop_pct": local or None,
        "wan_drop_pct": wan or None,
        "remote_drop_pct": remote or None,
        "drop_causes": ", ".join(causes) or None,
        "latency": _num(h.get("latency")),
        "jitter": _num(h.get("jitter")),
        "packets": _v(h.get("total_packets")),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def _decisions(devices: list[Any]) -> list[str]:
    out = []
    for d in devices:
        if not isinstance(d, dict) or _v(d.get("device_name")) is None:
            continue
        path = _dict(d.get("up_actual_path"))
        kind = path.get("Type")
        colour = path.get("Local Color")
        where = f"{kind.lower()}" if isinstance(kind, str) else "?"
        if colour:
            where += f" via {str(colour).lower()}"
        out.append(f"{d['device_name']}: {d.get('up_fwd_decision', '?')} -> {where}")
    return out


def flow_row(entry: dict[str, Any]) -> dict[str, Any]:
    """One finalised flow in plain words: who to whom, the hops each way, drops with their causes, the
    forwarding decision per edge, the policies that matched and what went wrong."""
    f = _dict(entry.get("data")) or entry
    up = [hop_row(h) for h in _as_list(f.get("upstream_hop_list")) if isinstance(h, dict)]
    down = [hop_row(h) for h in _as_list(f.get("downstream_hop_list")) if isinstance(h, dict)]
    up = [h for h in up if h.get("from") or h.get("to")]
    down = [h for h in down if h.get("from") or h.get("to")]
    issues = [text for key, text in FLAGS.items() if f.get(key) is True]
    drops = [h for h in up + down if h.get("drop_causes") or h.get("local_drop_pct") or h.get("wan_drop_pct")]

    def path_text(hops: list[dict[str, Any]]) -> str | None:
        return "; ".join(f"{h.get('from')} -> {h.get('to')} ({h.get('colour') or '?'})" for h in hops) or None

    row = {
        "flow": f"{f.get('src_ip')}:{f.get('src_port')} -> {f.get('dst_ip')}:{f.get('dst_port')} "
        f"{f.get('protocol') or ''}".strip(),
        "flow_id": f.get("flow_id"),
        "vpn": f.get("vpn_id"),
        "app": _v(f.get("app_name")),
        "domain": _v(f.get("domain_name")),
        "upstream": path_text(up),
        "downstream": path_text(down),
        "decisions": _decisions(_as_list(f.get("upstream_device_list"))) or None,
        "policies": [str(p) for p in _as_list(f.get("policy_keys"))] or None,
        "drops": [
            f"{h.get('from')} -> {h.get('to')}: "
            + ", ".join(
                x
                for x in (
                    f"local {h['local_drop_pct']}%" if h.get("local_drop_pct") else "",
                    f"WAN {h['wan_drop_pct']}%" if h.get("wan_drop_pct") else "",
                    h.get("drop_causes") or "",
                )
                if x
            )
            for h in drops
        ]
        or None,
        "issues": issues or None,
        "upstream_hops": up or None,
        "downstream_hops": down or None,
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def flows_of(body: Any) -> list[dict[str, Any]]:
    data = body.get("data") if isinstance(body, dict) else body
    return [r for r in _as_list(data) if isinstance(r, dict) and (r.get("type") in (None, "hops-of-flow"))]


def flow_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    with_drops = sum(1 for r in rows if r.get("drops"))
    with_issues = sum(1 for r in rows if r.get("issues"))
    colours: dict[str, int] = {}
    for r in rows:
        for h in r.get("upstream_hops", []):
            if h.get("encap") and (c := h.get("colour")):  # tunnel hops only, not the LAN side
                colours[c] = colours.get(c, 0) + 1
    return {
        "flows": len(rows),
        "with_drops": with_drops,
        "with_issues": with_issues,
        "upstream_colours": colours,
    }


def sort_flows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flows with drops first, then with issues, then by flow id."""
    return sorted(rows, key=lambda r: (not r.get("drops"), not r.get("issues"), r.get("flow_id") or 0))
