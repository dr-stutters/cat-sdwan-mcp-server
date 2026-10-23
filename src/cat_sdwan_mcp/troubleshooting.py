"""On-box troubleshooting (W17): pure helpers; the tools are in tools/troubleshooting.py.

The Manager runs these on the edge over its control connection (the Manager's 'Troubleshooting' screens).
Request bodies are the ones the Manager's own web UI sends (read from its 20.18.3 bundle, modules/monitor):
- POST /dataservice/device/tools/ping/{deviceIP} {host, vpn, source, count, size, rapid} and
  /nping/{deviceIP} with probeType (icmp, tcp, udp), destPort, sourcePort, tos, ttl, df, mtu; every value a
  string, empty ones left out. Answer (spec): {packetsTransmitted, packetsReceived, lossPercentage,
  minRoundTrip, avgRoundTrip, maxRoundTrip, rawOutput: [lines]}.
- POST /device/tools/traceroute/{deviceIP} {deviceIp, vpn, host, interface, interfaceIP, size}. Answer
  (spec): {nexthops: [{hopNumber, ipAddress, hopName, meanLatency, errorInfo}], rawOutput}.
- POST /device/tools/servicepath/{deviceIP} and /tunnelpath/{deviceIP} ('Simulate Flows') {deviceIp, vpn,
  interface, sourceIp, destIp, protocol, all, sourcePort, destPort, dscp, app}. Answer (the UI's template):
  {status, nexthops: [{type: nh-ipsec | nh-gre | nh-direct | nh-local | nh-remote | nh-blackhole | ...,
  sourceIp, destIp, localColor, remoteColor, remoteSystemIp, interface}], aar-policy, data-policy,
  exceptions: [{exception}], policy-drop-reason}.
- GET /dataservice/troubleshooting/devicebringup?uuid=<chassis> (recorded): {data: [{name, operation:
  vBondAuth | ControlPlane | RouterConfiguration | SoftwareImageUpdate | DataPlane, status: Success | Error |
  NA | Unknown, message: text or [text], timestamp}]}.
- GET /troubleshooting/control/{uuid} (recorded): per WAN colour the expected and actual control
  connections and each peer's local and remote status; 400 TBST1007 for a device without a system IP.
- POST /device/tools/admintech {deviceIP, device-type, exclude-cores, exclude-tech, exclude-logs}; GET
  /device/tools/admintechs (recorded: {data: []}; spec: creationTime, deviceIP, fileName, requestTokenId,
  size, state, tac_state), /admintechs/inprogress ({data: [{inProgressCount}]}, recorded) and
  /admintech/download/{fileName}.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from cat_sdwan_mcp.client import _as_list

PING_PATH = "/dataservice/device/tools/ping/{ip}"
NPING_PATH = "/dataservice/device/tools/nping/{ip}"
TRACEROUTE_PATH = "/dataservice/device/tools/traceroute/{ip}"
SERVICEPATH_PATH = "/dataservice/device/tools/servicepath/{ip}"
TUNNELPATH_PATH = "/dataservice/device/tools/tunnelpath/{ip}"
BRINGUP_PATH = "/dataservice/troubleshooting/devicebringup"
CONTROL_TS_PATH = "/dataservice/troubleshooting/control/{uuid}"
ADMINTECH_PATH = "/dataservice/device/tools/admintech"
ADMINTECHS_PATH = "/dataservice/device/tools/admintechs"
ADMINTECH_PROGRESS_PATH = "/dataservice/device/tools/admintechs/inprogress"
ADMINTECH_DOWNLOAD_PATH = "/dataservice/device/tools/admintech/download/{file}"

PROTOCOLS = {"icmp": "1", "tcp": "6", "udp": "17"}
TOOL_TIMEOUT = 180.0  # seconds; the Manager's UI allows 600 for these, a 5-probe ping takes a few

# The Manager's bring-up checklist in the order an edge goes through it.
BRINGUP_ORDER = ["vBondAuth", "ControlPlane", "RouterConfiguration", "SoftwareImageUpdate", "DataPlane"]
BRINGUP_HINT = {
    "vBondAuth": "the validator has not authorised it: check the WAN edge list (catsdwan_list_wan_edges), "
    "its validity, the org name and the validator address in its bootstrap",
    "ControlPlane": "no control connection to the controllers: catsdwan_control_connections(device) names "
    "the failed attempts",
    "RouterConfiguration": "the Manager has not configured it: deploy its configuration group or attach its "
    "template",
    "SoftwareImageUpdate": "a software update did not finish",
    "DataPlane": "no BFD sessions: check its TLOCs and colours (catsdwan_bfd_sessions, catsdwan_list_tlocs)",
}


def path(template: str, **kw: str) -> str:
    return template.format(**{k: quote(str(v), safe="") for k, v in kw.items()})


def strings(body: dict[str, Any]) -> dict[str, str]:
    """The UI's body shape: every value a string, None/empty/False left out."""
    out = {}
    for k, v in body.items():
        if v is None or v is False or (isinstance(v, str) and not v.strip()):
            continue
        out[k] = ("true" if v else "false") if isinstance(v, bool) else str(v)
    return out


def ping_body(
    destination: str,
    vpn: int,
    *,
    source: str | None,
    count: int,
    size: int | None,
    rapid: bool,
    probe: str,
    dest_port: int | None,
) -> dict[str, str]:
    body: dict[str, Any] = {
        "host": destination,
        "vpn": vpn,
        "source": source,
        "count": count,
        "size": size,
        "rapid": rapid,
    }
    if probe != "icmp":
        body.update(probeType=probe, destPort=dest_port)
    return strings(body)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def raw_lines(body: Any, keep: int = 40) -> list[str]:
    lines = body.get("rawOutput") if isinstance(body, dict) else None
    out = [str(x).rstrip() for x in _as_list(lines) if str(x).strip()]
    return out[-keep:]


def ping_result(body: Any, destination: str) -> dict[str, Any]:
    b = body if isinstance(body, dict) else {}
    sent, got = _num(b.get("packetsTransmitted")), _num(b.get("packetsReceived"))
    loss = _num(b.get("lossPercentage"))
    if loss is None and sent:
        loss = round(100 * (1 - (got or 0) / sent), 1)
    if sent is None and got is None:
        verdict = "no result: see raw_output"
    elif got:
        verdict = f"{destination} answered ({int(got)}/{int(sent or 0)}, {loss or 0:g}% loss)"
    else:
        verdict = f"{destination} did not answer (100% loss)"
    out = {
        "verdict": verdict,
        "sent": int(sent) if sent is not None else None,
        "received": int(got) if got is not None else None,
        "loss_percent": loss,
        "rtt_ms": {k: _num(b.get(f"{k}RoundTrip")) for k in ("min", "avg", "max")}
        if b.get("avgRoundTrip") is not None
        else None,
        "raw_output": raw_lines(b),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def traceroute_result(body: Any, destination: str) -> dict[str, Any]:
    b = body if isinstance(body, dict) else {}
    hops = []
    for h in _as_list(b.get("nexthops")):
        if not isinstance(h, dict):
            continue
        row = {
            "hop": h.get("hopNumber"),
            "address": h.get("ipAddress"),
            "name": h.get("hopName") if h.get("hopName") != h.get("ipAddress") else None,
            "latency_ms": _num(h.get("meanLatency")),
            "error": h.get("errorInfo"),
        }
        hops.append({k: v for k, v in row.items() if v not in (None, "")})
    reached = any(h.get("address") == destination for h in hops)
    if hops:
        last = hops[-1]
        verdict = (
            f"reached {destination} in {len(hops)} hops"
            if reached
            else f"did not reach {destination}: last answer from {last.get('address') or '*'} at hop "
            f"{last.get('hop')}" + (f" ({last['error']})" if last.get("error") else "")
        )
    else:
        verdict = "no hops returned: see raw_output"
    out = {"verdict": verdict, "reached": reached, "hops": hops, "raw_output": raw_lines(b)}
    return {k: v for k, v in out.items() if v not in (None, [])}


def flow_body(
    device_ip: str,
    *,
    vpn: int,
    interface: str | None,
    source_ip: str,
    destination: str,
    protocol: str,
    source_port: int | None,
    dest_port: int | None,
    dscp: int | None,
    app: str | None,
    all_paths: bool,
) -> dict[str, str]:
    return strings(
        {
            "deviceIp": device_ip,
            "vpn": vpn,
            "interface": interface,
            "sourceIp": source_ip,
            "destIp": destination,
            "protocol": PROTOCOLS.get(protocol.lower(), protocol),
            "all": all_paths,
            "sourcePort": source_port,
            "destPort": dest_port,
            "dscp": dscp,
            "app": app,
        }
    )


def _hop_type(t: Any) -> str:
    return str(t or "").removeprefix("nh-").lower()


def flow_result(body: Any, hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """Next hops (tunnel: colours and the remote edge; direct, local, blackhole) and the policies that
    decided, in plain words."""
    b = body if isinstance(body, dict) else {}
    hosts = hosts or {}
    hops = []
    for h in _as_list(b.get("nexthops")):
        if not isinstance(h, dict):
            continue
        kind = _hop_type(h.get("type"))
        remote = h.get("remoteSystemIp")
        row = {
            "type": kind,
            "local_colour": h.get("localColor"),
            "remote_colour": h.get("remoteColor"),
            "remote_edge": hosts.get(str(remote), remote) if remote else None,
            "remote_system_ip": remote,
            "source": h.get("sourceIp"),
            "destination": h.get("destIp"),
            "interface": h.get("interface"),
        }
        hops.append({k: v for k, v in row.items() if v not in (None, "")})
    policies = []
    for label, key in (("app-route", "aar-policy"), ("data", "data-policy")):
        p = b.get(key)
        for item in _as_list(p) if isinstance(p, list) else ([p] if isinstance(p, dict) and p else []):
            if isinstance(item, dict):
                policies.append({"kind": label, **{k: v for k, v in item.items() if v not in (None, "", [])}})
    drop = b.get("policy-drop-reason")
    exceptions = [
        str(e.get("exception") if isinstance(e, dict) else e) for e in _as_list(b.get("exceptions")) if e
    ]
    tunnels = [h for h in hops if h["type"] in ("ipsec", "gre")]
    if drop:
        verdict = f"dropped by policy: {drop}"
    elif any(h["type"] == "blackhole" for h in hops):
        verdict = "blackholed: no route for this flow"
    elif tunnels:
        picks = sorted(
            {
                f"{h.get('local_colour')} -> {h.get('remote_edge') or '?'} ({h.get('remote_colour')})"
                for h in tunnels
            }
        )
        verdict = f"{len(tunnels)} tunnel path(s): " + "; ".join(picks)
    elif hops:
        verdict = ", ".join(sorted({h["type"] for h in hops})) + " next hop: not through the overlay"
    else:
        verdict = "no next hop returned"
    out: dict[str, Any] = {"verdict": verdict, "next_hops": hops}
    if policies:
        out["policies"] = policies
    if drop:
        out["drop_reason"] = drop
    if exceptions:
        out["exceptions"] = exceptions
    if b.get("status") and b.get("status") != "success":
        out["status"] = b.get("status")
    return out


def _message(m: Any) -> str | None:
    parts = [str(x).strip() for x in _as_list(m) if str(x).strip()]
    text = " | ".join(re.sub(r"^\[[^\]]*\]\s*", "", p) for p in parts)
    return text or None


def bringup_steps(body: Any) -> tuple[list[dict[str, Any]], str]:
    """The Manager's checklist in bring-up order and a verdict naming the first failing step."""
    data = body.get("data") if isinstance(body, dict) else body
    rows = [r for r in _as_list(data) if isinstance(r, dict)]
    order = {op: i for i, op in enumerate(BRINGUP_ORDER)}
    rows.sort(key=lambda r: order.get(str(r.get("operation")), 99))
    steps = []
    for r in rows:
        status = str(r.get("status") or "Unknown")
        row = {
            "step": r.get("name"),
            "operation": r.get("operation"),
            "status": status.lower(),
            "detail": _message(r.get("message")),
        }
        steps.append({k: v for k, v in row.items() if v not in (None, "")})
    failing = next((s for s in steps if s["status"] in ("error", "unknown")), None)
    if not steps:
        verdict = "the Manager returned no bring-up checklist"
    elif failing is None:
        verdict = "every bring-up step succeeded"
    else:
        hint = BRINGUP_HINT.get(str(failing.get("operation")), "")
        verdict = (
            f"stuck at '{failing.get('step')}' ({failing['status']}"
            + (f": {failing['detail']}" if failing.get("detail") else "")
            + ")"
            + (f"; {hint}" if hint else "")
        )
    return steps, verdict


def control_check(body: Any) -> dict[str, Any]:
    """/troubleshooting/control/{uuid}: per colour the expected and actual control connections and the peers
    whose status is not green."""
    b = body if isinstance(body, dict) else {}
    colours = []
    for c in _as_list(b.get("data")):
        if not isinstance(c, dict):
            continue
        peers = [p for p in _as_list(c.get("control")) if isinstance(p, dict)]
        bad = [
            {
                k: v
                for k, v in {
                    "peer": p.get("host-name") or p.get("system-ip"),
                    "type": p.get("peer-type"),
                    "state": p.get("state"),
                    "local": p.get("local-status-info") or p.get("local-status"),
                    "remote": p.get("remote-status-info") or p.get("remote-status"),
                }.items()
                if v not in (None, "")
            }
            for p in peers
            if p.get("state") != "up" or "red" in (p.get("local-status"), p.get("remote-status"))
        ]
        row = {
            "colour": str(c.get("color") or "").lower() or None,
            "interface": c.get("interface"),
            "public": f"{c.get('public-ip')}:{c.get('public-port')}" if c.get("public-ip") else None,
            "nat": c.get("nat-type"),
            "connections": f"{c.get('actual-connections')}/{c.get('expected-connections')}",
            "status": c.get("tloc-status"),
            "peers": ", ".join(
                f"{p.get('host-name')} ({p.get('peer-type')}) {p.get('state')}" for p in peers
            ),
            "problems": bad,
        }
        colours.append({k: v for k, v in row.items() if v not in (None, "", [])})
    return {"colours": colours}


def admintech_rows(body: Any, device_ip: str | None = None) -> list[dict[str, Any]]:
    from cat_sdwan_mcp.inventory import iso

    data = body.get("data") if isinstance(body, dict) else body
    out = []
    for r in _as_list(data):
        if not isinstance(r, dict):
            continue
        ip = r.get("deviceIP") or r.get("local-system-ip")
        if device_ip and ip != device_ip:
            continue
        name = str(r.get("fileName") or "")
        row = {
            "file": name.rsplit("/", 1)[-1] or None,
            "device_ip": ip,
            "created": iso(r.get("creationTime")),
            "size_bytes": r.get("size"),
            "state": r.get("state"),
            "request_id": r.get("requestTokenId"),
            "download": path(ADMINTECH_DOWNLOAD_PATH, file=name.rsplit("/", 1)[-1]) if name else None,
        }
        out.append({k: v for k, v in row.items() if v not in (None, "")})
    out.sort(key=lambda r: str(r.get("created") or ""), reverse=True)
    return out


def in_progress(body: Any) -> int:
    data = body.get("data") if isinstance(body, dict) else body
    for r in _as_list(data):
        if isinstance(r, dict) and r.get("inProgressCount") is not None:
            try:
                return int(r["inProgressCount"])
            except (TypeError, ValueError):
                return 0
    if isinstance(body, dict) and body.get("inProgressCount") is not None:
        return int(body["inProgressCount"])
    return 0
