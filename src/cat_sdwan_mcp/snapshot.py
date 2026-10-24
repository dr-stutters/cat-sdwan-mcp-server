"""Snapshot sections (W46, core snapshot contract C53): the overlay's health as compact, stable items.

Each function fills one section of a core `Snapshot` from rows the existing reads already shape
(control.connection_row, dataplane.bfd_row, control.peer_row, the raw app-route statistics and alarms, and the
inventory rows). Keys are built from names (host, colour, peer), never from ids or timestamps, and every
volatile value (uptime, transitions, counters, entry times) is left out, so two snapshots of an unchanged
fabric compare as "No change".

Sources (recorded on 20.18.3.1):
- control: GET /dataservice/device/control/connections?deviceId= per device (a site), or the bulk state
  database ControlConnection (the fabric).
- bfd: GET /dataservice/device/bfd/sessions?deviceId= per edge (a site), or the bulk BFDSessions.
- omp: GET /dataservice/device/omp/peers?deviceId=: on an edge one row per controller (`peer`, `type`
  vsmart, `state`; no route counts on 20.18 C8000V), on a controller one row per edge and controller.
- app_route_sla: POST /dataservice/statistics/approute, the last hour, newest 10-minute row per tunnel
  (`state` Up/Down, `loss_percentage`, `latency`, `jitter`, `sla_class_names`), and the SLA classes from
  GET /dataservice/template/policy/list/sla (only classes an app-route policy references are checked).
- alarms: POST /dataservice/alarms with `active` = true over 7 days (the rule is honoured on 20.18.3.1).
- devices: the inventory (reachability, version, certificate, configuration sync state).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cat_sdwan_mcp._core.snapshot import Metric, Section
from cat_sdwan_mcp.dataplane import ALL_TUNNELS
from cat_sdwan_mcp.events import SEVERITY_RANK, alarm_ips, alarm_sites, alarm_state

# Noise floors: a tunnel's loss within 1 point, latency within 20 ms and jitter within 10 ms of before is
# the same tunnel. The SLA class limits decide `ok`; these only report drift.
APPROUTE_METRICS = {
    "loss_pct": Metric("lower", 1),
    "latency_ms": Metric("lower", 20),
    "jitter_ms": Metric("lower", 10),
}
OMP_METRICS = {"routes_received": Metric("higher", 0)}
ALARM_METRICS = {"count": Metric("lower", 0)}
STALE_MS = 30 * 60 * 1000  # a tunnel whose newest statistics row is this much older than the newest is gone
UNHEALTHY_ALARMS = ("critical", "major")  # active alarms of these severities are ok: false
ALARM_DETAIL_KEYS = ("color", "local-color", "remote-color", "remote-system-ip", "if-name", "interface")


def add(sec: Section, key: str, **fields: Any) -> None:
    """Add an item; a second item with the same key gets '#2', '#3', ... (several instances of one peer)."""
    key = key[:190]
    unique, n = key, 1
    while unique in sec.items:
        n += 1
        unique = f"{key}#{n}"
    sec.item(unique, **fields)


def _name(row: dict[str, Any], name_key: str, ip_key: str) -> str:
    return str(row.get(name_key) or row.get(ip_key) or "?")


def _up(v: Any) -> bool:
    return str(v or "").strip().lower() == "up"


def _sorted(rows: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    """Rows in a fixed order, so duplicate keys get the same '#n' suffix in every snapshot."""
    return sorted(rows, key=lambda r: tuple(str(r.get(k) or "") for k in keys))


# --- control connections -------------------------------------------------------------------------


def control_items(sec: Section, rows: list[dict[str, Any]]) -> None:
    """control.connection_row rows: one item per device, local colour and peer."""
    for r in _sorted(rows, "host", "system_ip", "local_colour", "peer", "peer_system_ip", "remote_colour"):
        key = "|".join(
            (
                _name(r, "host", "system_ip"),
                str(r.get("local_colour") or "-"),
                _name(r, "peer", "peer_system_ip"),
            )
        )
        add(
            sec,
            key,
            ok=_up(r.get("state")),
            state=r.get("state"),
            peer_type=r.get("peer_type"),
            remote_colour=r.get("remote_colour"),
            protocol=r.get("protocol"),
        )


# --- BFD -----------------------------------------------------------------------------------------


def tunnel_key(host: Any, local_colour: Any, remote: Any, remote_colour: Any) -> str:
    return "|".join(str(x or "-") for x in (host, local_colour, remote, remote_colour))


def bfd_items(sec: Section, rows: list[dict[str, Any]]) -> None:
    """dataplane.bfd_row rows: one item per tunnel (local edge and colour, remote edge and colour)."""
    for r in _sorted(
        rows, "host", "system_ip", "local_colour", "remote", "remote_system_ip", "remote_colour"
    ):
        key = tunnel_key(
            _name(r, "host", "system_ip"),
            r.get("local_colour"),
            _name(r, "remote", "remote_system_ip"),
            r.get("remote_colour"),
        )
        add(sec, key, ok=_up(r.get("state")), state=r.get("state"), encap=r.get("encap"))


# --- OMP -----------------------------------------------------------------------------------------


def _int(v: Any) -> int | None:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def omp_items(sec: Section, rows: list[dict[str, Any]]) -> None:
    """control.peer_row rows: one item per device and OMP peer; routes received as a metric where the
    device reports it."""
    for r in _sorted(rows, "host", "peer"):
        key = f"{r.get('host') or '?'}|{r.get('peer_host') or r.get('peer') or '?'}"
        add(
            sec,
            key,
            ok=_up(r.get("state")),
            state=r.get("state"),
            peer_type=r.get("peer_type"),
            routes_received=_int(r.get("routes_received")),
        )


# --- app-route SLA -------------------------------------------------------------------------------


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def newest_per_tunnel(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The newest statistics row of every tunnel, without tunnels that stopped reporting (their newest row
    is more than STALE_MS older than the newest row of all)."""
    newest: dict[tuple[str, ...], dict[str, Any]] = {}
    for r in rows:
        key = tuple(
            str(r.get(k)) for k in ("vdevice_name", "local_color", "remote_system_ip", "remote_color")
        )
        if key not in newest or (_num(r.get("entry_time")) or 0) > (_num(newest[key].get("entry_time")) or 0):
            newest[key] = r
    if not newest:
        return []
    latest = max(_num(r.get("entry_time")) or 0 for r in newest.values())
    return [r for r in newest.values() if latest - (_num(r.get("entry_time")) or 0) <= STALE_MS]


def sla_misses(row: dict[str, Any], classes: list[dict[str, Any]]) -> list[str]:
    """Names of the SLA classes (sla_rows shape) whose loss, latency or jitter limit the tunnel exceeds."""
    values = {
        "loss": _num(row.get("loss_percentage")),
        "latency": _num(row.get("latency")),
        "jitter": _num(row.get("jitter")),
    }
    out = []
    for c in classes:
        for metric, value in values.items():
            limit = c.get(f"{metric}_max")
            if isinstance(limit, int | float) and value is not None and value > limit:
                out.append(str(c.get("name")))
                break
    return sorted(out)


def approute_items(
    sec: Section, rows: list[dict[str, Any]], hosts: dict[str, str], classes: list[dict[str, Any]] | None
) -> None:
    """Raw app-route statistics rows: one item per tunnel from its newest row. `ok`: the tunnel is up and
    meets every SLA class an app-route policy references (`classes`, sla_rows shape; None = not read)."""
    in_use = [c for c in classes or [] if c.get("app_route_policies")]
    keyed: list[tuple[str, dict[str, Any]]] = []
    for r in newest_per_tunnel(rows):
        local = str(r.get("vdevice_name") or r.get("local_system_ip"))
        remote = str(r.get("remote_system_ip"))
        key = tunnel_key(
            r.get("host_name") or hosts.get(local) or local,
            r.get("local_color"),
            hosts.get(remote) or remote,
            r.get("remote_color"),
        )
        keyed.append((key, r))
    for key, r in sorted(keyed, key=lambda kr: kr[0]):
        state = r.get("state")
        missed = sla_misses(r, in_use)
        met = sorted(c for c in str(r.get("sla_class_names") or "").split(",") if c and c != ALL_TUNNELS)
        add(
            sec,
            key,
            ok=(_up(state) if state is not None else True) and not missed,
            state=state,
            loss_pct=_num(r.get("loss_percentage")),
            latency_ms=_num(r.get("latency")),
            jitter_ms=_num(r.get("jitter")),
            sla_met=",".join(met) or None,
            sla_missed=",".join(missed) or None,
        )


# --- alarms --------------------------------------------------------------------------------------


def alarm_in_scope(a: dict[str, Any], ips: set[str] | None, sites: set[str], names: set[str]) -> bool:
    """`ips` None = the whole fabric."""
    if ips is None:
        return True
    hosts = {str(v.get("host-name")) for v in a.get("values") or [] if isinstance(v, dict)}
    hosts.add(str(a.get("host_name") or ""))
    return bool(alarm_ips(a) & ips or alarm_sites(a) & sites or hosts & names)


def alarm_key(a: dict[str, Any]) -> str:
    """'<device>|<alarm type>[|<colour, interface or remote>]'."""
    values = [v for v in a.get("values") or [] if isinstance(v, dict)]
    first = values[0] if values else {}
    device = (
        a.get("host_name") or first.get("host-name") or a.get("system_ip") or first.get("system-ip") or "?"
    )
    detail = [str(first[k]) for k in ALARM_DETAIL_KEYS if first.get(k) not in (None, "")]
    return "|".join([str(device), str(a.get("type") or a.get("rulename") or "?"), *detail])


def alarm_items(sec: Section, alarms: list[dict[str, Any]]) -> None:
    """Active alarms grouped by device, type and detail: the worst severity as `state`, how many as `count`.
    Critical and major alarms are unhealthy (`ok: false`); medium and minor ones carry no `ok`."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in alarms:
        if alarm_state(a) == "active":
            groups[alarm_key(a)].append(a)
    for key in sorted(groups):
        group = groups[key]
        worst = min(
            (str(a.get("severity") or "").lower() for a in group), key=lambda s: SEVERITY_RANK.get(s, 9)
        )
        sec.item(
            key[:200],
            ok=False if worst in UNHEALTHY_ALARMS else None,
            state=worst or None,
            alarm=str(group[0].get("rule_name_display") or group[0].get("type") or ""),
            count=len(group),
        )


# --- devices -------------------------------------------------------------------------------------


def device_items(sec: Section, rows: list[dict[str, Any]]) -> None:
    """Inventory rows: reachability (`ok`), role, version, certificate and configuration sync state."""
    for r in _sorted(rows, "host", "chassis"):
        add(
            sec,
            str(r.get("host") or r.get("chassis") or r.get("system_ip") or "?"),
            ok=str(r.get("reachability", "")).lower() == "reachable",
            state=r.get("reachability"),
            role=r.get("role"),
            site_id=str(r["site_id"]) if r.get("site_id") not in (None, "") else None,
            version=r.get("version"),
            certificate=r.get("certificate"),
            config_status=r.get("config_status"),
        )
