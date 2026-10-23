"""W4 data plane and application-aware routing: catsdwan_bfd_sessions, catsdwan_tunnel_stats,
catsdwan_app_route_stats, catsdwan_list_sla_classes."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, _as_list, last_hours, rule
from cat_sdwan_mcp.dataplane import (
    APPROUTE_DEF_PATH,
    APPROUTE_RT_PATH,
    APPROUTE_STATS_PATH,
    BFD_SESSIONS_PATH,
    BFD_SUMMARY_PATH,
    BULK_BFD,
    SLA_LIST_PATH,
    TUNNEL_PATH,
    VSMART_POLICY_PATH,
    aggregate_approute,
    aggregate_realtime,
    bfd_row,
    bfd_summary,
    colour_matches,
    colour_pairs,
    is_up,
    remote_matches,
    sla_rows,
    sla_verdict,
    sort_sessions,
    sort_worst,
    tunnel_row,
)
from cat_sdwan_mcp.fabric import (
    device_rows,
    fan_out,
    find_device,
    host_map,
    reachable,
    require_reachable,
    safely,
    site_ips,
)
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve

Device = Annotated[str, Field(description="Host name, system IP, chassis number or serial number")]
Colour = Annotated[
    str | None, Field(description="Only tunnels with this colour at either end, e.g. 'mpls', 'biz-internet'")
]
Remote = Annotated[str | None, Field(description="Only tunnels to this edge (host name or system IP)")]
BULK_CAP = 5000
STATS_CAP = 10000  # statistics rows read per call (about 1600 tunnels for one hour)

BFD_COLUMNS = ["host", "local_colour", "remote", "remote_colour", "state", "uptime", "transitions"]
TUNNEL_COLUMNS = [
    "host",
    "local_colour",
    "remote",
    "remote_colour",
    "tx_packets",
    "rx_packets",
    "tx_bytes",
    "rx_bytes",
]
APPROUTE_COLUMNS = [
    "host",
    "local_colour",
    "remote",
    "remote_colour",
    "loss_percent",
    "latency_ms",
    "jitter_ms",
    "latency_max",
    "samples",
    "sla_classes",
]
SLA_COLUMNS = [
    "name",
    "loss_max",
    "latency_max",
    "jitter_max",
    "default",
    "app_route_policies",
    "centralized_policies",
]


def _remote_ip(inv: Inventory, remote: str | None) -> str | None:
    """The remote edge's system IP (host name, system IP, chassis or serial); None when not given."""
    if not remote:
        return None
    row = resolve(inv, remote)
    if not row.get("system_ip"):
        raise InvalidRequest(f"{remote!r} has not joined the fabric (no system IP): it has no tunnels.")
    return str(row["system_ip"])


def _rows(data: Any) -> list[dict[str, Any]]:
    return [r for r in _as_list(data) if isinstance(r, dict)]


async def _sla_classes(app: SdwanApp) -> tuple[list[dict[str, Any]], list[str]]:
    """The SLA classes with the policies that use them; the two optional policy reads may fail."""
    lists, defs, policies = await asyncio.gather(
        app.get_data(SLA_LIST_PATH),
        safely(app.get_data(APPROUTE_DEF_PATH), f"GET {APPROUTE_DEF_PATH}"),
        safely(app.get_data(VSMART_POLICY_PATH), f"GET {VSMART_POLICY_PATH}"),
    )
    warnings = [str(x["error"]) for x in (defs, policies) if isinstance(x, dict) and "error" in x]
    defs_rows = None if isinstance(defs, dict) and "error" in defs else _rows(defs)
    pol_rows = None if isinstance(policies, dict) and "error" in policies else _rows(policies)
    return sla_rows(_rows(lists), defs_rows, pol_rows), warnings


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN BFD sessions")
    async def catsdwan_bfd_sessions(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Host name, system IP, chassis or serial; omit for every edge"),
        ] = None,
        state: Annotated[
            Literal["up", "down", "not_up"] | None, Field(description="Only sessions in this state")
        ] = None,
        colour: Colour = None,
        remote: Remote = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """BFD sessions (one per IPsec/GRE tunnel between two TLOCs): local and remote colour, remote edge
        and system IP, site, state, uptime, transitions (flaps), source and destination, hello interval and
        multiplier. Down sessions first; `by_colour_pair` shows 'mpls -> mpls: 3/4 up' at a glance. With a
        device, read live from it plus its BFD summary (total, up, flaps); without one, every edge from the
        Manager's state database (or each reachable edge live when that API is missing)."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        extra: dict[str, Any] = {}
        if device:
            row = resolve(inv, device)
            ip = require_reachable(row)
            raw, summary = await asyncio.gather(
                device_rows(app, BFD_SESSIONS_PATH, ip),
                safely(device_rows(app, BFD_SUMMARY_PATH, ip), f"GET {BFD_SUMMARY_PATH}"),
            )
            extra["device"] = row.get("host")
            extra["source"] = f"GET {BFD_SESSIONS_PATH} (live)"
            if isinstance(summary, dict):
                extra["summary"] = summary
            elif shaped := bfd_summary(summary):
                extra["summary"] = shaped
        else:
            try:
                raw, more = await app.bulk_state(BULK_BFD, limit=BULK_CAP)
                extra["source"] = f"the Manager's state database (bulk {BULK_BFD})"
                if more:
                    extra["partial"] = f"the first {BULK_CAP} sessions only; name a device for the rest"
            except UpstreamError as e:
                edges = reachable(inv, "edge")
                got = await fan_out(edges, lambda d: device_rows(app, BFD_SESSIONS_PATH, str(d["system_ip"])))
                raw = [b for res in got if not isinstance(res, UpstreamError) for b in res]
                failed = [
                    str(d.get("host"))
                    for d, res in zip(edges, got, strict=True)
                    if isinstance(res, UpstreamError)
                ]
                extra["source"] = (
                    f"live from the {len(edges)} reachable edge(s): bulk state API failed ({str(e)[:140]})"
                )
                if failed:
                    extra["not_read"] = failed
            down = [
                str(r.get("host"))
                for r in inv.rows
                if r.get("role") == "edge" and str(r.get("reachability", "")).lower() != "reachable"
            ]
            if down:  # the state database keeps their last sessions; say they are gone
                extra["unreachable_edges"] = down
        rows = [bfd_row(b, hosts) for b in raw]
        rows = [r for r in rows if colour_matches(r, colour) and remote_matches(r, remote)]
        extra["by_state"] = dict(sorted(Counter(str(r.get("state")) for r in rows).items()))
        extra["by_colour_pair"] = colour_pairs(rows)
        if state == "not_up":
            rows = [r for r in rows if not is_up(r)]
        elif state:
            rows = [r for r in rows if str(r.get("state", "")).lower() == state]
        return list_result(
            page_of(sort_sessions(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=BFD_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN tunnel statistics")
    async def catsdwan_tunnel_stats(
        ctx: Context,
        device: Device,
        remote: Remote = None,
        colour: Colour = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Data-plane tunnel counters on one edge, read live: per tunnel the local and remote colour,
        remote edge, protocol (ipsec/gre), source and destination, packets and bytes sent and received
        (counters since the tunnel came up), MTU and TCP MSS. A tunnel that sends but has never received is
        named in `no_packets_received`. For loss, latency and jitter use catsdwan_app_route_stats; for up/down
        catsdwan_bfd_sessions."""
        app: SdwanApp = get_client(ctx)
        row, inv = await find_device(app, device)
        ip = require_reachable(row)
        hosts = host_map(inv)
        rows = [tunnel_row(t, hosts) for t in await device_rows(app, TUNNEL_PATH, ip)]
        rows = [r for r in rows if colour_matches(r, colour) and remote_matches(r, remote)]
        rows.sort(
            key=lambda r: (
                str(r.get("remote") or r.get("remote_system_ip")),
                str(r.get("local_colour")),
                str(r.get("remote_colour")),
            )
        )
        extra: dict[str, Any] = {
            "device": row.get("host"),
            "source": f"GET {TUNNEL_PATH} (live, counters since tunnel up)",
        }
        one_way = [
            f"{r.get('local_colour')} -> {r.get('remote') or r.get('remote_system_ip')} "
            f"{r.get('remote_colour')}"
            for r in rows
            if (r.get("tx_packets") or 0) > 0 and not r.get("rx_packets")
        ]
        if one_way:
            extra["no_packets_received"] = one_way
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=TUNNEL_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN app-route statistics")
    async def catsdwan_app_route_stats(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Only tunnels from this edge (host name, system IP, chassis or serial)"),
        ] = None,
        site: Annotated[
            str | None, Field(description="Only tunnels from the edges of this site (id or name)")
        ] = None,
        remote: Remote = None,
        colour: Annotated[
            str | None, Field(description="Only tunnels leaving on this local colour, e.g. 'biz-internet'")
        ] = None,
        window_hours: Annotated[
            int,
            Field(
                ge=1,
                le=24,
                description="Statistics window in hours (statistics source; longer windows: later)",
            ),
        ] = 1,
        sla_class: Annotated[
            str | None,
            Field(
                description="Check every tunnel against this SLA class (name, see catsdwan_list_sla_classes)"
            ),
        ] = None,
        source: Annotated[
            Literal["statistics", "realtime"],
            Field(
                description="statistics: the Manager's 10-minute app-route statistics over the window; "
                "realtime: the device's own current probe buckets (needs a device; no 10-minute lag)"
            ),
        ] = "statistics",
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Application-aware routing quality per tunnel: loss %, latency and jitter (average, min, max over
        the window, from the Manager's app-route statistics), samples, state and the SLA classes the
        Manager says the tunnel met, worst tunnels first. `sla_class` adds a verdict per tunnel ('meets', or
        'misses: latency 320 ms > 150 ms'). Filters: device or site (the local end), remote edge, local
        colour. Statistics arrive every 10 minutes; source='realtime' reads the device's own probe buckets
        now. Use it for 'which tunnels are lossy?' and 'is the voice SLA met on each transport?'."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        if device and site:
            raise InvalidRequest("Give device or site, not both.")
        extra: dict[str, Any] = {}
        remote_ip = _remote_ip(inv, remote)
        sla: dict[str, Any] | None = None
        if sla_class:
            classes, _ = await _sla_classes(app)
            sla = next(
                (c for c in classes if str(c.get("name", "")).lower() == sla_class.strip().lower()), None
            )
            if sla is None:
                names = ", ".join(str(c.get("name")) for c in classes)
                raise NotFound(f"No SLA class {sla_class!r}. SLA classes: {names or 'none'}.")
            extra["sla_class"] = {k: sla.get(k) for k in ("name", "loss_max", "latency_max", "jitter_max")}
        if source == "realtime":
            if not device:
                raise InvalidRequest("source='realtime' reads one device: give `device`.")
            row = resolve(inv, device)
            ip = require_reachable(row)
            rows = aggregate_realtime(await device_rows(app, APPROUTE_RT_PATH, ip), hosts)
            extra["source"] = (
                f"GET {APPROUTE_RT_PATH} (live probe buckets; loss/latency/jitter are the device's means)"
            )
            if remote_ip:
                rows = [r for r in rows if r.get("remote_system_ip") == remote_ip]
            if colour:
                rows = [r for r in rows if str(r.get("local_colour", "")).lower() == colour.strip().lower()]
        else:
            rules = []
            if device:
                row = resolve(inv, device)
                if not row.get("system_ip"):
                    raise InvalidRequest(
                        f"{device!r} has not joined the fabric (no system IP): it has no tunnels."
                    )
                rules.append(rule("vdevice_name", [row["system_ip"]]))
            elif site:
                rules.append(rule("vdevice_name", sorted(site_ips(inv, site))))
            if remote_ip:
                rules.append(rule("remote_system_ip", [remote_ip]))
            if colour:
                rules.append(rule("local_color", [colour.strip()]))
            result = await app.query(
                APPROUTE_STATS_PATH, last_hours(window_hours, *rules), limit=STATS_CAP, page_size=STATS_CAP
            )
            rows = aggregate_approute(result.rows, hosts)
            extra["source"] = (
                f"POST {APPROUTE_STATS_PATH}, last {window_hours} h ({len(result.rows)} statistics rows)"
            )
            if result.more:
                extra["partial"] = (
                    f"only the newest {STATS_CAP} statistics rows were read; narrow the filters or the window"
                )
            if not result.rows:
                extra["note"] = (
                    "no app-route statistics in the window (they arrive every 10 minutes; "
                    "source='realtime' reads the device now)"
                )
        if sla is not None:
            for r in rows:
                r["sla"] = sla_verdict(r, sla)
            extra["sla_summary"] = dict(Counter(r["sla"].split(":")[0] for r in rows))
        return list_result(
            page_of(sort_worst(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=[*APPROUTE_COLUMNS, "sla"] if sla is not None else APPROUTE_COLUMNS,
            extra=extra,
        )

    @reg.read(title="List SD-WAN SLA classes")
    async def catsdwan_list_sla_classes(
        ctx: Context,
        name: Annotated[str | None, Field(description="Only SLA classes whose name contains this")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The SLA classes app-aware routing steers by: maximum loss %, latency ms and jitter ms, whether it
        is a built-in default, which app-route policies use it and which centralized policies carry those
        (activated or not). Custom classes first. Use the name with catsdwan_app_route_stats(sla_class=...)
        to check every tunnel against it."""
        app: SdwanApp = get_client(ctx)
        rows, warnings = await _sla_classes(app)
        if name:
            rows = [r for r in rows if name.strip().lower() in str(r.get("name", "")).lower()]
        extra: dict[str, Any] = {"source": f"GET {SLA_LIST_PATH} (policy objects)"}
        if warnings:
            extra["warnings"] = warnings
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=SLA_COLUMNS, extra=extra
        )
