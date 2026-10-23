"""W18 device state reads: catsdwan_routes, catsdwan_device_state (reads)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.control import prefix_matches, sort_routes
from cat_sdwan_mcp.devicestate import (
    BGP_NEIGHBORS_PATH,
    BGP_ROUTES_PATH,
    CATALOGUE,
    EIGRP_INTERFACE_PATH,
    EIGRP_ROUTE_PATH,
    OSPF_NEIGHBOR_PATH,
    OSPF_ROUTES_PATH,
    ROUTES_IOSXE_PATH,
    ROUTES_VIPTELA_PATH,
    catalogue_rows,
    clean,
    fleet_rows,
    internal_vrf,
    is_unsupported,
    neighbour_row,
    neighbour_up,
    platform_of,
    route_row,
    suggest,
)
from cat_sdwan_mcp.fabric import device_rows, find_device, host_map, require_reachable

Device = Annotated[str, Field(description="Host name, system IP, chassis or serial number")]
ROUTE_COLUMNS = ["vpn", "prefix", "protocol", "next_hop", "via_edge", "interface", "preference", "metric"]
NEIGHBOUR_READS = {
    "bgp": BGP_NEIGHBORS_PATH,
    "ospf": OSPF_NEIGHBOR_PATH,
    "eigrp": EIGRP_INTERFACE_PATH,
}


async def _rows(app: SdwanApp, path: str, ip: str | None) -> list[dict[str, Any]]:
    if ip is None:
        data = await app.get_data(path)
        return [r for r in _as_list(data) if isinstance(r, dict)]
    return await device_rows(app, path, ip)


async def _table(app: SdwanApp, path: str, ip: str) -> list[dict[str, Any]] | str:
    """Rows, or a short reason when the device can't answer this table."""
    try:
        return await device_rows(app, path, ip)
    except UpstreamError as e:
        if is_unsupported(e):
            return "not on this platform (the Manager answered 'invalid data type')"
        return f"GET {path} failed: {str(e)[:200]}"


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN device routing table")
    async def catsdwan_routes(
        ctx: Context,
        device: Device,
        vpn: Annotated[
            int | None,
            Field(ge=0, le=65535, description="Only this VPN (0 transport, 512 management, 10 ...)"),
        ] = None,
        prefix: Annotated[
            str | None,
            Field(
                description="A prefix or address: the routes that cover or fall inside it (a default route "
                "covers everything)"
            ),
        ] = None,
        protocol: Annotated[
            str | None,
            Field(description="Only routes from this source: omp, static, connected, bgp, ospf, ..."),
        ] = None,
        include_neighbours: Annotated[
            bool,
            Field(description="Add the BGP, OSPF and EIGRP neighbours on the service side (default true)"),
        ] = True,
        include_internal: Annotated[
            bool, Field(description="Keep the platform's internal VRFs (65528/65529, __Platform_iVRF)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The device's routing table live (GET /device/ip/ipRoutes on IOS XE edges, /device/ip/routetable on
        Viptela OS): VPN, prefix, source protocol (omp, static, connected, bgp, ospf, eigrp), next hop (the
        remote edge's host name for an OMP route), interface, preference, metric; plus the service-side BGP,
        OSPF and EIGRP neighbours with their state. 'Why is this prefix missing?': give `prefix` and `vpn`;
        `missing` says when no route covers it (then check catsdwan_omp_routes for what OMP received). With
        protocol='bgp' or 'ospf' also the protocol's own route table."""
        app: SdwanApp = get_client(ctx)
        row, inv = await find_device(app, device)
        ip = require_reachable(row)
        hosts = host_map(inv)
        primary, fallback = (
            (ROUTES_IOSXE_PATH, ROUTES_VIPTELA_PATH)
            if platform_of(row) == "iosxe"
            else (ROUTES_VIPTELA_PATH, ROUTES_IOSXE_PATH)
        )
        extra: dict[str, Any] = {"device": row.get("host") or ip}
        raw = await _table(app, primary, ip)
        source = primary
        if not isinstance(raw, list) or not raw:
            alt = await _table(app, fallback, ip)
            if isinstance(alt, list) and alt:
                raw, source = alt, fallback
        if isinstance(raw, str):
            extra["routes_error"] = raw
            raw = []
        extra["source"] = source.removeprefix("/dataservice")
        routes = [route_row(r, hosts) for r in raw]
        if not include_internal:
            routes = [r for r in routes if not internal_vrf(r)]
        if vpn is not None:
            routes = [r for r in routes if str(r.get("vpn")) == str(vpn)]
        if protocol:
            want = protocol.strip().lower()
            want = {"connected": "direct"}.get(want, want) if source == ROUTES_IOSXE_PATH else want
            routes = [r for r in routes if str(r.get("protocol")) == want]
        if prefix:
            routes = [r for r in routes if prefix_matches(r.get("prefix"), prefix)]
            if not routes:
                where = f" in VPN {vpn}" if vpn is not None else ""
                extra["missing"] = (
                    f"no route covers {prefix}{where}: the edge would drop it (check "
                    f"catsdwan_omp_routes(device={extra['device']!r}, prefix={prefix!r}) for what OMP "
                    "received)"
                )
        routes = sort_routes(routes)
        by_protocol: dict[str, int] = {}
        for r in routes:
            by_protocol[str(r.get("protocol"))] = by_protocol.get(str(r.get("protocol")), 0) + 1
        extra["by_protocol"] = by_protocol
        if include_neighbours:
            got = await asyncio.gather(*(_table(app, p, ip) for p in NEIGHBOUR_READS.values()))
            neighbours: list[dict[str, Any]] = []
            notes = []
            for kind, res in zip(NEIGHBOUR_READS, got, strict=True):
                if isinstance(res, str):
                    notes.append(f"{kind}: {res}")
                else:
                    neighbours += [neighbour_row(kind, n) for n in res]
            if vpn is not None:
                neighbours = [n for n in neighbours if n.get("vpn") in (None, str(vpn))]
            extra["neighbours"] = neighbours or "none (no BGP, OSPF or EIGRP neighbour on this device)"
            if down := [n for n in neighbours if n.get("state") and not neighbour_up(n)]:
                extra["neighbours_not_up"] = len(down)
            if notes:
                extra["neighbour_notes"] = notes
        if protocol and protocol.lower() in ("bgp", "ospf", "eigrp"):
            path = {"bgp": BGP_ROUTES_PATH, "ospf": OSPF_ROUTES_PATH, "eigrp": EIGRP_ROUTE_PATH}[
                protocol.lower()
            ]
            own = await _table(app, path, ip)
            extra[f"{protocol.lower()}_table"] = (
                [clean(r) for r in own][:100] if isinstance(own, list) else own
            )
        return list_result(
            page_of(routes, limit=limit, offset=offset),
            fmt=response_format,
            columns=ROUTE_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN device state")
    async def catsdwan_device_state(
        ctx: Context,
        feature: Annotated[
            str,
            Field(
                description="What to read: arp, dhcp, vrrp, nat, interface_errors, hardware, crash_log, ntp, "
                "lacp, cdp, lldp, trackers, license, aaa, sdwan_drops, qos, policer, fib; 'list' "
                "describes them"
            ),
        ],
        device: Annotated[
            str | None, Field(description="Host name, system IP, chassis or serial (not needed for 'list')")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Rows per table")] = 100,
    ) -> dict[str, Any]:
        """One tool over the Manager's other real-time tables on a device: ARP, DHCP (client, server,
        interfaces), VRRP, NAT (translations, statistics), interface error/queue/port counters, hardware
        (environment, alarms, inventory), crash logs, NTP, LACP, CDP and LLDP neighbours, static-route and
        endpoint trackers, licence usage, AAA (users, servers, sessions, logging), the data plane's global
        drop counters, QoS, policers and the FIB. feature='list' says what each answers. Counters come back
        with the zeros left out; a table the platform doesn't have is named, not an error."""
        name = feature.strip().lower()
        if name == "list":
            return {"features": catalogue_rows()}
        spec = CATALOGUE.get(name)
        if spec is None:
            raise InvalidRequest(suggest(name))
        if not device:
            raise InvalidRequest(f"feature={name!r} needs a device.")
        app: SdwanApp = get_client(ctx)
        row, _ = await find_device(app, device)
        ip = require_reachable(row)
        platform = platform_of(row)
        if spec.platform and spec.platform != platform:
            raise InvalidRequest(
                f"{name} is a Viptela OS table; {row.get('host') or ip} ({row.get('model') or platform}) "
                "is an "
                "IOS XE edge and doesn't have it. feature='list' shows the others."
            )
        reads = await asyncio.gather(
            *(
                _table(app, t.path, ip) if not t.fleet else _fleet(app, t.path, ip, t.nested)
                for t in spec.tables
            )
        )
        tables: dict[str, Any] = {}
        empty = []
        for t, res in zip(spec.tables, reads, strict=True):
            if isinstance(res, str):
                tables[t.label] = res
                continue
            rows = [r for r in (clean(x, nonzero=spec.nonzero, keep=spec.keep) for x in res) if r]
            if not rows:
                empty.append(t.label)
                continue
            tables[t.label] = rows[:limit]
            if len(rows) > limit:
                tables[f"{t.label}_more"] = len(rows) - limit
        out: dict[str, Any] = {
            "device": row.get("host") or ip,
            "system_ip": ip,
            "feature": name,
            "answers": spec.answers,
            **tables,
        }
        if empty:
            out["empty"] = empty
            out["note"] = "empty tables: nothing configured or nothing to report" + (
                " (zero counters are left out)" if spec.nonzero else ""
            )
        return out


async def _fleet(app: SdwanApp, path: str, ip: str, nested: str | None) -> list[dict[str, Any]] | str:
    try:
        return fleet_rows(await _rows(app, path, None), ip, nested)
    except UpstreamError as e:
        return f"GET {path} failed: {str(e)[:200]}"
