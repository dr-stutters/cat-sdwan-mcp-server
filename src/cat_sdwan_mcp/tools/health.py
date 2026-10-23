"""W22 site, tunnel and interface health: catsdwan_site_health, catsdwan_tunnel_health,
catsdwan_interface_stats, catsdwan_topology. The Manager's own health model (the scores the operator sees on
its dashboard), not a score computed here."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

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
    object_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, last_hours, rule
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.fabric import host_map, safely
from cat_sdwan_mcp.health import (
    CAPACITY_PATH,
    DEVICE_HEALTH_OVERVIEW_PATH,
    INTERFACE_AGG_PATH,
    NETWORK_STATUS_PATH,
    QOS_PATH,
    SITE_TOPOLOGY_PATH,
    SITEHEALTH_PATH,
    SITEHEALTH_TREND_PATH,
    TUNNEL_HISTORY_PATH,
    TUNNEL_OVERVIEW_PATH,
    capacity_rows,
    history_rows,
    interface_body,
    interface_flags,
    interface_rows,
    network_status,
    overview_tunnels,
    qos_rows,
    site_intent,
    site_links,
    site_rows,
    site_trend,
)
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve
from cat_sdwan_mcp.tools.dataplane import Device

HealthFilter = Annotated[
    Literal["poor", "fair", "good", "not_good"] | None,
    Field(description="Only this health ('not_good' = fair or poor)"),
]
SITE_COLUMNS = ["site_id", "site_name", "health", "verdict", "tunnels", "device_names"]
TUNNEL_COLUMNS = ["tunnel", "health", "score", "loss_pct", "latency_ms", "jitter_ms", "state"]
HISTORY_COLUMNS = ["tunnel", "health", "loss_pct", "latency_ms", "bad_periods"]
INTERFACE_COLUMNS = ["interface", "rx_kbps", "tx_kbps", "peak_down_pct", "peak_up_pct", "errors", "drops"]
TUNNEL_LIMIT = 1000  # tunnels the Manager returns per health read


def _keep(health: str | None, value: str) -> bool:
    if health is None:
        return True
    if health == "not_good":
        return value in ("poor", "fair")
    return value == health


def _site_of(inv: Inventory) -> dict[str, str]:
    return {
        str(r["system_ip"]): str(r["site_id"]) for r in inv.rows if r.get("system_ip") and r.get("site_id")
    }


def _site_id(inv: Inventory, site: str) -> str:
    """A site id from a site id or name (the health APIs take the id)."""
    want = site.strip().lower()
    for r in inv.rows:
        if want in (str(r.get("site_id", "")).lower(), str(r.get("site_name", "")).lower()):
            return str(r["site_id"])
    known = sorted({str(r["site_id"]) for r in inv.rows if r.get("site_id")})
    raise InvalidRequest(f"No device is at site {site!r}. Sites: {', '.join(known) or 'none'}.")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN site health")
    async def catsdwan_site_health(
        ctx: Context,
        site: Annotated[str | None, Field(description="Site id or name (default: every site)")] = None,
        health: HealthFilter = None,
        window_hours: Annotated[int, Field(ge=1, le=168, description="Health over the last N hours")] = 3,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's site health (its dashboard model): per site the overall health (good, fair, poor), a
        verdict naming the component that pulls it down (devices, tunnels, apps; scores 0-10) and the tunnel
        counts, the devices and their configuration groups; worst first. Also the fabric summary
        (`/network/status`: controllers and edges by state), device health counts, and `trend`: the intervals
        in the window when any site was fair or poor. apps 'no_data' = application visibility is off."""
        app: SdwanApp = get_client(ctx)
        q = {"last_n_hours": window_hours}
        body, trend, overview, status = await asyncio.gather(
            app.api.get(SITEHEALTH_PATH, {**q, "includeDetails": "true"}),
            safely(app.api.get(SITEHEALTH_TREND_PATH, q), "site health trend"),
            safely(app.api.get(DEVICE_HEALTH_OVERVIEW_PATH), "device health overview"),
            safely(app.api.get(NETWORK_STATUS_PATH), "network status"),
        )
        rows = site_rows(body)
        if site:
            want = site.strip().lower()
            rows = [
                r
                for r in rows
                if want in (str(r.get("site_id", "")).lower(), str(r.get("site_name", "")).lower())
            ]
            if not rows:
                raise InvalidRequest(
                    f"The Manager reports no health for site {site!r} in the last {window_hours} h."
                )
        rows = [r for r in rows if _keep(health, r["health"])]
        extra: dict[str, Any] = {"window_hours": window_hours, "source": f"GET {SITEHEALTH_PATH}"}
        extra["fabric"] = status if isinstance(status, dict) and "error" in status else network_status(status)
        extra["device_health"] = overview
        if isinstance(trend, dict) and "error" in trend:
            extra["trend"] = trend
        else:
            bad = site_trend(trend)
            extra["trend"] = (
                bad or f"every site good (or no data) in each interval of the last {window_hours} h"
            )
        return list_result(page_of(rows, limit=200), fmt=response_format, columns=SITE_COLUMNS, extra=extra)

    @reg.read(title="SD-WAN tunnel health")
    async def catsdwan_tunnel_health(
        ctx: Context,
        site: Annotated[str | None, Field(description="Site id or name")] = None,
        device: Annotated[
            str | None, Field(description="Only tunnels from this edge (host, system IP, ...)")
        ] = None,
        health: HealthFilter = None,
        window_hours: Annotated[int, Field(ge=1, le=168, description="Over the last N hours")] = 1,
        history: Annotated[
            bool,
            Field(
                description="Per tunnel, the periods (30-minute intervals) it was fair or poor in the "
                "window, instead of the current scores"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's own tunnel health (good, fair, poor with a 0-10 score from loss, latency and jitter;
        vQoE), per tunnel ('br1:mpls-hub1:biz-internet' = local edge and colour to remote edge and colour),
        worst first, with the totals. history=true lists each tunnel's fair or poor periods in the window with
        the worst loss and latency in them ('when was br1's inet link bad?'). Filter by site, device (its
        tunnels) or health. catsdwan_app_route_stats has the raw loss, latency and jitter per tunnel."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        sid = _site_id(inv, site) if site else None
        ip: str | None = None
        if device:
            row = resolve(inv, device)
            ip = str(row.get("system_ip") or "")
            if not ip:
                raise InvalidRequest(f"{device!r} has no system IP: it has no tunnels.")
            sid = sid or (str(row["site_id"]) if row.get("site_id") else None)
        params: dict[str, Any] = {"last_n_hours": window_hours, "limit": TUNNEL_LIMIT}
        if sid:
            params["site"] = sid
        extra: dict[str, Any] = {"window_hours": window_hours}
        if history:
            body = await app.api.get(TUNNEL_HISTORY_PATH, params)
            rows = history_rows(body, hosts)
            columns = HISTORY_COLUMNS
            extra["source"] = f"GET {TUNNEL_HISTORY_PATH}"
        else:
            body = await app.api.get(path(TUNNEL_OVERVIEW_PATH, type="health"), params)
            totals, rows = overview_tunnels(body, hosts)
            extra["totals"] = totals
            columns = TUNNEL_COLUMNS
            extra["source"] = f"GET {TUNNEL_OVERVIEW_PATH.format(type='health')}"
        if ip:
            rows = [r for r in rows if r.get("local_system_ip") == ip]
        rows = [r for r in rows if _keep(health, r["health"])]
        if history:
            bad = sum(1 for r in rows if r["bad_periods"])
            extra["summary"] = f"{bad} of {len(rows)} tunnel(s) were fair or poor at some point in the window"
            extra["note_health"] = (
                "health and the averages are the Manager's over the whole window; bad_periods are when"
            )
            extra["note_health"] += " it was fair or poor (current scores: history=false)"
        if not rows:
            extra["note"] = "no tunnel health in the window (statistics arrive every 10-30 minutes)"
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=columns, extra=extra
        )

    @reg.read(title="SD-WAN interface statistics")
    async def catsdwan_interface_stats(
        ctx: Context,
        device: Device,
        interface: Annotated[str | None, Field(description="One interface, e.g. 'GigabitEthernet1'")] = None,
        window_hours: Annotated[int, Field(ge=1, le=24, description="Over the last N hours")] = 1,
        busy_pct: Annotated[
            float, Field(ge=1, le=100, description="Flag interfaces that peaked at this % of their bandwidth")
        ] = 80,
        capacity: Annotated[
            bool,
            Field(description="Add the site's circuit-capacity distribution (WAN links' use of bandwidth)"),
        ] = False,
        qos: Annotated[
            bool, Field(description="Add per-queue QoS drops (needs a QoS policy on the edge)")
        ] = False,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """An edge's interface statistics from the Manager's statistics database, aggregated over the window
        per interface: average rx and tx kbps, peak rx pps, errors and drops, peak use of the configured
        bandwidth (%) and the bandwidth; busiest first, with flags for a link near its bandwidth, errors or
        drops ('is a WAN link full?'). capacity=true adds the site's circuit-capacity distribution; qos=true
        the per-queue drops. Statistics arrive every 10-30 minutes; live counters: catsdwan_get_device."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        row = resolve(inv, device)
        ip = str(row.get("system_ip") or "")
        if not ip:
            raise InvalidRequest(f"{device!r} has no system IP: it has no interface statistics.")
        body = await app.api.post(INTERFACE_AGG_PATH, interface_body(ip, window_hours, interface), retry=True)
        rows = interface_rows(body)
        extra: dict[str, Any] = {
            "device": row.get("host") or ip,
            "window_hours": window_hours,
            "source": f"POST {INTERFACE_AGG_PATH}",
        }
        if flags := interface_flags(rows, busy_pct):
            extra["attention"] = flags
        if not rows:
            extra["note"] = (
                f"no interface statistics for {row.get('host') or ip} in the last {window_hours} h"
            )
        if capacity:
            if row.get("site_id"):
                got = await safely(app.api.get(CAPACITY_PATH, {"site-id": str(row["site_id"])}), "capacity")
                extra["capacity"] = (
                    got if isinstance(got, dict) and "error" in got else capacity_rows(got, ip)
                )
            else:
                extra["capacity"] = "not read: the device has no site id"
        if qos:
            try:
                result = await app.query(
                    QOS_PATH, last_hours(window_hours, rule("vdevice_name", [ip])), limit=2000
                )
                extra["qos"] = qos_rows(result.rows) or "no QoS statistics (no QoS policy on the edge?)"
            except UpstreamError as e:
                extra["qos"] = {"error": f"QoS statistics failed: {str(e)[:300]}"}
        return list_result(
            page_of(rows, limit=500), fmt=response_format, columns=INTERFACE_COLUMNS, extra=extra
        )

    @reg.read(title="SD-WAN topology")
    async def catsdwan_topology(
        ctx: Context,
        site: Annotated[
            str | None,
            Field(description="One site: its devices with their configuration intent and its links"),
        ] = None,
        window_hours: Annotated[
            int, Field(ge=1, le=24, description="Tunnel health over the last N hours")
        ] = 1,
    ) -> ToolResult:
        """The overlay as sites and links: each site's devices (host, role, system IP, reachability, model,
        version, configuration mode) and `site_links`: between sites, the tunnels joining them (how many, how
        many up, good / fair / poor by the Manager's tunnel health, worst loss and latency). With `site`: also
        each device's configuration intent (configuration group or template and its feature profiles, from
        /topology/device/site/{id}) and only that site's links."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        sid = _site_id(inv, site) if site else None
        params: dict[str, Any] = {"last_n_hours": window_hours, "limit": TUNNEL_LIMIT}
        reads: list[Any] = [
            safely(app.api.get(path(TUNNEL_OVERVIEW_PATH, type="health"), params), "tunnel health")
        ]
        if sid:
            reads.append(safely(app.api.get(path(SITE_TOPOLOGY_PATH, id=sid)), "site topology"))
        got = await asyncio.gather(*reads)
        intent = site_intent(got[1]) if sid and not (isinstance(got[1], dict) and "error" in got[1]) else {}
        sites: dict[str, dict[str, Any]] = {}
        for r in inv.rows:
            s = str(r.get("site_id") or "none")
            if sid and s != sid:
                continue
            entry = sites.setdefault(s, {"site_id": s, "site_name": r.get("site_name"), "devices": []})
            dev = {
                k: r.get(k)
                for k in (
                    "host",
                    "role",
                    "system_ip",
                    "reachability",
                    "model",
                    "version",
                    "config_mode",
                    "config",
                )
                if r.get(k) not in (None, "")
            }
            dev.update(intent.get(str(r.get("system_ip")), {}))
            entry["devices"].append(dev)
        out: dict[str, Any] = {"sites": sorted(sites.values(), key=lambda x: str(x["site_id"]))}
        tunnels_body = got[0]
        if isinstance(tunnels_body, dict) and "error" in tunnels_body:
            out["site_links"] = tunnels_body
        else:
            _, tunnels = overview_tunnels(tunnels_body, hosts)
            links = site_links(tunnels, _site_of(inv))
            if sid:
                links = [lk for lk in links if sid in lk["sites"].split(" <-> ")]
            out["site_links"] = links or "no tunnel health in the window"
        if sid and isinstance(got[1], dict) and "error" in got[1]:
            out["intent"] = got[1]
        if inv.warnings:
            out["warnings"] = inv.warnings
        out["source"] = (
            "inventory (GET /dataservice/device), "
            + f"GET {TUNNEL_OVERVIEW_PATH.format(type='health')}"
            + (f", GET {SITE_TOPOLOGY_PATH.format(id=sid)}" if sid else "")
        )
        return object_result(out, fmt="json")
