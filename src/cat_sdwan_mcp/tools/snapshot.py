"""W46 pre/post change check: catsdwan_snapshot and catsdwan_compare_snapshot on core's snapshot contract
(C53, docs/SNAPSHOTS.md in stutters-mcp-core). Read tier; the client holds the blobs (ADR-003)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections.abc import Awaitable, Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from fastmcp import Context

from cat_sdwan_mcp._core import ToolRegistrar, UpstreamError, get_client
from cat_sdwan_mcp._core.snapshot import Section, Snapshot, register_snapshot_tools
from cat_sdwan_mcp.client import SdwanApp, _as_list, last_hours, rule
from cat_sdwan_mcp.control import BULK_CONTROL, CONNECTIONS_PATH, OMP_PEERS_PATH, connection_row, peer_row
from cat_sdwan_mcp.dataplane import (
    APPROUTE_STATS_PATH,
    BFD_SESSIONS_PATH,
    BULK_BFD,
    SLA_LIST_PATH,
    bfd_row,
    sla_rows,
)
from cat_sdwan_mcp.events import ALARMS_PATH
from cat_sdwan_mcp.fabric import device_rows, fan_out, host_map, is_reachable, reachable, site_ips
from cat_sdwan_mcp.inventory import Inventory, load_inventory, matches_site
from cat_sdwan_mcp.snapshot import (
    ALARM_METRICS,
    APPROUTE_METRICS,
    OMP_METRICS,
    alarm_in_scope,
    alarm_items,
    approute_items,
    bfd_items,
    control_items,
    device_items,
    omp_items,
)

PREFIX = "catsdwan"
SERVER = "cat-sdwan-mcp-server"
BULK_CAP = 5000
STATS_CAP = 10000
ALARM_HOURS = 168  # active alarms raised in the last 7 days
ALARM_CAP = 2000
COVERS = (
    "control connections per device, colour and peer; BFD sessions per tunnel; OMP peers; app-route loss, "
    "latency and jitter per tunnel against the SLA classes in use (10-minute statistics: take the 'after' "
    "snapshot at least 10 minutes after the change); active alarms by device and type; device "
    "reachability, version and configuration sync"
)
SITE_DOC = "SD-WAN site id (e.g. '200') or site name; empty = the whole fabric"


def _version() -> str | None:
    try:
        return version(SERVER)
    except PackageNotFoundError:
        return None


def _err(what: str, e: Exception) -> str:
    return f"{what} failed: {str(e)[:250]}"


async def _live(
    app: SdwanApp, devices: list[dict[str, Any]], path: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """One real-time table from each device; the devices whose read failed, by host."""
    got = await fan_out(devices, lambda d: device_rows(app, path, str(d["system_ip"])))
    rows: list[dict[str, Any]] = []
    failed: list[str] = []
    for d, res in zip(devices, got, strict=True):
        if isinstance(res, UpstreamError):
            failed.append(str(d.get("host") or d.get("system_ip")))
        else:
            rows.extend(res)
    return rows, failed


async def _rows(
    app: SdwanApp,
    inv: Inventory,
    scoped: list[dict[str, Any]] | None,
    path: str,
    bulk: str,
    fallback: Callable[[], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """A site: `path` live from each reachable device there. The fabric: the bulk state database (rows of
    unreachable devices dropped, they are stale), else `path` live from the `fallback()` devices."""
    if scoped is not None:
        return await _live(app, [d for d in scoped if is_reachable(d)], path)
    try:
        raw, _ = await app.bulk_state(bulk, limit=BULK_CAP)
    except UpstreamError:
        return await _live(app, fallback(), path)
    live = {str(d["system_ip"]) for d in reachable(inv)}
    return [r for r in raw if str(r.get("vdevice-name")) in live], []


def _not_read(sec: Section, failed: list[str], rows: list[dict[str, Any]], what: str) -> None:
    """All devices failed: the section is unreadable. Some: one 'not read' item per device."""
    if failed and not rows:
        sec.fail(f"{what} failed on {', '.join(failed[:10])}")
        return
    for host in failed:
        sec.item(f"{host}|not read", state="not read")


async def _section(sec: Section, fill: Callable[[], Awaitable[None]], what: str) -> None:
    """Fill one section; an API failure marks it unreadable instead of failing the snapshot."""
    try:
        await fill()
    except UpstreamError as e:
        sec.fail(_err(what, e))


async def take(ctx: Context, site: str) -> Snapshot:
    app: SdwanApp = get_client(ctx)
    site = site.strip()
    inv = await load_inventory(app)
    hosts = host_map(inv)
    snap = Snapshot(PREFIX, SERVER, scope={"site": site}, server_version=_version())
    scoped: list[dict[str, Any]] | None = None
    ips: set[str] | None = None
    if site:
        ips = site_ips(inv, site)  # InvalidRequest naming the known sites when none matches
        scoped = [r for r in inv.rows if matches_site(r, site)]
    in_scope = scoped if scoped is not None else inv.rows
    edges = [d for d in in_scope if d.get("role") == "edge"]

    devices = snap.section("devices", "Devices")
    device_items(devices, in_scope)

    control = snap.section("control", "Control connections")
    bfd = snap.section("bfd", "BFD sessions")
    omp = snap.section("omp", "OMP peers", metrics=OMP_METRICS)
    sla = snap.section("app_route_sla", "App-route SLA", metrics=APPROUTE_METRICS)
    alarms = snap.section("alarms", "Active alarms", metrics=ALARM_METRICS)

    async def fill_control() -> None:
        rows, failed = await _rows(
            app,
            inv,
            scoped,
            CONNECTIONS_PATH,
            BULK_CONTROL,
            lambda: reachable(inv, "controller") + reachable(inv, "validator"),
        )
        shaped = [connection_row(c, hosts) for c in rows]
        control_items(control, shaped)
        _not_read(control, failed, shaped, f"GET {CONNECTIONS_PATH}")

    async def fill_bfd() -> None:
        scoped_edges = None if scoped is None else edges
        rows, failed = await _rows(
            app, inv, scoped_edges, BFD_SESSIONS_PATH, BULK_BFD, lambda: reachable(inv, "edge")
        )
        shaped = [bfd_row(b, hosts) for b in rows]
        bfd_items(bfd, shaped)
        _not_read(bfd, failed, shaped, f"GET {BFD_SESSIONS_PATH}")

    async def fill_omp() -> None:
        # A site: each edge's OMP sessions to the controllers; the fabric: every controller's peers.
        targets = (
            [d for d in edges if is_reachable(d)] if scoped is not None else reachable(inv, "controller")
        )
        rows, failed = await _live(app, targets, OMP_PEERS_PATH)
        shaped = [peer_row(p, hosts) for p in rows]
        omp_items(omp, shaped)
        _not_read(omp, failed, shaped, f"GET {OMP_PEERS_PATH}")

    async def fill_sla() -> None:
        rules = [rule("vdevice_name", sorted(ips))] if ips is not None else []
        result, classes = await asyncio.gather(
            app.query(APPROUTE_STATS_PATH, last_hours(1, *rules), limit=STATS_CAP, page_size=STATS_CAP),
            _sla_classes(app),
        )
        approute_items(sla, result.rows, hosts, classes)

    async def fill_alarms() -> None:
        active = rule("active", ["true"], type_="boolean", operator="equal")
        try:
            result = await app.query(ALARMS_PATH, last_hours(ALARM_HOURS, active), limit=ALARM_CAP)
        except UpstreamError:  # a Manager that refuses the rule: every alarm, filtered here
            result = await app.query(ALARMS_PATH, last_hours(ALARM_HOURS), limit=ALARM_CAP)
        names = {str(r["host"]) for r in in_scope if r.get("host")}
        sites = {str(r["site_id"]) for r in in_scope if r.get("site_id") not in (None, "")}
        alarm_items(alarms, [a for a in result.rows if alarm_in_scope(a, ips, sites, names)])

    await asyncio.gather(
        _section(control, fill_control, "control connections"),
        _section(bfd, fill_bfd, "BFD sessions"),
        _section(omp, fill_omp, "OMP peers"),
        _section(sla, fill_sla, f"POST {APPROUTE_STATS_PATH}"),
        _section(alarms, fill_alarms, f"POST {ALARMS_PATH}"),
    )
    return snap


async def _sla_classes(app: SdwanApp) -> list[dict[str, Any]] | None:
    """The SLA classes with the app-route policies referencing them; None when they cannot be read (the
    tunnels are then judged by their state alone)."""
    try:
        data = await app.get_data(SLA_LIST_PATH)
    except UpstreamError:
        return None
    return sla_rows([r for r in _as_list(data) if isinstance(r, dict)])


def register(reg: ToolRegistrar) -> None:
    register_snapshot_tools(reg, take, product="Catalyst SD-WAN Manager", covers=COVERS, site_doc=SITE_DOC)
