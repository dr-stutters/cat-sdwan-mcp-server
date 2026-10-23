"""W3 control plane: catsdwan_control_connections, catsdwan_omp_peers, catsdwan_omp_routes,
catsdwan_list_tlocs."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections import Counter
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
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.control import (
    BULK_CONTROL,
    CONNECTIONS_PATH,
    HISTORY_PATH,
    OMP_PEERS_PATH,
    OMP_ROUTES_PATH,
    OMP_TLOCS_PATH,
    SUMMARY_PATH,
    connection_row,
    failed_attempts,
    history_row,
    is_up,
    peer_row,
    per_device,
    prefix_matches,
    route_row,
    sort_connections,
    sort_routes,
    summary_row,
    tloc_row,
)
from cat_sdwan_mcp.fabric import (
    device_rows,
    fan_out,
    find_device,
    host_map,
    reachable,
    require_reachable,
    safely,
    unreachable_reason,
)
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve

Device = Annotated[str, Field(description="Host name, system IP, chassis number or serial number")]
PeerType = Literal["controller", "manager", "validator", "edge"]
BULK_CAP = 5000  # rows read from the bulk state API for the fabric view

CONNECTION_COLUMNS = [
    "host",
    "peer",
    "peer_type",
    "peer_system_ip",
    "local_colour",
    "remote_colour",
    "protocol",
    "state",
    "uptime",
]
PEER_COLUMNS = ["host", "peer", "peer_host", "peer_type", "site_id", "state", "uptime"]
ROUTE_COLUMNS = ["vpn", "prefix", "originator_host", "tloc", "status", "meaning", "protocol", "preference"]
TLOC_COLUMNS = ["host", "system_ip", "colour", "encap", "site_id", "public", "private", "bfd_status"]


async def _nothing() -> list[dict[str, Any]]:
    return []


def _state_filter(rows: list[dict[str, Any]], state: str | None) -> list[dict[str, Any]]:
    if not state:
        return rows
    want = state.strip().lower()
    if want in ("not_up", "not-up", "!up"):
        return [r for r in rows if not is_up(r)]
    return [r for r in rows if str(r.get("state", "")).lower() == want]


async def _validator_history(app: SdwanApp, inv: Inventory, hosts: dict[str, str]) -> dict[str, Any]:
    """Failed attempts the reachable validators saw (an edge that never joins only ever reaches them)."""
    validators = reachable(inv, "validator")
    if not validators:
        return {"failed_attempts_note": "no reachable validator to read connection history from"}
    got = await fan_out(validators, lambda v: device_rows(app, HISTORY_PATH, str(v["system_ip"])))
    rows: list[dict[str, Any]] = []
    errors = []
    for v, res in zip(validators, got, strict=True):
        if isinstance(res, UpstreamError):
            errors.append(f"{v.get('host')}: GET {HISTORY_PATH} failed: {str(res)[:200]}")
        else:
            rows.extend(history_row(h, hosts) for h in res)
    out: dict[str, Any] = {"failed_attempts": failed_attempts(rows)}
    if errors:
        out["history_errors"] = errors
    return out


async def _omp_targets(app: SdwanApp, device: str | None) -> tuple[list[dict[str, Any]], Inventory]:
    """The device asked for (reachable), or every reachable controller when none is given."""
    inv = await load_inventory(app)
    if device:
        row = resolve(inv, device)
        require_reachable(row)
        return [row], inv
    targets = reachable(inv, "controller")
    if not targets:
        raise InvalidRequest(
            "No reachable controller to read OMP from; name a device. catsdwan_list_controllers shows them."
        )
    return targets, inv


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN control connections")
    async def catsdwan_control_connections(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(
                description="Host name, system IP, chassis or serial; omit for the whole fabric (the "
                "Manager's state database)"
            ),
        ] = None,
        state: Annotated[
            str | None,
            Field(description="Only connections in this state: up, down, connect, challenge, ...; 'not_up' "),
        ] = None,
        peer_type: Annotated[
            PeerType | None, Field(description="Only connections to this kind of peer")
        ] = None,
        include_history: Annotated[
            bool,
            Field(
                description="Add the failed connection attempts with their error codes in plain words (the "
                "device's history; the validators' for the fabric view or a device that is not up)"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Control connections (DTLS/TLS from each device to the controllers, Manager and validators): peer,
        peer type, peer system IP, local and remote colour, protocol, state, uptime, public and private
        address. With a device, read live from it plus its control summary and connection history; without
        one, the whole fabric from the Manager's state database with the devices whose connections are not
        all up. `failed_attempts` names why connections failed in plain words (chassis/serial not in the WAN
        edge list, certificate or organisation-name mismatch, clock skew, DTLS timeouts): the answer to
        'why didn't this edge join?'. An edge that is down or never joined has no live state, so the tool
        reads the validators' history instead."""
        app: SdwanApp = get_client(ctx)
        extra: dict[str, Any] = {}
        if device:
            row, inv = await find_device(app, device)
            hosts = host_map(inv)
            extra["device"] = row.get("host") or row.get("chassis")
            why = unreachable_reason(row)
            if why:
                extra["realtime"] = f"not read: {why}"
                if include_history:
                    extra.update(await _validator_history(app, inv, hosts))
                    extra["note"] = (
                        "failed_attempts are the validators' (every edge's, newest first): an edge that "
                        "cannot join is named there by its public address or chassis, not its host name"
                    )
                return list_result(page_of([], limit=limit), fmt=response_format, extra=extra)
            ip = str(row["system_ip"])
            conns, summary, history = await asyncio.gather(
                device_rows(app, CONNECTIONS_PATH, ip),
                safely(device_rows(app, SUMMARY_PATH, ip), f"GET {SUMMARY_PATH}"),
                safely(device_rows(app, HISTORY_PATH, ip), f"GET {HISTORY_PATH}")
                if include_history
                else _nothing(),
            )
            rows = [connection_row(c, hosts) for c in conns]
            extra["source"] = f"GET {CONNECTIONS_PATH} (live from the device)"
            if isinstance(summary, dict):
                extra["summary"] = summary
            elif shaped := summary_row(summary):
                extra["summary"] = shaped
            if isinstance(history, dict):
                extra["history_error"] = history["error"]
            elif include_history:
                extra["failed_attempts"] = failed_attempts([history_row(x, hosts) for x in history])
        else:
            inv = await load_inventory(app)
            hosts = host_map(inv)
            try:
                raw, more = await app.bulk_state(BULK_CONTROL, limit=BULK_CAP)
                extra["source"] = f"the Manager's state database (bulk {BULK_CONTROL})"
                if more:
                    extra["partial"] = f"the first {BULK_CAP} connections only; name a device for the rest"
            except UpstreamError as e:
                targets = reachable(inv, "controller") + reachable(inv, "validator")
                got = await fan_out(
                    targets, lambda t: device_rows(app, CONNECTIONS_PATH, str(t["system_ip"]))
                )
                raw = [c for res in got if not isinstance(res, UpstreamError) for c in res]
                extra["source"] = (
                    f"live from the {len(targets)} reachable controller(s) and validator(s): the bulk state "
                    f"API failed ({str(e)[:150]})"
                )
            rows = [connection_row(c, hosts) for c in raw]
            down = [
                f"{r.get('host')} ({r.get('role')}): {r.get('reachability')}"
                for r in inv.rows
                if str(r.get("reachability", "")).lower() != "reachable"
            ]
            if down:
                extra["unreachable_devices"] = down
            if include_history:
                extra.update(await _validator_history(app, inv, hosts))
        extra["by_state"] = dict(sorted(Counter(str(r.get("state")) for r in rows).items()))
        if not_all_up := per_device(rows):
            extra["not_all_up"] = not_all_up
        rows = _state_filter(rows, state)
        if peer_type:
            rows = [r for r in rows if r.get("peer_type") == peer_type]
        return list_result(
            page_of(sort_connections(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=CONNECTION_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN OMP peers")
    async def catsdwan_omp_peers(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(
                description="Host name, system IP, chassis or serial; omit to ask every reachable controller"
            ),
        ] = None,
        state: Annotated[
            str | None, Field(description="Only peers in this state (up, down, init); 'not_up'")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """OMP peerings read live: on an edge its controllers, on a controller every edge and controller it
        peers with (peer system IP and host, type, site, state, uptime, routes received, installed and sent
        where the device reports them). With no device every reachable controller is asked, which shows the
        whole fabric's OMP sessions. An edge missing here has no OMP session even if its control connections
        are up."""
        app: SdwanApp = get_client(ctx)
        targets, inv = await _omp_targets(app, device)
        hosts = host_map(inv)
        got = await fan_out(targets, lambda t: device_rows(app, OMP_PEERS_PATH, str(t["system_ip"])))
        rows: list[dict[str, Any]] = []
        extra: dict[str, Any] = {"asked": [t.get("host") for t in targets]}
        errors = []
        for t, res in zip(targets, got, strict=True):
            if isinstance(res, UpstreamError):
                errors.append(f"{t.get('host')}: GET {OMP_PEERS_PATH} failed: {str(res)[:200]}")
            else:
                rows.extend(peer_row(p, hosts) for p in res)
        if errors and not rows:
            raise UpstreamError("; ".join(errors))
        if errors:
            extra["errors"] = errors
        extra["by_state"] = dict(sorted(Counter(str(r.get("state")) for r in rows).items()))
        rows = _state_filter(rows, state)
        rows.sort(key=lambda r: (is_up(r), str(r.get("host")), str(r.get("peer_type")), str(r.get("peer"))))
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=PEER_COLUMNS, extra=extra
        )

    @reg.read(title="SD-WAN OMP routes")
    async def catsdwan_omp_routes(
        ctx: Context,
        device: Device,
        vpn: Annotated[
            int | None, Field(ge=0, le=65535, description="Only this service VPN, e.g. 10")
        ] = None,
        prefix: Annotated[
            str | None,
            Field(
                description="Only routes overlapping this prefix or address, e.g. '10.61.200.0/24' or "
                "'10.61.200.5'"
            ),
        ] = None,
        originator: Annotated[
            str | None, Field(description="Only routes originated by this edge (host name or system IP)")
        ] = None,
        direction: Annotated[
            Literal["received", "advertised"],
            Field(description="received (from the controllers) or advertised (to them)"),
        ] = "received",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """OMP routes on one device, read live: VPN, prefix, originating edge, TLOC (system IP / colour /
        encapsulation), status flags with their meaning (C chosen, I installed, R resolved, Red
        redistributed, Inv invalid, U TLOC unresolved, ...), protocol and preference. Answers 'why does
        branch A not reach branch B?': is B's prefix received, and through which TLOCs, is it installed?
        `prefix` matches overlapping routes (a host address finds its covering prefix)."""
        app: SdwanApp = get_client(ctx)
        row, inv = await find_device(app, device)
        ip = require_reachable(row)
        hosts = host_map(inv)
        path = OMP_ROUTES_PATH.format(direction=direction)
        rows = [route_row(r, hosts) for r in await device_rows(app, path, ip)]
        extra: dict[str, Any] = {"device": row.get("host"), "source": f"GET {path} (live)"}
        if vpn is not None:
            rows = [r for r in rows if str(r.get("vpn")) == str(vpn)]
        if prefix:
            rows = [r for r in rows if prefix_matches(r.get("prefix"), prefix)]
        if originator:
            want = originator.strip().lower()
            origin_ip = next((ip_ for ip_, h in hosts.items() if h.lower() == want), want)
            rows = [r for r in rows if str(r.get("originator", "")).lower() == origin_ip]
        installed: dict[tuple[Any, Any], bool] = {}
        for r in rows:
            flags = set(str(r.get("status", "")).split())
            key = (r.get("vpn"), r.get("prefix"))
            installed[key] = installed.get(key, False) or bool(flags & {"I", "Red"})
        extra["prefixes"] = len(installed)
        if direction == "received" and (missing := [k for k, ok in installed.items() if not ok]):
            extra["not_installed"] = [f"vpn {v} {p}" for v, p in missing[:25]]
        return list_result(
            page_of(sort_routes(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=ROUTE_COLUMNS,
            extra=extra,
        )

    @reg.read(title="List SD-WAN TLOCs")
    async def catsdwan_list_tlocs(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Device whose received TLOCs to read; omit for the first reachable controller"),
        ] = None,
        edge: Annotated[
            str | None, Field(description="Only this edge's TLOCs (host name or system IP)")
        ] = None,
        colour: Annotated[
            str | None, Field(description="Only this colour, e.g. 'mpls', 'biz-internet'")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """TLOCs (transport locators: system IP + colour + encapsulation) the device has received over OMP,
        read live: the edge's host, colour, encapsulation, site, public and private address and port (NAT
        shows as a difference), BFD status, preference, weight and encryption. A controller receives every
        edge's TLOCs, so the default (no device) is the fabric's TLOC table; a TLOC missing there was never
        advertised."""
        app: SdwanApp = get_client(ctx)
        targets, inv = await _omp_targets(app, device)
        target = targets[0]
        hosts = host_map(inv)
        ip = str(target["system_ip"])
        rows = [tloc_row(t, hosts) for t in await device_rows(app, OMP_TLOCS_PATH, ip)]
        extra: dict[str, Any] = {"device": target.get("host"), "source": f"GET {OMP_TLOCS_PATH} (live)"}
        if edge:
            want = edge.strip().lower()
            rows = [r for r in rows if want in (str(r.get("host", "")).lower(), str(r.get("system_ip", "")))]
        if colour:
            rows = [r for r in rows if str(r.get("colour", "")).lower() == colour.strip().lower()]
        extra["by_colour"] = dict(sorted(Counter(str(r.get("colour")) for r in rows).items()))
        rows.sort(key=lambda r: (str(r.get("host") or r.get("system_ip")), str(r.get("colour"))))
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=TLOC_COLUMNS, extra=extra
        )
