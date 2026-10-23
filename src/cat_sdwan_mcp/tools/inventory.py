"""W2 inventory and device health: catsdwan_list_devices, catsdwan_get_device, catsdwan_list_controllers,
catsdwan_device_health."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.inventory import (
    CERT_WARN_DAYS,
    COUNTERS_PATH,
    HEALTH_PATH,
    ROLE_ORDER,
    computed_health_row,
    controller_row,
    health_row,
    load_inventory,
    matches_site,
    realtime,
    resolve,
    sort_health,
    sort_rows,
)

Role = Literal["edge", "controller", "validator", "manager"]
Site = Annotated[str | None, Field(description="Site id (e.g. '200') or site name (e.g. 'SITE_200')")]

DEVICE_COLUMNS = [
    "host",
    "role",
    "system_ip",
    "site_id",
    "model",
    "version",
    "reachability",
    "certificate",
    "config_mode",
    "config",
]
HEALTH_COLUMNS = ["host", "role", "system_ip", "site_id", "health", "reason", "cpu_percent", "memory_percent"]
CONTROLLER_COLUMNS = [
    "host",
    "role",
    "system_ip",
    "version",
    "reachability",
    "certificate",
    "certificate_serial",
    "certificate_expires",
    "days_left",
]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN devices")
    async def catsdwan_list_devices(
        ctx: Context,
        site: Site = None,
        personality: Annotated[
            Role | None,
            Field(description="Only this kind: edge (WAN edge), controller, validator or manager"),
        ] = None,
        reachability: Annotated[
            Literal["reachable", "unreachable"] | None, Field(description="Only devices in this state")
        ] = None,
        model: Annotated[str | None, Field(description="Model contains, e.g. 'C8000V'")] = None,
        version: Annotated[
            str | None, Field(description="Software version starts with, e.g. '17.18'")
        ] = None,
        include_unjoined: Annotated[
            bool,
            Field(
                description="Also list WAN edge slots from the serial file that have never joined (chassis, "
                "serial and certificate state only)"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the fabric's devices (WAN edges and controllers) with host name, system IP, site, model,
        version, reachability, status, uptime, serial and chassis, certificate state (valid, invalid, staging)
        and configuration mode (cli, template or configuration group, with the template or group). Filters
        combine (AND). Use catsdwan_get_device for CPU, memory, interfaces, software and reboots of one
        device, catsdwan_device_health for the unhealthy ones."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        rows = inv.rows + (inv.unjoined if include_unjoined else [])
        if site:
            rows = [r for r in rows if matches_site(r, site)]
        if personality:
            rows = [r for r in rows if r.get("role") == personality]
        if reachability:
            rows = [r for r in rows if str(r.get("reachability", "")).lower() == reachability]
        if model:
            rows = [r for r in rows if model.lower() in str(r.get("model", "")).lower()]
        if version:
            rows = [r for r in rows if str(r.get("version", "")).startswith(version)]
        extra: dict[str, Any] = {}
        if inv.unjoined and not include_unjoined:
            extra["not_joined"] = (
                f"{len(inv.unjoined)} WAN edge slot(s) in the serial file are not in the device list "
                "(include_unjoined=true lists them)"
            )
        if inv.warnings:
            extra["warnings"] = inv.warnings
        return list_result(
            page_of(sort_rows(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=DEVICE_COLUMNS,
            extra=extra or None,
        )

    @reg.read(title="Get SD-WAN device")
    async def catsdwan_get_device(
        ctx: Context,
        device: Annotated[str, Field(description="Host name, system IP, chassis number or serial number")],
        realtime_state: Annotated[
            bool,
            Field(
                description="Read CPU, memory, disk, interfaces, software and reboot history from the device "
                "(real-time, through the Manager's control connection); false for the inventory record only"
            ),
        ] = True,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """One device: its inventory record (site, model, version, reachability, uptime, serial and chassis,
        certificate state, configuration mode and template or group) plus, read live from the device, CPU,
        memory, disk and load, interfaces (admin and oper state, IP, VPN), installed and active software, and
        the last reboots with their reasons. A real-time read that fails (an unreachable edge) is reported in
        its section; the rest still answers. Accepts a host name, system IP, chassis or serial."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        out: dict[str, Any] = dict(resolve(inv, device))
        if inv.warnings:
            out["warnings"] = inv.warnings
        if not realtime_state:
            return object_result(out, fmt=response_format)
        ip = out.get("system_ip")
        if not ip:
            out["realtime"] = "not read: the device has not joined (no system IP)"
        elif str(out.get("reachability", "")).lower() != "reachable":
            out["realtime"] = (
                f"not read: the Manager reports the device {out.get('reachability') or 'unreachable'} "
                "(real-time reads go over its control connection)"
            )
        else:
            out.update(await realtime(app, str(ip)))
        return object_result(out, fmt=response_format)

    @reg.read(title="List SD-WAN controllers")
    async def catsdwan_list_controllers(
        ctx: Context,
        role: Annotated[
            Literal["manager", "controller", "validator"] | None,
            Field(description="Only this controller role"),
        ] = None,
        reachability: Annotated[
            Literal["reachable", "unreachable"] | None, Field(description="Only controllers in this state")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The control plane: manager, controller (vSmart) and validator (vBond) nodes with system IP,
        version, reachability, certificate validity and install status, certificate serial, expiry and days
        left. Certificates that are not valid or expire within 30 days are named in `attention`."""
        app: SdwanApp = get_client(ctx)
        rows = [controller_row(c) for c in await app.controllers()]
        rows.sort(key=lambda r: (ROLE_ORDER.get(str(r.get("role")), 9), str(r.get("host") or "")))
        if role:
            rows = [r for r in rows if r.get("role") == role]
        if reachability:
            rows = [r for r in rows if str(r.get("reachability", "")).lower() == reachability]
        extra: dict[str, Any] = {"by_role": dict(sorted(Counter(str(r.get("role")) for r in rows).items()))}
        attention = []
        for r in rows:
            name = r.get("host") or r.get("certificate_serial")
            if r.get("certificate") and str(r["certificate"]).lower() != "valid":
                attention.append(f"{name}: certificate {r['certificate']}")
            elif isinstance(r.get("days_left"), int) and r["days_left"] <= CERT_WARN_DAYS:
                attention.append(f"{name}: certificate expires in {r['days_left']} day(s)")
            if str(r.get("reachability", "")).lower() not in ("", "reachable"):
                attention.append(f"{name}: {r['reachability']}")
        if attention:
            extra["attention"] = attention
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=CONTROLLER_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN device health")
    async def catsdwan_device_health(
        ctx: Context,
        site: Site = None,
        health: Annotated[
            Literal["poor", "fair", "good"] | None, Field(description="Only devices with this health")
        ] = None,
        personality: Annotated[Role | None, Field(description="Only this kind of device")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Device health as the Manager rates it (good, fair, poor), the poor devices first, each with the
        reason: the Manager's own, plus what is visibly short (control connections, BFD sessions, TLOCs, OMP
        peers, reachability) and a high CPU or memory load. Also CPU and memory %, control/BFD/TLOC counts,
        version and configuration group. `counts` covers every device before the filters. On a Manager
        without /health/devices it is computed from reachability and the control-connection, BFD and OMP
        counters."""
        app: SdwanApp = get_client(ctx)
        extra: dict[str, Any] = {}
        try:
            body = await app.api.get(HEALTH_PATH)
            records = body.get("devices") if isinstance(body, dict) else body
            rows = [health_row(d) for d in _as_list(records) if isinstance(d, dict)]
            total = body.get("total_devices") if isinstance(body, dict) else None
            if isinstance(total, int) and total > len(rows):
                extra["partial"] = f"the Manager returned {len(rows)} of {total} device health records"
            extra["source"] = f"GET {HEALTH_PATH}"
        except NotFound:
            devices, counters = await asyncio.gather(app.devices(), app.get_data(COUNTERS_PATH))
            by_ip = {str(c.get("system-ip")): c for c in _as_list(counters) if isinstance(c, dict)}
            rows = [computed_health_row(d, by_ip.get(str(d.get("system-ip")))) for d in devices]
            extra["source"] = (
                f"computed: this Manager has no {HEALTH_PATH}; from /dataservice/device and {COUNTERS_PATH} "
                "(reachability, control connections, BFD, OMP; no CPU or memory)"
            )
        extra["counts"] = {h: sum(1 for r in rows if r.get("health") == h) for h in ("poor", "fair", "good")}
        if site:
            rows = [r for r in rows if matches_site(r, site)]
        if health:
            rows = [r for r in rows if r.get("health") == health]
        if personality:
            rows = [r for r in rows if r.get("role") == personality]
        return list_result(
            page_of(sort_health(rows), limit=limit, offset=offset),
            fmt=response_format,
            columns=HEALTH_COLUMNS,
            extra=extra,
        )
