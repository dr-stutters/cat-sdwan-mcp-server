"""W17 on-box troubleshooting: catsdwan_ping, catsdwan_traceroute, catsdwan_tunnel_path,
catsdwan_device_bringup, catsdwan_admin_tech.

Tiers: ping, traceroute and the flow simulation are POSTs that change nothing on the edge (the Manager runs
the command and returns its output), so they are read tier, like the device bring-up checklist.
catsdwan_admin_tech is write tier: it writes an archive to the device's disk and loads its CPU for minutes.
Factory reset, interface reset and user reset (/device/tools/factoryreset, /reset/interface, /resetuser) are
not offered.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import time
from collections.abc import Awaitable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    poll_until,
    preview_or_apply,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.fabric import device_rows, find_device, host_map, require_reachable
from cat_sdwan_mcp.inventory import INTERFACE_PATH
from cat_sdwan_mcp.troubleshooting import (
    ADMINTECH_PATH,
    ADMINTECH_PROGRESS_PATH,
    ADMINTECHS_PATH,
    BRINGUP_PATH,
    CONTROL_TS_PATH,
    NPING_PATH,
    PING_PATH,
    SERVICEPATH_PATH,
    TOOL_TIMEOUT,
    TRACEROUTE_PATH,
    TUNNELPATH_PATH,
    admintech_rows,
    bringup_steps,
    control_check,
    flow_body,
    flow_result,
    in_progress,
    path,
    ping_body,
    ping_result,
    traceroute_result,
)

Device = Annotated[
    str, Field(description="Host name, system IP, chassis or serial of the device to run it on")
]
Destination = Annotated[str, Field(description="Destination IP address or host name, e.g. '10.61.201.10'")]
Vpn = Annotated[
    int,
    Field(ge=0, le=65535, description="VPN (VRF) to run in: 0 = transport, 512 = management, 10 = service"),
]
SourceInterface = Annotated[
    str | None, Field(description="Source interface, e.g. 'GigabitEthernet3' (default: the device picks)")
]
PERSONALITY = {"edge": "vedge", "controller": "vsmart", "validator": "vbond", "manager": "vmanage"}
POLL_INTERVAL = 10.0  # seconds between admin-tech list reads (tests set it to 0)


async def _target(app: SdwanApp, device: str) -> tuple[dict[str, Any], str, dict[str, str]]:
    row, inv = await find_device(app, device)
    ip = require_reachable(row, "These tools run on the device through its control connection.")
    return row, ip, host_map(inv)


async def _maybe(coro: Awaitable[Any]) -> Any:
    """`coro`'s result, or the UpstreamError it raised (an optional section)."""
    try:
        return await coro
    except UpstreamError as e:
        return e


async def _none() -> None:
    return None


def _head(row: dict[str, Any], ip: str) -> dict[str, Any]:
    return {"device": row.get("host") or ip, "system_ip": ip}


async def _vpn_interface(app: SdwanApp, ip: str, vpn: int, name: str | None) -> tuple[str | None, str | None]:
    """(interface, its address) in `vpn`: the named one, or the first up interface with an address."""
    try:
        rows = await device_rows(app, INTERFACE_PATH, ip)
    except UpstreamError:
        return name, None
    for r in rows:
        if str(r.get("vpn-id")) != str(vpn):
            continue
        addr = r.get("ip-address")
        if not addr or addr == "0.0.0.0":
            continue
        if name and r.get("ifname") != name:
            continue
        if name is None and str(r.get("ifname", "")).lower().startswith(("loopback", "tunnel", "sdwan")):
            continue
        return str(r.get("ifname")), str(addr)
    return name, None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Ping from an SD-WAN device", idempotent=False)
    async def catsdwan_ping(
        ctx: Context,
        device: Device,
        destination: Destination,
        vpn: Vpn = 0,
        source_interface: SourceInterface = None,
        count: Annotated[int, Field(ge=1, le=100, description="Probes to send")] = 5,
        size: Annotated[int | None, Field(ge=36, le=18000, description="Packet size in bytes")] = None,
        probe: Annotated[
            Literal["icmp", "tcp", "udp"],
            Field(description="icmp (ping), or a tcp/udp probe to dest_port (the Manager's nping)"),
        ] = "icmp",
        dest_port: Annotated[
            int | None, Field(ge=1, le=65535, description="Port for a tcp/udp probe")
        ] = None,
    ) -> dict[str, Any]:
        """Ping a destination from an edge (or controller) through the Manager (POST
        /device/tools/ping/{deviceIP}; /nping for tcp and udp probes to a port): works on a customer fabric
        where there is no console. Returns sent, received, loss %, min/avg/max RTT, the device's own output
        and a verdict. Run it in the service VPN (e.g. vpn=10) to test branch-to-branch reachability."""
        app: SdwanApp = get_client(ctx)
        if probe != "icmp" and dest_port is None:
            raise InvalidRequest(f"A {probe} probe needs dest_port.")
        row, ip, _ = await _target(app, device)
        body = ping_body(
            destination,
            vpn,
            source=source_interface,
            count=count,
            size=size,
            rapid=True,
            probe=probe,
            dest_port=dest_port,
        )
        url = path(PING_PATH if probe == "icmp" else NPING_PATH, ip=ip)
        answer = await app.api.post(url, body, timeout=TOOL_TIMEOUT)
        return {**_head(row, ip), "destination": destination, "vpn": vpn, **ping_result(answer, destination)}

    @reg.read(title="Traceroute from an SD-WAN device", idempotent=False)
    async def catsdwan_traceroute(
        ctx: Context,
        device: Device,
        destination: Destination,
        vpn: Vpn = 0,
        source_interface: SourceInterface = None,
        size: Annotated[int | None, Field(ge=36, le=18000, description="Probe size in bytes")] = None,
    ) -> dict[str, Any]:
        """Traceroute from an edge (or controller) through the Manager (POST
        /device/tools/traceroute/{deviceIP}): each hop's address, name and latency, and whether the
        destination was reached. Inside the overlay the tunnel is one hop: catsdwan_tunnel_path says which
        tunnel."""
        app: SdwanApp = get_client(ctx)
        row, ip, _ = await _target(app, device)
        iface_ip = None
        if source_interface:
            _, iface_ip = await _vpn_interface(app, ip, vpn, source_interface)
        body = {
            "deviceIp": ip,
            "vpn": str(vpn),
            "host": destination,
            **({"interface": source_interface} if source_interface else {}),
            **({"interfaceIP": iface_ip} if iface_ip else {}),
            **({"size": str(size)} if size else {}),
        }
        answer = await app.api.post(path(TRACEROUTE_PATH, ip=ip), body, timeout=TOOL_TIMEOUT)
        return {
            **_head(row, ip),
            "destination": destination,
            "vpn": vpn,
            **traceroute_result(answer, destination),
        }

    @reg.read(title="Simulate an SD-WAN flow (tunnel path)", idempotent=False)
    async def catsdwan_tunnel_path(
        ctx: Context,
        device: Device,
        destination: Destination,
        vpn: Annotated[int, Field(ge=1, le=65530, description="Service VPN of the flow, e.g. 10")],
        source_ip: Annotated[
            str | None, Field(description="Source address of the flow (default: the VPN interface's address)")
        ] = None,
        source_interface: SourceInterface = None,
        protocol: Annotated[str, Field(description="icmp, tcp, udp or an IP protocol number")] = "icmp",
        source_port: Annotated[int | None, Field(ge=0, le=65535, description="Source port (tcp/udp)")] = None,
        dest_port: Annotated[
            int | None, Field(ge=0, le=65535, description="Destination port (tcp/udp)")
        ] = None,
        dscp: Annotated[
            int | None, Field(ge=0, le=63, description="DSCP value of the flow, e.g. 46 for voice")
        ] = None,
        app_name: Annotated[
            str | None, Field(description="Application name as the Manager's DPI knows it (needs DPI)")
        ] = None,
        path_kind: Annotated[
            Literal["service", "tunnel"],
            Field(
                description="service: traffic entering from the LAN (the usual question); tunnel: traffic "
                "arriving from the overlay"
            ),
        ] = "service",
        all_paths: Annotated[bool, Field(description="Every eligible path, not only the one picked")] = True,
    ) -> dict[str, Any]:
        """Which tunnel and next hop the edge picks for a flow, live (the Manager's 'Simulate Flows': POST
        /device/tools/servicepath/{deviceIP}, or /tunnelpath for traffic arriving from the overlay): each
        next hop's type (ipsec, gre, direct, local, blackhole), local and remote colour, the remote edge, plus
        the app-route and data policies that matched and any policy drop reason. The live answer to 'which
        transport does this branch use for voice?' (dscp=46) or 'why does this flow avoid mpls?'."""
        app: SdwanApp = get_client(ctx)
        row, ip, hosts = await _target(app, device)
        iface, addr = await _vpn_interface(app, ip, vpn, source_interface)
        src = source_ip or addr
        if not src:
            raise InvalidRequest(
                f"{row.get('host') or ip} has no interface with an address in VPN {vpn}"
                + (f" named {source_interface!r}" if source_interface else "")
                + ": pass source_ip (and source_interface)."
            )
        body = flow_body(
            ip,
            vpn=vpn,
            interface=iface,
            source_ip=src,
            destination=destination,
            protocol=protocol,
            source_port=source_port,
            dest_port=dest_port,
            dscp=dscp,
            app=app_name,
            all_paths=all_paths,
        )
        url = path(SERVICEPATH_PATH if path_kind == "service" else TUNNELPATH_PATH, ip=ip)
        answer = await app.api.post(url, body, timeout=TOOL_TIMEOUT)
        keys = ("vpn", "interface", "sourceIp", "destIp", "protocol", "destPort", "dscp", "app")
        flow = {k: body[k] for k in keys if k in body}
        return {**_head(row, ip), "path": path_kind, "flow": flow, **flow_result(answer, hosts)}

    @reg.read(title="SD-WAN device bring-up checklist")
    async def catsdwan_device_bringup(ctx: Context, device: Device) -> dict[str, Any]:
        """The Manager's own onboarding checklist for a device (GET /troubleshooting/devicebringup): validator
        authorisation, control plane, configuration, software update, data plane, each with its status and
        message in bring-up order, and a verdict naming the first failing step with what to check next.
        Works for an edge that never joined (give its chassis number). For a joined device also the control
        connection check per WAN colour (GET /troubleshooting/control/{uuid}: expected vs actual connections
        and the peers that are not up)."""
        app: SdwanApp = get_client(ctx)
        row, _ = await find_device(app, device)
        uuid = row.get("chassis")
        if not uuid:
            raise InvalidRequest(
                f"{device!r} has no chassis number in the inventory, so it has no checklist."
            )
        body, ctl = await asyncio.gather(
            app.api.get(BRINGUP_PATH, {"uuid": uuid}),
            _maybe(app.api.get(path(CONTROL_TS_PATH, uuid=uuid))) if row.get("system_ip") else _none(),
        )
        steps, verdict = bringup_steps(body)
        out: dict[str, Any] = {
            "device": row.get("host") or uuid,
            "chassis": uuid,
            "system_ip": row.get("system_ip"),
            "reachability": row.get("reachability"),
            "verdict": verdict,
            "steps": steps,
        }
        if isinstance(ctl, UpstreamError):
            out["control_check"] = f"not read: {str(ctl)[:200]}"
        elif isinstance(ctl, dict):
            out["control_check"] = control_check(ctl)
        return out

    @reg.write(title="Generate an SD-WAN admin-tech", task=True)
    async def catsdwan_admin_tech(
        ctx: Context,
        device: Device,
        exclude_cores: Annotated[
            bool, Field(description="Leave core files out (smaller; default true)")
        ] = True,
        exclude_logs: Annotated[bool, Field(description="Leave log files out")] = False,
        exclude_tech: Annotated[bool, Field(description="Leave the show tech-support output out")] = False,
        wait: Annotated[bool, Field(description="Wait until the archive is ready (default true)")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Generate an admin-tech archive on a device for TAC (POST /device/tools/admintech), wait until the
        Manager lists it (GET /device/tools/admintechs, /admintechs/inprogress) and return its file name and
        download path (GET /device/tools/admintech/download/{file}, e.g. with catsdwan_api_call or a browser
        session). Preview-first; the preview lists the device's existing admin-techs. Write tier: it writes a
        file to the device's disk and loads its CPU for several minutes."""
        app: SdwanApp = get_client(ctx)
        row, ip, _ = await _target(app, device)
        name = str(row.get("host") or ip)
        existing_body, progress_body = await asyncio.gather(
            _maybe(app.api.get(ADMINTECHS_PATH)), _maybe(app.api.get(ADMINTECH_PROGRESS_PATH))
        )
        existing = admintech_rows(existing_body, ip) if not isinstance(existing_body, UpstreamError) else []
        running = in_progress(progress_body) if not isinstance(progress_body, UpstreamError) else 0
        personality = PERSONALITY.get(str(row.get("role")), "vedge")
        body = {
            "deviceIP": ip,
            "device-type": personality,
            "exclude-cores": exclude_cores,
            "exclude-tech": exclude_tech,
            "exclude-logs": exclude_logs,
        }
        warnings = []
        if running:
            warnings.append(f"{running} admin-tech(s) already in progress on the Manager")
        plan = Plan(
            f"Generate an admin-tech on {name} ({ip})",
            details={
                "device": {**_head(row, ip), "role": row.get("role"), "model": row.get("model")},
                "request": f"POST {ADMINTECH_PATH} {body}",
                "existing_admin_techs": existing[:10] or "none",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                f"{name} writes an archive to its disk (tens to hundreds of MB) and its CPU is busy for "
                "several minutes; nothing else changes"
            ],
            fingerprint=None,
            blast_radius=1,
        )

        async def apply() -> Any:
            before = {r.get("request_id") for r in existing}
            started = time.time()
            answer = await app.api.post(ADMINTECH_PATH, body, timeout=600)
            out: dict[str, Any] = {"device": name}
            if not wait:
                out["answer"] = answer
                out["check_with"] = f"catsdwan_api_call('{ADMINTECHS_PATH}')"
                return out

            async def fetch() -> list[dict[str, Any]]:
                rows = admintech_rows(await app.api.get(ADMINTECHS_PATH), ip)
                return [r for r in rows if r.get("request_id") not in before]

            def done(rows: list[dict[str, Any]]) -> bool:
                return any(
                    str(r.get("state", "done")).lower() in ("done", "success", "completed") for r in rows
                )

            rows = await poll_until(
                fetch,
                done=done,
                describe=lambda rows: f"{len(rows)} new admin-tech(s) listed",
                timeout=app.settings.mcp_task_timeout,
                interval=POLL_INTERVAL,
                ctx=ctx,
                what=f"admin-tech on {name}",
            )
            out["admin_tech"] = rows[0]
            out["seconds"] = int(time.time() - started)
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_admin_tech",
            args={
                "device": device,
                "exclude_cores": exclude_cores,
                "exclude_logs": exclude_logs,
                "exclude_tech": exclude_tech,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
