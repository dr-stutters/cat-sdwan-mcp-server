"""cat-sdwan-mcp-server: server spec and factory."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from cat_sdwan_mcp._core import ServerSpec, build_server
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings
from cat_sdwan_mcp.tools import control, dataplane, events, inventory

INSTRUCTIONS = """
Tools for Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, tunnels, BFD and
app-route state, configuration groups and policies. Personalities: vmanage = Manager, vsmart = Controller,
vbond = Validator, vedge = WAN edge. Devices are named by host name, system IP, chassis or serial.
Start with catsdwan_status (release, login, controllers, edge counts); call it if anything fails.
Inventory: catsdwan_list_devices (site, kind, reachability, model, version; certificate state and
configuration mode), catsdwan_get_device (one device plus live CPU, memory, interfaces, software, reboots),
catsdwan_list_controllers (control plane and certificate expiry). "What is unhealthy?":
catsdwan_device_health(health='poor'). Control plane: "why didn't this edge join?" ->
catsdwan_control_connections(device) (failed attempts with the reason in plain words; no device = the
fabric); "why can't branch A reach B?" -> catsdwan_omp_routes(A, vpn, prefix) then catsdwan_list_tlocs and
catsdwan_omp_peers. Data plane: "which tunnels are down?" -> catsdwan_bfd_sessions(state='not_up');
"which are lossy / is the voice SLA met?" -> catsdwan_app_route_stats(sla_class=...) (statistics every
10 minutes; source='realtime' for now), catsdwan_list_sla_classes, catsdwan_tunnel_stats.
Logs: "what changed and who did it?" -> catsdwan_audit_log(changes_only=true); "what has been breaking at
this site?" -> catsdwan_recent_activity(site) (alarms, events and audit lines on one timeline);
catsdwan_list_alarms (active by default), catsdwan_list_events (busy: keep since_hours short).
Real-time reads go over the Manager's control connection, so an unreachable edge has none.
Other planned tools are in the server's ROADMAP.md; until they exist, say so instead of guessing.
"""

SPEC = ServerSpec(
    name="cat-sdwan-mcp-server",
    prefix="catsdwan",
    product="Cisco Catalyst SD-WAN Manager",
    env_prefix="CATSDWAN_",
    instructions=INSTRUCTIONS,
)


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    return build_server(
        SPEC,
        settings,
        client_factory=lambda s: SdwanApp(s, transport=transport),
        register=[inventory.register, control.register, dataplane.register, events.register],
        status=SdwanApp.status,
        auth=auth,
    )
