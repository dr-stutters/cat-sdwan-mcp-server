"""cat-sdwan-mcp-server: server spec and factory."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from cat_sdwan_mcp._core import ServerSpec, build_server
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings
from cat_sdwan_mcp.tools import inventory

INSTRUCTIONS = """
Tools for Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, tunnels, BFD and
app-route state, configuration groups and policies. Personalities: vmanage = Manager, vsmart = Controller,
vbond = Validator, vedge = WAN edge. Devices are named by host name, system IP, chassis or serial.
Start with catsdwan_status (release, login, controllers, edge counts); call it if anything fails.
Inventory: catsdwan_list_devices (site, kind, reachability, model, version; certificate state and
configuration mode), catsdwan_get_device (one device plus live CPU, memory, interfaces, software, reboots),
catsdwan_list_controllers (control plane and certificate expiry). "What is unhealthy?":
catsdwan_device_health(health='poor'). Real-time reads go over the Manager's control connection, so an
unreachable edge has none. Other planned tools are in the server's ROADMAP.md; until they exist, say so
instead of guessing.
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
        register=[inventory.register],
        status=SdwanApp.status,
        auth=auth,
    )
