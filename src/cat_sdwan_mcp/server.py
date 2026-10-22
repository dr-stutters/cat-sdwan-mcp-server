"""cat-sdwan-mcp-server: server spec and factory."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from cat_sdwan_mcp._core import ServerSpec, build_server
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings

INSTRUCTIONS = """
Tools for Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, tunnels, BFD and
app-route state, configuration groups and policies. This server is a scaffold (plan only): sdwan_status
is the only tool so far and it makes no SD-WAN Manager API calls. The planned tools are in the server's
ROADMAP.md; until they exist, say so instead of guessing.
"""

SPEC = ServerSpec(
    name="cat-sdwan-mcp-server",
    prefix="sdwan",
    product="Cisco Catalyst SD-WAN Manager",
    env_prefix="SDWAN_",
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
        register=[],
        status=SdwanApp.status,
        auth=auth,
    )
