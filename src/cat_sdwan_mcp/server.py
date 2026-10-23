"""cat-sdwan-mcp-server: server spec and factory."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from cat_sdwan_mcp._core import ServerSpec, ToolRegistrar, build_server
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings
from cat_sdwan_mcp.spec import spec_sources
from cat_sdwan_mcp.tools import api, changes, configuration, control, dataplane, events, inventory, onboarding

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
Configuration: "how is this edge configured, and did it drift?" -> catsdwan_get_device_config(device,
diff=true) (running vs intended, secrets masked; says configuration group, template or CLI mode);
catsdwan_list_config_groups -> catsdwan_get_config_group(group) (feature profiles, values, devices and their
variables); catsdwan_list_templates(type='device'|'feature'); catsdwan_list_policy_groups. A device is in a
configuration group or on a device template, never both.
Changes (with MCP_ENABLE_WRITES; preview-first): catsdwan_set_device_variables (stores values only) ->
catsdwan_deploy_config_group(group, devices) (preview = CLI and diff per device; confirm follows the action to
success or failure per device) -> catsdwan_get_device_config(diff=true). Legacy templates:
catsdwan_attach_device_template(template, devices, variables). One device is write tier; several devices, a
hub or a protected-site device need MCP_ENABLE_DANGEROUS. Name the preview's devices before confirming.
Onboarding: catsdwan_list_wan_edges(state='not_joined') -> catsdwan_onboard_edge(chassis, hostname, system_ip,
site_id, config_group or template) (validity, association, variables; stops at the failing step) -> boot the
edge with catsdwan_bootstrap_config(chassis) as its day-0, or the activate command it gives on a running
C8000V -> catsdwan_control_connections(device). catsdwan_set_edge_validity: invalid drops a joined edge
(dangerous). The one-time token is a secret: only catsdwan_bootstrap_config(reveal_otp=true) shows it.
Anything without a tool: catsdwan_search_spec('bfd') -> catsdwan_get_definition(path) -> catsdwan_api_call
(paths as /dataservice/..., checked against the Manager's own OpenAPI document; GET and the statistics, alarm,
event and audit query POSTs are reads, other writes are preview-first, /device/action/* is dangerous).
Other planned tools are in the server's ROADMAP.md; until they exist, say so instead of guessing.
"""

SPEC = ServerSpec(
    name="cat-sdwan-mcp-server",
    prefix="catsdwan",
    product="Cisco Catalyst SD-WAN Manager",
    env_prefix="CATSDWAN_",
    instructions=INSTRUCTIONS,
    spec_search_example="bfd sessions",
    spec_path_example="/dataservice/device/bfd/sessions",
)


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    mcp = build_server(
        SPEC,
        settings,
        client_factory=lambda s: SdwanApp(s, transport=transport),
        register=[
            inventory.register,
            control.register,
            dataplane.register,
            events.register,
            configuration.register,
            changes.register,
            onboarding.register,
        ],
        status=SdwanApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )
    # Core's generic api_call is GET-only or dangerous for every write; the Manager's is tiered per path.
    api.register_api_call(mcp, ToolRegistrar(mcp, settings, SPEC.prefix))
    return mcp
