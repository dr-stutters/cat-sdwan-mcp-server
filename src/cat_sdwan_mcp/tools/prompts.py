"""W10 workflow prompts (core `@reg.prompt`): catsdwan_branch_health, catsdwan_onboard_branch,
catsdwan_why_is_app_slow.

Each names the servers it expects in `uses`; the legs on other servers are optional and say "skipped if
not connected". Writes inside a workflow stay preview-first: the prompt tells the model to show each
preview and wait for the user's approval.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from cat_sdwan_mcp._core import Tier, ToolRegistrar, tool_ref

LAB = "mcp-lab-sdwan"  # default of CATSDWAN_CML_LAB: the standing SD-WAN CML lab
OPTIONAL = "skipped if that server is not connected: say so in one line and go on"

Site = Annotated[str, Field(description="Site id (e.g. '200') or site name (e.g. 'SITE_200')")]
CmlLab = Annotated[
    str,
    Field(description=f"CML lab of the fabric (title or id; blank = CATSDWAN_CML_LAB, default '{LAB}')"),
]


def default_lab(reg: ToolRegistrar) -> str:
    """The CML lab a blank `lab` argument means: CATSDWAN_CML_LAB, else LAB."""
    configured: str | None = getattr(reg.settings, "cml_lab", None)
    return (configured or "").strip() or LAB


def _lab(lab: str, default: str = LAB) -> str:
    return lab.strip() or default


def register(reg: ToolRegistrar) -> None:
    lab_default = default_lab(reg)

    @reg.prompt(
        title="SD-WAN branch health",
        uses=["catsdwan", "cml", "netbox"],
        example={"site": "200", "lab": LAB},
    )
    def catsdwan_branch_health(site: Site, lab: CmlLab = "") -> str:
        """Is this branch healthy? Device health, control connections, BFD and app-route loss, latency and
        jitter per transport colour, alarms and recent activity, then a verdict per transport (healthy,
        degraded, down); in a CML lab, the link scenarios say whether a degradation is deliberate."""
        lab_ = _lab(lab, lab_default)
        return f"""Report the health of SD-WAN site {site}, one verdict per transport.
Read-only: change nothing.

1. Devices: {tool_ref("catsdwan_device_health")} with site="{site}" (every edge at the site,
   health and the reason), and {tool_ref("catsdwan_list_devices")} with site="{site}" for host
   names, system IPs and reachability. No edge at the site: stop and say so (NetBox:
   {tool_ref("netbox_site_summary")} for "{site}" to check the site exists in the source of
   truth, {OPTIONAL}).
2. Control plane, per edge: {tool_ref("catsdwan_control_connections")} with device=<host>.
   Every edge should have its controller (vsmart) and Manager (vmanage) connections up on each
   colour; name any that are not, with the failure reason the tool gives.
3. Data plane, per edge: {tool_ref("catsdwan_bfd_sessions")} with device=<host> (state per
   local colour, by_colour_pair). A colour with no BFD session up is DOWN for that edge.
4. Quality, per colour: {tool_ref("catsdwan_app_route_stats")} with site="{site}" and
   colour=<each colour seen in step 3> (loss %, latency, jitter, worst tunnels first;
   window_hours=1 for now, source='realtime' if the statistics are older than the problem). If
   the fabric has SLA classes ({tool_ref("catsdwan_list_sla_classes")}), pass
   sla_class=<the one the site's traffic uses> to get meets / misses per tunnel.
5. Events: {tool_ref("catsdwan_list_alarms")} with site="{site}" (active), then
   {tool_ref("catsdwan_recent_activity")} with site="{site}" and since_hours=24 (alarms,
   events and who changed what, on one timeline).
6. Lab conditions ({OPTIONAL}): {tool_ref("cml_get_link_scenarios")} with lab="{lab_}". A
   scenario on a link of this site's edges (wan-satellite, lossy-wifi, brownout, flap) is a
   DELIBERATE degradation: name it next to the colour it explains. Not a CML lab: skip.

Verdict, one line per transport colour:
- healthy: BFD up to every remote site on that colour and loss < 1 %, latency and jitter
  within the SLA class (or, without one, loss < 1 % and latency < 150 ms);
- degraded: up, but loss, latency or jitter over those limits, or flapping (BFD transitions,
  alarms);
- down: no BFD session up on that colour, or no control connection over it.
Then one sentence on the branch as a whole and the most likely cause (a link scenario, a
transport, a device, a change in recent activity), and the next tool to run if anything is not
healthy."""

    @reg.prompt(
        title="Onboard an SD-WAN branch",
        uses=["catsdwan", "netbox", "cml"],
        tier=Tier.WRITE,
        example={
            "site": "201",
            "chassis": "C8K-00000000-0000-4000-8000-000000000001",
            "config_group": "mcp-test",
        },
    )
    def catsdwan_onboard_branch(
        site: Site,
        chassis: Annotated[
            str,
            Field(description="Chassis number of the edge to use (blank = pick a free one from the list)"),
        ] = "",
        config_group: Annotated[
            str, Field(description="Configuration group for the branch (blank = ask the user)")
        ] = "",
        hostname: Annotated[str, Field(description="Host name for the edge (blank = from NetBox)")] = "",
        lab: CmlLab = "",
    ) -> str:
        """Onboard a branch edge from the source of truth: site id, system IP and LAN prefixes from NetBox,
        then catsdwan_onboard_edge (validity, group, variables), boot or activate the edge, deploy the
        group, and prove it: control connections and BFD up, a ping from the branch host to the hub host,
        and a NetBox journal entry. Every write is preview-first."""
        lab_ = _lab(lab, lab_default)
        edge = f'chassis="{chassis.strip()}"' if chassis.strip() else "chassis=<the chassis from step 2>"
        group = (
            f'config_group="{config_group.strip()}"'
            if config_group.strip()
            else "config_group=<ask the user which group>"
        )
        name = hostname.strip() or "<the device name NetBox has for the site's edge>"
        pick = (
            f'use chassis "{chassis.strip()}".'
            if chassis.strip()
            else "pick a free chassis of the right model and tell the user which."
        )
        return f"""Onboard the SD-WAN branch at site {site}. Every write below is PREVIEW-FIRST: show
the preview, wait for the user's approval, then repeat the identical call with the confirm
token. Stop at the first step that fails and report it with its reason; never guess a value the
source of truth should give.

1. Source of truth (NetBox, {OPTIONAL}; without it, ask the user for the site id, host name and
   system IP):
   - {tool_ref("netbox_site_summary")} for "{site}": the site, its devices and prefixes; the
     SD-WAN site id is the site's custom field or description (ask if it isn't there).
   - {tool_ref("netbox_prefix_utilization")} for the site's LAN and system-IP prefixes.
   - The system IP: {tool_ref("netbox_next_available_ips")} in the system-IP prefix, then
     reserve it with {tool_ref("netbox_allocate_ips")} (preview first) for host name {name}.
2. The edge: {tool_ref("catsdwan_list_wan_edges")} with state="not_joined": {pick} Check it is
   in the list and hasn't joined already (the token stays masked).
3. Onboard: {tool_ref("catsdwan_onboard_edge")} with {edge}, hostname={name},
   system_ip=<from step 1>, site_id=<from step 1>, {group}. Show the preview's steps (validity,
   association, variables) and confirm.
4. Boot or activate the edge (CML, {OPTIONAL}; on hardware, hand the day-0 to whoever racks it):
   - a new or rebuilt node: {tool_ref("catsdwan_bootstrap_config")} with the chassis and
     reveal_otp=true (warn the user it returns the one-time token) as the node's day-0, built
     with {tool_ref("cml_build_recipe")} (recipe "cat-sdwan-fabric" for the whole lab) and
     started with {tool_ref("cml_set_node_state")};
   - a node already running in controller mode: the activate command from
     catsdwan_bootstrap_config, sent with {tool_ref("cml_configure_node")} (mode='exec') on that
     node in lab "{lab_}".
5. Joined? {tool_ref("catsdwan_control_connections")} with device=<host name> until the vsmart
   and vmanage connections are up (a few minutes after boot; failed attempts give the reason:
   not in the list, org, certificate, clock). {tool_ref("cml_run_commands")} with
   "show sdwan control connections" on the node shows the device's side.
6. Configure: {tool_ref("catsdwan_set_device_variables")} for anything the group still needs
   (the preview lists the variables), then {tool_ref("catsdwan_deploy_config_group")} with the
   group and devices=[<host name>]: show the per-device CLI and diff, confirm, and report each
   device's outcome.
7. Prove it: {tool_ref("catsdwan_bfd_sessions")} with device=<host name> (up on every colour to
   the hub), and, in CML, {tool_ref("cml_check_reachability")} in lab "{lab_}" from the branch
   host to the hub host (success % and RTT).
8. Record it (NetBox, {OPTIONAL}): {tool_ref("netbox_add_journal_entry")} on the site or
   device: chassis, system IP, site id, group, the date, and the BFD result (preview first).

End with a short table: step, result, and anything left for the user."""

    @reg.prompt(
        title="Why is this app slow over SD-WAN?",
        uses=["catsdwan", "ise", "fmc", "cml", "netbox"],
        example={"host": "10.61.200.10", "app": "office365", "lab": LAB},
    )
    def catsdwan_why_is_app_slow(
        host: Annotated[
            str,
            Field(description="The user name, client IP or MAC that sees the slowness, e.g. '10.61.200.10'"),
        ],
        app: Annotated[
            str, Field(description="The application, e.g. 'office365', 'webex', 'ssh to 10.61.100.10'")
        ],
        lab: CmlLab = "",
    ) -> str:
        """Why is this application slow for this user or host? Find the host's site (ISE session or
        NetBox), read the app-route loss, latency and jitter on each transport against the SLA class, the
        policy that picks the path, the firewall leg where an FTD sits behind the edge, and CML link
        conditions, then say in one sentence where the delay is."""
        lab_ = _lab(lab, lab_default)
        return f"""Find where {app} is slow for {host}.
Read-only: change nothing; suggest fixes, don't apply them.

1. Where is the host? ISE ({OPTIONAL}): {tool_ref("ise_find_session")} for "{host}" (IP, MAC
   or user): its IP, the switch (NAD) and so the site. Otherwise NetBox ({OPTIONAL}):
   {tool_ref("netbox_lookup_ip")} for the IP, which names the prefix and its site. Otherwise ask
   the user for the site. Map it to the SD-WAN site id and its edge(s) with
   {tool_ref("catsdwan_list_devices")} (site=<site id>).
2. The path: {tool_ref("catsdwan_bfd_sessions")} with device=<the branch edge>: which colours
   are up towards the site that hosts {app} (a data centre or hub site, or the internet
   breakout).
3. Path quality per transport: {tool_ref("catsdwan_app_route_stats")} with
   device=<the branch edge> and window_hours=1 (and once with source='realtime'): loss %,
   latency and jitter per tunnel and colour, worst first.
4. The SLA: {tool_ref("catsdwan_list_sla_classes")} names the SLA classes and the app-route
   policies that use them; the class {app} is matched to is the policy's (ask the user if it
   isn't clear: per-application policy reads come with a later tool). Run step 3 again with
   sla_class=<that class>: does the tunnel {app} uses meet it, and does another colour meet it
   while the chosen one doesn't (then the policy isn't steering it, or it has no fallback)?
5. Recent changes and alarms on that edge: {tool_ref("catsdwan_recent_activity")} with
   device=<the edge>.
6. The firewall leg (FMC, {OPTIONAL}): if an FTD sits behind the edge
   ({tool_ref("fmc_list_devices")}), run {tool_ref("fmc_packet_tracer")} for the host's IP to
   the application's server and port: a drop, an inspection (decryption, IPS) or a slow NAT
   path there explains slowness the SD-WAN statistics don't show.
7. Lab conditions (CML, {OPTIONAL}): {tool_ref("cml_get_link_scenarios")} in lab "{lab_}": a
   lossy-wifi or wan-satellite scenario on the branch host's link or a transport link is a
   deliberate cause; name it.

Answer in ONE sentence first: where the delay is (the host's access link, a transport colour
and its SLA miss, the policy picking the wrong path, the firewall, or the application side when
the overlay is clean), with the numbers that show it. Then the evidence per step, and the next
action."""
