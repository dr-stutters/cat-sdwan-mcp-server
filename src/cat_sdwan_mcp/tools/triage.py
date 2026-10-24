"""W51 branch triage prompts (core `@reg.prompt`, scenario C54): catsdwan_wifi_lan_or_wan,
catsdwan_network_or_ise, catsdwan_site_down, catsdwan_brownout_drill.

The four questions a branch asks first, each ending in a verdict instead of a tour of four consoles. Like the
W10 prompts, each names the servers it expects in `uses` and the legs on other servers say "skipped if not
connected". The first three are read-only; the brownout drill changes the CML lab's link conditioning only,
with cml_apply_link_scenario / cml_clear_link_scenarios, which are preview-first on the CML server: the
prompt says so and tells the model to show each preview and wait for the user's approval.

Recorded on lab `mcp-cat-sdwan` (recipe cat-sdwan-fabric, 20.18): each edge (hub1 at site 100, br1 at 200,
br2 at 201) has GigabitEthernet1 on the `mpls` switch and GigabitEthernet2 on the `inet` switch (colours
mpls and biz-internet), a host on GigabitEthernet3 and VPN 512 on GigabitEthernet4; the CML links read
'br1:GigabitEthernet1<->mpls:port2'. The Manager carries the default SLA classes (Realtime,
Voice-And-Video, Business-Critical, ...) plus custom ones such as mcp-test-sla.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from cat_sdwan_mcp._core import ToolRegistrar, tool_ref
from cat_sdwan_mcp.tools.prompts import LAB, OPTIONAL, CmlLab, Site, _lab

NO_CATC = (
    "skipped when Catalyst Center is not connected or does not manage this site's access layer "
    "(switches, WLC, APs): say so in one line and judge from the other layers"
)


def _site_arg(site: str) -> str:
    return f'site="{site.strip()}"' if site.strip() else "site=<the site found in step 1>"


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Is it the Wi-Fi, the LAN or the WAN?",
        uses=["catsdwan", "catc", "ise", "cml"],
        example={"host": "10.61.200.10", "site": "200", "lab": LAB},
    )
    def catsdwan_wifi_lan_or_wan(
        host: Annotated[
            str,
            Field(description="The user name, client IP or MAC with the problem, e.g. '10.61.200.10'"),
        ],
        site: Annotated[
            str, Field(description="SD-WAN site id or name of the branch (blank = find it from the host)")
        ] = "",
        lab: CmlLab = "",
    ) -> str:
        """Is this user's problem the Wi-Fi, the LAN or the WAN? Locate the host (catsdwan_find_host, ISE
        session, Catalyst Center), read the client's own health and the access layer at the site (client
        360, site health, switch and AP health) against the SD-WAN site and tunnel health and app-route SLA,
        then give a verdict per layer (Wi-Fi, LAN, WAN) and name the one at fault."""
        lab_ = _lab(lab)
        where = _site_arg(site)
        return f"""Find out whether {host}'s problem is the Wi-Fi, the LAN or the WAN, one verdict per
layer. Read-only: change nothing; suggest fixes, don't apply them.

1. Locate the host. An IP or MAC: {tool_ref("catsdwan_find_host")} with host="{host}"
   (and {where} when you know it): the edge, site, VPN and the edge interface it sits behind.
   A user name: {tool_ref("ise_find_session")} for "{host}" (ISE, {OPTIONAL}) gives the MAC, IP
   and the switch or WLC (NAD); then catsdwan_find_host with that IP. Catalyst Center
   ({NO_CATC}): {tool_ref("catc_find_host")} (mac, ip or user) names the switch port or AP, SSID
   and the CatC site path. Neither finds it: ask the user for the site.
2. Wi-Fi and LAN, the client itself (Catalyst Center, {NO_CATC}): {tool_ref("catc_client_360")}
   with the MAC: health score, wired or wireless, onboarding (association, AAA, DHCP) times and
   failures, RSSI/SNR and AP for wireless, switch and port for wired, its issues.
3. Wi-Fi and LAN, the site (Catalyst Center, {NO_CATC}): {tool_ref("catc_site_health_report")}
   with the CatC site path (client and device health, issues over 24 h), and
   {tool_ref("catc_list_device_health")} with site=<that path> and health="POOR": the access
   switch, WLC or AP that pulls the site down.
4. WAN, the site: {tool_ref("catsdwan_site_health")} with {where} (the Manager's verdict: devices,
   tunnels, apps), then {tool_ref("catsdwan_tunnel_health")} with {where} and history=true (when
   were tunnels bad?).
5. WAN, the path quality: {tool_ref("catsdwan_app_route_stats")} with {where} (loss %, latency,
   jitter per colour, worst first; source='realtime' if the problem is now), with
   sla_class=<the class the user's application maps to> from
   {tool_ref("catsdwan_list_sla_classes")} when there is one; and
   {tool_ref("catsdwan_bfd_sessions")} with device=<the edge from step 1> and state="not_up".
6. Lab conditions (CML, {OPTIONAL}): {tool_ref("cml_get_link_scenarios")} with lab="{lab_}". A
   lossy-wifi scenario on the host's access link is a deliberate Wi-Fi/LAN fault; brownout,
   wan-satellite or flap on an edge's transport link is a deliberate WAN fault. Name it.

Verdict, one line per layer (Wi-Fi, LAN, WAN): fine, degraded or down, with the numbers that
show it (client health and RSSI/SNR or onboarding failures; switch or port health and errors;
site/tunnel health and the SLA the path misses). A layer whose data was skipped is "not
checked", never "fine". Then ONE sentence: "It is the <layer>", or "the network looks clean:
look at the application or the device", and the next tool to run."""

    @reg.prompt(
        title="Is it the network or ISE?",
        uses=["catsdwan", "ise"],
        example={"site": "200", "nad": "br1-sw1", "host": "aa:bb:cc:00:02:00"},
    )
    def catsdwan_network_or_ise(
        site: Site,
        nad: Annotated[
            str,
            Field(description="The branch switch or WLC as ISE knows it (NAD name or IP; blank = every NAD)"),
        ] = "",
        host: Annotated[
            str, Field(description="A user or MAC that fails to log in (blank = the site's failures)")
        ] = "",
        minutes: Annotated[str, Field(description="How far back to look, in minutes (blank = 60)")] = "",
    ) -> str:
        """Logins fail or are slow at this branch: is it the network or ISE? The overlay path from the site
        to ISE's data centre (BFD, OMP route, app-route loss and latency), RADIUS latency and timeouts per
        NAD as ISE saw them (ise_nad_radius_stats), then policy (ise_why_auth_failed); a verdict naming the
        network, ISE or the policy."""
        mins = minutes.strip() or "60"
        nad_ = f'nad="{nad.strip()}"' if nad.strip() else "nad=<each NAD at the site>"
        who = host.strip()
        policy = (
            f'{tool_ref("ise_why_auth_failed")} for "{who}" (MAC, or username)'
            if who
            else f"{tool_ref('ise_recent_auth_failures')} for the site's NADs, then "
            f"{tool_ref('ise_why_auth_failed')} for the newest failing MAC"
        )
        return f"""Find out whether the login problems at SD-WAN site {site} are the network (the overlay
between the branch and ISE), ISE itself, or the policy. Read-only: change nothing.

1. Where is ISE? {tool_ref("ise_deployment_health")} (ISE, {OPTIONAL}; without it, ask the user
   for the PSN addresses): the PSNs, their IPs and health. Then {tool_ref("catsdwan_find_host")}
   with host=<each PSN IP>: the data-centre site and edge (the hub) ISE sits behind, and its VPN.
2. The branch: {tool_ref("catsdwan_list_devices")} with site="{site}" (the edge(s), system IPs,
   reachability).
3. Overlay path, branch edge to the DC edge:
   - {tool_ref("catsdwan_omp_routes")} with device=<branch edge>, vpn=<ISE's VPN> and
     prefix=<PSN IP>: is there a route to ISE, from which TLOCs, installed or not?
   - {tool_ref("catsdwan_bfd_sessions")} with device=<branch edge> and remote=<DC edge system
     IP>: which colours are up towards the DC.
   - {tool_ref("catsdwan_app_route_stats")} with device=<branch edge> and remote=<DC edge>
     (source='realtime' for now): loss %, latency and jitter per colour. EAP needs several round
     trips through the NAD, so 20 % loss or 300 ms there is enough to time logins out.
   - Optional proof: {tool_ref("catsdwan_ping")} from the branch edge to the PSN IP in that VPN
     (count 5).
4. RADIUS as ISE saw it: {tool_ref("ise_nad_radius_stats")} with {nad_}, since_minutes={mins}
   and compare_previous=true: attempts, response time (median, p95, max), timeouts (NAD or
   supplicant stopped answering) per NAD and the PSN that answered, against the previous window.
   No records at all from a NAD that should be sending: RADIUS isn't reaching ISE (path, wrong
   secret or unknown NAD: {tool_ref("ise_get_nad")} for the NAD).
5. Policy: {policy}: the decoded failure reason, the rule and authorization profile.

Verdict, ONE sentence first, one of:
- the network: no OMP route or BFD down to the DC, or loss/latency on the path to ISE, and
  RADIUS times or timeouts that follow it (EAP slow, MAB normal);
- ISE: the overlay is clean but response times are high for every NAD, or a PSN is unhealthy
  or not answering;
- the policy: requests reach ISE quickly and are rejected (name the failure reason and the rule);
- none of these: logins pass; look at the client or the access layer.
Then the evidence per step and the next action."""

    @reg.prompt(
        title="SD-WAN site down: power, underlay or overlay?",
        uses=["catsdwan", "catc", "ise", "cml"],
        example={"site": "200", "lab": LAB},
    )
    def catsdwan_site_down(site: Site, lab: CmlLab = "") -> str:
        """The branch is down: is it power, the underlay (transport circuits) or the overlay (control and
        BFD)? Edge reachability, control connections with their failure reasons, BFD and the last alarms,
        then the switches behind the edge (Catalyst Center health), when ISE last heard from the site's NADs,
        and in the CML lab the edge's console log; a verdict: power, underlay, overlay or not down."""
        lab_ = _lab(lab)
        return f"""SD-WAN site {site} is reported down. Find out whether it is power, the underlay or the
overlay. Read-only: change nothing.

1. Edges: {tool_ref("catsdwan_list_devices")} with site="{site}": each edge's reachability,
   status and uptime (a recent uptime = it rebooted).
2. Control plane, per edge: {tool_ref("catsdwan_control_connections")} with device=<host> and
   include_history=true: connections to the controller and Manager per colour, and the failed
   attempts with their reason (DTLS/TLS timeout = no path; certificate, org or not in the list =
   overlay configuration).
3. Data plane, per edge: {tool_ref("catsdwan_bfd_sessions")} with device=<host>: up/down per
   colour. Every colour down but the control plane up on one = a transport is gone.
4. Alarms and timeline: {tool_ref("catsdwan_list_alarms")} with site="{site}" and
   since_hours=24, then {tool_ref("catsdwan_recent_activity")} with site="{site}": the first
   alarm (interface down, control or BFD down, reboot) and any change just before it.
5. Behind the edge (Catalyst Center, {NO_CATC}): {tool_ref("catc_list_device_health")} with
   site=<the CatC path of this branch>: are the switches still reachable and healthy? A switch
   that is fine while the edge is not points at the edge or the WAN, not the site's power.
6. ISE ({OPTIONAL}): {tool_ref("ise_get_auth_list")} with nad=<each branch switch or WLC> and
   since_minutes=240: when ISE last heard RADIUS from the site. Silence since the outage began
   with the switches healthy = the path to ISE is gone (WAN), not the switches.
7. The edge itself (CML, {OPTIONAL}; on hardware ask whoever is on site to check power and
   circuit LEDs): {tool_ref("cml_get_node_console_log")} with lab="{lab_}", node=<edge> and
   lines=200: no output or a boot loop = power or the box; "%LINEPROTO" / "%LINK" down on a
   transport interface = underlay; "%Cisco-SDWAN" control, OMP or BFD messages with the interface
   up = overlay. Then {tool_ref("cml_get_link_scenarios")} with lab="{lab_}": a flap or brownout
   on a transport link is a deliberate fault.

Verdict, ONE line first:
- power (or the box): the edge and the site's switches are unreachable, ISE has heard nothing
  from the site, and the console is silent or rebooting;
- underlay: the edge is alive (console, switches fine) but its transport interfaces are down or
  have no path (control attempts time out on every colour);
- overlay: transports are up, but control connections fail with a configuration reason
  (certificate, validity, org), or OMP/BFD are down while the underlay answers;
- not down: control and BFD are up; say what is degraded instead (catsdwan_branch_health).
Then the evidence per step and the next tool to run."""

    @reg.prompt(
        title="SD-WAN brownout drill (CML lab)",
        uses=["catsdwan", "cml"],
        example={"site": "200", "lab": LAB, "scenario": "brownout"},
    )
    def catsdwan_brownout_drill(
        site: Site,
        lab: CmlLab = "",
        scenario: Annotated[
            str,
            Field(
                description="CML link scenario to apply to each transport in turn: brownout, "
                "wan-satellite, lossy-wifi or flap (blank = brownout)"
            ),
        ] = "",
        sla_class: Annotated[
            str, Field(description="Only report this SLA class (blank = every class the policy uses)")
        ] = "",
    ) -> str:
        """Brownout drill in the CML lab: degrade each transport of the branch in turn with
        cml_apply_link_scenario, watch app-aware routing move (or not move) each SLA class to the other
        colour, report what each class did, and clear the scenario. The CML writes are preview-first; the
        SD-WAN side is read-only."""
        lab_ = _lab(lab)
        scen = scenario.strip() or "brownout"
        classes = (
            f'sla_class="{sla_class.strip()}"'
            if sla_class.strip()
            else "sla_class=<each class the site's app-route policy uses>"
        )
        return f"""Run a {scen} drill on the transports of SD-WAN site {site} in CML lab "{lab_}" and report
what app-aware routing did for each SLA class.

This drill CHANGES THE LAB: {tool_ref("cml_apply_link_scenario")} and
{tool_ref("cml_clear_link_scenarios")} are write tools on the CML server and PREVIEW-FIRST: show
each preview (the link and the netem values), wait for the user's approval, then repeat the
identical call with the confirm token. Only touch the links of this site's edges in this lab;
never a production device. Everything on the SD-WAN Manager is read-only. If any step fails, still
clear the scenario before you stop.

1. Baseline:
   - {tool_ref("catsdwan_list_devices")} with site="{site}": the edge(s).
   - {tool_ref("catsdwan_list_sla_classes")}: the classes and the app-route policies that use
     them (a class no activated policy uses steers nothing: say so).
   - {tool_ref("catsdwan_bfd_sessions")} with device=<edge>: the colours that are up.
   - {tool_ref("cml_get_lab_topology")} with lab="{lab_}": the edge's transport links (in the
     cat-sdwan-fabric recipe GigabitEthernet1 is on 'mpls', GigabitEthernet2 on 'inet', so
     '<edge>:GigabitEthernet1<->mpls:portN' is the mpls colour). Check against
     {tool_ref("catsdwan_list_tlocs")} with device=<edge> if unsure.
   - {tool_ref("cml_get_link_scenarios")} with lab="{lab_}": no scenario may be on those links
     already (clear it first, preview-first, or stop and ask).
   - {tool_ref("catsdwan_app_route_stats")} with site="{site}", source='realtime' and
     {classes}: loss, latency, jitter and meets/misses per tunnel and colour, before.
   - {tool_ref("catsdwan_tunnel_path")} with device=<edge>, destination=<a host at the hub>,
     vpn=<service VPN> (once per class's DSCP or app if the policy matches on them): the colour
     each class takes now.
2. For each transport colour, one at a time:
   a. {tool_ref("cml_apply_link_scenario")} with lab="{lab_}", link=<that colour's link of the
      edge>, scenario="{scen}" (preview, approval, confirm).
   b. Wait for detection: BFD sees loss within seconds, app-route decisions use the poll
      interval x multiplier (about 10 minutes by default); poll every 2-3 minutes, at most 15.
   c. {tool_ref("catsdwan_app_route_stats")} with site="{site}", source='realtime' and
      {classes}: the degraded colour should now miss the SLA.
   d. {tool_ref("catsdwan_tunnel_path")} as in step 1: did each class move to the other colour?
      {tool_ref("catsdwan_bfd_sessions")} with device=<edge>: did BFD drop it (flap) or keep it
      up and lossy (brownout)?
   e. {tool_ref("cml_check_reachability")} in lab "{lab_}" from the branch host to the hub host:
      what the user sees (loss %, RTT).
   f. {tool_ref("cml_clear_link_scenarios")} with lab="{lab_}" and link=<that link> (preview,
      approval, confirm), then wait until app_route_stats meets the SLA on that colour again
      before the next colour; note how long it took.
3. After the last colour: {tool_ref("cml_get_link_scenarios")} with lab="{lab_}" shows no
   scenario left on this site's links, and {tool_ref("catsdwan_list_alarms")} with
   site="{site}" names the alarms the drill raised.

Report a table: transport degraded, SLA class, colour before / during / after, met the SLA
during (yes/no), time to move and time to recover, and the user's loss/RTT. Then ONE sentence per
class: failed over as designed, stayed on the degraded colour (no fallback or no policy), or lost
traffic; and the next step for anything that did not fail over."""
