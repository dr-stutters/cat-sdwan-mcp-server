"""W54 resilience drills (core `@reg.prompt`, scenario C58 hub/DC failover): catsdwan_hub_failover_drill.

Hub loss is the biggest SD-WAN outage: every branch tunnel to the data centre ends on the hub. The drill takes
one hub down, proves that each branch moves each service VPN to the other hub (OMP routes, TLOC preference,
the policy's path), that each SLA class still meets its SLA, and that the data-centre services (ISE, DHCP,
the FTD) still answer; then it restores the hub and compares a snapshot taken before with one taken after.

Separate from triage.py's catsdwan_brownout_drill (one branch, its transports degraded in turn). The SD-WAN
side is read-only. The hub goes down in a CML lab with cml_set_link_state (transport links, a cable pull) or
cml_set_node_state (power), both preview-first on the CML server; without a lab the operator takes the hub
down by hand and the prompt waits. The restore step is always part of the drill, and the prompt says to run it
even when a step fails.

Which hub: the `hub` argument, else CATSDWAN_HUB_DEVICES, else the same evidence the change tiering uses
when that setting is unset (#102): the hub sites of a hub-and-spoke topology, or the edge whose BFD sessions
reach every other site. The prompt only describes that resolution (text), it reads nothing while rendering.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from cat_sdwan_mcp._core import ToolRegistrar, tool_ref
from cat_sdwan_mcp.tools.prompts import LAB, OPTIONAL

METHODS = {"links", "node"}


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _hub_step(hub: str, configured: str | None) -> str:
    """Step 1b: which hub to fail. Text only: nothing is read while the prompt renders."""
    if hub.strip():
        return f"""The hub to fail is "{hub.strip()}" (given). Check it in catsdwan_list_devices: it must
   be a WAN edge (personality vedge), never a Manager, Controller or Validator."""
    hubs = _csv(configured or "")
    if hubs:
        named = ", ".join(f'"{h}"' for h in hubs)
        return f"""The hubs are the ones this server is configured with (CATSDWAN_HUB_DEVICES): {named}.
   Several: ask the user which one to fail (one per drill). Check it in catsdwan_list_devices: it
   must be a WAN edge (personality vedge), never a Manager, Controller or Validator."""
    return f"""No hub was given and CATSDWAN_HUB_DEVICES is not set, so find the hubs the way this
   server's change tiering does (#102), in this order:
   - Hub-and-spoke topology: {tool_ref("catsdwan_list_policies")} (the activated centralised
     policy), then {tool_ref("catsdwan_get_policy")} on it: the hub site list of each hub-and-spoke
     definition (site ranges count); the hubs are the edges at those sites.
   - BFD, when no hub-and-spoke topology names one: {tool_ref("catsdwan_bfd_sessions")} for the
     fabric (no device), sessions by local edge and remote site: an edge whose sessions reach
     every other site seen in BFD (at least two) is a hub; if every edge's do, it is a full mesh
     with no hub to fail: stop and say so.
   A hub found this way is "hub by heuristic": name the evidence (the policy, or the session count
   and sites) and ask the user to confirm it before going on; recommend setting
   CATSDWAN_HUB_DEVICES. Then check it in catsdwan_list_devices: a WAN edge (personality vedge),
   never a Manager, Controller or Validator."""


def register(reg: ToolRegistrar) -> None:
    configured_hubs: str | None = getattr(reg.settings, "hub_devices", None)

    @reg.prompt(
        title="SD-WAN hub failover drill",
        uses=["catsdwan", "cml", "ise", "fmc"],
        example={"hub": "hub1", "lab": LAB, "method": "links", "vpns": "10"},
    )
    def catsdwan_hub_failover_drill(
        hub: Annotated[
            str,
            Field(
                description="The hub edge to take down (host name or system IP; blank = "
                "CATSDWAN_HUB_DEVICES, else found from hub-and-spoke policy or BFD)"
            ),
        ] = "",
        lab: Annotated[
            str,
            Field(
                description=f"CML lab the hub runs in (title or id, e.g. '{LAB}'); blank = no CML lab: "
                "the operator takes the hub down by hand and the drill waits"
            ),
        ] = "",
        method: Annotated[
            str,
            Field(
                description="How the hub goes down in CML: 'links' (its transport links down, a cable "
                "pull; quick to restore) or 'node' (powered off; restore means a reboot) (blank = links)"
            ),
        ] = "",
        vpns: Annotated[
            str,
            Field(description="Service VPNs to check, comma-separated, e.g. '10,20' (blank = every one)"),
        ] = "",
        sites: Annotated[
            str,
            Field(description="Branch sites to check, comma-separated ids or names (blank = every branch)"),
        ] = "",
        dc_services: Annotated[
            str,
            Field(
                description="Data-centre service addresses to prove, comma-separated, e.g. "
                "'ISE 192.0.2.20, DHCP 192.0.2.30, FTD 192.0.2.40' (blank = find ISE and the FTD, ask "
                "for DHCP)"
            ),
        ] = "",
    ) -> str:
        """Hub failover drill: snapshot the fabric, take one hub down (in a CML lab with cml_set_link_state
        or cml_set_node_state, preview-first; by hand without one), then per branch and service VPN check
        that paths moved to the other hub (OMP routes, TLOC preference, catsdwan_explain_path), that each
        SLA class still meets its SLA, and that ISE, DHCP and the FTD in the data centre still answer;
        restore the hub, compare the snapshots and report. The SD-WAN side is read-only."""
        lab_ = lab.strip()
        how = method.strip().lower() or "links"
        if how not in METHODS:
            how = "links"
        vpn_list = _csv(vpns)
        vpn_note = (
            "service VPN (" + ", ".join(vpn_list) + ")"
            if vpn_list
            else "service VPN (every one: from catsdwan_omp_routes on a branch edge, the VPNs other "
            "than 0 and 512)"
        )
        site_list = _csv(sites)
        site_txt = ", ".join(f'"{s}"' for s in site_list) if site_list else "every branch site"
        svc_list = _csv(dc_services)
        if svc_list:
            services = "The data-centre services to prove: " + "; ".join(svc_list) + "."
        else:
            services = f"""Find the data-centre services: {tool_ref("ise_deployment_health")} (ISE,
     {OPTIONAL}) for the PSN addresses; {tool_ref("fmc_list_devices")} and
     {tool_ref("fmc_list_device_interfaces")} (FMC, {OPTIONAL}) for the DC FTD and its inside
     address; ask the user for the DHCP server (the branches' ip helper-address). For each address
     {tool_ref("catsdwan_find_host")} names the DC site, edge and VPN behind it."""

        if lab_:
            mode = f"""This drill CHANGES THE CML LAB "{lab_}": {tool_ref("cml_set_link_state")} and
{tool_ref("cml_set_node_state")} are write tools on the CML server and PREVIEW-FIRST: show each
preview (the lab, the node or link, the new state), wait for the user's approval, then repeat the
identical call with the confirm token. Only touch the chosen hub's node and links in this lab:
never a Manager, Controller or Validator node, never another edge."""
            locate = f"""{tool_ref("cml_get_lab_topology")} with lab="{lab_}": the hub's node and its
     transport links (in the cat-sdwan-fabric recipe GigabitEthernet1 is on 'mpls' and
     GigabitEthernet2 on 'inet', e.g. '<hub>:GigabitEthernet1<->mpls:portN'); check the colours with
     {tool_ref("catsdwan_list_tlocs")} with edge=<hub>. Never a link to VPN 512 (management)."""
            if how == "node":
                down = f"""{tool_ref("cml_set_node_state")} with lab="{lab_}", node=<hub>, state="stop"
   (preview, approval, confirm): a power loss. Note the time (T0)."""
                restore = f"""{tool_ref("cml_set_node_state")} with lab="{lab_}", node=<hub>,
   state="start" (preview, approval, confirm; it waits for the boot), then
   {tool_ref("cml_wait_for_converged")} with lab="{lab_}"."""
            else:
                down = f"""{tool_ref("cml_set_link_state")} with lab="{lab_}", link=<each transport link
   of the hub>, state="down" (preview, approval, confirm, one link at a time, back to back): the
   hub loses every colour. Note the time the last link went down (T0)."""
                restore = f"""{tool_ref("cml_set_link_state")} with lab="{lab_}", link=<each link taken
   down in step 2>, state="up" (preview, approval, confirm)."""
            reach = f"""In the lab: {tool_ref("cml_check_reachability")} with lab="{lab_}",
     nodes=<a host behind each branch edge>, targets=<the service addresses> and wait_seconds=60:
     what a user sees (success %, RTT)."""
        else:
            mode = """No CML lab: the hub is taken down by the operator (shut its transport interfaces,
or pull its power or circuits) on hardware, in an agreed window. You change nothing: tell the user
exactly what to take down, and wait until they say it is down. Never a Manager, Controller or
Validator, never another edge."""
            locate = f"""{tool_ref("catsdwan_list_tlocs")} with edge=<hub>: the hub's colours
     (transports) the operator must take down."""
            down = """Ask the user to take the hub down now (every transport, or its power) and to tell
   you when it is done. Note that time (T0)."""
            restore = """Ask the user to bring the hub back (transports up, or power on) and to tell you
   when it is done."""
            reach = "No lab: the edge pings above are the proof; ask the user to test from a branch host too."

        return f"""Run a hub failover drill: take one hub down and prove that the branches move to the other
hub, that each SLA class keeps its SLA and that the data-centre services still answer; then restore the
hub and show the fabric is back as it was.

{mode}
Everything on the SD-WAN Manager is read-only. Whatever fails, ALWAYS run step 7 (restore) before you
stop, and report what failed.

1. Before:
   a. {tool_ref("catsdwan_snapshot")} for the whole fabric (site=""): keep the blob as BEFORE.
   b. {_hub_step(hub, configured_hubs)}
   c. The other hub: the drill proves failover only if another hub (a second DC) carries the same
      VPNs. Without one, say that the branches will lose the DC for the drill's duration and ask
      the user whether to go on.
   d. {tool_ref("catsdwan_list_devices")}: the branches to check, {site_txt}, their edges and
      system IPs; all reachable before you start (one that is not: stop and say so).
   e. Paths, per branch edge and per {vpn_note}:
      - {tool_ref("catsdwan_omp_routes")} with device=<branch edge>, vpn=<VPN> and prefix=<a DC
        prefix>: the routes from each hub, their TLOCs, preference and which are installed;
      - {tool_ref("catsdwan_list_tlocs")} with edge=<each hub>: TLOC preference and weight (the
        primary hub should be preferred);
      - {tool_ref("catsdwan_explain_path")} with source_site=<branch site>, destination=<the DC
        prefix> and vpn=<VPN>: the policy's path (hub-and-spoke, TLOC lists, app-route).
   f. SLA per class: {tool_ref("catsdwan_list_sla_classes")} (classes and the policies that use
      them), then {tool_ref("catsdwan_app_route_stats")} with device=<branch edge>,
      remote=<each hub system IP>, source='realtime' and sla_class=<each class>: loss, latency,
      jitter and meets/misses.
   g. DC services. {services}
      Prove each from each branch edge: {tool_ref("catsdwan_ping")} with device=<branch edge>,
      destination=<service address>, vpn=<its VPN> and count=5.
   h. Where the hub sits: {locate}

2. Hub down: {down}

3. Convergence: {tool_ref("catsdwan_bfd_sessions")} with device=<branch edge> and
   remote=<hub system IP>: the sessions to the hub go down within seconds (hello x multiplier).
   {tool_ref("catsdwan_control_connections")} with device=<hub> shows it gone from the controllers.
   Poll every minute, at most 10.

4. Paths during, per branch and VPN, as in 1e: {tool_ref("catsdwan_omp_routes")} (the installed
   route now uses the other hub's TLOCs; the failed hub's routes may stay in the table under OMP
   graceful restart, up to 12 h by default, but must not be installed), {tool_ref("catsdwan_list_tlocs")}
   for the other hub, and {tool_ref("catsdwan_explain_path")}. Note how long after T0 each branch
   moved.

5. SLA during: {tool_ref("catsdwan_app_route_stats")} as in 1f with remote=<the other hub>:
   each class meets its SLA on the surviving paths, or which class misses and by how much.

6. DC services during: {tool_ref("catsdwan_ping")} as in 1g from each branch edge to each service
   (ISE, DHCP, FTD). {reach}
   ISE ({OPTIONAL}): {tool_ref("ise_deployment_health")}: the PSNs still healthy (a PSN that sits
   only in the failed hub's DC is expected to be unreachable: say so). FMC ({OPTIONAL}):
   {tool_ref("fmc_get_ha_status")} for the DC FTD pair, if it is one.

7. Restore (ALWAYS, also after a failure): {restore}
   Then {tool_ref("catsdwan_control_connections")} with device=<hub> until its controller and
   Manager connections are up on every colour, and {tool_ref("catsdwan_bfd_sessions")} with
   device=<hub> until every session is up (poll every minute, at most 15). Note the time to
   recover and whether traffic moved back to the preferred hub.

8. After: {tool_ref("catsdwan_snapshot")} again (site="") as AFTER, then
   {tool_ref("catsdwan_compare_snapshot")} with before=BEFORE and after=AFTER: anything not back as
   it was (devices, BFD, control, alarms); {tool_ref("catsdwan_list_alarms")} names the alarms the
   drill raised (they clear on their own; say which are still active).

Report a table: branch, VPN, path before (hub and TLOC) / during / after, time to move, each SLA
class met during (yes/no, with the numbers), each DC service reachable during (ISE, DHCP, FTD), and
the time to recover. Then ONE sentence per VPN: failed over as designed, failed over but missed an
SLA, or black-holed (no route via the other hub); the compare_snapshot verdict; and the next step
for anything that did not fail over."""
