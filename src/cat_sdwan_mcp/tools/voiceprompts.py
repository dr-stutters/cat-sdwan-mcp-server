"""W56 voice prompt (core `@reg.prompt`, scenario C61 voice/collab SLA): catsdwan_why_is_voice_bad.

"Voice is bad at this branch" needs four layers read together: the overlay against the voice SLA class
(app-route loss, latency and jitter per transport), the edge's QoS (the class map that puts EF/DSCP 46 in the
low-latency queue and the per-queue drops), the Wi-Fi QoS of the caller (Catalyst Center client 360 and the
WLAN's QoS/WMM), and the caller's ISE session (authorization profile, dACL and SGT, re-authentications).
Read-only. Like the other prompts, the legs on other servers say "skipped if not connected"; without a host
the client legs (ISE session, Wi-Fi) are left out and the verdict says they were not checked.

The default SLA classes on a 20.x Manager include Voice-And-Video and Realtime; a custom voice class (e.g.
mcp-voice-sla) is just as likely, so the prompt asks catsdwan_list_sla_classes instead of assuming a name.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from cat_sdwan_mcp._core import ToolRegistrar, tool_ref
from cat_sdwan_mcp.tools.prompts import LAB, OPTIONAL, CmlLab, _lab, default_lab
from cat_sdwan_mcp.tools.triage import NO_CATC

VOICE_DSCP = 46  # EF: RFC 4594 telephony, the class every Cisco QoS model puts in the priority queue


def _client_legs(host: str) -> str:
    """Steps 7-8, the caller's own Wi-Fi and ISE session; a note instead when no host was given."""
    if not host:
        return """7. Wi-Fi and 8. ISE: no host was given, so the caller's Wi-Fi QoS and ISE session are NOT
   checked; say so in the verdict ("Wi-Fi: not checked", "ISE: not checked"), and suggest running
   this prompt again with the caller's IP, MAC or user name if the overlay and the edge are clean."""
    return f"""7. Wi-Fi (Catalyst Center, {NO_CATC}): {tool_ref("catc_client_360")} for "{host}" (its MAC
   from step 1): wired or wireless, health score, RSSI/SNR, AP, SSID, roaming and onboarding
   failures. Wireless: {tool_ref("catc_get_wlc_config")} for the WLC that serves the SSID: the
   WLAN's QoS level (voice needs platinum, or a policy profile that trusts DSCP), WMM allowed or
   required, and CAC/voice settings. A poor RSSI/SNR, a silver/bronze QoS level or WMM off is a
   Wi-Fi cause the WAN statistics never show.
8. ISE ({OPTIONAL}): {tool_ref("ise_find_session")} for "{host}": the authorization profile, dACL
   and SGT the caller got, and when it last authenticated. A dACL or SGT that doesn't match the
   voice policy (a phone landing in the data VLAN or a guest profile), or re-authentications every
   few minutes (each one a gap in the call), is an ISE cause."""


def register(reg: ToolRegistrar) -> None:
    lab_default = default_lab(reg)

    @reg.prompt(
        title="Why is voice bad over SD-WAN?",
        uses=["catsdwan", "catc", "ise", "cml"],
        example={"site": "200", "host": "198.51.100.10", "lab": LAB},
    )
    def catsdwan_why_is_voice_bad(
        site: Annotated[str, Field(description="SD-WAN site id or name of the branch, e.g. '200'")],
        host: Annotated[
            str,
            Field(
                description="The caller's IP, MAC or user name (blank = site-level only: the Wi-Fi and ISE "
                "legs are skipped)"
            ),
        ] = "",
        sla_class: Annotated[
            str,
            Field(description="The voice SLA class (blank = find it with catsdwan_list_sla_classes)"),
        ] = "",
        lab: CmlLab = "",
    ) -> str:
        """Why is voice bad at this branch? The voice SLA class and app-route loss, latency and jitter per
        transport, the path voice (DSCP 46) takes, the edge's QoS map and per-queue drops, the caller's
        Wi-Fi QoS (Catalyst Center) and ISE session, and CML link conditions; ends in a verdict naming the
        cause: a transport, a queue, the Wi-Fi or ISE."""
        lab_ = _lab(lab, lab_default)
        site_ = site.strip()
        host_ = host.strip()
        sla = sla_class.strip()
        cls = f'sla_class="{sla}"' if sla else "sla_class=<the voice class from step 2>"
        find_cls = (
            f'{tool_ref("catsdwan_list_sla_classes")} with name="{sla}": its loss, latency and\n'
            "   jitter limits and the app-route policies that use it."
            if sla
            else f"{tool_ref('catsdwan_list_sla_classes')}: pick the class voice is mapped to\n"
            "   (Voice-And-Video, Realtime or a custom voice class used by the app-route policy; ask the\n"
            "   user if two fit), with its loss, latency and jitter limits."
        )
        locate = (
            f'{tool_ref("catsdwan_find_host")} with host="{host_}" and site="{site_}": the edge,\n'
            "   VPN and LAN interface the caller sits behind (a user name: "
            f"{tool_ref('ise_find_session')} first\n   for its IP, {OPTIONAL}).\n   Then "
            if host_
            else ""
        )
        return f"""Find out why voice is bad at SD-WAN site {site_}{f" for {host_}" if host_ else ""}, and
name the cause: a transport, a queue on the edge, the Wi-Fi or ISE.
Read-only: change nothing; suggest fixes, don't apply them.

1. The edges: {locate}{tool_ref("catsdwan_list_devices")} with site="{site_}" (host names, system
   IPs, reachability). No edge at the site: stop and say so.
2. The voice SLA class: {find_cls}
3. Each transport against it: {tool_ref("catsdwan_app_route_stats")} with site="{site_}" and
   {cls} (window_hours=1; then once per edge with source='realtime' when the complaint is now):
   loss %, latency and jitter per tunnel and local colour, meets or misses. Voice needs roughly
   loss < 1 %, latency < 150 ms one way and jitter < 30 ms when the class doesn't say. When did it
   start? {tool_ref("catsdwan_sla_history")} with site="{site_}" and {cls}.
4. The path voice takes: {tool_ref("catsdwan_tunnel_path")} on the edge with the voice VPN,
   protocol udp and dscp={VOICE_DSCP} (EF) to the far end of the call (the hub or the other
   branch): the colour the policy picks and the eligible paths. Voice on a colour that misses
   the SLA while another meets it means the app-route policy isn't steering it (no SLA match,
   no fallback, or the DSCP doesn't reach the edge).
5. The QoS map on the edge: {tool_ref("catsdwan_get_device_config")} with device=<the edge>:
   the class-map / policy-map (QoS map) on the WAN interfaces: is DSCP 46 matched into the
   priority (low-latency) queue 0, with bandwidth for it, and is a shaper set to the circuit
   rate? No QoS map on a WAN interface: the edge queues voice with everything else.
6. Queue drops and load on the edge: {tool_ref("catsdwan_device_state")} with feature="qos" and
   device=<the edge> (per-tunnel QoS sessions and per-interface queue statistics: drops in the
   voice/priority queue, or in the queue voice is wrongly put in), and
   {tool_ref("catsdwan_interface_stats")} with device=<the edge> and qos=true (is the WAN link
   near its bandwidth, per-queue drops over the window).
{_client_legs(host_)}
9. Lab conditions (CML, {OPTIONAL}): {tool_ref("cml_get_link_scenarios")} with lab="{lab_}". A
   wan-satellite, brownout or flap scenario on one edge transport link is a deliberate transport
   fault; lossy-wifi on the caller's access link is a deliberate Wi-Fi fault. Name it.

Verdict, one line per layer: transport (per colour: meets or misses the voice SLA, with loss,
latency and jitter), queue (QoS map present, voice in the priority queue, drops), Wi-Fi and ISE
(fine, a problem, or "not checked" when its leg was skipped: never "fine" without the data).
Then ONE sentence naming the cause, e.g. "voice rides biz-internet, which misses Voice-And-Video
on jitter (48 ms) while mpls meets it: the app-route policy has no fallback", "priority-queue drops
on GigabitEthernet2: the shaper is above the circuit rate", "the caller is on a silver-QoS SSID",
or "the overlay and the edge are clean: look at the phone, the call manager or the far end", and
the next tool to run."""
