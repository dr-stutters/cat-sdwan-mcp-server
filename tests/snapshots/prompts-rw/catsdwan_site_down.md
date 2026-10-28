# catsdwan_site_down

title: SD-WAN site down: power, underlay or overlay?
arguments: {"lab": "mcp-lab-sdwan", "site": "200"}

The branch is down: is it power, the underlay (transport circuits) or the overlay (control and
BFD)? Edge reachability, control connections with their failure reasons, BFD and the last alarms,
then the switches behind the edge (Catalyst Center health), when ISE last heard from the site's NADs,
and in the CML lab the edge's console log; a verdict: power, underlay, overlay or not down.

## user

SD-WAN site 200 is reported down. Find out whether it is power, the underlay or the
overlay. Read-only: change nothing.

1. Edges: `catsdwan_list_devices` with site="200": each edge's reachability,
   status and uptime (a recent uptime = it rebooted).
2. Control plane, per edge: `catsdwan_control_connections` with device=<host> and
   include_history=true: connections to the controller and Manager per colour, and the failed
   attempts with their reason (DTLS/TLS timeout = no path; certificate, org or not in the list =
   overlay configuration).
3. Data plane, per edge: `catsdwan_bfd_sessions` with device=<host>: up/down per
   colour. Every colour down but the control plane up on one = a transport is gone.
4. Alarms and timeline: `catsdwan_list_alarms` with site="200" and
   since_hours=24, then `catsdwan_recent_activity` with site="200": the first
   alarm (interface down, control or BFD down, reboot) and any change just before it.
5. Behind the edge (Catalyst Center, skipped when Catalyst Center is not connected or does not manage this site's access layer (switches, WLC, APs): say so in one line and judge from the other layers): `catc_list_device_health` with
   site=<the CatC path of this branch>: are the switches still reachable and healthy? A switch
   that is fine while the edge is not points at the edge or the WAN, not the site's power.
6. ISE (skipped if that server is not connected: say so in one line and go on): `ise_get_auth_list` with nad=<each branch switch or WLC> and
   since_minutes=240: when ISE last heard RADIUS from the site. Silence since the outage began
   with the switches healthy = the path to ISE is gone (WAN), not the switches.
7. The edge itself (CML, skipped if that server is not connected: say so in one line and go on; on hardware ask whoever is on site to check power and
   circuit LEDs): `cml_get_node_console_log` with lab="mcp-lab-sdwan", node=<edge> and
   lines=200: no output or a boot loop = power or the box; "%LINEPROTO" / "%LINK" down on a
   transport interface = underlay; "%Cisco-SDWAN" control, OMP or BFD messages with the interface
   up = overlay. Then `cml_get_link_scenarios` with lab="mcp-lab-sdwan": a flap or brownout
   on a transport link is a deliberate fault.

Verdict, ONE line first:
- power (or the box): the edge and the site's switches are unreachable, ISE has heard nothing
  from the site, and the console is silent or rebooting;
- underlay: the edge is alive (console, switches fine) but its transport interfaces are down or
  have no path (control attempts time out on every colour);
- overlay: transports are up, but control connections fail with a configuration reason
  (certificate, validity, org), or OMP/BFD are down while the underlay answers;
- not down: control and BFD are up; say what is degraded instead (catsdwan_branch_health).
Then the evidence per step and the next tool to run.
