# catsdwan_branch_health

title: SD-WAN branch health
arguments: {"lab": "mcp-lab-sdwan", "site": "200"}

Is this branch healthy? Device health, control connections, BFD and app-route loss, latency and
jitter per transport colour, alarms and recent activity, then a verdict per transport (healthy,
degraded, down); in a CML lab, the link scenarios say whether a degradation is deliberate.

## user

Report the health of SD-WAN site 200, one verdict per transport.
Read-only: change nothing.

1. Devices: `catsdwan_device_health` with site="200" (every edge at the site,
   health and the reason), and `catsdwan_list_devices` with site="200" for host
   names, system IPs and reachability. No edge at the site: stop and say so (NetBox:
   `netbox_site_summary` for "200" to check the site exists in the source of
   truth, skipped if that server is not connected: say so in one line and go on).
2. Control plane, per edge: `catsdwan_control_connections` with device=<host>.
   Every edge should have its controller (vsmart) and Manager (vmanage) connections up on each
   colour; name any that are not, with the failure reason the tool gives.
3. Data plane, per edge: `catsdwan_bfd_sessions` with device=<host> (state per
   local colour, by_colour_pair). A colour with no BFD session up is DOWN for that edge.
4. Quality, per colour: `catsdwan_app_route_stats` with site="200" and
   colour=<each colour seen in step 3> (loss %, latency, jitter, worst tunnels first;
   window_hours=1 for now, source='realtime' if the statistics are older than the problem). If
   the fabric has SLA classes (`catsdwan_list_sla_classes`), pass
   sla_class=<the one the site's traffic uses> to get meets / misses per tunnel.
5. Events: `catsdwan_list_alarms` with site="200" (active), then
   `catsdwan_recent_activity` with site="200" and since_hours=24 (alarms,
   events and who changed what, on one timeline).
6. Lab conditions (skipped if that server is not connected: say so in one line and go on): `cml_get_link_scenarios` with lab="mcp-lab-sdwan". A
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
healthy.
