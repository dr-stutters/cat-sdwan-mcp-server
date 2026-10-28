# catsdwan_why_is_app_slow

title: Why is this app slow over SD-WAN?
arguments: {"app": "ssh to 10.61.100.10", "host": "10.61.200.10", "lab": "mcp-lab-sdwan"}

Why is this application slow for this user or host? Find the host's site (ISE session or
NetBox), read the app-route loss, latency and jitter on each transport against the SLA class, the
policy that picks the path, the firewall leg where an FTD sits behind the edge, and CML link
conditions, then say in one sentence where the delay is.

## user

Find where ssh to 10.61.100.10 is slow for 10.61.200.10.
Read-only: change nothing; suggest fixes, don't apply them.

1. Where is the host? ISE (skipped if that server is not connected: say so in one line and go on): `ise_find_session` for "10.61.200.10" (IP, MAC
   or user): its IP, the switch (NAD) and so the site. Otherwise NetBox (skipped if that server is not connected: say so in one line and go on):
   `netbox_lookup_ip` for the IP, which names the prefix and its site. Otherwise ask
   the user for the site. Map it to the SD-WAN site id and its edge(s) with
   `catsdwan_list_devices` (site=<site id>).
2. The path: `catsdwan_bfd_sessions` with device=<the branch edge>: which colours
   are up towards the site that hosts ssh to 10.61.100.10 (a data centre or hub site, or the internet
   breakout).
3. Path quality per transport: `catsdwan_app_route_stats` with
   device=<the branch edge> and window_hours=1 (and once with source='realtime'): loss %,
   latency and jitter per tunnel and colour, worst first.
4. The SLA: `catsdwan_list_sla_classes` names the SLA classes and the app-route
   policies that use them; the class ssh to 10.61.100.10 is matched to is the policy's (ask the user if it
   isn't clear: per-application policy reads come with a later tool). Run step 3 again with
   sla_class=<that class>: does the tunnel ssh to 10.61.100.10 uses meet it, and does another colour meet it
   while the chosen one doesn't (then the policy isn't steering it, or it has no fallback)?
5. Recent changes and alarms on that edge: `catsdwan_recent_activity` with
   device=<the edge>.
6. The firewall leg (FMC, skipped if that server is not connected: say so in one line and go on): if an FTD sits behind the edge
   (`fmc_list_devices`), run `fmc_packet_tracer` for the host's IP to
   the application's server and port: a drop, an inspection (decryption, IPS) or a slow NAT
   path there explains slowness the SD-WAN statistics don't show.
7. Lab conditions (CML, skipped if that server is not connected: say so in one line and go on): `cml_get_link_scenarios` in lab "mcp-lab-sdwan": a
   lossy-wifi or wan-satellite scenario on the branch host's link or a transport link is a
   deliberate cause; name it.

Answer in ONE sentence first: where the delay is (the host's access link, a transport colour
and its SLA miss, the policy picking the wrong path, the firewall, or the application side when
the overlay is clean), with the numbers that show it. Then the evidence per step, and the next
action.
