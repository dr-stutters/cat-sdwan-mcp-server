# catsdwan_wifi_lan_or_wan

title: Is it the Wi-Fi, the LAN or the WAN?
arguments: {"host": "10.61.200.10", "lab": "mcp-lab-sdwan", "site": "200"}

Is this user's problem the Wi-Fi, the LAN or the WAN? Locate the host (catsdwan_find_host, ISE
session, Catalyst Center), read the client's own health and the access layer at the site (client
360, site health, switch and AP health) against the SD-WAN site and tunnel health and app-route SLA,
then give a verdict per layer (Wi-Fi, LAN, WAN) and name the one at fault.

## user

Find out whether 10.61.200.10's problem is the Wi-Fi, the LAN or the WAN, one verdict per
layer. Read-only: change nothing; suggest fixes, don't apply them.

1. Locate the host. An IP or MAC: `catsdwan_find_host` with host="10.61.200.10"
   (and site="200" when you know it): the edge, site, VPN and the edge interface it sits behind.
   A user name: `ise_find_session` for "10.61.200.10" (ISE, skipped if that server is not connected: say so in one line and go on) gives the MAC, IP
   and the switch or WLC (NAD); then catsdwan_find_host with that IP. Catalyst Center
   (skipped when Catalyst Center is not connected or does not manage this site's access layer (switches, WLC, APs): say so in one line and judge from the other layers): `catc_find_host` (mac, ip or user) names the switch port or AP, SSID
   and the CatC site path. Neither finds it: ask the user for the site.
2. Wi-Fi and LAN, the client itself (Catalyst Center, skipped when Catalyst Center is not connected or does not manage this site's access layer (switches, WLC, APs): say so in one line and judge from the other layers): `catc_client_360`
   with the MAC: health score, wired or wireless, onboarding (association, AAA, DHCP) times and
   failures, RSSI/SNR and AP for wireless, switch and port for wired, its issues.
3. Wi-Fi and LAN, the site (Catalyst Center, skipped when Catalyst Center is not connected or does not manage this site's access layer (switches, WLC, APs): say so in one line and judge from the other layers): `catc_site_health_report`
   with the CatC site path (client and device health, issues over 24 h), and
   `catc_list_device_health` with site=<that path> and health="POOR": the access
   switch, WLC or AP that pulls the site down.
4. WAN, the site: `catsdwan_site_health` with site="200" (the Manager's verdict: devices,
   tunnels, apps), then `catsdwan_tunnel_health` with site="200" and history=true (when
   were tunnels bad?).
5. WAN, the path quality: `catsdwan_app_route_stats` with site="200" (loss %, latency,
   jitter per colour, worst first; source='realtime' if the problem is now), with
   sla_class=<the class the user's application maps to> from
   `catsdwan_list_sla_classes` when there is one; and
   `catsdwan_bfd_sessions` with device=<the edge from step 1> and state="not_up".
6. Lab conditions (CML, skipped if that server is not connected: say so in one line and go on): `cml_get_link_scenarios` with lab="mcp-lab-sdwan". A
   lossy-wifi scenario on the host's access link is a deliberate Wi-Fi/LAN fault; brownout,
   wan-satellite or flap on an edge's transport link is a deliberate WAN fault. Name it.

Verdict, one line per layer (Wi-Fi, LAN, WAN): fine, degraded or down, with the numbers that
show it (client health and RSSI/SNR or onboarding failures; switch or port health and errors;
site/tunnel health and the SLA the path misses). A layer whose data was skipped is "not
checked", never "fine". Then ONE sentence: "It is the <layer>", or "the network looks clean:
look at the application or the device", and the next tool to run.
