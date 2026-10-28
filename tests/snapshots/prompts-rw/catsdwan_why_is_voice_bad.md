# catsdwan_why_is_voice_bad

title: Why is voice bad over SD-WAN?
arguments: {"host": "198.51.100.10", "lab": "mcp-cat-sdwan", "site": "200", "sla_class": "Voice-And-Video"}

Why is voice bad at this branch? The voice SLA class and app-route loss, latency and jitter per
transport, the path voice (DSCP 46) takes, the edge's QoS map and per-queue drops, the caller's
Wi-Fi QoS (Catalyst Center) and ISE session, and CML link conditions; ends in a verdict naming the
cause: a transport, a queue, the Wi-Fi or ISE.

## user

Find out why voice is bad at SD-WAN site 200 for 198.51.100.10, and
name the cause: a transport, a queue on the edge, the Wi-Fi or ISE.
Read-only: change nothing; suggest fixes, don't apply them.

1. The edges: `catsdwan_find_host` with host="198.51.100.10" and site="200": the edge,
   VPN and LAN interface the caller sits behind (a user name: `ise_find_session` first
   for its IP, skipped if that server is not connected: say so in one line and go on).
   Then `catsdwan_list_devices` with site="200" (host names, system
   IPs, reachability). No edge at the site: stop and say so.
2. The voice SLA class: `catsdwan_list_sla_classes` with name="Voice-And-Video": its loss, latency and
   jitter limits and the app-route policies that use it.
3. Each transport against it: `catsdwan_app_route_stats` with site="200" and
   sla_class="Voice-And-Video" (window_hours=1; then once per edge with source='realtime' when the complaint is now):
   loss %, latency and jitter per tunnel and local colour, meets or misses. Voice needs roughly
   loss < 1 %, latency < 150 ms one way and jitter < 30 ms when the class doesn't say. When did it
   start? `catsdwan_sla_history` with site="200" and sla_class="Voice-And-Video".
4. The path voice takes: `catsdwan_tunnel_path` on the edge with the voice VPN,
   protocol udp and dscp=46 (EF) to the far end of the call (the hub or the other
   branch): the colour the policy picks and the eligible paths. Voice on a colour that misses
   the SLA while another meets it means the app-route policy isn't steering it (no SLA match,
   no fallback, or the DSCP doesn't reach the edge).
5. The QoS map on the edge: `catsdwan_get_device_config` with device=<the edge>:
   the class-map / policy-map (QoS map) on the WAN interfaces: is DSCP 46 matched into the
   priority (low-latency) queue 0, with bandwidth for it, and is a shaper set to the circuit
   rate? No QoS map on a WAN interface: the edge queues voice with everything else.
6. Queue drops and load on the edge: `catsdwan_device_state` with feature="qos" and
   device=<the edge> (per-tunnel QoS sessions and per-interface queue statistics: drops in the
   voice/priority queue, or in the queue voice is wrongly put in), and
   `catsdwan_interface_stats` with device=<the edge> and qos=true (is the WAN link
   near its bandwidth, per-queue drops over the window).
7. Wi-Fi (Catalyst Center, skipped when Catalyst Center is not connected or does not manage this site's access layer (switches, WLC, APs): say so in one line and judge from the other layers): `catc_client_360` for "198.51.100.10" (its MAC
   from step 1): wired or wireless, health score, RSSI/SNR, AP, SSID, roaming and onboarding
   failures. Wireless: `catc_get_wlc_config` for the WLC that serves the SSID: the
   WLAN's QoS level (voice needs platinum, or a policy profile that trusts DSCP), WMM allowed or
   required, and CAC/voice settings. A poor RSSI/SNR, a silver/bronze QoS level or WMM off is a
   Wi-Fi cause the WAN statistics never show.
8. ISE (skipped if that server is not connected: say so in one line and go on): `ise_find_session` for "198.51.100.10": the authorization profile, dACL
   and SGT the caller got, and when it last authenticated. A dACL or SGT that doesn't match the
   voice policy (a phone landing in the data VLAN or a guest profile), or re-authentications every
   few minutes (each one a gap in the call), is an ISE cause.
9. Lab conditions (CML, skipped if that server is not connected: say so in one line and go on): `cml_get_link_scenarios` with lab="mcp-cat-sdwan". A
   wan-satellite, brownout or flap scenario on one edge transport link is a deliberate transport
   fault; lossy-wifi on the caller's access link is a deliberate Wi-Fi fault. Name it.

Verdict, one line per layer: transport (per colour: meets or misses the voice SLA, with loss,
latency and jitter), queue (QoS map present, voice in the priority queue, drops), Wi-Fi and ISE
(fine, a problem, or "not checked" when its leg was skipped: never "fine" without the data).
Then ONE sentence naming the cause, e.g. "voice rides biz-internet, which misses Voice-And-Video
on jitter (48 ms) while mpls meets it: the app-route policy has no fallback", "priority-queue drops
on GigabitEthernet2: the shaper is above the circuit rate", "the caller is on a silver-QoS SSID",
or "the overlay and the edge are clean: look at the phone, the call manager or the far end", and
the next tool to run.
