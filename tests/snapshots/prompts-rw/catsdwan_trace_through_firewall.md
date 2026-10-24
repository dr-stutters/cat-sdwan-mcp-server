# catsdwan_trace_through_firewall

title: Trace a flow through the SD-WAN service chain and the firewall
arguments: {"app": "tcp/22", "destination": "10.61.100.10", "source": "10.61.220.10", "vpn": "10"}

Which firewall does this flow cross, and what does it decide? Source host -> its edge -> the
SD-WAN path (catsdwan_explain_path) -> the service-chain hop (the FW service and the steering rule
that matches, or none) -> fmc_packet_tracer on the hub FTD (chained) or the branch FTD (inline) ->
verdict: allowed / blocked by <rule> on <FTD>, or not chained.

## user

Trace tcp/22 from 10.61.220.10 to 10.61.100.10 through the SD-WAN service chain and the
firewall(s) it crosses, and give the firewall's verdict with the rule that decides. Read-only: change
nothing; suggest fixes, don't apply them.

1. Where are the hosts? `catsdwan_find_host` with host="10.61.220.10", vpn="10", then
   host="10.61.100.10", vpn="10": each one's edge, site, VPN and interface. A host behind a branch
   firewall (an FTD between the edge's LAN interface and the hosts, e.g. alice/bob behind br1-ftd) is
   found by the route the edge has to its subnet: note that FTD as the branch firewall.
2. The SD-WAN path: `catsdwan_explain_path` with source_site=<the source edge's site>,
   destination="10.61.100.10", vpn=10, app or dscp when tcp/22 names one: the data-policy sequences that
   may override the path, the tunnels the flow takes, and the edge that delivers it.
3. The chain hop: `catsdwan_service_chains` with vpn=10, device=<the source edge>:
   the FW service (type, the firewall's address, tracking, the edge that advertises it) and the
   steering sequence that matches 10.61.220.10 -> 10.61.100.10 (local, restrict).
   Then device=<the hub edge> to see the service in OMP. A centralised data policy may steer instead:
   `catsdwan_get_policy`. No sequence matches: the flow is NOT chained (say so, and still
   trace the branch firewall if there is one).
4. Map the service address to an FTD (FMC, skipped if that server is not connected: say so in one line and go on): `fmc_find_address` or
   `fmc_list_devices` then `fmc_list_device_interfaces`: which FTD owns the
   service address (e.g. hub-ftd inside 10.61.110.2), its ingress interface for the chained traffic, and
   its egress back to the edge.
5. The firewall's verdict (FMC, skipped if that server is not connected: say so in one line and go on): `fmc_packet_tracer` on that FTD with the ingress
   interface from step 4, source 10.61.220.10, destination 10.61.100.10 and tcp/22: the verdict, the drop
   reason and the access rule that decides. For a branch firewall, trace there too (ingress = its inside
   interface). Cross-check offline with `fmc_rule_lookup` and whether the rule is hit with
   `fmc_get_hit_counts`; is the FTD itself healthy: `fmc_device_health`.

Verdict, ONE line first, one of:
- allowed by <rule> on <FTD>: chained at <edge> by <traffic policy / sequence> (and through <branch FTD>
  when there is one);
- blocked by <rule> on <FTD>: the drop reason, and which firewall (hub chain or branch);
- not chained: no steering sequence matches (the flow goes <path> without a firewall), or the service is
  not advertised (tracking withdrew it: restrict drops the flow, otherwise it routes around the firewall);
- chain broken: the service address is on no FTD interface, or the FTD's interface is down.
Then the evidence per step (path, chain, FTD, rule) and the next action (which rule, which sequence).
