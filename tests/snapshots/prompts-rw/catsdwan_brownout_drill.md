# catsdwan_brownout_drill

title: SD-WAN brownout drill (CML lab)
arguments: {"lab": "mcp-lab-sdwan", "scenario": "brownout", "site": "200", "sla_class": "example"}

Brownout drill in the CML lab: degrade each transport of the branch in turn with
cml_apply_link_scenario, watch app-aware routing move (or not move) each SLA class to the other
colour, report what each class did, and clear the scenario. The CML writes are preview-first; the
SD-WAN side is read-only.

## user

Run a brownout drill on the transports of SD-WAN site 200 in CML lab "mcp-lab-sdwan" and report
what app-aware routing did for each SLA class.

This drill CHANGES THE LAB: `cml_apply_link_scenario` and
`cml_clear_link_scenarios` are write tools on the CML server and PREVIEW-FIRST: show
each preview (the link and the netem values), wait for the user's approval, then repeat the
identical call with the confirm token. Only touch the links of this site's edges in this lab;
never a production device. Everything on the SD-WAN Manager is read-only. If any step fails, still
clear the scenario before you stop.

1. Baseline:
   - `catsdwan_list_devices` with site="200": the edge(s).
   - `catsdwan_list_sla_classes`: the classes and the app-route policies that use
     them (a class no activated policy uses steers nothing: say so).
   - `catsdwan_bfd_sessions` with device=<edge>: the colours that are up.
   - `cml_get_lab_topology` with lab="mcp-lab-sdwan": the edge's transport links (in the
     cat-sdwan-fabric recipe GigabitEthernet1 is on 'mpls', GigabitEthernet2 on 'inet', so
     '<edge>:GigabitEthernet1<->mpls:portN' is the mpls colour). Check against
     `catsdwan_list_tlocs` with device=<edge> if unsure.
   - `cml_get_link_scenarios` with lab="mcp-lab-sdwan": no scenario may be on those links
     already (clear it first, preview-first, or stop and ask).
   - `catsdwan_app_route_stats` with site="200", source='realtime' and
     sla_class="example": loss, latency, jitter and meets/misses per tunnel and colour, before.
   - `catsdwan_tunnel_path` with device=<edge>, destination=<a host at the hub>,
     vpn=<service VPN> (once per class's DSCP or app if the policy matches on them): the colour
     each class takes now.
2. For each transport colour, one at a time:
   a. `cml_apply_link_scenario` with lab="mcp-lab-sdwan", link=<that colour's link of the
      edge>, scenario="brownout" (preview, approval, confirm).
   b. Wait for detection: BFD sees loss within seconds, app-route decisions use the poll
      interval x multiplier (about 10 minutes by default); poll every 2-3 minutes, at most 15.
   c. `catsdwan_app_route_stats` with site="200", source='realtime' and
      sla_class="example": the degraded colour should now miss the SLA.
   d. `catsdwan_tunnel_path` as in step 1: did each class move to the other colour?
      `catsdwan_bfd_sessions` with device=<edge>: did BFD drop it (flap) or keep it
      up and lossy (brownout)?
   e. `cml_check_reachability` in lab "mcp-lab-sdwan" from the branch host to the hub host:
      what the user sees (loss %, RTT).
   f. `cml_clear_link_scenarios` with lab="mcp-lab-sdwan" and link=<that link> (preview,
      approval, confirm), then wait until app_route_stats meets the SLA on that colour again
      before the next colour; note how long it took.
3. After the last colour: `cml_get_link_scenarios` with lab="mcp-lab-sdwan" shows no
   scenario left on this site's links, and `catsdwan_list_alarms` with
   site="200" names the alarms the drill raised.

Report a table: transport degraded, SLA class, colour before / during / after, met the SLA
during (yes/no), time to move and time to recover, and the user's loss/RTT. Then ONE sentence per
class: failed over as designed, stayed on the degraded colour (no fallback or no policy), or lost
traffic; and the next step for anything that did not fail over.
