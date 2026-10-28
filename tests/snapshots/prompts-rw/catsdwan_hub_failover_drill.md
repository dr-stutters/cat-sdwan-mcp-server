# catsdwan_hub_failover_drill

title: SD-WAN hub failover drill
arguments: {"dc_services": "ISE 192.0.2.20, DHCP 192.0.2.30, FTD 192.0.2.40", "hub": "hub1", "lab": "mcp-cat-sdwan", "method": "links", "sites": "200,201", "vpns": "10"}

Hub failover drill: snapshot the fabric, take one hub down (in a CML lab with cml_set_link_state
or cml_set_node_state, preview-first; by hand without one), then per branch and service VPN check
that paths moved to the other hub (OMP routes, TLOC preference, catsdwan_explain_path), that each
SLA class still meets its SLA, and that ISE, DHCP and the FTD in the data centre still answer;
restore the hub, compare the snapshots and report. The SD-WAN side is read-only.

## user

Run a hub failover drill: take one hub down and prove that the branches move to the other
hub, that each SLA class keeps its SLA and that the data-centre services still answer; then restore the
hub and show the fabric is back as it was.

This drill CHANGES THE CML LAB "mcp-cat-sdwan": `cml_set_link_state` and
`cml_set_node_state` are write tools on the CML server and PREVIEW-FIRST: show each
preview (the lab, the node or link, the new state), wait for the user's approval, then repeat the
identical call with the confirm token. Only touch the chosen hub's node and links in this lab:
never a Manager, Controller or Validator node, never another edge.
Everything on the SD-WAN Manager is read-only. Whatever fails, ALWAYS run step 7 (restore) before you
stop, and report what failed.

1. Before:
   a. `catsdwan_snapshot` for the whole fabric (site=""): keep the blob as BEFORE.
   b. The hub to fail is "hub1" (given). Check it in catsdwan_list_devices: it must
   be a WAN edge (personality vedge), never a Manager, Controller or Validator.
   c. The other hub: the drill proves failover only if another hub (a second DC) carries the same
      VPNs. Without one, say that the branches will lose the DC for the drill's duration and ask
      the user whether to go on.
   d. `catsdwan_list_devices`: the branches to check, "200", "201", their edges and
      system IPs; all reachable before you start (one that is not: stop and say so).
   e. Paths, per branch edge and per service VPN (10):
      - `catsdwan_omp_routes` with device=<branch edge>, vpn=<VPN> and prefix=<a DC
        prefix>: the routes from each hub, their TLOCs, preference and which are installed;
      - `catsdwan_list_tlocs` with edge=<each hub>: TLOC preference and weight (the
        primary hub should be preferred);
      - `catsdwan_explain_path` with source_site=<branch site>, destination=<the DC
        prefix> and vpn=<VPN>: the policy's path (hub-and-spoke, TLOC lists, app-route).
   f. SLA per class: `catsdwan_list_sla_classes` (classes and the policies that use
      them), then `catsdwan_app_route_stats` with device=<branch edge>,
      remote=<each hub system IP>, source='realtime' and sla_class=<each class>: loss, latency,
      jitter and meets/misses.
   g. DC services. The data-centre services to prove: ISE 192.0.2.20; DHCP 192.0.2.30; FTD 192.0.2.40.
      Prove each from each branch edge: `catsdwan_ping` with device=<branch edge>,
      destination=<service address>, vpn=<its VPN> and count=5.
   h. Where the hub sits: `cml_get_lab_topology` with lab="mcp-cat-sdwan": the hub's node and its
     transport links (in the cat-sdwan-fabric recipe GigabitEthernet1 is on 'mpls' and
     GigabitEthernet2 on 'inet', e.g. '<hub>:GigabitEthernet1<->mpls:portN'); check the colours with
     `catsdwan_list_tlocs` with edge=<hub>. Never a link to VPN 512 (management).

2. Hub down: `cml_set_link_state` with lab="mcp-cat-sdwan", link=<each transport link
   of the hub>, state="down" (preview, approval, confirm, one link at a time, back to back): the
   hub loses every colour. Note the time the last link went down (T0).

3. Convergence: `catsdwan_bfd_sessions` with device=<branch edge> and
   remote=<hub system IP>: the sessions to the hub go down within seconds (hello x multiplier).
   `catsdwan_control_connections` with device=<hub> shows it gone from the controllers.
   Poll every minute, at most 10.

4. Paths during, per branch and VPN, as in 1e: `catsdwan_omp_routes` (the installed
   route now uses the other hub's TLOCs; the failed hub's routes may stay in the table under OMP
   graceful restart, up to 12 h by default, but must not be installed), `catsdwan_list_tlocs`
   for the other hub, and `catsdwan_explain_path`. Note how long after T0 each branch
   moved.

5. SLA during: `catsdwan_app_route_stats` as in 1f with remote=<the other hub>:
   each class meets its SLA on the surviving paths, or which class misses and by how much.

6. DC services during: `catsdwan_ping` as in 1g from each branch edge to each service
   (ISE, DHCP, FTD). In the lab: `cml_check_reachability` with lab="mcp-cat-sdwan",
     nodes=<a host behind each branch edge>, targets=<the service addresses> and wait_seconds=60:
     what a user sees (success %, RTT).
   ISE (skipped if that server is not connected: say so in one line and go on): `ise_deployment_health`: the PSNs still healthy (a PSN that sits
   only in the failed hub's DC is expected to be unreachable: say so). FMC (skipped if that server is not connected: say so in one line and go on):
   `fmc_get_ha_status` for the DC FTD pair, if it is one.

7. Restore (ALWAYS, also after a failure): `cml_set_link_state` with lab="mcp-cat-sdwan", link=<each link taken
   down in step 2>, state="up" (preview, approval, confirm).
   Then `catsdwan_control_connections` with device=<hub> until its controller and
   Manager connections are up on every colour, and `catsdwan_bfd_sessions` with
   device=<hub> until every session is up (poll every minute, at most 15). Note the time to
   recover and whether traffic moved back to the preferred hub.

8. After: `catsdwan_snapshot` again (site="") as AFTER, then
   `catsdwan_compare_snapshot` with before=BEFORE and after=AFTER: anything not back as
   it was (devices, BFD, control, alarms); `catsdwan_list_alarms` names the alarms the
   drill raised (they clear on their own; say which are still active).

Report a table: branch, VPN, path before (hub and TLOC) / during / after, time to move, each SLA
class met during (yes/no, with the numbers), each DC service reachable during (ISE, DHCP, FTD), and
the time to recover. Then ONE sentence per VPN: failed over as designed, failed over but missed an
SLA, or black-holed (no route via the other hub); the compare_snapshot verdict; and the next step
for anything that did not fail over.
