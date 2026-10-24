# catsdwan_network_or_ise

title: Is it the network or ISE?
arguments: {"host": "aa:bb:cc:00:02:00", "minutes": "example", "nad": "br1-sw1", "site": "200"}

Logins fail or are slow at this branch: is it the network or ISE? The overlay path from the site
to ISE's data centre (BFD, OMP route, app-route loss and latency), RADIUS latency and timeouts per
NAD as ISE saw them (ise_nad_radius_stats), then policy (ise_why_auth_failed); a verdict naming the
network, ISE or the policy.

## user

Find out whether the login problems at SD-WAN site 200 are the network (the overlay
between the branch and ISE), ISE itself, or the policy. Read-only: change nothing.

1. Where is ISE? `ise_deployment_health` (ISE, skipped if that server is not connected: say so in one line and go on; without it, ask the user
   for the PSN addresses): the PSNs, their IPs and health. Then `catsdwan_find_host`
   with host=<each PSN IP>: the data-centre site and edge (the hub) ISE sits behind, and its VPN.
2. The branch: `catsdwan_list_devices` with site="200" (the edge(s), system IPs,
   reachability).
3. Overlay path, branch edge to the DC edge:
   - `catsdwan_omp_routes` with device=<branch edge>, vpn=<ISE's VPN> and
     prefix=<PSN IP>: is there a route to ISE, from which TLOCs, installed or not?
   - `catsdwan_bfd_sessions` with device=<branch edge> and remote=<DC edge system
     IP>: which colours are up towards the DC.
   - `catsdwan_app_route_stats` with device=<branch edge> and remote=<DC edge>
     (source='realtime' for now): loss %, latency and jitter per colour. EAP needs several round
     trips through the NAD, so 20 % loss or 300 ms there is enough to time logins out.
   - Optional proof: `catsdwan_ping` from the branch edge to the PSN IP in that VPN
     (count 5).
4. RADIUS as ISE saw it: `ise_nad_radius_stats` with nad="br1-sw1", since_minutes=example
   and compare_previous=true: attempts, response time (median, p95, max), timeouts (NAD or
   supplicant stopped answering) per NAD and the PSN that answered, against the previous window.
   No records at all from a NAD that should be sending: RADIUS isn't reaching ISE (path, wrong
   secret or unknown NAD: `ise_get_nad` for the NAD).
5. Policy: `ise_why_auth_failed` for "aa:bb:cc:00:02:00" (MAC, or username): the decoded failure reason, the rule and authorization profile.

Verdict, ONE sentence first, one of:
- the network: no OMP route or BFD down to the DC, or loss/latency on the path to ISE, and
  RADIUS times or timeouts that follow it (EAP slow, MAB normal);
- ISE: the overlay is clean but response times are high for every NAD, or a PSN is unhealthy
  or not answering;
- the policy: requests reach ISE quickly and are rejected (name the failure reason and the rule);
- none of these: logins pass; look at the client or the access layer.
Then the evidence per step and the next action.
