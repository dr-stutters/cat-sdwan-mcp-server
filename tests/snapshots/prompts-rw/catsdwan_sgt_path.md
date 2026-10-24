# catsdwan_sgt_path

title: SGT path across the SD-WAN overlay
arguments: {"destination": "10.61.100.10", "source": "10.61.200.10", "vpn": "10"}

Does SGT segmentation hold from this source to this destination across the SD-WAN? Source host ->
its edge -> the SGT it is given (802.1X/MAB, SXP, pxGrid, static) -> inline tagging on each tunnel ->
the destination edge's SGACL -> what ISE's egress matrix intends; verdict: enforced as ISE intends /
tag lost on <tunnel> / no policy at <edge>.

## user

Check that SGT policy from 10.61.200.10 to 10.61.100.10 is enforced across the SD-WAN as
ISE intends. Read-only: change nothing; suggest fixes, don't apply them.

1. Where are the hosts? `catsdwan_find_host` with host="10.61.200.10", vpn="10", then with
   host="10.61.100.10", vpn="10": the edge, site and VPN of each. If 10.61.200.10 is a user name, find
   the IP first with ISE's `ise_find_session` (skipped if that server is not connected: say so in one line and go on). Both behind one edge: say
   so and check that edge only with `catsdwan_trustsec`.
2. What ISE gives the source (ISE, skipped if that server is not connected: say so in one line and go on): `ise_find_session` for the source
   (the authorization result and its SGT), `ise_list_sgts` (SGT names and numbers),
   and, when the edges learn bindings over SXP or static mappings,
   `ise_list_sxp_bindings` / `ise_list_ip_sgt_mappings`.
3. Each edge's TrustSec state: `catsdwan_trustsec` with device=<each edge>: the
   environment data from ISE (downloaded or not: without it an edge has no SGACLs), bindings,
   SXP, pxGrid.
4. The overlay: `catsdwan_trustsec_path` with source_edge, destination_edge,
   source_ip="10.61.200.10", destination_ip="10.61.100.10", vpn="10" (add source_sgt / destination_sgt
   from step 2 when an edge has no binding). Per tunnel and colour: does the source edge send the
   tag (propagate) and does the destination edge keep it (trusted); SXP or pxGrid as the other
   way the tag arrives; the destination edge's SGACL and its counters.
5. What ISE intends (ISE, skipped if that server is not connected: say so in one line and go on): `ise_get_egress_matrix` with
   source=<the source SGT's name> and destination=<the destination SGT's name>: the SGACLs and the
   catch-all; no cell = the ANY-ANY default.

Verdict, ONE line first, one of:
- enforced as ISE intends: the tag arrives (name the tunnels or SXP) and the destination edge's
  SGACL matches ISE's cell (name it, with the deny/permit counters);
- tag lost on <tunnel>: the colour and the reason (inline tagging off on <interface>, untrusted
  ingress), and whether another colour still carries it (then it depends on the path the policy
  picks: `catsdwan_explain_path`);
- no policy at <edge>: no SGACL for the pair, or the edge's environment data was never
  downloaded, while ISE has a cell;
- differs from ISE: the edge enforces another SGACL than ISE's cell (stale environment data:
  refresh it on the edge);
- the source has no SGT: classification is missing at the source edge or in ISE's authorization.
Then the evidence per step and the next action (which interface to tag, which SXP peer, which
ISE cell).
