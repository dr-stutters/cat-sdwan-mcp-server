# catsdwan_contain_host

title: Contain a host (ISE quarantine SGT, or its SD-WAN edge)
arguments: {"anc_policy": "", "host": "10.61.100.10", "hours": "24", "reason": "INC-1 beaconing"}

Contain one host the way a real deployment does: through ISE (ANC policy -> Quarantine SGT -> the
standing SGT rule on the SD-WAN edges, no per-incident Manager change) when the host has an ISE
session, else at the one edge where it sits (device-scoped, time-boxed, audited); then verify the
drop and say how to release.

## user

Contain 10.61.100.10 (reason: INC-1 beaconing). Every write below is PREVIEW-FIRST: show the preview,
name the devices it reaches, and wait for the user's approval before confirming. Never confirm on your own.

1. Locate it: `catsdwan_find_host` with host="10.61.100.10": its edge, site, VPN, interface and MAC.
   Several edges or none: stop and ask.
2. The standing baseline (once per policy group, NOT per incident): `catsdwan_containment_status`
   with group=<the edge's policy group>, trustsec=true. Needed: the edge's NGFW policy on the host's VPN holds
   the mcp-quarantine-* rules (main path) and the mcp-contain-slots-* rules (fallback), deployed. Missing:
   `catsdwan_set_containment_baseline` (quarantine_sgt=<ISE's Quarantine SGT name:tag>,
   remediation=[remediation server, DNS]) is a change for EVERY edge of the group: say so, and only with the
   user's go-ahead for a change window, then `catsdwan_deploy_policy_group` to the group's edges.
   The main path needs TrustSec on the edge (W42's enforcement part): `trustsec.<edge>.ready` true
   (environment data from ISE, and the edge learns the SGT by an IP-to-SGT binding, SXP or inline tagging).
   Not ready: the quarantine rule matches nothing there; say so plainly and use the fallback (step 5).
3. Does ISE know the host? (ISE, skipped if that server is not connected: say so in one line and go on; not connected = fallback) `ise_find_session` with
   the IP or MAC, then `ise_endpoint_360`: an active session, its NAD, authorization profile and
   current SGT. No active session: go to step 5.
4. Main path, ISE ANC: `ise_list_anc_policies` -> the ANC policy whose authorization rule
   (Session:ANCPolicy equals <policy>) returns the Quarantine SGT; none: stop and say what ISE needs (an ANC
   policy with `ise_create_anc_policy` and that authorization rule first in the policy set; build
   it only if the user asks). Then `ise_apply_anc` with the MAC, policy=<the policy from step 3> (preview, approve: ISE
   sends CoA and the host re-authenticates). Verify, in order:
   a. ISE: `ise_find_session` again: the new session carries the Quarantine SGT.
   b. The edge has the new tag: `catsdwan_trustsec` with device=<edge>: the IP-to-SGT binding for
      10.61.100.10 shows the Quarantine tag (learned by SXP, pxGrid or the access switch), or
      `catsdwan_trustsec_path` from the host's edge to a peer edge with source_ip="10.61.100.10": the
      source SGT is the Quarantine tag. Still the old SGT or none: TrustSec does not bring the tag to the edge
      (no SXP/pxGrid binding, no inline tagging): say so, keep the ANC, and add the fallback (step 5).
   c. Traffic is dropped: `catsdwan_security_status` with device=<edge>: drops on the zone pair
      for mcp-quarantine-out/-in grow while the host sends; `catsdwan_ping` from the edge to a
      peer host still works (only the quarantined host is cut off).
   Release: `ise_clear_anc` with the MAC (preview, approve; CoA), then check the SGT is back.
5. Fallback, no ISE session (or no TrustSec on the edge): `catsdwan_contain_at_edge` with
   ip="10.61.100.10", reason="INC-1 beaconing", hours=24, edge=<the edge from step 1>. Show from the
   preview: the ONE device, the slot variable from -> to, the record and its expiry, and `proof.other_devices`
   (every other edge of the group unchanged). Approve, confirm, then verify:
   `catsdwan_get_device_config` with device=<edge>, diff=true (the object-group holds
   10.61.100.10/32), `catsdwan_security_status` (drops for mcp-contain-slots-out/-in), and the result's
   `audit` entries (`catsdwan_audit_log` with changes_only=true when they are not there yet).
   Release: `catsdwan_release_at_edge` with ip="10.61.100.10" (preview, approve). It does NOT expire by
   itself: tell the user the expiry and that `catsdwan_containment_status` lists expired hosts.

Report, ONE line first: contained by ISE (Quarantine SGT seen on <edge>, drops counted) / contained at <edge>
until <expiry> (fallback, why) / NOT contained (what is missing: ISE ANC policy, TrustSec on the edge, the
baseline). Then the evidence per step, how to release, and what the user still has to do (for example:
TrustSec on the edges, an ANC policy on ISE).
