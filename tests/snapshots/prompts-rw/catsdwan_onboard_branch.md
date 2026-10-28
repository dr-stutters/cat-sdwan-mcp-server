# catsdwan_onboard_branch

title: Onboard an SD-WAN branch
arguments: {"chassis": "C8K-00000000-0000-4000-8000-000000000001", "config_group": "mcp-test", "hostname": "br2", "lab": "mcp-lab-sdwan", "site": "201"}

Onboard a branch edge from the source of truth: site id, system IP and LAN prefixes from NetBox,
then catsdwan_onboard_edge (validity, group, variables), boot or activate the edge, deploy the
group, and prove it: control connections and BFD up, a ping from the branch host to the hub host,
and a NetBox journal entry. Every write is preview-first.

## user

Onboard the SD-WAN branch at site 201. Every write below is PREVIEW-FIRST: show
the preview, wait for the user's approval, then repeat the identical call with the confirm
token. Stop at the first step that fails and report it with its reason; never guess a value the
source of truth should give.

1. Source of truth (NetBox, skipped if that server is not connected: say so in one line and go on; without it, ask the user for the site id, host name and
   system IP):
   - `netbox_site_summary` for "201": the site, its devices and prefixes; the
     SD-WAN site id is the site's custom field or description (ask if it isn't there).
   - `netbox_prefix_utilization` for the site's LAN and system-IP prefixes.
   - The system IP: `netbox_next_available_ips` in the system-IP prefix, then
     reserve it with `netbox_allocate_ips` (preview first) for host name br2.
2. The edge: `catsdwan_list_wan_edges` with state="not_joined": use chassis "C8K-00000000-0000-4000-8000-000000000001". Check it is
   in the list and hasn't joined already (the token stays masked).
3. Onboard: `catsdwan_onboard_edge` with chassis="C8K-00000000-0000-4000-8000-000000000001", hostname=br2,
   system_ip=<from step 1>, site_id=<from step 1>, config_group="mcp-test". Show the preview's steps (validity,
   association, variables) and confirm.
4. Boot or activate the edge (CML, skipped if that server is not connected: say so in one line and go on; on hardware, hand the day-0 to whoever racks it):
   - a new or rebuilt node: `catsdwan_bootstrap_config` with the chassis and
     reveal_otp=true (warn the user it returns the one-time token) as the node's day-0, built
     with `cml_build_recipe` (recipe "cat-sdwan-fabric" for the whole lab) and
     started with `cml_set_node_state`;
   - a node already running in controller mode: the activate command from
     catsdwan_bootstrap_config, sent with `cml_configure_node` (mode='exec') on that
     node in lab "mcp-lab-sdwan".
5. Joined? `catsdwan_control_connections` with device=<host name> until the vsmart
   and vmanage connections are up (a few minutes after boot; failed attempts give the reason:
   not in the list, org, certificate, clock). `cml_run_commands` with
   "show sdwan control connections" on the node shows the device's side.
6. Configure: `catsdwan_set_device_variables` for anything the group still needs
   (the preview lists the variables), then `catsdwan_deploy_config_group` with the
   group and devices=[<host name>]: show the per-device CLI and diff, confirm, and report each
   device's outcome.
7. Prove it: `catsdwan_bfd_sessions` with device=<host name> (up on every colour to
   the hub), and, in CML, `cml_check_reachability` in lab "mcp-lab-sdwan" from the branch
   host to the hub host (success % and RTT).
8. Record it (NetBox, skipped if that server is not connected: say so in one line and go on): `netbox_add_journal_entry` on the site or
   device: chassis, system IP, site id, group, the date, and the BFD result (preview first).

End with a short table: step, result, and anything left for the user.
