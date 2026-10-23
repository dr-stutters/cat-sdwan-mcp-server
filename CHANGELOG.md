# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: minor bumps may break consumers).

## [Unreleased]

### Added
- W11 (#12): policy. `catsdwan_list_policies` (centralised `/template/policy/vsmart`, localised
  `/template/policy/vedge`, policy groups `/v1/policy-group`; activated state and each policy's parts),
  `catsdwan_get_policy` (the assembly from `/template/policy/vsmart/definition/{id}` with site and VPN lists
  resolved, each definition from `/template/policy/definition/<type>/{id}` with its sequences in plain words: SLA
  class and limits, preferred and backup colours, data-policy actions, control and hub-and-spoke/mesh topologies;
  lists from `/template/policy/list`, or per type when that isn't available), `catsdwan_explain_path` (offline
  walk: control/topology parts on the two sites, OMP routes at a source edge for a prefix, data-policy sequences
  that may override, the first matching app-route sequence by app list or DSCP with 'maybe' sequences named, the
  tunnels' SLA now from the app-route statistics, and the choice: preferred colour, another SLA-meeting colour,
  backup colour, best path, strict drop or load-balance) and `catsdwan_activate_policy` (dangerous; activate
  `{"isEdited": false}` or deactivate, followed per controller; preview names the controllers, the sites and their
  edges, the policy replaced, `blast_radius`; blocked for a controller in CLI mode or unreachable). Tools that are
  always dangerous are listed with `MCP_ENABLE_WRITES` alone (write tier) so their preview refuses with the reason;
  with `MCP_ENABLE_DANGEROUS` they register at the dangerous tier. Recorded 20.18.3.1 policy fixtures (policy,
  definition record, definition and list types); spec subset extended with the policy operations.
- W12 (#13): device operations. `catsdwan_list_software` (repository and image list, per edge installed, active
  and default versions read live, the release ceiling), `catsdwan_list_device_actions` (running actions with
  per-device progress and failure reasons; action types), `catsdwan_reboot_devices` and `catsdwan_upgrade_software`
  (always dangerous; preview names each device's site and role, `blast_radius` = devices, refuses two edges of one
  site in a run, unreachable or busy devices; the upgrade also refuses an empty repository, a version not in it, a
  release train newer than the Manager and controllers, too little bootflash, a version already running, and
  controllers; install body per the spec's `ProcessInstallReq`, activation by `changepartition` when the version is
  installed already). Recorded 20.18.3.1 fixtures for the empty repository, installed software, reboot history,
  action types and running tasks; spec subset extended.
- W13 (#14): SLA history and reports. `catsdwan_sla_history` (the Manager's hourly or daily histogram per tunnel from
  `POST /statistics/approute/aggregation`, recorded on 20.18.3.1; SLA class by name or from the app-route policy for
  an `app`; miss periods merged across buckets; site, device or tunnel scope), `catsdwan_top_applications` (DPI
  aggregation per application and family; an empty answer says application visibility is off and how to turn it
  on) and `catsdwan_site_report` (devices, availability and SLA misses per transport with a verdict, control
  drops per colour, top alarms, top applications). The two long ones are core tasks; the aggregations run on the
  statistics semaphore. Recorded aggregation and empty DPI fixtures; spec subset extended.
- W20 (#34): `catsdwan_config_history(device, since_hours, version, at, diff, diff_between, section)`: the
  configurations the Manager stored for a device (`GET /device/history/config`; with a `query` the Manager ignores
  `deviceId`, so the query carries a `system_ip` rule and `fields` keeps the text out of the list), one version
  (`/history/config/{id}`), the version in effect at a time, and a block diff of two versions
  (`/history/config/diff/list` answers both texts, not a diff); secrets masked.
- W21 (#35): feature-profile and configuration-group authoring. `catsdwan_get_feature_parcel` (a parcel's values by
  source, the CLI parcel's text, the groups and devices using the profile, `fields=true` for the Manager's schema of
  the parcel type), `catsdwan_set_feature_parcel` (values, `cli_replace` for the CLI parcel, or a new parcel; every
  value checked against `GET .../<parcel>/schema?schemaType=put|post` before the PUT/POST, all problems at once;
  `blast_radius` = the devices of every group using the profile; stores only),
  `catsdwan_associate_config_group` (`POST`/`DELETE .../device/associate`) and `catsdwan_deploy_policy_group` (the
  Manager's policy-group preview, deploy and action status; W8's tiers).
- W22 (#36): the Manager's own health model. `catsdwan_site_health` (`/statistics/sitehealth/common` with
  `/sitehealth/topology`, `/health/devices/overview`, `/network/status`), `catsdwan_tunnel_health`
  (`/statistics/tunnelhealth/overview`, `history=true` from `/tunnelhealth/history` as fair/poor periods),
  `catsdwan_interface_stats` (`POST /statistics/interface/aggregation`, one metric per property; circuit capacity,
  QoS drops) and `catsdwan_topology` (sites, devices, configuration intent, site-to-site tunnel links).
- W16 (#30): certificates and trust. `catsdwan_certificates` (controller and edge certificates with status,
  expiry, days left and what breaks when each expires, invalid/expired/expiring first; the Manager's counts,
  signing modes, root chain, HTTPS certificate and an edge's trustpoints), `catsdwan_renew_controller_certificate`
  (dangerous; two previewed steps: CSR on the controller, then install of the Enterprise-CA-signed certificate and
  send to the validators; refused unless controller signing is Enterprise) and `catsdwan_sync_root_cert` (write;
  `POST /certificate/forcesync/rootCert`).
- W17 (#31): on-box troubleshooting through the Manager. `catsdwan_ping` (ping, or tcp/udp probes via nping),
  `catsdwan_traceroute`, `catsdwan_tunnel_path` (the Manager's flow simulation: next hops with colours and the
  remote edge, matched policies, drop reason), `catsdwan_device_bringup` (the onboarding checklist with the first
  failing step, plus the control check per colour) as reads; `catsdwan_admin_tech` (write, preview-first). Request
  bodies are the ones the Manager's own UI sends.
- W18 (#32): device state reads. `catsdwan_routes` (the live RIB from `/device/ip/ipRoutes` or `/ip/routetable`,
  OMP next hops named by edge, VPN/prefix/protocol filters with a `missing` verdict, BGP/OSPF/EIGRP neighbours)
  and `catsdwan_device_state` (a catalogue of 18 real-time tables by plain name, `feature='list'`, 'did you mean',
  zero counters left out, platform-specific tables refused).
- W19 (#33): Network Wide Path Insight. `catsdwan_list_path_traces` (trace and task history, GUI traces too; a
  trace's flows hop by hop with colours, decisions, policies, drop causes and issues) and `catsdwan_path_insight`
  (write, preview-first: start a trace at a site, wait for flows, read them, always stop it).
- W23 (#37): edge security reads. `catsdwan_security_status(device)` (live from the edge: UTD engine,
  image supported and recommended, IPS signatures and updates, URL-filtering cloud connection, zone-based firewall
  zone pairs and non-zero drop counters, SSL proxy, SIG tunnels to Umbrella or Zscaler, plus the Manager's
  security policies and embedded-security profiles; `features` and a one-line `verdict`, which says plainly when
  there is no security policy at all) and `catsdwan_security_events(kind=ips|url|connection|dns, device or site,
  hours)` (`POST /statistics/ipsalert`, `/urlf`, `/sul/connections`, `/umbrella`, aggregated by signature, per
  edge or by firewall policy, action and drop reason; with no records it says whether none is expected).
- W24 (#38): TrustSec and integrations. `catsdwan_trustsec(device)` (live from the edge: environment data
  from ISE with what a missing download means, PAC with the opaque value masked, IP-to-SGT bindings and their
  source, SGACLs with permit/deny counters, SXP, pxGrid status and bindings, 802.1X; tables the edge does not
  support, such as `iptosgtbindings` on a C8000V, listed as `not_supported`; `in_use` and a `verdict`) and
  `catsdwan_integrations` (ISE credentials masked, the connection test and ISE SGT list only when ISE is
  configured, pxGrid, partners with a Catalyst Center partner's SD-Access sites and devices, SD-Access VPNs; says
  plainly when no ISE, pxGrid or partner is configured).
- W25 (#39): Manager operations. `catsdwan_manager_health` (cluster nodes and state, services per node up or
  down, health summary and details, JVM and third-party memory with %, CPUs, statistics indexes not enabled,
  disaster recovery with its history when configured; a `verdict`), `catsdwan_list_backups` (`/backup/list`
  newest first with state and file, `/schedule/list`) and `catsdwan_create_backup` (write tier, preview-first:
  `POST /backup/export` on demand, followed through `/backup/backupinfo/{id}` to ALL_SUCCESS or a failure; the
  preview names the newest backup, warns that the Manager is busy and blocks while another backup runs or
  when no cluster IP is configured; `srcIpAddress` / `followerIpAddressList` come from the nodes' cluster IPs,
  and EXPORT_FAILED is explained). `catsdwan_manager_health` reports `cluster_ip_configured`.
- W26 (#40): access and AAA. `catsdwan_list_users` (users with groups, status and sessions; user groups with
  read and write feature counts; sessions per user with sources; VPN groups; this login's auth type),
  `catsdwan_get_aaa` (login order, never set = local only, fall-back, RADIUS and TACACS+ servers with secrets
  masked, `local_fallback`) and `catsdwan_set_external_authentication(protocol, order, servers, ...)` (write tool,
  confirm needs `MCP_ENABLE_DANGEROUS`: the preview shows the order and servers before and after and blocks an
  order without `local`, a method with no server and a no-op; confirm writes `/admin/tacacs` or `/admin/radius`
  and `/admin/aaa`, then a fresh test login as the API user, and puts the previous order back if it fails).

## [0.2.0] - 2026-10-23

### Added
- W8 (#9): preview-first configuration changes. `catsdwan_set_device_variables` (read-merge-write of every
  variable of the device with its original type, as the Manager requires; preview old -> new for the changed
  names, secrets masked; stores only), `catsdwan_deploy_config_group` (preview per device from the Manager's CLI
  preview `POST /v1/config-group/{id}/device/{deviceId}/preview` with a diff against running, or the stored
  intended-vs-running diff labelled as such; `POST .../device/deploy`, then `GET /device/action/status/{id}` until
  every device succeeds or fails, with the failing device's reason) and `catsdwan_attach_device_template`
  (`template/device/config/input` checks the variables, `template/device/config/config` renders the CLI per
  device; `attachcli` for CLI templates, `attachfeature` for feature templates; the same action-status follow-up).
  Blockers: a device in the other configuration mode, not in the group, unreachable or with an action still
  running; a group without feature profiles; a template variable without a value. One device is write tier;
  several devices, a hub (`CATSDWAN_HUB_DEVICES`) or a protected-site device (`CATSDWAN_PROTECTED_SITES`) need
  `MCP_ENABLE_DANGEROUS`; `blast_radius` = the devices. Settings `CATSDWAN_HUB_DEVICES`, `CATSDWAN_PROTECTED_SITES`.
- W9 (#10): edge onboarding. `catsdwan_list_wan_edges` (`/system/device/vedges`: chassis, model, hardware or
  software, validity, joined, certificate state, certificate org with `org_mismatch`, managed by; `state` filter),
  `catsdwan_bootstrap_config` (`GET /system/device/bootstrap/device/{uuid}`, cloud-init or encoded, otp masked
  unless `reveal_otp=true`, plus the `request platform software sdwan vedge_cloud activate` command),
  `catsdwan_onboard_edge` (preview lists the steps, confirm runs them in order and stops at the failing one:
  optional signed serial-file upload as multipart `POST /system/device/fileupload` with validity valid and upload
  true, validity valid + send to controllers, configuration-group association and host name / system IP / site id
  variables, or a device-template attach; refuses a chassis not in the list with the two ways in, an org mismatch,
  a failed certificate, a system IP in use) and `catsdwan_set_edge_validity` (`POST /certificate/save/vedge/list`
  then `/certificate/vedge/list?action=push`, followed; invalid, staging on a joined edge, a hub or a
  protected-site edge are dangerous). The one-time token is masked everywhere and registered with the secret
  scrubber. Spec subset extended with the certificate, bootstrap, fileupload and Smart Account operations.
- W10 (#11): workflow prompts. `catsdwan_branch_health(site, lab)` (uses cml, netbox: health, control connections,
  BFD and app-route per colour, alarms, recent activity, CML link scenarios; a verdict per transport),
  `catsdwan_onboard_branch(site, chassis, config_group, hostname, lab)` (write tier; uses netbox, cml: NetBox
  site, prefixes and system IP, `catsdwan_onboard_edge`, bootstrap or activate in CML, deploy, BFD and
  reachability proof, NetBox journal entry; every write preview-first) and `catsdwan_why_is_app_slow(host, app,
  lab)` (uses ise, fmc, cml, netbox: site from the ISE session or NetBox, app-route statistics against the SLA
  class, `fmc_packet_tracer` for the firewall leg, link scenarios; one sentence on where the delay is). Prompt
  contract checked against the cml, ise and fmc manifests and a hand-written netbox manifest
  (`tests/manifests`); snapshots in `tests/snapshots/prompts-rw`.

### Changed
- `catsdwan_list_devices(include_unjoined=true)` and `catsdwan_get_device` no longer show a never-joined software
  edge's serial number (it is the one-time token): `token: ********` instead.
- `catsdwan_get_config_group` reads device variables in the recorded 20.18.3 shape (no `value` key for an empty
  variable, native types).

## [0.1.0] - 2026-10-23

### Added
- W1 (#2): the SD-WAN Manager client. JWT login (`POST /jwt/login`, refresh before expiry) with the session login
  as fallback (`POST /j_security_check` + `GET /dataservice/client/token`; the HTML login page of a failed or
  expired login is an auth error, never a parse error; re-login on 401 or that page; `POST /logout` on close),
  `X-XSRF-TOKEN` on `/dataservice` writes only, an optional tenant `VSessionId`, pacing at 100 requests/s with
  separate buckets for the bulk APIs (48/min, two at a time) and bulk statistics (two at a time), and readable
  errors from the Manager's `{"error": {...}}` body. Settings `CATSDWAN_AUTH`, `CATSDWAN_SESSION_SECONDS`,
  `CATSDWAN_TENANT`.
- `catsdwan_status`: Manager release, login style, tenant, controllers by role with reachability and certificate
  expiry, edges and how many are unreachable (`/dataservice/device`, `/dataservice/system/device/controllers`).
- W2 (#3): inventory and device health. `catsdwan_list_devices` (`/dataservice/device` joined with
  `/system/device/vedges` and `/system/device/controllers`: certificate state, configuration mode and its template
  or group; filters site, personality, reachability, model, version; `include_unjoined` for serial-file slots that
  never joined), `catsdwan_get_device` (by host name, system IP, chassis or serial with 'did you mean'; live
  `device/system/status`, `device/interface`, `device/software` and `device/reboothistory`, each failure reported in
  its own section and no real-time reads for an unreachable device), `catsdwan_list_controllers` (certificate
  serial, expiry, days left, `attention` for invalid or expiring certificates) and `catsdwan_device_health`
  (`/dataservice/health/devices`, which exists on 20.18.3: poor first with the reason; a partial answer says so;
  computed from `/dataservice/device/counters` where the endpoint is missing).
- W3 (#4): the control plane. `catsdwan_control_connections` (live `device/control/connections` plus
  `device/control/summary` and `device/control/connectionshistory` for one device; without one the fabric from the
  bulk state API `/dataservice/data/device/state/ControlConnection`, paged with `startId`/`moreEntries` in the 48/min
  bucket, falling back to live reads of the controllers and validators; `failed_attempts` explain the vdaemon error
  codes such as BIDNTVRFD, SERNTPRES, CTORGNMMIS, CRTVERFL in plain words; for an edge that is down or never joined
  the validators' history is read), `catsdwan_omp_peers` (`device/omp/peers`, every reachable controller by
  default), `catsdwan_omp_routes` (`device/omp/routes/received|advertised`, VPN, overlapping-prefix and originator
  filters, status flags explained, prefixes without an installed path named) and `catsdwan_list_tlocs`
  (`device/omp/tlocs/received`, the first reachable controller by default). Every `device` argument resolves like
  W2's (host name, system IP, chassis or serial, 'did you mean'); a device the Manager cannot reach is refused with
  the reason instead of waiting for a timeout.
- W4 (#5): data plane and application-aware routing. `catsdwan_bfd_sessions` (`device/bfd/sessions` and
  `/bfd/summary` live, or every edge from the bulk `BFDSessions` state API with a live per-edge fallback; down first,
  up counts per colour pair), `catsdwan_tunnel_stats` (`device/tunnel/statistics`: packets and bytes per tunnel, tunnels
  that never received named), `catsdwan_app_route_stats` (`POST /dataservice/statistics/approute` over 1-24 h with
  rules on `vdevice_name`, `remote_system_ip` and `local_color`, aggregated per tunnel: loss, latency and jitter avg/min/
  max, samples, the SLA classes met; worst first; `sla_class` gives a meets/misses verdict per tunnel; `source='realtime'`
  reads `device/app-route/statistics`) and `catsdwan_list_sla_classes` (`/template/policy/list/sla` with the app-route
  definitions and centralized policies that use each class, activated or not).
- Client: query-body paging for the statistics-style APIs (`SdwanApp.query`: POST with `{"query", "size"}`, then the
  `pageInfo` scroll on `<path>/page?scrollId=`, cut to the caller's limit with `more` when rows were left out) and the
  `last_hours`/`rule` query builders, shared by W4 and W5.
- W5 (#6): alarms, events and the audit log, pull-only. `catsdwan_list_alarms` (`POST /dataservice/alarms`: active
  by default, severity-or-worse, device, site and type filters, cleared time, `by_type` counts), `catsdwan_list_events`
  (`POST /dataservice/event`: device, site, event name, component and severity filters), `catsdwan_audit_log`
  (`POST /dataservice/auditlog`, since a GET answers 400: user, module and device filters, `changes_only` without
  logins and logouts, `include_details` with secrets masked) and `catsdwan_recent_activity` (the three merged into one
  timeline for a device, site or the fabric; a failing source becomes a warning). Each reads the newest 2000 rows of
  its window (1 h to 7 days) and says when the window held more.
- `catsdwan_control_connections` adds `rejected_joins` for the fabric view and an edge that is down: the validator's
  `vbond-reject-vedge-connection` and `control-connection-auth-fail` events of the last 24 h with the chassis and the
  reason in plain words (`ERR_BID_NOT_VERIFIED` and friends).
- W6 (#7): API discovery over the Manager's own OpenAPI document. `catsdwan_search_spec` and `catsdwan_get_definition`
  index `GET /apidocs/vmanageapi.json` (recorded on 20.18.3.1: OpenAPI 3.0.1, 2811 paths, 13.4 MB, behind the API
  login; paths relative to `servers: /dataservice`, shown with the prefix), cached per Manager release in
  `MCP_CACHE_DIR`. `catsdwan_api_call` replaces core's generic call: the path must be an operation in the spec
  ('did you mean' otherwise; `/device/...` is read as `/dataservice/device/...`), GET and the query POSTs of
  `/statistics/<index>`, `/alarms`, `/event` and `/auditlog` are reads (also on a read-only server), every other
  POST/PUT/DELETE is write tier and preview-first, `/device/action/*` writes are dangerous; XSRF and the rate buckets
  as for every other call, secrets masked. When the Manager won't serve the spec, GETs go through unchecked with a
  note and writes are refused (a bundled per-release copy as fallback is not shipped yet). `scripts/spec_subset.py`
  cuts the test fixture out of a recorded document.
- W7 (#8): configuration reads. `catsdwan_list_config_groups` (`GET /dataservice/v1/config-group`, deploy state from
  the Manager's `state` or the up-to-date count, associated devices from `.../device/associate`),
  `catsdwan_get_config_group` (feature profiles from `GET /v1/feature-profile/sdwan/<type>/{id}` with each parcel's
  values flattened, variables and secrets masked; the devices' variables from `GET .../device/variables?device-id=`,
  which answers 400 without `device-id` although the spec calls it optional), `catsdwan_list_policy_groups`
  (`GET /v1/policy-group`), `catsdwan_list_templates` (`GET /template/device?feature=all` and `/template/feature`,
  factory defaults hidden by default, attached devices from `/template/device/config/attached/{id}`) and
  `catsdwan_get_device_config` (`GET /template/config/running/{chassis}` and `/template/config/attached/{chassis}`,
  secrets masked; `diff=true` compares by top-level block since the Manager renders the intended configuration
  indented and in another order; the device's configuration mode and sync status). `catsdwan_api_call` also masks
  secrets inside configuration text.
- `cat-sdwan-mcp-server check`: reachability, TLS, auth and version (tested 20.18 and 26.x, minimum 20.15).
- Unit tests on recorded, redacted 20.18 payloads (`tests/fixtures/20.18/`).
- Scaffold on stutters-mcp-core v0.14.4 (bundled as `cat_sdwan_mcp._core`, ADR-005): `catsdwan_status` (reports the
  scaffold stage; no SD-WAN Manager API calls yet), contract tests, CI and release workflows, Docker files.
- [ROADMAP.md](ROADMAP.md): the plan-only roadmap (W0 onwards).
