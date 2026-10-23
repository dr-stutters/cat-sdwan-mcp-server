# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: minor bumps may break consumers).

## [Unreleased]

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

### Changed
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
