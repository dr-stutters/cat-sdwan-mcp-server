# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x: minor bumps may break consumers).

## [Unreleased]

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
- `cat-sdwan-mcp-server check`: reachability, TLS, auth and version (tested 20.18 and 26.x, minimum 20.15).
- Unit tests on recorded, redacted 20.18 payloads (`tests/fixtures/20.18/`).
- Scaffold on stutters-mcp-core v0.14.4 (bundled as `cat_sdwan_mcp._core`, ADR-005): `catsdwan_status` (reports the
  scaffold stage; no SD-WAN Manager API calls yet), contract tests, CI and release workflows, Docker files.
- [ROADMAP.md](ROADMAP.md): the plan-only roadmap (W0 onwards).
