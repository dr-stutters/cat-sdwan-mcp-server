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
- `cat-sdwan-mcp-server check`: reachability, TLS, auth and version (tested 20.18 and 26.x, minimum 20.15).
- Unit tests on recorded, redacted 20.18 payloads (`tests/fixtures/20.18/`).
- Scaffold on stutters-mcp-core v0.14.4 (bundled as `cat_sdwan_mcp._core`, ADR-005): `catsdwan_status` (reports the
  scaffold stage; no SD-WAN Manager API calls yet), contract tests, CI and release workflows, Docker files.
- [ROADMAP.md](ROADMAP.md): the plan-only roadmap (W0 onwards).
