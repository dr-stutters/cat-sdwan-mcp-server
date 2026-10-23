# cat-sdwan-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst SD-WAN Manager**, built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) like the other servers in the suite
(cml, ise, catc, fmc).

> **Status: early.** The client (JWT and session login, throttling, error mapping), `catsdwan_status` and the
> `check` preflight (W1), the inventory and device health tools (W2), the control-plane tools (W3), the data-plane
> and app-route tools (W4), the alarm, event and audit tools (W5), API discovery over the Manager's own OpenAPI
> document (W6), the configuration reads (W7), preview-first configuration changes (W8), edge onboarding
> (W9), the workflow prompts (W10), the policy tools (W11), device operations (W12) and SLA history and
> reports (W13) exist, unit-tested against recorded 20.18 payloads; nothing is proven live yet. The rest is planned in [ROADMAP.md](ROADMAP.md) (item W0 is the lab fabric in CML) and tracked on the suite board.

## What it will do

Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, control, BFD and OMP state, application-aware routing, alarms and events, then preview-first configuration-group and policy deploys. See [ROADMAP.md](ROADMAP.md) for the planned tools, the workflow prompts with the other suite
servers, the production gate and the external prerequisites.

## Tools

| Tool | Tier | What it does |
|---|---|---|
| `catsdwan_status` | read | Manager release, login style (JWT or session), tenant, API user, controllers by role (manager, controller, validator) with reachability and certificate expiry, edge count, how many are unreachable |
| `catsdwan_list_devices` | read | Edges and controllers (site, kind, reachability, model, version filters): system IP, site, model, version, reachability, uptime, serial and chassis, certificate state (valid, invalid, staging) and configuration mode (CLI, template or configuration group, with its name); `include_unjoined` adds serial-file slots that never joined |
| `catsdwan_get_device` | read | One device by host name, system IP, chassis or serial ('did you mean'): the inventory record plus, read live from the device, CPU, memory, disk and load, interfaces, installed and active software, last reboots; a failed real-time read is reported in its section |
| `catsdwan_list_controllers` | read | Manager, controller and validator nodes with reachability, certificate validity, serial, expiry and days left; invalid or soon-expiring certificates named in `attention` |
| `catsdwan_device_health` | read | The Manager's device health (good, fair, poor), poor first, each with the reason (the Manager's, plus short control connections, BFD, TLOCs, OMP peers, high CPU or memory); computed from reachability and counters on a Manager without `/health/devices` |
| `catsdwan_control_connections` | read | Control connections (peer, type, colours, DTLS/TLS, state, uptime) live from one device with its control summary, or the whole fabric from the bulk state API (devices not all up first); `failed_attempts` from the connection history with the error codes in plain words (serial not in the WAN edge list, certificate or organisation mismatch, clock skew, DTLS timeouts), read from the validators for an edge that is down or never joined; `rejected_joins` lists the validator's join rejections from the event log (chassis and reason) |
| `catsdwan_omp_peers` | read | OMP peers live (peer and host, type, site, state, uptime, routes received/installed/sent where reported); no device = every reachable controller, i.e. the fabric's OMP sessions |
| `catsdwan_omp_routes` | read | OMP routes received or advertised on one device (VPN, prefix, originating edge, TLOC, status flags explained, preference); `prefix` finds overlapping routes, `not_installed` names prefixes with no installed path |
| `catsdwan_list_tlocs` | read | TLOCs received over OMP (edge, colour, encapsulation, site, public and private address, BFD status, preference, weight); no device = the first reachable controller's table, i.e. the whole fabric |
| `catsdwan_bfd_sessions` | read | BFD sessions (local and remote colour, remote edge, state, uptime, transitions, hello and multiplier), down first, with `by_colour_pair` up counts; live from one edge with its BFD summary, or every edge from the bulk state API (each reachable edge live when it is missing) |
| `catsdwan_tunnel_stats` | read | Per-tunnel packet and byte counters on one edge (live, since the tunnel came up), MTU and TCP MSS; tunnels that send but never received are named |
| `catsdwan_app_route_stats` | read | Loss %, latency and jitter per tunnel (avg, min, max over 1-24 h of the Manager's app-route statistics; `device`, `site`, `remote`, `colour` filters sent as query rules), worst first; `sla_class` adds a meets/misses verdict per tunnel; `source='realtime'` reads the device's own probe buckets now |
| `catsdwan_list_sla_classes` | read | SLA classes (loss, latency, jitter limits; default or custom) with the app-route policies that use them and the centralized policies carrying those, activated or not |
| `catsdwan_list_alarms` | read | Alarms over 1 h to 7 days (severity or worse, device, site, type), active only by default, newest first: severity, name, active or cleared (with the time), devices, site, message; `by_type` counts active and cleared per alarm |
| `catsdwan_list_events` | read | Device events (BFD, control and OMP state changes, interface changes, reboots, logins, validator rejections, ...) with their details, filtered by device, site, event name, component, severity; `by_event` counts |
| `catsdwan_audit_log` | read | Who did what on the Manager (user, source IP, module, message, device); `changes_only` drops logins and logouts, `device` finds lines that name it, `include_details` adds the bodies with secrets masked |
| `catsdwan_recent_activity` | read | One newest-first timeline of alarms, events and audit lines for a device, a site or the whole fabric; a source that fails is reported and the others still answer |
| `catsdwan_list_config_groups` | read | Configuration groups: solution, feature profiles, devices associated and up to date, deploy state (never deployed, partly, up to date), last change and by whom, the associated devices by host name |
| `catsdwan_get_config_group` | read | One group by name ('did you mean') or id: each feature profile with its parcels and values (variables as `{{name}}`, defaults left out, secrets masked), the associated devices (in sync, up to date with the group, deployable) and each device's variable values |
| `catsdwan_list_policy_groups` | read | Policy groups: profiles, devices, deploy state, last change |
| `catsdwan_list_templates` | read | Device templates (CLI or feature-based, device model, devices attached and which) or feature templates (type, device models, devices attached, device templates using them); factory defaults hidden unless `include_defaults` |
| `catsdwan_get_device_config` | read | A device's running or intended configuration (`template/config/running` and `/attached`), secrets masked (passwords, secrets, keys, pre-shared keys, SNMP communities and user keys), `section` filter; `diff=true` compares the two by block, order-independent (only on the device, only intended, changed lines); says whether the device is in a configuration group, on a template or in CLI mode |
| `catsdwan_set_device_variables` | write | A device's variable values in a configuration group (`PUT /v1/config-group/{id}/device/variables`): the preview shows each changed variable old -> new (secrets masked) and the old values to undo; the Manager needs every variable of the device in one write, so the tool reads them all, merges and writes them back with their original types. Stores only: nothing reaches the device until a deploy |
| `catsdwan_deploy_config_group` | write / dangerous | Push a configuration group to named devices (`POST /v1/config-group/{id}/device/deploy`). Preview per device: the Manager's CLI preview (`POST .../device/{id}/preview`) and its diff against the running configuration, or, when that isn't available, the stored intended-vs-running diff (labelled as such). Blocked for a device not in the group, on a template, unreachable or with an action running, and for a group without feature profiles. Confirm follows `GET /device/action/status/{id}` until each device reports success or failure (with the reason) |
| `catsdwan_attach_device_template` | write / dangerous | Attach a device template (CLI: `attachcli`, feature-based: `attachfeature`) with variables for every device or per device. Preview: the template's variables per device (`template/device/config/input`, a missing value blocks) and the rendered CLI per device (`template/device/config/config`) with its diff against running. Blocked for a configuration-group device, an unreachable device, another device model or a running action. Confirm follows the action status like the deploy |
| `catsdwan_list_wan_edges` | read | The WAN edge list (`/system/device/vedges`: serial-file and Smart Account slots, joined or not): chassis, model, hardware or software, validity (valid, invalid, staging), joined (host, system IP, site), certificate state, the org name in its certificate (`org_mismatch` when it isn't the overlay's), managed by; `state` filter (joined, not_joined, valid, invalid, staging). A software edge's one-time token is always shown as `********` |
| `catsdwan_bootstrap_config` | read | The day-0 bootstrap an edge boots with (`/system/device/bootstrap/device/{uuid}`, cloud-init or encoded): vinitparam uuid, otp, validator, org; for the day-0 configuration of a C8000V in `cml_build_lab`. The otp is masked unless `reveal_otp=true` (then in full, with a warning); also gives the `request platform software sdwan vedge_cloud activate` command for a running edge; warns when the edge has joined already, is not valid, or its org differs |
| `catsdwan_onboard_edge` | write / dangerous | Bring a WAN edge slot into the fabric in order, stopping at the first failing step with its reason: (0) upload a signed serial file when the chassis isn't in the list (`serial_file`; multipart `POST /system/device/fileupload`, validity valid, upload true), (1) validity valid and the list sent to the controllers, (2) associate with a configuration group and store host name, system IP and site id (plus `variables`) as its variables, or attach a device template with them. Preview lists every step; blocked for a chassis not in the list (with the two ways in), an org mismatch, a failed certificate, a system IP in use, the other configuration mode. A hub or protected-site edge is dangerous. The result says how the edge joins (bootstrap at first boot, or the activate command) |
| `catsdwan_set_edge_validity` | write / dangerous | valid, invalid or staging in the WAN edge list (`POST /certificate/save/vedge/list`), then send the list to the controllers (`POST /certificate/vedge/list?action=push`, followed to the end). invalid (the edge can't join; a joined edge drops its control connections and tunnels), staging on a joined edge (no data plane) and a hub or protected-site edge are dangerous; the preview names the edge's site and the undo |
| `catsdwan_list_policies` | read | Centralised policies (`/template/policy/vsmart`: activated or not, their parts such as 'mcp-test-app-route (application-aware routing)'), localised policies (`/template/policy/vedge`: devices and device templates using them) and policy groups (`/v1/policy-group`); `active_centralised_policy` names the one in force |
| `catsdwan_get_policy` | read | One policy in plain words: where each part applies (site and VPN lists resolved), each definition's sequences as 'if <match> -> <action>' (app-route: SLA class with its limits, preferred and backup colours; data: accept/drop, set TLOC, NAT; control and hub-and-spoke/mesh topologies), the default action; lists from `/template/policy/list` (or per type); CLI policies as text with secrets masked |
| `catsdwan_explain_path` | read | Offline path walk like `fmc_rule_lookup`: for a source site, a destination site or prefix (OMP routes read live at a source edge) and an app or DSCP, the control/topology parts on the two sites, data-policy sequences that may override, the first matching app-route sequence (and the ones that might), each tunnel's loss/latency/jitter now against its SLA class, and the verdict ('the preferred colour mpls misses Realtime: latency 320 ms > 150 ms; biz-internet meets it'). `policy=` walks a policy that isn't activated |
| `catsdwan_activate_policy` | dangerous | Activate (`POST /template/policy/vsmart/activate/{id}` `{"isEdited": false}`) or deactivate (`.../deactivate/{id}`) a centralised policy, followed with `/device/action/status/{id}` per controller. Preview: the controllers, every site the policy names with its edges, the policy it replaces, `blast_radius` = controllers + edges; blocked for a controller unreachable or in CLI mode (the Manager activates centralised policy only on controllers with a device template). Listed with `MCP_ENABLE_WRITES` alone so its preview can say it needs `MCP_ENABLE_DANGEROUS` |
| `catsdwan_list_software` | read | The software repository (`/device/action/software` and `/software/images`: version, the controller release it needs, files; an empty repository is said plainly), per edge the running, active, default and installed versions (read live), and the release ceiling (edges never run a newer train than the Manager and controllers: IOS XE 17.18 with 20.18) |
| `catsdwan_list_device_actions` | read | The Manager's running actions (`/device/action/status/tasks`: upgrades, reboots, pushes, started here or in the GUI), each with per-device progress and the failing device's reason (`/device/action/status/{id}`); `since_hours`, `name` filters; `show_types` lists the action types (`/device/action/list`) |
| `catsdwan_reboot_devices` | dangerous | Reboot edges or controllers (`POST /device/action/reboot` `{action, deviceType, devices: [{deviceIP, deviceId}]}`), followed per device. Preview: each device's site, role (hub per `CATSDWAN_HUB_DEVICES`), version, uptime and last reboots; `blast_radius` = the devices; blocked for the Manager, an unreachable or busy device, and two edges of the same site in one run |
| `catsdwan_upgrade_software` | dangerous | Install a version from the repository on edges (`POST /device/action/install`), `activate=true` reboots them into it; an installed version is only activated (`/device/action/changepartition`). Blocked when the repository is empty or lacks the version, the version is a newer release train than the Manager and controllers, the image needs newer controllers, an edge runs it already or has under 1 GB free on bootflash, is unreachable or busy, two edges of one site are in the run, or a target is a controller |
| `catsdwan_sla_history` | read | App-route loss, latency and jitter per tunnel over 1-30 days, aggregated by the Manager per hour or day (`POST /statistics/approute/aggregation` with a histogram); with an SLA class (by name, or the one the app-route policy gives `app`) the periods each tunnel missed it, consecutive buckets merged, worst tunnels first. Scope: site, device or one tunnel (`br1:mpls-hub1:mpls`, or `br1:mpls`). Runs as a core task |
| `catsdwan_top_applications` | read | Bytes, packets and share per application and per family (`POST /statistics/dpi/aggregation`) for a site or edge over 1-168 h. Needs application visibility (DPI/NBAR) on the edges: with no DPI statistics it says so and how to enable it, not an empty list |
| `catsdwan_site_report` | read | One summary of a site over 1-30 days (like `catc_site_health_report`): devices, availability per transport (buckets in which the colour carried traffic) with loss, latency, jitter, SLA misses and a verdict, control-connection drops per colour (connection history, live), top alarms by type, top applications; a section that can't be read says why. Runs as a core task |
| `catsdwan_config_history` | read | The running configurations the Manager stored for a device over time (`GET /device/history/config` with a query on the device's system IP: time, config id, how it was stored); `version` (id, index, 'latest', 'previous') or `at` (the version in effect at a time) shows one (`/history/config/{id}`), `diff=true` or `diff_between` diffs two by block (`/history/config/diff/list` returns both texts; '-' older, '+' newer); secrets masked, `section` filter |
| `catsdwan_get_feature_parcel` | read | A feature-profile parcel (`/v1/feature-profile/sdwan/<type>/{profile}/<parcel>/{id}`) by profile or configuration group and parcel name, id or type: values by source (configured global values and `{{variables}}`, defaults), the CLI parcel's text (secrets masked), the groups using the profile and their devices; `fields=true` adds the Manager's schema for the parcel type (option types, value type, enum, range, default, required); no `parcel` lists the parcels |
| `catsdwan_set_feature_parcel` | write | Change a parcel's values (`values`: global, `'{{name}}'` = variable, null = the schema's default) or the CLI parcel's text (`cli_replace`), or create a parcel (`new_parcel_name`, required fields filled from the schema's defaults). Preview: old -> new per field or the changed CLI lines, every value checked against the Manager's own schema (`.../<parcel>/schema`) with all problems at once, the groups and devices the profile reaches (`blast_radius`). Confirm PUTs (POST for a new parcel); stores only, nothing reaches a device until `catsdwan_deploy_config_group` |
| `catsdwan_associate_config_group` | write | Add devices to or remove them from a configuration group (`POST` / `DELETE .../device/associate`); preview shows the devices before and after; blocked for a device on a template, in another group, already in (add) or not in (remove) the group. Pushes nothing |
| `catsdwan_deploy_policy_group` | write / dangerous | Push a policy group to named devices: preview per device from the Manager's own preview (`POST /v1/policy-group/{id}/device/{deviceId}/preview`) with its diff against running; confirm `POST .../device/deploy` and the action status per device; tiers and blockers as the configuration-group deploy |
| `catsdwan_search_spec` | read | Search the Manager's own OpenAPI document (`GET /apidocs/vmanageapi.json`, OpenAPI 3, about 2800 paths on 20.18) for operations and schemas; paths shown as `/dataservice/...`; indexed once per Manager release and cached in `MCP_CACHE_DIR` |
| `catsdwan_get_definition` | read | One operation (parameters, request fields, required fields; `examples=true` for the spec's examples) or schema |
| `catsdwan_api_call` | read / write / dangerous | Any endpoint, the path checked against the spec ('did you mean' when it isn't there). GET and the query POSTs of `/statistics/<index>`, `/alarms`, `/event`, `/auditlog` are reads; with `MCP_ENABLE_WRITES` other POST/PUT/DELETE calls are preview-first; `/device/action/*` writes (reboot, software) need `MCP_ENABLE_DANGEROUS`. Secrets masked |

`cat-sdwan-mcp-server check` is the preflight: reachability (login and a `/dataservice` read), TLS trust,
credentials (a wrong password reports `auth`, also on the session login whose failure is an HTML page), and the
Manager release (tested 20.18 and 26.x, minimum 20.15). `--json` for the report as JSON.

## Configuration changes

Every change tool is preview-first: a call without `confirm` changes nothing and returns the preview plus a
single-use token; the identical call with `confirm=<token>` applies it after checking that nothing it depends on
changed (the fingerprint: the preview CLI per device and the group's or template's last change). A deploy or
attach to **one** device is write tier (`MCP_ENABLE_WRITES`); to **several** devices, or to a hub
(`CATSDWAN_HUB_DEVICES`) or a device at a protected site (`CATSDWAN_PROTECTED_SITES`), it is dangerous: the
preview is blocked unless `MCP_ENABLE_DANGEROUS` is on (and, with per-user roles, the caller is admin). Every
deploy reports `blast_radius` = its devices, so `MCP_MAX_BLAST_RADIUS` caps it. The Manager has no undo: the
variables preview lists the old values, and a deploy's preview diff shows the running configuration it replaces.

Typical flow: `catsdwan_get_config_group` (variables) -> `catsdwan_set_device_variables` (preview, confirm) ->
`catsdwan_deploy_config_group` (preview: per-device CLI and diff; confirm) -> `catsdwan_get_device_config(diff=true)`.

## Prompts

Workflow prompts (the client lists them; each names the servers it expects in `uses`, and the legs on servers
that aren't connected are skipped with a one-line note):

| Prompt | Tier | Uses | What it does |
|---|---|---|---|
| `catsdwan_branch_health(site, lab)` | read | catsdwan, cml, netbox | Device health, control connections, BFD per colour, app-route loss/latency/jitter per colour (against the SLA class when there is one), alarms and recent activity, then a verdict per transport (healthy, degraded, down); in CML, `cml_get_link_scenarios` says when a degradation is a deliberate scenario |
| `catsdwan_onboard_branch(site, chassis, config_group, hostname, lab)` | write | catsdwan, netbox, cml | Site id, system IP and prefixes from NetBox (`netbox_next_available_ips`, `netbox_allocate_ips` preview-first), `catsdwan_list_wan_edges` -> `catsdwan_onboard_edge` -> the edge booted with `catsdwan_bootstrap_config` (`cml_build_recipe` 'cat-sdwan-fabric', `cml_set_node_state`) or activated on a running node (`cml_configure_node` exec) -> control connections -> `catsdwan_set_device_variables` / `catsdwan_deploy_config_group` -> BFD and `cml_check_reachability` branch host to hub host -> `netbox_add_journal_entry`; every write preview-first. Hidden without `MCP_ENABLE_WRITES` |
| `catsdwan_why_is_app_slow(host, app, lab)` | read | catsdwan, ise, fmc, cml, netbox | The host's site from `ise_find_session` or `netbox_lookup_ip`, BFD and app-route statistics on the branch edge per colour against the SLA class, recent activity, `fmc_packet_tracer` for an FTD behind the edge, CML link scenarios; one sentence on where the delay is |

The prompt test kit checks every `cml_`, `ise_`, `fmc_` and `netbox_` reference against the manifests in
`tests/manifests` (cml, ise and fmc copied from their repos; `netbox.json` hand-written, as netbox-mcp has no
`tools --json`), and `tests/snapshots/prompts-rw` holds the rendered prompts (`UPDATE_PROMPT_SNAPSHOTS=1` rewrites
them).

## Onboarding an edge

`catsdwan_list_wan_edges(state='not_joined')` (a free chassis) -> `catsdwan_onboard_edge(chassis, hostname,
system_ip, site_id, config_group=...)` (preview, confirm) -> boot the edge: either with the cloud-init from
`catsdwan_bootstrap_config(chassis, reveal_otp=true)` as its day-0 (in CML, the node configuration in
`cml_build_lab`), or, on a C8000V already running in controller mode, the exec command
`request platform software sdwan vedge_cloud activate chassis-number <chassis> token <token>`. A C8000V needs
some uuid/otp in its day-0 `vinitparam`, or it boots in autonomous mode. Then `catsdwan_control_connections(device)`
until it is up, and `catsdwan_deploy_config_group` to push its configuration.

The one-time token (the serial number of a software edge that has not joined, the bootstrap's otp) is a secret:
masked in every result except `catsdwan_bootstrap_config(reveal_otp=true)`, and registered with the secret
scrubber so it never reaches a log line or an error. A chassis that isn't in the WAN edge list gets in by the
signed serial file (`catsdwan_onboard_edge(serial_file=...)`) or a Smart Account sync
(`POST /dataservice/system/device/smartaccount/sync` through `catsdwan_api_call`; no tool yet).

## Login and throttling

- `CATSDWAN_AUTH=auto` (default) logs in with JWT (`POST /jwt/login`, 20.18.1 and later) and falls back to the
  session login (`POST /j_security_check`, a `JSESSIONID` cookie and the `X-XSRF-TOKEN` from
  `GET /dataservice/client/token`) when the Manager answers 404/405. `jwt` or `session` forces one.
- JWT tokens are refreshed (`POST /jwt/refresh`) shortly before `CATSDWAN_SESSION_SECONDS` runs out; a session
  is renewed when the Manager answers 401 or its HTML login page, and closed with `POST /logout`.
- The XSRF token goes on every `/dataservice` call (20.18.3 refuses some JWT reads, such as `/dataservice/health/devices`, without it). One login is shared by every caller of the server.
- Pacing: 100 requests/s (the Manager's per-user limit; `CATSDWAN_RATE_LIMIT` in requests/min overrides it),
  48/min and two at a time for the bulk APIs (`/dataservice/data/device/...`, paged with `startId`), two concurrent
  `/dataservice/statistics/...` requests.
- Statistics, alarm, event and audit reads POST a query body (`entry_time last_n_hours` plus rules) and follow the
  `pageInfo` scroll (`scrollId`/`hasMoreData` on `<path>/page`) up to the tool's cap; a cut answer says so.
- The Manager's `{"error": {"message", "details", "code"}}` body becomes the error text.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CATSDWAN_URL` | (required) | SD-WAN Manager base URL, e.g. `https://sdwan-manager.example.com` |
| `CATSDWAN_USERNAME` / `CATSDWAN_PASSWORD` | | API account (`CATSDWAN_PASSWORD_FILE` or `_REF` instead of the password) |
| `CATSDWAN_AUTH` | `auto` | `auto` (JWT, else session), `jwt` (20.18.1+) or `session` |
| `CATSDWAN_SESSION_SECONDS` | `1800` | JWT lifetime asked for at login (300 to 1800: 20.18.3 refuses more) |
| `CATSDWAN_TENANT` | | Multi-tenant Manager with a provider login: tenant name or id; requests carry its `VSessionId` (needs the Tenant Management read role) |
| `CATSDWAN_VERIFY_SSL` | `true` | TLS verification; `false` for self-signed labs |
| `CATSDWAN_CA_BUNDLE` | | CA bundle for the Manager certificate |
| `CATSDWAN_TIMEOUT` / `CATSDWAN_RETRIES` | `30` / `2` | Per-request timeout (s) and retries (429 always retried, honouring `Retry-After`) |
| `CATSDWAN_RATE_LIMIT` / `CATSDWAN_MAX_CONCURRENCY` | `6000` / none | Client-side pacing (requests/min) and concurrent requests |
| `CATSDWAN_INSTANCES` | | Several Managers in one server (`CATSDWAN_<NAME>_URL`, ...; `_TENANT` is never inherited): every tool gets `instance` |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | `name:sha256:<hex>` entries; **required** for HTTP |
| `CATSDWAN_HUB_DEVICES` | | Hubs (host names, system IPs or chassis, comma-separated): a deploy or attach touching one is dangerous tier |
| `CATSDWAN_PROTECTED_SITES` | | Site ids or names (comma-separated): a deploy or attach touching a device there is dangerous tier |
| `MCP_ENABLE_WRITES` / `MCP_ENABLE_DANGEROUS` | `false` | Write tools and `catsdwan_api_call` writes (preview-first) / `/device/action/*` calls and dangerous-tier changes |
| `LOG_LEVEL` | `INFO` | |

Everything else `MCP_*` comes from stutters-mcp-core ([PRODUCTION.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/PRODUCTION.md)).

## Development

```bash
python scripts/bundle_core.py vendor   # bundle the pinned stutters-mcp-core into src/cat_sdwan_mcp/_core
uv sync
uv run pytest tests/unit
uv run cat-sdwan-mcp-server tools                    # list the tools and prompts
uv run cat-sdwan-mcp-server check                    # preflight against the configured Manager
```

Configuration: copy `.env.example` to `.env`. `CATSDWAN_URL`, `CATSDWAN_USERNAME` and `CATSDWAN_PASSWORD` name the SD-WAN Manager;
everything `MCP_*` comes from stutters-mcp-core ([PRODUCTION.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/PRODUCTION.md)).
Writes stay off until `MCP_ENABLE_WRITES=true`, and every write is preview-first with a confirm token.

Docker: `docker compose up -d --build` publishes the server on port 8041 (HTTP transport; set
`MCP_AUTH_TOKENS`).

## Licence

MIT, see [LICENSE](LICENSE).
