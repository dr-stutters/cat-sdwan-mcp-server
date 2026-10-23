# cat-sdwan-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst SD-WAN Manager**, built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) like the other servers in the suite
(cml, ise, catc, fmc).

> **Status: early.** The client (JWT and session login, throttling, error mapping), `catsdwan_status` and the
> `check` preflight (W1), and the inventory and device health tools (W2) exist, unit-tested against recorded
> 20.18 payloads; nothing is proven live yet. The
> rest is planned in [ROADMAP.md](ROADMAP.md) (item W0 is the lab fabric in CML) and tracked on the suite board.

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

`cat-sdwan-mcp-server check` is the preflight: reachability (login and a `/dataservice` read), TLS trust,
credentials (a wrong password reports `auth`, also on the session login whose failure is an HTML page), and the
Manager release (tested 20.18 and 26.x, minimum 20.15). `--json` for the report as JSON.

## Login and throttling

- `CATSDWAN_AUTH=auto` (default) logs in with JWT (`POST /jwt/login`, 20.18.1 and later) and falls back to the
  session login (`POST /j_security_check`, a `JSESSIONID` cookie and the `X-XSRF-TOKEN` from
  `GET /dataservice/client/token`) when the Manager answers 404/405. `jwt` or `session` forces one.
- JWT tokens are refreshed (`POST /jwt/refresh`) shortly before `CATSDWAN_SESSION_SECONDS` runs out; a session
  is renewed when the Manager answers 401 or its HTML login page, and closed with `POST /logout`.
- The XSRF token goes on every `/dataservice` call (20.18.3 refuses some JWT reads, such as `/dataservice/health/devices`, without it). One login is shared by every caller of the server.
- Pacing: 100 requests/s (the Manager's per-user limit; `CATSDWAN_RATE_LIMIT` in requests/min overrides it),
  48/min and two at a time for the bulk APIs (`/dataservice/data/device/...`), two concurrent
  `/dataservice/statistics/...` requests.
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
| `MCP_ENABLE_WRITES` / `MCP_ENABLE_DANGEROUS` | `false` | Register the write / dangerous tools (none yet) |
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
Writes stay off until `MCP_ENABLE_WRITES=true`, and every write will be preview-first with a confirm token.

Docker: `docker compose up -d --build` publishes the server on port 8041 (HTTP transport; set
`MCP_AUTH_TOKENS`).

## Licence

MIT, see [LICENSE](LICENSE).
