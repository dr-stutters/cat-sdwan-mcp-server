# cat-sdwan-mcp-server

An [MCP](https://modelcontextprotocol.io) server for **Cisco Catalyst SD-WAN Manager**, built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) like the other servers in the suite
(cml, ise, catc, fmc).

> **Status: plan only.** This repository is a scaffold. The only tool is `sdwan_status`, and it makes no
> SD-WAN Manager API calls. There is no live SD-WAN fabric to build and prove the tools against yet, so the work
> is planned in [ROADMAP.md](ROADMAP.md) (item W0 is the lab fabric in CML) and tracked on the suite board.

## What it will do

Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, control, BFD and OMP state, application-aware routing, alarms and events, then preview-first configuration-group and policy deploys. See [ROADMAP.md](ROADMAP.md) for the planned tools, the workflow prompts with the other suite
servers, the production gate and the external prerequisites.

## Development

```bash
python scripts/bundle_core.py vendor   # bundle the pinned stutters-mcp-core into src/cat_sdwan_mcp/_core
uv sync
uv run pytest
uv run cat-sdwan-mcp-server tools                    # list the tools and prompts
```

Configuration: copy `.env.example` to `.env`. `SDWAN_URL`, `SDWAN_USERNAME` and `SDWAN_PASSWORD` name the SD-WAN Manager;
everything `MCP_*` comes from stutters-mcp-core ([PRODUCTION.md](https://github.com/dr-stutters/stutters-mcp-core/blob/main/docs/PRODUCTION.md)).
Writes stay off until `MCP_ENABLE_WRITES=true`, and every write will be preview-first with a confirm token.

Docker: `docker compose up -d --build` publishes the server on port 8041 (HTTP transport; set
`MCP_AUTH_TOKENS`).

## Licence

MIT, see [LICENSE](LICENSE).
