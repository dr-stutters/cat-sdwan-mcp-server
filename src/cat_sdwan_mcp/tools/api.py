"""W6 raw API call: catsdwan_api_call, checked against the Manager's OpenAPI document.

Core registers catsdwan_search_spec and catsdwan_get_definition from `spec_sources`, and a generic api_call
that is GET-only, or dangerous for every write. The Manager's tiers are finer (spec.classify): the query POSTs
of the statistics, alarm, event and audit APIs are reads, other writes are write tier with a preview and only
/device/action/* is dangerous. So `register_api_call` replaces core's tool after build_server:

- writes off: read tier; GET and the query POSTs.
- MCP_ENABLE_WRITES: write tier; reads run at once, other writes are preview-first, /device/action/* refused.
- MCP_ENABLE_DANGEROUS too: dangerous tier (roles and rails treat it as such); /device/action/* preview-first.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, preview_or_apply, text_result
from cat_sdwan_mcp._core.audit import redact_value
from cat_sdwan_mcp._core.formatting import compact, dumps
from cat_sdwan_mcp._core.spec import get_specs
from cat_sdwan_mcp.spec import api_path, classify, match_operation

NAME = "catsdwan_api_call"

Path = Annotated[
    str,
    Field(
        description="Path as catsdwan_search_spec lists it, ids substituted, e.g. "
        "'/dataservice/device/bfd/sessions' ('/device/bfd/sessions' works too); the query string goes "
        "in `params`"
    ),
]
Params = Annotated[
    dict[str, Any] | None, Field(description="Query parameters, e.g. {'deviceId': '10.0.0.1'}")
]
Body = Annotated[
    Any, Field(description="JSON body (POST/PUT), e.g. a statistics query {'query': {...}, 'size': 100}")
]


def _shape(result: Any) -> Any:
    return redact_value(compact(result, keep_empty=True))


async def _checked(ctx: Context, method: str, path: str) -> tuple[str, str, list[str]]:
    """(full path, tier of the call, notes): the path must be an operation in the spec."""
    full = api_path(path)
    store = get_specs(ctx)
    idx = await store.get()
    notes: list[str] = []
    if not idx.operations:
        why = "; ".join(f"{k}: {v}" for k, v in store.errors.items()) or "no operations"
        if method.upper() != "GET":
            raise InvalidRequest(
                f"The Manager's API spec could not be loaded ({why}), so writes are refused."
            )
        notes.append(f"path not checked: the Manager's API spec could not be loaded ({why})")
    else:
        match_operation(idx, method, full)
    return full, classify(method, full), notes


async def _send(ctx: Context, method: str, full: str, params: dict[str, Any] | None, body: Any) -> Any:
    store = get_specs(ctx)
    client = next(iter(store.sources.values())).client(store.app)
    json_body = body if method in ("POST", "PUT") else None
    return await client.request(method, full, params=params, json=json_body)


def _answer(result: Any, notes: list[str]) -> ToolResult:
    out: Any = _shape(result)
    if notes:
        out = {"result": out, **({"notes": notes} if notes else {})}
    return text_result(dumps(out))


def register_api_call(mcp: FastMCP[Any], reg: ToolRegistrar) -> None:
    """Replace core's catsdwan_api_call with the Manager-tiered one (called after build_server)."""
    provider = getattr(mcp, "_local_provider", None)
    try:
        if provider is not None:
            provider.remove_tool(NAME)
    except Exception:  # noqa: BLE001 - absent (withheld by policy): registering below adds it or not
        pass
    reg.tiers.pop(NAME, None)
    settings = reg.settings
    writes = settings.mcp_enable_writes
    dangerous = writes and settings.mcp_enable_dangerous

    if not writes:

        @reg.read(title="Raw SD-WAN Manager API read", name=NAME)
        async def catsdwan_api_call_ro(
            ctx: Context,
            path: Path,
            method: Annotated[
                Literal["GET", "POST"],
                Field(description="GET, or POST for a statistics/alarm/event/audit query"),
            ] = "GET",
            params: Params = None,
            body: Body = None,
        ) -> ToolResult:
            """Call any SD-WAN Manager REST endpoint the other tools don't cover (this server is read-only:
            GET, and the query POSTs of /dataservice/statistics/<index>, /alarms, /event and /auditlog, which
            change nothing). The path is checked against the Manager's own OpenAPI document ('did you mean'
            when it isn't there); find paths with catsdwan_search_spec and parameters or bodies with
            catsdwan_get_definition. Secret values are masked."""
            full, tier, notes = await _checked(ctx, method, path)
            if tier != "read":
                raise InvalidRequest(
                    f"{method} {full} changes the Manager; this server is read-only (MCP_ENABLE_WRITES"
                    + (" and MCP_ENABLE_DANGEROUS" if tier == "dangerous" else "")
                    + "). Nothing was sent."
                )
            return _answer(await _send(ctx, method, full, params, body), notes)

        return

    deco = (
        reg.dangerous(title="Raw SD-WAN Manager API call", name=NAME)
        if dangerous
        else reg.write(title="Raw SD-WAN Manager API call", name=NAME)
    )

    async def catsdwan_api_call(
        ctx: Context,
        path: Path,
        method: Literal["GET", "POST", "PUT", "DELETE"] = "GET",
        params: Params = None,
        body: Body = None,
        confirm: Confirm = None,
    ) -> ToolResult:
        """Call any SD-WAN Manager REST endpoint the other tools don't cover. The path is checked against
        the Manager's own OpenAPI document ('did you mean' when it isn't there); find paths with
        catsdwan_search_spec and bodies with catsdwan_get_definition. GET and the query POSTs of
        /dataservice/statistics/<index>, /alarms, /event and /auditlog run at once; every other POST, PUT and
        DELETE is preview-first (nothing is sent until the call is repeated with the confirm token);
        /dataservice/device/action/* (reboot, software install and activate, ...) needs
        MCP_ENABLE_DANGEROUS. Secret values are masked in the preview and the result."""
        full, tier, notes = await _checked(ctx, method, path)
        if tier == "read":
            return _answer(await _send(ctx, method, full, params, body), notes)
        if tier == "dangerous" and not dangerous:
            raise InvalidRequest(
                f"{method} {full} acts on devices (reboot, software, reset): it needs MCP_ENABLE_DANGEROUS. "
                "Nothing was sent."
            )
        plan = Plan(
            f"{method} {full}",
            # Masked: a body can carry a password or key; the confirmed call still sends the real values.
            details={k: redact_value(v) for k, v in {"params": params, "body": body}.items() if v},
            side_effects=(
                ["acts on the devices named in the body (a reboot or software action interrupts traffic)"]
                if tier == "dangerous"
                else []
            ),
        )
        result = await preview_or_apply(
            ctx,
            tool=NAME,
            args={"path": path, "method": method, "params": params, "body": body},
            confirm=confirm,
            plan=plan,
            apply=lambda: _send(ctx, method, full, params, body),
        )
        if "result" in result:
            result["result"] = _shape(result["result"])
        if notes:
            result["notes"] = notes
        return text_result(dumps(result))

    deco(catsdwan_api_call)
