"""W26 access and AAA: catsdwan_list_users, catsdwan_get_aaa, catsdwan_set_external_authentication."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
from collections import Counter
from typing import Annotated, Any, Literal

import httpx
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp._core.secrets import register_secret
from cat_sdwan_mcp.access import (
    AAA_PATH,
    AUTH_TYPE_PATH,
    GROUPS_PATH,
    LOGOUT_PATH,
    MASK,
    RADIUS_PATH,
    SESSION_LOGIN_PATH,
    SESSIONS_PATH,
    TACACS_PATH,
    USERS_PATH,
    VPN_GROUPS_PATH,
    aaa_view,
    data_of,
    group_row,
    order_problems,
    server_body,
    session_summary,
    user_row,
)
from cat_sdwan_mcp.client import SdwanApp, _as_list, is_html_response
from cat_sdwan_mcp.configuration import RUNNING_PATH, path
from cat_sdwan_mcp.inventory import load_inventory
from cat_sdwan_mcp.manageraaa import CLIENT_SERVER_PATH, DEFAULT_SYSTEM_ORDER, system_aaa, tenancy
from cat_sdwan_mcp.tools.changes import _running, dangerous_blockers
from cat_sdwan_mcp.tools.manageraaa import system_path

# The first write of /admin/radius, /admin/tacacs and /admin/aaa (never set: `"data": {}`) sends the 20.18
# spec's defaults explicitly; #40's POST /admin/tacacs with the servers alone answered 400 without detail.
FIRST_SERVER_DEFAULTS: dict[str, dict[str, Any]] = {
    "radius": {"timeout": 5, "retransmit": 3},
    "tacacs": {"timeout": 5, "authentication": "pap"},
}
FIRST_AAA_DEFAULTS: dict[str, Any] = {
    "authFallback": False,
    "adminAuthOrder": False,
    "accounting": False,
    "auditDisable": False,
}
USER_COLUMNS = ["user", "groups", "status", "sessions", "description"]
Method = Literal["local", "radius", "tacacs"]


class AuthServer(BaseModel):
    address: str = Field(description="Server IP address")
    secret: str = Field(description="Shared secret (masked in every preview and result)")
    auth_port: int | None = Field(default=None, ge=1, le=65535, description="Default 49 / 1812")
    acct_port: int | None = Field(default=None, ge=1, le=65535, description="Default 49 / 1813")
    vpn: Literal[0, 512] = Field(default=0, description="VPN the Manager reaches it in (RADIUS: sourceVpn)")
    priority: int = Field(default=0, ge=0, le=7, description="0-7, lower first")
    tag: str | None = Field(
        default=None,
        description="RADIUS on a single-tenant Manager (system AAA) only: a name, 4-16 characters",
    )
    destination_vpn: int | None = Field(
        default=None,
        ge=0,
        le=65530,
        description="Multi-tenant provider RADIUS with vpn 512 only: the destination VPN (GUI default 0)",
    )
    vpn_ip_subnet: str | None = Field(
        default=None, description="Multi-tenant provider RADIUS with vpn 512 only: the source subnet"
    )


async def _get(app: SdwanApp, path: str) -> Any:
    try:
        return await app.api.get(path)
    except UpstreamError as e:
        return {"error": f"GET {path} failed: {str(e)[:300]}"}


def _err(body: Any) -> str | None:
    return body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else None


async def _aaa(app: SdwanApp) -> tuple[Any, Any, Any]:
    aaa, radius, tacacs = await asyncio.gather(
        app.api.get(AAA_PATH), app.api.get(RADIUS_PATH), app.api.get(TACACS_PATH)
    )
    return aaa, radius, tacacs


async def manager_tenancy(app: SdwanApp) -> str | None:
    """'single' / 'multi' from /client/server (tenancyMode), None when it can't be read."""
    try:
        return tenancy(await app.api.get(CLIENT_SERVER_PATH))
    except UpstreamError:
        return None


async def _system_aaa(app: SdwanApp) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    """The single-tenant Manager's own AAA from its running configuration's `system aaa` (#175): order,
    fallback, RADIUS and TACACS+ servers (secrets masked), labelled with the source and the attached template.
    None when it can't be read (the reason is in the warnings)."""
    sources = ["GET /dataservice/device (the Manager)"]
    try:
        inv = await load_inventory(app)
    except UpstreamError as e:
        return None, sources, [f"the inventory could not be read: {str(e)[:200]}"]
    warnings = list(inv.warnings)
    mgr = next((r for r in inv.rows if r.get("role") == "manager" and r.get("chassis")), None)
    if mgr is None:
        return None, sources, [*warnings, "the inventory lists no Manager (personality vmanage) with a uuid"]
    chassis = str(mgr["chassis"])
    sources.append(f"GET {path(RUNNING_PATH, id=chassis)}")
    running, note = await _running(app, chassis)
    if running is None:
        return (
            None,
            sources,
            [*warnings, note or f"{mgr.get('host') or 'the Manager'} returned no running configuration"],
        )
    view = system_aaa(running)
    if view["order_source"] == "default":
        view["order_source"] = (
            "not set: Viptela's default auth-order "
            + " ".join(DEFAULT_SYSTEM_ORDER)
            + " (a method with no server is skipped)"
        )
    view["source"] = "running configuration (system aaa)"
    mode, cfg = mgr.get("config_mode"), mgr.get("config")
    view["manager"] = {"host": mgr.get("host"), "config_mode": mode}
    if mode == "template" and cfg:
        view["template"] = cfg
    elif mode == "configuration group" and cfg:
        view["configuration_group"] = cfg
    return view, sources, warnings


async def login_check(app: SdwanApp) -> dict[str, Any]:
    """A fresh session login as the API user (as catc_test_login does), logged out again at once. Our own
    token is untouched, so a failure here can still be undone."""
    user, password = app.settings.require_credentials("CATSDWAN_")
    try:
        resp = await app.api.send_raw(
            "POST",
            SESSION_LOGIN_PATH,
            data={"j_username": user, "j_password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except (UpstreamError, httpx.HTTPError) as e:
        return {"user": user, "ok": False, "detail": f"login request failed: {str(e)[:200]}"}
    cookie = resp.cookies.get("JSESSIONID")
    ok = resp.status_code == 200 and not resp.content.strip() and bool(cookie)
    if cookie:
        register_secret(cookie)
        with contextlib.suppress(UpstreamError, httpx.HTTPError):
            await app.api.send_raw("POST", LOGOUT_PATH, headers={"Cookie": f"JSESSIONID={cookie}"})
    detail = (
        "logged in"
        if ok
        else (
            "the Manager answered with its login page (rejected)"
            if is_html_response(resp)
            else f"HTTP {resp.status_code}"
        )
    )
    return {"user": user, "ok": ok, "detail": detail}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN Manager users")
    async def catsdwan_list_users(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Who can log in to the Manager and with what rights: users with their groups, status, lock state,
        description and open sessions; `user_groups` with how many features each may read and write (the
        write features named when there are few); `sessions` per user with source addresses and modes; VPN
        groups; how this API login was authenticated. Local users only: users authenticated by RADIUS or
        TACACS+ (ISE) appear in `sessions` while logged in."""
        app: SdwanApp = get_client(ctx)
        users, groups, sessions, vpn_groups, auth_type = await asyncio.gather(
            app.api.get(USERS_PATH),
            _get(app, GROUPS_PATH),
            _get(app, SESSIONS_PATH),
            _get(app, VPN_GROUPS_PATH),
            _get(app, AUTH_TYPE_PATH),
        )
        per_user, session_rows = (Counter(), []) if _err(sessions) else session_summary(data_of(sessions))
        rows = [user_row(u, per_user) for u in _as_list(data_of(users)) if isinstance(u, dict)]
        rows.sort(key=lambda r: str(r.get("user")))
        extra: dict[str, Any] = {}
        if not _err(groups):
            extra["user_groups"] = [group_row(g) for g in _as_list(data_of(groups)) if isinstance(g, dict)]
        if session_rows:
            local = {r.get("user") for r in rows}
            extra["sessions"] = session_rows
            remote = [s["user"] for s in session_rows if s["user"] not in local]
            if remote:
                extra["remote_users"] = remote
        if not _err(vpn_groups):
            extra["vpn_groups"] = [g for g in _as_list(data_of(vpn_groups)) if isinstance(g, dict)] or "none"
        if isinstance(auth_type, dict) and auth_type.get("userAuthType"):
            extra["this_login_auth_type"] = auth_type["userAuthType"]
        errors = [e for e in (_err(groups), _err(sessions), _err(vpn_groups)) if e]
        if errors:
            extra["errors"] = errors
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=USER_COLUMNS, extra=extra
        )

    @reg.read(title="SD-WAN Manager AAA")
    async def catsdwan_get_aaa(ctx: Context, response_format: ResponseFormat = "json") -> ToolResult:
        """How logins to the Manager are authenticated: the order (local, radius, tacacs; local only when
        never set, the Manager's default), fall-back, accounting, and the RADIUS and TACACS+ servers (address,
        ports, VPN, priority; secrets always masked). `local_fallback` says whether local users can still log
        in when the servers fail. The source follows the Manager's tenancy (/client/server tenancyMode):
        single-tenant (the usual case) reads its running configuration's `system aaa` (auth-order,
        auth-fallback, the radius and tacacs blocks; `source` and `template` say where it came from) and shows
        the provider-only Remote AAA (/admin/*) beside it as `remote_aaa`; a multi-tenant provider reads
        /admin/aaa, /admin/radius and /admin/tacacs. Change it with catsdwan_set_external_authentication."""
        app: SdwanApp = get_client(ctx)
        mode = await manager_tenancy(app)
        remote_sources = [f"GET {AAA_PATH}", f"GET {RADIUS_PATH}", f"GET {TACACS_PATH}"]
        if mode != "single":
            aaa, radius, tacacs = await _aaa(app)
            out = aaa_view(aaa, radius, tacacs)
            out["source"] = "Remote AAA (/admin/*, multi-tenant provider)"
            out["sources"] = remote_sources
            if mode is None:
                out["warnings"] = [
                    f"the Manager's tenancy ({CLIENT_SERVER_PATH} tenancyMode) could not be read: this "
                    "is the multi-tenant provider's Remote AAA; a single-tenant Manager's own logins "
                    "follow its system AAA (catsdwan_get_device_config(device='manager', section='system'))"
                ]
            return object_result(out, fmt=response_format)
        # Single-tenant (#175): the Manager's own logins follow its system AAA in the running configuration;
        # /admin/* is the provider's Remote AAA (empty here), shown alongside, labelled, when it answers.
        system, sys_sources, warnings = await _system_aaa(app)
        aaa, radius, tacacs = await asyncio.gather(
            _get(app, AAA_PATH), _get(app, RADIUS_PATH), _get(app, TACACS_PATH)
        )
        remote_errors = [e for e in (_err(aaa), _err(radius), _err(tacacs)) if e]
        remote = None if remote_errors else aaa_view(aaa, radius, tacacs)
        if system is None:
            out = dict(remote) if remote else {}
            out["source"] = "Remote AAA (/admin/*): the system AAA could not be read"
            warnings.append(
                "this Manager is single-tenant: its own logins follow its system AAA, which could not be "
                "read, so the order below may not be the one in use"
            )
        else:
            out = system
            if remote is not None:
                remote_set = remote["order_source"] == "set" or any(
                    remote[k] != "not configured" for k in ("radius", "tacacs")
                )
                out["remote_aaa"] = (
                    {"source": "Remote AAA (/admin/*, multi-tenant provider only)", **remote}
                    if remote_set
                    else "not set (the multi-tenant provider's Remote AAA, unused on a single-tenant Manager)"
                )
        out["tenancy"] = "single"
        out["sources"] = sys_sources + remote_sources
        if remote_errors:
            warnings += remote_errors
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt=response_format)

    @reg.write(title="Set SD-WAN Manager external authentication", destructive=True)
    async def catsdwan_set_external_authentication(
        ctx: Context,
        protocol: Annotated[
            Literal["tacacs", "radius"], Field(description="The server kind the change configures")
        ],
        order: Annotated[
            list[Method],
            Field(
                min_length=1,
                max_length=3,
                description="The login order after the change, e.g. ['tacacs', 'local']; must keep 'local'",
            ),
        ],
        servers: Annotated[
            list[AuthServer] | None,
            Field(
                description="Replace the servers of `protocol` (1-8); omit to keep the current ones; [] "
                "removes them (single-tenant system AAA)"
            ),
        ] = None,
        fallback: Annotated[
            bool | None,
            Field(description="authFallback (fall back along the order); omit to keep the current"),
        ] = None,
        server_timeout: Annotated[
            int | None, Field(ge=1, le=1000, description="Server timeout in seconds")
        ] = None,
        authentication: Annotated[
            Literal["pap", "ascii"] | None, Field(description="TACACS+ only: pap (default) or ascii")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Point Manager logins at RADIUS (ISE) or TACACS+ servers and set the login order. The path follows
        the Manager's tenancy (/client/server tenancyMode). Single-tenant (the usual case): /admin/radius and
        /admin/aaa are a multi-tenant provider's Remote AAA only (the 20.18 GUI has no Remote AAA tab there),
        so RADIUS or TACACS+ for the Manager's own logins goes into its system AAA: the preview shows the
        running configuration's AAA lines before and after (auth-order, auth-fallback, the radius or tacacs
        block; nothing else changes) and the diff; confirm tests the API user's login, puts that
        configuration in CLI device template mcp-manager-system-aaa attached to the Manager, follows the
        attach, tests the login again and re-attaches the old configuration if it fails (the Manager leaves
        CLI mode). Multi-tenant
        provider: /admin/radius in the GUI's body shape, or /admin/tacacs, then /admin/aaa, then a test login
        with the old order put back if it fails. Lockout risk: BLOCKS an order without 'local', a method with
        no server and a no-op; keep 'local' first with fallback. Secrets are always masked. Dangerous tier.
        Prove with catsdwan_test_login before and after. Undo: the preview's `undo`."""
        app: SdwanApp = get_client(ctx)
        if servers is not None and len(servers) > 8:
            raise InvalidRequest("servers takes 1 to 8 servers (omit it to keep the current ones).")
        if authentication and protocol != "tacacs":
            raise InvalidRequest("authentication (pap or ascii) is a TACACS+ setting.")
        for s in servers or []:
            register_secret(s.secret)
        call_args = {
            "protocol": protocol,
            "order": list(order),
            "servers": [s.model_dump() for s in servers] if servers is not None else None,
            "fallback": fallback,
            "server_timeout": server_timeout,
            "authentication": authentication,
        }
        mode = await manager_tenancy(app)
        if mode == "single":
            return await system_path(
                ctx,
                app,
                protocol=protocol,
                order=list(order),
                servers=[s.model_dump() for s in servers] if servers is not None else None,
                fallback=fallback,
                server_timeout=server_timeout,
                args=call_args,
                confirm=confirm,
                login_check=login_check,
                authentication=authentication,
            )
        if servers is not None and not servers:
            raise InvalidRequest("servers takes 1 to 8 servers (omit it to keep the current ones).")
        aaa, radius, tacacs = await _aaa(app)
        before = aaa_view(aaa, radius, tacacs)
        cur_aaa = data_of(aaa) if isinstance(data_of(aaa), dict) else {}
        cur_srv = data_of(tacacs if protocol == "tacacs" else radius)
        cur_srv = cur_srv if isinstance(cur_srv, dict) else {}
        srv_key = "servers" if protocol == "tacacs" else "server"
        has = {
            "radius": before["radius"] != "not configured",
            "tacacs": before["tacacs"] != "not configured",
        }
        server_req: dict[str, Any] | None = None
        if servers is not None or server_timeout is not None or authentication is not None:
            server_req = {
                k: v for k, v in cur_srv.items() if k in ("timeout", "retransmit", "authentication")
            }
            if not cur_srv:  # first write: the spec's defaults, sent explicitly (#40)
                server_req = FIRST_SERVER_DEFAULTS[protocol] | server_req
            server_req[srv_key] = (
                [server_body(protocol, s.model_dump()) for s in servers]
                if servers is not None
                else _as_list(cur_srv.get("servers") or cur_srv.get("server"))
            )
            if server_timeout is not None:
                server_req["timeout"] = server_timeout
            if authentication is not None:
                server_req["authentication"] = authentication
            has[protocol] = bool(server_req[srv_key])
        aaa_req = {
            k: v
            for k, v in cur_aaa.items()
            if k in ("authFallback", "adminAuthOrder", "accounting", "auditDisable")
        }
        if not cur_aaa:  # first write: every field explicit; adminAuthOrder false keeps admin local (#40)
            aaa_req = {**FIRST_AAA_DEFAULTS, **aaa_req}
        aaa_req["authOrder"] = list(order)
        if fallback is not None:
            aaa_req["authFallback"] = fallback
        blockers = order_problems(list(order), has)
        tenancy_warning = (
            ["the Manager's tenancy (/client/server tenancyMode) could not be read: this uses the "
             "multi-tenant provider's /admin/* Remote AAA, which a single-tenant Manager refuses"]
            if mode is None
            else []
        )  # fmt: skip
        if (
            server_req is None
            and list(order) == before["order"]
            and (fallback is None or fallback == before.get("fallback"))
        ):
            blockers.append("nothing to change: the order and servers are as asked")
        reasons = ["it changes how every user, admin included, logs in to the Manager (lockout risk)"]
        hint = " Deploy to one non-hub device at a time, or have the operator enable dangerous changes."
        blockers += [
            b.replace(hint, " Have the operator enable dangerous changes.")
            for b in dangerous_blockers(ctx, app, reasons)
        ]

        def shown(req: dict[str, Any] | None) -> Any:
            if req is None:
                return f"unchanged ({protocol}: {before[protocol]})"
            return {**req, srv_key: [{**s, "secretKey": MASK} for s in req[srv_key]]}

        user = app.settings.username or "the API user"
        warnings = list(tenancy_warning)
        if protocol == "radius" and any(s.tag for s in servers or []):
            warnings.append(
                "tag is left out: the provider's Remote AAA has no tag field (the GUI sends none)"
            )
        locals_ = ", ".join(dict.fromkeys(["admin", user]))
        if order[0] != "local":
            warnings.append(
                f"{order[0]} is tried first: a RADIUS/TACACS+ reject ends the login and never falls back, "
                f"so local users ({locals_}) log in only while that server is unreachable or times out. "
                f"Create {user!r} in ISE with a netadmin role, or put 'local' first and test with a "
                "second session."
            )
        method = "the" + (" new" if servers is not None else "") + f" {protocol} servers"
        plan = Plan(
            f"Set Manager login order {before['order']} -> {list(order)}"
            + (f" and replace the {protocol.upper()} servers" if servers is not None else ""),
            details={
                "path": "Remote AAA (/admin/*, multi-tenant provider)",
                "before": {
                    "order": before["order"],
                    "fallback": before.get("fallback"),
                    protocol: before[protocol],
                },
                "after": {
                    "order": list(order),
                    "fallback": aaa_req.get("authFallback"),
                    protocol: shown(server_req),
                },
                "local_fallback": "local" in order,
                "requests": (
                    [f"{'PUT' if cur_srv else 'POST'} {TACACS_PATH if protocol == 'tacacs' else RADIUS_PATH}"]
                    if server_req is not None
                    else []
                )
                + [
                    f"{'PUT' if cur_aaa else 'POST'} {AAA_PATH} {aaa_req}",
                    f"POST {SESSION_LOGIN_PATH} (test login as {user})",
                ],
                "tier": "dangerous",
                "tier_reasons": reasons,
                **({"warnings": warnings} if warnings else {}),
                "undo": (
                    f"catsdwan_set_external_authentication(protocol={protocol!r}, order={before['order']!r})"
                ),
            },
            side_effects=[
                f"Every login to the Manager is checked against {method} in the order {list(order)}."
            ],
            fingerprint=[
                before["order"],
                before.get("fallback"),
                str(before["radius"]),
                str(before["tacacs"]),
            ],
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            done: list[str] = []
            if server_req is not None:
                p = TACACS_PATH if protocol == "tacacs" else RADIUS_PATH
                if cur_srv:
                    await app.api.put(p, server_req)
                else:
                    await app.api.post(p, server_req)
                done.append(f"{protocol} servers written")
            if cur_aaa:
                await app.api.put(AAA_PATH, aaa_req)
            else:
                await app.api.post(AAA_PATH, aaa_req)
            done.append(f"order set to {list(order)}")
            login = await login_check(app)
            out: dict[str, Any] = {"steps": done, "test_login": login}
            if not login["ok"]:
                restore = {**aaa_req, "authOrder": before["order"]}
                if "fallback" in before:
                    restore["authFallback"] = before["fallback"]
                await app.api.put(AAA_PATH, restore)
                out["outcome"] = "rolled back"
                out["rolled_back"] = f"the test login failed, so the order is back to {before['order']}"
            else:
                out["outcome"] = "done"
                out["check"] = (
                    "catsdwan_get_aaa; log in as an ISE user in the GUI before closing this session"
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_external_authentication",
            args=call_args,
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
