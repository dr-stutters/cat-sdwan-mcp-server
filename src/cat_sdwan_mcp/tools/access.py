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
from cat_sdwan_mcp.tools.changes import dangerous_blockers

USER_COLUMNS = ["user", "groups", "status", "sessions", "description"]
Method = Literal["local", "radius", "tacacs"]


class AuthServer(BaseModel):
    address: str = Field(description="Server IP address")
    secret: str = Field(description="Shared secret (masked in every preview and result)")
    auth_port: int | None = Field(default=None, ge=1, le=65535, description="Default 49 / 1812")
    acct_port: int | None = Field(default=None, ge=1, le=65535, description="Default 49 / 1813")
    vpn: Literal[0, 512] = Field(default=0, description="VPN the Manager reaches it in")
    priority: int = Field(default=0, ge=0, le=7, description="0-7, lower first")
    tag: str | None = Field(default=None, description="RADIUS only: a 4-16 character name")


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
        in when the servers fail. Change it with catsdwan_set_external_authentication."""
        app: SdwanApp = get_client(ctx)
        aaa, radius, tacacs = await _aaa(app)
        out = aaa_view(aaa, radius, tacacs)
        out["sources"] = [f"GET {AAA_PATH}", f"GET {RADIUS_PATH}", f"GET {TACACS_PATH}"]
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
            Field(description="Replace the servers of `protocol` (1-8); omit to keep the current ones"),
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
        """Point Manager logins at TACACS+ or RADIUS servers (ISE) and set the login order. Lockout risk:
        the preview shows the order and servers before and after, names the local fallback, and BLOCKS an
        order without 'local', an order naming a method with no server, and a change that alters nothing.
        Confirm (needs MCP_ENABLE_DANGEROUS) writes /admin/tacacs or /admin/radius, then /admin/aaa, then logs
        in afresh as the API user; if that login fails, the previous order is put back. Secrets are always
        masked. The ISE side: ise_set_tacacs_server / ise_set_shell_profile. Undo: the preview's `undo`."""
        app: SdwanApp = get_client(ctx)
        if servers is not None and not 1 <= len(servers) <= 8:
            raise InvalidRequest("servers takes 1 to 8 servers (omit it to keep the current ones).")
        if authentication and protocol != "tacacs":
            raise InvalidRequest("authentication (pap or ascii) is a TACACS+ setting.")
        for s in servers or []:
            register_secret(s.secret)
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
        aaa_req["authOrder"] = list(order)
        if fallback is not None:
            aaa_req["authFallback"] = fallback
        blockers = order_problems(list(order), has)
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
        warnings = []
        locals_ = ", ".join(dict.fromkeys(["admin", user]))
        if order[0] != "local":
            warnings.append(
                f"{order[0]} is tried first: local users ({locals_}) log in only when it falls back "
                f"along the order. Create {user!r} in ISE with a netadmin role, or test with a second "
                "session first."
            )
        method = "the" + (" new" if servers is not None else "") + f" {protocol} servers"
        plan = Plan(
            f"Set Manager login order {before['order']} -> {list(order)}"
            + (f" and replace the {protocol.upper()} servers" if servers is not None else ""),
            details={
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
            args={
                "protocol": protocol,
                "order": list(order),
                "servers": [s.model_dump() for s in servers] if servers is not None else None,
                "fallback": fallback,
                "server_timeout": server_timeout,
                "authentication": authentication,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
