"""W40 Manager admin login through ISE: catsdwan_test_login and the prompt catsdwan_admin_access_via_ise."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import httpx
import mcp_types
from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import Field

from cat_sdwan_mcp._core import InvalidRequest, Tier, ToolRegistrar, UpstreamError, get_client, tool_ref
from cat_sdwan_mcp._core.secrets import register_secret
from cat_sdwan_mcp.access import AUTH_TYPE_PATH, LOGOUT_PATH, USERS_PATH, data_of
from cat_sdwan_mcp.adminlogin import (
    CLIENT_SERVER_PATH,
    SETTINGS_VAR,
    TEST_LOGIN_SECONDS,
    auth_source,
    granted_view,
    parse_passwords,
)
from cat_sdwan_mcp.client import (
    JWT_LOGIN_PATH,
    SESSION_LOGIN_PATH,
    XSRF_PATH,
    SdwanApp,
    _as_list,
    is_html_response,
    looks_html,
    sdwan_error_detail,
)

PasswordFrom = Literal["auto", "settings", "prompt"]
ASK_KEY = "catsdwan_test_login_password"
USER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@\\-]{0,127}")


@dataclass
class PasswordForm:
    password: str


def _body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


def settings_password(app: SdwanApp, user: str) -> str | None:
    """CATSDWAN_PASSWORD for the API user, else CATSDWAN_TEST_LOGIN_PASSWORDS[user]."""
    if user == app.settings.username and app.settings.password:
        return app.settings.password_value()
    spec = app.settings.test_login_passwords
    if spec is None:
        return None
    try:
        return parse_passwords(spec.get_secret_value()).get(user)
    except ValueError as e:
        raise InvalidRequest(str(e)) from None


def _ask_message(user: str) -> str:
    return (
        f"catsdwan_test_login: the password of {user!r} for one test login to the SD-WAN Manager. It goes "
        "to the Manager only: it is not stored, logged or shown to the model."
    )


def _ask_request(user: str) -> mcp_types.InputRequiredResult:
    schema = {
        "type": "object",
        "properties": {
            "password": {
                "type": "string",
                "title": f"Password for {user}",
                "description": "Used for one login to the SD-WAN Manager; never stored, logged or shown",
            }
        },
        "required": ["password"],
    }
    params = mcp_types.ElicitRequestFormParams(message=_ask_message(user), requested_schema=schema)
    return mcp_types.InputRequiredResult(input_requests={ASK_KEY: mcp_types.ElicitRequest(params=params)})


def _answer(result: Any) -> str | None:
    """The password from an accepted elicitation; None when declined or cancelled."""
    if getattr(result, "action", None) != "accept":
        return None
    content = getattr(result, "content", None)
    if content is None:
        content = getattr(result, "data", None)
    value = content.get("password") if isinstance(content, dict) else getattr(content, "password", None)
    return value if isinstance(value, str) and value else None


async def ask_password(ctx: Context, user: str) -> str | mcp_types.InputRequiredResult | None:
    """The password from the client's prompt: on a 2026-07-28 connection the guard round trip (an
    InputRequiredResult the client answers, then retries the call with), on an older one a server-initiated
    elicitation. None = the user declined. InvalidRequest when the client can't show a prompt."""
    answered = (ctx.input_responses or {}).get(ASK_KEY)
    if answered is not None:
        return _answer(answered)
    caps = getattr(ctx.session, "client_capabilities", None)
    if caps is None or getattr(caps, "elicitation", None) is None:
        raise InvalidRequest(
            f"This client can't prompt for a password (no elicitation support). Put the password in "
            f"{SETTINGS_VAR} on the server (user=password per line; _FILE and _REF work): never in a tool "
            "argument or the chat."
        )
    rc = ctx.request_context
    if rc is not None and rc.protocol_version in MODERN_PROTOCOL_VERSIONS:
        return _ask_request(user)
    try:
        result = await ctx.elicit(_ask_message(user), PasswordForm)
    except ToolError as e:
        raise InvalidRequest(
            f"The client could not prompt for the password ({e}); use {SETTINGS_VAR}."
        ) from None
    return _answer(result)


async def _jwt(app: SdwanApp, user: str, password: str) -> tuple[str, dict[str, str] | None, str | None]:
    """('jwt' | 'session', headers of the new session or None, why it failed)."""
    body = {"username": user, "password": password, "duration": TEST_LOGIN_SECONDS}
    resp = await app.api.send_raw("POST", JWT_LOGIN_PATH, json=body)
    if resp.status_code in (404, 405) or (resp.status_code == 200 and is_html_response(resp)):
        return "session", None, None  # no JWT login on this Manager: use the form login
    if resp.status_code != 200:
        detail = None if is_html_response(resp) else sdwan_error_detail(_body(resp))
        return "jwt", None, f"HTTP {resp.status_code}" + (f": {detail}" if detail else "")
    data = _body(resp)
    token = data.get("token") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token:
        return "jwt", None, sdwan_error_detail(data) or "the answer carried no token"
    register_secret(token)
    headers = {"Authorization": f"Bearer {token}"}
    for k in ("csrf", "refresh"):
        if isinstance(data.get(k), str) and data[k]:
            register_secret(data[k])
    if isinstance(data.get("csrf"), str) and data["csrf"]:
        headers["X-XSRF-TOKEN"] = data["csrf"]
    return "jwt", headers, None


async def _session(app: SdwanApp, user: str, password: str) -> tuple[dict[str, str] | None, str | None]:
    resp = await app.api.send_raw(
        "POST",
        SESSION_LOGIN_PATH,
        data={"j_username": user, "j_password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    cookie = resp.cookies.get("JSESSIONID")
    if cookie:
        register_secret(cookie)
    if resp.status_code != 200 or resp.content.strip() or not cookie:
        if resp.status_code == 200 and is_html_response(resp):
            return None, "the Manager answered with its login page (rejected)"
        return None, f"HTTP {resp.status_code}" + ("" if cookie else ", no session cookie")
    headers = {"Cookie": f"JSESSIONID={cookie}"}
    with contextlib.suppress(UpstreamError, httpx.HTTPError):
        xsrf = await app.api.send_raw("GET", XSRF_PATH, headers=headers)
        text = xsrf.text.strip() if xsrf.status_code == 200 else ""
        if text and not looks_html(text):
            register_secret(text)
            headers["X-XSRF-TOKEN"] = text
    return headers, None


async def _as_user(app: SdwanApp, path: str, headers: dict[str, str]) -> Any:
    """A read with the tested session's headers; None when it gives nothing usable."""
    try:
        resp = await app.api.send_raw("GET", path, headers=headers)
    except (UpstreamError, httpx.HTTPError):
        return None
    if resp.status_code != 200 or is_html_response(resp):
        return None
    return _body(resp)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Test a login to the SD-WAN Manager")
    async def catsdwan_test_login(
        ctx: Context,
        username: Annotated[
            str,
            Field(max_length=128, description="Account to log in as (blank = this server's API user)"),
        ] = "",
        password_from: Annotated[
            PasswordFrom,
            Field(
                description="Where the password comes from: 'settings' (CATSDWAN_PASSWORD for the API user, "
                f"{SETTINGS_VAR} for others), 'prompt' (the client asks the user; it never reaches the "
                "model), 'auto' (settings when they hold one, else prompt)"
            ),
        ] = "auto",
    ) -> dict[str, Any]:
        """Prove that an account can log in to the Manager (a local user, or a RADIUS/TACACS+ user through
        ISE once external authentication is on) and report what the Manager granted: one login with that
        account, separate from this server's session, then two reads as that user. Returns pass/fail with
        the Manager's reason, the user groups (roles: netadmin, operator, ...), whether the Manager treats
        it as an external (remote) user, and whether a local account of that name exists. The password
        never is a tool argument: it comes from the server's settings or a prompt the client shows the
        user, and it is not stored, logged or returned (nor is the session token, which expires within 5
        minutes; a form-login session is logged out). Each failed try counts towards the Manager's lockout
        of that account. Use it before and after catsdwan_set_external_authentication (local admin first)."""
        app: SdwanApp = get_client(ctx)
        user = username.strip() or (app.settings.username or "")
        if not user:
            raise InvalidRequest("Give a username (no API user is configured).")
        if not USER_RE.fullmatch(user):
            raise InvalidRequest("username must be printable text: letters, digits and . _ - @ \\.")
        password = settings_password(app, user) if password_from != "prompt" else None
        source = "settings"
        if password is None:
            if password_from == "settings":
                raise InvalidRequest(
                    f"No password for {user!r} in the settings: set {SETTINGS_VAR} (user=password per line), "
                    "or use password_from='prompt'."
                )
            asked = await ask_password(ctx, user)
            if isinstance(asked, mcp_types.InputRequiredResult):
                # The client prompts the user and retries this call with the answer (FastMCP passes the
                # InputRequiredResult through as the result of this round).
                return asked  # type: ignore[return-value]
            if asked is None:
                return {"username": user, "login": "not tested", "reason": "the password prompt was declined"}
            password, source = asked, "prompt"
        register_secret(password)

        style = app.login_style or app.settings.auth
        method, headers, failure = "session", None, None
        if style in ("auto", "jwt"):
            method, headers, failure = await _jwt(app, user, password)
        if method == "session" and headers is None and failure is None:
            headers, failure = await _session(app, user, password)
        out: dict[str, Any] = {"username": user, "password_from": source, "method": method}
        if headers is None:
            out |= {"login": "failed", "reason": (failure or "rejected")[:300]}
            out["check"] = (
                "a wrong password, a locked account (catsdwan_list_users), or the RADIUS/TACACS+ server "
                "refused it (on ISE: ise_recent_auth_failures, the policy set's hit counters)"
            )
            return out
        out["login"] = "passed"
        try:
            server = await _as_user(app, CLIENT_SERVER_PATH, headers)
            auth_type = await _as_user(app, AUTH_TYPE_PATH, headers)
        finally:
            if method == "session":
                with contextlib.suppress(UpstreamError, httpx.HTTPError):
                    await app.api.send_raw("POST", LOGOUT_PATH, headers=headers)
        granted = granted_view(server)
        if isinstance(auth_type, dict) and auth_type.get("userAuthType"):
            granted["auth_type"] = auth_type["userAuthType"]
        local_users: set[str] | None = None
        try:  # the server's own session reads the local user list
            rows = _as_list(data_of(await app.api.get(USERS_PATH)))
            local_users = {str(u.get("userName")) for u in rows if isinstance(u, dict)}
            out["local_account"] = user in local_users
        except UpstreamError as e:
            out["local_account"] = f"unknown: {str(e)[:150]}"
        out["roles"] = granted.get("roles") or "not reported"
        out["auth_source"] = auth_source(granted, local_users, user)
        out["granted"] = granted or "the Manager gave no session details"
        if granted.get("user") and granted["user"] != user:
            out["note"] = f"the Manager names the session's user {granted['user']!r}"
        out["session"] = (
            f"JWT, never reused, expires within {TEST_LOGIN_SECONDS // 60} minutes"
            if method == "jwt"
            else "form login, logged out"
        )
        return out

    @reg.prompt(
        title="SD-WAN Manager admin login through ISE",
        uses=["catsdwan", "ise", "win"],
        tier=Tier.DANGEROUS,
        example={"manager_ip": "192.0.2.10", "ise_ip": "192.0.2.20"},
    )
    def catsdwan_admin_access_via_ise(
        manager_ip: Annotated[
            str, Field(description="The IP the Manager sends RADIUS from (its VPN 0 or VPN 512 interface)")
        ],
        ise_ip: Annotated[str, Field(description="The ISE node (PSN) address the Manager sends RADIUS to")],
        ad_group: Annotated[
            str, Field(description="AD group whose members get the Manager user group")
        ] = "mcp-sdwan-admins",
        ad_user: Annotated[
            str, Field(description="AD user to prove the login with (created if missing; blank = ask)")
        ] = "",
        sdwan_group: Annotated[
            str,
            Field(description="Manager user group the AD group gets: operator, netadmin or a custom group"),
        ] = "operator",
        vpn: Annotated[
            Literal["0", "512"], Field(description="VPN the Manager reaches ISE in (0 transport, 512 mgmt)")
        ] = "0",
        keep_enabled: Annotated[
            Literal["true", "false"],
            Field(description="false: a proof run, the login order goes back to local at the end"),
        ] = "false",
    ) -> str:
        """Move SD-WAN Manager administrator logins onto Active Directory through ISE over RADIUS: an AD
        group and user, ISE's NAD for the Manager, an authorization profile returning
        Viptela-Group-Name=<group>, a policy set for the Manager's logins, then RADIUS external
        authentication with local first, local and AD test logins, a group change, and an undo list.
        Every write is preview-first; uses the ise and Windows_Server (win_) servers; dangerous tier."""
        texts = (manager_ip, ise_ip, ad_group, ad_user, sdwan_group)
        if any(not ch.isprintable() or ch in '"`' for t in texts for ch in t):
            raise ValueError("Arguments must be printable text without quotes or backticks.")
        try:
            ip = str(ipaddress.ip_address(manager_ip.strip()))
            ise = str(ipaddress.ip_address(ise_ip.strip()))
        except ValueError as exc:
            raise ValueError(f"manager_ip and ise_ip must be IP addresses: {exc}") from exc
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", sdwan_group.strip()):
            raise ValueError(f"sdwan_group must be a Manager user group name, not {sdwan_group!r}.")
        group, user, role = ad_group.strip(), ad_user.strip() or "(ask the user)", sdwan_group.strip()
        other = "netadmin" if role != "netadmin" else "operator"
        profile, other_profile = f"mcp-sdwan-{role}", f"mcp-sdwan-{other}"
        pset = "mcp-sdwan-admin-login"
        end = (
            f"""12. Switch off (keep_enabled=false): {tool_ref("catsdwan_set_external_authentication")}
    protocol='radius', order=['local'] (preview, approval), then {tool_ref("catsdwan_test_login")}
    with the local admin once more and {tool_ref("catsdwan_get_aaa")} (order ['local']). The RADIUS
    server entry may stay on the Manager (unused while the order is local); remove it only if the user
    asks ({tool_ref("catsdwan_api_call")} DELETE /dataservice/admin/radius, preview-first). Then the
    ISE undo, each preview-first: policy set {pset} ({tool_ref("ise_delete_object")}), profiles
    {profile} and {other_profile}, the NAD's RADIUS secret or the NAD itself if step 3 created it
    ({tool_ref("ise_delete_nad")}), and the AD user/group if step 2 created them for this proof (ask
    first)."""
            if keep_enabled == "false"
            else """12. Leave it on (keep_enabled=true). Write the undo list down: the order back to
    ['local'], then the ISE objects created here."""
        )
        return f"""Move SD-WAN Manager admin logins onto AD through ISE (RADIUS): members of AD group
"{group}" get the Manager user group {role}; prove it with AD user {user}. The Manager sends RADIUS
(PAP) from {ip} to ISE at {ise} in VPN {vpn}. Every write is preview-first: show the preview, wait for
the user's approval, then repeat the call with the confirm token. Stop and report on any failure.
Passwords and shared secrets: the user types them where a tool asks; never repeat one in the chat.
catsdwan_test_login takes no password argument: it uses the server's settings or prompts the user.

Lockout rules (read them to the user before step 8):
- authFallback only falls back when the RADIUS server is unreachable or times out. A RADIUS REJECT
  (ISE answering "no", e.g. for admin, who is not in AD) ends the login: it never falls back to local.
- So RADIUS first (order ['radius', 'local']) locks out every local account ISE doesn't know, admin
  and this server's own API user included. Use order ['local', 'radius']: local accounts are checked
  first, a name that isn't a local user goes on to ISE. Never remove 'local' from the order.
- Keep this server's session open until step 9 passes: it is the undo path.

1. Preconditions: {tool_ref("catsdwan_get_aaa")}: note the order, fallback and any RADIUS server
   (local_fallback must stay true). {tool_ref("catsdwan_list_users")}: the local accounts and the
   user groups; {role} must be among `user_groups` (a custom group must exist on the Manager first,
   or the RADIUS user gets no rights). ISE: {tool_ref("ise_status")}, then
   {tool_ref("ise_list_dictionary_attributes")} with dictionary="Viptela" and scope="policyset":
   Viptela-Group-Name (STRING) must be listed (the default authorization scope leaves this OUT-only
   attribute out). If the Viptela dictionary is missing, stop: the user adds it in the ISE GUI
   (Policy > Policy Elements > Dictionaries > System > Radius > RADIUS Vendors: Viptela, vendor id
   41916, attribute Viptela-Group-Name, id 1, string).
2. Active Directory: {tool_ref("win_list_ad_groups")} for "{group}"; create it with
   {tool_ref("win_create_ad_group")} if missing. {tool_ref("win_get_ad_user")} for {user}; create
   it with {tool_ref("win_create_ad_user")} if missing (the user sets the password) and add it with
   {tool_ref("win_add_group_member")}. On ISE: {tool_ref("ise_get_ad_join_point")} (joined, its
   name and domain), {tool_ref("ise_list_ad_groups")}; if "{group}" isn't selectable yet, add it with
   {tool_ref("ise_add_ad_groups")}. {tool_ref("ise_test_ad_user")} for {user} must list the group.
3. ISE NAD for the Manager: {tool_ref("ise_get_nad")} "{ip}". If none, preview
   {tool_ref("ise_create_nad")} name "sdwan-manager", ips ["{ip}"], with a RADIUS shared secret the
   user chooses (the same secret goes on the Manager in step 8). If one exists without RADIUS
   settings (e.g. a TACACS+-only NAD), add the RADIUS secret with {tool_ref("ise_update_nad")}; if it
   has one, the user must know it for step 8.
4. Authorization profiles: {tool_ref("ise_create_authz_profile")} name "{profile}", access accept,
   sdwan_group="{role}" (the preview must show Viptela:Viptela-Group-Name={role}); and the same for
   "{other_profile}" with sdwan_group="{other}" (used by step 10).
5. Policy: create policy set "{pset}" with {tool_ref("ise_create_policy_set")}, condition
   "Network Access:Device IP Address equals {ip}", rank 0, allowed protocols that permit PAP
   (Default Network Access). Authentication: an identity source sequence mcp_sdwan_admins with the
   AD join point ({tool_ref("ise_set_identity_sequence")}), used by an authentication rule in the set
   ({tool_ref("ise_create_authn_rule")}, condition "Network Access:Device IP Address equals {ip}").
   Authorization ({tool_ref("ise_create_authz_rule")}): rule mcp-sdwan-ad with condition
   "<join point>:ExternalGroups equals <domain>/<path>/{group}" (the exact value from step 2) ->
   {profile}. The set's Default rule stays DenyAccess. Review it with {tool_ref("ise_get_policy_set")}.
6. Baseline: {tool_ref("catsdwan_test_login")} with the local admin the user names (blank username =
   this server's API user): it must pass with roles [netadmin] and auth_source "local account".
7. A second break-glass check: ask the user to keep a GUI session to the Manager open as a local
   admin until step 9 passes.
8. External authentication: {tool_ref("catsdwan_set_external_authentication")} protocol='radius',
   order=['local', 'radius'], servers=[{{address: "{ise}", secret: <the step 3 secret, typed by the
   user>, vpn: {vpn}}}], fallback=true. Show the preview (before/after, local_fallback true, the
   warnings) and the lockout rules above; apply only after approval (it needs MCP_ENABLE_DANGEROUS).
   The confirm logs in afresh as the API user and puts the old order back if that fails.
9. Right after: {tool_ref("catsdwan_test_login")} with the local admin again (must still pass, auth
   source local). If it fails, at once {tool_ref("catsdwan_set_external_authentication")}
   protocol='radius', order=['local'] (preview, approval) from this server's session and stop.
10. The AD login: {tool_ref("catsdwan_test_login")} with username="{user}" (the client prompts the user
    for the password, or it comes from the server's settings): it must pass with roles [{role}],
    external_user true and local_account false. ISE: {tool_ref("ise_get_policy_set")} "{pset}": the
    set, the authentication rule and mcp-sdwan-ad must have counted the login (a hit on Default means
    the group or condition didn't match: {tool_ref("ise_test_ad_user")});
    {tool_ref("ise_get_auth_list")} for the NAD or user when ISE logged a session. A failed login:
    {tool_ref("ise_recent_auth_failures")} for the reason; passed but roles not [{role}]: the profile
    didn't return Viptela-Group-Name, or the group doesn't exist on the Manager (step 1).
    Then the group change: point mcp-sdwan-ad at {other_profile} with
    {tool_ref("ise_update_policy_rule")} (preview, approval), test {user} again: roles [{other}].
    Point the rule back at {profile} the same way.
11. Summary: what was created where (AD, ISE NAD, profiles, sequence, policy set, the Manager's
    RADIUS server and order), the login results with the groups granted, and the undo list.
{end}"""
