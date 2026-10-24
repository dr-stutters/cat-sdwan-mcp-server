"""W40 Manager admin login through ISE: the helpers of catsdwan_test_login.

A test login is one login with the caller's credentials, separate from this server's own session: JWT
(POST /jwt/login, 20.18.1 and later; the token simply expires, there is no logout) or the form login
(POST /j_security_check, logged out again at once). With the new session the tool reads what the Manager
granted, as that user: GET /dataservice/client/server (recorded on 20.18.3.1: `user`, `roles` such as
["netadmin"], `externalUser` false for a local account, `isSamlUser`, plus the session's CSRFToken and
VSessionId, which are dropped) and GET /dataservice/admin/user/userAuthType.

Passwords come from the server's settings (CATSDWAN_PASSWORD for the API user, CATSDWAN_TEST_LOGIN_PASSWORDS
for other accounts) only: never from a tool argument and never from a client prompt (the MCP spec forbids
asking for passwords through form-mode elicitation), so they never pass through the conversation. They are registered as secrets (masked in logs) and never returned.
"""

from __future__ import annotations

import json
from typing import Any

from cat_sdwan_mcp.client import _as_list

CLIENT_SERVER_PATH = "/dataservice/client/server"
TEST_LOGIN_SECONDS = 300  # the shortest JWT the tool asks for; it is never used again after the reads
SETTINGS_VAR = "CATSDWAN_TEST_LOGIN_PASSWORDS"
# Fields of /client/server worth reporting; CSRFToken and VSessionId are session secrets and never copied.
GRANTED_FIELDS = {
    "user": "user",
    "roles": "roles",
    "externalUser": "external_user",
    "isSamlUser": "saml_user",
    "isRbacVpnUser": "rbac_vpn_user",
    "tenantId": "tenant",
    "userMode": "user_mode",
}


def parse_passwords(spec: str) -> dict[str, str]:
    """CATSDWAN_TEST_LOGIN_PASSWORDS: a JSON object {"user": "password"} or one `user=password` per line
    (the password is everything after the first '='; blank lines and '#' comments are skipped)."""
    text = spec.strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError as e:
            raise ValueError(f"{SETTINGS_VAR} is not valid JSON (line {getattr(e, 'lineno', '?')})") from None
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise ValueError(f'{SETTINGS_VAR} must be a JSON object of strings, {{"user": "password"}}')
        return {k.strip(): v for k, v in data.items() if k.strip() and v}
    out: dict[str, str] = {}
    for n, line in enumerate(spec.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        user, sep, password = line.partition("=")
        if not sep or not user.strip() or not password:
            raise ValueError(f"{SETTINGS_VAR} line {n}: use user=password")
        out[user.strip()] = password.rstrip("\r\n")
    return out


def granted_view(body: Any) -> dict[str, Any]:
    """What the Manager granted the session, from /client/server (no session secrets)."""
    data = body.get("data", body) if isinstance(body, dict) else {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, Any] = {}
    for key, name in GRANTED_FIELDS.items():
        if key in data and data[key] not in (None, ""):
            out[name] = [str(r) for r in _as_list(data[key])] if key == "roles" else data[key]
    return out


def auth_source(granted: dict[str, Any], local_users: set[str] | None, user: str) -> str:
    """Local account or a remote server (RADIUS/TACACS+, e.g. ISE), from externalUser and the user list."""
    ext = granted.get("external_user")
    if ext is True:
        return "remote (RADIUS or TACACS+ server, e.g. ISE)"
    if granted.get("saml_user") is True:
        return "SAML (single sign-on)"
    if ext is False:
        return "local account"
    if local_users is not None:
        return "local account" if user in local_users else "remote (not a local user)"
    return "unknown"
