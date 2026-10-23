"""The SD-WAN Manager "app" object: one ApiClient with JWT or session login, throttling and error mapping.

Login (CATSDWAN_AUTH=auto|jwt|session):
- JWT (20.18.1 and later): POST /jwt/login {username, password, duration} -> {token, csrf, refresh}.
  Requests carry `Authorization: Bearer <token>` and `X-XSRF-TOKEN: <csrf>` (some GETs need it too).
  POST /jwt/refresh renews the token shortly before it expires; there is no logout.
- Session (every release): POST /j_security_check (form j_username, j_password). Success is a JSESSIONID
  cookie and an empty body; a wrong password answers 200 with the HTML login page, so that page is an auth
  error, never a parse error. GET /dataservice/client/token (a plain-text body) gives the XSRF token for
  writes. An idle session (30 min) answers /dataservice calls with 401 or the login page: log in again.
  POST /logout on close.
- auto: JWT first, the session login when /jwt/login answers 404/405 (a Manager before 20.18.1).

The session cookie travels in the token's headers, not httpx's cookie jar (the jar is cleared before every
request), so a re-login replaces it everywhere at once and LoginTokenAuth's single-flight renewal works.

Throttling: the Manager allows 100 requests/s per user (since 20.6), bulk APIs (/dataservice/data/device/...)
48/min and two concurrent bulk statistics requests; a throttled Manager slows every GUI user too.

Errors: the Manager's {"error": {"message", "details", "code"}} body becomes the error text.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any
from urllib.parse import quote

import httpx

from cat_sdwan_mcp._core import AuthError, UpstreamError
from cat_sdwan_mcp._core.http import ApiClient, LoginTokenAuth, NoPaging, RateLimiter, Token
from cat_sdwan_mcp._core.http.client import Expect, default_error_detail
from cat_sdwan_mcp._core.secrets import register_secret
from cat_sdwan_mcp.config import Settings

log = logging.getLogger(__name__)

PRODUCT = "SD-WAN Manager"
ENV_PREFIX = "CATSDWAN_"
JWT_LOGIN_PATH = "/jwt/login"
JWT_REFRESH_PATH = "/jwt/refresh"
SESSION_LOGIN_PATH = "/j_security_check"
XSRF_PATH = "/dataservice/client/token"
LOGOUT_PATH = "/logout"
TENANTS_PATH = "/dataservice/tenant"
VSESSION_PATH = "/dataservice/tenant/{id}/vsessionid"
DEVICE_PATH = "/dataservice/device"
CONTROLLERS_PATH = "/dataservice/system/device/controllers"
VEDGES_PATH = "/dataservice/system/device/vedges"

REQUESTS_PER_MINUTE = 6000  # 100 requests/s, the Manager's per-user limit
BULK_PREFIXES = ("dataservice/data/device/",)
BULK_PER_MINUTE = 48
BULK_CONCURRENCY = 2
STATISTICS_PREFIX = "dataservice/statistics/"
STATISTICS_CONCURRENCY = 2

# The Manager's personality names -> the names its GUI uses since 20.12.
ROLE = {"vmanage": "manager", "vsmart": "controller", "vbond": "validator", "vedge": "edge"}


def _text(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip()
    if isinstance(v, int | float) and not isinstance(v, bool):
        return str(v)
    return None


def looks_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith(("<!doctype html", "<html")) or "<html" in head


def sdwan_error_detail(body: Any) -> str | None:
    """Readable message from the Manager's {"error": {"message", "details", "code"}} body (code first, the
    details only when they add something); an HTML page (the login page) is named, not quoted."""
    if isinstance(body, str) and looks_html(body):
        return "an HTML page instead of JSON (the login page: the session has expired or the login failed)"
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        code, message, details = (_text(err.get(k)) for k in ("code", "message", "details"))
        parts = [p for p in (code, message) if p]
        if details and details != message:
            parts.append(details)
        if parts:
            return ": ".join(parts)[:500]
    return default_error_detail(body)


def _rel(base_url: str, path: str) -> str:
    """`path` relative to the base URL, without the leading slash ("dataservice/device")."""
    if path.startswith(base_url + "/"):
        path = path[len(base_url) :]
    return path.lstrip("/")


def is_html_response(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "").lower()
    return "text/html" in ctype or (bool(resp.content) and looks_html(resp.text))


class SdwanApiClient(ApiClient):
    """ApiClient with the Manager's quirks: the XSRF token on every /dataservice call, separate buckets for
    the bulk APIs, no cookie jar, and the HTML login page on a /dataservice read treated as an expired
    session (log in again once, then an auth error)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.bulk_limiter = RateLimiter(BULK_PER_MINUTE, BULK_CONCURRENCY)
        self.statistics_limiter = RateLimiter(None, STATISTICS_CONCURRENCY)

    def _csrf(self) -> str | None:
        token = self.auth.token if isinstance(self.auth, LoginTokenAuth) else None
        csrf = token.data.get("csrf") if token else None
        return csrf if isinstance(csrf, str) and csrf else None

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        rel = _rel(self.base_url, path)
        # Session state lives in the token's headers; a jar would resend a stale JSESSIONID after a re-login.
        self._http.cookies.clear()
        headers = dict(kwargs.pop("headers", None) or {})
        # Every /dataservice call, reads too: with a JWT, 20.18.3 answers some GETs (/dataservice/health/...)
        # with a 403 login page unless the XSRF token comes along.
        if rel.startswith("dataservice/") and "X-XSRF-TOKEN" not in headers and (csrf := self._csrf()):
            headers["X-XSRF-TOKEN"] = csrf
        kwargs["headers"] = headers
        if rel.startswith(BULK_PREFIXES):
            limiter: RateLimiter | None = self.bulk_limiter
        elif rel.startswith(STATISTICS_PREFIX):
            limiter = self.statistics_limiter
        else:
            limiter = None
        if limiter is None:
            return await super()._send(method, path, **kwargs)
        async with limiter.slot():
            return await super()._send(method, path, **kwargs)

    async def request(self, method: str, path: str, *, expect: Expect = "json", **kw: Any) -> Any:
        if expect != "json" or not _rel(self.base_url, path).startswith("dataservice/"):
            return await super().request(method, path, expect=expect, **kw)
        for attempt in range(2):
            resp: httpx.Response = await super().request(method, path, expect="response", **kw)
            if not is_html_response(resp):
                return self._decode(resp, "json")
            if attempt == 0 and isinstance(self.auth, LoginTokenAuth):
                log.info(
                    "%s answered %s %s with the login page; logging in again", self.product, method, path
                )
                self.auth.invalidate()
        raise AuthError(
            f"{self.product} answered {method.upper()} /{_rel(self.base_url, path)} with its HTML login page "
            f"after a fresh login. Check {self.env_prefix}USERNAME/{self.env_prefix}PASSWORD and that the "
            "account may use the API.",
            401,
        )


def _login_rejected(how: str, detail: str | None = None) -> AuthError:
    # Always 401: a refused login is a credentials problem (`check` reports `auth`), never a role (403) one.
    more = f": {detail}" if detail else ""
    return AuthError(
        f"{PRODUCT} rejected the {how} login{more}. Check {ENV_PREFIX}USERNAME and {ENV_PREFIX}PASSWORD "
        f"(or {ENV_PREFIX}PASSWORD_FILE).",
        401,
    )


class SdwanApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.login_style: str | None = None  # "jwt" or "session" once logged in
        self.tenant_id: str | None = None
        self.auth = LoginTokenAuth(self._login, refresh=self._refresh)
        self.api = SdwanApiClient(
            settings.url,
            product=PRODUCT,
            env_prefix=ENV_PREFIX,
            auth=self.auth,
            verify=settings.verify,
            timeout=settings.timeout,
            retries=settings.retries,
            limiter=RateLimiter(settings.rate_limit or REQUESTS_PER_MINUTE, settings.max_concurrency),
            error_detail=sdwan_error_detail,
            transport=transport,
        )
        # Inventory reads return the whole collection in {"data": [...]}. Configuration lists (offset/limit)
        # and statistics (scrollId) get their own pagers with the tools that need them.
        self.pager = NoPaging(items="data")
        self._version: str | None = None

    # --- login -----------------------------------------------------------------------------

    async def _login(self, client: ApiClient) -> Token:
        user, password = self.settings.require_credentials(ENV_PREFIX)  # AuthError if unset
        style = self.login_style or self.settings.auth
        token: Token | None = None
        if style in ("auto", "jwt"):
            token = await self._jwt_login(client, user, password, fallback=style == "auto")
            style = "jwt" if token is not None else "session"
        if token is None:
            token = await self._session_login(client, user, password)
        self.login_style = style
        return await self._enter_tenant(client, token)

    async def _jwt_login(
        self, client: ApiClient, user: str, password: str, *, fallback: bool
    ) -> Token | None:
        """The JWT login, or None (auto only) when this Manager has no /jwt/login."""
        body = {"username": user, "password": password, "duration": self.settings.session_seconds}
        resp = await client.send_raw("POST", JWT_LOGIN_PATH, json=body)
        missing = resp.status_code in (404, 405) or (resp.status_code == 200 and is_html_response(resp))
        if missing:
            if fallback:
                log.info("%s has no JWT login (HTTP %s); using the session login", PRODUCT, resp.status_code)
                return None
            raise UpstreamError(
                f"{PRODUCT} has no JWT login (POST {JWT_LOGIN_PATH} answered {resp.status_code}; it needs "
                f"20.18.1 or later). Set {ENV_PREFIX}AUTH=session or auto.",
                resp.status_code,
            )
        if resp.status_code in (401, 403):
            raise _login_rejected("JWT", sdwan_error_detail(_body(resp)))
        if resp.is_error or resp.is_redirect:
            raise client.error_from_response(resp)
        return self._jwt_token(_body(resp), self.settings.session_seconds)

    def _jwt_token(self, data: Any, seconds: int) -> Token:
        token = data.get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise _login_rejected("JWT", sdwan_error_detail(data) or "the response carried no token")
        extra = {k: data[k] for k in ("csrf", "refresh") if isinstance(data.get(k), str) and data[k]}
        if "csrf" in extra:
            register_secret(extra["csrf"])
        return Token({"Authorization": f"Bearer {token}"}, Token.expiring_in(seconds), extra)

    async def _refresh(self, client: ApiClient, old: Token) -> Token | None:
        """POST /jwt/refresh with the refresh token (body shape unverified until W0); None = log in again."""
        refresh = old.data.get("refresh")
        if self.login_style != "jwt" or not refresh:
            return None
        resp = await client.send_raw("POST", JWT_REFRESH_PATH, json={"refresh": refresh}, headers=old.headers)
        if resp.status_code != 200 or is_html_response(resp):
            log.info("%s token refresh answered %s; logging in again", PRODUCT, resp.status_code)
            return None
        data = _body(resp)
        if isinstance(data, dict) and "refresh" not in data:
            data = {**data, "refresh": refresh}  # keep using the old refresh token
        return await self._enter_tenant(client, self._jwt_token(data, self.settings.session_seconds))

    async def _session_login(self, client: ApiClient, user: str, password: str) -> Token:
        resp = await client.send_raw(
            "POST",
            SESSION_LOGIN_PATH,
            data={"j_username": user, "j_password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code in (401, 403) or (resp.status_code == 200 and resp.content.strip()):
            # A failed login answers 200 with the HTML login page.
            raise _login_rejected(
                "session", None if is_html_response(resp) else sdwan_error_detail(_body(resp))
            )
        if resp.is_error or resp.is_redirect:
            raise client.error_from_response(resp)
        session = resp.cookies.get("JSESSIONID")
        if not session:
            raise _login_rejected("session", "no JSESSIONID cookie in the answer")
        register_secret(session)
        cookie = {"Cookie": f"JSESSIONID={session}"}
        xsrf = await client.send_raw("GET", XSRF_PATH, headers=cookie)
        text = xsrf.text.strip() if xsrf.status_code == 200 else ""
        if not text or looks_html(text):
            raise _login_rejected(
                "session", f"GET {XSRF_PATH} returned no XSRF token (HTTP {xsrf.status_code})"
            )
        register_secret(text)
        return Token(cookie, None, {"csrf": text})  # idle timeout and lifetime: renewed on 401 / login page

    async def _enter_tenant(self, client: ApiClient, token: Token) -> Token:
        """With CATSDWAN_TENANT: the tenant's VSessionId, added to every request (a provider login)."""
        tenant = self.settings.tenant
        if not tenant:
            return token
        headers = dict(token.headers)
        tenants = await _raw_json(client, "GET", TENANTS_PATH, headers)
        rows = tenants.get("data") if isinstance(tenants, dict) else tenants
        match = next(
            (
                t
                for t in rows or []
                if isinstance(t, dict) and tenant in (str(t.get("tenantId")), t.get("name"), t.get("orgName"))
            ),
            None,
        )
        if match is None:
            raise UpstreamError(
                f"{PRODUCT} has no tenant {tenant!r} (or the account can't list tenants: it needs the Tenant "
                f"Management read role). Check {ENV_PREFIX}TENANT."
            )
        self.tenant_id = str(match["tenantId"])
        csrf = token.data.get("csrf")
        post_headers = {**headers, **({"X-XSRF-TOKEN": csrf} if isinstance(csrf, str) else {})}
        path = VSESSION_PATH.format(id=quote(self.tenant_id, safe=""))
        data = await _raw_json(client, "POST", path, post_headers)
        vsession = data.get("VSessionId") if isinstance(data, dict) else None
        if not isinstance(vsession, str) or not vsession:
            raise UpstreamError(f"{PRODUCT} returned no VSessionId for tenant {tenant!r}")
        register_secret(vsession)
        return Token({**headers, "VSessionId": vsession}, token.expires_at, dict(token.data))

    def login_description(self) -> str:
        if self.login_style == "jwt":
            return f"JWT (POST {JWT_LOGIN_PATH}, {self.settings.session_seconds} s, refreshed before expiry)"
        if self.login_style == "session":
            why = ", no JWT login on this Manager" if self.settings.auth == "auto" else ""
            return f"session (POST {SESSION_LOGIN_PATH} + XSRF token{why})"
        return "not logged in yet"

    async def aclose(self) -> None:
        token = self.auth.token
        if self.login_style == "session" and token is not None:
            try:  # best effort: an idle session times out on its own
                await self.api.send_raw("POST", LOGOUT_PATH, headers=token.headers)
            except (UpstreamError, httpx.HTTPError) as e:
                log.debug("%s logout failed: %s", PRODUCT, e)
            self.auth.invalidate()
        await self.api.aclose()

    # --- helpers ---------------------------------------------------------------------------

    async def get_data(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET and unwrap the usual {"header": ..., "data": ...} envelope (bare bodies pass through)."""
        body = await self.api.get(path, params)
        if isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    async def devices(self) -> list[dict[str, Any]]:
        """GET /dataservice/device: every controller and edge with its live state."""
        return [d for d in _as_list(await self.get_data(DEVICE_PATH)) if isinstance(d, dict)]

    async def controllers(self) -> list[dict[str, Any]]:
        """GET /dataservice/system/device/controllers: the controller inventory with certificates."""
        return [d for d in _as_list(await self.get_data(CONTROLLERS_PATH)) if isinstance(d, dict)]

    async def vedges(self) -> list[dict[str, Any]]:
        """GET /dataservice/system/device/vedges: every WAN edge slot (joined or not) with chassis,
        certificate state and configuration mode."""
        return [d for d in _as_list(await self.get_data(VEDGES_PATH)) if isinstance(d, dict)]

    async def version(self, devices: list[dict[str, Any]] | None = None) -> str:
        """The Manager's release, from its own row(s) in /dataservice/device ("unknown" if absent)."""
        if self._version is None or devices is not None:
            rows = devices if devices is not None else await self.devices()
            found = sorted(
                {str(d["version"]) for d in rows if d.get("personality") == "vmanage" and d.get("version")}
            )
            self._version = ", ".join(found) or "unknown"
        return self._version

    async def status(self) -> dict[str, Any]:
        devices = await self.devices()
        out: dict[str, Any] = {
            "product": PRODUCT,
            "version": await self.version(devices),
            "login": self.login_description(),
            "api_user": self.settings.username,
            "tenant": (
                {"name": self.settings.tenant, "id": self.tenant_id}
                if self.settings.tenant
                else "single-tenant"
            ),
        }
        # The controller inventory adds certificate expiry; failing it shouldn't hide that login works.
        try:
            out["controllers"] = controller_summary(await self.controllers())
        except UpstreamError as e:
            rows = [d for d in devices if d.get("personality") != "vedge"]
            out["controllers"] = {**controller_summary(rows), "inventory_unavailable": str(e)[:200]}
        out["edges"] = edge_summary([d for d in devices if d.get("personality") == "vedge"])
        return out


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


async def _raw_json(client: ApiClient, method: str, path: str, headers: dict[str, str]) -> Any:
    """One login-time request outside the auth strategy (it is still logging in), errors mapped."""
    resp = await client.send_raw(method, path, headers=headers)
    if resp.is_error or resp.is_redirect:
        raise client.error_from_response(resp)
    if is_html_response(resp):
        raise _login_rejected("tenant", f"{method} {path} answered with the login page")
    return _body(resp)


def _reachable(d: dict[str, Any]) -> bool:
    return str(d.get("reachability", "")).lower() == "reachable"


def controller_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by role (manager, controller, validator), the unreachable ones, and each controller's
    certificate expiry (the controller inventory reports it)."""
    roles = Counter(ROLE.get(str(d.get("personality") or d.get("deviceType")), "other") for d in rows)
    detail = []
    for d in rows:
        row = {
            "host": d.get("host-name"),
            "role": ROLE.get(str(d.get("personality") or d.get("deviceType")), d.get("personality")),
            "system_ip": d.get("system-ip"),
            "version": d.get("version"),
            "reachability": d.get("reachability"),
            "certificate_expires": d.get("expirationDate"),
        }
        detail.append({k: v for k, v in row.items() if v is not None})
    unreachable = [d.get("host-name") or d.get("system-ip") for d in rows if not _reachable(d)]
    return {
        "total": len(rows),
        "by_role": dict(sorted(roles.items())),
        "unreachable": len(unreachable),
        **({"unreachable_hosts": unreachable} if unreachable else {}),
        "devices": detail,
    }


def edge_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    unreachable = [d.get("host-name") or d.get("system-ip") for d in rows if not _reachable(d)]
    out: dict[str, Any] = {"total": len(rows), "unreachable": len(unreachable)}
    if unreachable:
        out["unreachable_hosts"] = unreachable[:25]
    versions = Counter(str(d.get("version")) for d in rows if d.get("version"))
    if versions:
        out["versions"] = dict(sorted(versions.items()))
    return out
