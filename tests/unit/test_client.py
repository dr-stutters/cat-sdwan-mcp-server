"""W1: the Manager client: JWT and session login, XSRF on writes, re-login, tenancy, throttling, errors."""

import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
import respx

from cat_sdwan_mcp._core import AuthError, UpstreamError, ValidationFailed
from cat_sdwan_mcp.client import (
    BULK_PER_MINUTE,
    REQUESTS_PER_MINUTE,
    SdwanApp,
    controller_summary,
    edge_summary,
    sdwan_error_detail,
)

from .conftest import SESSION_COOKIE, fixture, make_settings, mock_manager

LOGIN_PAGE = (
    "<!DOCTYPE html>\n<html><head><title>Cisco Catalyst SD-WAN</title></head><body>login</body></html>"
)
HTML = {"Content-Type": "text/html;charset=UTF-8"}


def _session_router(router: respx.MockRouter) -> None:
    router.post("/jwt/login").respond(404)
    router.post("/j_security_check").respond(200, headers={"Set-Cookie": SESSION_COOKIE})
    router.get("/dataservice/client/token").respond(200, text="xsrf-1")
    router.post("/logout").respond(200)


def test_error_detail_shapes() -> None:
    body = {"error": {"message": "Invalid input", "details": "siteId is mandatory", "code": "DEVICE0001"}}
    assert sdwan_error_detail(body) == "DEVICE0001: Invalid input: siteId is mandatory"
    same = {"error": {"message": "Not allowed", "details": "Not allowed", "code": "USER0003"}}
    assert sdwan_error_detail(same) == "USER0003: Not allowed"
    assert "login page" in (sdwan_error_detail(LOGIN_PAGE) or "")
    assert sdwan_error_detail({"message": "plain"}) == "plain"
    assert sdwan_error_detail({}) is None


# --- JWT -------------------------------------------------------------------------------------------


async def test_jwt_login_bearer_and_xsrf_on_writes_only(api: respx.MockRouter) -> None:
    read = api.get("/dataservice/template/feature").respond(json={"data": []})
    write = api.post("/dataservice/template/feature").respond(json={"templateId": "t1"})
    app = SdwanApp(make_settings())
    try:
        assert await app.get_data("/dataservice/template/feature") == []
        await app.api.post("/dataservice/template/feature", {"templateName": "x"})
    finally:
        await app.aclose()
    login = json.loads(api.routes[0].calls.last.request.content)
    assert login == {"username": "admin", "password": "pw", "duration": 3600}
    got = read.calls.last.request.headers
    assert got["Authorization"] == "Bearer jwt-123" and "X-XSRF-TOKEN" not in got
    sent = write.calls.last.request.headers
    assert sent["Authorization"] == "Bearer jwt-123" and sent["X-XSRF-TOKEN"] == "csrf-123"
    assert app.login_style == "jwt"
    assert api.routes[1].call_count == 0  # no logout for JWT


async def test_jwt_duration_from_settings(api: respx.MockRouter) -> None:
    app = SdwanApp(make_settings(session_seconds=7200))
    await app.devices()
    await app.aclose()
    assert json.loads(api.routes[0].calls.last.request.content)["duration"] == 7200


async def test_jwt_refresh_before_expiry(api: respx.MockRouter) -> None:
    refresh = api.post("/jwt/refresh").respond(json={"token": "jwt-456", "csrf": "csrf-456"})
    app = SdwanApp(make_settings())
    try:
        await app.devices()
        assert app.auth.token is not None
        app.auth.token.expires_at = time.monotonic()  # inside the renewal margin
        await app.devices()
    finally:
        await app.aclose()
    assert api.routes[0].call_count == 1  # one full login, then the refresh
    assert json.loads(refresh.calls.last.request.content) == {"refresh": "refresh-123"}
    assert refresh.calls.last.request.headers["Authorization"] == "Bearer jwt-123"
    last = [c for c in api.calls if c.request.url.path == "/dataservice/device"][-1]
    assert last.request.headers["Authorization"] == "Bearer jwt-456"
    assert app.auth.token is not None and app.auth.token.data["refresh"] == "refresh-123"


async def test_jwt_refresh_refused_logs_in_again(api: respx.MockRouter) -> None:
    api.post("/jwt/refresh").respond(401)
    app = SdwanApp(make_settings())
    await app.devices()
    assert app.auth.token is not None
    app.auth.token.expires_at = time.monotonic()
    await app.devices()
    await app.aclose()
    assert api.routes[0].call_count == 2


@pytest.mark.parametrize("status", [401, 403])
async def test_jwt_wrong_password_is_auth(router: respx.MockRouter, status: int) -> None:
    router.post("/jwt/login").respond(
        status, json={"error": {"message": "Authentication failed", "details": "", "code": "AUTH0001"}}
    )
    app = SdwanApp(make_settings())
    with pytest.raises(AuthError, match="CATSDWAN_USERNAME") as e:
        await app.devices()
    await app.aclose()
    assert e.value.status_code == 401 and "AUTH0001: Authentication failed" in str(e.value)
    assert router.routes[0].call_count == 1  # no fallback to the session login on a refused password


async def test_jwt_only_without_jwt_endpoint(router: respx.MockRouter) -> None:
    router.post("/jwt/login").respond(404)
    app = SdwanApp(make_settings(auth="jwt"))
    with pytest.raises(UpstreamError, match="CATSDWAN_AUTH=session"):
        await app.devices()
    await app.aclose()


# --- session ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", [404, 405])
async def test_auto_falls_back_to_session(router: respx.MockRouter, status: int) -> None:
    router.post("/jwt/login").respond(status)
    form = router.post("/j_security_check").respond(200, headers={"Set-Cookie": SESSION_COOKIE})
    router.get("/dataservice/client/token").respond(200, text="xsrf-1")
    logout = router.post("/logout").respond(200)
    read = router.get("/dataservice/device").respond(json=fixture("device"))
    write = router.post("/dataservice/template/feature").respond(json={})
    app = SdwanApp(make_settings())
    await app.devices()
    await app.api.post("/dataservice/template/feature", {})
    assert app.login_style == "session" and "no JWT login" in app.login_description()
    await app.aclose()
    assert form.calls.last.request.content == b"j_username=admin&j_password=pw"
    got = read.calls.last.request.headers
    assert got["Cookie"] == "JSESSIONID=sess-1" and "X-XSRF-TOKEN" not in got
    sent = write.calls.last.request.headers
    assert sent["Cookie"] == "JSESSIONID=sess-1" and sent["X-XSRF-TOKEN"] == "xsrf-1"
    assert logout.call_count == 1 and logout.calls.last.request.headers["Cookie"] == "JSESSIONID=sess-1"


async def test_session_only_skips_jwt(router: respx.MockRouter) -> None:
    _session_router(router)
    router.get("/dataservice/device").respond(json=fixture("device"))
    app = SdwanApp(make_settings(auth="session"))
    await app.devices()
    await app.aclose()
    assert router.routes[0].call_count == 0 and app.login_style == "session"
    assert "no JWT login" not in app.login_description()


async def test_session_wrong_password_is_auth_not_parse_error(router: respx.MockRouter) -> None:
    """A failed form login answers 200 with the HTML login page (and a JSESSIONID)."""
    router.post("/j_security_check").respond(
        200, headers={**HTML, "Set-Cookie": SESSION_COOKIE}, text=LOGIN_PAGE
    )
    app = SdwanApp(make_settings(auth="session"))
    with pytest.raises(AuthError, match="rejected the session login") as e:
        await app.devices()
    await app.aclose()
    assert e.value.status_code == 401 and "<html" not in str(e.value).lower()


async def test_session_without_xsrf_token_is_auth(router: respx.MockRouter) -> None:
    router.post("/j_security_check").respond(200, headers={"Set-Cookie": SESSION_COOKIE})
    router.get("/dataservice/client/token").respond(200, headers=HTML, text=LOGIN_PAGE)
    app = SdwanApp(make_settings(auth="session"))
    with pytest.raises(AuthError, match="no XSRF token"):
        await app.devices()
    await app.aclose()


async def test_session_relogin_on_login_page(router: respx.MockRouter) -> None:
    """An idle session (30 min) answers a /dataservice read with the login page: log in again, once."""
    _session_router(router)
    router.post("/j_security_check").mock(
        side_effect=[
            httpx.Response(200, headers={"Set-Cookie": SESSION_COOKIE}),
            httpx.Response(200, headers={"Set-Cookie": "JSESSIONID=sess-2; Path=/; Secure"}),
        ]
    )
    device = router.get("/dataservice/device").mock(
        side_effect=[
            httpx.Response(200, json={"data": []}),
            httpx.Response(200, headers=HTML, text=LOGIN_PAGE),
            httpx.Response(200, json=fixture("device")),
        ]
    )
    app = SdwanApp(make_settings(auth="session"))
    assert await app.devices() == []
    assert len(await app.devices()) == 3
    await app.aclose()
    assert device.calls[1].request.headers["Cookie"] == "JSESSIONID=sess-1"
    assert device.calls[2].request.headers["Cookie"] == "JSESSIONID=sess-2"  # the jar never resends sess-1


async def test_session_login_page_twice_is_auth(router: respx.MockRouter) -> None:
    _session_router(router)
    router.get("/dataservice/device").respond(200, headers=HTML, text=LOGIN_PAGE)
    app = SdwanApp(make_settings(auth="session"))
    with pytest.raises(AuthError, match="HTML login page after a fresh login"):
        await app.devices()
    await app.aclose()
    assert router.routes[1].call_count == 2


async def test_session_relogin_on_401(router: respx.MockRouter) -> None:
    _session_router(router)
    router.get("/dataservice/device").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"data": [{"personality": "vedge"}]})]
    )
    app = SdwanApp(make_settings(auth="session"))
    assert await app.devices() == [{"personality": "vedge"}]
    await app.aclose()
    assert router.routes[1].call_count == 2


# --- tenancy, errors, throttling -------------------------------------------------------------------


async def test_tenant_vsessionid_on_every_request(api: respx.MockRouter) -> None:
    tenants = api.get("/dataservice/tenant").respond(
        json={"data": [{"tenantId": "t-9", "name": "customer-a"}, {"tenantId": "t-7", "name": "other"}]}
    )
    vsession = api.post("/dataservice/tenant/t-9/vsessionid").respond(json={"VSessionId": "vs-1"})
    app = SdwanApp(make_settings(tenant="customer-a"))
    await app.devices()
    status = await app.status()
    await app.aclose()
    assert tenants.calls.last.request.headers["Authorization"] == "Bearer jwt-123"
    assert vsession.calls.last.request.headers["X-XSRF-TOKEN"] == "csrf-123"
    device = [c for c in api.calls if c.request.url.path == "/dataservice/device"][-1]
    assert device.request.headers["VSessionId"] == "vs-1"
    assert status["tenant"] == {"name": "customer-a", "id": "t-9"}


async def test_unknown_tenant(api: respx.MockRouter) -> None:
    api.get("/dataservice/tenant").respond(json={"data": [{"tenantId": "t-7", "name": "other"}]})
    app = SdwanApp(make_settings(tenant="customer-a"))
    with pytest.raises(UpstreamError, match="no tenant 'customer-a'"):
        await app.devices()
    await app.aclose()


async def test_error_body_is_readable(api: respx.MockRouter) -> None:
    api.post("/dataservice/template/device").respond(
        400, json={"error": {"message": "Template exists", "details": "name br2 in use", "code": "TEMP0001"}}
    )
    app = SdwanApp(make_settings())
    with pytest.raises(ValidationFailed, match="TEMP0001: Template exists: name br2 in use"):
        await app.api.post("/dataservice/template/device", {})
    await app.aclose()


async def test_rate_limit_buckets(api: respx.MockRouter) -> None:
    api.get("/dataservice/data/device/state/Interface").respond(json={"data": []})
    api.post("/dataservice/statistics/approute").respond(json={"data": []})
    app = SdwanApp(make_settings())
    used: list[str] = []

    def counting(name: str, limiter: object) -> None:
        original = limiter.slot  # type: ignore[attr-defined]

        @asynccontextmanager
        async def slot() -> AsyncIterator[None]:
            used.append(name)
            async with original():
                yield

        limiter.slot = slot  # type: ignore[attr-defined]

    counting("bulk", app.api.bulk_limiter)
    counting("statistics", app.api.statistics_limiter)
    try:
        await app.get_data("/dataservice/data/device/state/Interface")
        await app.api.post("/dataservice/statistics/approute", {"query": {}})
        await app.devices()
    finally:
        await app.aclose()
    assert used == ["bulk", "statistics"]
    assert app.api.limiter.per_minute == REQUESTS_PER_MINUTE
    assert app.api.bulk_limiter.per_minute == BULK_PER_MINUTE and app.api.bulk_limiter.max_concurrency == 2
    assert app.api.statistics_limiter.per_minute is None and app.api.statistics_limiter.max_concurrency == 2


def test_rate_limit_setting_overrides_the_default() -> None:
    app = SdwanApp(make_settings(rate_limit=600, max_concurrency=4))
    assert app.api.limiter.per_minute == 600 and app.api.limiter.max_concurrency == 4


# --- status from the recorded 20.18 payloads -------------------------------------------------------


async def test_status_from_recorded_payloads(api: respx.MockRouter) -> None:
    app = SdwanApp(make_settings())
    status = await app.status()
    await app.aclose()
    assert status["version"] == "20.18.3.1"
    assert status["login"].startswith("JWT") and status["tenant"] == "single-tenant"
    controllers = status["controllers"]
    assert controllers["total"] == 3 and controllers["unreachable"] == 0
    assert controllers["by_role"] == {"controller": 1, "manager": 1, "validator": 1}
    validator = next(d for d in controllers["devices"] if d["role"] == "validator")
    assert validator["certificate_expires"] == "Oct 22 06:05:23 2028 GMT" and validator["host"] == "validator"
    assert status["edges"] == {"total": 0, "unreachable": 0}


async def test_status_without_controller_inventory(api: respx.MockRouter) -> None:
    api.get("/dataservice/system/device/controllers").respond(
        403, json={"error": {"message": "Forbidden", "code": "USER0001"}}
    )
    app = SdwanApp(make_settings())
    status = await app.status()
    await app.aclose()
    assert (
        status["controllers"]["total"] == 3 and "USER0001" in status["controllers"]["inventory_unavailable"]
    )


def test_edge_and_controller_summaries() -> None:
    edges = [
        {"host-name": "hub1", "personality": "vedge", "reachability": "reachable", "version": "17.18.02"},
        {"host-name": "br1", "personality": "vedge", "reachability": "unreachable", "version": "17.18.02"},
        {"system-ip": "10.0.0.3", "personality": "vedge", "reachability": "unreachable"},
    ]
    assert edge_summary(edges) == {
        "total": 3,
        "unreachable": 2,
        "unreachable_hosts": ["br1", "10.0.0.3"],
        "versions": {"17.18.02": 2},
    }
    rows = [*fixture("system_device_controllers")["data"]]
    rows[0] = {**rows[0], "reachability": "unreachable"}
    summary = controller_summary(rows)
    assert summary["unreachable"] == 1 and summary["unreachable_hosts"] == ["validator"]


async def test_jwt_login_page_answer_falls_back(router: respx.MockRouter) -> None:
    """A Manager answering an unknown path with the login page (not 404) still gets the session login."""
    mock_manager(router, jwt=False)
    router.routes[0].respond(200, headers=HTML, text=LOGIN_PAGE)
    app = SdwanApp(make_settings())
    await app.devices()
    await app.aclose()
    assert app.login_style == "session"
