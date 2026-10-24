"""W40: catsdwan_test_login and the RADIUS first write of catsdwan_set_external_authentication.

Recorded on 20.18.3.1: GET /dataservice/client/server as the API user (admin: roles ["netadmin"],
externalUser false; CSRFToken and VSessionId redacted). The RADIUS user's answer (externalUser true, roles
["operator"]) is hand-built from that shape, and marked so: no RADIUS login has run on the lab Manager yet.
"""

import json
import logging
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.adminlogin import auth_source, granted_view, parse_passwords

from .conftest import fixture, make_server
from .test_access import mock_aaa

TEST_TOKEN = "jwt-test-login-0001"
TEST_CSRF = "csrf-test-login-0001"
AD_PASSWORD = "Ad-Us3r-pass!"
RADIUS_USER = {  # hand-built from client_server: a RADIUS (ISE) user granted operator
    "data": {
        **fixture("client_server")["data"],
        "user": "ad-op1",
        "roles": ["operator"],
        "externalUser": True,
    }
}


def jwt_router(api: respx.MockRouter, users: dict[str, int | dict[str, Any]]) -> respx.Route:
    """/jwt/login: the server's own login (1800 s) as before; a test login (300 s) answers per user."""

    def login(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["duration"] != 300:
            return httpx.Response(200, json={"token": "jwt-123", "csrf": "csrf-123", "refresh": "r"})
        answer = users.get(body["username"], 401)
        if isinstance(answer, int):
            return httpx.Response(answer, json={"error": {"message": "Authentication failed"}})
        return httpx.Response(200, json={"token": TEST_TOKEN, "csrf": TEST_CSRF, "refresh": "r2"})

    return api.post("/jwt/login").mock(side_effect=login)


def as_user(api: respx.MockRouter, server: Any) -> respx.Route:
    """/client/server answers the test session with `server`, anything else with the recorded admin."""

    def answer(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") == f"Bearer {TEST_TOKEN}":
            assert request.headers.get("X-XSRF-TOKEN") == TEST_CSRF
            return httpx.Response(200, json=server)
        return httpx.Response(200, json=fixture("client_server"))

    api.get("/dataservice/admin/user/userAuthType").respond(json=fixture("admin_user_authtype"))
    api.get("/dataservice/admin/user").respond(json=fixture("admin_user_list"))
    return api.get("/dataservice/client/server").mock(side_effect=answer)


async def test_login_api_user_from_settings(api: respx.MockRouter) -> None:
    login = jwt_router(api, {"admin": {}})
    server = as_user(api, fixture("client_server"))
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_test_login", {})).structured_content
    assert out["login"] == "passed" and out["username"] == "admin" and out["method"] == "jwt"
    assert out["password_from"] == "CATSDWAN_PASSWORD" and out["roles"] == ["netadmin"]
    assert out["auth_source"] == "local account" and out["local_account"] is True
    assert out["granted"]["external_user"] is False and out["granted"]["auth_type"] == "OTHER"
    bodies = [json.loads(c.request.content) for c in login.calls]
    sent = [b for b in bodies if b["duration"] == 300]
    assert sent == [{"username": "admin", "password": "pw", "duration": 300}]
    assert server.called
    text = json.dumps(out)
    assert '"pw"' not in text
    for secret in (TEST_TOKEN, TEST_CSRF, "REDACTED-CSRF-TOKEN", "REDACTED-VSESSION"):
        assert secret not in text


async def test_login_radius_user_from_the_settings(
    api: respx.MockRouter, caplog: pytest.LogCaptureFixture
) -> None:
    jwt_router(api, {"ad-op1": {}})
    as_user(api, RADIUS_USER)
    asked: list[str] = []

    async def prompt(message: str, *_: Any) -> dict[str, str]:  # must never be called
        asked.append(message)
        return {"password": "wrong"}

    caplog.set_level(logging.DEBUG)
    server = make_server(test_login_passwords=f"ad-op1={AD_PASSWORD}")
    async with Client(server, elicitation_handler=prompt) as c:
        out = (await c.call_tool("catsdwan_test_login", {"username": "ad-op1"})).structured_content
    assert asked == []
    assert out["login"] == "passed" and out["password_from"] == "CATSDWAN_TEST_LOGIN_PASSWORDS"
    assert out["roles"] == ["operator"] and out["local_account"] is False
    assert out["auth_source"].startswith("remote")
    assert AD_PASSWORD not in json.dumps(out) and TEST_TOKEN not in json.dumps(out)
    assert AD_PASSWORD not in caplog.text and TEST_TOKEN not in caplog.text


async def test_login_rejected_reports_the_reason(api: respx.MockRouter) -> None:
    jwt_router(api, {})  # every test login answers 401
    async with Client(make_server(test_login_passwords=f"ad-op1={AD_PASSWORD}")) as c:
        out = (await c.call_tool("catsdwan_test_login", {"username": "ad-op1"})).structured_content
    assert out["login"] == "failed" and out["reason"].startswith("HTTP 401")
    assert "Authentication failed" in out["reason"] and AD_PASSWORD not in json.dumps(out)


async def test_login_without_a_settings_password_names_the_setting(api: respx.MockRouter) -> None:
    login = jwt_router(api, {"ad-op1": {}})
    asked: list[str] = []

    async def prompt(message: str, *_: Any) -> dict[str, str]:  # the server never elicits a password
        asked.append(message)
        return {"password": AD_PASSWORD}

    for server in (make_server(), make_server(test_login_passwords="someone-else=x")):
        async with Client(server, elicitation_handler=prompt) as c:
            with pytest.raises(ToolError, match="No password for 'ad-op1'.*CATSDWAN_TEST_LOGIN_PASSWORDS"):
                await c.call_tool("catsdwan_test_login", {"username": "ad-op1"})
    assert asked == []
    assert all(json.loads(c.request.content)["duration"] != 300 for c in login.calls)


async def test_login_settings_password_on_the_session_login(router: respx.MockRouter) -> None:
    router.post("/jwt/login").respond(404)

    def form(request: httpx.Request) -> httpx.Response:
        user = dict(httpx.QueryParams(request.content.decode()))["j_username"]
        return httpx.Response(200, headers={"Set-Cookie": f"JSESSIONID=sess-{user}; Path=/"})

    router.post("/j_security_check").mock(side_effect=form)
    router.get("/dataservice/client/token").respond(200, text="xsrf-1")
    logout = router.post("/logout").respond(200)
    ro = {"data": {**fixture("client_server")["data"], "user": "mcp-ro", "roles": ["operator"]}}
    router.get("/dataservice/client/server").respond(json=ro)
    router.get("/dataservice/admin/user/userAuthType").respond(json=fixture("admin_user_authtype"))
    router.get("/dataservice/admin/user").respond(json=fixture("admin_user_list"))
    server = make_server(test_login_passwords='{"mcp-ro": "ro-s3cret"}')
    async with Client(server) as c:
        out = (await c.call_tool("catsdwan_test_login", {"username": "mcp-ro"})).structured_content
    assert out["login"] == "passed" and out["method"] == "session"
    assert out["roles"] == ["operator"] and out["auth_source"] == "local account"
    assert any(c.request.headers.get("Cookie") == "JSESSIONID=sess-mcp-ro" for c in logout.calls)
    assert "ro-s3cret" not in json.dumps(out) and "sess-mcp-ro" not in json.dumps(out)


async def test_login_refuses_odd_usernames(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        with pytest.raises(ToolError, match="printable"):
            await c.call_tool("catsdwan_test_login", {"username": "a b\nc"})


def test_parse_passwords_and_views() -> None:
    assert parse_passwords("") == {}
    assert parse_passwords("# lab\nad-op1=p=w\n\nmcp-ro = x ") == {"ad-op1": "p=w", "mcp-ro": " x "}
    assert parse_passwords('{"a": "1"}') == {"a": "1"}
    with pytest.raises(ValueError, match="line 1: use user=password"):
        parse_passwords("nopassword")
    with pytest.raises(ValueError, match="JSON object of strings"):
        parse_passwords('{"a": 1}')
    granted = granted_view(fixture("client_server"))
    assert granted == {
        "user": "admin",
        "roles": ["netadmin"],
        "external_user": False,
        "saml_user": False,
        "rbac_vpn_user": False,
        "tenant": "default",
        "user_mode": "tenant",
    }
    assert auth_source({}, {"admin"}, "ad-op1") == "remote (not a local user)"
    assert auth_source({}, None, "x") == "unknown"


async def test_set_external_auth_first_radius_write_sends_defaults(api: respx.MockRouter) -> None:
    mock_aaa(api)
    radius = api.post("/dataservice/admin/radius").respond(json={})
    api.post("/dataservice/admin/aaa").respond(json={})
    api.post("/j_security_check").respond(200, headers={"Set-Cookie": "JSESSIONID=test-1; Path=/"})
    args = {
        "protocol": "radius",
        "order": ["local", "radius"],
        "servers": [{"address": "192.0.2.20", "secret": "radius-s3cret"}],
        "fallback": True,
    }
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        prev = (await c.call_tool("catsdwan_set_external_authentication", args)).structured_content
        assert prev["status"] == "preview" and "warnings" not in prev["preview"]
        assert prev["preview"]["after"]["radius"]["timeout"] == 5
        done = (
            await c.call_tool("catsdwan_set_external_authentication", {**args, "confirm": prev["confirm"]})
        ).structured_content["result"]
    sent = json.loads(radius.calls[0].request.content)
    assert sent["timeout"] == 5 and sent["retransmit"] == 3
    # The 20.18 GUI's own server entry (Wave 8 capture): key "", sourceVpn, no vpn/vpnIpSubnet/tag at VPN 0.
    assert sent["server"] == [
        {
            "address": "192.0.2.20",
            "authPort": 1812,
            "acctPort": 1813,
            "key": "",
            "secretKey": "radius-s3cret",
            "priority": 0,
            "sourceVpn": 0,
        }
    ]
    assert done["outcome"] == "done" and "radius-s3cret" not in json.dumps(done)
