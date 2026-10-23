"""W26: Manager users, AAA and external authentication.

Recorded on 20.18.3.1: the three users (admin, mcp-ro operator, mcp-rw netadmin), the five default user groups
(trimmed to each group's first 30 of 360 features), the active sessions, the API login's auth type, VPN groups
and the never-set AAA, RADIUS and TACACS+ objects (`"data": {}`). A configured AAA (TACACS+ first, a server
with a secret) is hand-built from the 20.18 OpenAPI schema, and marked so. The write is preview-only in the
live run (lockout risk); confirm is exercised here against mocks only.
"""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from cat_sdwan_mcp.access import aaa_view, order_problems

from .conftest import fixture, make_server
from .test_inventory import call

SECRET = "tacacs-shared-s3cret"
TACACS_SET = {  # hand-built: TACACS+ configured, order tacacs then local
    "data": {"authentication": "pap", "timeout": 5, "servers": [
        {"address": "198.18.133.27", "secretKey": "$CRYPT$abcdefghijklmnopq", "authPort": 49, "acctPort": 49,
         "vpn": 0, "priority": 0}]}
}  # fmt: skip
AAA_SET = {"data": {"authOrder": ["tacacs", "local"], "authFallback": True, "accounting": False}}


def mock_aaa(api: respx.MockRouter, aaa: Any = None, tacacs: Any = None) -> None:
    api.get("/dataservice/admin/aaa").respond(json=aaa or fixture("admin_aaa"))
    api.get("/dataservice/admin/radius").respond(json=fixture("admin_radius"))
    api.get("/dataservice/admin/tacacs").respond(json=tacacs or fixture("admin_tacacs"))


async def test_list_users_groups_and_sessions(api: respx.MockRouter) -> None:
    api.get("/dataservice/admin/user").respond(json=fixture("admin_user_list"))
    api.get("/dataservice/admin/usergroup").respond(json=fixture("admin_usergroup_trimmed"))
    api.get("/dataservice/admin/user/activeSessions").respond(json=fixture("admin_user_activesessions"))
    api.get("/dataservice/admin/vpngroup").respond(json=fixture("admin_vpngroup"))
    api.get("/dataservice/admin/user/userAuthType").respond(json=fixture("admin_user_authtype"))
    out = await call("catsdwan_list_users", {"response_format": "json"})
    users = {u["user"]: u for u in out["results"]}
    assert list(users) == ["admin", "mcp-ro", "mcp-rw"]
    assert users["admin"]["groups"] == ["netadmin (built-in admin)"] and users["admin"]["sessions"] == 13
    assert users["mcp-ro"]["groups"] == ["operator"] and users["mcp-rw"]["groups"] == ["netadmin"]
    groups = {g["group"]: g for g in out["user_groups"]}
    assert groups["operator"]["write"] == 0 and groups["netadmin"]["write_features"] == "all"
    assert (
        groups["security_operations"]["write"] == 6
        and len(groups["security_operations"]["write_features"]) == 6
    )
    [sessions] = out["sessions"]
    assert sessions == {"user": "admin", "sessions": 13, "sources": ["192.0.2.10"], "modes": ["webui"]}
    assert out["vpn_groups"] == "none" and out["this_login_auth_type"] == "OTHER"
    assert "remote_users" not in out


async def test_get_aaa_default_is_local_only(api: respx.MockRouter) -> None:
    mock_aaa(api)
    out = await call("catsdwan_get_aaa", {})
    assert out["order"] == ["local"] and out["order_source"].startswith("not set")
    assert out["radius"] == "not configured" and out["tacacs"] == "not configured"
    assert out["local_fallback"] is True


async def test_get_aaa_configured_masks_secret(api: respx.MockRouter) -> None:
    mock_aaa(api, aaa=AAA_SET, tacacs=TACACS_SET)
    out = await call("catsdwan_get_aaa", {})
    assert out["order"] == ["tacacs", "local"] and out["fallback"] is True
    [server] = out["tacacs"]["servers"]
    assert server["address"] == "198.18.133.27" and server["secretKey"] == "********"
    assert "$CRYPT$" not in json.dumps(out)


def writes(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


TACACS_ARGS = {
    "protocol": "tacacs",
    "order": ["tacacs", "local"],
    "servers": [{"address": "198.18.133.27", "secret": SECRET}],
}


async def test_set_external_auth_preview_shows_order_and_needs_dangerous(api: respx.MockRouter) -> None:
    mock_aaa(api)
    put = api.put("/dataservice/admin/aaa").respond(json={})
    async with Client(writes()) as c:
        prev = (await c.call_tool("catsdwan_set_external_authentication", TACACS_ARGS)).structured_content
    assert prev["status"] == "blocked" and not put.called
    assert any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])
    p = prev["preview"]
    assert p["before"]["order"] == ["local"] and p["after"]["order"] == ["tacacs", "local"]
    assert p["local_fallback"] is True and p["after"]["tacacs"]["servers"][0]["secretKey"] == "********"
    assert p["after"]["tacacs"]["servers"][0]["authPort"] == 49
    assert p["requests"][0] == "POST /dataservice/admin/tacacs"  # never set before: POST
    assert "tacacs is tried first" in p["warnings"][0]
    assert p["undo"] == "catsdwan_set_external_authentication(protocol='tacacs', order=['local'])"
    assert SECRET not in json.dumps(prev)


async def test_set_external_auth_refuses_order_without_local(api: respx.MockRouter) -> None:
    mock_aaa(api)
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args = {**TACACS_ARGS, "order": ["tacacs"]}
        prev = (await c.call_tool("catsdwan_set_external_authentication", args)).structured_content
        no_server = {"protocol": "radius", "order": ["radius", "local"]}
        prev2 = (await c.call_tool("catsdwan_set_external_authentication", no_server)).structured_content
    assert prev["status"] == "blocked" and prev["preview"]["local_fallback"] is False
    assert prev["blockers"][0].startswith("order ['tacacs'] has no 'local'")
    assert not any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])
    assert prev2["status"] == "blocked"
    assert "uses radius, but no RADIUS server is configured" in prev2["blockers"][0]


async def test_set_external_auth_confirm_writes_and_tests_login(api: respx.MockRouter) -> None:
    mock_aaa(api)
    tacacs = api.post("/dataservice/admin/tacacs").respond(json={})
    aaa = api.post("/dataservice/admin/aaa").respond(json={})
    login = api.post("/j_security_check").respond(200, headers={"Set-Cookie": "JSESSIONID=test-1; Path=/"})
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = (await c.call_tool("catsdwan_set_external_authentication", TACACS_ARGS)).structured_content
        assert prev["status"] == "preview"
        args = {**TACACS_ARGS, "confirm": prev["confirm"]}
        done = (await c.call_tool("catsdwan_set_external_authentication", args)).structured_content["result"]
    sent = json.loads(tacacs.calls[0].request.content)
    assert sent["servers"][0] == {
        "address": "198.18.133.27",
        "secretKey": SECRET,
        "authPort": 49,
        "acctPort": 49,
        "vpn": 0,
        "priority": 0,
    }
    assert json.loads(aaa.calls[0].request.content) == {"authOrder": ["tacacs", "local"]}
    assert login.called and done["outcome"] == "done" and done["test_login"]["ok"] is True
    assert SECRET not in json.dumps(done)


async def test_set_external_auth_rolls_back_when_test_login_fails(api: respx.MockRouter) -> None:
    mock_aaa(api, aaa=AAA_SET, tacacs=TACACS_SET)
    put_aaa = api.put("/dataservice/admin/aaa").respond(json={})
    api.post("/j_security_check").mock(
        return_value=httpx.Response(
            200, text="<html><body>login</body></html>", headers={"Content-Type": "text/html"}
        )
    )
    args: dict[str, Any] = {"protocol": "tacacs", "order": ["local", "tacacs"]}
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = (await c.call_tool("catsdwan_set_external_authentication", args)).structured_content
        assert prev["status"] == "preview" and prev["preview"]["requests"][0].startswith(
            "PUT /dataservice/admin/aaa"
        )
        done = (
            await c.call_tool("catsdwan_set_external_authentication", {**args, "confirm": prev["confirm"]})
        ).structured_content["result"]
    assert done["outcome"] == "rolled back" and "rejected" in done["test_login"]["detail"]
    first, second = (json.loads(c.request.content) for c in put_aaa.calls)
    assert first["authOrder"] == ["local", "tacacs"] and second["authOrder"] == ["tacacs", "local"]
    assert second["authFallback"] is True


def test_order_problems_and_view() -> None:
    assert order_problems(["local"], {"radius": False, "tacacs": False}) == []
    assert "twice" in order_problems(["local", "local"], {"radius": False, "tacacs": False})[0]
    view = aaa_view(fixture("admin_aaa"), fixture("admin_radius"), fixture("admin_tacacs"))
    assert view["order"] == ["local"] and view["local_fallback"] is True
