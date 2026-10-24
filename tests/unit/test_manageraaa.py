"""W40 (#66, #100): catsdwan_set_external_authentication on a single-tenant Manager goes to its system AAA.

Recorded on 20.18.3.1 (Wave 8): /client/server tenancyMode "SingleTenant" (fixture client_server), the
Manager in CLI mode, and its running configuration (GET /template/config/running/{uuid}; fixture
template_config_running_manager: password hashes, organisation and addresses replaced) with
`aaa / auth-order local radius tacacs` and no radius block. The GUI capture found no Remote AAA tab on a
single-tenant Manager (provider-only /admin/radius, /admin/aaa). The CLI template create answer is the spec's
example ({templateId}); the attach and its action status follow Cisco's documented shapes (as in
test_changes); the confirm path runs against mocks only.
"""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from cat_sdwan_mcp.access import server_body
from cat_sdwan_mcp.configuration import mask_config
from cat_sdwan_mcp.manageraaa import edit_system_aaa, system_aaa, tenancy

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

MGR = "00000000-0000-4000-8000-000000000001"
RUNNING = f"/dataservice/template/config/running/{MGR}"
SECRET = "radius-s3cret-w40"
ISE = "198.51.100.35"
ARGS: dict[str, Any] = {
    "protocol": "radius",
    "order": ["local", "radius"],
    "servers": [{"address": ISE, "secret": SECRET, "vpn": 512}],
    "fallback": True,
}
LOGIN_OK = httpx.Response(200, headers={"Set-Cookie": "JSESSIONID=t-1; Path=/"})
LOGIN_REJECTED = httpx.Response(200, text="<html>login</html>", headers={"Content-Type": "text/html"})


def running_text() -> str:
    return str(fixture("template_config_running_manager")["config"])


def server(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw)


def mock_single(api: respx.MockRouter, *, templates: Any = None) -> dict[str, respx.Route]:
    mock_inventory(api)
    api.get("/dataservice/client/server").respond(json=fixture("client_server"))
    api.get(RUNNING).respond(json=fixture("template_config_running_manager"))
    api.get("/dataservice/device/action/status/tasks").respond(json={"runningTasks": []})
    api.get("/dataservice/template/device").respond(json=templates or {"data": []})
    return {
        "admin_radius": api.post("/dataservice/admin/radius").respond(400),
        "admin_aaa": api.post("/dataservice/admin/aaa").respond(400),
        "create": api.post("/dataservice/template/device/cli").respond(json={"templateId": "tpl-w40"}),
        "input": api.post("/dataservice/template/device/config/input").respond(
            json={
                "header": {"columns": []},
                "data": [
                    {
                        "csv-status": "complete",
                        "csv-deviceId": MGR,
                        "csv-deviceIP": "1.1.1.1",
                        "csv-host-name": "manager",
                    }
                ],
            }
        ),  # fmt: skip
        "attach": api.post("/dataservice/template/device/config/attachcli").respond(json={"id": "push-w40"}),
        "status": api.get("/dataservice/device/action/status/push-w40").respond(
            json={
                "data": [
                    {
                        "host-name": "manager",
                        "system-ip": "1.1.1.1",
                        "uuid": MGR,
                        "status": "Success",
                        "statusId": "success",
                    }
                ],
                "summary": {"status": "done"},
            }
        ),  # fmt: skip
        "logout": api.post("/logout").respond(200),
    }


async def tool(c: Client, args: dict[str, Any]) -> dict[str, Any]:
    out = (await c.call_tool("catsdwan_set_external_authentication", args)).structured_content
    assert out is not None
    return out


async def test_single_tenant_preview_is_the_system_aaa(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
    assert prev["status"] == "preview", prev.get("blockers")
    p = prev["preview"]
    assert p["path"] == "system AAA (single-tenant Manager)"
    assert "only for a multi-tenant provider" in p["why"] and "Remote AAA" in p["why"]
    assert p["before"] == {
        "order": ["local", "radius", "tacacs"],
        "fallback": False,
        "radius": "not configured",
    }
    assert p["after"]["order"] == ["local", "radius"] and p["after"]["fallback"] is True
    assert p["after"]["radius"]["servers"] == [
        {"address": ISE, "vpn": 512, "secret-key": "********", "auth-port": 1812, "acct-port": 1813,
         "priority": 0}
    ]  # fmt: skip
    diff = json.dumps(p["diff_vs_running"])
    assert "auth-order local radius" in diff and "auth-fallback" in diff and f"server {ISE}" in diff
    assert "vpn 0" not in json.dumps(p["diff_vs_running"].get("only_intended", []))  # nothing else changes
    assert p["requests"][0].startswith("POST /j_security_check (test login as admin, before")
    assert p["requests"][1].startswith("POST /dataservice/template/device/cli (CLI device template")
    assert "attachcli" in p["requests"][2]
    assert p["tier"] == "dangerous" and p["local_fallback"] is True
    assert "servers=[])" in p["undo"] and "order=['local', 'radius', 'tacacs']" in p["undo"]
    assert SECRET not in json.dumps(prev)
    assert not routes["admin_radius"].called and not routes["admin_aaa"].called


async def test_single_tenant_confirm_attaches_the_template_and_tests_logins(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    login = api.post("/j_security_check").mock(side_effect=[LOGIN_OK, LOGIN_OK])
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
        done = (await tool(c, {**ARGS, "confirm": prev["confirm"]}))["result"]
    assert login.call_count == 2 and done["outcome"] == "done"
    assert done["test_login_before"]["ok"] and done["test_login"]["ok"]
    body = json.loads(routes["create"].calls[0].request.content)
    assert body["templateName"] == "mcp-manager-system-aaa" and body["deviceType"] == "vmanage"
    assert body["configType"] == "file" and body["factoryDefault"] is False
    cfg = body["templateConfiguration"]
    assert f"  server {ISE}\n   vpn 512\n   secret-key {SECRET}\n" in cfg
    assert "  auth-order local radius\n  auth-fallback\n" in cfg
    assert "$6$REDACTED-HASH-ADMIN" in cfg and "ip route 0.0.0.0/0 198.51.100.1" in cfg  # the rest kept
    push = json.loads(routes["attach"].calls[0].request.content)["deviceTemplateList"][0]
    assert push["templateId"] == "tpl-w40"
    assert push["device"][0]["csv-deviceId"] == MGR and push["device"][0]["csv-templateId"] == "tpl-w40"
    assert done["attach"]["outcome"] == "success"
    assert not routes["admin_radius"].called and not routes["admin_aaa"].called
    assert SECRET not in json.dumps(done)


async def test_single_tenant_rolls_back_when_the_login_fails_after(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    api.post("/j_security_check").mock(side_effect=[LOGIN_OK, LOGIN_REJECTED])
    put = api.put("/dataservice/template/device/tpl-w40").respond(json={})
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
        done = (await tool(c, {**ARGS, "confirm": prev["confirm"]}))["result"]
    assert done["outcome"] == "rolled back" and routes["attach"].call_count == 2
    restored = json.loads(put.calls[0].request.content)["templateConfiguration"]
    assert restored == running_text() and "radius" not in system_aaa(restored)["order"][3:]
    assert "secret-key" not in restored


async def test_single_tenant_stops_when_the_login_fails_before(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    api.post("/j_security_check").mock(return_value=LOGIN_REJECTED)
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
        done = (await tool(c, {**ARGS, "confirm": prev["confirm"]}))["result"]
    assert done["outcome"] == "not started" and not routes["create"].called and not routes["attach"].called


async def test_single_tenant_blocks(api: respx.MockRouter) -> None:
    mock_single(api)
    async with Client(server()) as c:
        no_local = await tool(c, {**ARGS, "order": ["radius"]})
        tacacs = await tool(c, {**ARGS, "protocol": "tacacs", "order": ["local", "tacacs"]})
        noop = await tool(c, {"protocol": "radius", "order": ["local", "radius", "tacacs"]})
    assert no_local["status"] == "blocked" and "has no 'local'" in no_local["blockers"][0]
    assert any("TACACS+ for the Manager's own logins is not built yet" in b for b in tacacs["blockers"])
    assert any("nothing to change" in b for b in noop["blockers"])


async def test_single_tenant_needs_dangerous(api: respx.MockRouter) -> None:
    mock_single(api)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = await tool(c, ARGS)
    assert prev["status"] == "blocked" and any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])


async def test_manager_on_another_template_is_blocked(api: respx.MockRouter) -> None:
    mock_single(api)
    ctrl = fixture("system_device_controllers")
    for r in ctrl["data"]:
        if r.get("uuid") == MGR or r.get("deviceType") == "vmanage":
            r.update({"configOperationMode": "vmanage", "template": "dc-manager"})
    api.get("/dataservice/system/device/controllers").respond(json=ctrl)
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
    assert any("device template dc-manager" in b and "AAA feature template" in b for b in prev["blockers"])


def test_edit_and_read_system_aaa() -> None:
    text = running_text()
    view = system_aaa(text)
    assert view["order"] == ["local", "radius", "tacacs"] and view["radius"] == "not configured"
    servers = [{"address": ISE, "secret": SECRET, "vpn": 512, "tag": "ise1", "priority": 1}]
    new = edit_system_aaa(
        text, order=["local", "radius"], fallback=True, servers=servers, timeout=5, retransmit=3
    )
    got = system_aaa(new)
    assert got["order"] == ["local", "radius"] and got["fallback"] is True
    assert got["radius"] == {
        "servers": [{"address": ISE, "vpn": 512, "tag": "ise1", "secret-key": "********", "auth-port": 1812,
                     "acct-port": 1813, "priority": 1}],
        "retransmit": 3, "timeout": 5,
    }  # fmt: skip
    # Only the AAA lines differ; the undo (servers=[], the old order, no fallback) gives the old text back
    # apart from the auth-order line's spacing.
    back = edit_system_aaa(new, order=["local", "radius", "tacacs"], fallback=False, servers=[], timeout=None,
                           retransmit=None)  # fmt: skip
    assert [ln.split() for ln in back.splitlines()] == [ln.split() for ln in text.splitlines()]
    kept = edit_system_aaa(
        new, order=["local", "radius"], fallback=None, servers=None, timeout=None, retransmit=None
    )
    assert system_aaa(kept)["radius"] == got["radius"] and system_aaa(kept)["fallback"] is True
    assert SECRET not in mask_config(new)[0]


def test_tenancy_and_provider_radius_body() -> None:
    assert tenancy(fixture("client_server")) == "single"
    assert tenancy({"data": {"tenancyMode": "MultiTenant"}}) == "multi" and tenancy({}) is None
    vpn512 = server_body(
        "radius",
        {"address": ISE, "secret": "k", "vpn": 512, "destination_vpn": 10, "vpn_ip_subnet": "198.51.100.0/24",
         "tag": "x"},
    )  # fmt: skip
    assert vpn512 == {
        "address": ISE, "authPort": 1812, "acctPort": 1813, "key": "", "secretKey": "k", "priority": 0,
        "sourceVpn": 512, "vpn": 10, "vpnIpSubnet": "198.51.100.0/24",
    }  # fmt: skip
    vpn0 = server_body("radius", {"address": ISE, "secret": "k"})
    assert "vpn" not in vpn0 and "vpnIpSubnet" not in vpn0 and "tag" not in vpn0 and vpn0["sourceVpn"] == 0
