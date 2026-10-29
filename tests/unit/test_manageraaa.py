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
    # C81: the back-out step is a real call: the factory order back, local first, no RADIUS server
    assert prev["undo"] == (
        'back-out: catsdwan_set_external_authentication(protocol="radius", '
        'order=["local", "radius", "tacacs"], servers=[])'
    )
    assert SECRET not in json.dumps(prev)
    assert not routes["admin_radius"].called and not routes["admin_aaa"].called


async def test_single_tenant_confirm_attaches_the_template_and_tests_logins(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    login = api.post("/j_security_check").mock(side_effect=[LOGIN_OK, LOGIN_OK])
    async with Client(server()) as c:
        prev = await tool(c, ARGS)
        applied = await tool(c, {**ARGS, "confirm": prev["confirm"]})
        done = applied["result"]
    assert applied["undo"]["tool"] == "catsdwan_set_external_authentication"
    assert applied["undo"]["args"] == {
        "protocol": "radius",
        "order": ["local", "radius", "tacacs"],
        "servers": [],
    }
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
        tacacs = await tool(c, {"protocol": "tacacs", "order": ["local", "tacacs"]})
        noop = await tool(c, {"protocol": "radius", "order": ["local", "radius", "tacacs"]})
    assert no_local["status"] == "blocked" and "has no 'local'" in no_local["blockers"][0]
    assert any("uses tacacs, but no TACACS server" in b for b in tacacs["blockers"])
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


async def test_single_tenant_undo_of_a_first_radius_change_is_not_blocked(api: respx.MockRouter) -> None:
    # #120: the first change's undo (order local radius tacacs, servers=[]) was refused by the tool's own
    # rule "uses radius, but no RADIUS server is configured". The factory order is allowed back.
    mock_single(api)
    with_radius = edit_system_aaa(
        running_text(),
        order=["local", "radius"],
        fallback=True,
        servers=[{"address": ISE, "secret": SECRET, "vpn": 512}],
        timeout=5,
        retransmit=3,
    )
    api.get(RUNNING).respond(json={**fixture("template_config_running_manager"), "config": with_radius})
    async with Client(server()) as c:
        prev = await tool(c, {"protocol": "radius", "order": ["local", "radius", "tacacs"], "servers": []})
        bare = await tool(c, {"protocol": "radius", "order": ["local", "radius"], "servers": []})
    assert prev["status"] == "preview", prev.get("blockers")
    assert prev["preview"]["after"]["radius"] == "removed"
    assert any("factory order" in w for w in prev["preview"]["warnings"])
    assert bare["status"] == "blocked" and any("no RADIUS server" in b for b in bare["blockers"])


def test_undo_order_passes_the_guard() -> None:
    from cat_sdwan_mcp.tools.manageraaa import undo_order

    factory = {"order": ["local", "radius", "tacacs"], "radius": "not configured"}
    assert undo_order(factory) == ["local", "radius", "tacacs"]
    assert undo_order({"order": ["local", "radius"], "radius": "not configured"}) == ["local"]
    assert undo_order({"order": ["local", "radius"], "radius": {"servers": [{}]}}) == ["local", "radius"]


# --- W26 (#158): TACACS+ in the system AAA ---------------------------------------------------------------

TAC_SECRET = "tacacs-s3cret-w26"
TAC = "198.51.100.36"
TAC_ARGS: dict[str, Any] = {
    "protocol": "tacacs",
    "order": ["local", "tacacs"],
    "servers": [{"address": TAC, "secret": TAC_SECRET, "vpn": 512}],
    "fallback": True,
    "authentication": "ascii",
}


def with_radius() -> str:
    """The lab's state after the W40 round: RADIUS set, order local radius, fallback on."""
    return edit_system_aaa(
        running_text(),
        order=["local", "radius"],
        fallback=True,
        servers=[{"address": ISE, "secret": SECRET, "vpn": 512, "tag": "ise1"}],
        timeout=5,
        retransmit=3,
    )


def mock_running(api: respx.MockRouter, text: str) -> None:
    api.get(RUNNING).respond(json={**fixture("template_config_running_manager"), "config": text})


async def test_single_tenant_tacacs_preview(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    async with Client(server()) as c:
        prev = await tool(c, TAC_ARGS)
    assert prev["status"] == "preview", prev.get("blockers")
    p = prev["preview"]
    assert p["path"] == "system AAA (single-tenant Manager)"
    factory = ["local", "radius", "tacacs"]
    assert p["before"] == {"order": factory, "fallback": False, "tacacs": "not configured"}
    assert p["after"]["order"] == ["local", "tacacs"] and p["after"]["fallback"] is True
    assert p["after"]["tacacs"] == {
        "servers": [{"address": TAC, "vpn": 512, "secret-key": "********", "auth-port": 49, "priority": 0}],
        "timeout": 5,
        "authentication": "ascii",
    }
    diff = json.dumps(p["diff_vs_running"])
    assert "auth-order local tacacs" in diff and f"server {TAC}" in diff and "authentication ascii" in diff
    assert "radius" not in json.dumps(p["after"]) and "unchanged" not in p  # no RADIUS on the factory config
    assert p["tier"] == "dangerous" and p["local_fallback"] is True
    assert "protocol='tacacs'" in p["undo"] and "servers=[])" in p["undo"]
    assert "order=['local', 'radius', 'tacacs']" in p["undo"]  # the factory order, which the guard allows
    assert TAC_SECRET not in json.dumps(prev)
    assert not routes["admin_radius"].called and not routes["admin_aaa"].called


async def test_single_tenant_tacacs_next_to_radius(api: respx.MockRouter) -> None:
    mock_single(api)
    mock_running(api, with_radius())
    args = {**TAC_ARGS, "order": ["local", "tacacs", "radius"], "fallback": None, "authentication": None}
    async with Client(server()) as c:
        prev = await tool(c, args)
    assert prev["status"] == "preview", prev.get("blockers")
    p = prev["preview"]
    assert p["before"]["order"] == ["local", "radius"] and p["before"]["tacacs"] == "not configured"
    assert p["unchanged"]["radius"]["servers"][0]["address"] == ISE
    assert "authentication" not in p["after"]["tacacs"]  # Viptela's default (pap): no line
    # The undo keeps RADIUS and drops TACACS+: order [local, radius], no TACACS+ servers.
    assert "order=['local', 'radius'], servers=[])" in p["undo"]
    assert SECRET not in json.dumps(prev) and TAC_SECRET not in json.dumps(prev)


async def test_single_tenant_tacacs_confirm_and_undo(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    login = api.post("/j_security_check").mock(side_effect=[LOGIN_OK, LOGIN_OK])
    async with Client(server()) as c:
        prev = await tool(c, TAC_ARGS)
        done = (await tool(c, {**TAC_ARGS, "confirm": prev["confirm"]}))["result"]
    assert login.call_count == 2 and done["outcome"] == "done"
    assert done["test_login_before"]["ok"] and done["test_login"]["ok"]
    cfg = json.loads(routes["create"].calls[0].request.content)["templateConfiguration"]
    assert "  auth-order local tacacs\n  auth-fallback\n" in cfg
    assert (
        f" tacacs\n  timeout 5\n  authentication ascii\n  server {TAC}\n   vpn 512\n"
        f"   secret-key {TAC_SECRET}\n   auth-port 49\n   priority 0\n  exit\n !\n"
    ) in cfg
    assert "$6$REDACTED-HASH-ADMIN" in cfg and "ip route 0.0.0.0/0 198.51.100.1" in cfg  # the rest kept
    assert TAC_SECRET not in json.dumps(done)


async def test_single_tenant_tacacs_undo_from_local_only(api: respx.MockRouter) -> None:
    mock_single(api)
    local_only = edit_system_aaa(
        running_text(), order=["local"], fallback=None, servers=None, timeout=None, retransmit=None
    )
    tac = edit_system_aaa(
        local_only,
        order=["local", "tacacs"],
        fallback=None,
        servers=[{"address": TAC, "secret": TAC_SECRET}],
        timeout=5,
        retransmit=None,
        protocol="tacacs",
    )
    mock_running(api, local_only)
    async with Client(server()) as c:
        first = await tool(c, {**TAC_ARGS, "fallback": None, "authentication": None})
    assert first["status"] == "preview", first.get("blockers")
    assert "order=['local'], servers=[])" in first["preview"]["undo"]
    mock_running(api, tac)
    async with Client(server()) as c:
        undo = await tool(c, {"protocol": "tacacs", "order": ["local"], "servers": []})
    assert undo["status"] == "preview", undo.get("blockers")
    assert undo["preview"]["after"] == {"order": ["local"], "fallback": False, "tacacs": "removed"}
    changed = undo["preview"]["diff_vs_running"]["changed"]["system"]
    assert "+ auth-order local" in changed and "-tacacs" in changed and f"- server {TAC}" in changed
    assert TAC_SECRET not in json.dumps(undo)


async def test_single_tenant_tacacs_rolls_back_and_guards(api: respx.MockRouter) -> None:
    routes = mock_single(api)
    api.post("/j_security_check").mock(side_effect=[LOGIN_OK, LOGIN_REJECTED])
    put = api.put("/dataservice/template/device/tpl-w40").respond(json={})
    async with Client(server()) as c:
        prev = await tool(c, TAC_ARGS)
        done = (await tool(c, {**TAC_ARGS, "confirm": prev["confirm"]}))["result"]
        no_local = await tool(c, {**TAC_ARGS, "order": ["tacacs"]})
        first = await tool(c, {**TAC_ARGS, "order": ["tacacs", "local"]})
        extra = {"address": TAC, "secret": TAC_SECRET, "tag": "ise1", "acct_port": 49}
        tagged = await tool(c, {**TAC_ARGS, "servers": [extra]})
    assert done["outcome"] == "rolled back" and routes["attach"].call_count == 2
    assert json.loads(put.calls[0].request.content)["templateConfiguration"] == running_text()
    assert no_local["status"] == "blocked" and "has no 'local'" in no_local["blockers"][0]
    assert any("TACACS+ reject ends the login" in w for w in first["preview"]["warnings"])
    assert any("tag and acct_port left out" in w for w in tagged["preview"]["warnings"])
    assert "tag" not in json.dumps(tagged["preview"]["after"]["tacacs"])


def test_edit_and_read_system_tacacs() -> None:
    text = with_radius()
    servers = [{"address": TAC, "secret": TAC_SECRET, "vpn": 0, "priority": 1, "auth_port": 4949}]
    new = edit_system_aaa(
        text,
        order=["local", "tacacs", "radius"],
        fallback=None,
        servers=servers,
        timeout=10,
        retransmit=None,
        protocol="tacacs",
        authentication="pap",
    )
    got = system_aaa(new)
    assert got["order"] == ["local", "tacacs", "radius"] and got["fallback"] is True
    assert got["tacacs"] == {
        "servers": [{"address": TAC, "vpn": 0, "secret-key": "********", "auth-port": 4949, "priority": 1}],
        "timeout": 10,
        "authentication": "pap",
    }
    assert got["radius"] == system_aaa(text)["radius"]  # RADIUS kept as it was
    lines = new.splitlines()
    assert lines.index(" tacacs") > lines.index(" radius")  # after the radius block
    assert SECRET not in mask_config(new)[0] and TAC_SECRET not in mask_config(new)[0]
    # Removing TACACS+ with the old order gives the RADIUS configuration back.
    back = edit_system_aaa(
        new, order=["local", "radius"], fallback=None, servers=[], timeout=None, retransmit=None,
        protocol="tacacs",
    )  # fmt: skip
    assert back == text
    # A TACACS+ block in place is replaced where it is; RADIUS removal leaves TACACS+ alone.
    again = edit_system_aaa(
        new,
        order=["local", "tacacs"],
        fallback=None,
        servers=[{"address": "198.51.100.37", "secret": "x"}],
        timeout=None,
        retransmit=None,
        protocol="tacacs",
    )
    assert [a["address"] for a in system_aaa(again)["tacacs"]["servers"]] == ["198.51.100.37"]
    no_rad = edit_system_aaa(
        new, order=["local", "tacacs"], fallback=None, servers=[], timeout=None, retransmit=None
    )
    assert system_aaa(no_rad)["radius"] == "not configured" and system_aaa(no_rad)["tacacs"] == got["tacacs"]


def test_undo_order_tacacs() -> None:
    from cat_sdwan_mcp.tools.manageraaa import undo_order

    assert undo_order({"order": ["local"], "tacacs": "not configured"}, "tacacs") == ["local"]
    assert undo_order({"order": ["local", "radius"], "radius": {"servers": [{}]}, "tacacs": "not configured"},
                      "tacacs") == ["local", "radius"]  # fmt: skip
    assert undo_order({"order": ["local", "radius", "tacacs"], "tacacs": "not configured"}, "tacacs") == [
        "local", "radius", "tacacs"
    ]  # fmt: skip


# --- #175 catsdwan_get_aaa on a single-tenant Manager ---------------------------------------------------
# The running configuration after #158's live round (20.18.3.1, 2026-10-28; shape read with
# catsdwan_get_device_config(section='system')): `auth-order local radius`, `auth-fallback` and one RADIUS
# server under `system radius` (tag, vpn 512, secret). Synthetic: the recorded fixture with those lines
# edited in, a documentation address and a placeholder secret.
RADIUS_SET_SECRET = "get-aaa-s3cret-175"


def running_with_radius() -> dict[str, Any]:
    body = dict(fixture("template_config_running_manager"))
    text = str(body["config"]).replace(
        "  auth-order      local radius tacacs\n", "  auth-order local radius\n  auth-fallback\n"
    )
    assert "auth-order local radius\n" in text
    radius = (
        f" radius\n  server {ISE}\n   tag mcpise1\n   vpn 512\n"
        f"   secret-key {RADIUS_SET_SECRET}\n  exit\n !\n"
    )  # fmt: skip
    text = text.replace(" ntp\n", radius + " ntp\n", 1)
    body["config"] = text
    return body


def mock_get_aaa(api: respx.MockRouter, running: Any) -> None:
    mock_inventory(api)
    api.get("/dataservice/client/server").respond(json=fixture("client_server"))
    api.get(RUNNING).respond(json=running)
    api.get("/dataservice/admin/aaa").respond(json=fixture("admin_aaa"))
    api.get("/dataservice/admin/radius").respond(json=fixture("admin_radius"))
    api.get("/dataservice/admin/tacacs").respond(json=fixture("admin_tacacs"))


async def get_aaa() -> dict[str, Any]:
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_get_aaa", {})).structured_content
    assert out is not None
    return out


async def test_get_aaa_single_tenant_reads_system_aaa(api: respx.MockRouter) -> None:
    mock_get_aaa(api, running_with_radius())
    out = await get_aaa()
    assert out["tenancy"] == "single"
    assert out["source"] == "running configuration (system aaa)"
    assert out["order"] == ["local", "radius"] and out["order_source"] == "set"
    assert out["fallback"] is True and out["local_fallback"] is True
    [srv] = out["radius"]["servers"]
    assert srv == {"address": ISE, "tag": "mcpise1", "vpn": 512, "secret-key": "********"}
    assert out["tacacs"] == "not configured"
    assert RADIUS_SET_SECRET not in json.dumps(out)
    # The recorded empty /admin/* answers: shown beside it, labelled, not as the order in use.
    assert out["remote_aaa"].startswith("not set (the multi-tenant provider's Remote AAA")
    assert f"GET {RUNNING}" in out["sources"] and "GET /dataservice/admin/aaa" in out["sources"]
    assert out["manager"]["host"] == "manager"


async def test_get_aaa_single_tenant_recorded_default_order(api: respx.MockRouter) -> None:
    mock_get_aaa(api, fixture("template_config_running_manager"))
    out = await get_aaa()
    assert out["order"] == ["local", "radius", "tacacs"] and out["order_source"] == "set"
    assert out["radius"] == "not configured" and out["tacacs"] == "not configured"
    assert out["source"] == "running configuration (system aaa)"


async def test_get_aaa_single_tenant_remote_set_shown_beside(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/client/server").respond(json=fixture("client_server"))
    api.get(RUNNING).respond(json=running_with_radius())
    api.get("/dataservice/admin/aaa").respond(json={"data": {"authOrder": ["local", "tacacs"]}})
    api.get("/dataservice/admin/radius").respond(json=fixture("admin_radius"))
    api.get("/dataservice/admin/tacacs").respond(json=fixture("admin_tacacs"))
    out = await get_aaa()
    assert out["order"] == ["local", "radius"]  # the system AAA is the one in use
    assert out["remote_aaa"]["source"].startswith("Remote AAA (/admin/*")
    assert out["remote_aaa"]["order"] == ["local", "tacacs"]


async def test_get_aaa_single_tenant_running_unreadable_falls_back(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/client/server").respond(json=fixture("client_server"))
    api.get(RUNNING).respond(500)
    api.get("/dataservice/admin/aaa").respond(json=fixture("admin_aaa"))
    api.get("/dataservice/admin/radius").respond(json=fixture("admin_radius"))
    api.get("/dataservice/admin/tacacs").respond(json=fixture("admin_tacacs"))
    out = await get_aaa()
    assert out["source"].startswith("Remote AAA (/admin/*): the system AAA could not be read")
    assert any("may not be the one in use" in w for w in out["warnings"])
