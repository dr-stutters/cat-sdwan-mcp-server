"""W41: catsdwan_set_ise_integration, and catsdwan_integrations naming pxGrid's state.

Recorded on 20.18.3.1 with no ISE configured: /ise/credentials and /ise/credentials/pxgrid answer `{}`
(fixtures ise_credentials, ise_credentials_pxgrid). The bodies with an ISE configured (IseServer, PxGridInfo,
the create and activate answers, the sync task) are hand-built from the Manager's 20.18.3 OpenAPI schema, and
marked so; the confirm path is exercised against mocks only (the live run is the C44 stage).
"""

import json
from typing import Any

import respx
from fastmcp import Client

from cat_sdwan_mcp.iseintegration import cert_check, differences, pxgrid_state, server_body, stored

from .conftest import fixture, make_server
from .test_inventory import call, mock_inventory

ISE = "198.51.100.35"
ISE_PW = "ise-ers-s3cret"
PX_PW = "pxgrid-client-s3cret"
CREDS = "/dataservice/ise/credentials"
PXGRID = "/dataservice/ise/credentials/pxgrid"
SET = {  # hand-built IseServer: ISE configured, SGTs only
    "iseServerIP": ISE, "userName": "ers-admin", "password": "$CRYPT$abcdefghijkl", "vpn": "0",
    "destinationVpn": "0", "vpnIpSubnet": "", "sgt": "true", "userAndUserGroup": "false",
}  # fmt: skip
PX_PENDING = {"nodeName": "vmanage-manager", "pxGridUserName": "vmanage-manager", "pxGridPassword": "x",
              "pxGridServerIp": ISE, "status": "PENDING"}  # fmt: skip


def server(**kw: Any) -> Any:
    base = {
        "mcp_enable_writes": True,
        "mcp_enable_dangerous": True,
        "ise_username": "ers-admin",
        "ise_password": ISE_PW,
    }
    return make_server(**{**base, **kw})


def mock_state(api: respx.MockRouter, creds: Any = None, px: Any = None) -> None:
    mock_inventory(api)
    api.get(CREDS).respond(json=creds if creds is not None else fixture("ise_credentials"))
    api.get(PXGRID).respond(json=px if px is not None else fixture("ise_credentials_pxgrid"))


async def tool(c: Client, args: dict[str, Any]) -> dict[str, Any]:
    out = (await c.call_tool("catsdwan_set_ise_integration", args)).structured_content
    assert out is not None
    return out


async def test_connect_preview_plans_every_step(api: respx.MockRouter) -> None:
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "preview" and not post.called
    p = prev["preview"]
    assert p["before"] == {"ise": "not configured", "pxgrid": {"state": "none"}}
    assert p["requests"] == [
        f"POST {CREDS} (ISE {ISE}, VPN 0)",
        "POST /dataservice/ise/pxgrid/create {nodeName: 'vmanage-manager'} (the client account on ISE)",
        "POST /dataservice/ise/pxgrid/activate (ISE lists 'vmanage-manager' as pending)",
    ]
    assert p["after"]["ise"]["password"] == "********" and p["after"]["ise"]["sgt"] == "true"
    assert p["after"]["pxgrid"] == {"node": "vmanage-manager", "state": "pending"}
    assert "ise_approve_pxgrid_client(name='vmanage-manager')" in p["then"]
    assert p["certificate_check"]["given"] is False
    assert p["undo"] == "catsdwan_set_ise_integration(action='disconnect')"
    assert ISE_PW not in json.dumps(prev)


async def test_connect_without_dangerous_or_login_is_blocked(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server(mcp_enable_dangerous=False, ise_username=None, ise_password=None)) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "blocked"
    assert any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])
    assert any("CATSDWAN_ISE_USERNAME" in b for b in prev["blockers"])


async def test_connect_confirm_creates_and_activates_then_waits(api: respx.MockRouter) -> None:
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    create = api.post("/dataservice/ise/pxgrid/create").respond(
        json={"nodeName": "vmanage-manager", "userName": "vmanage-manager", "password": PX_PW}
    )
    activate = api.post("/dataservice/ise/pxgrid/activate").respond(json={"accountState": "PENDING"})
    sync = api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "t1"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    sent = json.loads(post.calls[0].request.content)
    assert sent["iseServerIP"] == ISE and sent["password"] == ISE_PW and sent["userName"] == "ers-admin"
    assert sent["sgt"] == "true" and sent["userAndUserGroup"] == "false" and sent["vpn"] == "0"
    assert json.loads(create.calls[0].request.content) == {"nodeName": "vmanage-manager"}
    body = json.loads(activate.calls[0].request.content)
    assert body["pxGridUserName"] == "vmanage-manager" and body["pxGridPassword"] == PX_PW
    assert not sync.called
    assert done["outcome"] == "waiting for approval" and done["pxgrid_state"] == "pending"
    assert "ise_approve_pxgrid_client(name='vmanage-manager')" in done["next"]
    assert PX_PW not in json.dumps(done) and ISE_PW not in json.dumps(done)


async def test_second_run_after_approval_only_syncs(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px={**PX_PENDING, "status": "ENABLED"})
    put = api.put(CREDS).respond(json=True)
    sync = api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "sync-7"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        assert prev["status"] == "preview"
        assert prev["preview"]["requests"] == [
            "POST /dataservice/ise/credentials/vsmart/sync (send ISE and pxGrid settings to controller)"
        ]
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    assert not put.called and sync.called
    assert done["outcome"] == "done" and done["sync_task"] == "sync-7"


async def test_pending_with_manager_approval(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=PX_PENDING)
    approve = api.put("/dataservice/ise/pxgrid/approve").respond(json=True)
    api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "s"})
    async with Client(server()) as c:
        waiting = await tool(c, {"ise_host": ISE})
        prev = await tool(c, {"ise_host": ISE, "approve_on_manager": True})
        done = (await tool(c, {"ise_host": ISE, "approve_on_manager": True, "confirm": prev["confirm"]}))[
            "result"
        ]
    assert waiting["status"] == "blocked" and "nothing to change" in waiting["blockers"][0]
    assert prev["preview"]["requests"][0].startswith("PUT /dataservice/ise/pxgrid/approve")
    assert approve.called and done["outcome"] == "done"


async def test_changed_vpn_puts_and_shows_the_difference(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px={**PX_PENDING, "status": "ENABLED"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "vpn": 512, "pxgrid": False, "sync_controllers": False})
    p = prev["preview"]
    assert p["requests"] == [f"PUT {CREDS} (ISE {ISE}, VPN 512)"]
    assert p["changes"]["vpn"] == {"from": "0", "to": "512"}
    assert p["before"]["ise"]["password"] == "********"


async def test_disconnect_is_the_undo(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px={**PX_PENDING, "status": "ENABLED"})
    delete = api.delete("/dataservice/ise/credentials/iseandpxgrid").respond(json=True)
    api.post("/dataservice/ise/credentials/vsmart/sync").respond(400, json={"error": {"message": "no ISE"}})
    async with Client(server()) as c:
        prev = await tool(c, {"action": "disconnect"})
        done = (await tool(c, {"action": "disconnect", "confirm": prev["confirm"]}))["result"]
    assert prev["preview"]["requests"][0].startswith("DELETE /dataservice/ise/credentials/iseandpxgrid")
    assert any("vmanage-manager" in s for s in prev["side_effects"])
    assert delete.called and done["outcome"] == "done" and "sync_error" in done


async def test_disconnect_with_nothing_configured_is_blocked(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"action": "disconnect"})
    assert prev["status"] == "blocked" and "nothing to disconnect" in prev["blockers"][0]


async def test_users_need_a_join_point(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        res = await c.call_tool(
            "catsdwan_set_ise_integration", {"ise_host": ISE, "subscribe_users": True}, raise_on_error=False
        )
    assert res.is_error and "join_point" in res.content[0].text  # type: ignore[union-attr]


async def test_bad_root_cert_blocks(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "ise_root_cert": "not a cert"})
    assert prev["status"] == "blocked" and any("ise_root_cert" in b for b in prev["blockers"])


async def test_integrations_names_a_pending_pxgrid_client(api: respx.MockRouter) -> None:
    api.get(CREDS).respond(json={"data": SET})
    api.get(PXGRID).respond(json={"data": PX_PENDING})
    api.get("/dataservice/partner").respond(json=fixture("partner"))
    api.get("/dataservice/partner/dnac/sda/vpn").respond(json=fixture("partner_dnac_sda_vpn"))
    api.get("/dataservice/ise/connect").respond(json={"VersionInfo": {"currentServerVersion": "3.5"}})
    api.get("/dataservice/template/policy/ise/identity/sgt").respond(json={"data": []})
    out = await call("catsdwan_integrations", {})
    assert out["pxgrid"]["state"] == "pending"
    assert "vmanage-manager waits for approval" in out["pxgrid"]["meaning"]
    assert out["pxgrid"]["credentials"]["pxGridPassword"] == "********"


def test_helpers() -> None:
    assert stored({}) == {} and stored({"data": {}}) == {}
    assert pxgrid_state({}) == "none" and pxgrid_state({"status": "ENABLED"}) == "enabled"
    assert pxgrid_state({"nodeName": "x"}) == "created"
    body = server_body(
        ise_host=ISE, username="u", password="p", vpn=0, subscribe_sgt=True, subscribe_users=False,
        ad_domain=None, join_point=None, root_cert=None, pxgrid_root_cert=None,
    )  # fmt: skip
    assert differences(SET, body) == {}
    assert differences({**SET, "sgt": "false"}, body) == {"sgt": {"from": "false", "to": "true"}}
    assert cert_check(None)["given"] is False
    assert cert_check("junk")["ok"] is False


def _self_signed(cn: str, days: int) -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_cert_check_root_and_expiry() -> None:
    ok = cert_check(_self_signed("Lab Root CA", 365))
    assert ok["ok"] is True and ok["common_name"] == "Lab Root CA"
    soon = cert_check(_self_signed("Lab Root CA", 10))
    assert soon["ok"] is False and "expires in" in soon["problems"][0]


async def test_connect_with_root_cert_sends_it(api: respx.MockRouter) -> None:
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    sync = api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "s"})
    pem = _self_signed("Lab Root CA", 365)
    args = {"ise_host": ISE, "ise_root_cert": pem, "pxgrid": False}
    async with Client(server()) as c:
        prev = await tool(c, args)
        assert prev["preview"]["after"]["ise"]["iseRootCert"]["common_name"] == "Lab Root CA"
        await tool(c, {**args, "confirm": prev["confirm"]})
    sent = json.loads(post.calls[0].request.content)
    assert sent["iseRootCert"] == pem and sent["pxGridRootCert"] == pem
    assert sync.called  # without pxGrid the ISE settings go to the controllers at once
