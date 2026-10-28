"""W41: catsdwan_set_ise_integration, and catsdwan_integrations naming pxGrid's state.

Recorded on 20.18.3.1 with no ISE configured: /ise/credentials and /ise/credentials/pxgrid answer `{}`
(fixtures ise_credentials, ise_credentials_pxgrid). The bodies with an ISE configured (IseServer, PxGridInfo,
the create and activate answers, the sync task) are hand-built from the Manager's 20.18.3 OpenAPI schema, and
marked so; the confirm path is exercised against mocks only (the live run is the C44 stage).
"""

import json
import re
from typing import Any

import respx
from fastmcp import Client

from cat_sdwan_mcp.iseintegration import (
    cert_check,
    connectivity_hints,
    differences,
    is_host,
    keep_stored_certs,
    node_name_of,
    pxgrid_create_hint,
    pxgrid_node_problem,
    pxgrid_push,
    pxgrid_raw,
    pxgrid_state,
    server_body,
    stored,
    username_problem,
)
from cat_sdwan_mcp.tools.iseintegration import _node_default

from .conftest import fixture, make_server
from .test_inventory import call, mock_inventory

ISE = "198.51.100.35"
ISE_PW = "ise-ers-s3cret"
PX_PW = "pxgrid-client-s3cret"
CREDS = "/dataservice/ise/credentials"
PXGRID = "/dataservice/ise/credentials/pxgrid"
SET = {  # hand-built IseServer: ISE configured, SGTs only
    "iseServerIP": ISE, "userName": "ersadmin", "password": "$CRYPT$abcdefghijkl", "vpn": "0",
    "destinationVpn": "", "vpnIpSubnet": "", "sgt": "true", "userAndUserGroup": "false",
}  # fmt: skip
PX_PENDING = {"nodeName": "vmanage-manager", "pxGridUserName": "vmanage-manager", "pxGridPassword": "x",
              "pxGridServerIp": ISE, "status": "PENDING"}  # fmt: skip


def server(**kw: Any) -> Any:
    base = {
        "mcp_enable_writes": True,
        "mcp_enable_dangerous": True,
        "ise_username": "ersadmin",
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
        "POST /dataservice/ise/pxgrid/create {nodeName: 'vmanagemanager'} (the client account on ISE)",
        "POST /dataservice/ise/pxgrid/activate (ISE lists 'vmanagemanager' as pending)",
    ]
    assert p["after"]["ise"]["password"] == "********" and p["after"]["ise"]["sgt"] == "true"
    assert p["after"]["pxgrid"] == {"node": "vmanagemanager", "state": "pending"}
    assert "ise_approve_pxgrid_client(name='vmanagemanager')" in p["then"]
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
        json={"nodeName": "vmanagemanager", "userName": "vmanagemanager", "password": PX_PW}
    )
    activate = api.post("/dataservice/ise/pxgrid/activate").respond(json={"accountState": "PENDING"})
    sync = api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "t1"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    sent = json.loads(post.calls[0].request.content)
    assert sent["iseServerIP"] == ISE and sent["password"] == ISE_PW and sent["userName"] == "ersadmin"
    assert sent["sgt"] == "true" and sent["userAndUserGroup"] == "false" and sent["vpn"] == "0"
    assert json.loads(create.calls[0].request.content) == {"nodeName": "vmanagemanager"}
    body = json.loads(activate.calls[0].request.content)
    assert body["pxGridUserName"] == "vmanagemanager" and body["pxGridPassword"] == PX_PW
    # ISE refused "(...)" in the description (XSS filter, ISEERRORR0014, live 2026-10-25).
    assert body["description"] == "Catalyst SD-WAN Manager"
    assert re.fullmatch(r"[A-Za-z0-9 -]+", body["description"])
    assert not sync.called
    assert done["outcome"] == "waiting for approval" and done["pxgrid_state"] == "pending"
    assert "ise_approve_pxgrid_client(name='vmanagemanager')" in done["next"]
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
    assert waiting["status"] == "blocked" and "nothing to change yet" in waiting["blockers"][0]
    assert "ise_approve_pxgrid_client(name='vmanage-manager')" in waiting["blockers"][0]
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
    soon = cert_check(_self_signed("Lab Root CA", 10))  # still valid: a warning, not a blocker
    assert soon["ok"] is True and "expires in" in soon["warnings"][0] and "problems" not in soon


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


# --- Wave 8 W41 fixes: the GUI's body, IP only, alphanumeric user, pxgrid_root_cert, cert kept on PUT,
# <30-day warning, TestConnectivity hints. The GUI's request was captured on 20.18.3.1 (Wave 8 gui-capture,
# notes/w8-fixtures/gui-capture/20-ise-credentials-ip.json, addresses and secrets replaced); the REST0002
# answer is the Manager's own from that capture.

ISE_FQDN = "ise.example.com"
TEST_CONNECTIVITY = {
    "error": {"message": "Server error", "code": "REST0002", "details": "Test Connectivity failed"}
}
# The GUI's POST /dataservice/ise/credentials (Add Connection, SGT subscription, VPN 512), password masked.
GUI_BODY = {
    "iseServerIP": ISE, "userName": "ersadmin", "password": "********", "vpn": "512",
    "userAndUserGroup": "false", "activeDirectoryDomain": "", "joinPoint": "", "sgt": "true",
    "vpnIpSubnet": "", "destinationVpn": "", "iseRootCert": "", "iseCertName": "", "pxGridRootCert": "",
    "pxGridCertName": "",
}  # fmt: skip


async def test_post_is_the_guis_body(api: respx.MockRouter) -> None:
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "s"})
    args = {"ise_host": ISE, "vpn": 512, "pxgrid": False}
    async with Client(server(ise_username="ersadmin")) as c:
        prev = await tool(c, args)
        assert prev["preview"]["after"]["ise"] == GUI_BODY
        await tool(c, {**args, "confirm": prev["confirm"]})
    raw = post.calls[0].request.content
    sent = json.loads(raw)
    assert list(sent) == list(GUI_BODY)  # every field, in the GUI's order
    assert {**sent, "password": "********"} == GUI_BODY and sent["password"] == ISE_PW
    assert all(isinstance(v, str) for v in sent.values())


def test_server_body_fills_every_field() -> None:
    pem = _self_signed("Lab Root CA", 365)
    body = server_body(
        ise_host=ISE, username="u", password="p", vpn=0, subscribe_sgt=False, subscribe_users=True,
        ad_domain="corp.example", join_point="corp", root_cert=pem, pxgrid_root_cert=None,
    )  # fmt: skip
    assert list(body) == list(GUI_BODY) and all(isinstance(v, str) for v in body.values())
    assert body["userAndUserGroup"] == "true" and body["sgt"] == "false"
    assert body["activeDirectoryDomain"] == "corp.example" and body["joinPoint"] == "corp"
    assert body["iseRootCert"] == pem and body["pxGridRootCert"] == pem
    assert body["iseCertName"] and body["pxGridCertName"]
    assert body["destinationVpn"] == "" and body["vpnIpSubnet"] == ""


async def test_non_alphanumeric_user_blocks(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server(ise_username="mcp-ers-admin")) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "blocked"
    [b] = [b for b in prev["blockers"] if "CATSDWAN_ISE_USERNAME" in b]
    assert "/^[a-zA-Z0-9]+$/" in b and "'mcp-ers-admin'" in b and "alphanumeric ERS admin" in b


async def test_host_name_is_resolved_and_said(api: respx.MockRouter, monkeypatch: Any) -> None:
    import cat_sdwan_mcp.tools.iseintegration as tool_mod

    async def fake(host: str) -> str | None:
        return ISE if host == ISE_FQDN else None

    monkeypatch.setattr(tool_mod, "resolve_ip", fake)
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "s"})
    args = {"ise_host": ISE_FQDN, "pxgrid": False}
    async with Client(server()) as c:
        prev = await tool(c, args)
        p = prev["preview"]
        assert p["ise_host_resolved"] == {"name": ISE_FQDN, "ip": ISE}
        assert any(f"resolved to {ISE}" in w and "IP only" in w for w in p["warnings"])
        assert p["requests"][0] == f"POST {CREDS} (ISE {ISE}, VPN 0)"
        await tool(c, {**args, "confirm": prev["confirm"]})
    assert json.loads(post.calls[0].request.content)["iseServerIP"] == ISE


async def test_unresolvable_host_name_is_refused(api: respx.MockRouter, monkeypatch: Any) -> None:
    import cat_sdwan_mcp.tools.iseintegration as tool_mod

    async def fake(host: str) -> str | None:
        return None

    monkeypatch.setattr(tool_mod, "resolve_ip", fake)
    mock_state(api)
    async with Client(server()) as c:
        res = await c.call_tool("catsdwan_set_ise_integration", {"ise_host": ISE_FQDN}, raise_on_error=False)
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "by IP address only" in text and "Use valid IP Address" in text


async def test_ip_host_draws_no_name_warning(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert not any("resolved" in w or "named by IP" in w for w in prev["preview"].get("warnings", []))


async def test_bad_host_is_refused(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        res = await c.call_tool(
            "catsdwan_set_ise_integration", {"ise_host": "ise host;rm"}, raise_on_error=False
        )
    assert res.is_error and "neither an IP address nor a host name" in res.content[0].text  # type: ignore[union-attr]


async def test_separate_pxgrid_root_cert(api: respx.MockRouter) -> None:
    mock_state(api)
    post = api.post(CREDS).respond(json=True)
    api.post("/dataservice/ise/credentials/vsmart/sync").respond(json={"id": "s"})
    admin = _self_signed("ise.example.com", 700)  # ISE's default self-signed admin certificate
    px = _self_signed("Lab Root CA", 3000)
    args = {"ise_host": ISE, "ise_root_cert": admin, "pxgrid_root_cert": px, "pxgrid": False}
    async with Client(server()) as c:
        prev = await tool(c, args)
        p = prev["preview"]
        assert p["certificate_check"]["common_name"] == "ise.example.com"
        assert p["pxgrid_certificate_check"]["common_name"] == "Lab Root CA"
        await tool(c, {**args, "confirm": prev["confirm"]})
    sent = json.loads(post.calls[0].request.content)
    assert sent["iseRootCert"] == admin and sent["pxGridRootCert"] == px


async def test_bad_pxgrid_root_cert_blocks(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "pxgrid_root_cert": "junk"})
    assert prev["status"] == "blocked" and any(b.startswith("pxgrid_root_cert:") for b in prev["blockers"])


async def test_root_cert_expiring_soon_warns_not_blocks(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "ise_root_cert": _self_signed("Lab Root CA", 12)})
    assert prev["status"] == "preview"
    assert any(w.startswith("ise_root_cert: expires in") for w in prev["preview"]["warnings"])


async def test_put_without_root_cert_keeps_the_stored_one(api: respx.MockRouter) -> None:
    pem = _self_signed("Lab Root CA", 365)
    stored_rec = {**SET, "iseRootCert": pem, "iseCertName": "iseCertificate", "pxGridRootCert": pem}
    mock_state(api, creds={"data": stored_rec}, px={**PX_PENDING, "status": "ENABLED"})
    put = api.put(CREDS).respond(json=True)
    args = {"ise_host": ISE, "vpn": 512, "pxgrid": False, "sync_controllers": False}
    async with Client(server()) as c:
        prev = await tool(c, args)
        assert prev["preview"]["certificates_kept"] == ["iseRootCert", "pxGridRootCert"]
        await tool(c, {**args, "confirm": prev["confirm"]})
    sent = json.loads(put.calls[0].request.content)
    assert sent["iseRootCert"] == pem and sent["iseCertName"] == "iseCertificate"
    assert sent["pxGridRootCert"] == pem and sent["vpn"] == "512"


async def test_put_with_no_cert_anywhere_warns(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px={**PX_PENDING, "status": "ENABLED"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "vpn": 512, "pxgrid": False, "sync_controllers": False})
    assert any("may clear it" in w for w in prev["preview"]["warnings"])


async def test_test_connectivity_failure_names_the_suspects(api: respx.MockRouter) -> None:
    mock_state(api)
    api.post(CREDS).respond(400, json=TEST_CONNECTIVITY)
    create = api.post("/dataservice/ise/pxgrid/create").respond(json={})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        res = await c.call_tool(
            "catsdwan_set_ise_integration",
            {"ise_host": ISE, "confirm": prev["confirm"]},
            raise_on_error=False,
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "REST0002: Server error: Test Connectivity failed" in text
    assert "Nothing was stored" in text and "ERS Admin" in text and "FQDN" not in text
    assert ISE_PW not in text and not create.called


def test_host_helpers() -> None:
    assert is_host("198.51.100.35") and is_host("2001:db8::35") and is_host("ise.example.com")
    assert not is_host("198.51.100") and not is_host("ise host") and not is_host("-bad.example.com")
    assert not any("FQDN" in h for h in connectivity_hints(512, "198.51.100.35"))
    assert "VPN 512" in connectivity_hints(512, "198.51.100.35")[-1]
    wanted = {"iseRootCert": "given", "iseCertName": "a.pem", "pxGridRootCert": "", "pxGridCertName": ""}
    assert keep_stored_certs(wanted, {"iseRootCert": "old", "pxGridRootCert": "px"}) == ["pxGridRootCert"]
    assert wanted["iseRootCert"] == "given" and wanted["pxGridRootCert"] == "px"
    assert wanted["pxGridCertName"] == "pxgrid-root-ca.pem"
    assert username_problem("mcpw8capture") is None and username_problem("ers_admin")


async def test_pxgrid_only_rerun_shows_the_stored_record(api: respx.MockRouter) -> None:
    # #120: a re-run that plans only pxGrid create/activate showed after.ise's certificates as "" (the
    # body a write would send) although no credentials write was planned.
    pem = _self_signed("Lab Root CA", 365)
    stored_rec = {**SET, "iseRootCert": pem, "iseCertName": "iseCertificate", "pxGridRootCert": pem}
    mock_state(api, creds={"data": stored_rec}, px={})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    p = prev["preview"]
    assert prev["status"] == "preview", prev.get("blockers")
    assert not any(r.startswith(("PUT", "POST")) and CREDS + " " in r for r in p["requests"])
    assert p["after"]["ise_record"] == "unchanged (no credentials write)"
    assert p["after"]["ise"]["iseRootCert"]["common_name"] == "Lab Root CA"
    assert p["after"]["ise"]["pxGridRootCert"]["common_name"] == "Lab Root CA"
    assert p["after"]["ise"]["password"] == "********"
    assert p["after"]["pxgrid"]["state"] == "pending"


# #131: the pxGrid record's `status` on 20.18.3.1 (live 2026-10-25): 'activated' after POST
# /ise/pxgrid/activate, 'vSmart push is pending' after PUT /ise/pxgrid/approve + the controller sync
# started, 'vSmart push is successful' once the sync task succeeded. 'vSmart push is failed' is the
# failure wording the issue names (not yet seen live).
SYNC = "/dataservice/ise/credentials/vsmart/sync"
APPROVE = "/dataservice/ise/pxgrid/approve"
SYNC_STEP = f"POST {SYNC} (send ISE and pxGrid settings to controller)"


def px_with(status: str) -> dict[str, Any]:
    return {**PX_PENDING, "status": status}


def test_pxgrid_state_maps_every_status_from_the_issue() -> None:
    assert pxgrid_state(px_with("activated")) == "activated"
    assert pxgrid_push(px_with("activated")) is None
    assert pxgrid_state(px_with("vSmart push is pending")) == "enabled"
    assert pxgrid_push(px_with("vSmart push is pending")) == "pending"
    assert pxgrid_state(px_with("vSmart push is successful")) == "enabled"
    assert pxgrid_push(px_with("vSmart push is successful")) == "successful"
    assert pxgrid_state(px_with("vSmart push is failed")) == "enabled"
    assert pxgrid_push(px_with("vSmart push is failed")) == "failed"
    assert pxgrid_state(px_with("PENDING")) == "pending" and pxgrid_state(px_with("ENABLED")) == "enabled"
    assert pxgrid_state(px_with("DISABLED")) == "disabled"
    assert pxgrid_state(px_with("deactivated")) == "unknown"
    assert pxgrid_state(px_with("vSmart push is sideways")) == "unknown"
    # status is read before accountState
    assert pxgrid_state({"nodeName": "x", "status": "activated", "accountState": "PENDING"}) == "activated"
    assert pxgrid_state({"nodeName": "x", "accountState": "ENABLED"}) == "enabled"
    assert pxgrid_raw({"accountState": " ENABLED "}) == "ENABLED"


async def test_activated_rerun_without_manager_approval_plans_approve_and_sync(api: respx.MockRouter) -> None:
    # The failure in #131: ISE lists the client enabled, the Manager says 'activated', and
    # approve_on_manager=false planned nothing, so the controllers never got 'identity pxgrid'.
    mock_state(api, creds={"data": SET}, px=px_with("activated"))
    approve = api.put(APPROVE).respond(json=True)
    sync = api.post(SYNC).respond(json={"id": "sync-131"})
    args = {"ise_host": ISE, "approve_on_manager": False}
    async with Client(server()) as c:
        prev = await tool(c, args)
        assert prev["status"] == "preview", prev.get("blockers")
        p = prev["preview"]
        assert p["before"]["pxgrid"]["state"] == "activated"
        assert p["requests"] == [
            f"PUT {APPROVE} (the Manager's own approve step for 'vmanage-manager': its pxGrid record says "
            "'activated')",
            SYNC_STEP,
        ]
        assert p["after"]["pxgrid"]["state"] == "enabled"
        assert not approve.called and not sync.called
        done = (await tool(c, {**args, "confirm": prev["confirm"]}))["result"]
    assert approve.called and sync.called
    assert done["outcome"] == "done" and done["pxgrid_state"] == "enabled" and done["sync_task"] == "sync-131"


async def test_activated_with_manager_approval_plans_one_approve(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=px_with("activated"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "approve_on_manager": True})
    reqs = prev["preview"]["requests"]
    assert sum(r.startswith(f"PUT {APPROVE}") for r in reqs) == 1 and reqs[-1] == SYNC_STEP


async def test_push_pending_plans_no_second_sync(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=px_with("vSmart push is pending"))
    sync = api.post(SYNC).respond(json={"id": "s"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "blocked" and not sync.called
    assert any("controller sync is still running" in b for b in prev["blockers"])
    assert any("vSmart push is pending" in b for b in prev["blockers"])


async def test_push_successful_plans_nothing(api: respx.MockRouter) -> None:
    # #148: a re-run at 'vSmart push is successful' with nothing changed planned the sync again.
    mock_state(api, creds={"data": SET}, px=px_with("vSmart push is successful"))
    sync = api.post(SYNC).respond(json={"id": "s"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    p = prev["preview"]
    assert prev["status"] == "blocked" and not sync.called
    assert p["before"]["pxgrid"] == {
        "state": "enabled",
        "status": "vSmart push is successful",
        "controller_push": "successful",
        "node": "vmanage-manager",
    }
    assert p["requests"] == []
    assert any(b.startswith("already connected; nothing to do") for b in prev["blockers"])


async def test_push_failed_plans_a_resync_and_shows_the_failure(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=px_with("vSmart push is failed"))
    sync = api.post(SYNC).respond(json={"id": "resync"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        p = prev["preview"]
        assert prev["status"] == "preview", prev.get("blockers")
        assert p["requests"] == [SYNC_STEP]
        assert p["controller_push"] == {"status": "vSmart push is failed", "result": "failed"}
        assert any("last controller sync failed" in w and "again" in w for w in p["warnings"])
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    assert sync.called and done["sync_task"] == "resync"


async def test_push_failed_without_sync_says_no_resync(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=px_with("vSmart push is failed"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "sync_controllers": False})
    assert prev["status"] == "blocked"
    assert any("no re-sync is planned" in w for w in prev["preview"]["warnings"])


async def test_unknown_pxgrid_status_blocks_with_the_raw_text(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=px_with("Quarantined by admin"))
    sync = api.post(SYNC).respond(json={"id": "s"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "blocked" and not sync.called
    assert any("'Quarantined by admin'" in b and "does not know" in b for b in prev["blockers"])
    assert prev["preview"]["requests"] == []


async def test_fresh_activate_answering_activated_stops_without_unplanned_approve(
    api: respx.MockRouter,
) -> None:
    mock_state(api)
    api.post(CREDS).respond(json=True)
    api.post("/dataservice/ise/pxgrid/create").respond(
        json={"nodeName": "vmanagemanager", "userName": "vmanagemanager", "password": PX_PW}
    )
    api.post("/dataservice/ise/pxgrid/activate").respond(json={"accountState": "activated"})
    approve = api.put(APPROVE).respond(json=True)
    sync = api.post(SYNC).respond(json={"id": "s"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    assert not approve.called and not sync.called
    assert done["outcome"] == "waiting for the Manager's approve step"
    assert "plans PUT /dataservice/ise/pxgrid/approve" in done["next"]


async def test_integrations_names_the_push_and_activated_states(api: respx.MockRouter) -> None:
    api.get(CREDS).respond(json={"data": SET})
    route = api.get(PXGRID)
    route.respond(json={"data": px_with("vSmart push is failed")})
    api.get("/dataservice/partner").respond(json=fixture("partner"))
    api.get("/dataservice/partner/dnac/sda/vpn").respond(json=fixture("partner_dnac_sda_vpn"))
    api.get("/dataservice/ise/connect").respond(json={"VersionInfo": {"currentServerVersion": "3.5"}})
    api.get("/dataservice/template/policy/ise/identity/sgt").respond(json={"data": []})
    out = await call("catsdwan_integrations", {})
    assert out["pxgrid"]["state"] == "enabled" and out["pxgrid"]["controller_push"] == "failed"
    assert out["pxgrid"]["status"] == "vSmart push is failed"
    assert "failed" in out["pxgrid"]["meaning"]
    route.respond(json={"data": px_with("activated")})
    out = await call("catsdwan_integrations", {})
    assert out["pxgrid"]["state"] == "activated" and "approve step" in out["pxgrid"]["meaning"]


# #148: the four statuses of the live 20.18.3.1 sequence (approve_on_manager=false, fresh connect), one
# fixture each, hand-built from the issue's table (documentation addresses, password redacted). From the
# approve on, `nodeName` is ISE's own pxGrid node ('~ise-admin-ise'); `pxGridUserName` is the client ISE
# lists.
CLIENT = "example_vmanage-manager"


def px_fixture(status: str) -> dict[str, Any]:
    return stored(fixture(f"ise_credentials_pxgrid_{status}"))


def test_pxgrid_fixtures_map_every_status_of_the_live_sequence() -> None:
    expect = {
        "activated": ("activated", None),
        "approved": ("enabled", None),
        "push_pending": ("enabled", "pending"),
        "push_successful": ("enabled", "successful"),
    }
    for name, (state, push) in expect.items():
        rec = px_fixture(name)
        assert (pxgrid_state(rec), pxgrid_push(rec)) == (state, push), name
        assert node_name_of(rec) == CLIENT, name
    assert pxgrid_state(px_with("approved")) == "enabled"


def test_node_name_prefers_the_client_ise_lists() -> None:
    assert node_name_of({"nodeName": "~ise-admin-ise", "pxGridUserName": CLIENT}) == CLIENT
    assert node_name_of({"nodeName": "~ise-admin-ise"}) is None
    assert node_name_of({"nodeName": "vmanage-manager"}) == "vmanage-manager"
    assert node_name_of({}) is None


async def test_activated_fixture_plans_approve_and_sync(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_activated"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "preview", prev.get("blockers")
    reqs = prev["preview"]["requests"]
    assert reqs[0].startswith(f"PUT {APPROVE}") and CLIENT in reqs[0] and reqs[1:] == [SYNC_STEP]


async def test_approved_fixture_plans_the_sync(api: respx.MockRouter) -> None:
    # 'Approved' is the minute between PUT /ise/pxgrid/approve and the sync task starting: it was 'unknown'
    # and blocked; now it is enabled with the controller sync still due.
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_approved"))
    sync = api.post(SYNC).respond(json={"id": "sync-148"})
    approve = api.put(APPROVE).respond(json=True)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        assert prev["status"] == "preview", prev.get("blockers")
        p = prev["preview"]
        assert p["before"]["pxgrid"] == {"state": "enabled", "status": "Approved", "node": CLIENT}
        assert p["requests"] == [SYNC_STEP]
        assert p["after"]["pxgrid"] == {"node": CLIENT, "state": "enabled"}
        done = (await tool(c, {"ise_host": ISE, "confirm": prev["confirm"]}))["result"]
    assert sync.called and not approve.called and done["sync_task"] == "sync-148"
    assert done["outcome"] == "done"


async def test_push_pending_fixture_plans_no_second_sync(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_push_pending"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "blocked" and prev["preview"]["requests"] == []
    assert any("controller sync is still running" in b for b in prev["blockers"])


async def test_push_successful_fixture_is_already_connected(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_push_successful"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    p = prev["preview"]
    assert prev["status"] == "blocked" and p["requests"] == []
    assert p["before"]["pxgrid"]["node"] == CLIENT
    assert any(b.startswith("already connected; nothing to do") for b in prev["blockers"])


async def test_push_successful_rotate_password_puts_and_resyncs(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_push_successful"))
    put = api.put(CREDS).respond(json=True)
    sync = api.post(SYNC).respond(json={"id": "rot"})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "rotate_password": True})
        assert prev["status"] == "preview", prev.get("blockers")
        assert prev["preview"]["requests"] == [f"PUT {CREDS} (ISE {ISE}, VPN 0)", SYNC_STEP]
        done = (await tool(c, {"ise_host": ISE, "rotate_password": True, "confirm": prev["confirm"]}))[
            "result"
        ]
    assert put.called and sync.called and done["sync_task"] == "rot"


async def test_push_successful_changed_setting_resyncs(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_push_successful"))
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "vpn": 512})
    assert prev["status"] == "preview", prev.get("blockers")
    assert prev["preview"]["requests"] == [f"PUT {CREDS} (ISE {ISE}, VPN 512)", SYNC_STEP]


async def test_disconnect_names_the_client_not_ises_node(api: respx.MockRouter) -> None:
    mock_state(api, creds={"data": SET}, px=fixture("ise_credentials_pxgrid_push_successful"))
    async with Client(server()) as c:
        prev = await tool(c, {"action": "disconnect"})
    assert prev["status"] == "preview", prev.get("blockers")
    effects = " ".join(prev["side_effects"])
    assert f"pxGrid client {CLIENT}" in effects and "~ise-admin-ise" not in effects


async def test_integrations_explains_approved(api: respx.MockRouter) -> None:
    api.get(CREDS).respond(json={"data": SET})
    api.get(PXGRID).respond(json=fixture("ise_credentials_pxgrid_approved"))
    api.get("/dataservice/partner").respond(json=fixture("partner"))
    api.get("/dataservice/partner/dnac/sda/vpn").respond(json=fixture("partner_dnac_sda_vpn"))
    api.get("/dataservice/ise/connect").respond(json={"VersionInfo": {"currentServerVersion": "3.5"}})
    api.get("/dataservice/template/policy/ise/identity/sgt").respond(json={"data": []})
    out = await call("catsdwan_integrations", {})
    assert out["pxgrid"]["state"] == "enabled" and out["pxgrid"]["status"] == "Approved"
    assert "approved" in out["pxgrid"]["meaning"] and CLIENT in out["pxgrid"]["meaning"]


# #149: ISE refuses a pxGrid client name with anything but letters and digits (ISEERRORR0013, live #67/#131).
async def test_default_node_name_is_alphanumeric(api: respx.MockRouter) -> None:
    mock_state(api)
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
    assert prev["status"] == "preview", prev.get("blockers")
    assert prev["preview"]["after"]["pxgrid"]["node"] == "vmanagemanager"
    assert (
        _node_default([{"role": "manager", "host": "sdwan-mgr_01.example.com"}])
        == "vmanagesdwanmgr01examplecom"
    )
    assert _node_default([]) == "vmanage"


async def test_hyphenated_node_name_blocks(api: respx.MockRouter) -> None:
    mock_state(api)
    create = api.post("/dataservice/ise/pxgrid/create").respond(json={})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "pxgrid_node_name": "vmanage-manager"})
    assert prev["status"] == "blocked" and not create.called
    [b] = [b for b in prev["blockers"] if "pxgrid_node_name" in b]
    assert "'vmanage-manager'" in b and "should only be alphanumeric" in b and "ISEERRORR0013" in b
    assert "pxgrid_node_name='vmanagemanager'" in b
    assert pxgrid_node_problem("vmanagemanager") is None


async def test_stored_pending_client_is_not_blocked_by_its_name(api: respx.MockRouter) -> None:
    # No create planned: the name ISE already holds is not re-checked.
    mock_state(api, creds={"data": SET}, px={"data": PX_PENDING})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE, "approve_on_manager": True})
    assert not any("pxgrid_node_name" in b for b in prev.get("blockers", []))


ISE_R0013 = {  # synthetic: the Manager's 400 for a refused pxGrid create (code from the #67 run)
    "error": {"message": "Failed to create pxGrid account", "code": "ISEERRORR0013", "details": "ISE error"}
}


async def test_iseerrorr0013_on_create_says_the_name_must_be_alphanumeric(api: respx.MockRouter) -> None:
    mock_state(api)
    api.post(CREDS).respond(json=True)
    api.post("/dataservice/ise/pxgrid/create").respond(400, json=ISE_R0013)
    activate = api.post("/dataservice/ise/pxgrid/activate").respond(json={})
    async with Client(server()) as c:
        prev = await tool(c, {"ise_host": ISE})
        res = await c.call_tool(
            "catsdwan_set_ise_integration",
            {"ise_host": ISE, "confirm": prev["confirm"]},
            raise_on_error=False,
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "ISEERRORR0013" in text
    assert "pxGrid client name must be alphanumeric" in text and "'vmanagemanager'" in text
    assert not activate.called and ISE_PW not in text
    assert pxgrid_create_hint("400 REST0002 Server error", "x") is None
