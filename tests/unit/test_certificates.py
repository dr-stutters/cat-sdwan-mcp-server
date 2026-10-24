"""W16: certificates and trust on the recorded 20.18.3.1 certificate lists.

Recorded: three controllers (Enterprise-CA certificates expiring Oct 2028), three joined edges with
Manager-signed certificates (Oct 2036) and 22 empty slots, the root chain (11 CAs), the Manager's HTTPS
certificate, br1's trustpoints, Enterprise controller signing and the Manager as the edge CA. The PEMs in the
recording are redacted, so the renewal tests make their own CA, CSR and certificate.
"""

import datetime as dt
import json
from typing import Any

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastmcp import Client

from cat_sdwan_mcp import certificates as cert
from cat_sdwan_mcp.changes import RUNNING_TASKS_PATH
from cat_sdwan_mcp.tools import changes as change_tools

from .conftest import fixture, make_server
from .test_changes import STATUS, status_body
from .test_inventory import mock_inventory

NOW = dt.datetime(2026, 10, 23, tzinfo=dt.UTC).timestamp()
CSR_CN = "vsmart-00000000-0000-4000-8000-000000000001-0.cisco.com"


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


# --- a CA, a CSR and a signed certificate made here (the recording's PEMs are redacted) ------------


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("example-CA")
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, ca


def make_csr(cn: str = CSR_CN) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name(cn, "Cisco Systems"))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def sign(csr_pem: str, ca: tuple[ec.EllipticCurvePrivateKey, x509.Certificate], days: int = 730) -> str:
    """The signing callback: what the Enterprise CA (win_sign_csr in the lab) does with the CSR."""
    key, ca_cert = ca
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = dt.datetime.now(dt.UTC)
    c = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return c.public_bytes(serialization.Encoding.PEM).decode()


def pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


CA = make_ca()
OLD_CSR = make_csr()
OLD_CERT = sign(OLD_CSR, CA)


def controllers_body(**edits: Any) -> dict[str, Any]:
    """The recorded controller certificate list with real PEMs on the controller (vsmart) row."""
    body = fixture("certificate_data_controller_list")
    for c in body["data"]:
        if c["personality"] == "vsmart":
            c.update(deviceCSR=OLD_CSR, deviceEnterpriseCertificate=OLD_CERT, deviceCSRCommonName=CSR_CN)
            c.update(edits)
    return body


def mock_certs(api: respx.MockRouter, signing: str = "enterprise", **edits: Any) -> None:
    api.get(cert.SUMMARY_PATH).respond(json=fixture("certificate_stats_summary"))
    api.get(cert.DETAIL_PATH).respond(json=fixture("certificate_stats_detail"))
    api.get(cert.CONTROLLER_LIST_PATH).respond(json=controllers_body(**edits))
    api.get(cert.EDGE_LIST_PATH).respond(json=fixture("certificate_data_vedge_list"))
    api.get(cert.ROOT_CHAIN_PATH).respond(json=fixture("certificate_rootcertchains"))
    api.get(cert.WEBSERVER_PATH).respond(json=fixture("setting_webserver_certificate"))
    api.get(cert.LIST_STATUS_PATH).respond(200, text="")
    api.get(cert.SIGNING_PATH).respond(
        json={"data": [{"certificateSigning": signing, "retrieveInterval": 1}]}
    )
    api.get(cert.EDGE_CA_PATH).respond(json=fixture("settings_vedgecloud"))
    api.get(cert.ENTERPRISE_ROOT_PATH).respond(json={"data": [{"enterpriseRootCA": pem(CA[1])}]})


async def run(server: Any, name: str, args: dict[str, Any]) -> Any:
    result = await server.call_tool(name, args)
    return result.structured_content


def writes(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


# --- helpers -------------------------------------------------------------------------------------


def test_parse_time_forms() -> None:
    assert cert.iso_day(cert.parse_time("Oct 22 07:52:38 2028 GMT")) == "2028-10-22T07:52:38Z"
    assert cert.iso_day(cert.parse_time("Oct  2 07:52:38 2028 UTC")) == "2028-10-02T07:52:38Z"
    assert cert.iso_day(cert.parse_time("Fri Oct 17 01:04:19 UTC 2036")) == "2036-10-17T01:04:19Z"
    assert cert.iso_day(cert.parse_time("2033-11-18T21:59:46+00:00")) == "2033-11-18T21:59:46Z"
    assert cert.iso_day(cert.parse_time(1855813958000)) == "2028-10-22T07:52:38Z"
    assert cert.parse_time("NA") is None and cert.parse_time("") is None and cert.parse_time("soon") is None


def test_controller_rows_from_the_recording() -> None:
    body = fixture("certificate_data_controller_list")
    rows = [cert.controller_cert_row(c, now=NOW) for c in body["data"]]
    assert {r["role"] for r in rows} == {"manager", "controller", "validator"}
    for r in rows:
        assert r["status"] == "ok" and r["expires"].startswith("2028-10-22") and 700 < r["days_left"] < 731
        assert "breaks_when_expired" in r
    ctl = next(r for r in rows if r["role"] == "controller")
    assert "every control connection" in ctl["breaks_when_expired"]
    # 20 days before expiry it is expiring; after, expired
    late = cert.parse_time("Oct 02 07:52:38 2028 GMT")
    assert cert.controller_cert_row(body["data"][0], now=late)["status"] == "expiring"
    assert cert.controller_cert_row(body["data"][0], now=late + 40 * 86400)["status"] == "expired"
    assert cert.controller_cert_row({**body["data"][0], "validity": "invalid"})["status"] == "invalid"


def test_edge_rows_skip_empty_slots() -> None:
    rows = [
        r for v in fixture("certificate_data_vedge_list")["data"] if (r := cert.edge_cert_row(v, now=NOW))
    ]
    assert sorted(r["host"] for r in rows) == ["br1", "br2", "hub1"]
    assert all(r["expires"].startswith("2036-10-20") and r["status"] == "ok" for r in rows)


def test_root_chain_webserver_and_trustpoints() -> None:
    roots = cert.root_rows(fixture("certificate_rootcertchains")["data"], now=NOW)
    assert len(roots) == 11 and all("Certificate" not in r for r in roots)
    assert roots[0]["expires"] <= roots[-1]["expires"]  # soonest first among the ok ones
    assert any(r["name"] == "example-CA" and r["issuer"] == "self-signed (a root)" for r in roots)
    web = cert.webserver_row(fixture("setting_webserver_certificate")["certificateDetails"], now=NOW)
    assert web is not None
    assert (
        web["expires"] == "2029-10-22T07:51:20Z" and web["issuer"] == "self-signed" and web["status"] == "ok"
    )
    tps = [cert.trustpoint_row(t, now=NOW) for t in fixture("device_pki_trustpoint_br1")["data"]]
    assert len(tps) == 18 and tps[0]["label"] == "Trustpool" and tps[0]["authenticated"] == "true"


def test_describe_pem() -> None:
    assert cert.describe_pem(OLD_CSR) == {
        "kind": "csr",
        "subject": f"CN={CSR_CN},O=Cisco Systems",
        "common_name": CSR_CN,
    }
    info = cert.describe_pem(OLD_CERT)
    assert info is not None
    assert (
        info["issuer"] == "CN=example-CA" and info["serial"] == "1234ABCD" and info["common_name"] == CSR_CN
    )
    assert cert.describe_pem("not a pem") is None
    assert cert.describe_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----") is None


# --- catsdwan_certificates -----------------------------------------------------------------------


async def test_certificates_lists_controllers_and_edges(api: respx.MockRouter) -> None:
    mock_certs(api)
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_certificates", {"response_format": "json"})
    hosts = [r["host"] for r in out["results"]]
    assert set(hosts) == {"manager", "controller", "validator", "hub1", "br1", "br2"}
    assert hosts[:3] != ["hub1", "br1", "br2"]  # controllers expire first (2028 before 2036)
    assert out["results"][0]["kind"] == "controller" and out["results"][0]["manager_status"] == "normal"
    assert out["summary"] == {"invalid": 0, "warning": 0, "revoked": 0}
    assert out["signing"]["controllers"] == "enterprise" and out["signing"]["edges"] == "vmanage"
    assert len(out["root_chain"]) == 11 and out["webserver"]["expires"].startswith("2029")
    assert "attention" not in out and "errors" not in out


async def test_certificates_expiring_filter_and_kind(api: respx.MockRouter) -> None:
    mock_certs(api)
    async with Client(make_server()) as c:
        none = await run(c, "catsdwan_certificates", {"expiring_days": 30, "response_format": "json"})
        soon = await run(
            c,
            "catsdwan_certificates",
            {"expiring_days": 1000, "kind": "controller", "include_trust": False, "response_format": "json"},
        )
    assert none["results"] == [] and none["root_chain"] == []
    assert {r["host"] for r in soon["results"]} == {"manager", "controller", "validator"}
    assert all(r["status"] == "expiring" for r in soon["results"]) and len(soon["attention"]) == 3
    assert "signing" not in soon


async def test_certificates_trustpoints_for_an_edge(api: respx.MockRouter) -> None:
    mock_certs(api)
    mock_inventory(api)
    tp = api.get(cert.TRUSTPOINT_PATH).respond(json=fixture("device_pki_trustpoint_br1"))
    async with Client(make_server()) as c:
        out = await run(
            c, "catsdwan_certificates", {"device": "br1", "kind": "edge", "response_format": "json"}
        )
    assert tp.calls[0].request.url.params["deviceId"] == "10.0.0.2"
    assert out["trustpoints"]["device"] == "br1" and len(out["trustpoints"]["rows"]) == 18


async def test_certificates_survive_a_failing_section(api: respx.MockRouter) -> None:
    mock_certs(api)
    api.get(cert.ROOT_CHAIN_PATH).respond(500, json={"error": {"message": "boom"}})
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_certificates", {"response_format": "json"})
    assert len(out["results"]) == 6 and "root_chain" not in out
    assert any("rootcertchains" in e for e in out["errors"])


# --- catsdwan_renew_controller_certificate -------------------------------------------------------


async def test_renew_is_blocked_without_dangerous_but_previews(api: respx.MockRouter) -> None:
    mock_certs(api)
    gen = api.post(cert.GENERATE_CSR_PATH).respond(json={"data": [{"deviceCSR": make_csr()}]})
    async with Client(writes()) as c:
        out = await run(c, "catsdwan_renew_controller_certificate", {"controller": "controller"})
    assert out["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in out["blockers"][-1]
    prev = out["preview"]
    assert prev["controller"]["host"] == "controller" and prev["tier"] == "dangerous"
    assert prev["current_certificate"]["issuer"] == "CN=example-CA"
    assert prev["csr_fields"]["common_name"] == CSR_CN and len(prev["steps"]) == 3
    assert not gen.called


async def test_renew_refused_when_the_ca_is_not_enterprise(api: respx.MockRouter) -> None:
    mock_certs(api, signing="cisco")
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        out = await run(c, "catsdwan_renew_controller_certificate", {"controller": "1.1.1.3"})
    assert out["status"] == "blocked" and "not an Enterprise CA" in out["blockers"][0]


async def test_renew_unknown_controller() -> None:
    from fastmcp.exceptions import ToolError

    with respx.mock(base_url="https://catsdwan.test", assert_all_called=False) as api:
        from .conftest import mock_manager

        mock_manager(api)
        mock_certs(api)
        async with Client(writes(mcp_enable_dangerous=True)) as c:
            with pytest.raises(ToolError, match="validator"):
                await c.call_tool("catsdwan_renew_controller_certificate", {"controller": "hub1"})


async def test_renew_full_flow_with_a_signing_callback(api: respx.MockRouter) -> None:
    """Step 1 generates the CSR, the CA signs it (the callback), step 2 installs and sends to validators."""
    mock_certs(api)
    new_csr = make_csr()
    gen = api.post(cert.GENERATE_CSR_PATH).respond(json={"data": [{"deviceCSR": new_csr}]})
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args = {"controller": "controller"}
        prev = await run(c, "catsdwan_renew_controller_certificate", args)
        assert prev["status"] == "preview" and not gen.called
        done = await run(c, "catsdwan_renew_controller_certificate", {**args, "confirm": prev["confirm"]})
    assert json.loads(gen.calls[0].request.content) == {"deviceIP": "1.1.1.3"}
    step1 = done["result"]
    assert step1["csr"] == new_csr.strip() and "signed_certificate" in step1["next"]

    signed = sign(step1["csr"], CA)  # the Enterprise CA's signature
    # the Manager now shows the new CSR on the controller
    api.get(cert.CONTROLLER_LIST_PATH).respond(
        json=controllers_body(deviceCSR=new_csr, state="CSR Generated")
    )
    install = api.post(cert.INSTALL_PATH).respond(json={"id": "install-1"})
    send = api.post(cert.SEND_TO_VALIDATORS_PATH).respond(json={"id": "send-1"})
    api.get(f"{STATUS}/install-1").respond(json=status_body(("vsmart", "controller", "success")))
    api.get(f"{STATUS}/send-1").respond(json=status_body(("vbond", "validator", "success")))
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args2 = {"controller": "controller", "signed_certificate": signed}
        prev2 = await run(c, "catsdwan_renew_controller_certificate", args2)
        assert prev2["status"] == "preview", prev2.get("blockers")
        assert prev2["preview"]["new_certificate"]["issuer"] == "CN=example-CA"
        assert "warnings" not in prev2["preview"] and not install.called
        done2 = await run(c, "catsdwan_renew_controller_certificate", {**args2, "confirm": prev2["confirm"]})
    assert install.calls[0].request.content.decode() == signed.strip()
    res = done2["result"]
    assert res["install"]["outcome"] == "success" and res["sent_to_validators"]["outcome"] == "success"
    assert send.called


async def test_renew_step2_rejects_a_certificate_from_another_csr(api: respx.MockRouter) -> None:
    mock_certs(api)
    other = sign(make_csr("vsmart-someone-else-0.cisco.com"), CA)
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        out = await run(
            c,
            "catsdwan_renew_controller_certificate",
            {"controller": "controller", "signed_certificate": other},
        )
        csr = await run(
            c,
            "catsdwan_renew_controller_certificate",
            {"controller": "controller", "signed_certificate": OLD_CSR},
        )
        same = await run(
            c,
            "catsdwan_renew_controller_certificate",
            {"controller": "controller", "signed_certificate": OLD_CERT},
        )
    assert out["status"] == "blocked" and "common name" in out["blockers"][0]
    assert csr["status"] == "blocked" and "not a PEM certificate" in csr["blockers"][0]
    assert same["status"] == "blocked" and "already has installed" in same["blockers"][0]


async def test_renew_install_failure_skips_the_send(api: respx.MockRouter) -> None:
    mock_certs(api)
    signed = sign(OLD_CSR, CA, days=900)
    api.post(cert.INSTALL_PATH).respond(json={"id": "install-2"})
    send = api.post(cert.SEND_TO_VALIDATORS_PATH).respond(json={"id": "send-2"})
    api.get(f"{STATUS}/install-2").respond(json=status_body(("vsmart", "controller", "failure")))
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args = {"controller": "controller", "signed_certificate": signed}
        prev = await run(c, "catsdwan_renew_controller_certificate", args)
        done = await run(c, "catsdwan_renew_controller_certificate", {**args, "confirm": prev["confirm"]})
    assert done["result"]["install"]["outcome"] == "failed" and not send.called
    assert "skipped" in done["result"]["sent_to_validators"]


# --- catsdwan_sync_root_cert ---------------------------------------------------------------------


async def test_sync_root_cert_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_certs(api)
    sync = api.post(cert.FORCE_SYNC_ROOT_PATH).respond(json={"id": "sync-1"})
    api.get(f"{STATUS}/sync-1").respond(json=status_body(("vedge", "br1", "success")))
    api.get(RUNNING_TASKS_PATH).respond(json={"runningTasks": []})
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_sync_root_cert", {})
        assert prev["status"] == "preview" and not sync.called
        assert len(prev["preview"]["root_chain"]) == 11 and prev["blast_radius"] == prev["preview"]["devices"]
        done = await run(c, "catsdwan_sync_root_cert", {"confirm": prev["confirm"]})
    assert done["result"]["sync"]["outcome"] == "success"


async def test_sync_root_cert_rowless_status_ends_when_it_leaves_running_tasks(api: respx.MockRouter) -> None:
    # live 2026-10-24: the status never lists device rows nor a summary; the old wait ran for 600 s
    mock_certs(api)
    api.post(cert.FORCE_SYNC_ROOT_PATH).respond(json={"id": "sync-2"})
    status = api.get(f"{STATUS}/sync-2").respond(json=fixture("device_action_status_rootcert_sync"))
    tasks = api.get(RUNNING_TASKS_PATH).mock(
        side_effect=[
            httpx.Response(200, json={"runningTasks": [{"processId": "sync-2"}]}),
            httpx.Response(200, json={"runningTasks": []}),
        ]
    )
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_sync_root_cert", {})
        done = await run(c, "catsdwan_sync_root_cert", {"confirm": prev["confirm"]})
    sync = done["result"]["sync"]
    assert sync["outcome"] == "done" and sync["devices"] == [] and "audit" in sync["note"]
    assert status.call_count == 2 and tasks.call_count == 2


async def test_certificate_writes_need_writes() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catsdwan_certificates" in names
    assert not names & {"catsdwan_renew_controller_certificate", "catsdwan_sync_root_cert"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", cert.SUMMARY_PATH),
        ("GET", cert.CONTROLLER_LIST_PATH),
        ("GET", cert.EDGE_LIST_PATH),
        ("GET", cert.ROOT_CHAIN_PATH),
        ("GET", cert.TRUSTPOINT_PATH),
        ("POST", cert.GENERATE_CSR_PATH),
        ("POST", cert.INSTALL_PATH),
        ("POST", cert.SEND_TO_VALIDATORS_PATH),
        ("POST", cert.FORCE_SYNC_ROOT_PATH),
    ],
)
def test_certificate_paths_are_in_the_spec(method: str, path: str) -> None:
    from cat_sdwan_mcp._core.spec import build_index
    from cat_sdwan_mcp.spec import match_operation

    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, path)
    assert method in methods
