"""W49: the SSL proxy CA (catsdwan_ssl_proxy_ca, catsdwan_set_ssl_proxy_ca) and the decryption parcels.

Recorded on 20.18.3.1 with no proxy CA: /sslproxy/settings/certificate (both flags false), vmanage/rootca
(no rows), enterprise/rootca ({}), vmanage/csr ({"csr": []}), /sslproxy/list (empty). The bodies with a CA
follow the Manager's OpenAPI examples (enterpriseRootCA, csr[].csr, data[].vManageRootCA) and are hand-built;
the certificates are generated here (a throwaway root, a CSR, a subordinate CA signed from it).
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
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.sslproxy import decryption_data, decryption_profile_data, mode_of, root_check, signed_check

from .conftest import fixture, make_server
from .test_securityprofiles import BASE, PO, mock_po, parcel

SETTINGS = "/dataservice/sslproxy/settings/certificate"
ENT = "/dataservice/sslproxy/settings/enterprise/rootca"
MROOT = "/dataservice/sslproxy/settings/vmanage/rootca"
MCERT = "/dataservice/sslproxy/settings/vmanage/certificate"
CSR = "/dataservice/sslproxy/settings/vmanage/csr"
GEN = "/dataservice/sslproxy/generate/vmanage/csr"
LIST = "/dataservice/sslproxy/list"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem(c: Any) -> str:
    return str(c.public_bytes(serialization.Encoding.PEM).decode())


def make_pki(*, ca: bool = True, other_key: bool = False) -> dict[str, str]:
    now = dt.datetime.now(dt.UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("lab-root"))
        .issuer_name(_name("lab-root"))
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    mgr_key = ec.generate_private_key(ec.SECP256R1())  # stands in for the key the Manager keeps
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name("sdwan-ssl-proxy-ca"))
        .sign(mgr_key, hashes.SHA256())
    )
    signed_key = ec.generate_private_key(ec.SECP256R1()).public_key() if other_key else mgr_key.public_key()
    sub = (
        x509.CertificateBuilder()
        .subject_name(_name("sdwan-ssl-proxy-ca"))
        .issuer_name(root.subject)
        .public_key(signed_key)
        .serial_number(2)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    return {"root": _pem(root), "csr": _pem(csr), "sub": _pem(sub)}


def mock_ca(
    api: respx.MockRouter, *, root: str | None = None, csr: str | None = None, cert: str | None = None
) -> None:
    api.get(SETTINGS).respond(json=fixture("sslproxy_settings_certificate"))
    api.get(ENT).respond(
        json={"enterpriseRootCA": root} if root else fixture("sslproxy_settings_enterprise_rootca")
    )
    api.get(MROOT).respond(json=fixture("sslproxy_settings_vmanage_rootca"))
    api.get(MCERT).respond(
        json={"data": [{"vManageRootCA": cert, "commonName": "sdwan-ssl-proxy-ca", "intermediateCA": "true"}]}
        if cert
        else {"data": []}
    )
    api.get(CSR).respond(
        json={"csr": [{"csr": csr, "commonName": "sdwan-ssl-proxy-ca"}]}
        if csr
        else fixture("sslproxy_settings_vmanage_csr")
    )
    api.get(LIST).respond(json=fixture("sslproxy_list"))


def server(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


async def run(c: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    out = (await c.call_tool(name, args)).structured_content
    assert out is not None
    return out


def test_checks() -> None:
    pki = make_pki()
    assert root_check(pki["root"])["ok"] is True
    assert "not self-signed" in root_check(pki["sub"])["problems"][0]
    assert root_check(None)["ok"] is False
    assert signed_check(pki["sub"], pki["csr"], pki["root"])["ok"] is True
    leaf = make_pki(ca=False)
    assert any(
        "subordinate-CA template" in p
        for p in signed_check(leaf["sub"], leaf["csr"], leaf["root"])["problems"]
    )
    other = make_pki(other_key=True)
    assert any(
        "not the one in the Manager's pending CSR" in p
        for p in signed_check(other["sub"], other["csr"], None)["problems"]
    )
    assert any(
        "not issued by the enterprise root" in p
        for p in signed_check(pki["sub"], pki["csr"], other["root"])["problems"]
    )
    assert mode_of(fixture("sslproxy_settings_certificate"), None, None) == "none"
    assert mode_of({}, {"vManageRootCA": "x"}, None) == "manager-intermediate-ca"


def test_decryption_bodies() -> None:
    off = decryption_data(
        enabled=False,
        expired_certificate="drop",
        untrusted_certificate="drop",
        revocation="none",
        unknown_status="drop",
        unsupported_protocols="no-decrypt",
        unsupported_ciphers="no-decrypt",
        failure_mode="close",
        key_modulus="2048",
        ec_key="P256",
        certificate_lifetime_days=1,
        min_tls="TLSv1.2",
    )
    assert off == {"sslEnable": {"optionType": "global", "value": False}}
    on = decryption_data(
        enabled=True,
        expired_certificate="drop",
        untrusted_certificate="drop",
        revocation="ocsp",
        unknown_status="decrypt",
        unsupported_protocols="no-decrypt",
        unsupported_ciphers="drop",
        failure_mode="close",
        key_modulus="2048",
        ec_key="P256",
        certificate_lifetime_days=1,
        min_tls="TLSv1.2",
    )
    assert on["caTpLabel"]["value"] == "PROXY-SIGNING-CA" and on["certificateLifetime"]["value"] == "1"
    assert on["unknownStatus"]["value"] == "decrypt" and on["caCertBundle"] == {
        "default": {"optionType": "global", "value": True}
    }
    prof = decryption_profile_data(
        decrypt=["gambling"],
        never=["financial-services"],
        skip=[],
        reputation=False,
        decrypt_threshold="suspicious",
        skip_threshold=None,
        fail_decrypt=True,
    )
    assert "decryptThreshold" not in prof and "skipDecryptCategories" not in prof
    with pytest.raises(Exception, match="in both decrypt_categories and never_decrypt_categories"):
        decryption_profile_data(
            decrypt=["games"],
            never=["games"],
            skip=[],
            reputation=False,
            decrypt_threshold="suspicious",
            skip_threshold=None,
            fail_decrypt=True,
        )


async def test_read_on_the_recorded_lab(api: respx.MockRouter) -> None:
    mock_ca(api)
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_ssl_proxy_ca", {})
    assert out["mode"] == "none" and out["enterprise_root"] == "none" and out["manager_ca"] == "none"
    assert out["edge_certificates"].startswith("none")
    assert "win_sign_csr(template='SubCA')" in out["next"]


async def test_step1_generates_the_csr(api: respx.MockRouter) -> None:
    pki = make_pki()
    mock_ca(api)
    api.get(CSR).mock(
        side_effect=[httpx.Response(200, json=fixture("sslproxy_settings_vmanage_csr"))] * 2
        + [httpx.Response(200, json={"csr": [{"csr": pki["csr"], "commonName": "sdwan-ssl-proxy-ca"}]})]
    )
    root_post = api.post(ENT).respond(json={"enterpriseRootCA": pki["root"]})
    gen = api.post(GEN).respond(json={"id": "task-1"})
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ssl_proxy_ca", {"root_certificate": pki["root"]})
        assert prev["status"] == "preview" and not gen.called
        p = prev["preview"]
        assert p["root_check"]["ok"] is True and p["tier"] == "write"
        assert p["csr_subject"]["commonName"] == "sdwan-ssl-proxy-ca" and p["csr_subject"]["country"] == "CA"
        assert p["requests"][0].startswith(f"POST {ENT}") and p["requests"][1].startswith(f"POST {GEN}")
        done = (
            await run(
                c, "catsdwan_set_ssl_proxy_ca", {"root_certificate": pki["root"], "confirm": prev["confirm"]}
            )
        )["result"]
    assert done["outcome"] == "csr generated" and done["csr"] == pki["csr"].strip()
    assert json.loads(root_post.calls.last.request.content) == {
        "enterpriseRootCA": pki["root"].strip(),
        "intermediateCA": "true",
    }
    sent = json.loads(gen.calls.last.request.content)
    assert (
        sent["intermediateCA"] == "true"
        and sent["orgUnit"] == "Network"
        and "key" not in json.dumps(sent).lower()
    )


async def test_step1_refuses_a_bad_root(api: respx.MockRouter) -> None:
    pki = make_pki()
    mock_ca(api)
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ssl_proxy_ca", {"root_certificate": pki["sub"]})
        assert prev["status"] == "blocked" and "not self-signed" in prev["blockers"][0]
        with pytest.raises(ToolError, match="two-letter"):
            await c.call_tool(
                "catsdwan_set_ssl_proxy_ca", {"root_certificate": pki["root"], "country": "Canada"}
            )


async def test_step2_installs_the_signed_ca(api: respx.MockRouter) -> None:
    pki = make_pki()
    mock_ca(api, root=pki["root"], csr=pki["csr"])
    install = api.post(MCERT).respond(
        json={"data": [{"commonName": "sdwan-ssl-proxy-ca", "vManageRootCA": pki["sub"]}]}
    )
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ssl_proxy_ca", {"signed_certificate": pki["sub"]})
        assert prev["status"] == "preview", prev.get("blockers")
        assert prev["preview"]["certificate_check"]["ok"] is True
        done = (
            await run(
                c, "catsdwan_set_ssl_proxy_ca", {"signed_certificate": pki["sub"], "confirm": prev["confirm"]}
            )
        )["result"]
    assert done["outcome"] == "installed" and done["answer"]["data"][0]["commonName"] == "sdwan-ssl-proxy-ca"
    body = json.loads(install.calls.last.request.content)
    assert body == {
        "data": [
            {
                "commonName": "sdwan-ssl-proxy-ca",
                "vManageRootCA": pki["sub"].strip(),
                "intermediateCA": "true",
            }
        ]
    }


async def test_step2_wrong_key_and_existing_ca(api: respx.MockRouter) -> None:
    pki = make_pki()
    other = make_pki(other_key=True)
    mock_ca(api, root=pki["root"], csr=pki["csr"], cert=pki["sub"])
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ssl_proxy_ca", {"signed_certificate": other["sub"]})
        assert prev["status"] == "blocked"
        assert any("already has an SSL proxy CA (manager-intermediate-ca)" in b for b in prev["blockers"])
        assert any("not the one in the Manager's pending CSR" in b for b in prev["blockers"])
        rep = await run(c, "catsdwan_set_ssl_proxy_ca", {"signed_certificate": pki["sub"], "replace": True})
    assert rep["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in rep["blockers"][0]
    assert rep["preview"]["tier"] == "dangerous"


async def test_decryption_parcels(api: respx.MockRouter) -> None:
    mock_ca(api)
    mock_po(api, [parcel("9b9b9b9b-0000-4000-8000-00000000009b", "unified/ssl-decryption-profile", "old")])
    post = api.post(f"{BASE}/{PO}/unified/ssl-decryption").respond(json={"parcelId": "p1"})
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ssl_decryption", {"name": "mcp-ssl"})
        assert any("no SSL proxy CA yet" in n for n in prev["preview"]["notes"])
        assert prev["preview"]["values"]["minTlsVer"] == "TLSv1.2"
        assert (
            prev["undo"]
            == 'back-out: catsdwan_delete_security_profile(kind="ssl-decryption", name="mcp-ssl")'
        )
        await run(c, "catsdwan_set_ssl_decryption", {"name": "mcp-ssl", "confirm": prev["confirm"]})
        sent = json.loads(post.calls.last.request.content)
        assert (
            sent["description"] == "TLS/SSL Proxy Policy Definition"
            and sent["data"]["sslEnable"]["value"] is True
        )
        with pytest.raises(ToolError, match="nothing is decrypted"):
            await c.call_tool("catsdwan_set_ssl_decryption_profile", {"name": "p"})
        prof = await run(
            c,
            "catsdwan_set_ssl_decryption_profile",
            {
                "name": "mcp-decrypt",
                "decrypt_categories": ["gambling"],
                "never_decrypt_categories": ["Financial Services"],
            },
        )
    v = prof["preview"]["values"]
    assert v["decryptCategories"] == ["gambling"] and v["neverDecryptCategories"] == ["financial-services"]
    assert prof["preview"]["action"] == "create"
    assert prof["undo"].startswith('back-out: catsdwan_delete_security_profile(kind="ssl-decryption-profile"')


async def test_inspection_profile_decrypt_uses_the_profile(api: respx.MockRouter) -> None:
    ips = "b2b2b2b2-0000-4000-8000-000000000002"
    sslp = "9b9b9b9b-0000-4000-8000-00000000009b"
    mock_po(
        api,
        [
            parcel(ips, "unified/intrusion-prevention", "mcp-ips"),
            parcel(sslp, "unified/ssl-decryption-profile", "mcp-decrypt"),
        ],
    )
    async with Client(server()) as c:
        prev = await run(
            c,
            "catsdwan_set_inspection_profile",
            {
                "name": "aip",
                "ips": "mcp-ips",
                "tls_action": "decrypt",
                "ssl_decryption_profile": "mcp-decrypt",
            },
        )
    assert prev["undo"].startswith(
        'back-out: catsdwan_delete_security_profile(kind="advanced-inspection-profile"'
    )
    v = prev["preview"]["values"]
    assert v["tlsDecryptionAction"] == "decrypt" and v["sslDecryptionProfile"] == f"ref {sslp}"
