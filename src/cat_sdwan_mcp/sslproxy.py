"""W49 the edges' TLS/SSL proxy: the proxy CA on the Manager (Manager as an intermediate CA under the
enterprise CA, so the CA's private key is generated on the Manager and never leaves it) and the two SSL
decryption parcels of the policy-object profile.

Pure helpers; the tools are in tools/sslproxy.py. Sources:
- Recorded on 20.18.3.1 (no proxy CA): GET /sslproxy/settings/certificate {"enterpriseCA": false,
  "vManageRootCA": false}; GET /sslproxy/settings/vmanage/rootca {header, data: []}; GET
  /sslproxy/settings/enterprise/rootca {}; GET /sslproxy/settings/vmanage/csr {"csr": []}; GET /sslproxy/list
  {"sslproxylist": []}; the ssl-decryption and ssl-decryption-profile parcel schemas (POST).
- The Manager's OpenAPI examples (20.18.3) for the intermediate-CA flow, not recorded with a CA:
  1. POST /sslproxy/settings/enterprise/rootca {enterpriseRootCA: <PEM>, intermediateCA: "true"}: the
     enterprise root that will sign the Manager's CA (answers {enterpriseRootCA, fingerprint, last updated}).
  2. POST /sslproxy/generate/vmanage/csr {commonName, org, orgUnit, locality, state, country, email,
     intermediateCA: "true"} answers a task {id}; GET /sslproxy/settings/vmanage/csr then lists {csr:
     [{csr: <PEM>, commonName, hostCommonName, ...}]}.
  3. The CSR is signed by the enterprise CA as a subordinate CA (lab: win_sign_csr, template SubCA).
  4. POST /sslproxy/settings/vmanage/certificate {data: [{commonName, vManageRootCA: <signed PEM>,
     intermediateCA: "true"}]}; GET on the same path lists it {data: [{vManageRootCA, commonName, fingerprint,
     intermediateCA}]}.
  The edges' proxy certificates (/sslproxy/list: chasisNumber, state, expirationDate, hasCert) are issued by
  the Manager's CA once a policy with SSL decryption is deployed to them.
"""

from __future__ import annotations

from typing import Any

from cat_sdwan_mcp._core import InvalidRequest
from cat_sdwan_mcp.certificates import describe_pem, pem_digest
from cat_sdwan_mcp.securityprofiles import g

SETTINGS_PATH = "/dataservice/sslproxy/settings/certificate"
ENTERPRISE_ROOT_PATH = "/dataservice/sslproxy/settings/enterprise/rootca"
MANAGER_ROOT_PATH = "/dataservice/sslproxy/settings/vmanage/rootca"
MANAGER_CERT_PATH = "/dataservice/sslproxy/settings/vmanage/certificate"
MANAGER_CSR_PATH = "/dataservice/sslproxy/settings/vmanage/csr"
GENERATE_CSR_PATH = "/dataservice/sslproxy/generate/vmanage/csr"
EDGE_LIST_PATH = "/dataservice/sslproxy/list"


def records(body: Any, *keys: str) -> list[dict[str, Any]]:
    """The records of an sslproxy answer: {data: [...]}, {csr: [...]}, {sslproxylist: [...]}, a bare list, or
    one bare record ({} = none)."""
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict) and r]
    if not isinstance(body, dict):
        return []
    for k in ("data", *keys):
        if isinstance(body.get(k), list):
            return [r for r in body[k] if isinstance(r, dict) and r]
    return [body] if any(isinstance(v, str) and "BEGIN" in v for v in body.values()) else []


def first_pem(rec: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and "-----BEGIN" in v:
            return v.strip()
    return None


def cert_view(pem: str | None) -> dict[str, Any] | None:
    if not pem:
        return None
    info = describe_pem(pem) or {"kind": "unreadable"}
    return {**info, "digest": pem_digest(pem)}


def mode_of(settings: Any, manager_cert: dict[str, Any] | None, enterprise_root: str | None) -> str:
    """none / manager-root-ca / manager-intermediate-ca / enterprise-ca / enterprise-root-only."""
    s = settings if isinstance(settings, dict) else {}
    if manager_cert:
        return "manager-intermediate-ca"
    if s.get("vManageRootCA"):
        return "manager-root-ca"
    if s.get("enterpriseCA"):
        return "enterprise-ca"
    if enterprise_root:
        return "enterprise-root-only"
    return "none"


def edge_row(r: dict[str, Any]) -> dict[str, Any]:
    row = {
        "device": r.get("configuredHostname") or r.get("chasisNumber"),
        "chassis": r.get("chasisNumber") or r.get("uuid"),
        "site_id": r.get("configuredSiteId"),
        "state": r.get("state"),
        "has_certificate": r.get("hasCert"),
        "expires": r.get("expirationDate"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


# --- the CA ---------------------------------------------------------------------------------------


def csr_body(
    *,
    common_name: str,
    org: str,
    org_unit: str,
    locality: str,
    state: str,
    country: str,
    email: str,
) -> dict[str, Any]:
    if len(country) != 2 or not country.isalpha():
        raise InvalidRequest(f"country {country!r}: the two-letter ISO code (e.g. 'CA', 'US').")
    return {
        "commonName": common_name,
        "org": org,
        "orgUnit": org_unit,
        "locality": locality,
        "state": state,
        "country": country.upper(),
        "email": email,
        "intermediateCA": "true",
    }


def install_body(common_name: str, signed_pem: str) -> dict[str, Any]:
    return {"data": [{"commonName": common_name, "vManageRootCA": signed_pem, "intermediateCA": "true"}]}


def root_check(pem: str | None, *, now: float | None = None) -> dict[str, Any]:
    """The enterprise root certificate: self-signed, a CA, in date."""
    if not pem:
        return {
            "ok": False,
            "problems": ["no root certificate given (win_get_ca_certificate gives the lab CA's)"],
        }
    try:
        from cryptography import x509
    except ImportError:  # pragma: no cover - a fastmcp dependency
        return {"ok": True}
    try:
        cert = x509.load_pem_x509_certificate(pem.strip().encode())
    except ValueError:
        return {"ok": False, "problems": ["not a PEM certificate"]}
    info = describe_pem(pem, now=now) or {}
    problems = []
    if cert.subject != cert.issuer:
        problems.append("not self-signed: give the enterprise root CA, not an intermediate or a leaf")
    if not _is_ca(cert):
        problems.append("not a CA certificate (basicConstraints CA:TRUE missing)")
    if isinstance(info.get("days_left"), int | float) and info["days_left"] < 0:
        problems.append("expired")
    return {**info, "ok": not problems, **({"problems": problems} if problems else {})}


def _is_ca(cert: Any) -> bool:
    from cryptography import x509

    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def signed_check(
    signed_pem: str, csr_pem: str | None, root_pem: str | None, *, now: float | None = None
) -> dict[str, Any]:
    """The certificate the enterprise CA signed from the Manager's CSR: a CA, the CSR's key, issued by the
    root, in date."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    try:
        cert = x509.load_pem_x509_certificate(signed_pem.strip().encode())
    except ValueError:
        return {"ok": False, "problems": ["signed_certificate is not a PEM certificate"]}
    info = describe_pem(signed_pem, now=now) or {}
    problems = []
    if not _is_ca(cert):
        problems.append(
            "not a CA certificate: sign the CSR with a subordinate-CA template (win_sign_csr template "
            "'SubCA'), the Manager issues the edges' proxy certificates with it"
        )
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    if csr_pem:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.strip().replace("NEW CERTIFICATE", "CERTIFICATE").encode())
            if csr.public_key().public_bytes(der, spki) != cert.public_key().public_bytes(der, spki):
                problems.append(
                    "its key is not the one in the Manager's pending CSR (signed from another CSR?)"
                )
        except ValueError:
            problems.append("the Manager's pending CSR could not be read to compare keys")
    else:
        problems.append("the Manager has no pending CSR: run step 1 (generate the CSR) first")
    if root_pem:
        try:
            root = x509.load_pem_x509_certificate(root_pem.strip().encode())
        except ValueError:
            root = None
        if root is not None:
            try:
                cert.verify_directly_issued_by(root)  # issuer name and the root's signature
            except (ValueError, TypeError, InvalidSignature):
                problems.append(f"not issued by the enterprise root {root.subject.rfc4514_string()}")
    if isinstance(info.get("days_left"), int | float) and info["days_left"] < 0:
        problems.append("expired")
    return {**info, "ok": not problems, **({"problems": problems} if problems else {})}


def csr_pem_of(body: Any) -> tuple[str | None, dict[str, Any]]:
    """(the pending CSR PEM, its record) from GET /sslproxy/settings/vmanage/csr."""
    for r in records(body, "csr"):
        pem = first_pem(r, "csr")
        if pem:
            return pem, r
    return None, {}


# --- SSL decryption parcels -----------------------------------------------------------------------


def decryption_data(
    *,
    enabled: bool,
    expired_certificate: str,
    untrusted_certificate: str,
    revocation: str,
    unknown_status: str,
    unsupported_protocols: str,
    unsupported_ciphers: str,
    failure_mode: str,
    key_modulus: str,
    ec_key: str,
    certificate_lifetime_days: int,
    min_tls: str,
) -> dict[str, Any]:
    """The ssl-decryption parcel: with sslEnable false no other field may be given; with true all of them."""
    if not enabled:
        return {"sslEnable": g(False)}
    data: dict[str, Any] = {
        "sslEnable": g(True),
        "expiredCertificate": g(expired_certificate),
        "untrustedCertificate": g(untrusted_certificate),
        "certificateRevocationStatus": g(revocation),
        "unsupportedProtocolVersions": g(unsupported_protocols),
        "unsupportedCipherSuites": g(unsupported_ciphers),
        "failureMode": g(failure_mode),
        "caCertBundle": {"default": g(True)},
        "keyModulus": g(key_modulus),
        "eckeyType": g(ec_key),
        "certificateLifetime": g(str(certificate_lifetime_days)),
        "minTlsVer": g(min_tls),
        "caTpLabel": g("PROXY-SIGNING-CA"),
    }
    if revocation == "ocsp":
        data["unknownStatus"] = g(unknown_status)
    return data


def decryption_profile_data(
    *,
    decrypt: list[str],
    never: list[str],
    skip: list[str],
    reputation: bool,
    decrypt_threshold: str,
    skip_threshold: str | None,
    fail_decrypt: bool,
) -> dict[str, Any]:
    seen: dict[str, str] = {}
    for label, cats in (("decrypt", decrypt), ("never_decrypt", never), ("skip_decrypt", skip)):
        for c in cats:
            if c in seen:
                raise InvalidRequest(f"{c!r} is in both {seen[c]}_categories and {label}_categories.")
            seen[c] = label
    data: dict[str, Any] = {
        "decryptCategories": g(decrypt),
        "neverDecryptCategories": g(never),
        "reputation": g(reputation),
        "failDecrypt": g(fail_decrypt),
    }
    if skip:
        data["skipDecryptCategories"] = g(skip)
    if reputation:
        data["decryptThreshold"] = g(decrypt_threshold)
        if skip_threshold:
            data["skipDecryptThreshold"] = g(skip_threshold)
    return data
