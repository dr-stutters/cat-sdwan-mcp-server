"""Certificates and trust (W16): pure helpers; the tools are in tools/certificates.py.

Sources (recorded on 20.18.3.1 unless noted):
- GET /dataservice/certificate/stats/summary: {data: [{invalid, warning, revoked}]} (counts).
- GET /dataservice/certificate/stats/detail: the controllers with host-name, local-system-ip, expirationDate
  ("Oct 22 07:52:38 2028 GMT") and expirationStatus ("normal", "warning", ...).
- GET /dataservice/certificate/data/controller/list: one row per Manager, controller and validator:
  personality, deviceIP (the system IP once installed), host-name, state ("Installed", "vBond Updated",
  "CSR Generated"), certInstallStatus, validity, expirationDate, expirationDateLong (ms), deviceCSR (the
  last CSR, PEM), deviceCSRCommonName ("vsmart-<uuid>-0.cisco.com"), deviceEnterpriseCertificate (the
  installed certificate, PEM), serialNumber (the certificate's), org, rootCertHash, activity.
- GET /dataservice/certificate/data/vedge/list: every WAN edge slot: host-name, system-ip, chasisNumber,
  vedgeCertificateState (certinstalled, tokengenerated, ...), validity, expirationDate ("Oct 20 08:05:47
  2036 UTC", "NA" before a join), expirationDateLong, expirationStatus.
- GET /dataservice/certificate/rootcertchains?action=get: {data: [{CommonName, Subject, Issuer, SerialNumber,
  FingerPrint, ExpirationDate ("Fri Oct 17 01:04:19 UTC 2036"), Certificate}]}: the trust chain the fabric
  uses (the Enterprise root, Cisco's and the Manager's own roots).
- GET /dataservice/certificate/list/status: an empty text body on the lab.
- GET /dataservice/setting/configuration/webserver/certificate/getcertificate: {certificateDetails: Java's
  certificate text} ("Subject: ...", "Issuer: ...", "Validity: [From: ..., To: Mon Oct 22 07:51:20 UTC
  2029]").
- GET /dataservice/device/pki/trustpoint?deviceId=<system-ip>: an IOS XE edge's trustpoints (label,
  cert/subject-name, cert/issuer-name, cert/validity-end ISO 8601, tp-authenticated); empty on a controller.
- GET /dataservice/settings/configuration/certificate: {data: [{certificateSigning: enterprise | cisco |
  manual, retrieveInterval}]} (controller certificate authorisation);
  /settings/configuration/vedgecloud: {data: [{certificateauthority: vmanage | enterprise}]};
  /settings/configuration/certificate/enterpriserootca: {data: [{enterpriseRootCA: PEM}]}.

Renewal (the W0 build's steps, recorded by the lab seed): POST /certificate/generate/csr {deviceIP} ->
{data: [{deviceCSR: PEM}]}; POST /certificate/install/signedCert with the signed PEM as the raw body -> {id}
(an action, followed through /device/action/status/{id}); POST /certificate/vsmart/list sends the controller
list to the validators -> {id} (Cisco's documented shape; not recorded).
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import UTC, datetime
from typing import Any

from cat_sdwan_mcp.client import ROLE

SUMMARY_PATH = "/dataservice/certificate/stats/summary"
DETAIL_PATH = "/dataservice/certificate/stats/detail"
CONTROLLER_LIST_PATH = "/dataservice/certificate/data/controller/list"
EDGE_LIST_PATH = "/dataservice/certificate/data/vedge/list"
ROOT_CHAIN_PATH = "/dataservice/certificate/rootcertchains"
LIST_STATUS_PATH = "/dataservice/certificate/list/status"
WEBSERVER_PATH = "/dataservice/setting/configuration/webserver/certificate/getcertificate"
TRUSTPOINT_PATH = "/dataservice/device/pki/trustpoint"
SIGNING_PATH = "/dataservice/settings/configuration/certificate"
EDGE_CA_PATH = "/dataservice/settings/configuration/vedgecloud"
ENTERPRISE_ROOT_PATH = "/dataservice/settings/configuration/certificate/enterpriserootca"
GENERATE_CSR_PATH = "/dataservice/certificate/generate/csr"
INSTALL_PATH = "/dataservice/certificate/install/signedCert"
SEND_TO_VALIDATORS_PATH = "/dataservice/certificate/vsmart/list"
FORCE_SYNC_ROOT_PATH = "/dataservice/certificate/forcesync/rootCert"

WARN_DAYS = 30  # "expiring" when no expiring_days is given
STATUS_ORDER = {"invalid": 0, "expired": 1, "expiring": 2, "not installed": 3, "ok": 4}

# What stops working when this kind of certificate expires (or is invalid).
BREAKS = {
    "validator": "edges and controllers can no longer authenticate to the validator: new joins and every "
    "reconnection fail",
    "controller": "every control connection to this controller drops: OMP routes and policy stop reaching "
    "the edges, whose tunnels age out after OMP graceful restart",
    "manager": "the Manager's control connections drop: no configuration pushes, monitoring or real-time "
    "reads of any device",
    "edge": "the edge's control connections drop: it loses OMP and, after graceful restart, its tunnels",
    "root": "devices can no longer verify the certificates this CA signed",
    "webserver": "browsers and API clients get an expired HTTPS certificate from the Manager (clients that "
    "verify TLS refuse to connect)",
}

_FORMATS = (
    "%b %d %H:%M:%S %Y %Z",  # Oct 22 07:52:38 2028 GMT (controller and edge lists)
    "%a %b %d %H:%M:%S %Z %Y",  # Fri Oct 17 01:04:19 UTC 2036 (root chain, web server)
)


def parse_time(value: Any) -> float | None:
    """Epoch seconds from the Manager's date forms: milliseconds, 'Oct 22 07:52:38 2028 GMT', 'Fri Oct 17
    01:04:19 UTC 2036' or ISO 8601; None for 'NA', '' and anything else."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value) / 1000 if value > 1e11 else float(value)
    if not isinstance(value, str) or not value.strip() or value.strip().upper() in ("NA", "N/A"):
        return None
    text = " ".join(value.split())
    if text.isdigit():
        return parse_time(int(text))
    for fmt in _FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()


def iso_day(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def days_left(ts: float | None, now: float | None = None) -> int | None:
    if ts is None:
        return None
    now = time.time() if now is None else now
    return int((ts - now) // 86400)


def status_of(days: int | None, warn_days: int, *, installed: bool = True, valid: bool = True) -> str:
    if not valid:
        return "invalid"
    if not installed:
        return "not installed"
    if days is None:
        return "ok"
    if days < 0:
        return "expired"
    return "expiring" if days <= warn_days else "ok"


def _clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v not in (None, "", [], "NA")}


def _expiry(rec: dict[str, Any]) -> float | None:
    return parse_time(rec.get("expirationDateLong")) or parse_time(rec.get("expirationDate"))


def _valid(rec: dict[str, Any]) -> bool:
    return str(rec.get("validity") or "valid").lower() == "valid"


def controller_cert_row(
    c: dict[str, Any],
    status: dict[str, str] | None = None,
    *,
    warn_days: int = WARN_DAYS,
    now: float | None = None,
) -> dict[str, Any]:
    """One /certificate/data/controller/list row: who, its certificate and what breaks when it expires.
    `status` maps a system IP to the Manager's own expirationStatus (/certificate/stats/detail)."""
    role = ROLE.get(str(c.get("personality") or c.get("deviceType")), c.get("personality"))
    ts = _expiry(c)
    days = days_left(ts, now)
    installed = str(c.get("certInstallStatus") or "").lower() == "installed" or bool(
        c.get("deviceEnterpriseCertificate")
    )
    ip = c.get("system-ip") or c.get("deviceIP")
    row = {
        "kind": "controller",
        "host": c.get("host-name"),
        "role": role,
        "system_ip": ip,
        "status": status_of(days, warn_days, installed=installed, valid=_valid(c)),
        "expires": iso_day(ts),
        "days_left": days,
        "manager_status": (status or {}).get(str(ip)),
        "state": c.get("state"),
        "install_status": c.get("certInstallStatus"),
        "validity": c.get("validity"),
        "serial": c.get("serialNumber") if c.get("serialNumber") != "No certificate installed" else None,
        "csr_common_name": c.get("deviceCSRCommonName"),
        "key_length": c.get("keyLength"),
        "breaks_when_expired": BREAKS.get(str(role)),
    }
    return _clean(row)


EDGE_SKIP_STATES = {"tokengenerated", "bootstrapconfiggenerated"}  # slots that never joined: no certificate


def edge_cert_row(
    v: dict[str, Any], *, warn_days: int = WARN_DAYS, now: float | None = None
) -> dict[str, Any] | None:
    """One /certificate/data/vedge/list row for an edge that has a certificate (None for an empty slot)."""
    state = str(v.get("vedgeCertificateState") or "").lower()
    if state in EDGE_SKIP_STATES and not v.get("system-ip"):
        return None
    ts = _expiry(v)
    days = days_left(ts, now)
    installed = state in ("certinstalled", "") or ts is not None
    row = {
        "kind": "edge",
        "host": v.get("host-name"),
        "role": "edge",
        "system_ip": v.get("system-ip"),
        "site_id": v.get("site-id"),
        "chassis": v.get("chasisNumber") or v.get("uuid"),
        "status": status_of(days, warn_days, installed=installed, valid=_valid(v)),
        "expires": iso_day(ts),
        "days_left": days,
        "manager_status": v.get("expirationStatus"),
        "state": v.get("vedgeCertificateState"),
        "validity": v.get("validity"),
        "issuer": "Manager (vEdge cloud CA)" if v.get("vedgeCSR") or state == "certinstalled" else None,
        "breaks_when_expired": BREAKS["edge"],
    }
    return _clean(row)


def sort_certs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Invalid and expired first, then expiring, then by days left."""
    return sorted(
        rows,
        key=lambda r: (
            STATUS_ORDER.get(str(r.get("status")), 9),
            r.get("days_left") if isinstance(r.get("days_left"), int) else 10**9,
            str(r.get("host") or ""),
        ),
    )


def root_rows(
    rows: list[dict[str, Any]], *, warn_days: int = WARN_DAYS, now: float | None = None
) -> list[Any]:
    """The trust chain: name, subject, issuer, expiry and status (expiring first); PEMs left out."""
    out = []
    for r in rows:
        ts = parse_time(r.get("ExpirationDate"))
        days = days_left(ts, now)
        subject, issuer = r.get("Subject"), r.get("Issuer")
        row = {
            "name": r.get("CommonName"),
            "subject": subject,
            "issuer": issuer if issuer != subject else "self-signed (a root)",
            "status": status_of(days, warn_days),
            "expires": iso_day(ts),
            "days_left": days,
            "fingerprint": r.get("FingerPrint"),
        }
        out.append(_clean(row))
    return sort_certs(out)


_FIELD = re.compile(r"^\s*(Subject|Issuer|SerialNumber):\s*(.+?)\s*$", re.M)
_VALIDITY = re.compile(r"From:\s*([^,\]]+),\s*To:\s*([^\]]+)\]", re.S)


def webserver_row(
    details: Any, *, warn_days: int = WARN_DAYS, now: float | None = None
) -> dict[str, Any] | None:
    """The Manager's HTTPS certificate from Java's certificate text (subject, issuer, validity)."""
    if not isinstance(details, str) or not details.strip():
        return None
    fields = {k: v for k, v in _FIELD.findall(details)}
    m = _VALIDITY.search(details)
    start, end = (parse_time(m.group(1)), parse_time(m.group(2))) if m else (None, None)
    days = days_left(end, now)
    subject, issuer = fields.get("Subject"), fields.get("Issuer")
    row = {
        "subject": subject,
        "issuer": "self-signed" if subject and subject == issuer else issuer,
        "valid_from": iso_day(start),
        "expires": iso_day(end),
        "days_left": days,
        "status": status_of(days, warn_days),
        "breaks_when_expired": BREAKS["webserver"],
    }
    return _clean(row)


def trustpoint_row(
    t: dict[str, Any], *, warn_days: int = WARN_DAYS, now: float | None = None
) -> dict[str, Any]:
    ts = parse_time(t.get("cert/validity-end"))
    days = days_left(ts, now)
    subject, issuer = t.get("cert/subject-name"), t.get("cert/issuer-name")
    row = {
        "label": t.get("label"),
        "subject": subject,
        "issuer": "self-signed" if subject and subject == issuer else issuer,
        "expires": iso_day(ts),
        "days_left": days,
        "status": status_of(days, warn_days),
        "authenticated": t.get("tp-authenticated"),
    }
    return _clean(row)


def first(body: Any) -> dict[str, Any]:
    data = body.get("data") if isinstance(body, dict) else body
    if isinstance(data, list):
        data = data[0] if data else {}
    return data if isinstance(data, dict) else {}


SIGNING = {
    "enterprise": "Enterprise CA: the operator signs each controller CSR with the organisation's CA",
    "cisco": "Cisco (automated via Cisco PKI / PnP): the Manager signs and installs certificates itself",
    "manual": "Cisco, manual: the operator uploads CSRs to Cisco's portal",
    "vmanage": "the Manager's own CA (edges get Manager-signed certificates)",
}


def signing_row(controller_mode: Any, edge_mode: Any) -> dict[str, Any]:
    c, e = str(controller_mode or "").lower(), str(edge_mode or "").lower()
    row = {
        "controllers": c or None,
        "controllers_meaning": SIGNING.get(c),
        "edges": e or None,
        "edges_meaning": SIGNING.get(e) if e != "enterprise" else "Enterprise CA",
    }
    return _clean(row)


# --- renewal ---------------------------------------------------------------------------------------


def resolve_controller(rows: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    want = ref.strip().lower()
    for c in rows:
        role = ROLE.get(str(c.get("personality") or c.get("deviceType")), "")
        keys = (c.get("host-name"), c.get("system-ip"), c.get("deviceIP"), c.get("uuid"), role)
        if want in {str(k).lower() for k in keys if k}:
            return c
    return None


def controller_names(rows: list[dict[str, Any]]) -> list[str]:
    return [f"{c.get('host-name') or c.get('deviceIP')} ({c.get('deviceIP')})" for c in rows]


def pem_digest(pem: Any) -> str | None:
    if not isinstance(pem, str) or "-----BEGIN" not in pem:
        return None
    return hashlib.sha256("".join(pem.split()).encode()).hexdigest()[:16]


def _name(n: Any) -> str:
    return str(n.rfc4514_string())


def describe_pem(pem: Any, *, now: float | None = None) -> dict[str, Any] | None:
    """Subject, issuer, serial and validity of a PEM certificate, or the subject of a PEM CSR (None when it
    isn't one, or the cryptography package is missing)."""
    if not isinstance(pem, str) or "-----BEGIN" not in pem:
        return None
    try:
        from cryptography import x509
    except ImportError:  # pragma: no cover - a fastmcp dependency, so always present
        return None
    data = pem.strip().encode()
    try:
        if "CERTIFICATE REQUEST" in pem:
            csr = x509.load_pem_x509_csr(data)
            return {"kind": "csr", "subject": _name(csr.subject), "common_name": _cn(csr.subject)}
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        return None
    end = cert.not_valid_after_utc.timestamp()
    return _clean(
        {
            "kind": "certificate",
            "subject": _name(cert.subject),
            "common_name": _cn(cert.subject),
            "issuer": _name(cert.issuer),
            "serial": format(cert.serial_number, "X"),
            "valid_from": iso_day(cert.not_valid_before_utc.timestamp()),
            "expires": iso_day(end),
            "days_left": days_left(end, now),
        }
    )


def _cn(name: Any) -> str | None:
    from cryptography.x509.oid import NameOID

    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def csr_of(body: Any) -> str | None:
    """The CSR PEM from POST /certificate/generate/csr ({data: [{deviceCSR}]}) or a bare text answer."""
    if isinstance(body, str) and "BEGIN CERTIFICATE REQUEST" in body:
        return body.strip()
    row = first(body)
    for k in ("deviceCSR", "csr", "CSR"):
        if isinstance(row.get(k), str) and "BEGIN" in row[k]:
            return str(row[k]).strip()
    return None


def is_pem_certificate(text: str) -> bool:
    return "-----BEGIN CERTIFICATE-----" in text and "-----END CERTIFICATE-----" in text
