"""W41 the Manager's ISE and pxGrid integration (Administration > Integration Management > Identity Services
Engine): connect, activate pxGrid, sync to the controllers, disconnect.

The 20.18 API (the Manager's own OpenAPI document, 20.18.3):
- GET/POST/PUT /ise/credentials: the ISE server (`IseServer`: iseServerIP, userName, password, vpn,
  destinationVpn, vpnIpSubnet, sgt, userAndUserGroup (strings "true"/"false"), activeDirectoryDomain,
  joinPoint, iseRootCert / iseCertName, pxGridRootCert / pxGridCertName); POST and PUT answer a boolean.
- POST /ise/pxgrid/create {nodeName}: creates the pxGrid client account on ISE (answers nodeName, userName and
  a password: a secret, never shown).
- POST /ise/pxgrid/activate {pxGridUserName, pxGridPassword, description}: answers accountState, PENDING until
  the client is approved on ISE (ise_approve_pxgrid_client), ENABLED after.
- PUT /ise/pxgrid/approve: the Manager approves its own client with the ISE admin login (optional here).
- GET /ise/credentials/pxgrid: the pxGrid account (`PxGridInfo`: pxGridServerIp, pxGridHostName, nodeName,
  pxGridUserName, pxGridPassword, status, ...); GET /ise/credentials/pxgrid/cert: the pxGrid certificate.
- POST /ise/credentials/vsmart/sync: sends the ISE and pxGrid settings to the controllers (answers a task id).
- DELETE /ise/credentials/iseandpxgrid: removes both on the Manager and the pxGrid client on ISE (the undo).

Recorded on 20.18.3.1 with no ISE configured: /ise/credentials and /ise/credentials/pxgrid answer `{}`;
/ise/credentials/pxgrid/cert answers 400 ISEERRORR0005 'Failed to save pxgrid account details: pxGrid details
are empty'. The bodies with an ISE configured are built from the schema and are proven live in the C44 stage.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cat_sdwan_mcp.certificates import describe_pem, is_pem_certificate

CREDENTIALS_PATH = "/dataservice/ise/credentials"
PXGRID_PATH = "/dataservice/ise/credentials/pxgrid"
PXGRID_CERT_PATH = "/dataservice/ise/credentials/pxgrid/cert"
PXGRID_CREATE_PATH = "/dataservice/ise/pxgrid/create"
PXGRID_ACTIVATE_PATH = "/dataservice/ise/pxgrid/activate"
PXGRID_APPROVE_PATH = "/dataservice/ise/pxgrid/approve"
SYNC_PATH = "/dataservice/ise/credentials/vsmart/sync"
DISCONNECT_PATH = "/dataservice/ise/credentials/iseandpxgrid"

MASK = "********"
# The IseServer fields compared to decide whether the stored connection already matches (the password is
# write-only in practice, so a change of password alone is not detected: pass rotate_password=true).
COMPARED = (
    "iseServerIP",
    "vpn",
    "destinationVpn",
    "sgt",
    "userAndUserGroup",
    "activeDirectoryDomain",
    "joinPoint",
)
SECRET_KEYS = ("password", "pxGridPassword", "AccessSecret")


def data_of(body: Any) -> Any:
    return body.get("data", body) if isinstance(body, dict) else body


def stored(body: Any) -> dict[str, Any]:
    """The stored IseServer / PxGridInfo record, {} when none (the Manager answers `{}`)."""
    data = data_of(body)
    if isinstance(data, list):
        data = next((d for d in data if isinstance(d, dict) and d), {})
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if v not in (None, "", [], {})}


def masked(rec: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if k in SECRET_KEYS:
            out[k] = MASK
        elif k in ("iseRootCert", "pxGridRootCert") and isinstance(v, str):
            out[k] = describe_pem(v) or "(not a PEM certificate)"
        else:
            out[k] = v
    return out


def flag(v: bool) -> str:
    return "true" if v else "false"


def server_body(
    *,
    ise_host: str,
    username: str,
    password: str,
    vpn: int,
    subscribe_sgt: bool,
    subscribe_users: bool,
    ad_domain: str | None,
    join_point: str | None,
    root_cert: str | None,
    pxgrid_root_cert: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "iseServerIP": ise_host,
        "userName": username,
        "password": password,
        "vpn": str(vpn),
        "destinationVpn": str(vpn),
        "vpnIpSubnet": "",
        "sgt": flag(subscribe_sgt),
        "userAndUserGroup": flag(subscribe_users),
    }
    if ad_domain:
        body["activeDirectoryDomain"] = ad_domain
    if join_point:
        body["joinPoint"] = join_point
    if root_cert:
        body["iseRootCert"] = root_cert
    if pxgrid_root_cert or root_cert:
        body["pxGridRootCert"] = pxgrid_root_cert or root_cert
    return body


def differences(current: dict[str, Any], wanted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{field: {from, to}} for the compared fields that differ (missing counts as '')."""
    out = {}
    for k in COMPARED:
        a, b = str(current.get(k, "") or ""), str(wanted.get(k, "") or "")
        if a.lower() != b.lower():
            out[k] = {"from": current.get(k), "to": wanted.get(k)}
    return out


def pxgrid_state(rec: dict[str, Any]) -> str:
    """none / pending / enabled / disabled / <raw> from the pxGrid account record."""
    if not rec:
        return "none"
    raw = str(rec.get("status") or rec.get("accountState") or "").strip().lower()
    if not raw:
        return "created"
    for s in ("pending", "enabled", "disabled"):
        if s in raw:
            return s
    return raw


def node_name_of(rec: dict[str, Any]) -> str | None:
    v = rec.get("nodeName") or rec.get("pxGridUserName")
    return str(v) if v else None


def cert_check(pem: str | None, *, now: float | None = None) -> dict[str, Any]:
    """What the preview says about a root certificate given for ISE (the chain the Manager will trust)."""
    if not pem:
        return {
            "given": False,
            "note": "no ISE root certificate given: the Manager must already trust the CA that signed ISE's "
            "admin and pxGrid certificates (ise_pxgrid_status shows that chain), and ISE must trust the "
            "Manager's pxGrid client certificate",
        }
    if not is_pem_certificate(pem):
        return {"given": True, "ok": False, "problem": "not a PEM certificate (-----BEGIN CERTIFICATE-----)"}
    info = describe_pem(pem, now=now) or {}
    out: dict[str, Any] = {"given": True, **info}
    problems = []
    warnings = []
    if info.get("subject") and info.get("issuer") and info["subject"] != info["issuer"]:
        problems.append("not self-signed: give the root CA (or the whole chain), not ISE's own certificate")
    days = info.get("days_left")
    if isinstance(days, int | float) and days < 0:
        problems.append("expired")
    elif isinstance(days, int | float) and days < 30:
        # Still valid: a warning, not a blocker (renewing the CA is a separate job).
        warnings.append(f"expires in {int(days)} days: renew it and run this tool again before then")
    out["ok"] = not problems
    if problems:
        out["problems"] = problems
    if warnings:
        out["warnings"] = warnings
    return out


# Stored certificate fields a PUT must send again: the Manager's PUT replaces the whole IseServer record, so
# leaving them out could clear a stored certificate (W41 review).
CERT_FIELDS = {"iseRootCert": "iseCertName", "pxGridRootCert": "pxGridCertName"}


def keep_stored_certs(wanted: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Copy the stored root certificates (and their names) into a PUT body that gives none; the fields
    kept."""
    kept = []
    for cert, name in CERT_FIELDS.items():
        if cert not in wanted and isinstance(current.get(cert), str) and current[cert]:
            wanted[cert] = current[cert]
            kept.append(cert)
            if current.get(name) and name not in wanted:
                wanted[name] = current[name]
    return kept


def is_host(value: str) -> bool:
    """An IPv4/IPv6 address or a DNS name (ise.example.com)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    return len(value) <= 253 and all(_LABEL.fullmatch(lb) for lb in labels) and not labels[-1].isdigit()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def connectivity_hints(vpn: int, host: str) -> list[str]:
    """What to check when the Manager answers REST0002 'TestConnectivity failed' on /ise/credentials (seen
    on 20.18.3.1 with ISE reachable on 443/9060 in the VPN): the suspects, most likely first."""
    hints = []
    if is_ip(host):
        hints.append(
            f"ISE was named by IP ({host}); ISE's admin certificate names its host name: try ise_host=<the "
            f"FQDN in that certificate> (the Manager must resolve it in VPN {vpn})"
        )
    hints += [
        "the ISE login (CATSDWAN_ISE_USERNAME) needs the ERS Admin role on ISE, with ERS enabled "
        "(ise_status shows ERS)",
        "ise_root_cert must be the CA that signed ISE's Admin certificate on 443/9060 (it can be ISE's own "
        "self-signed one); pxGrid's chain goes in pxgrid_root_cert when it differs (ise_pxgrid_status)",
        f"catsdwan_ping from the Manager to {host} in VPN {vpn} (tcp 443 and 9060)",
    ]
    return hints


def first_value(body: Any, *keys: str) -> Any:
    data = data_of(body)
    if isinstance(data, list):
        data = next((d for d in data if isinstance(d, dict)), {})
    if isinstance(data, dict):
        for k in keys:
            if data.get(k) not in (None, ""):
                return data[k]
    return None
