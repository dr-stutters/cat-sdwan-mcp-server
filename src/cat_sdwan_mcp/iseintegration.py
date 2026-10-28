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
are empty'.

The GUI's own request (captured on 20.18.3.1, Wave 8, single-tenant Manager, Add Connection): POST
/ise/credentials with every IseServer field present and every value a string, "" when empty, booleans
as "true"/"false"; `destinationVpn` and `vpnIpSubnet` are "" (only a multi-tenant Manager with VPN 512 fills
them).
The POST itself runs TestConnectivity and stores nothing when it fails (no separate /ise/connect). The GUI
accepts only an IP address for the ISE server ('Use valid IP Address') and only a user name matching
/^[a-zA-Z0-9]+$/ ('Enter valid user name'). server_body sends exactly that shape.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
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
# destinationVpn/vpnIpSubnet are left out: the single-tenant GUI always sends them as "".
COMPARED = (
    "iseServerIP",
    "vpn",
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
        elif k in ("iseRootCert", "pxGridRootCert") and isinstance(v, str) and v:
            out[k] = describe_pem(v) or "(not a PEM certificate)"
        else:
            out[k] = v
    return out


def flag(v: bool) -> str:
    return "true" if v else "false"


# The GUI's POST /ise/credentials body, in its order: every field is sent, "" when empty.
GUI_FIELDS = (
    "iseServerIP",
    "userName",
    "password",
    "vpn",
    "userAndUserGroup",
    "activeDirectoryDomain",
    "joinPoint",
    "sgt",
    "vpnIpSubnet",
    "destinationVpn",
    "iseRootCert",
    "iseCertName",
    "pxGridRootCert",
    "pxGridCertName",
)
# The certificate names the body carries when a root certificate is given (the GUI sends the uploaded file's
# name; the Manager only stores it as a label).
CERT_NAMES = {"iseCertName": "ise-root-ca.pem", "pxGridCertName": "pxgrid-root-ca.pem"}
# The 20.18 GUI's user-name rule for the ISE login (Add Connection: 'Enter valid user name').
USERNAME_RE = re.compile(r"^[a-zA-Z0-9]+$")
# The pxGrid client's description in POST /ise/pxgrid/activate. Plain words only: the Manager relays it
# to ISE's pxGrid AccountActivate, whose XSS filter refuses parentheses with HTTP 400 (20.18.3.1 log:
# 'FastPathXssVerification: XSS script match found', then ISEERRORR0014). Live 2026-10-25: this one activated.
PXGRID_DESCRIPTION = "Catalyst SD-WAN Manager"


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
    """The IseServer body exactly as the 20.18 GUI sends it: all GUI_FIELDS, strings only, "" when empty."""
    px_cert = pxgrid_root_cert or root_cert or ""
    values = {
        "iseServerIP": ise_host,
        "userName": username,
        "password": password,
        "vpn": str(vpn),
        "userAndUserGroup": flag(subscribe_users),
        "activeDirectoryDomain": ad_domain or "",
        "joinPoint": join_point or "",
        "sgt": flag(subscribe_sgt),
        "vpnIpSubnet": "",
        "destinationVpn": "",
        "iseRootCert": root_cert or "",
        "iseCertName": CERT_NAMES["iseCertName"] if root_cert else "",
        "pxGridRootCert": px_cert,
        "pxGridCertName": CERT_NAMES["pxGridCertName"] if px_cert else "",
    }
    return {k: values[k] for k in GUI_FIELDS}


def username_problem(user: str) -> str | None:
    """Why the Manager's GUI would refuse this ISE login name, or None."""
    if USERNAME_RE.fullmatch(user):
        return None
    return (
        f"the ISE login CATSDWAN_ISE_USERNAME {user!r} does not match the Manager's rule /^[a-zA-Z0-9]+$/ "
        "(letters and digits only; the 20.18 GUI refuses it with 'Enter valid user name'): create an "
        "alphanumeric ERS admin account on ISE (ise_create_internal_user, ERS Admin group) and set "
        "CATSDWAN_ISE_USERNAME to it"
    )


def differences(current: dict[str, Any], wanted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{field: {from, to}} for the compared fields that differ (missing counts as '')."""
    out = {}
    for k in COMPARED:
        a, b = str(current.get(k, "") or ""), str(wanted.get(k, "") or "")
        if a.lower() != b.lower():
            out[k] = {"from": current.get(k), "to": wanted.get(k)}
    return out


def pxgrid_raw(rec: dict[str, Any]) -> str:
    """The Manager's own pxGrid status text, `status` first, then `accountState` ("" when neither)."""
    return str(rec.get("status") or rec.get("accountState") or "").strip()


# The controller-push states the 20.18.3.1 Manager writes into the pxGrid record's `status` once the
# Manager approved its client and POST /ise/credentials/vsmart/sync ran (live 2026-10-25, #131):
# 'vSmart push is pending' -> 'vSmart push is successful' (or '... failed').
_PUSH_PREFIX = "vsmart push"


def pxgrid_push(rec: dict[str, Any]) -> str | None:
    """pending / successful / failed / unknown for a 'vSmart push is ...' status; None for any other."""
    raw = pxgrid_raw(rec).lower()
    if not raw.startswith(_PUSH_PREFIX):
        return None
    if "fail" in raw or "error" in raw:
        return "failed"
    if "success" in raw:
        return "successful"
    if "pending" in raw or "progress" in raw:
        return "pending"
    return "unknown"


def pxgrid_state(rec: dict[str, Any]) -> str:
    """The pxGrid account's state from its record, `status` read before `accountState`:

    - none: no record; created: a record with no status yet (create ran, activate did not)
    - activated: POST /ise/pxgrid/activate ran; the Manager's own PUT /ise/pxgrid/approve is still due
    - pending: waits for approval on ISE (activate answered PENDING)
    - enabled: approved (ENABLED; 'Approved' right after PUT /ise/pxgrid/approve, before the controller sync
      task starts, #148), or any 'vSmart push is ...' status (pxgrid_push says how the controller sync went)
    - disabled: the client is disabled on ISE
    - unknown: a status this server does not know (pxgrid_raw has the text)
    """
    if not rec:
        return "none"
    raw = pxgrid_raw(rec).lower()
    if not raw:
        return "created"
    if raw.startswith(_PUSH_PREFIX):
        return "enabled" if pxgrid_push(rec) != "unknown" else "unknown"
    if raw == "activated":
        return "activated"
    if raw == "approved":
        return "enabled"
    for s in ("disabled", "enabled", "pending"):
        if s in raw:
            return s
    return "unknown"


def node_name_of(rec: dict[str, Any]) -> str | None:
    """The pxGrid client name ISE lists: `pxGridUserName` first. After the approve, 20.18.3.1 puts ISE's own
    pxGrid node ('~ise-admin-ise') in `nodeName` (#148), so a '~' name there is never the client."""
    v = rec.get("pxGridUserName")
    if not v:
        n = str(rec.get("nodeName") or "")
        v = n if n and not n.startswith("~") else None
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
        if not wanted.get(cert) and isinstance(current.get(cert), str) and current[cert]:
            wanted[cert] = current[cert]
            kept.append(cert)
            wanted[name] = str(current.get(name) or wanted.get(name) or CERT_NAMES[name])
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


async def resolve_ip(host: str) -> str | None:
    """The first address this MCP server's own resolver gives for a host name (IPv4 first), None if none.
    The Manager's GUI takes only an IP for ISE, so a name is resolved here and the preview says so."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None
    addrs = [str(i[4][0]) for i in infos if i and i[4]]
    v4 = [a for a in addrs if ":" not in a]
    picked = v4 or addrs
    return picked[0] if picked else None


def connectivity_hints(vpn: int, host: str) -> list[str]:
    """What to check when the Manager answers REST0002 'Test Connectivity failed' on /ise/credentials (seen
    on 20.18.3.1 with ISE reachable on 443/9060 in the VPN, and with the GUI's own request and a wrong
    password): the suspects, most likely first. The Manager tests the login over ERS, so a wrong password
    and a missing role look the same as a network problem."""
    return [
        "the ISE login (CATSDWAN_ISE_USERNAME / _PASSWORD) must log in to ISE's ERS API: an ERS Admin "
        "account with ERS enabled (ise_status shows ERS), the password current",
        "ise_root_cert must be the CA that signed ISE's Admin certificate on 443/9060 (it can be ISE's own "
        "self-signed one); pxGrid's chain goes in pxgrid_root_cert when it differs (ise_pxgrid_status)",
        f"catsdwan_ping from the Manager to {host} in VPN {vpn} (tcp 443 and 9060)",
    ]


def first_value(body: Any, *keys: str) -> Any:
    data = data_of(body)
    if isinstance(data, list):
        data = next((d for d in data if isinstance(d, dict)), {})
    if isinstance(data, dict):
        for k in keys:
            if data.get(k) not in (None, ""):
                return data[k]
    return None
