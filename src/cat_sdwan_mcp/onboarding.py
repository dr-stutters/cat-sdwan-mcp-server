"""Edge onboarding (W9): the WAN edge list, the one-time token, bootstrap configuration and validity.

Pure helpers; the tools are in tools/onboarding.py. Sources (recorded on 20.18.3.1 unless marked):
- GET /dataservice/system/device/vedges: one row per WAN edge slot from the serial file: chasisNumber [sic],
  uuid (= the chassis, 'C8K-...' for a C8000V), serialNumber, validity valid|invalid|staging,
  vedgeCertificateState (tokengenerated, bootstrapconfiggenerated, csrgenerated, certinstalled, ...),
  hardwareVedge, deviceModel, uploadSource; a joined edge also has host-name, system-ip, site-id and the
  organization-name of its certificate. For a software edge that has not joined, serialNumber is the ONE-TIME
  TOKEN the Manager minted at upload: a secret, masked everywhere here except where a tool hands it over.
- POST /dataservice/system/device/fileupload (multipart: `file`, form `validity=valid`, `upload=true`):
  uploads a signed serial file; 20.18.3 accepted 25 C8000V entries marked isSdwanCapable N (recorded).
  Answers {vedgeListUploadStatus, vedgeListUploadMsg, activityList, id} (spec example).
- POST /dataservice/system/device/smartaccount/sync {username, password, validity_string}: the other way in
  (Smart Account), answers {processId} (spec example; not used by a tool yet).
- GET /dataservice/system/device/bootstrap/device/{uuid}?configtype=cloudinit&inclDefRootCert=false ->
  {"bootstrapConfig": "#cloud-config\\nvinitparam:\\n - uuid : <chassis>\\n - otp : <token>\\n - vbond :
  <validator>\\n - org : <org>\\n - rcc : true\\nca-certs: ..."} (recorded). configtype=encodedstring gives
  the same as one encoded string (Cisco's documented value; not recorded yet).
- POST /dataservice/certificate/save/vedge/list [{chasisNumber, serialNumber, validity}] then
  POST /dataservice/certificate/vedge/list?action=push -> {id} (an action: "Send to Controllers"), the
  validity change as the GUI makes it (Cisco's documented flow; bodies not recorded yet).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any

import httpx

from cat_sdwan_mcp._core import InvalidRequest, NotFound
from cat_sdwan_mcp.client import _as_list

FILEUPLOAD_PATH = "/dataservice/system/device/fileupload"
SMART_SYNC_PATH = "/dataservice/system/device/smartaccount/sync"
BOOTSTRAP_PATH = "/dataservice/system/device/bootstrap/device/{id}"
SAVE_VALIDITY_PATH = "/dataservice/certificate/save/vedge/list"
PUSH_VEDGES_PATH = "/dataservice/certificate/vedge/list"

MASK = "********"
MAX_SERIAL_FILE = 4 * 1024 * 1024  # bytes; a serial file for a few thousand edges is well under this

CONFIG_TYPES = {"cloud-init": "cloudinit", "encoded": "encodedstring"}

WAYS_IN = (
    "Two ways in, both write tier: upload the signed serial file from Cisco Plug and Play (PnP) "
    f"(POST {FILEUPLOAD_PATH}, multipart `file` with validity=valid and upload=true; "
    "catsdwan_onboard_edge(serial_file=...) does it as its first step), or sync the Smart Account "
    f"(POST {SMART_SYNC_PATH} with the Smart Account credentials, through catsdwan_api_call)."
)

ACTIVATE_COMMAND = (
    "request platform software sdwan vedge_cloud activate chassis-number {chassis} token {token}"
)

# vedgeCertificateState values that mean the edge never got (or lost) its certificate.
FAILED_CERT_STATES = {
    "csrfailed": "the edge's certificate signing request failed",
    "certinstallfailed": "installing the edge's certificate failed",
}
TOKEN_STATES = {"tokengenerated", "bootstrapconfiggenerated"}


# --- the WAN edge list ---------------------------------------------------------------------------


def chassis_of(v: dict[str, Any]) -> str:
    return str(v.get("chasisNumber") or v.get("chassisNumber") or v.get("uuid") or "")


def is_joined(v: dict[str, Any]) -> bool:
    """Whether the edge has joined: it has a system IP and a host name, or an installed certificate."""
    state = str(v.get("vedgeCertificateState") or "").lower()
    return bool(v.get("system-ip") and v.get("host-name")) or state == "certinstalled"


def holds_token(v: dict[str, Any]) -> bool:
    """Whether serialNumber is the one-time token: a software edge (hardwareVedge false) that has not joined,
    or any edge whose certificate state says a token was generated."""
    state = str(v.get("vedgeCertificateState") or "").lower()
    if state in TOKEN_STATES:
        return True
    return v.get("hardwareVedge") is False and not is_joined(v)


def token_of(v: dict[str, Any]) -> str | None:
    if not holds_token(v):
        return None
    tok = str(v.get("serialNumber") or "").strip()
    return tok if tok and tok.upper() != "NA" else None


def manager_org(controllers: list[dict[str, Any]] | None) -> str | None:
    """The overlay's organization name, from the controllers' certificate records."""
    for c in controllers or []:
        for k in ("organization-name", "org", "sp-organization-name"):
            if c.get(k) not in (None, "", "NA"):
                return str(c[k])
    return None


def edge_row(v: dict[str, Any], org: str | None = None) -> dict[str, Any]:
    """One WAN edge slot as the tools show it: the token masked, never the value."""
    joined = is_joined(v)
    row: dict[str, Any] = {
        "chassis": chassis_of(v),
        "host": v.get("host-name"),
        "system_ip": v.get("system-ip"),
        "site_id": v.get("site-id") or v.get("configuredSiteId"),
        "model": v.get("deviceModel"),
        "kind": "hardware" if v.get("hardwareVedge") else "software",
        "validity": v.get("validity"),
        "joined": joined,
        "certificate_state": v.get("vedgeCertificateState"),
        "org": v.get("organization-name"),
        "upload_source": v.get("uploadSource"),
        "managed_by": v.get("managed-by"),
        "reachability": v.get("reachability") if joined else "not joined",
    }
    if holds_token(v):
        row["token"] = MASK if token_of(v) else None
    else:
        row["serial"] = v.get("serialNumber")
    if v.get("expirationDate") not in (None, "", "NA"):
        row["certificate_expires"] = v.get("expirationDate")
    if joined and org and row.get("org") and str(row["org"]) != org:
        row["org_mismatch"] = f"certificate org {row['org']!r}, overlay org {org!r}"
    if (state := str(v.get("vedgeCertificateState") or "").lower()) in FAILED_CERT_STATES:
        row["problem"] = FAILED_CERT_STATES[state]
    return {k: x for k, x in row.items() if x not in (None, "", [])}


def matches_state(row: dict[str, Any], state: str | None) -> bool:
    if not state:
        return True
    if state == "joined":
        return bool(row.get("joined"))
    if state == "not_joined":
        return not row.get("joined")
    return str(row.get("validity", "")).lower() == state


def find_edge(vedges: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    """A WAN edge slot by chassis number, host name or system IP (exact, case-insensitive). Never by the
    token: it is a secret and not an identifier."""
    want = ref.strip().lower()
    if not want:
        raise InvalidRequest("Give the edge's chassis number (e.g. C8K-...), host name or system IP.")
    for v in vedges:
        keys = {chassis_of(v), v.get("uuid"), v.get("host-name"), v.get("system-ip")}
        if want in {str(k).lower() for k in keys if k}:
            return v
    return None


def edge_or_not_found(vedges: list[dict[str, Any]], ref: str) -> dict[str, Any]:
    v = find_edge(vedges, ref)
    if v is None:
        raise NotFound(f"{ref!r} is not in the Manager's WAN edge list (catsdwan_list_wan_edges). {WAYS_IN}")
    return v


def protected_row(v: dict[str, Any], host: str | None = None, system_ip: str | None = None) -> dict[str, Any]:
    """The keys tier_reasons() checks (host, system IP, chassis, site) for an edge slot."""
    out = {
        "host": host or v.get("host-name"),
        "system_ip": system_ip or v.get("system-ip"),
        "chassis": chassis_of(v),
        "site_id": v.get("site-id") or v.get("configuredSiteId"),
        "site_name": v.get("site-name"),
    }
    return {k: x for k, x in out.items() if x not in (None, "")}


# --- bootstrap -----------------------------------------------------------------------------------

_OTP_RE = re.compile(r"(?im)^(\s*-?\s*otp\s*:\s*)(\S+)")
_PARAM_RE = re.compile(r"(?im)^\s*-\s*([a-z][a-z0-9_-]*)\s*:\s*(.*?)\s*$")


def mask_otp(text: str, token: str | None = None) -> str:
    """The bootstrap text with its otp line (and the token wherever else it appears) masked."""
    out = _OTP_RE.sub(lambda m: m.group(1) + MASK, text)
    if token:
        out = out.replace(token, MASK)
    return out


def vinit_params(text: str) -> dict[str, str]:
    """{uuid, otp, vbond, org, rcc, ...} from the cloud-init `vinitparam` list."""
    out: dict[str, str] = {}
    block = text.split("vinitparam:", 1)
    if len(block) < 2:
        return out
    for line in block[1].splitlines()[1:]:
        if line.strip() and not line.lstrip().startswith("-"):
            break
        if m := _PARAM_RE.match(line):
            out.setdefault(m.group(1).lower(), m.group(2))
    return out


def decode_bootstrap(value: str) -> str | None:
    """The text inside an encoded bootstrap (base64), or None when it isn't base64 text."""
    try:
        raw = base64.b64decode(value.strip(), validate=True)
        return raw.decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def bootstrap_text(body: Any) -> str | None:
    if isinstance(body, dict):
        for k in ("bootstrapConfig", "config", "data"):
            if isinstance(body.get(k), str) and body[k].strip():
                return str(body[k])
    if isinstance(body, str) and body.strip():
        return body
    return None


def activate_command(chassis: str, token: str | None = None) -> str:
    return ACTIVATE_COMMAND.format(chassis=chassis, token=token or "<token>")


def boot_routes(chassis: str) -> list[str]:
    """How a software edge (C8000V) uses its chassis and token, for the operator."""
    return [
        f"At first boot: catsdwan_bootstrap_config(chassis={chassis!r}) gives the cloud-init day-0 (uuid, "
        "otp, validator, org); boot the edge with it (in CML: the node's day-0 configuration in "
        "cml_build_lab). Day-0 needs SOME uuid/otp in vinitparam, or the image boots in autonomous mode.",
        "On a running edge (already in controller mode): run the exec command `"
        + activate_command(chassis)
        + "` with the token from catsdwan_bootstrap_config(reveal_otp=true).",
        "Either way the edge then needs to reach the validator on UDP 12346; watch "
        f"catsdwan_control_connections(device={chassis!r}) for it to come up.",
    ]


# --- inputs --------------------------------------------------------------------------------------


def check_system_ip(value: str) -> str:
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError as e:
        raise InvalidRequest(f"system_ip {value!r} is not an IPv4 address.") from e
    return str(ip)


def serial_file_body(name: str, data: bytes) -> tuple[bytes, str]:
    """(body, Content-Type) of the serial-file upload: multipart `file` plus validity=valid, upload=true
    (upload=true also sends the list to the controllers)."""
    req = httpx.Request(
        "POST",
        "https://manager.invalid" + FILEUPLOAD_PATH,
        files={"file": (name, data, "application/octet-stream")},
        data={"validity": "valid", "upload": "true"},
    )
    return req.read(), req.headers["Content-Type"]


def upload_summary(body: Any) -> dict[str, Any]:
    """The upload answer without the uploaded (chassis, serial/token) pairs it lists."""
    if not isinstance(body, dict):
        return {"answer": "the Manager returned no upload summary"}
    out = {
        "upload_status": body.get("vedgeListUploadStatus"),
        "message": body.get("vedgeListUploadMsg"),
        "id": body.get("id"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def validity_payload(v: dict[str, Any], validity: str) -> list[dict[str, Any]]:
    return [{"chasisNumber": chassis_of(v), "serialNumber": v.get("serialNumber"), "validity": validity}]


# Names tried in a device template's input for each onboarding value (match_variable compares the last path
# segment, so '//system/host-name' matches 'host-name').
TEMPLATE_KEYS = {
    "hostname": ("host-name", "hostname", "host_name"),
    "system_ip": ("system-ip", "system_ip"),
    "site_id": ("site-id", "site_id"),
}
# The same values in a configuration group's system profile variables (recorded: host_name, system_ip,
# site_id).
GROUP_KEYS = {"hostname": "host_name", "system_ip": "system_ip", "site_id": "site_id"}


def rows_of(body: Any) -> list[dict[str, Any]]:
    rows = body.get("data") if isinstance(body, dict) else body
    return [r for r in _as_list(rows) if isinstance(r, dict)]
