"""Control plane (W3): control connections and their failed attempts, OMP peers, OMP routes and TLOCs.

Sources (recorded on 20.18.3.1 unless marked):
- GET /dataservice/device/control/connections?deviceId=: one row per peer and local colour (`peer-type`
  vsmart|vbond|vmanage|vedge, `system-ip` = the peer's, `peer-host-name`, `local-color`, `remote-color`,
  `protocol` dtls|tls, `state`, `uptime`, `uptime-date`, public/private ip and port).
- GET /dataservice/device/control/summary?deviceId= (not recorded): counts per peer type.
- GET /dataservice/device/control/connectionshistory?deviceId= (not recorded): failed and torn-down
  connections with the local and remote error codes (`local_enum`, `remote_enum`, their `-desc`), the time
  and a repeat count. Field names are read leniently until a payload is recorded.
- A real-time read of a device the Manager has lost (powered off, its transport down) answers 400 DEV0001
  'Device data error: System IP <ip> is not connected to vmanage' (seen on 20.18.3, issue #103), often
  before /device marks it unreachable.
- GET /dataservice/data/device/state/ControlConnection (not recorded; bulk, 48/min): the same rows for every
  device from the Manager's state database, paged with `pageInfo.startId/endId/moreEntries`.
- GET /dataservice/device/omp/peers?deviceId=: `peer`, `type`, `state`, `site-id`, `up-time(-date)`.
- GET /dataservice/device/omp/routes/received?deviceId= (and /advertised, not recorded): `vpn-id`, `prefix`,
  `ip` + `color` + `encap` (the TLOC), `originator`, `from-peer`, `status` ("C I R"), `preference`.
- GET /dataservice/device/omp/tlocs/received?deviceId=: `ip`, `color`, `encap`, `tloc-public-ip/port`,
  `tloc-private-ip/port`, `site-id`, `bfd-status`, `preference`, `weight`, `originator`.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from cat_sdwan_mcp.client import ROLE
from cat_sdwan_mcp.inventory import iso

CONNECTIONS_PATH = "/dataservice/device/control/connections"
SUMMARY_PATH = "/dataservice/device/control/summary"
HISTORY_PATH = "/dataservice/device/control/connectionshistory"
BULK_CONTROL = "ControlConnection"
OMP_PEERS_PATH = "/dataservice/device/omp/peers"
OMP_ROUTES_PATH = "/dataservice/device/omp/routes/{direction}"
OMP_TLOCS_PATH = "/dataservice/device/omp/tlocs/received"

# vdaemon error codes (show sdwan control connection-history), in plain words. The validator also reports
# them in events as ERR_<NAME> (`reason=ERR_BID_NOT_VERIFIED`); KEYWORDS below catches those.
REASONS = {
    "BIDNTVRFD": "the peer's chassis/serial is not verified: not in the WAN edge list, marked invalid, or "
    "the list was not sent to the validator",
    "BIDNTPR": "the board ID (chassis certificate) is not initialised on the device",
    "SERNTPRES": "the serial number is not in the WAN edge list (upload or sync the serial file)",
    "CTORGNMMIS": "the certificate's organisation name does not match the fabric's organisation name",
    "CRTVERFL": "the peer certificate failed verification (wrong or missing root CA, or clock skew: a "
    "certificate that is not yet valid)",
    "CRTREJSER": "the peer rejected the challenge (certificate serial not authorised on the controllers)",
    "CERTEXPRD": "the certificate has expired",
    "VECRTREV": "the edge's certificate was revoked (invalidated on the Manager)",
    "VSCRTREV": "the controller's certificate was revoked",
    "NOSLPRCRT": "the peer's certificate could not be read",
    "DCONFAIL": "DTLS connection failure: the peer is unreachable on UDP 12346+ (routing, NAT or ACL)",
    "DHSTMO": "DTLS handshake timed out (packet loss, MTU or a firewall on the transport)",
    "HAFAIL": "TLS/DTLS handshake failure",
    "NOACTVB": "no active validator to connect to (validator address or DNS)",
    "DUPSER": "duplicate serial number: another device uses the same chassis/serial",
    "DUPSYSIPDEL": "duplicate system IP: another device uses the same system IP",
    "SYSIPCHNG": "the system IP changed",
    "SYSPRCH": "a system property (site id, organisation, system IP) changed",
    "DISTLOC": "the TLOC (transport interface) is disabled",
    "RXTRDWN": "the peer tore the connection down",
    "VM_TMO": "the Manager stopped answering hellos (timed out)",
    "VS_TMO": "the controller stopped answering hellos (timed out)",
    "VB_TMO": "the validator stopped answering hellos (timed out)",
    "VP_TMO": "the edge stopped answering hellos (timed out)",
    "ORPTMO": "the peer timed out",
    "XTVMTRDN": "teardown of an extra Manager connection (normal)",
    "XTVSTRDN": "teardown of an extra controller connection (normal)",
    "DISCVBD": "disconnected from the validator after registration (normal)",
    "STNMODETD": "teardown of an extra validator connection in STUN mode (normal)",
    "MGRTBLCKD": "migration blocked",
    "UNAUTHEL": "hello from an unauthenticated peer",
    "TUNALC": "tunnel allocation failure on the device (memory)",
    "MEMALCFL": "memory allocation failure on the device",
}
KEYWORDS = (
    ("BID_NOT_VERIFIED", "BIDNTVRFD"),
    ("SERIAL_NOT_PRESENT", "SERNTPRES"),
    ("SER_NOT_PRESENT", "SERNTPRES"),
    ("ORG", "CTORGNMMIS"),
    ("EXPIRED", "CERTEXPRD"),
    ("REVOKED", "VECRTREV"),
    ("CERT", "CRTVERFL"),
    ("DTLS", "DCONFAIL"),
    ("TIMEOUT", "ORPTMO"),
    ("DUP_SERIAL", "DUPSER"),
    ("DUP_SYSTEM_IP", "DUPSYSIPDEL"),
)
NORMAL_CODES = {"NOERR", "XTVMTRDN", "XTVSTRDN", "DISCVBD", "STNMODETD", ""}
# The Manager's answer when it has no control connection to the device it is asked to read.
NOT_CONNECTED = re.compile(r"not connected to v?manage|DEV0001", re.I)

# OMP route status flags (show sdwan omp routes).
FLAGS = {
    "C": "chosen",
    "I": "installed",
    "Red": "redistributed",
    "Rej": "rejected",
    "L": "looped",
    "R": "resolved",
    "S": "stale",
    "Ext": "extranet",
    "Inv": "invalid",
    "Stg": "staged",
    "IA": "on-demand inactive",
    "U": "TLOC unresolved",
    "BR-R": "border-router reoriginated",
    "TGW-R": "transport-gateway reoriginated",
}


def _first(rec: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", "None", "NA", "N/A"):
            return v
    return None


def _endpoint(ip: Any, port: Any) -> str | None:
    if not ip or ip in ("::", "0.0.0.0"):
        return None
    return f"{ip}:{port}" if port not in (None, "", 0, "0") else str(ip)


def role(v: Any) -> Any:
    return ROLE.get(str(v), v) if v else None


def clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v not in (None, "", [], "None", "N/A", "NA")}


# --- control connections -------------------------------------------------------------------------


def connection_row(c: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    peer_ip = c.get("system-ip")
    return clean(
        {
            "host": c.get("vdevice-host-name") or (hosts or {}).get(str(c.get("vdevice-name"))),
            "system_ip": c.get("vdevice-name"),
            "peer": c.get("peer-host-name") or (hosts or {}).get(str(peer_ip)),
            "peer_type": role(c.get("peer-type")),
            "peer_system_ip": peer_ip,
            "site_id": c.get("site-id"),
            "local_colour": c.get("local-color"),
            "remote_colour": c.get("remote-color"),
            "protocol": c.get("protocol"),
            "state": c.get("state"),
            "uptime": c.get("uptime"),
            "up_since": iso(c.get("uptime-date")),
            "public": _endpoint(c.get("public-ip"), c.get("public-port")),
            "private": _endpoint(c.get("private-ip"), c.get("private-port")),
            "behind_proxy": c.get("behind-proxy") if c.get("behind-proxy") not in (None, "No") else None,
        }
    )


def explain(code: Any, desc: Any = None) -> str | None:
    """A vdaemon error code (BIDNTVRFD or ERR_BID_NOT_VERIFIED) in plain words, else the Manager's text."""
    raw = str(code or "").strip()
    key = raw.upper()
    if key in NORMAL_CODES:
        return None
    text = REASONS.get(key)
    if text is None:
        bare = key.removeprefix("ERR_")
        text = REASONS.get(bare) or next((REASONS[target] for word, target in KEYWORDS if word in bare), None)
    detail = str(desc).strip() if desc not in (None, "", "None") else None
    if text and detail and detail.lower() not in text.lower():
        return f"{raw}: {text} ({detail})"
    if text:
        return f"{raw}: {text}"
    return f"{raw}: {detail}" if detail else raw


def history_row(h: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """One connection-history record: who, when, how often, and both sides' error codes in plain words."""
    local = _first(h, "local_enum", "local-enum", "localEnum")
    remote = _first(h, "remote_enum", "remote-enum", "remoteEnum")
    local_desc = _first(h, "local_enum_desc", "local-enum-desc", "localEnumDesc")
    remote_desc = _first(h, "remote_enum_desc", "remote-enum-desc", "remoteEnumDesc")
    reasons = [r for r in (explain(local, local_desc), explain(remote, remote_desc)) if r]
    peer_ip = _first(h, "system-ip", "peer-system-ip")
    when = _first(h, "downtime-date", "downtime_date", "lastupdated")
    return clean(
        {
            "host": h.get("vdevice-host-name") or (hosts or {}).get(str(h.get("vdevice-name"))),
            "system_ip": h.get("vdevice-name"),
            "peer": h.get("peer-host-name") or (hosts or {}).get(str(peer_ip)),
            "peer_type": role(h.get("peer-type")),
            "peer_system_ip": peer_ip if peer_ip not in ("::", "0.0.0.0") else None,
            "site_id": h.get("site-id"),
            "local_colour": h.get("local-color"),
            "remote_colour": h.get("remote-color"),
            "public": _endpoint(h.get("public-ip"), h.get("public-port")),
            "state": h.get("state"),
            "time": iso(when) or _first(h, "downtime"),
            "repeats": _first(h, "rep-count", "repeat-count", "rep_count"),
            "local_error": local,
            "remote_error": remote,
            "reason": "; ".join(dict.fromkeys(reasons)) or None,
        }
    )


def failed_attempts(rows: list[dict[str, Any]], keep: int = 25) -> list[dict[str, Any]]:
    """History rows that carry an error (normal teardowns dropped), newest first."""
    out = [r for r in rows if r.get("reason")]
    out.sort(key=lambda r: str(r.get("time") or ""), reverse=True)
    return out[:keep]


def now() -> datetime:
    """The current time (a function so tests can pin it)."""
    return datetime.now(UTC)


def _when(v: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def within(rows: list[dict[str, Any]], hours: int) -> tuple[list[dict[str, Any]], int]:
    """The rows whose `time` is in the last `hours` hours (rows without a readable time are kept), and how
    many older rows were dropped."""
    cutoff = now() - timedelta(hours=hours)
    kept = []
    for r in rows:
        t = _when(r.get("time"))
        if t is None or t >= cutoff:
            kept.append(r)
    return kept, len(rows) - len(kept)


def about(rows: list[dict[str, Any]], system_ip: Any, chassis: Any) -> list[dict[str, Any]]:
    """The history or rejection rows naming this device (by peer system IP or chassis)."""
    ip = str(system_ip or "").strip()
    ch = str(chassis or "").strip().lower()
    return [
        r
        for r in rows
        if (ip and str(r.get("peer_system_ip") or "") == ip)
        or (ch and str(r.get("chassis") or "").lower() == ch)
    ]


def last_known(raw: list[dict[str, Any]], system_ip: str) -> list[dict[str, Any]]:
    """State-database ControlConnection records about one device: its own last report, and its peers' rows
    for it (a controller's row towards the edge shows when that side went down)."""
    return [r for r in raw if system_ip in (str(r.get("vdevice-name") or ""), str(r.get("system-ip") or ""))]


def is_up(row: dict[str, Any]) -> bool:
    return str(row.get("state", "")).lower() == "up"


def sort_connections(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {"controller": 0, "manager": 1, "validator": 2, "edge": 3}
    return sorted(
        rows,
        key=lambda r: (
            is_up(r),
            str(r.get("host") or ""),
            order.get(str(r.get("peer_type")), 9),
            str(r.get("peer") or r.get("peer_system_ip") or ""),
            str(r.get("local_colour") or ""),
        ),
    )


def per_device(rows: list[dict[str, Any]]) -> list[str]:
    """'host: 2/3 up' for every device with a connection that is not up."""
    total: Counter[str] = Counter()
    up: Counter[str] = Counter()
    for r in rows:
        name = str(r.get("host") or r.get("system_ip"))
        total[name] += 1
        up[name] += is_up(r)
    return [f"{n}: {up[n]}/{total[n]} up" for n in sorted(total) if up[n] < total[n]]


def summary_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """device/control/summary (shape not recorded): its first record without the device keys."""
    if not rows:
        return None
    return clean(
        {k: v for k, v in rows[0].items() if not str(k).startswith("vdevice") and k != "lastupdated"}
    )


# --- OMP -----------------------------------------------------------------------------------------


def peer_row(p: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    peer = p.get("peer")
    return clean(
        {
            "host": p.get("vdevice-host-name"),
            "peer": peer,
            "peer_host": (hosts or {}).get(str(peer)),
            "peer_type": role(p.get("type")),
            "site_id": p.get("site-id"),
            "region_id": p.get("region-id"),
            "state": p.get("state"),
            "uptime": p.get("up-time"),
            "up_since": iso(p.get("up-time-date")),
            "routes_received": _first(p, "routes-received", "route-received"),
            "routes_installed": _first(p, "routes-installed", "route-installed"),
            "routes_sent": _first(p, "routes-sent", "route-sent"),
            "legit": p.get("legit"),
        }
    )


def status_meaning(status: Any) -> str | None:
    words = [FLAGS.get(f, f) for f in str(status or "").split()]
    return ", ".join(words) or None


def _tloc(r: dict[str, Any]) -> str | None:
    parts = [str(r[k]) for k in ("ip", "color", "encap") if r.get(k) not in (None, "", "None")]
    return " / ".join(parts) or None


def route_row(r: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    origin = r.get("originator")
    return clean(
        {
            "vpn": r.get("vpn-id"),
            "prefix": r.get("prefix"),
            "originator": origin,
            "originator_host": (hosts or {}).get(str(origin)),
            "tloc": _tloc(r),
            "status": r.get("status"),
            "meaning": status_meaning(r.get("status")),
            "protocol": r.get("protocol"),
            "site_id": r.get("site-id"),
            "from_peer": r.get("from-peer"),
            "to_peer": r.get("to-peer"),
            "preference": r.get("preference"),
            "label": r.get("label"),
        }
    )


def _net(v: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(v), strict=False)
    except ValueError:
        return None


def prefix_matches(route_prefix: Any, want: str) -> bool:
    """True when the route's prefix and `want` (a prefix or an address) overlap; text match otherwise."""
    a, b = _net(route_prefix), _net(want)
    if a is None or b is None or a.version != b.version:
        return str(want).strip() in str(route_prefix)
    return a.subnet_of(b) or b.subnet_of(a)  # type: ignore[arg-type]


def sort_routes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(r: dict[str, Any]) -> tuple[Any, ...]:
        net = _net(r.get("prefix"))
        vpn = str(r.get("vpn", ""))
        return (
            int(vpn) if vpn.isdigit() else 0,
            (net.version, int(net.network_address), net.prefixlen) if net else (9, 0, 0),
            "C" not in str(r.get("status", "")).split(),
            str(r.get("tloc") or ""),
        )

    return sorted(rows, key=key)


def tloc_row(t: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    ip = t.get("ip")
    return clean(
        {
            "system_ip": ip,
            "host": (hosts or {}).get(str(ip)),
            "colour": t.get("color"),
            "encap": t.get("encap"),
            "site_id": t.get("site-id"),
            "public": _endpoint(t.get("tloc-public-ip"), t.get("tloc-public-port")),
            "private": _endpoint(t.get("tloc-private-ip"), t.get("tloc-private-port")),
            "bfd_status": t.get("bfd-status"),
            "preference": t.get("preference"),
            "weight": t.get("weight"),
            "encryption": t.get("tloc-encrypt-type"),
            "from_peer": t.get("from-peer"),
            "address_family": t.get("address-family"),
        }
    )
