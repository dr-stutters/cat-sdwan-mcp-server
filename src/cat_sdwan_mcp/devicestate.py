"""Device state reads (W18): routes and a catalogue of the Manager's other real-time tables.

Every read is GET /dataservice/device/<what>?deviceId=<system-ip> (real time, over the control connection).
Recorded on 20.18.3.1 against br1 (a C8000V, IOS XE): /device/ip/ipRoutes answers the RIB of every VRF
(routing-instance-name 'default' = VPN 0, 'Mgmt-intf' = VPN 512, a number = that service VPN; OMP routes are
route-source-protocol 'rt-ext:omp' with the remote edge's system IP as next hop); /device/ip/routetable (the
Viptela OS table: vpn-id, prefix, protocol, nexthop-addr, ip, color, encap) answers an empty list;
/device/ip/fib answers 400 DEV0001 'Invalid data type IPFib' (a Viptela OS table). /device/arp,
/hardware/inventory, /policer, /ip/nat/interfacestatistics, /sdwan-global-drop-statistics and /featurelist
have rows; most other tables are empty on the lab (no BGP, OSPF, DHCP, VRRP or NAT configured).
/device/cdp/neighbors and /lldp/neighbors take no deviceId: one row per edge with its neighbours nested.
/device/featurelist lists the Manager-facing capabilities of the device (tools, admin-tech-options,
enterprise-csr, ...), not its monitoring tables, so it can't say which table a platform lacks: the catalogue
says that itself (`platform`), and a 'DEV0001 Invalid data type' answer is reported as 'not on this platform'.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from cat_sdwan_mcp.client import _as_list

ROUTES_IOSXE_PATH = "/dataservice/device/ip/ipRoutes"
ROUTES_VIPTELA_PATH = "/dataservice/device/ip/routetable"
FIB_PATH = "/dataservice/device/ip/fib"
BGP_SUMMARY_PATH = "/dataservice/device/bgp/summary"
BGP_NEIGHBORS_PATH = "/dataservice/device/bgp/neighbors"
BGP_ROUTES_PATH = "/dataservice/device/bgp/routes"
OSPF_NEIGHBOR_PATH = "/dataservice/device/ospf/neighbor"
OSPF_ROUTES_PATH = "/dataservice/device/ospf/routes"
OSPF_DATABASE_PATH = "/dataservice/device/ospf/database"
EIGRP_ROUTE_PATH = "/dataservice/device/eigrp/route"
EIGRP_INTERFACE_PATH = "/dataservice/device/eigrp/interface"
FEATURELIST_PATH = "/dataservice/device/featurelist"

META = {"vdevice-dataKey", "vdevice-name", "vdevice-host-name", "lastupdated"}
VRF_VPN = {"default": "0", "mgmt-intf": "512"}
UNSUPPORTED = re.compile(r"invalid data type|DEV0001", re.I)


@dataclass(frozen=True)
class Table:
    label: str
    path: str
    fleet: bool = False  # no deviceId: one row per device, filtered by local-system-ip
    nested: str | None = None  # the key holding the rows inside a fleet row


@dataclass(frozen=True)
class Feature:
    answers: str
    tables: tuple[Table, ...]
    nonzero: bool = False  # counters: keep only the non-zero ones
    platform: str | None = None  # "viptela": Viptela OS devices only (not IOS XE edges)
    keep: tuple[str, ...] = field(default_factory=tuple)  # the fields shown (empty = every field)


def _t(label: str, rel: str, **kw: Any) -> Table:
    return Table(label, "/dataservice/device/" + rel, **kw)


CATALOGUE: dict[str, Feature] = {
    "arp": Feature(
        "ARP entries: address, MAC, interface, VPN, dynamic or static",
        (_t("arp", "arp"),),
        keep=("vpn-id", "address", "hardware", "interface", "mode", "time"),
    ),
    "dhcp": Feature(
        "DHCP: the device as a client (leases it got), as a server (pools and leases) and per interface",
        (_t("client", "dhcp/client"), _t("server", "dhcp/server"), _t("interface", "dhcp/interface")),
    ),
    "vrrp": Feature(
        "VRRP groups: interface, group, state (master/backup/init), priority, virtual IP and MAC, OMP state "
        "(a split brain shows two masters)",
        (_t("vrrp", "vrrp"),),
    ),
    "nat": Feature(
        "NAT translations and NAT interface statistics (hits, misses, drops)",
        (_t("translations", "ip/nat/translation"), _t("statistics", "ip/nat/interfacestatistics")),
        nonzero=True,
    ),
    "interface_errors": Feature(
        "Per-interface error, queue and port counters (drops, CRC, overruns)",
        (
            _t("errors", "interface/error_stats"),
            _t("queues", "interface/queue_stats"),
            _t("ports", "interface/port_stats"),
        ),
        nonzero=True,
    ),
    "hardware": Feature(
        "Hardware: environment (temperature, fans, power), hardware alarms and the inventory (chassis, "
        "modules, part and serial numbers)",
        (
            _t("environment", "hardware/environment"),
            _t("alarms", "hardware/alarms"),
            _t("inventory", "hardware/inventory"),
        ),
    ),
    "crash_log": Feature("Crash logs on the device (time, core file, reason)", (_t("crashes", "crashlog"),)),
    "ntp": Feature(
        "NTP associations and status (synchronised or not, stratum, offset)",
        (_t("associations", "ntp/associations"), _t("status", "ntp/status")),
    ),
    "lacp": Feature(
        "Port channels (LACP): channel groups and their members",
        (_t("channels", "lacp/info"), _t("members", "lacp/members")),
    ),
    "cdp": Feature(
        "CDP neighbours (device, port, platform)",
        (_t("neighbours", "cdp/neighbors", fleet=True, nested="cdp"),),
    ),
    "lldp": Feature(
        "LLDP neighbours (device, port, capabilities)",
        (_t("neighbours", "lldp/neighbors", fleet=True, nested="lldp"),),
    ),
    "trackers": Feature(
        "Static-route and endpoint trackers (up or down, latency)",
        (_t("static_route", "staticRouteTracker"), _t("endpoint", "endpointTracker")),
    ),
    "license": Feature(
        "Smart licence usage and registration as the edge sees them",
        (_t("usage", "license/usage"), _t("registration", "license/registration")),
    ),
    "aaa": Feature(
        "Local users, AAA servers, logged-in sessions and logging servers",
        (
            _t("users", "aaa/users"),
            _t("servers", "aaa/servers"),
            _t("sessions", "users"),
            _t("logging", "logging"),
        ),
    ),
    "sdwan_drops": Feature(
        "The data plane's global drop counters (why packets were dropped: no adjacency, TTL exceeded, ACL, "
        "policy, IPsec, ...); only the non-zero ones",
        (_t("drops", "sdwan-global-drop-statistics"),),
        nonzero=True,
    ),
    "qos": Feature(
        "QoS: per-tunnel QoS sessions and per-interface queue statistics",
        (_t("sessions", "qos/session/summary"), _t("queues", "interface/queue_stats")),
        nonzero=True,
    ),
    "policer": Feature("Policers: rate, burst, conformed and exceeded packets", (_t("policers", "policer"),)),
    "fib": Feature(
        "The forwarding table (prefix, next hop, TLOC, colour)",
        (_t("fib", "ip/fib"),),
        platform="viptela",
    ),
}


def suggest(name: str) -> str:
    close = difflib.get_close_matches(name.strip().lower(), list(CATALOGUE), n=3, cutoff=0.5)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    return f"No device state feature {name!r}.{hint} feature='list' lists them."


def catalogue_rows() -> list[dict[str, Any]]:
    out = []
    for name, f in CATALOGUE.items():
        row = {
            "feature": name,
            "answers": f.answers,
            "reads": ", ".join(t.path.removeprefix("/dataservice") for t in f.tables),
        }
        if f.platform:
            row["platform"] = "Viptela OS devices only (not IOS XE edges)"
        out.append(row)
    return out


def platform_of(row: dict[str, Any]) -> str:
    """'iosxe' for IOS XE SD-WAN edges (C8000V, ISR, ASR, ...), 'viptela' for Viptela OS edges and the
    controllers (device-os 'next')."""
    os_ = str(row.get("device_os") or "").lower()
    if os_:
        return "iosxe" if "ios" in os_ else "viptela"
    model = str(row.get("model") or "").lower()
    if row.get("role") in ("controller", "validator", "manager"):
        return "viptela"
    if re.match(r"vedge-(c\d|isr|asr|ir|csr|c8|cat)", model):
        return "iosxe"
    return "viptela"


def is_unsupported(error: Exception) -> bool:
    return bool(UNSUPPORTED.search(str(error)))


def _drop_zero(v: Any) -> bool:
    return str(v).strip() in ("0", "0.0", "")


def clean(row: dict[str, Any], *, nonzero: bool = False, keep: tuple[str, ...] = ()) -> dict[str, Any]:
    out = {}
    for k, v in row.items():
        if k in META or v in (None, "", [], {}):
            continue
        if keep and k not in keep:
            continue
        if nonzero and _drop_zero(v) and k not in ("vpn-id", "ifname", "if-name", "af-type"):
            continue
        out[k] = v
    return out


def fleet_rows(rows: list[dict[str, Any]], system_ip: str, nested: str | None) -> list[dict[str, Any]]:
    """The device's neighbours from a fleet-wide table (one row per edge, neighbours nested)."""
    out: list[dict[str, Any]] = []
    for r in rows:
        if str(r.get("local-system-ip") or r.get("system-ip")) != system_ip:
            continue
        inner = r.get(nested) if nested else None
        if isinstance(inner, dict):
            inner = inner.get("neighbors", inner.get("neighbours"))
        out.extend(x for x in _as_list(inner) if isinstance(x, dict))
    return out


# --- routes ----------------------------------------------------------------------------------------


def _vpn(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return VRF_VPN.get(s.lower(), s)


def _protocol(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    return s.removeprefix("rt-ext:") or None


def route_row(r: dict[str, Any], hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """A route from either table, in one shape: vpn, prefix, protocol, next hop (the remote edge's host name
    for an OMP route), interface, colour, preference, metric."""
    hosts = hosts or {}
    if "route-destination-prefix" in r:  # IOS XE /ip/ipRoutes
        nh = r.get("next-hop-next-hop-address-list") or r.get("next-hop-next-hop-address")
        row = {
            "vpn": _vpn(r.get("routing-instance-name")),
            "prefix": r.get("route-destination-prefix"),
            "protocol": _protocol(r.get("route-source-protocol")),
            "next_hop": None if nh == "0.0.0.0" else nh,
            "interface": r.get("next-hop-outgoing-interface"),
            "preference": r.get("route-route-preference"),
            "metric": r.get("route-metric"),
            "family": r.get("rib-address-family"),
        }
    else:  # Viptela OS /ip/routetable
        row = {
            "vpn": _vpn(r.get("vpn-id")),
            "prefix": r.get("prefix"),
            "protocol": _protocol(r.get("protocol")),
            "next_hop": r.get("nexthop-addr") or r.get("ip"),
            "interface": r.get("nexthop-ifname"),
            "colour": r.get("color"),
            "encap": r.get("encap"),
            "status": r.get("rstatus"),
            "family": r.get("address-family"),
        }
    if row.get("protocol") == "omp" and isinstance(row.get("next_hop"), str):
        names = [hosts.get(x.strip(), x.strip()) for x in str(row["next_hop"]).split(",")]
        row["via_edge"] = ", ".join(names)
    return {k: v for k, v in row.items() if v not in (None, "", "0.0.0.0")}


def internal_vrf(row: dict[str, Any]) -> bool:
    """The platform's own VRFs (__Platform_iVRF, 65528/65529 loopbacks): not the operator's."""
    vpn = str(row.get("vpn") or "")
    return vpn.startswith("__") or vpn in ("65528", "65529", "65530")


def neighbour_row(kind: str, r: dict[str, Any]) -> dict[str, Any]:
    if kind == "bgp":
        row = {
            "protocol": "bgp",
            "vpn": _vpn(r.get("vpn-id")),
            "peer": r.get("peer-addr"),
            "as": r.get("as"),
            "state": r.get("state"),
            "afi": r.get("afi"),
            "messages_in": r.get("msg-rcvd"),
            "messages_out": r.get("msg-sent"),
        }
    elif kind == "ospf":
        row = {
            "protocol": "ospf",
            "vpn": _vpn(r.get("vpn-id")),
            "neighbour": r.get("neighbor-id") or r.get("router-id"),
            "address": r.get("if-addr") or r.get("address"),
            "interface": r.get("if-name") or r.get("interface"),
            "state": r.get("neighbor-state") or r.get("state"),
            "instance": r.get("instance-id"),
        }
    else:
        row = {"protocol": kind, **clean(r)}
    return {k: v for k, v in row.items() if v not in (None, "")}


def neighbour_up(row: dict[str, Any]) -> bool:
    return str(row.get("state") or "").lower() in ("established", "full", "up")
