"""Find a host on the fabric (W44): which edge, site, VPN and interface an IP or MAC sits behind, and the OMP
route that advertises it.

Recorded on 20.18.3.1 (C8000V edges, IOS XE 17.18): /device/arp?deviceId= answers every VRF's ARP table
(vpn-id 'Default' = VPN 0, 'Mgmt-intf' = VPN 512, a number = that service VPN; mode
'ios-arp-mode-dynamic' = learned, '...-interface' = the edge's own address, '...-static'; `time` = when the
entry was last refreshed; the 65528/65529 VRFs answer stub rows without an address). /device/bridge/mac
(bridge-id, if-name, mac-address, interface, vlan, type) answers an empty list on a routed C8000V: it only has
rows on edges with switchports (ISR with an L2 module). /device/omp/routes/received on an edge lists its own
prefixes too (status 'C Red R', protocol 'connected') next to the other edges' ('C I R'), each per TLOC
colour; /omp/routes/advertised carries no colour, so the received table is the one read.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cat_sdwan_mcp.control import status_meaning
from cat_sdwan_mcp.devicestate import route_row

ARP_PATH = "/dataservice/device/arp"
BRIDGE_MAC_PATH = "/dataservice/device/bridge/mac"
OMP_RECEIVED_PATH = "/dataservice/device/omp/routes/received"
TRANSPORT_VPNS = ("0", "512")
ARP_VPN = {"default": "0", "mgmt-intf": "512"}
ENTRY = {"dynamic": "learned (dynamic)", "interface": "the edge's own address", "static": "static"}
_HEX = re.compile(r"[^0-9a-f]")


def parse_host(value: str) -> tuple[str, str]:
    """('ip', '10.1.2.3') or ('mac', 'aa:bb:cc:dd:ee:ff') from an address in any common notation
    (aa:bb:..., aa-bb-..., aabb.ccdd.eeff); ValueError otherwise."""
    s = value.strip()
    try:
        return "ip", str(ipaddress.ip_address(s))
    except ValueError:
        pass
    hexed = _HEX.sub("", s.lower())
    if len(hexed) == 12 and re.fullmatch(r"[0-9a-f:.\-\s]+", s.lower()):
        return "mac", ":".join(hexed[i : i + 2] for i in range(0, 12, 2))
    raise ValueError(f"{value!r} is neither an IP address nor a MAC address")


def norm_mac(v: Any) -> str | None:
    hexed = _HEX.sub("", str(v or "").lower())
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)) if len(hexed) == 12 else None


def arp_vpn(v: Any) -> str:
    s = str(v or "").strip()
    return ARP_VPN.get(s.lower(), s)


def _entry(mode: Any) -> str | None:
    m = str(mode or "").lower().removeprefix("ios-arp-mode-")
    return ENTRY.get(m, m or None)


def arp_hit(r: dict[str, Any]) -> dict[str, Any]:
    """An ARP row as a location: VPN, address, MAC, interface, entry kind, last refreshed."""
    row = {
        "vpn": arp_vpn(r.get("vpn-id")),
        "address": r.get("address"),
        "mac": norm_mac(r.get("hardware")),
        "interface": r.get("interface"),
        "entry": _entry(r.get("mode")),
        "last_seen": r.get("time"),
        "seen_in": "arp",
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def bridge_hit(r: dict[str, Any]) -> dict[str, Any]:
    row = {
        "mac": norm_mac(r.get("mac-address")),
        "interface": r.get("if-name") or r.get("interface"),
        "vlan": r.get("vlan"),
        "bridge": r.get("bridge-id"),
        "entry": str(r.get("type") or "").lower() or None,
        "seen_in": "mac table",
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def match_arp(rows: list[dict[str, Any]], kind: str, value: str) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if not r.get("address"):
            continue  # the platform VRFs' stub rows
        key = str(r.get("address")) if kind == "ip" else norm_mac(r.get("hardware"))
        if key == value:
            out.append(arp_hit(r))
    return out


def match_bridge(rows: list[dict[str, Any]], mac: str) -> list[dict[str, Any]]:
    return [bridge_hit(r) for r in rows if norm_mac(r.get("mac-address")) == mac]


def connected_route(routes: list[dict[str, Any]], address: str, vpn: str | None) -> dict[str, Any] | None:
    """The most specific route covering `address` in `vpn` (a normalised catsdwan_routes row), skipping the
    edge's own /32s that carry no interface."""
    best: tuple[int, dict[str, Any]] | None = None
    for raw in routes:
        r = route_row(raw)
        if vpn is not None and str(r.get("vpn")) != str(vpn):
            continue
        prefix = str(r.get("prefix") or "")
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if ipaddress.ip_address(address) not in net:
                continue
        except ValueError:
            continue
        if net.prefixlen == net.max_prefixlen and not r.get("interface"):
            continue
        if best is None or net.prefixlen > best[0]:
            best = (net.prefixlen, r)
    return best[1] if best else None


def omp_routes_for(
    rows: list[dict[str, Any]], address: str, vpn: str | None, hosts: dict[str, str]
) -> list[dict[str, Any]]:
    """The OMP routes covering `address` (most specific prefix only), one row per TLOC, chosen first."""
    found: list[tuple[int, dict[str, Any]]] = []
    for r in rows:
        if vpn is not None and str(r.get("vpn-id")) != str(vpn):
            continue
        prefix = str(r.get("prefix") or "")
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if ipaddress.ip_address(address) not in net:
                continue
        except ValueError:
            continue
        origin = str(r.get("originator") or "")
        colour = r.get("color") if r.get("color") not in (None, "", "None") else None
        row = {
            "vpn": r.get("vpn-id"),
            "prefix": prefix,
            "originator": origin or None,
            "originator_host": hosts.get(origin),
            "site_id": r.get("site-id"),
            "colour": colour,
            "tloc": " / ".join(
                str(r[k]) for k in ("ip", "color", "encap") if r.get(k) not in (None, "", "None")
            )
            or None,
            "protocol": r.get("protocol"),
            "status": r.get("status"),
            "meaning": status_meaning(r.get("status")),
            "preference": r.get("preference"),
        }
        found.append((net.prefixlen, {k: v for k, v in row.items() if v not in (None, "")}))
    if not found:
        return []
    longest = max(p for p, _ in found)
    best = [r for p, r in found if p == longest]
    return sorted(best, key=lambda r: ("C" not in str(r.get("status", "")).split(), str(r.get("tloc"))))


def omp_summary(routes: list[dict[str, Any]]) -> dict[str, Any] | None:
    """One line per (prefix, originator): who advertises it, from which site, over which colours."""
    if not routes:
        return None
    first = routes[0]
    colours = sorted({str(r["colour"]) for r in routes if r.get("colour")})
    chosen = [r for r in routes if "C" in str(r.get("status", "")).split()]
    return {
        "prefix": first.get("prefix"),
        "vpn": first.get("vpn"),
        "advertised_by": first.get("originator_host") or first.get("originator"),
        "originator": first.get("originator"),
        "site_id": first.get("site_id"),
        "protocol": first.get("protocol"),
        "colours": colours,
        "chosen_paths": len(chosen),
    }


def service_first(hit: dict[str, Any]) -> tuple[int, int, str]:
    """Order locations: service-VPN learned hosts first, the edges' own addresses and transport VPNs last."""
    transport = str(hit.get("vpn")) in TRANSPORT_VPNS
    own = hit.get("entry") == ENTRY["interface"]
    return (int(transport), int(own), str(hit.get("edge")))
