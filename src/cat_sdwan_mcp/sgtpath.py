"""W42 an SGT's path across the overlay: the source edge's IP-to-SGT binding, inline tagging on each tunnel to
the destination edge (sending and receiving interface), SXP or pxGrid as the fallback that carries the source
tag to the destination edge, and the destination edge's SGACL for the source/destination SGT pair.

Sources (real-time, per edge, recorded on 20.18.3.1 with no TrustSec configured):
- GET /dataservice/device/interface/trustsec?deviceId=: per interface `if-name`, `mode`
  (cts-ndac-mode-manual), `sgt-propagate` (cts-sgt-propagate-enabled / -disabled), `peer-sgt`, `trusted`
  (cts-manual-trusted / cts-manual-untrusted). br1 answers no rows (no `cts manual` anywhere); the row shape
  is the OpenAPI example's.
- GET /dataservice/device/bfd/sessions?deviceId=: the tunnels (local and remote colour, `src-ip`, `dst-ip`,
  remote `system-ip`, state); a tunnel's interfaces are the ones holding `src-ip` / `dst-ip` in
  GET /dataservice/device/interface (the WAN interface and its TunnelN share the address on a C8000V).
- W24's tables: /device/roleBasedSgtMap (IP-to-SGT, `source` = CLI, SXP, LOCAL, ...),
  /roleBasedPermissions + /roleBasedCounters (SGACLs per SGT pair), /sxpConnections, /environmentData.
"""

from __future__ import annotations

import ipaddress
from typing import Any

INTERFACE_TRUSTSEC_PATH = "/dataservice/device/interface/trustsec"


def _net(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def _sgt(v: Any) -> int | None:
    try:
        return int(str(v).split("(")[0].strip())
    except (TypeError, ValueError):
        return None


def binding_for(rows: list[dict[str, Any]], ip: str, vrf: str | None = None) -> dict[str, Any] | None:
    """The longest IP-to-SGT binding covering `ip` (in `vrf` when the row names one)."""
    addr = _net(ip)
    if addr is None:
        return None
    best: tuple[int, dict[str, Any]] | None = None
    for r in rows:
        net = _net(r.get("ip"))
        if net is None or net.version != addr.version or not addr.subnet_of(net):  # type: ignore[arg-type]
            continue
        if vrf and r.get("vrf-name") not in (None, "", vrf):
            continue
        if best is None or net.prefixlen > best[0]:
            best = (net.prefixlen, r)
    if best is None:
        return None
    r = best[1]
    out = {
        "binding": r.get("ip"),
        "sgt": _sgt(r.get("sgt")),
        "learned_from": r.get("source"),
        "vrf": r.get("vrf-name"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def interfaces_with(rows: list[dict[str, Any]], ip: Any) -> list[str]:
    """Interface names holding `ip` (a WAN interface and its TunnelN), physical first."""
    want = str(ip or "").split("/")[0]
    names = [
        str(r.get("ifname")) for r in rows if str(r.get("ip-address", "")).split("/")[0] == want and want
    ]
    return sorted(dict.fromkeys(names), key=lambda n: (n.lower().startswith("tunnel"), n))


def inline_state(ts_rows: list[dict[str, Any]], names: list[str]) -> dict[str, Any]:
    """`cts manual` on any of these interfaces: propagate (sends tags), trusted (keeps received tags)."""
    rows = [r for r in ts_rows if str(r.get("if-name")) in names]
    if not rows:
        return {"configured": False, "propagate": False, "trusted": False}
    propagate = any("enabled" in str(r.get("sgt-propagate", "")).lower() for r in rows)
    trusted = not any("untrusted" in str(r.get("trusted", "")).lower() for r in rows)
    out: dict[str, Any] = {
        "configured": True,
        "interface": rows[0].get("if-name"),
        "propagate": propagate,
        "trusted": trusted,
    }
    peer = rows[0].get("peer-sgt")
    if peer not in (None, ""):
        out["peer_sgt"] = peer
    return out


def tunnel_row(
    bfd: dict[str, Any],
    src_ifaces: list[dict[str, Any]],
    src_ts: list[dict[str, Any]],
    dst_ifaces: list[dict[str, Any]],
    dst_ts: list[dict[str, Any]],
) -> dict[str, Any]:
    """One tunnel: does it carry the SGT inline from the source edge into the destination edge?"""
    out_if = interfaces_with(src_ifaces, bfd.get("src-ip"))
    in_if = interfaces_with(dst_ifaces, bfd.get("dst-ip"))
    send = inline_state(src_ts, out_if)
    recv = inline_state(dst_ts, in_if)
    up = str(bfd.get("state", "")).lower() == "up"
    row: dict[str, Any] = {
        "tunnel": f"{bfd.get('local-color')} -> {bfd.get('color')}",
        "state": bfd.get("state"),
        "source_interface": out_if[0] if out_if else None,
        "destination_interface": in_if[0] if in_if else None,
        "sends_tag": send["propagate"],
        "keeps_tag": recv["configured"] and recv["trusted"],
    }
    reasons = []
    if not up:
        reasons.append("tunnel is not up")
    if not send["configured"]:
        reasons.append(f"no `cts manual` on {_names(out_if)} at the source edge (inline tagging off)")
    elif not send["propagate"]:
        reasons.append(f"`propagate sgt` is off on {send.get('interface')} at the source edge")
    if not in_if:
        reasons.append(f"no destination interface holds {bfd.get('dst-ip')} (NAT?): its tagging is not known")
    elif not recv["configured"]:
        reasons.append(f"no `cts manual` on {_names(in_if)} at the destination edge (the tag is not read)")
    elif not recv["trusted"]:
        reasons.append(
            f"{recv.get('interface')} at the destination edge is untrusted: received tags are replaced by "
            f"peer SGT {recv.get('peer_sgt', 0)}"
        )
    row["carries_tag"] = up and not reasons
    if reasons:
        row["why_not"] = reasons
    return {k: v for k, v in row.items() if v is not None}


def _names(names: list[str]) -> str:
    return "/".join(names) if names else "the tunnel's interface"


def policy_for(
    perms: list[dict[str, Any]], counters: list[dict[str, Any]], src: int, dst: int
) -> dict[str, Any] | None:
    """The SGACL(s) the destination edge holds for src -> dst, with permit/deny counters."""
    rows = [r for r in perms if _sgt(r.get("src-sgt")) == src and _sgt(r.get("dst-sgt")) == dst]
    if not rows:
        return None
    count = next((c for c in counters if _sgt(c.get("src-sgt")) == src and _sgt(c.get("dst-sgt")) == dst), {})
    acls = [str(r.get("sgacl-name")) for r in rows if r.get("sgacl-name")]
    out: dict[str, Any] = {
        "sgacls": acls,
        "monitor_mode": rows[0].get("monitor-mode"),
        "permitted": count.get("total-permit-count"),
        "denied": count.get("total-deny-count"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}
