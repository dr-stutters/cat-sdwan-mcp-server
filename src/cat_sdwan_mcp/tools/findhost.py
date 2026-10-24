"""W44 find a host: catsdwan_find_host (read)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.devicestate import ROUTES_IOSXE_PATH, ROUTES_VIPTELA_PATH, platform_of
from cat_sdwan_mcp.fabric import device_rows, fan_out, host_map, reachable, site_ips
from cat_sdwan_mcp.findhost import (
    ARP_PATH,
    BRIDGE_MAC_PATH,
    OMP_RECEIVED_PATH,
    TRANSPORT_VPNS,
    connected_route,
    match_arp,
    match_bridge,
    omp_routes_for,
    omp_summary,
    parse_host,
    service_first,
)
from cat_sdwan_mcp.inventory import load_inventory, resolve

DETAIL_EDGES = 5  # edges whose routes (and MAC table) are read to name the subnet of a hit


def _internal(vpn: Any) -> bool:
    s = str(vpn or "")
    return s.startswith("__") or s in ("65528", "65529", "65530")


def _where(row: dict[str, Any]) -> dict[str, Any]:
    out = {
        "edge": row.get("host") or row.get("system_ip"),
        "system_ip": row.get("system_ip"),
        "site_id": row.get("site_id"),
        "site_name": row.get("site_name"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


async def _routes(app: SdwanApp, row: dict[str, Any]) -> list[dict[str, Any]]:
    ip = str(row["system_ip"])
    primary, fallback = (
        (ROUTES_IOSXE_PATH, ROUTES_VIPTELA_PATH)
        if platform_of(row) == "iosxe"
        else (ROUTES_VIPTELA_PATH, ROUTES_IOSXE_PATH)
    )
    rows = await device_rows(app, primary, ip)
    return rows or await device_rows(app, fallback, ip)


def _err(e: UpstreamError) -> str:
    return str(e)[:200]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Find a host on the SD-WAN fabric")
    async def catsdwan_find_host(
        ctx: Context,
        host: Annotated[
            str,
            Field(
                description="The host's IP address (10.61.100.10) or MAC address (aa:bb:cc:dd:ee:ff, "
                "aa-bb-..., aabb.ccdd.eeff)"
            ),
        ],
        site: Annotated[
            str | None,
            Field(description="Only read the edges at this site (site id or name); default every edge"),
        ] = None,
        vpn: Annotated[
            int | None, Field(ge=0, le=65535, description="Only this VPN (10 ...); default every VPN")
        ] = None,
        seen_from: Annotated[
            str | None,
            Field(
                description="The edge whose OMP table names the advertising route when the host is in no "
                "ARP table (host name or system IP); default the first edge read"
            ),
        ] = None,
        max_edges: Annotated[
            int, Field(ge=1, le=100, description="Read at most this many reachable edges (real-time reads)")
        ] = 25,
    ) -> dict[str, Any]:
        """Where a host sits on the fabric, from an IP or a MAC: the edge, its site, the VPN, the interface
        and MAC (the edges' live ARP tables, plus the MAC tables where an edge has switchports), the
        connected subnet it falls in, when the entry was last refreshed, and the OMP route that advertises
        it to the fabric (originating edge, site, TLOC colours, chosen/installed flags). A host in no ARP
        table (silent, or behind a router at the site) is located by the OMP route that covers it ('learned'
        rather than 'local'). Answers 'which branch is 10.61.200.15 at?' and 'where is this MAC?' before
        catsdwan_explain_path, catsdwan_routes or an ISE session lookup. Reads every reachable edge (or one
        site's) in real time, four at a time; `max_edges` caps it."""
        try:
            kind, value = parse_host(host)
        except ValueError as e:
            raise InvalidRequest(f"{e}. Give an IP address or a MAC address.") from None
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        edges = sorted(reachable(inv, "edge"), key=lambda r: str(r.get("host") or r.get("system_ip")))
        if site:
            ips = site_ips(inv, site)
            edges = [r for r in edges if str(r.get("system_ip")) in ips]
            if not edges:
                raise InvalidRequest(f"No reachable WAN edge at site {site!r}: nothing to read in real time.")
        if not edges:
            raise InvalidRequest("No reachable WAN edge: real-time ARP tables come over control connections.")
        read, skipped = edges[:max_edges], edges[max_edges:]
        unreachable = sorted(
            str(r.get("host") or r.get("system_ip"))
            for r in inv.rows
            if r.get("role") == "edge" and r not in reachable(inv, "edge")
        )
        errors: list[str] = []

        arp = await fan_out(read, lambda r: device_rows(app, ARP_PATH, str(r["system_ip"])))
        hits: list[dict[str, Any]] = []
        for row, res in zip(read, arp, strict=True):
            if isinstance(res, UpstreamError):
                errors.append(f"{row.get('host')}: ARP read failed: {_err(res)}")
                continue
            hits += [{**_where(row), **h} for h in match_arp(res, kind, value)]
        if kind == "mac":
            bridge = await fan_out(read, lambda r: device_rows(app, BRIDGE_MAC_PATH, str(r["system_ip"])))
            for row, res in zip(read, bridge, strict=True):
                if isinstance(res, UpstreamError):
                    errors.append(f"{row.get('host')}: MAC table read failed: {_err(res)}")
                    continue
                hits += [{**_where(row), **h} for h in match_bridge(res, value)]
        hits = [h for h in hits if not _internal(h.get("vpn"))]
        if vpn is not None:
            hits = [h for h in hits if "vpn" not in h or str(h["vpn"]) == str(vpn)]
        hits.sort(key=service_first)

        by_ip = {str(r["system_ip"]): r for r in read}
        address = value if kind == "ip" else next((str(h["address"]) for h in hits if h.get("address")), None)

        # The subnet each hit falls in (the edge's connected route), and the switchport behind a routed port.
        hit_edges = dict.fromkeys(str(h["system_ip"]) for h in hits if h.get("address"))
        detail_edges = list(hit_edges)[:DETAIL_EDGES]
        route_tables: dict[str, list[dict[str, Any]]] = {}
        got = await fan_out([by_ip[i] for i in detail_edges], lambda r: _routes(app, r))
        for ip, res in zip(detail_edges, got, strict=True):
            if isinstance(res, UpstreamError):
                errors.append(f"{hosts.get(ip, ip)}: route read failed: {_err(res)}")
            else:
                route_tables[ip] = res
        for h in hits:
            if not h.get("address") or str(h["system_ip"]) not in route_tables:
                continue
            r = connected_route(route_tables[str(h["system_ip"])], str(h["address"]), h.get("vpn"))
            if r:
                h["subnet"] = r.get("prefix")
                h["route_protocol"] = r.get("protocol")
                h["local"] = r.get("protocol") in ("direct", "connected")
        if kind == "ip":
            service = [h for h in hits if str(h.get("vpn")) not in TRANSPORT_VPNS and h.get("mac")]
            for h in service[:1]:
                try:
                    rows = await device_rows(app, BRIDGE_MAC_PATH, str(h["system_ip"]))
                except UpstreamError as e:
                    errors.append(f"{h.get('edge')}: MAC table read failed: {_err(e)}")
                    continue
                ports = match_bridge(rows, str(h["mac"]))
                if ports:
                    h["switchport"] = ports[0].get("interface")
                    if ports[0].get("vlan"):
                        h["vlan"] = ports[0]["vlan"]

        # The OMP route that carries it to the fabric.
        primary = hits[0] if hits else None
        omp: dict[str, Any] | None = None
        omp_vpn = (
            str(vpn)
            if vpn is not None
            else (str(primary["vpn"]) if primary and primary.get("vpn") is not None else None)
        )
        if address and omp_vpn not in TRANSPORT_VPNS:
            if primary:
                ref_row = by_ip[str(primary["system_ip"])]
            elif seen_from:
                ref_row = resolve(inv, seen_from)
                if ref_row not in reachable(inv):
                    raise InvalidRequest(f"seen_from={seen_from!r} is not a reachable device.")
            else:
                ref_row = read[0]
            try:
                omp_rows = await device_rows(app, OMP_RECEIVED_PATH, str(ref_row["system_ip"]))
                routes = omp_routes_for(omp_rows, address, omp_vpn, hosts)
                omp = {"seen_from": ref_row.get("host") or ref_row.get("system_ip")}
                if routes:
                    omp |= {"route": omp_summary(routes), "paths": routes[:20]}
                else:
                    omp["route"] = None
                    omp["note"] = "no OMP route covers it: the fabric can't reach it from this edge"
            except UpstreamError as e:
                errors.append(f"{ref_row.get('host')}: OMP read failed: {_err(e)}")

        # Not in any ARP table: locate it by the advertising edge's connected route.
        if not hits and omp and omp.get("route"):
            route = omp["route"]
            origin = str(route.get("originator") or "")
            origin_row = next((r for r in inv.rows if str(r.get("system_ip")) == origin), None)
            learned: dict[str, Any] = {
                **(_where(origin_row) if origin_row else {"edge": origin}),
                "vpn": route.get("vpn"),
                "subnet": route.get("prefix"),
                "route_protocol": route.get("protocol"),
                "local": False,
                "seen_in": f"omp (from {omp['seen_from']})",
            }
            if origin_row and origin_row in reachable(inv, "edge") and address:
                try:
                    r = connected_route(await _routes(app, origin_row), address, route.get("vpn"))
                    if r and r.get("interface"):
                        learned["interface"] = r["interface"]
                except UpstreamError as e:
                    errors.append(f"{origin_row.get('host')}: route read failed: {_err(e)}")
            hits = [learned]

        out: dict[str, Any] = {"query": value, "kind": kind, "found": bool(hits)}
        out["verdict"] = _verdict(value, hits, omp)
        out["locations"] = hits
        if omp:
            out["omp"] = omp
        searched: dict[str, Any] = {"edges": [r.get("host") or r.get("system_ip") for r in read]}
        if skipped:
            searched["not_read"] = f"{len(skipped)} more edge(s) past max_edges={max_edges}: " + ", ".join(
                str(r.get("host")) for r in skipped[:20]
            )
        if unreachable and not site:
            searched["unreachable"] = unreachable
        if errors:
            searched["errors"] = errors
        out["searched"] = searched
        return out


def _verdict(value: str, hits: list[dict[str, Any]], omp: dict[str, Any] | None) -> str:
    if not hits:
        return (
            f"{value} is in no ARP or MAC table on the edges read and no OMP route covers it: not on the "
            "fabric (or behind an edge that wasn't read)"
        )
    h = hits[0]
    where = f"{h.get('edge')} (site {h.get('site_id', '?')})"
    vpn = str(h.get("vpn", "?"))
    vpn_txt = f"transport VPN {vpn}" if vpn in TRANSPORT_VPNS else f"VPN {vpn}"
    if str(h.get("seen_in", "")).startswith("omp"):
        line = f"{value} is behind {where} in {vpn_txt} per OMP ({h.get('subnet')}"
        line += f" on {h['interface']})" if h.get("interface") else ")"
        line += "; it is in no ARP table read (silent, or behind a router at the site)"
    elif h.get("entry") == "the edge's own address":
        line = f"{value} is {h.get('edge')}'s own address on {h.get('interface')} in {vpn_txt}"
    else:
        line = f"{value} is behind {where} in {vpn_txt} on {h.get('interface') or h.get('switchport')}"
        bits = [b for b in (h.get("address"), h.get("mac")) if b and b != value]
        if bits:
            line += f" ({', '.join(bits)})"
        if h.get("last_seen"):
            line += f", ARP refreshed {h['last_seen']}"
    route = (omp or {}).get("route")
    if route and not str(h.get("seen_in", "")).startswith("omp"):
        colours = ", ".join(route.get("colours") or []) or "no TLOC colour"
        line += (
            f"; advertised to the fabric by {route.get('advertised_by')} as {route.get('prefix')} "
            f"({route.get('protocol')}) over {colours}"
        )
    others = {str(x.get("edge")) for x in hits[1:]} - {str(h.get("edge"))}
    if others:
        line += f". Also seen on {', '.join(sorted(others))}"
    return line
