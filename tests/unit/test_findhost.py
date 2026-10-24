"""W44: catsdwan_find_host on recorded real-time tables (20.18.3.1, C8000V edges).

Recorded 2026-10-24: hub1's and br2's ARP tables (hub1 has a host 10.61.100.10 learned on Gi3 in VPN 10;
br2 has only its own addresses in VPN 10), hub1's empty bridge MAC table (a routed C8000V has no
switchports), hub1's received OMP routes (its own 10.61.100.0/24 'C Red R' next to br1's and br2's 'C I R',
per colour) and br1's ARP table from W18. hub1's and br2's RIBs are in the /ip/ipRoutes shape, VPN 0 and 10.
"""

from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import findhost as fh

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

DEV = "/dataservice/device"
EMPTY = {"data": []}
IPS = {"hub1": "10.0.0.1", "br1": "10.0.0.2", "br2": "10.0.0.3"}


def mock_edges(api: respx.MockRouter, **overrides: Any) -> dict[str, Any]:
    """Per-edge ARP, routes, MAC table and OMP; returns the ARP routes by host for call counting."""
    tables = {
        "arp": {
            "hub1": fixture("devstate_arp_hub1"),
            "br1": fixture("devstate_arp_br1"),
            "br2": fixture("devstate_arp_br2"),
        },
        "ip/ipRoutes": {
            "hub1": fixture("devstate_ip_iproutes_hub1"),
            "br1": fixture("devstate_ip_iproutes_br1"),
            "br2": fixture("devstate_ip_iproutes_br2"),
        },
        "bridge/mac": {h: fixture("devstate_bridge_mac_hub1") for h in IPS},
        "omp/routes/received": {h: fixture("device_omp_routes_received_hub1") for h in IPS},
    }
    for rel, per in overrides.items():
        tables[rel].update(per)
    routes: dict[str, Any] = {}
    for rel, per in tables.items():
        for host, body in per.items():
            route = api.get(f"{DEV}/{rel}", params={"deviceId": IPS[host]})
            if isinstance(body, int):
                route.respond(body, json={"error": {"message": "Server error"}})
            else:
                route.respond(json=body)
            if rel == "arp":
                routes[host] = route
    api.get(f"{DEV}/ip/routetable").respond(json=EMPTY)
    return routes


async def run(args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool("catsdwan_find_host", args)
    return result.structured_content


# --- helpers -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("10.61.100.10", ("ip", "10.61.100.10")),
        (" 2001:db8::1 ", ("ip", "2001:db8::1")),
        ("52:54:00:F8:04:F0", ("mac", "52:54:00:f8:04:f0")),
        ("52-54-00-f8-04-f0", ("mac", "52:54:00:f8:04:f0")),
        ("5254.00f8.04f0", ("mac", "52:54:00:f8:04:f0")),
    ],
)
def test_parse_host(value: str, want: tuple[str, str]) -> None:
    assert fh.parse_host(value) == want


def test_parse_host_refuses_names() -> None:
    with pytest.raises(ValueError, match="neither"):
        fh.parse_host("printer-1")


def test_match_arp_skips_platform_stubs() -> None:
    rows = fixture("devstate_arp_hub1")["data"]
    hit = fh.match_arp(rows, "ip", "10.61.100.10")
    assert hit == [
        {
            "vpn": "10",
            "address": "10.61.100.10",
            "mac": "52:54:00:f8:04:f0",
            "interface": "GigabitEthernet3",
            "entry": "learned (dynamic)",
            "last_seen": "2026-10-24T01:14:29.505+00:00",
            "seen_in": "arp",
        }
    ]
    assert fh.match_arp(rows, "mac", "00:50:56:00:00:01")[0]["vpn"] == "512"
    assert all(h.get("address") for h in fh.match_arp(rows, "mac", "52:54:00:bd:37:bf"))


def test_omp_routes_for_a_host_behind_br2() -> None:
    rows = fixture("device_omp_routes_received_hub1")["data"]
    routes = fh.omp_routes_for(rows, "10.61.201.15", "10", {"10.0.0.3": "br2"})
    assert {r["colour"] for r in routes if r.get("colour")} == {"mpls", "biz-internet"}
    assert routes[0]["meaning"] == "chosen, installed, resolved" and routes[0]["originator_host"] == "br2"
    summary = fh.omp_summary(routes)
    assert summary == {
        "prefix": "10.61.201.0/24",
        "vpn": "10",
        "advertised_by": "br2",
        "originator": "10.0.0.3",
        "site_id": "201",
        "protocol": "connected",
        "colours": ["biz-internet", "mpls"],
        "chosen_paths": 2,
    }
    assert fh.omp_routes_for(rows, "10.99.0.1", None, {}) == []


def test_connected_route_skips_own_host_routes() -> None:
    rows = fixture("devstate_ip_iproutes_hub1")["data"]
    assert fh.connected_route(rows, "10.61.100.1", "10")["prefix"] == "10.61.100.0/24"  # type: ignore[index]
    assert fh.connected_route(rows, "10.61.201.9", "10")["protocol"] == "omp"  # type: ignore[index]
    assert fh.connected_route(rows, "10.61.100.10", "20") is None


# --- catsdwan_find_host --------------------------------------------------------------------------


async def test_find_hub1_host_by_ip(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api)
    out = await run({"host": "10.61.100.10"})
    assert out["found"] is True and out["kind"] == "ip"
    loc = out["locations"][0]
    assert loc["edge"] == "hub1" and loc["site_id"] == "100" and loc["vpn"] == "10"
    assert loc["interface"] == "GigabitEthernet3" and loc["mac"] == "52:54:00:f8:04:f0"
    assert loc["subnet"] == "10.61.100.0/24" and loc["local"] is True and loc["entry"] == "learned (dynamic)"
    assert "switchport" not in loc and len(out["locations"]) == 1
    route = out["omp"]["route"]
    assert route["advertised_by"] == "hub1" and route["colours"] == ["biz-internet", "mpls"]
    assert out["omp"]["seen_from"] == "hub1"
    assert out["verdict"].startswith("10.61.100.10 is behind hub1 (site 100) in VPN 10 on GigabitEthernet3")
    assert (
        "advertised to the fabric by hub1 as 10.61.100.0/24 (connected) over biz-internet, mpls"
        in (out["verdict"])
    )
    assert out["searched"]["edges"] == ["br1", "br2", "hub1"]


async def test_find_by_mac_in_cisco_notation(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api)
    out = await run({"host": "5254.00f8.04f0"})
    loc = out["locations"][0]
    assert out["kind"] == "mac" and loc["edge"] == "hub1" and loc["address"] == "10.61.100.10"
    assert "(10.61.100.10)" in out["verdict"] and out["omp"]["route"]["prefix"] == "10.61.100.0/24"


async def test_host_behind_br2_seen_from_hub1_as_omp_route(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api)
    out = await run({"host": "10.61.201.15", "seen_from": "hub1"})
    loc = out["locations"][0]
    assert out["found"] is True and loc["edge"] == "br2" and loc["site_id"] == "201"
    assert loc["subnet"] == "10.61.201.0/24" and loc["interface"] == "GigabitEthernet3"
    assert loc["local"] is False and loc["seen_in"] == "omp (from hub1)"
    assert out["omp"]["route"]["chosen_paths"] == 2
    assert "per OMP (10.61.201.0/24 on GigabitEthernet3)" in out["verdict"]
    assert "in no ARP table read" in out["verdict"]


async def test_not_on_the_fabric(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api)
    out = await run({"host": "10.99.0.1"})
    assert out["found"] is False and out["locations"] == []
    assert out["omp"]["route"] is None and "not on the fabric" in out["verdict"]


async def test_transport_address_is_an_edge_interface_without_omp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api)
    out = await run({"host": "10.60.1.13"})
    first = out["locations"][0]
    assert first["vpn"] == "0" and "omp" not in out
    assert {loc["edge"] for loc in out["locations"]} == {"hub1", "br1", "br2"}
    # learned entries on br1/br2 sort before hub1's own address
    assert first["entry"] == "learned (dynamic)" and first["edge"] in ("br1", "br2")
    assert "transport VPN 0" in out["verdict"] and "Also seen on" in out["verdict"]


async def test_vpn_filter_and_site_scope(api: respx.MockRouter) -> None:
    mock_inventory(api)
    arp = mock_edges(api)
    out = await run({"host": "10.60.1.13", "vpn": 10})
    assert out["found"] is False
    scoped = await run({"host": "10.61.100.10", "site": "201"})
    assert scoped["searched"]["edges"] == ["br2"] and arp["hub1"].call_count == 1  # hub1's ARP not read
    # not in br2's ARP table, so located by the OMP route br2 holds for it
    loc = scoped["locations"][0]
    assert loc["edge"] == "hub1" and loc["seen_in"] == "omp (from br2)"
    assert loc["interface"] == "GigabitEthernet3"


async def test_edge_cap_and_read_errors(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edges(api, arp={"br1": 500})
    out = await run({"host": "10.61.100.10", "max_edges": 2})
    assert out["locations"][0]["seen_in"] == "omp (from br1)"  # hub1 not read: found through OMP
    assert "1 more edge(s) past max_edges=2: hub1" in out["searched"]["not_read"]
    assert out["searched"]["errors"][0].startswith("br1: ARP read failed")


async def test_unreachable_edges_named_and_bad_input(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    mock_edges(api)
    out = await run({"host": "10.61.100.10"})
    assert out["searched"]["unreachable"] == ["br2"] and out["searched"]["edges"] == ["br1", "hub1"]
    with pytest.raises(ToolError, match="neither an IP address nor a MAC"):
        await run({"host": "printer-1"})
    with pytest.raises(ToolError, match="No device is at site"):
        await run({"host": "10.61.100.10", "site": "999"})
