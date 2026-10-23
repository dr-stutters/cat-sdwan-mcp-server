"""W18: device state reads on br1's recorded real-time tables (20.18.3.1, a C8000V).

Recorded: the IOS XE RIB (/ip/ipRoutes, 17 routes in VPN 0, 10, 512 and internal VRFs; br2's LAN
via OMP from 10.0.0.3), the FIB's 'Invalid data type' refusal, ARP, NAT statistics, the global drop counters,
the hardware inventory (serials redacted), the fleet-wide CDP table, empty BGP neighbours and DHCP server.
Viptela OS route table and BGP/OSPF rows follow the spec's examples.
"""

from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import devicestate as ds

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

DEV = "/dataservice/device"
EMPTY = {"data": []}


def mock_tables(api: respx.MockRouter, **overrides: Any) -> None:
    """br1's recorded tables; every other real-time table answers empty."""
    recorded = {
        "ip/ipRoutes": fixture("devstate_ip_iproutes_br1"),
        "ip/routetable": EMPTY,
        "arp": fixture("devstate_arp_br1"),
        "ip/nat/interfacestatistics": fixture("devstate_nat_interfacestatistics_br1"),
        "sdwan-global-drop-statistics": fixture("devstate_sdwan_drops_br1"),
        "hardware/inventory": fixture("devstate_hardware_inventory_br1"),
        "cdp/neighbors": fixture("devstate_cdp_neighbors"),
        "bgp/neighbors": fixture("devstate_bgp_neighbors_br1"),
        "dhcp/server": fixture("devstate_dhcp_server_br1"),
        **overrides,
    }
    for rel, body in recorded.items():
        if isinstance(body, int):
            api.get(f"{DEV}/{rel}").respond(body, json=fixture("devstate_ip_fib_br1"))
        else:
            api.get(f"{DEV}/{rel}").respond(json=body)
    api.get(f"{DEV}/ip/fib").respond(400, json=fixture("devstate_ip_fib_br1"))
    api.get(
        url__regex=r"/dataservice/device/(ospf|eigrp|bgp|dhcp|vrrp|ip/nat|interface/|hardware|crashlog|ntp"
        r"|lacp|lldp|staticRouteTracker|endpointTracker|license|aaa|users|logging|qos|policer)"
    ).respond(json=EMPTY)


async def run(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return "\n".join(getattr(x, "text", "") for x in result.content)


# --- helpers -------------------------------------------------------------------------------------


def test_route_rows_from_both_tables() -> None:
    rows = [ds.route_row(r, {"10.0.0.3": "br2"}) for r in fixture("devstate_ip_iproutes_br1")["data"]]
    omp = next(r for r in rows if r["prefix"] == "10.61.201.0/24")
    assert omp["via_edge"] == "br2" and omp["vpn"] == "10" and omp["protocol"] == "omp"
    assert omp["next_hop"] == "10.0.0.3" and omp["preference"] == "251"
    default = next(r for r in rows if r["prefix"] == "0.0.0.0/0" and r["vpn"] == "0")
    assert default["protocol"] == "static" and "10.60.2.254" in default["next_hop"]
    assert {r["vpn"] for r in rows if r["prefix"] == "198.18.128.0/18"} == {"512"}
    viptela = ds.route_row(
        {
            "vpn-id": 10,
            "prefix": "10.0.5.0/24",
            "protocol": "omp",
            "ip": "172.16.254.4",
            "color": "mpls",
            "encap": "ipsec",
            "rstatus": "F S",
        },
        {"172.16.254.4": "hub"},
    )
    assert viptela["via_edge"] == "hub" and viptela["colour"] == "mpls" and viptela["vpn"] == "10"


def test_platform_and_catalogue() -> None:
    assert ds.platform_of({"model": "vedge-C8000V", "role": "edge"}) == "iosxe"
    assert ds.platform_of({"model": "vedge-cloud", "role": "edge"}) == "viptela"
    assert ds.platform_of({"model": "vsmart", "role": "controller"}) == "viptela"
    names = {r["feature"] for r in ds.catalogue_rows()}
    assert {"arp", "dhcp", "vrrp", "nat", "interface_errors", "hardware", "sdwan_drops", "qos"} <= names
    assert "Did you mean: arp" in ds.suggest("arpp")


def test_clean_keeps_nonzero_counters() -> None:
    row = fixture("devstate_sdwan_drops_br1")["data"][0]
    out = ds.clean(row, nonzero=True)
    assert out["ipv4-no-adj-pkts"] == "4" and "bad-len-pkts" not in out and "vdevice-name" not in out


# --- catsdwan_routes -----------------------------------------------------------------------------


async def test_routes_br1_shows_br2_lan_via_omp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api)
    out = await run("catsdwan_routes", {"device": "br1", "vpn": 10, "response_format": "json"})
    prefixes = {r["prefix"]: r for r in out["results"]}
    assert (
        prefixes["10.61.201.0/24"]["via_edge"] == "br2" and prefixes["10.61.100.0/24"]["via_edge"] == "hub1"
    )
    assert out["by_protocol"] == {"omp": 2, "direct": 2} and out["source"] == "/device/ip/ipRoutes"
    assert out["neighbours"].startswith("none")


async def test_routes_missing_prefix_and_internal_vrfs(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api)
    gone = await run(
        "catsdwan_routes",
        {
            "device": "br1",
            "vpn": 10,
            "prefix": "10.61.250.0/24",
            "response_format": "json",
            "include_neighbours": False,
        },
    )
    allv = await run(
        "catsdwan_routes", {"device": "br1", "response_format": "json", "include_internal": True}
    )
    some = await run("catsdwan_routes", {"device": "br1", "response_format": "json"})
    assert gone["results"] == [] and "no route covers 10.61.250.0/24 in VPN 10" in gone["missing"]
    assert allv["total"] == 17 and some["total"] < 17


async def test_routes_protocol_filter_and_neighbours(api: respx.MockRouter) -> None:
    mock_inventory(api)
    bgp = {
        "data": [
            {
                "vpn-id": 10,
                "peer-addr": "10.61.200.2",
                "as": 65200,
                "state": "active",
                "afi": "ipv4-unicast",
                "msg-rcvd": 0,
                "msg-sent": 0,
            }
        ]
    }
    mock_tables(api, **{"bgp/neighbors": bgp})
    out = await run("catsdwan_routes", {"device": "br1", "protocol": "omp", "response_format": "json"})
    assert {r["protocol"] for r in out["results"]} == {"omp"}
    assert out["neighbours"][0]["peer"] == "10.61.200.2" and out["neighbours_not_up"] == 1


async def test_routes_viptela_table_fallback(api: respx.MockRouter) -> None:
    mock_inventory(api)
    table = {
        "data": [
            {
                "vpn-id": 10,
                "prefix": "10.61.201.0/24",
                "protocol": "omp",
                "ip": "10.0.0.3",
                "color": "mpls",
                "encap": "ipsec",
                "rstatus": "F S",
            }
        ]
    }
    mock_tables(api, **{"ip/ipRoutes": EMPTY, "ip/routetable": table})
    out = await run("catsdwan_routes", {"device": "br1", "response_format": "json"})
    assert out["source"] == "/device/ip/routetable" and out["results"][0]["colour"] == "mpls"


# --- catsdwan_device_state -----------------------------------------------------------------------


async def test_device_state_list_and_unknown() -> None:
    out = await run("catsdwan_device_state", {"feature": "list"})
    assert any(f["feature"] == "vrrp" for f in out["features"])
    with pytest.raises(ToolError, match="Did you mean: vrrp"):
        await run("catsdwan_device_state", {"feature": "vrp", "device": "br1"})


async def test_device_state_arp_and_drops(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api)
    arp = await run("catsdwan_device_state", {"feature": "arp", "device": "br1"})
    drops = await run("catsdwan_device_state", {"feature": "sdwan_drops", "device": "br1"})
    assert len(arp["arp"]) == 16 and set(arp["arp"][0]) <= {
        "vpn-id",
        "address",
        "hardware",
        "interface",
        "mode",
        "time",
    }
    assert drops["drops"][0]["ipv4-no-adj-pkts"] == "4" and "bad-len-pkts" not in drops["drops"][0]


async def test_device_state_empty_tables_and_fleet_cdp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api)
    dhcp = await run("catsdwan_device_state", {"feature": "dhcp", "device": "br1"})
    cdp = await run("catsdwan_device_state", {"feature": "cdp", "device": "br1"})
    hw = await run("catsdwan_device_state", {"feature": "hardware", "device": "br1"})
    assert dhcp["empty"] == ["client", "server", "interface"] and "nothing configured" in dhcp["note"]
    assert cdp["empty"] == ["neighbours"]
    assert hw["inventory"][0]["hw-description"].startswith("Cisco Catalyst 8000V") and hw["empty"] == [
        "environment",
        "alarms",
    ]


async def test_device_state_fib_is_refused_on_iosxe(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api)
    with pytest.raises(ToolError, match="Viptela OS table"):
        await run("catsdwan_device_state", {"feature": "fib", "device": "br1"})


async def test_device_state_unsupported_answer_is_named(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_tables(api, arp=400)
    out = await run("catsdwan_device_state", {"feature": "arp", "device": "br1"})
    assert out["arp"].startswith("not on this platform")


async def test_device_state_needs_a_device() -> None:
    with pytest.raises(ToolError, match="needs a device"):
        await run("catsdwan_device_state", {"feature": "arp"})


@pytest.mark.parametrize(
    "path",
    sorted(
        {t.path for f in ds.CATALOGUE.values() for t in f.tables}
        | {
            ds.ROUTES_IOSXE_PATH,
            ds.ROUTES_VIPTELA_PATH,
            ds.BGP_NEIGHBORS_PATH,
            ds.OSPF_NEIGHBOR_PATH,
            ds.EIGRP_INTERFACE_PATH,
            ds.BGP_ROUTES_PATH,
            ds.OSPF_ROUTES_PATH,
            ds.EIGRP_ROUTE_PATH,
        }
    ),
)
def test_device_state_paths_are_in_the_spec(path: str) -> None:
    from cat_sdwan_mcp._core.spec import build_index
    from cat_sdwan_mcp.spec import match_operation

    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, "GET", path)
    assert "GET" in methods
