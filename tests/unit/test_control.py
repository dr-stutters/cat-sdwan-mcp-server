"""W3: control connections, OMP peers, OMP routes and TLOCs on recorded 20.18.3.1 payloads.

Connection history and the bulk ControlConnection state API were not recorded (the lab had no failures);
their bodies here are hand-built from the documented fields and marked so.
"""

import copy
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.control import explain, history_row, prefix_matches, status_meaning

from .conftest import fixture
from .test_inventory import call, mock_inventory

HUB1, BR1, BR2, VALIDATOR, CONTROLLER = "10.0.0.1", "10.0.0.2", "10.0.0.3", "1.1.1.2", "1.1.1.3"


def history(*rows: dict[str, Any], device: str = HUB1, host: str = "hub1") -> dict[str, Any]:
    """A hand-built GET device/control/connectionshistory body (not recorded yet)."""
    return {"data": [{"vdevice-name": device, "vdevice-host-name": host, **r} for r in rows]}


BID_FAIL = {
    "peer-type": "vedge",
    "system-ip": "::",
    "public-ip": "10.60.1.15",
    "public-port": 12386,
    "local-color": "default",
    "remote-color": "mpls",
    "state": "tear_down",
    "local_enum": "BIDNTVRFD",
    "local_enum_desc": "Peer Board ID Cert not verified",
    "remote_enum": "NOERR",
    "downtime-date": 1792742000000,
    "rep-count": 7,
}
ORG_FAIL = {
    "peer-type": "vsmart",
    "system-ip": CONTROLLER,
    "peer-host-name": "controller",
    "local-color": "mpls",
    "state": "connect",
    "local_enum": "NOERR",
    "remote_enum": "CTORGNMMIS",
    "downtime-date": 1792742500000,
    "rep-count": 2,
}
NORMAL = {
    "peer-type": "vsmart",
    "system-ip": CONTROLLER,
    "state": "tear_down",
    "local_enum": "XTVSTRDN",
    "remote_enum": "NOERR",
    "downtime-date": 1792742600000,
}


def rt(api: respx.MockRouter, path: str, ip: str, body: Any, status: int = 200) -> respx.Route:
    return api.get(f"/dataservice/device/{path}", params={"deviceId": ip}).respond(status, json=body)


# --- catsdwan_control_connections ----------------------------------------------------------------


async def test_control_connections_device_with_history(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "control/connections", HUB1, fixture("device_control_connections_hub1"))
    rt(api, "control/summary", HUB1, {"error": {"message": "Not found", "code": "X"}}, 404)
    rt(api, "control/connectionshistory", HUB1, history(ORG_FAIL, NORMAL))
    out = await call("catsdwan_control_connections", {"device": "hub1", "response_format": "json"})
    rows = out["results"]
    assert out["total"] == 3 and out["by_state"] == {"up": 3} and "not_all_up" not in out
    assert [(r["peer"], r["local_colour"]) for r in rows] == [
        ("controller", "biz-internet"),
        ("controller", "mpls"),
        ("manager", "mpls"),
    ]
    c = rows[1]
    assert c["peer_type"] == "controller" and c["peer_system_ip"] == CONTROLLER and c["protocol"] == "dtls"
    assert c["host"] == "hub1" and c["public"] == "10.60.2.12:12346" and c["up_since"].endswith("Z")
    assert "error" in out["summary"]  # the optional summary failing is reported, not fatal
    [failed] = out["failed_attempts"]  # the normal XTVSTRDN teardown is dropped
    assert failed["peer"] == "controller" and failed["repeats"] == 2
    assert "organisation name does not match" in failed["reason"] and failed["remote_error"] == "CTORGNMMIS"


async def test_control_connections_unreachable_edge_reads_the_validator(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    conns = rt(api, "control/connections", BR2, {"data": []})
    rt(
        api,
        "control/connectionshistory",
        VALIDATOR,
        history(BID_FAIL, NORMAL, device=VALIDATOR, host="validator"),
    )
    out = await call("catsdwan_control_connections", {"device": "br2", "response_format": "json"})
    assert conns.call_count == 0 and out["total"] == 0
    assert out["realtime"].startswith("not read: the Manager reports br2 unreachable")
    [failed] = out["failed_attempts"]
    assert failed["host"] == "validator" and failed["public"] == "10.60.1.15:12386" and failed["repeats"] == 7
    assert "peer_system_ip" not in failed  # '::' is no address
    assert failed["reason"].startswith("BIDNTVRFD: the peer's chassis/serial is not verified")
    assert "(Peer Board ID Cert not verified)" in failed["reason"]


def bulk_pages(router: respx.MockRouter) -> respx.Route:
    """The bulk ControlConnection state API (not recorded): the controller's nine rows plus hub1's three,
    in two pages; br2's mpls connection to the controller is down."""
    rows = copy.deepcopy(fixture("device_control_connections_controller")["data"])
    rows += fixture("device_control_connections_hub1")["data"]
    for r in rows:
        if r.get("peer-host-name") == "br2" and r.get("remote-color") == "mpls":
            r["state"] = "down"
    first = {"data": rows[:7], "pageInfo": {"startId": "1", "endId": "7", "moreEntries": True, "count": 7}}
    second = {"data": rows[7:], "pageInfo": {"startId": "8", "endId": "12", "moreEntries": False, "count": 5}}

    def page(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=second if request.url.params.get("startId") == "7" else first)

    return router.get("/dataservice/data/device/state/ControlConnection").mock(side_effect=page)


async def test_control_connections_fabric_view_pages_the_bulk_api(api: respx.MockRouter) -> None:
    mock_inventory(api)
    bulk = bulk_pages(api)
    rt(api, "control/connectionshistory", VALIDATOR, history(BID_FAIL, device=VALIDATOR, host="validator"))
    out = await call("catsdwan_control_connections", {"response_format": "json"})
    assert bulk.call_count == 2
    assert bulk.calls[1].request.url.params["startId"] == "7"
    assert out["total"] == 12 and out["by_state"] == {"down": 1, "up": 11}
    assert out["not_all_up"] == ["controller: 8/9 up"]
    first = out["results"][0]  # what is not up comes first
    assert (first["host"], first["peer"], first["state"]) == ("controller", "br2", "down")
    assert first["peer_type"] == "edge" and first["remote_colour"] == "mpls"
    assert out["source"].startswith("the Manager's state database")
    assert out["failed_attempts"][0]["local_error"] == "BIDNTVRFD"
    only = await call(
        "catsdwan_control_connections",
        {"state": "not_up", "include_history": False, "response_format": "json"},
    )
    assert [r["peer"] for r in only["results"]] == ["br2"] and "failed_attempts" not in only


async def test_control_connections_fabric_falls_back_to_live_reads(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/data/device/state/ControlConnection").respond(
        404, json={"error": {"message": "nope"}}
    )
    rt(api, "control/connections", CONTROLLER, fixture("device_control_connections_controller"))
    rt(api, "control/connections", VALIDATOR, {"data": []})
    out = await call(
        "catsdwan_control_connections",
        {"peer_type": "edge", "include_history": False, "response_format": "json"},
    )
    assert "live from the 2 reachable controller(s)" in out["source"]
    assert out["total"] == 6 and {r["peer"] for r in out["results"]} == {"hub1", "br1", "br2"}


async def test_control_connections_markdown_and_unknown_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "control/connections", HUB1, fixture("device_control_connections_hub1"))
    rt(
        api,
        "control/summary",
        HUB1,
        {"data": [{"vdevice-name": HUB1, "vsmart_counts": 1, "vmanage_counts": 1}]},
    )
    text = await call("catsdwan_control_connections", {"device": "10.0.0.1", "include_history": False})
    assert "| hub1 | controller | controller | 1.1.1.3 | mpls | default | dtls | up |" in text
    assert "vsmart_counts" in text
    with pytest.raises(ToolError, match="Did you mean"):
        await call("catsdwan_control_connections", {"device": "hub9"})


def test_explain_reason_codes() -> None:
    assert explain("NOERR") is None and explain("") is None
    assert explain("ERR_BID_NOT_VERIFIED").startswith("ERR_BID_NOT_VERIFIED: the peer's chassis/serial")
    assert "clock skew" in str(explain("CRTVERFL"))
    assert explain("ZZZ", "Something odd") == "ZZZ: Something odd"
    assert explain("SERNTPRES", "Serial Number not present") == (
        "SERNTPRES: the serial number is not in the WAN edge list (upload or sync the serial file) "
        "(Serial Number not present)"
    )
    row = history_row({"local-enum": "DCONFAIL", "remote-enum": "DCONFAIL", "downtime": "2026-10-23"})
    assert row["reason"].startswith("DCONFAIL: DTLS connection failure") and ";" not in row["reason"]


# --- catsdwan_omp_peers --------------------------------------------------------------------------


async def test_omp_peers_default_asks_the_controller(api: respx.MockRouter) -> None:
    mock_inventory(api)
    body = fixture("device_omp_peers_controller")
    body["data"][2]["state"] = "down"
    rt(api, "omp/peers", CONTROLLER, body)
    out = await call("catsdwan_omp_peers", {"response_format": "json"})
    assert out["asked"] == ["controller"] and out["by_state"] == {"down": 1, "up": 2}
    first = out["results"][0]
    assert (first["peer"], first["peer_host"], first["state"]) == (BR2, "br2", "down")
    assert first["peer_type"] == "edge" and first["site_id"] == 201
    up = await call("catsdwan_omp_peers", {"state": "up", "response_format": "json"})
    assert [r["peer_host"] for r in up["results"]] == ["hub1", "br1"]
    assert up["results"][0]["up_since"].endswith("Z")


async def test_omp_peers_unreachable_device(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    with pytest.raises(ToolError, match="Not read: the Manager reports br2 unreachable"):
        await call("catsdwan_omp_peers", {"device": "br2"})


async def test_omp_peers_all_failed(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "omp/peers", CONTROLLER, {"error": {"message": "Failed to get data", "code": "DEVICE0001"}}, 400)
    with pytest.raises(ToolError, match="DEVICE0001"):
        await call("catsdwan_omp_peers", {})


# --- catsdwan_omp_routes -------------------------------------------------------------------------


async def test_omp_routes_prefix_lookup(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "omp/routes/received", HUB1, fixture("device_omp_routes_received_hub1"))
    out = await call(
        "catsdwan_omp_routes",
        {"device": "hub1", "vpn": 10, "prefix": "10.61.200.5", "response_format": "json"},
    )
    rows = out["results"]
    assert out["total"] == 3 and out["prefixes"] == 1 and "not_installed" not in out
    assert {r["prefix"] for r in rows} == {"10.61.200.0/24"} and {r["originator_host"] for r in rows} == {
        "br1"
    }
    assert rows[0]["status"] == "C I R" and rows[0]["meaning"] == "chosen, installed, resolved"
    assert rows[0]["tloc"] in ("10.0.0.2 / mpls / ipsec", "10.0.0.2 / biz-internet / ipsec")
    assert rows[-1]["status"] == "R" and rows[-1]["tloc"] == "10.0.0.2"


async def test_omp_routes_all_sorted_and_not_installed(api: respx.MockRouter) -> None:
    mock_inventory(api)
    body = fixture("device_omp_routes_received_hub1")
    for r in body["data"]:
        if r["prefix"] == "10.61.201.0/24":
            r["status"] = "Inv U"
    rt(api, "omp/routes/received", HUB1, body)
    out = await call("catsdwan_omp_routes", {"device": "hub1", "response_format": "json"})
    assert [r["prefix"] for r in out["results"]][::3] == [
        "10.61.100.0/24",
        "10.61.200.0/24",
        "10.61.201.0/24",
    ]
    assert out["not_installed"] == ["vpn 10 10.61.201.0/24"]
    assert out["results"][0]["meaning"] == "chosen, redistributed, resolved"
    br2 = await call(
        "catsdwan_omp_routes", {"device": "hub1", "originator": "br2", "response_format": "json"}
    )
    assert {r["prefix"] for r in br2["results"]} == {"10.61.201.0/24"}
    none = await call("catsdwan_omp_routes", {"device": "hub1", "vpn": 20, "response_format": "json"})
    assert none["total"] == 0


async def test_omp_routes_advertised(api: respx.MockRouter) -> None:
    mock_inventory(api)
    adv = rt(
        api,
        "omp/routes/advertised",
        BR1,
        {"data": [{"vpn-id": "10", "prefix": "10.61.200.0/24", "to-peer": CONTROLLER, "status": "C Red R"}]},
    )
    text = await call("catsdwan_omp_routes", {"device": "br1", "direction": "advertised"})
    assert adv.call_count == 1 and "| 10 | 10.61.200.0/24 |" in text and "redistributed" in text


def test_prefix_matching_and_flags() -> None:
    assert prefix_matches("10.61.200.0/24", "10.61.200.0/24")
    assert prefix_matches("10.61.200.0/24", "10.61.0.0/16") and prefix_matches(
        "10.61.200.0/24", "10.61.200.9"
    )
    assert not prefix_matches("10.61.201.0/24", "10.61.200.0/24")
    assert prefix_matches("2001:db8::/64", "2001:db8::1") and not prefix_matches("10.0.0.0/8", "2001:db8::1")
    assert prefix_matches("weird", "wei")
    assert status_meaning("C I R") == "chosen, installed, resolved" and status_meaning("") is None
    assert status_meaning("Q") == "Q"


# --- catsdwan_list_tlocs -------------------------------------------------------------------------


async def test_list_tlocs_fabric_table(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "omp/tlocs/received", CONTROLLER, fixture("device_omp_tlocs_received_hub1"))
    out = await call("catsdwan_list_tlocs", {"response_format": "json"})
    assert out["device"] == "controller" and out["total"] == 6
    assert out["by_colour"] == {"biz-internet": 3, "mpls": 3}
    assert [(r["host"], r["colour"]) for r in out["results"]][:2] == [
        ("br1", "biz-internet"),
        ("br1", "mpls"),
    ]
    br1 = out["results"][1]
    assert br1["public"] == "10.60.1.14:12426" and br1["private"] == "10.60.1.14:12426"
    assert br1["bfd_status"] == "up" and br1["encap"] == "ipsec" and br1["site_id"] == "200"
    only = await call("catsdwan_list_tlocs", {"edge": "br2", "colour": "MPLS", "response_format": "json"})
    assert [(r["system_ip"], r["colour"]) for r in only["results"]] == [(BR2, "mpls")]


async def test_list_tlocs_on_a_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = rt(api, "omp/tlocs/received", HUB1, fixture("device_omp_tlocs_received_hub1"))
    out = await call("catsdwan_list_tlocs", {"device": "hub1", "edge": "10.0.0.1", "response_format": "json"})
    assert route.call_count == 1 and out["total"] == 2 and out["device"] == "hub1"


async def test_omp_tools_without_a_reachable_controller(api: respx.MockRouter) -> None:
    body = fixture("device")
    for d in body["data"]:
        d["reachability"] = "unreachable"
    api.get("/dataservice/device").respond(json=body)
    api.get("/dataservice/system/device/vedges").respond(json=fixture("system_device_vedges"))
    with pytest.raises(ToolError, match="No reachable controller"):
        await call("catsdwan_list_tlocs", {})
