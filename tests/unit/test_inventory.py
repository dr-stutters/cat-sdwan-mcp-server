"""W2: inventory and device health on recorded 20.18.3.1 payloads (edited copies for the edge cases).

The recorded /dataservice/device predates the edges joining (controllers only), so `device_body()` adds the
three edges built from their recorded /system/device/vedges records (same host names, system IPs, sites,
chassis and serials), as the Manager lists them once joined.
"""

import json
import time
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp._core import InvalidRequest, NotFound
from cat_sdwan_mcp.inventory import (
    config_mode,
    controller_row,
    health_row,
    interfaces,
    iso,
    join_inventory,
    reboots,
    resolve,
    system_status,
)

from .conftest import fixture, make_server

EDGES = {"hub1": "10.0.0.1", "br1": "10.0.0.2", "br2": "10.0.0.3"}


def device_body(**reach: str) -> dict[str, Any]:
    """GET /dataservice/device with the three edges; `br2="unreachable"` changes one edge's reachability."""
    body = fixture("device")
    template = next(d for d in body["data"] if d["personality"] == "vbond")
    for v in fixture("system_device_vedges")["data"]:
        if not v.get("system-ip"):
            continue
        row = {
            **template,
            "deviceId": v["system-ip"],
            "system-ip": v["system-ip"],
            "local-system-ip": v["system-ip"],
            "host-name": v["host-name"],
            "site-id": v["site-id"],
            "site-name": v["site-name"],
            "personality": "vedge",
            "device-type": "vedge",
            "device-model": v["deviceModel"],
            "version": v["version"],
            "uuid": v["uuid"],
            "board-serial": v["serialNumber"],
            "uptime-date": v["uptime-date"],
            "controlConnections": "3",
            "reachability": reach.get(v["host-name"], "reachable"),
        }
        body["data"].append(row)
    return body


def vedges_body(**edits: dict[str, Any]) -> dict[str, Any]:
    """GET /system/device/vedges; `br2={"validity": "staging"}` edits one edge's record."""
    body = fixture("system_device_vedges")
    for v in body["data"]:
        if v.get("host-name") in edits:
            v.update(edits[v["host-name"]])
    return body


def mock_inventory(api: respx.MockRouter, *, reach: dict[str, str] | None = None, **edits: Any) -> None:
    api.get("/dataservice/device").respond(json=device_body(**(reach or {})))
    api.get("/dataservice/system/device/vedges").respond(json=vedges_body(**edits))


async def call(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return "\n".join(getattr(x, "text", "") for x in result.content)


def by_host(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r.get("host") or r["chassis"]: r for r in rows}


# --- catsdwan_list_devices -----------------------------------------------------------------------


async def test_list_devices_joins_certificates_and_config_modes(api: respx.MockRouter) -> None:
    mock_inventory(api)
    out = await call("catsdwan_list_devices", {"response_format": "json"})
    rows = by_host(out["results"])
    assert [r["host"] for r in out["results"]] == ["manager", "controller", "validator", "br1", "br2", "hub1"]
    assert out["total"] == 6
    assert "22 WAN edge slot(s)" in out["not_joined"]
    hub1, br2 = rows["hub1"], rows["br2"]
    assert hub1["role"] == "edge" and hub1["system_ip"] == "10.0.0.1" and hub1["site_id"] == "100"
    assert hub1["chassis"] == "REDACTED-17" and hub1["board_serial"] == "REDACTED-49"
    assert hub1["certificate"] == "valid" and hub1["certificate_state"] == "certinstalled"
    assert (hub1["config_mode"], hub1["config"]) == ("configuration group", "mcp-test")
    assert br2["config_mode"] == "cli" and "config" not in br2
    assert hub1["up_since"].endswith("Z") and hub1["config_status"] == "In Sync"
    assert rows["controller"]["certificate"] == "valid" and rows["controller"]["role"] == "controller"


async def test_list_devices_unreachable_edge_and_staging_certificate(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"}, br2={"validity": "staging"})
    out = await call("catsdwan_list_devices", {"reachability": "unreachable", "response_format": "json"})
    assert [r["host"] for r in out["results"]] == ["br2"]
    assert out["results"][0]["certificate"] == "staging"
    up = await call("catsdwan_list_devices", {"reachability": "reachable", "response_format": "json"})
    assert "br2" not in {r["host"] for r in up["results"]} and up["total"] == 5


async def test_list_devices_template_mode(api: respx.MockRouter) -> None:
    mock_inventory(
        api,
        br1={"configOperationMode": "vmanage", "managed-by": "Unmanaged", "template": "branch-c8kv"},
        br2={"configOperationMode": "vmanage", "managed-by": "Template branch-b", "template": None},
    )
    out = await call("catsdwan_list_devices", {"personality": "edge", "response_format": "json"})
    rows = by_host(out["results"])
    assert (rows["br1"]["config_mode"], rows["br1"]["config"]) == ("template", "branch-c8kv")
    assert (rows["br2"]["config_mode"], rows["br2"]["config"]) == ("template", "branch-b")
    assert rows["hub1"]["config_mode"] == "configuration group"


@pytest.mark.parametrize(
    ("args", "hosts"),
    [
        ({"personality": "controller"}, ["controller"]),
        ({"personality": "validator"}, ["validator"]),
        ({"site": "200"}, ["br1"]),
        ({"site": "site_201"}, ["br2"]),
        ({"model": "c8000v"}, ["br1", "br2", "hub1"]),
        ({"version": "20.18"}, ["manager", "controller", "validator"]),
        ({"personality": "edge", "site": "100", "version": "17.18"}, ["hub1"]),
        ({"personality": "edge", "limit": 1, "offset": 1}, ["br2"]),
    ],
)
async def test_list_devices_filters(api: respx.MockRouter, args: dict[str, Any], hosts: list[str]) -> None:
    mock_inventory(api)
    out = await call("catsdwan_list_devices", {**args, "response_format": "json"})
    assert [r["host"] for r in out["results"]] == hosts


async def test_list_devices_include_unjoined(api: respx.MockRouter) -> None:
    mock_inventory(api)
    out = await call(
        "catsdwan_list_devices",
        {"personality": "edge", "include_unjoined": True, "limit": 500, "response_format": "json"},
    )
    assert out["total"] == 25 and "not_joined" not in out
    slot = by_host(out["results"])["REDACTED-21"]
    assert slot["reachability"] == "not joined" and slot["certificate_state"] == "tokengenerated"
    assert "system_ip" not in slot


async def test_list_devices_without_certificate_inventory(api: respx.MockRouter) -> None:
    api.get("/dataservice/device").respond(json=device_body())
    api.get("/dataservice/system/device/vedges").respond(
        403, json={"error": {"message": "Forbidden", "code": "USER0003"}}
    )
    out = await call("catsdwan_list_devices", {"response_format": "json"})
    assert out["total"] == 6
    assert any("WAN edge certificate inventory" in w for w in out["warnings"])
    hub1 = by_host(out["results"])["hub1"]
    assert hub1["certificate"] == "valid"  # /dataservice/device carries `validity` too
    assert "config_mode" not in hub1 and "certificate_state" not in hub1
    assert by_host(out["results"])["controller"]["certificate"] == "valid"


async def test_list_devices_markdown(api: respx.MockRouter) -> None:
    mock_inventory(api)
    text = await call("catsdwan_list_devices", {"personality": "edge"})
    assert "| host | role | system_ip |" in text and "| hub1 | edge | 10.0.0.1 |" in text
    assert "configuration group | mcp-test" in text


# --- catsdwan_get_device -------------------------------------------------------------------------


def mock_realtime(api: respx.MockRouter, ip: str = "10.0.0.2") -> dict[str, respx.Route]:
    return {
        "status": api.get("/dataservice/device/system/status", params={"deviceId": ip}).respond(
            json=fixture("device_system_status_br1")
        ),
        "interface": api.get("/dataservice/device/interface", params={"deviceId": ip}).respond(
            json=fixture("device_interface_br1")
        ),
        "software": api.get("/dataservice/device/software", params={"deviceId": ip}).respond(
            json=fixture("device_software_br1")
        ),
        "reboot": api.get("/dataservice/device/reboothistory", params={"deviceId": ip}).respond(
            json=fixture("device_reboothistory_br1")
        ),
    }


async def test_get_device_with_realtime_state(api: respx.MockRouter) -> None:
    mock_inventory(api)
    routes = mock_realtime(api)
    out = await call("catsdwan_get_device", {"device": "BR1"})
    assert out["host"] == "br1" and out["system_ip"] == "10.0.0.2" and out["site_id"] == "200"
    assert out["config_mode"] == "configuration group" and out["certificate"] == "valid"
    system = out["system"]
    assert system["cpu_used_percent"] == 52.2 and system["memory_used_percent"] == 66.9
    assert system["disk_used_percent"] == 28 and system["reboot_reason"] == "factory-reset"
    assert system["state"] == "green All daemons up" and system["load_1_5_15"] == "1.34 / 1.28 / 1.30"
    gi1 = next(i for i in out["interfaces"] if i["name"] == "GigabitEthernet1")
    assert gi1 == {
        "name": "GigabitEthernet1",
        "vpn": "0",
        "admin": "up",
        "oper": "up",
        "ip": "10.60.1.14/24",
        "description": "mpls transport",
        "mac": "52:54:00:f8:e1:90",
        "speed_mbps": 1000,
    }
    assert out["software"] == [{"version": "17.18.02.0.4112", "active": True, "default": True}]
    assert out["reboots"][0]["reason"] == "factory-reset" and out["reboots"][0]["category"] == "factory-reset"
    assert all(r.call_count == 1 for r in routes.values())


@pytest.mark.parametrize("ref", ["10.0.0.2", "REDACTED-16", "redacted-50", "br1"])
async def test_get_device_by_any_identifier(api: respx.MockRouter, ref: str) -> None:
    mock_inventory(api)
    out = await call("catsdwan_get_device", {"device": ref, "realtime_state": False})
    assert out["host"] == "br1" and "system" not in out


async def test_get_device_realtime_failure_is_per_section(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    api.get("/dataservice/device/interface", params={"deviceId": "10.0.0.2"}).respond(
        400, json={"error": {"message": "Failed to get data from device", "code": "DEVICE0001"}}
    )
    out = await call("catsdwan_get_device", {"device": "br1"})
    assert "DEVICE0001" in out["interfaces"]["error"]
    assert out["system"]["cpu_used_percent"] == 52.2 and out["software"][0]["active"] is True


async def test_get_device_unreachable_edge_skips_realtime(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    routes = mock_realtime(api, "10.0.0.3")
    out = await call("catsdwan_get_device", {"device": "br2"})
    assert out["reachability"] == "unreachable" and "unreachable" in out["realtime"]
    assert all(r.call_count == 0 for r in routes.values())


async def test_get_device_unjoined_slot(api: respx.MockRouter) -> None:
    mock_inventory(api)
    out = await call("catsdwan_get_device", {"device": "REDACTED-21"})
    assert out["reachability"] == "not joined" and "has not joined" in out["realtime"]


async def test_get_device_did_you_mean(api: respx.MockRouter) -> None:
    mock_inventory(api)
    with pytest.raises(ToolError, match=r"Did you mean: br\d, br\d"):
        await call("catsdwan_get_device", {"device": "br3"})
    with pytest.raises(ToolError, match="matches 2 devices"):
        await call("catsdwan_get_device", {"device": "br"})


def test_resolve_prefix_and_errors() -> None:
    inv = join_inventory(
        device_body()["data"], vedges_body()["data"], fixture("system_device_controllers")["data"]
    )
    assert resolve(inv, "hu")["host"] == "hub1"
    with pytest.raises(InvalidRequest):
        resolve(inv, "  ")
    with pytest.raises(NotFound, match="Did you mean: hub1"):
        resolve(inv, "hub2")


# --- catsdwan_list_controllers -------------------------------------------------------------------


async def test_list_controllers(api: respx.MockRouter) -> None:
    out = await call("catsdwan_list_controllers", {"response_format": "json"})
    assert [r["role"] for r in out["results"]] == ["manager", "controller", "validator"]
    m = out["results"][0]
    assert m["host"] == "manager" and m["system_ip"] == "1.1.1.1" and m["certificate"] == "valid"
    assert m["certificate_expires"] == "Oct 22 06:04:58 2028 GMT" and m["certificate_status"] == "Installed"
    assert m["certificate_serial"].startswith("A0") and m["days_left"] > 300
    assert out["by_role"] == {"controller": 1, "manager": 1, "validator": 1} and "attention" not in out


async def test_list_controllers_attention(api: respx.MockRouter) -> None:
    body = fixture("system_device_controllers")
    for c in body["data"]:
        if c["personality"] == "vsmart":
            c["expirationDateLong"] = int((time.time() + 10 * 86400) * 1000)
        if c["personality"] == "vbond":
            c["validity"] = "invalid"
            c["reachability"] = "unreachable"
    api.get("/dataservice/system/device/controllers").respond(json=body)
    out = await call("catsdwan_list_controllers", {"response_format": "json"})
    att = " | ".join(out["attention"])
    assert "controller: certificate expires in 9 day(s)" in att or "expires in 10 day(s)" in att
    assert "validator: certificate invalid" in att and "validator: unreachable" in att
    only = await call("catsdwan_list_controllers", {"reachability": "unreachable", "response_format": "json"})
    assert [r["host"] for r in only["results"]] == ["validator"]


def test_controller_row_days_left() -> None:
    c = fixture("system_device_controllers")["data"][0]
    row = controller_row(c, now=c["expirationDateLong"] / 1000 - 5 * 86400)
    assert row["days_left"] == 5


# --- catsdwan_device_health ----------------------------------------------------------------------


async def test_device_health_poor_first_with_reason(api: respx.MockRouter) -> None:
    api.get("/dataservice/health/devices").respond(json=fixture("health_devices"))
    out = await call("catsdwan_device_health", {"response_format": "json"})
    hosts = [r["host"] for r in out["results"]]
    assert hosts == ["validator", "manager", "controller", "br1", "br2", "hub1"]
    v, m = out["results"][0], out["results"][1]
    assert v["health"] == "poor" and v["reason"].startswith("Control connections are not all up")
    assert "control connections up 6/8" in v["reason"] and v["control"] == "6/8"
    assert m["health"] == "fair" and m["reason"] == "CPU load 81.46%"
    assert out["counts"] == {"poor": 1, "fair": 1, "good": 4}
    hub1 = by_host(out["results"])["hub1"]
    assert hub1["config_group"] == "mcp-test" and hub1["bfd"] == "8/8" and "reason" not in hub1


async def test_device_health_filters(api: respx.MockRouter) -> None:
    api.get("/dataservice/health/devices").respond(json=fixture("health_devices"))
    poor = await call("catsdwan_device_health", {"health": "poor", "response_format": "json"})
    assert [r["host"] for r in poor["results"]] == ["validator"]
    site = await call("catsdwan_device_health", {"site": "SITE_200", "response_format": "json"})
    assert [r["host"] for r in site["results"]] == ["br1"]
    edges = await call("catsdwan_device_health", {"personality": "edge", "response_format": "json"})
    assert len(edges["results"]) == 3 and edges["counts"]["poor"] == 1


async def test_device_health_unreachable_edge_and_partial(api: respx.MockRouter) -> None:
    body = fixture("health_devices")
    for d in body["devices"]:
        if d["name"] == "br2":
            d.update(health="red", reachability="unreachable", reason=None, bfd_sessions_up=0, up_tloc_num=0)
    body["total_devices"] = 40
    api.get("/dataservice/health/devices").respond(json=body)
    out = await call("catsdwan_device_health", {"health": "poor", "response_format": "json"})
    br2 = by_host(out["results"])["br2"]
    assert br2["reason"] == "reachability unreachable; BFD sessions up 0/8; TLOCs up 0/2"
    assert out["partial"] == "the Manager returned 6 of 40 device health records"


async def test_device_health_computed_without_health_api(api: respx.MockRouter) -> None:
    api.get("/dataservice/health/devices").respond(404, json={"error": {"message": "Not found"}})
    api.get("/dataservice/device").respond(json=device_body(br2="unreachable"))
    counters = fixture("device_counters")
    for c in counters["data"]:
        if c["system-ip"] == "10.0.0.1":
            c["bfdSessionsDown"] = 2
        if c["system-ip"] == "10.0.0.3":
            c["number-vsmart-control-connections"] = 0
    api.get("/dataservice/device/counters").respond(json=counters)
    out = await call("catsdwan_device_health", {"response_format": "json"})
    assert out["source"].startswith("computed")
    rows = by_host(out["results"])
    assert out["results"][0]["host"] == "br2" and rows["br2"]["health"] == "poor"
    assert rows["br2"]["reason"] == "reachability unreachable; controller connections 0/2"
    assert rows["hub1"]["health"] == "fair" and rows["hub1"]["reason"] == "BFD sessions down: 2"
    assert rows["br1"]["health"] == "good" and rows["br1"]["control"] == "2/2"
    assert out["counts"] == {"poor": 1, "fair": 1, "good": 4}


async def test_device_health_markdown(api: respx.MockRouter) -> None:
    api.get("/dataservice/health/devices").respond(json=fixture("health_devices"))
    text = await call("catsdwan_device_health", {"health": "poor"})
    assert "| validator | validator | 1.1.1.2 | 1 | poor |" in text


# --- shaping helpers -----------------------------------------------------------------------------


def test_config_mode() -> None:
    assert config_mode(None) == (None, None)
    assert config_mode({"configOperationMode": "cli", "managed-by": "Config-Group g1"}) == (
        "configuration group",
        "g1",
    )
    assert config_mode({"configOperationMode": "cli", "managed-by": "Unmanaged"}) == ("cli", None)
    assert config_mode({"configOperationMode": "vmanage", "template": "t1"}) == ("template", "t1")
    assert config_mode({"configOperationMode": "vmanage"}) == ("template", None)


def test_iso_and_shapes() -> None:
    assert iso(1792738778799) == "2026-10-23T06:59:38Z"
    assert iso("x") is None and iso(0) is None and iso(True) is None
    assert system_status([]) == {}
    down = {
        "ifname": "Gi9",
        "vpn-id": "10",
        "if-admin-status": "if-state-down",
        "if-oper-status": "if-oper-state-down",
    }
    assert interfaces([down]) == [{"name": "Gi9", "vpn": "10", "admin": "down", "oper": "down"}]
    rows = fixture("device_reboothistory_br1")["data"]
    older = {
        **rows[0],
        "reload-time": "2026-10-01T00:00:00+00:00",
        "reload-time-date": 1,
        "reload-desc": "old",
    }
    assert [r["reason"] for r in reboots([older, *rows])] == ["factory-reset", "old"]
    hub = health_row({"name": "x", "health": "gray"})
    assert hub == {"host": "x", "health": "gray"}


def test_fixture_bodies_are_untouched_by_edits() -> None:
    vedges_body(br2={"validity": "staging"})
    assert json.dumps(fixture("system_device_vedges")).count('"staging"') == 0
