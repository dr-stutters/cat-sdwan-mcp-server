"""W23: edge security status and events.

Recorded on 20.18.3.1 (the lab has no security policy): UTD engine status and IPS events with no rows, the
UTD version status (image supported, recommended version), the zone-based firewall statistics (one empty
record) and drop counters (every counter "0"), an empty security-policy list. The bodies with data (a running
UTD engine, zone pairs, a SIG tunnel, IPS, URL and connection records) are hand-built from the field names the
same Manager lists in each response header, and marked so. #126: br1's zone-pair statistics with the W47 drop
rule active (2026-10-25, columns trimmed) are recorded (device_policy_zonepairstatistics_br1).
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.security import (
    EMBEDDED_PROFILES_PATH,
    STATUS_PATHS,
    aggregate,
    drop_check,
    nonzero_drops,
    records,
    zone_pair_rows,
)

from .conftest import fixture
from .test_inventory import call, mock_inventory

BR1 = "10.0.0.2"
EMPTY: dict[str, Any] = {"data": []}

ENGINE = {  # hand-built: a running UTD engine
    "vdevice-name": BR1,
    "vdevice-host-name": "br1",
    "utd-engine-status-version": "1.0.13_SV3.1.67.0_XE17.18",
    "utd-engine-status-profile": "Low",
    "utd-engine-status-status": "utd-oper-status-green",
    "utd-engine-status-memory-usage": "6.40",
    "utd-engine-status-memory-status": "utd-oper-status-green",
}
ZONE_PAIR = {  # hand-built
    "vdevice-name": BR1,
    "zonepair-name": "ZP_lan_wan",
    "src-zone-name": "lan",
    "dst-zone-name": "wan",
    "policy-name": "fw-branch",
    "class-name": "seq-11-cm_",
    "class-action": "Inspect",
    "pkts-counter": "1200",
    "bytes-counter": "880000",
    "current-active-conn": "4",
    "attempted-conn": "52",
}
SIG = {  # hand-built: an Umbrella tunnel that is down
    "vdevice-name": BR1,
    "tunnel-name": "ipsec1",
    "provider": "Umbrella",
    "destination-data-center": "primary-dc",
    "sig-state": "Down",
    "tracker-state": "down",
}


def mock_status(api: respx.MockRouter, **tables: Any) -> dict[str, respx.Route]:
    """Every real-time security table of br1 (empty unless given), the recorded UTD version status and
    zone-based firewall tables, and the Manager's (recorded, empty) security-policy lists."""
    recorded = {
        "utd_engine": fixture("device_utd_engine_status_br1"),
        "utd_version": fixture("device_utd_version_status_br1"),
        "zbfw_statistics": fixture("device_policy_zbfwstatistics_br1"),
        "zbfw_drops": fixture("device_policy_zbfwdropstatistics_br1"),
    }
    routes = {}
    for key, path in STATUS_PATHS.items():
        body = tables.get(key, recorded.get(key, EMPTY))
        routes[key] = api.get(path, params={"deviceId": BR1}).respond(json=body)
    api.get("/dataservice/template/policy/security").respond(
        json=tables.get("legacy", fixture("template_policy_security"))
    )
    api.get(EMBEDDED_PROFILES_PATH).respond(json=tables.get("embedded", []))
    return routes


# --- catsdwan_security_status --------------------------------------------------------------------


async def test_security_status_no_policy_says_so(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_status(api)
    out = await call("catsdwan_security_status", {"device": "br1"})
    assert out["device"] == "br1" and out["security_policies"] == "none"
    assert out["features"] == {
        "utd": False,
        "zone_based_firewall": False,
        "ssl_proxy": False,
        "sig_tunnels": False,
    }
    assert out["verdict"].startswith("No security policy: the Manager has no security policy")
    assert "Nothing on this edge inspects or blocks traffic" in out["verdict"]
    # The recorded version status: the image is not supported yet, the recommended one is named.
    assert out["utd"]["image"]["image_supported"] is False
    assert out["utd"]["image"]["recommended_image"].endswith("_XE17.18")
    assert "zone_based_firewall" not in out and "errors" not in out


async def test_security_status_running_stack_with_attention(api: respx.MockRouter) -> None:
    mock_inventory(api)
    drops = fixture("device_policy_zbfwdropstatistics_br1")
    drops["data"][0]["policy-action-drop"] = "17"
    drops["data"][0]["l4-tcp-syn-flood-drop"] = "3"
    mock_status(
        api,
        utd_engine={"data": [ENGINE]},
        zone_pairs={"data": [ZONE_PAIR]},
        zbfw_drops=drops,
        sig_tunnels={"data": [SIG]},
        legacy={"data": [{"policyName": "sec-branch", "devicesAttached": 1}]},
    )
    out = await call("catsdwan_security_status", {"device": "10.0.0.2"})
    assert out["security_policies"] == ["sec-branch (security policy, on 1 device(s))"]
    assert out["features"] == {
        "utd": True,
        "zone_based_firewall": True,
        "ssl_proxy": False,
        "sig_tunnels": True,
    }
    [engine] = out["utd"]["engine"]
    assert engine["status"] == "green" and engine["profile"] == "Low"
    fw = out["zone_based_firewall"]
    assert fw["zone_pairs"][0]["packets"] == 1200 and fw["zone_pairs"][0]["action"] == "Inspect"
    assert fw["drops"] == {"policy-action-drop": 17, "l4-tcp-syn-flood-drop": 3}
    assert out["sig_tunnels"][0]["state"] == "Down"
    verdict = out["verdict"]
    assert verdict.startswith("br1 runs utd, zone based firewall, sig tunnels; attention:")
    assert "policy-action-drop 17" in verdict and "SIG tunnel ipsec1 is Down" in verdict


async def test_security_status_w47_drop_rule_on_the_recorded_shape(api: respx.MockRouter) -> None:
    # #126, recorded on br1 (20.18.3.1, 2026-10-25) with the W47 rule dropping bob's ICMP: 9 policy drops in
    # zbfwdropstatistics (= the edge's 'Policy drop:classify result'), the drop class listed once per match.
    mock_inventory(api)
    drops = fixture("device_policy_zbfwdropstatistics_br1")
    drops["data"][0]["policy-action-drop"] = "9"
    mock_status(api, zone_pairs=fixture("device_policy_zonepairstatistics_br1"), zbfw_drops=drops)
    fw = (await call("catsdwan_security_status", {"device": BR1}))["zone_based_firewall"]
    drop, default = fw["zone_pairs"]
    assert drop["class"].startswith("mcp-w8-br1-fw-seq-drop-bob") and drop["action"] == "Drop"
    assert drop["packets"] == 9 and len(drop["matches"]) == 2
    assert default["class"] == "class-default" and default["packets"] == 52 and "matches" not in default
    assert fw["dropped_by_policy"] == 9 and fw["drop_class_packets"] == 9 and "note" not in fw


def test_drop_check_flags_class_counters_behind_the_data_plane() -> None:
    # The live finding: right after bob's pings the drop class read 0 while the data plane had counted them.
    rows = fixture("device_policy_zonepairstatistics_br1")["data"]
    for r in rows:
        if r["class-action"] == "Drop":
            r["pkts-counter"] = "0"
    pairs = zone_pair_rows(records(rows))
    out = drop_check(pairs, {"policy-action-drop": 4})
    assert out["dropped_by_policy"] == 4 and out["drop_class_packets"] == 0
    assert "refreshed later" in out["note"]
    # Summing the raw per-match rows would have counted the class twice.
    assert drop_check(
        zone_pair_rows(records(fixture("device_policy_zonepairstatistics_br1")["data"])), {}
    ) == {
        "dropped_by_policy": 0,
        "drop_class_packets": 9,
    }


async def test_security_status_policy_not_on_this_edge_and_failed_section(api: respx.MockRouter) -> None:
    mock_inventory(api)
    routes = mock_status(
        api,
        embedded=[{"profileName": "ngfw-profile"}],
        zbfw_drops=EMPTY,
        zbfw_statistics=EMPTY,
    )
    routes["ssl_proxy"].respond(400, json={"error": {"message": "Device data error", "code": "DEV0001"}})
    out = await call("catsdwan_security_status", {"device": "br1"})
    assert out["security_policies"] == ["ngfw-profile (embedded-security profile)"]
    assert "none runs on br1" in out["verdict"]
    [err] = out["errors"]
    assert err.startswith("ssl_proxy: GET /dataservice/device/sslproxy/status failed")


async def test_security_status_refuses_unreachable_edge(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br1": "unreachable"})
    routes = mock_status(api)
    with pytest.raises(ToolError, match="reports br1 unreachable"):
        await call("catsdwan_security_status", {"device": "br1"})
    assert routes["utd_engine"].call_count == 0


# --- catsdwan_security_events --------------------------------------------------------------------


def mock_index(api: respx.MockRouter, path: str, rows: list[dict[str, Any]]) -> respx.Route:
    def answer(request: httpx.Request) -> httpx.Response:
        body = (
            fixture("statistics_ipsalert") if not rows else {"data": rows, "pageInfo": {"count": len(rows)}}
        )
        return httpx.Response(200, json=body)

    return api.post(path).mock(side_effect=answer)


def ips(sid: int, src: str, action: str = "drop", device: str = BR1) -> dict[str, Any]:
    return {  # hand-built ipsalert record
        "vdevice_name": device,
        "host_name": "br1" if device == BR1 else "hub1",
        "entry_time": 1792758000000,
        "sid": sid,
        "gid": 1,
        "message": f"TEST signature {sid}",
        "classification": "Potentially Bad Traffic",
        "priority": 2,
        "action": action,
        "src_ip": src,
        "dst_ip": "10.61.100.10",
    }


async def test_security_events_none_with_no_policy(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_status(api)
    route = mock_index(api, "/dataservice/statistics/ipsalert", [])
    out = await call("catsdwan_security_events", {"kind": "ips", "device": "br1", "response_format": "json"})
    assert out["results"] == [] and out["records"] == 0 and out["scope"] == "br1"
    assert out["note"].startswith("No security policy: the Manager has no security policy")
    assert "none is expected" in out["note"]
    query = json.loads(route.calls[0].request.content)["query"]
    assert query["rules"][0]["operator"] == "last_n_hours" and query["rules"][0]["value"] == ["24"]
    assert query["rules"][1] == {"value": [BR1], "field": "vdevice_name", "type": "string", "operator": "in"}


async def test_security_events_ips_by_signature(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rows = [ips(1000001, "10.61.200.10"), ips(1000001, "10.61.200.11"), ips(2000002, "10.61.200.10", "alert")]
    route = mock_index(api, "/dataservice/statistics/ipsalert", rows)
    out = await call(
        "catsdwan_security_events", {"kind": "ips", "site": "200", "hours": 4, "response_format": "json"}
    )
    first, second = out["results"]
    assert first["signature"] == "1:1000001" and first["hits"] == 2 and first["actions"] == {"drop": 2}
    assert first["edges"] == {"br1": 2} and first["top_sources"] == ["10.61.200.10", "10.61.200.11"]
    assert second["signature"] == "1:2000002" and second["actions"] == {"alert": 1}
    assert out["records"] == 3 and "note" not in out
    query = json.loads(route.calls[0].request.content)["query"]
    assert query["rules"][0]["value"] == ["4"] and query["rules"][1]["value"] == [BR1]


async def test_security_events_connections_and_url() -> None:
    hosts = {BR1: "br1"}
    conns = [  # hand-built sul/connections records
        {"vdevice_name": BR1, "fw_policy": "fw-branch", "fw_zone_pair": "ZP_lan_wan", "fw_action": "drop",
         "fw_drop_reason": "policy-action-drop", "application": "ssh"},
        {"vdevice_name": BR1, "fw_policy": "fw-branch", "fw_zone_pair": "ZP_lan_wan", "fw_action": "drop",
         "fw_drop_reason": "policy-action-drop", "application": "telnet"},
        {"vdevice_name": BR1, "fw_policy": "fw-branch", "fw_zone_pair": "ZP_lan_wan", "fw_action": "inspect"},
    ]  # fmt: skip
    [drop, inspect] = aggregate("connection", conns, hosts, keep=10)
    assert drop["connections"] == 2 and drop["drop_reason"] == "policy-action-drop"
    assert drop["applications"] == ["ssh", "telnet"] and inspect["action"] == "inspect"
    urlf = [  # hand-built urlf records (counters per stat cycle)
        {
            "vdevice_name": BR1,
            "category_action_block": "3",
            "reputation_action_block": "1",
            "action": "block",
        },
        {"vdevice_name": BR1, "category_action_block": "2", "category_action_pass": "40"},
    ]
    [edge] = aggregate("url", urlf, hosts, keep=10)
    assert edge == {
        "edge": "br1",
        "records": 2,
        "category_action_block": 5,
        "reputation_action_block": 1,
        "category_action_pass": 40,
        "action_block": 1,
    }


async def test_security_events_device_and_site_together_refused(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="not both"):
        await call("catsdwan_security_events", {"kind": "dns", "device": "br1", "site": "200"})


def test_records_drop_empty_and_counters() -> None:
    assert records(fixture("device_policy_zbfwstatistics_br1")["data"]) == []
    assert nonzero_drops(records(fixture("device_policy_zbfwdropstatistics_br1")["data"])) == {}
