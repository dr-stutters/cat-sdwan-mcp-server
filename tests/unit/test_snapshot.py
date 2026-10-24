"""W46: catsdwan_snapshot / catsdwan_compare_snapshot (core snapshot contract) on recorded 20.18.3.1 payloads.

hub1's control connections, BFD sessions and app-route statistics, br1's OMP peers (recorded 2026-10-24, one
vsmart peer and no route counts; re-hosted as hub1 here), the SLA classes (mcp-test-sla is the one an
app-route policy references) and the alarm log. The degraded state is hub1's mpls tunnel to br2's mpls going
down, as when br2's mpls link stops: BFD down, the tunnel's statistics Down with 100 % loss and a new major
BFD alarm on hub1.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp._core.snapshot import MAX_CHARS, Snapshot, compare, digest
from cat_sdwan_mcp.snapshot import (
    add,
    alarm_items,
    alarm_key,
    approute_items,
    newest_per_tunnel,
    sla_misses,
)

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

HUB1, BR1, BR2 = "10.0.0.1", "10.0.0.2", "10.0.0.3"
DEV = "/dataservice/device"
STATS = "/dataservice/statistics/approute"
ALARMS = "/dataservice/alarms"
SLA_LIST = "/dataservice/template/policy/list/sla"
DOWN_TUNNEL = "hub1|mpls|br2|mpls"


def omp_peers(host: str, ip: str) -> dict[str, Any]:
    body = fixture("device_omp_peers_br1")
    for p in body["data"]:
        p.update({"vdevice-name": ip, "vdevice-host-name": host})
    return body


def stats_of(ip: str) -> dict[str, Any]:
    body = fixture("statistics_approute")
    body["data"] = [r for r in body["data"] if r["vdevice_name"] == ip]
    return body


def degraded() -> dict[str, Any]:
    """hub1's recorded state with its mpls tunnel to br2's mpls down."""
    bfd = fixture("device_bfd_sessions_hub1")
    for b in bfd["data"]:
        if b["system-ip"] == BR2 and b["local-color"] == "mpls" and b["color"] == "mpls":
            b.update({"state": "down", "transitions": 3, "uptime": "0:00:00:05"})
    stats = stats_of(HUB1)
    newest = max(r["entry_time"] for r in stats["data"])
    down = copy.deepcopy(
        next(
            r
            for r in stats["data"]
            if (r["local_color"], r["remote_system_ip"], r["remote_color"]) == ("mpls", BR2, "mpls")
        )
    )
    down.update(
        {"entry_time": newest + 600_000, "state": "Down", "loss_percentage": 100.0, "latency": 0, "jitter": 0}
    )
    # Every other tunnel reports again in the new cycle, with counters that moved: not a change.
    later = []
    for r in stats["data"]:
        if (r["local_color"], r["remote_system_ip"], r["remote_color"]) == ("mpls", BR2, "mpls"):
            continue
        r2 = copy.deepcopy(r)
        r2.update({"entry_time": newest + 600_000, "tx_pkts": r.get("tx_pkts", 0) + 999, "total": 700})
        later.append(r2)
    stats["data"] = [*stats["data"], *later, down]
    alarms = fixture("alarms")
    new = copy.deepcopy(next(a for a in alarms["data"] if a.get("host_name") == "hub1"))
    new.update(
        {
            "type": "bfd-state-change",
            "rulename": "bfd-state-change",
            "rule_name_display": "BFD_State_Change",
            "severity": "Major",
            "active": True,
            "cleared_time": 0,
            "message": "The BFD session went down",
            "values": [
                {
                    "system-ip": HUB1,
                    "host-name": "hub1",
                    "local-color": "mpls",
                    "remote-color": "mpls",
                    "remote-system-ip": BR2,
                }
            ],
            "entry_time": newest + 700_000,
        }
    )
    alarms["data"] = [new, *alarms["data"]]
    return {"bfd": bfd, "stats": stats, "alarms": alarms}


def mock_site_100(api: respx.MockRouter, state: dict[str, Any] | None = None) -> dict[str, respx.Route]:
    state = state or {}
    mock_inventory(api)
    api.get(f"{DEV}/control/connections", params={"deviceId": HUB1}).respond(
        json=fixture("device_control_connections_hub1")
    )
    api.get(f"{DEV}/bfd/sessions", params={"deviceId": HUB1}).respond(
        json=state.get("bfd") or fixture("device_bfd_sessions_hub1")
    )
    api.get(f"{DEV}/omp/peers", params={"deviceId": HUB1}).respond(json=omp_peers("hub1", HUB1))
    api.get(SLA_LIST).respond(json=fixture("template_policy_list_sla"))
    return {
        "stats": api.post(STATS).respond(json=state.get("stats") or stats_of(HUB1)),
        "alarms": api.post(ALARMS).respond(json=state.get("alarms") or fixture("alarms")),
    }


async def snap(server: Any, site: str = "100") -> dict[str, Any]:
    async with Client(server) as c:
        result = await c.call_tool("catsdwan_snapshot", {"site": site})
    assert result.structured_content is not None
    return result.structured_content


async def compare_tool(server: Any, before: Any, after: Any = None) -> dict[str, Any]:
    args: dict[str, Any] = {"before": before}
    if after is not None:
        args["after"] = after
    async with Client(server) as c:
        result = await c.call_tool("catsdwan_compare_snapshot", args)
    assert result.structured_content is not None
    return result.structured_content


# --- the blob ------------------------------------------------------------------------------------


async def test_snapshot_of_a_site(api: respx.MockRouter) -> None:
    routes = mock_site_100(api)
    blob = await snap(make_server())
    assert blob["snapshot"] == 1 and blob["prefix"] == "catsdwan" and blob["server"] == "cat-sdwan-mcp-server"
    assert blob["scope"] == {"site": "100"} and blob["digest"] == digest(blob)
    assert len(json.dumps(blob)) < MAX_CHARS
    s = blob["sections"]
    assert set(s) == {"alarms", "app_route_sla", "bfd", "control", "devices", "omp"}
    assert not any("error" in sec for sec in s.values())
    assert s["devices"]["items"] == {
        "hub1": {
            "ok": True,
            "state": "reachable",
            "role": "edge",
            "site_id": "100",
            "version": s["devices"]["items"]["hub1"]["version"],
            "certificate": "valid",
            "config_status": "In Sync",
        }
    }
    assert s["control"]["items"] == {
        "hub1|biz-internet|controller": {
            "ok": True,
            "state": "up",
            "peer_type": "controller",
            "remote_colour": "default",
            "protocol": "dtls",
        },
        "hub1|mpls|controller": {
            "ok": True,
            "state": "up",
            "peer_type": "controller",
            "remote_colour": "default",
            "protocol": "dtls",
        },
        "hub1|mpls|manager": {
            "ok": True,
            "state": "up",
            "peer_type": "manager",
            "remote_colour": "default",
            "protocol": "dtls",
        },
    }
    assert len(s["bfd"]["items"]) == 8
    assert s["bfd"]["items"][DOWN_TUNNEL] == {"ok": True, "state": "up", "encap": "ipsec"}
    assert s["omp"]["items"] == {"hub1|controller": {"ok": True, "state": "up", "peer_type": "controller"}}
    assert s["omp"]["metrics"] == {"routes_received": {"better": "higher", "tolerance": 0}}
    sla = s["app_route_sla"]
    assert len(sla["items"]) == 8
    assert sla["items"][DOWN_TUNNEL] == {
        "ok": True,
        "state": "Up",
        "loss_pct": 0,
        "latency_ms": 0,
        "jitter_ms": 0,
    }
    assert sla["metrics"]["latency_ms"] == {"better": "lower", "tolerance": 20}
    # Only hub1's alarms (site 100), grouped by device and type; the minor ones carry no ok.
    assert set(s["alarms"]["items"]) == {
        "hub1|security-new-csr-generated",
        "hub1|security-root-cert-chain-installed",
    }
    assert s["alarms"]["items"]["hub1|security-root-cert-chain-installed"] == {
        "state": "minor",
        "alarm": "Root_Cert_Chain_Installed",
        "count": 2,
    }
    # Nothing volatile in any item.
    text = json.dumps(s)
    for word in ("uptime", "transitions", "entry_time", "up_since", "tx_pkts", "last_seen"):
        assert word not in text
    # The statistics are asked for the site's edges only; active alarms over 7 days.
    stats_query = json.loads(routes["stats"].calls[0].request.content)["query"]
    assert {"value": [HUB1], "field": "vdevice_name", "type": "string", "operator": "in"} in stats_query[
        "rules"
    ]
    alarm_query = json.loads(routes["alarms"].calls[0].request.content)["query"]
    assert alarm_query["rules"][0]["value"] == ["168"]
    assert {"value": ["true"], "field": "active", "type": "boolean", "operator": "equal"} in alarm_query[
        "rules"
    ]


async def test_unchanged_fixture_compares_as_no_change(api: respx.MockRouter) -> None:
    mock_site_100(api)
    server = make_server()
    before = await snap(server)
    after = await snap(server)
    out = await compare_tool(server, before, after)
    assert out["verdict"].startswith("No change")
    assert out["counts"] == {"major": 0, "minor": 0, "info": 0} and not out.get("changes")
    assert out["unchanged_items"] == sum(len(sec["items"]) for sec in before["sections"].values())
    assert "notes" not in out and "integrity" not in out
    # JSON text is accepted as well as the object, and an empty `after` takes a fresh snapshot of the scope.
    fresh = await compare_tool(server, json.dumps(before))
    assert fresh["verdict"].startswith("No change") and fresh["scope"] == {"site": "100"}


async def test_degraded_fixture_names_the_tunnel_and_the_alarm(api: respx.MockRouter) -> None:
    mock_site_100(api)
    server = make_server()
    before = await snap(server)
    mock_site_100(api, degraded())  # the same routes now answer with the degraded state
    out = await compare_tool(server, before)
    majors = {(c["section"], c["item"], c["kind"]) for c in out["changes"] if c["severity"] == "major"}
    assert majors == {
        ("alarms", "hub1|bfd-state-change|mpls|mpls|10.0.0.3", "added"),
        ("app_route_sla", DOWN_TUNNEL, "degraded"),
        ("bfd", DOWN_TUNNEL, "degraded"),
    }
    assert out["counts"] == {"major": 3, "minor": 0, "info": 0}
    what = {c["section"]: c["what"] for c in out["changes"]}
    assert what["bfd"] == f"BFD sessions {DOWN_TUNNEL}: healthy -> unhealthy; state up -> down"
    assert "state Up -> Down" in what["app_route_sla"] and "loss_pct 0 -> 100" in what["app_route_sla"]
    assert out["verdict"] == "3 major changes; " + f"{out['unchanged_items']} items unchanged."


async def test_snapshot_of_the_fabric_from_the_bulk_state(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    br2_stale = copy.deepcopy(fixture("device_bfd_sessions_hub1")["data"][0])
    br2_stale.update({"vdevice-name": BR2, "vdevice-host-name": "br2"})
    api.get("/dataservice/data/device/state/BFDSessions").respond(
        json={
            "data": [*fixture("device_bfd_sessions_hub1")["data"], br2_stale],
            "pageInfo": {"moreEntries": False},
        }
    )
    api.get("/dataservice/data/device/state/ControlConnection").respond(
        json={
            "data": fixture("device_control_connections_controller")["data"],
            "pageInfo": {"moreEntries": False},
        }
    )
    api.get(f"{DEV}/omp/peers", params={"deviceId": "1.1.1.3"}).respond(
        json=fixture("device_omp_peers_controller")
    )
    api.get(SLA_LIST).respond(500, json={"error": {"message": "boom"}})
    api.post(STATS).respond(json=fixture("statistics_approute"))
    api.post(ALARMS).respond(json=fixture("alarms"))
    blob = await snap(make_server(), site="")
    s = blob["sections"]
    assert blob["scope"] == {}
    assert (
        s["devices"]["items"]["br2"]["ok"] is False and s["devices"]["items"]["br2"]["state"] == "unreachable"
    )
    assert len(s["bfd"]["items"]) == 8 and not any(k.startswith("br2|") for k in s["bfd"]["items"])
    # Two connections from the controller to the validator: the second gets '#2'.
    assert {"controller|default|validator", "controller|default|validator#2"} <= set(s["control"]["items"])
    assert all(k.startswith("controller|") for k in s["omp"]["items"])
    # SLA classes unreadable: tunnels judged by state alone.
    assert len(s["app_route_sla"]["items"]) == 24
    assert all(i["ok"] for i in s["app_route_sla"]["items"].values())
    assert "manager|memory-usage" in s["alarms"]["items"]
    assert s["alarms"]["items"]["manager|memory-usage"]["state"] == "major"
    assert s["alarms"]["items"]["manager|memory-usage"]["ok"] is False


async def test_a_failing_read_marks_its_section_unreadable(api: respx.MockRouter) -> None:
    mock_site_100(api)
    server = make_server()
    before = await snap(server)
    api.post(STATS).respond(503, json={"error": {"message": "statistics down"}})
    after = await snap(server)
    assert "statistics" in after["sections"]["app_route_sla"]["error"]
    assert after["sections"]["app_route_sla"]["items"] == {}
    out = await compare_tool(server, before, after)
    assert [(c["severity"], c["kind"], c["section"]) for c in out["changes"]] == [
        ("minor", "unreadable", "app_route_sla")
    ]


async def test_a_device_read_failure_is_named(api: respx.MockRouter) -> None:
    mock_site_100(api)
    api.get(f"{DEV}/omp/peers", params={"deviceId": HUB1}).respond(
        400, json={"error": {"message": "Failed to get data", "code": "DEVICE0001"}}
    )
    blob = await snap(make_server())
    assert "hub1" in blob["sections"]["omp"]["error"]


async def test_unknown_site_and_foreign_blobs_are_refused(api: respx.MockRouter) -> None:
    mock_site_100(api)
    server = make_server()
    with pytest.raises(ToolError, match="No device is at site '999'"):
        await snap(server, site="999")
    other = Snapshot("ise", "ise-mcp-server").blob()
    with pytest.raises(ToolError, match="taken by 'ise'"):
        await compare_tool(server, other)


# --- helpers -------------------------------------------------------------------------------------


def test_newest_per_tunnel_drops_tunnels_that_stopped_reporting() -> None:
    rows = [
        {
            "vdevice_name": HUB1,
            "local_color": "mpls",
            "remote_system_ip": BR1,
            "remote_color": "mpls",
            "entry_time": 1000,
            "loss_percentage": 5,
        },
        {
            "vdevice_name": HUB1,
            "local_color": "mpls",
            "remote_system_ip": BR1,
            "remote_color": "mpls",
            "entry_time": 4_000_000,
            "loss_percentage": 0,
        },
        {
            "vdevice_name": HUB1,
            "local_color": "mpls",
            "remote_system_ip": BR2,
            "remote_color": "mpls",
            "entry_time": 1000,
        },
    ]
    out = newest_per_tunnel(rows)
    assert [(r["remote_system_ip"], r["loss_percentage"]) for r in out] == [(BR1, 0)]
    assert newest_per_tunnel([]) == []


def test_sla_misses_and_items() -> None:
    classes = [
        {"name": "voice", "loss_max": 1, "latency_max": 150, "jitter_max": 30, "app_route_policies": ["p"]},
        {"name": "bulk", "loss_max": 5, "latency_max": 500, "jitter_max": 500},
    ]
    row = {
        "vdevice_name": HUB1,
        "host_name": "hub1",
        "local_color": "mpls",
        "remote_system_ip": BR1,
        "remote_color": "mpls",
        "entry_time": 1,
        "state": "Up",
        "loss_percentage": 2.5,
        "latency": 20,
        "jitter": 3,
        "sla_class_names": "__all_tunnels__,bulk",
    }
    assert sla_misses(row, classes) == ["voice"]
    assert sla_misses({**row, "loss_percentage": 6}, classes) == ["bulk", "voice"]
    snap_ = Snapshot("catsdwan", "cat-sdwan-mcp-server")
    sec = snap_.section("app_route_sla", "App-route SLA")
    approute_items(sec, [row], {BR1: "br1"}, classes)
    assert sec.items == {
        "hub1|mpls|br1|mpls": {
            "ok": False,
            "state": "Up",
            "loss_pct": 2.5,
            "latency_ms": 20,
            "jitter_ms": 3,
            "sla_met": "bulk",
            "sla_missed": "voice",
        }
    }


def test_alarm_grouping_and_keys() -> None:
    alarms = [
        {
            "type": "memory-usage",
            "severity": "Medium",
            "active": True,
            "host_name": "manager",
            "values": [{"host-name": "manager"}],
        },
        {
            "type": "memory-usage",
            "severity": "Major",
            "active": True,
            "host_name": "manager",
            "values": [{"host-name": "manager"}],
        },
        {
            "type": "memory-usage",
            "severity": "Critical",
            "active": False,
            "cleared_time": 5,
            "host_name": "manager",
        },
        {
            "type": "interface-state-change",
            "severity": "Minor",
            "active": True,
            "host_name": "br1",
            "values": [{"host-name": "br1", "if-name": "Gi1"}],
        },
    ]
    assert alarm_key(alarms[3]) == "br1|interface-state-change|Gi1"
    snap_ = Snapshot("catsdwan", "cat-sdwan-mcp-server")
    sec = snap_.section("alarms", "Active alarms")
    alarm_items(sec, alarms)
    assert sec.items == {
        "br1|interface-state-change|Gi1": {"state": "minor", "alarm": "interface-state-change", "count": 1},
        "manager|memory-usage": {"ok": False, "state": "major", "alarm": "memory-usage", "count": 2},
    }


def test_duplicate_keys_get_a_suffix() -> None:
    sec = Snapshot("catsdwan", "cat-sdwan-mcp-server").section("control", "Control connections")
    add(sec, "a|b", ok=True)
    add(sec, "a|b", ok=False)
    assert list(sec.items) == ["a|b", "a|b#2"]


def test_compare_is_core_compare() -> None:
    a = Snapshot("catsdwan", "cat-sdwan-mcp-server", scope={"site": "100"})
    a.section("bfd", "BFD sessions").item("x", ok=True, state="up")
    b = Snapshot("catsdwan", "cat-sdwan-mcp-server", scope={"site": "100"})
    b.section("bfd", "BFD sessions").item("x", ok=False, state="down")
    out = compare(a.blob(), b.blob(), prefix="catsdwan")
    assert out["counts"]["major"] == 1
