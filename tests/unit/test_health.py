"""W22: site, tunnel and interface health and the topology.

Recorded on the lab Manager (20.18.3.1): site health (sites 1 = controllers, 100, 200, 201; apps no_data as
application visibility is off), the site-health trend, /network/status, /health/devices/overview, tunnel
health for site 200, tunnel-health history over 12 h (two poor periods from link scenarios), the interface
aggregation and circuit capacity for br1, and /topology/device/site/200 (config-group intent).
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import health as hl
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

HOSTS = {"10.0.0.1": "hub1", "10.0.0.2": "br1", "10.0.0.3": "br2"}


async def run(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool(
            name, {"response_format": "json", **args} if name != "catsdwan_topology" else args
        )
    return result.structured_content


def overview_with_a_poor_tunnel() -> dict[str, Any]:
    body = copy.deepcopy(fixture("statistics_tunnelhealth_overview"))
    t = body["detail"]["good"].pop(0)
    body["detail"]["poor"] = [
        {**t, "health": "poor", "health_score": 0.0, "latency": 600.0, "loss_percentage": 9.5}
    ]
    body["total"] = {"good": 7, "fair": 0, "poor": 1}
    return body


def mock_health(api: respx.MockRouter) -> dict[str, respx.Route]:
    mock_inventory(api)
    return {
        "site": api.get(hl.SITEHEALTH_PATH).respond(json=fixture("statistics_sitehealth_common")),
        "trend": api.get(hl.SITEHEALTH_TREND_PATH).respond(json=fixture("statistics_sitehealth_topology")),
        "overview": api.get(hl.DEVICE_HEALTH_OVERVIEW_PATH).respond(json=fixture("health_devices_overview")),
        "status": api.get(hl.NETWORK_STATUS_PATH).respond(json=fixture("network_status")),
        "tunnels": api.get(hl.TUNNEL_OVERVIEW_PATH.format(type="health")).respond(
            json=overview_with_a_poor_tunnel()
        ),
        "history": api.get(hl.TUNNEL_HISTORY_PATH).respond(json=fixture("statistics_tunnelhealth_history")),
        "iface": api.post(hl.INTERFACE_AGG_PATH).respond(json=fixture("statistics_interface_aggregation")),
        "capacity": api.get(hl.CAPACITY_PATH).respond(json=fixture("statistics_interface_ccapacity")),
        "qos": api.post(hl.QOS_PATH).respond(json={"header": {}, "pageInfo": {"count": 0}, "data": []}),
        "topo": api.get(hl.SITE_TOPOLOGY_PATH.format(id="200")).respond(json=fixture("topology_site_200")),
    }


# --- helpers -------------------------------------------------------------------------------------


def test_site_rows_and_verdicts() -> None:
    rows = hl.site_rows(fixture("statistics_sitehealth_common"))
    assert rows[0]["site_id"] == "1" and rows[0]["health"] == "poor"
    assert rows[0]["verdict"].startswith("poor: devices poor (score")
    br1 = next(r for r in rows if r["site_id"] == "200")
    assert br1["verdict"] == "good" and br1["tunnels"] == "8 good, 0 fair, 0 poor"
    assert (
        br1["device_names"] == "br1"
        and br1["config_groups"] == "mcp-test"
        and br1["apps_health"] == "no_data"
    )
    fair = hl.site_verdict(
        {
            "site_health": "fair",
            "tunnels_health": "fair",
            "tunnels_health_score": 5,
            "tunnel_summary": {"fair_tunnel_count": 2, "poor_tunnel_count": 1},
        }
    )
    assert fair == "fair: tunnels fair (score 5.0/10); 1 poor and 2 fair tunnel(s)"


def test_network_status_and_trend() -> None:
    status = hl.network_status(fixture("network_status"))
    assert status["vEdge"] == {"total": 3, "normal": 3} and status["vSmart"]["normal"] == 1
    body = {
        "data": [
            {"entry_time": 1, "poor_site_count": 0, "fair_site_count": 0, "good_site_count": 4},
            {"entry_time": 1792747800000, "poor_site_count": 1, "fair_site_count": 0, "good_site_count": 3},
        ]
    }
    assert hl.site_trend(body) == [{"time": "2026-10-23T09:30:00Z", "poor": 1, "fair": 0, "good": 3}]


def test_overview_tunnels_worst_first() -> None:
    totals, rows = hl.overview_tunnels(overview_with_a_poor_tunnel(), HOSTS)
    assert totals == {"good": 7, "fair": 0, "poor": 1}
    assert rows[0]["health"] == "poor" and rows[0]["loss_pct"] == 9.5 and rows[0]["local"] == "br1"
    assert all(r["health"] == "good" for r in rows[1:])


def test_bad_periods_join_consecutive_intervals() -> None:
    half = 30 * 60 * 1000
    hist = [
        {"entry_time": 0, "health": "good", "data": {}},
        {"entry_time": half, "health": "fair", "data": {"loss_percentage": 1.0, "latency": 200}},
        {"entry_time": 2 * half, "health": "poor", "data": {"loss_percentage": 3.0, "latency": 150}},
        {"entry_time": 3 * half, "health": "n/a", "data": {}},
        {"entry_time": 4 * half, "health": "fair", "data": {"loss_percentage": 0.5}},
    ]
    got = hl.bad_periods(hist)
    assert len(got) == 2
    assert got[0]["worst"] == "poor" and got[0]["max_loss_pct"] == 3.0 and got[0]["max_latency_ms"] == 200
    assert got[0]["from"] == "1970-01-01T00:30:00Z" and got[0]["to"] == "1970-01-01T01:30:00Z"


def test_history_rows_recorded() -> None:
    rows = hl.history_rows(fixture("statistics_tunnelhealth_history"), HOSTS)
    assert len(rows) == 4 and all(r["bad_periods"] for r in rows)
    first = rows[0]
    assert (
        first["bad_periods"][0]["worst"] == "poor"
        and first["bad_periods"][0]["from"] == "2026-10-23T09:30:00Z"
    )


def test_interface_body_and_rows() -> None:
    body = hl.interface_body("10.0.0.2", 2, "GigabitEthernet1")
    rules = body["query"]["rules"]
    assert (
        rules[0]["value"] == ["2"]
        and rules[1]["field"] == "vdevice_name"
        and rules[2]["value"] == ["GigabitEthernet1"]
    )
    props = [m["property"] for m in body["aggregation"]["metrics"]]
    assert len(props) == len(set(props))  # one metric per property: the Manager 500s on two
    rows = hl.interface_rows(fixture("statistics_interface_aggregation"))
    assert rows[0]["interface"].startswith("GigabitEthernet") and len(rows) == 11
    tunnel = next(r for r in rows if r["interface"] == "Tunnel1")
    assert tunnel["peak_down_pct"] == 4.0 and tunnel["bw_down_kbps"] == 100
    flags = hl.interface_flags(rows, 3)
    assert "Tunnel1 peaked at 4.0% of its configured bandwidth" in flags
    assert hl.interface_flags([{"interface": "Gi1", "errors": 2, "drops": 0}], 80) == ["Gi1 counted 2 errors"]


def test_capacity_qos_links_and_intent() -> None:
    cap = hl.capacity_rows(fixture("statistics_interface_ccapacity"), "10.0.0.2")
    assert [c["interface"] for c in cap] == ["GigabitEthernet1", "GigabitEthernet2"]
    q = hl.qos_rows(
        [
            {"interface": "Gi1", "queue": "0", "tx_drops": 3, "tx_pkts": 100},
            {"interface": "Gi1", "queue": "0", "tx_drops": 2},
        ]
    )
    assert q == [{"interface": "Gi1", "queue": "0", "tx_drops": 5}]
    _, tunnels = hl.overview_tunnels(overview_with_a_poor_tunnel(), HOSTS)
    links = hl.site_links(tunnels, {"10.0.0.1": "100", "10.0.0.2": "200", "10.0.0.3": "201"})
    assert {lk["sites"] for lk in links} == {"100 <-> 200", "200 <-> 201"}
    assert links[0]["poor"] == 1 and sum(lk["tunnels"] for lk in links) == 8
    intent = hl.site_intent(fixture("topology_site_200"))
    assert intent["10.0.0.2"]["intent"] == "config-group mcp-test"
    assert intent["10.0.0.2"]["profiles"] == ["mcp-test-transport", "mcp-test-system", "mcp-test-cli"]


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("GET", hl.SITEHEALTH_PATH),
        ("GET", hl.SITEHEALTH_TREND_PATH),
        ("GET", hl.DEVICE_HEALTH_OVERVIEW_PATH),
        ("GET", hl.NETWORK_STATUS_PATH),
        ("GET", hl.TUNNEL_OVERVIEW_PATH.format(type="health")),
        ("GET", hl.TUNNEL_HISTORY_PATH),
        ("POST", hl.INTERFACE_AGG_PATH),
        ("GET", hl.CAPACITY_PATH),
        ("POST", hl.QOS_PATH),
        ("GET", hl.SITE_TOPOLOGY_PATH.format(id="200")),
    ],
)
def test_health_paths_are_in_the_spec(method: str, template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, template)
    assert method in methods


# --- tools ---------------------------------------------------------------------------------------


async def test_site_health(api: respx.MockRouter) -> None:
    routes = mock_health(api)
    out = await run("catsdwan_site_health", {"window_hours": 12})
    assert routes["site"].calls.last.request.url.params["includeDetails"] == "true"
    assert out["total"] == 4 and out["results"][0]["site_id"] == "1"
    assert out["fabric"]["vEdge"]["normal"] == 3 and out["device_health"]["good"] == 3
    only = await run("catsdwan_site_health", {"site": "SITE_200"})
    assert [r["site_id"] for r in only["results"]] == ["200"]
    bad = await run("catsdwan_site_health", {"health": "not_good"})
    assert [r["site_id"] for r in bad["results"]] == ["1"]


async def test_site_health_survives_a_failed_side_read(api: respx.MockRouter) -> None:
    routes = mock_health(api)
    routes["status"].respond(500, json={"error": {"message": "Server error", "code": "REST0001"}})
    out = await run("catsdwan_site_health", {})
    assert "network status failed" in out["fabric"]["error"] and out["total"] == 4


async def test_tunnel_health_by_device_and_health(api: respx.MockRouter) -> None:
    routes = mock_health(api)
    out = await run("catsdwan_tunnel_health", {"device": "br1"})
    params = routes["tunnels"].calls.last.request.url.params
    assert params["site"] == "200" and params["last_n_hours"] == "1"
    assert out["totals"]["poor"] == 1 and out["results"][0]["health"] == "poor"
    assert all(r["local"] == "br1" for r in out["results"])
    poor = await run("catsdwan_tunnel_health", {"site": "200", "health": "poor"})
    assert len(poor["results"]) == 1


async def test_tunnel_health_history(api: respx.MockRouter) -> None:
    mock_health(api)
    out = await run("catsdwan_tunnel_health", {"history": True, "window_hours": 12})
    assert out["summary"] == "4 of 4 tunnel(s) were fair or poor at some point in the window"
    assert out["results"][0]["bad_periods"]


async def test_interface_stats(api: respx.MockRouter) -> None:
    routes = mock_health(api)
    out = await run(
        "catsdwan_interface_stats", {"device": "br1", "busy_pct": 3, "capacity": True, "qos": True}
    )
    sent = json.loads(routes["iface"].calls.last.request.content)
    assert {"value": ["10.0.0.2"], "field": "vdevice_name", "type": "string", "operator": "in"} in sent[
        "query"
    ]["rules"]
    assert out["total"] == 11 and any("Tunnel2 peaked" in a for a in out["attention"])
    assert routes["capacity"].calls.last.request.url.params["site-id"] == "200"
    assert out["capacity"][0]["interface"] == "GigabitEthernet1"
    assert "no QoS statistics" in out["qos"]


async def test_topology(api: respx.MockRouter) -> None:
    routes = mock_health(api)
    out = await run("catsdwan_topology", {})
    assert {s["site_id"] for s in out["sites"]} >= {"100", "200", "201"}
    assert {lk["sites"] for lk in out["site_links"]} == {"100 <-> 200", "200 <-> 201"}
    assert not routes["topo"].called
    one = await run("catsdwan_topology", {"site": "200"})
    assert [s["site_id"] for s in one["sites"]] == ["200"]
    br1 = one["sites"][0]["devices"][0]
    assert br1["host"] == "br1" and br1["intent"] == "config-group mcp-test"
    assert all("200" in lk["sites"] for lk in one["site_links"])
