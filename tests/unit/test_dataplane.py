"""W4: BFD, tunnel counters, app-route statistics and SLA classes on recorded 20.18.3.1 payloads, and the
query-body paging in the client (the scroll pages are hand-built: the recorded answers fit in one page)."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.client import SdwanApp, last_hours, rule
from cat_sdwan_mcp.dataplane import aggregate_approute, sla_rows, sla_verdict

from .conftest import fixture, make_settings
from .test_inventory import call, mock_inventory

HUB1, BR1, BR2 = "10.0.0.1", "10.0.0.2", "10.0.0.3"
STATS = "/dataservice/statistics/approute"


def rt(api: respx.MockRouter, path: str, ip: str, body: Any, status: int = 200) -> respx.Route:
    return api.get(f"/dataservice/device/{path}", params={"deviceId": ip}).respond(status, json=body)


def body_of(route: respx.Route, call_index: int = 0) -> Any:
    return json.loads(route.calls[call_index].request.content)


# --- client.query: the statistics/alarm/event/audit paging ---------------------------------------


async def test_query_single_recorded_page(api: respx.MockRouter) -> None:
    route = api.post(STATS).respond(json=fixture("statistics_approute"))
    app = SdwanApp(make_settings())
    q = last_hours(1, rule("local_color", ["mpls"]))
    result = await app.query(STATS, q, limit=50)
    await app.aclose()
    assert len(result.rows) == 31 and result.more is False and result.pages == 1
    assert body_of(route) == {
        "query": {
            "condition": "AND",
            "rules": [
                {"value": ["1"], "field": "entry_time", "type": "date", "operator": "last_n_hours"},
                {"value": ["mpls"], "field": "local_color", "type": "string", "operator": "in"},
            ],
        },
        "size": 50,
    }
    assert route.calls[0].request.headers["X-XSRF-TOKEN"] == "csrf-123"


async def test_query_follows_the_scroll_until_the_limit(api: respx.MockRouter) -> None:
    rows = fixture("statistics_approute")["data"]
    first = api.post(STATS).respond(
        json={"data": rows[:10], "pageInfo": {"scrollId": "s1", "hasMoreData": True, "count": 10}}
    )

    def page(request: httpx.Request) -> httpx.Response:
        sid = request.url.params["scrollId"]
        nxt = {"s1": (rows[10:20], "s2", True), "s2": (rows[20:30], "s3", True)}[sid]
        return httpx.Response(
            200, json={"data": nxt[0], "pageInfo": {"scrollId": nxt[1], "hasMoreData": nxt[2]}}
        )

    scroll = api.post(f"{STATS}/page").mock(side_effect=page)
    app = SdwanApp(make_settings())
    result = await app.query(STATS, last_hours(1), limit=25, page_size=10)
    await app.aclose()
    assert len(result.rows) == 25 and result.more is True and result.pages == 3
    assert first.call_count == 1 and scroll.call_count == 2
    assert scroll.calls[1].request.url.params["count"] == "5"
    assert body_of(scroll)["query"] == body_of(first)["query"]


async def test_query_cuts_an_oversized_answer(api: respx.MockRouter) -> None:
    rows = fixture("statistics_approute")["data"]
    api.post(STATS).respond(json={"data": rows, "pageInfo": {"count": 31}})  # /event ignored `size` like this
    app = SdwanApp(make_settings())
    result = await app.query(STATS, last_hours(1), limit=5)
    full = await app.query(STATS, last_hours(1), limit=31, page_size=31)
    await app.aclose()
    assert len(result.rows) == 5 and result.more is True
    assert len(full.rows) == 31 and full.more is True  # a full page without a scroll may hide more


# --- catsdwan_bfd_sessions -----------------------------------------------------------------------


def bfd_with_down(host: str = "hub1", ip: str = HUB1) -> dict[str, Any]:
    body = fixture("device_bfd_sessions_hub1")
    for b in body["data"]:
        b.update({"vdevice-name": ip, "vdevice-host-name": host})
        if b["system-ip"] == BR2 and b["color"] == "biz-internet":
            b["state"] = "down"
            b["transitions"] = 4
    return body


async def test_bfd_sessions_on_a_device_one_colour_down(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "bfd/sessions", HUB1, bfd_with_down())
    rt(api, "bfd/summary", HUB1, fixture("device_bfd_summary_hub1"))
    out = await call("catsdwan_bfd_sessions", {"device": "hub1", "response_format": "json"})
    assert out["total"] == 8 and out["by_state"] == {"down": 2, "up": 6}
    assert out["summary"] == {"total": 8, "up": 8, "max": 8, "flaps": 0}
    assert out["by_colour_pair"]["mpls -> biz-internet"] == "1/2 up"
    assert out["by_colour_pair"]["mpls -> mpls"] == "2/2 up"
    first = out["results"][0]
    assert (first["remote"], first["remote_colour"], first["state"], first["transitions"]) == (
        "br2",
        "biz-internet",
        "down",
        4,
    )
    up = out["results"][-1]
    assert up["site_id"] == 201 or up["site_id"] == 200
    assert up["hello_ms"] == 1000 and up["detect_multiplier"] == 7 and up["encap"] == "ipsec"
    assert up["source"].startswith("10.60.") and up["up_since"].endswith("Z")
    down = await call(
        "catsdwan_bfd_sessions", {"device": "hub1", "state": "not_up", "response_format": "json"}
    )
    assert {(r["local_colour"], r["remote_colour"]) for r in down["results"]} == {
        ("mpls", "biz-internet"),
        ("biz-internet", "biz-internet"),
    }
    br1 = await call(
        "catsdwan_bfd_sessions",
        {"device": "hub1", "remote": "br1", "colour": "mpls", "response_format": "json"},
    )
    assert br1["total"] == 3 and {r["remote"] for r in br1["results"]} == {"br1"}


async def test_bfd_sessions_fabric_from_the_bulk_api(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    bulk = api.get("/dataservice/data/device/state/BFDSessions").respond(
        json={"data": bfd_with_down()["data"], "pageInfo": {"moreEntries": False, "endId": "8"}}
    )
    out = await call("catsdwan_bfd_sessions", {"state": "down", "response_format": "json"})
    assert bulk.call_count == 1 and bulk.calls[0].request.url.params["count"] == "1000"
    assert out["source"].startswith("the Manager's state database") and out["unreachable_edges"] == ["br2"]
    assert [r["host"] for r in out["results"]] == ["hub1", "hub1"]


async def test_bfd_sessions_fabric_falls_back_to_each_edge(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/data/device/state/BFDSessions").respond(404, json={"error": {"message": "no"}})
    rt(api, "bfd/sessions", HUB1, fixture("device_bfd_sessions_hub1"))
    rt(api, "bfd/sessions", BR1, bfd_with_down("br1", BR1))
    rt(api, "bfd/sessions", BR2, {"error": {"message": "Failed to get data", "code": "DEVICE0001"}}, 400)
    out = await call("catsdwan_bfd_sessions", {"response_format": "json", "limit": 100})
    assert "live from the 3 reachable edge(s)" in out["source"] and out["not_read"] == ["br2"]
    assert out["total"] == 16 and out["results"][0]["host"] == "br1"


async def test_bfd_sessions_unreachable_device(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    with pytest.raises(ToolError, match="br2 unreachable"):
        await call("catsdwan_bfd_sessions", {"device": "br2"})


# --- catsdwan_tunnel_stats -----------------------------------------------------------------------


async def test_tunnel_stats(api: respx.MockRouter) -> None:
    mock_inventory(api)
    body = fixture("device_tunnel_statistics_hub1")
    body["data"][0]["rx_pkts"] = 0
    rt(api, "tunnel/statistics", HUB1, body)
    out = await call("catsdwan_tunnel_stats", {"device": "hub1", "response_format": "json"})
    assert out["total"] == 8 and [r["remote"] for r in out["results"]][::4] == ["br1", "br2"]
    t = next(
        r
        for r in out["results"]
        if r["remote"] == "br1" and r["remote_colour"] == "mpls" and r["local_colour"] == "mpls"
    )
    assert t["protocol"] == "ipsec" and t["mtu"] == 1438 and t["tcp_mss"] == 1358
    assert t["source"] == "10.60.1.13:12386" and t["destination"] == "10.60.1.14:12426"
    assert t["tx_packets"] == 1282 and t["tx_bytes"] == 140315 and t["rx_packets"] == 0
    assert out["no_packets_received"] == ["mpls -> br1 mpls"]
    only = await call(
        "catsdwan_tunnel_stats", {"device": "hub1", "remote": "10.0.0.3", "colour": "biz-internet"}
    )
    assert "| hub1 | biz-internet | br2 |" in only and "br1" not in only.split("\n", 2)[2]


# --- catsdwan_app_route_stats --------------------------------------------------------------------


def mock_sla(api: respx.MockRouter) -> None:
    api.get("/dataservice/template/policy/list/sla").respond(json=fixture("template_policy_list_sla"))
    api.get("/dataservice/template/policy/definition/approute").respond(
        json=fixture("template_policy_definition_approute")
    )
    api.get("/dataservice/template/policy/vsmart").respond(json=fixture("template_policy_vsmart"))


async def test_app_route_stats_aggregates_per_tunnel(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = api.post(STATS).respond(json=fixture("statistics_approute"))
    out = await call("catsdwan_app_route_stats", {"limit": 100, "response_format": "json"})
    assert out["total"] == 24 and "31 statistics rows" in out["source"] and "partial" not in out
    assert body_of(route)["query"]["rules"] == [
        {"value": ["1"], "field": "entry_time", "type": "date", "operator": "last_n_hours"}
    ]
    assert body_of(route)["size"] == 10000
    t = next(
        r
        for r in out["results"]
        if (r["host"], r["local_colour"], r["remote"], r["remote_colour"]) == ("hub1", "mpls", "br1", "mpls")
    )
    assert t["samples"] == 2 and t["state"] == "Up" and t["last_seen"].endswith("Z")
    assert "sla_classes" not in t  # only __all_tunnels__, which every tunnel is in
    worst = out["results"][0]
    assert worst["loss_percent"] == max(r.get("loss_percent", 0) for r in out["results"])


async def test_app_route_stats_filters_become_query_rules(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = api.post(STATS).respond(json={"data": [], "pageInfo": {"count": 0}})
    out = await call(
        "catsdwan_app_route_stats",
        {
            "device": "br1",
            "remote": "hub1",
            "colour": "biz-internet",
            "window_hours": 6,
            "response_format": "json",
        },
    )
    assert out["total"] == 0 and "arrive every 10 minutes" in out["note"]
    rules = body_of(route)["query"]["rules"]
    assert rules[0]["value"] == ["6"]
    assert rules[1:] == [
        rule("vdevice_name", [BR1]),
        rule("remote_system_ip", [HUB1]),
        rule("local_color", ["biz-internet"]),
    ]
    await call("catsdwan_app_route_stats", {"site": "100"})
    assert body_of(route, 1)["query"]["rules"][1] == rule("vdevice_name", [HUB1])
    with pytest.raises(ToolError, match="No device is at site '999'"):
        await call("catsdwan_app_route_stats", {"site": "999"})
    with pytest.raises(ToolError, match="not both"):
        await call("catsdwan_app_route_stats", {"site": "100", "device": "hub1"})
    with pytest.raises(ToolError):
        await call("catsdwan_app_route_stats", {"window_hours": 48})


async def test_app_route_stats_sla_verdict_brownout(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sla(api)
    body = fixture("statistics_approute")
    for r in body["data"]:
        if r["vdevice_name"] == BR1 and r["local_color"] == "biz-internet" and r["remote_system_ip"] == HUB1:
            r.update(latency=320, loss_percentage=6.5, jitter=12)
    api.post(STATS).respond(json=body)
    out = await call(
        "catsdwan_app_route_stats", {"sla_class": "MCP-TEST-SLA", "limit": 100, "response_format": "json"}
    )
    assert out["sla_class"] == {
        "name": "mcp-test-sla",
        "loss_max": 2.0,
        "latency_max": 150.0,
        "jitter_max": 50.0,
    }
    assert out["sla_summary"] == {"misses": 2, "meets": 22}
    first = out["results"][0]
    assert (first["host"], first["local_colour"], first["remote"]) == ("br1", "biz-internet", "hub1")
    assert first["sla"] == "misses: loss 6.5% > 2%, latency 320 ms > 150 ms"
    with pytest.raises(ToolError, match="SLA classes: mcp-test-sla, Best-Effort"):
        await call("catsdwan_app_route_stats", {"sla_class": "gold"})


async def test_app_route_stats_realtime(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rt(api, "app-route/statistics", HUB1, fixture("device_app_route_statistics_hub1"))
    out = await call(
        "catsdwan_app_route_stats", {"device": "hub1", "source": "realtime", "response_format": "json"}
    )
    assert out["total"] == 8 and out["source"].startswith("GET /dataservice/device/app-route/statistics")
    t = out["results"][0]
    assert t["buckets"] == 6 and t["host"] == "hub1" and t["remote"] in ("br1", "br2")
    assert t["loss_percent"] == 0.0 and t["sla_class_index"] == "0"
    mpls = await call(
        "catsdwan_app_route_stats",
        {
            "device": "hub1",
            "source": "realtime",
            "colour": "mpls",
            "remote": "br2",
            "response_format": "json",
        },
    )
    assert mpls["total"] == 2
    with pytest.raises(ToolError, match="give `device`"):
        await call("catsdwan_app_route_stats", {"source": "realtime"})


def test_aggregate_and_verdict_helpers() -> None:
    rows = [
        {"vdevice_name": BR1, "local_color": "mpls", "remote_system_ip": HUB1, "remote_color": "mpls",
         "latency": 10, "jitter": 2, "loss_percentage": 0.0, "entry_time": 2, "state": "Up",
         "sla_class_names": "__all_tunnels__,Voice"},
        {"vdevice_name": BR1, "local_color": "mpls", "remote_system_ip": HUB1, "remote_color": "mpls",
         "latency": 30, "jitter": 4, "loss_percentage": 1.0, "entry_time": 1, "state": "Down"},
    ]  # fmt: skip
    [t] = aggregate_approute(rows, {HUB1: "hub1"})
    assert (t["latency_ms"], t["latency_min"], t["latency_max"]) == (20.0, 10.0, 30.0)
    assert t["loss_percent"] == 0.5 and t["state"] == "Up" and t["sla_classes"] == ["Voice"]
    assert sla_verdict({}, {"latency_max": 1}) == "no data"
    assert sla_verdict(t, {"latency_max": 150.0, "loss_max": 1.0}) == "meets"


# --- catsdwan_list_sla_classes -------------------------------------------------------------------


async def test_list_sla_classes(api: respx.MockRouter) -> None:
    mock_sla(api)
    out = await call("catsdwan_list_sla_classes", {"response_format": "json"})
    assert out["total"] == 9 and "warnings" not in out
    custom = out["results"][0]
    assert custom["name"] == "mcp-test-sla" and custom["default"] is False
    assert (custom["loss_max"], custom["latency_max"], custom["jitter_max"]) == (2.0, 150.0, 50.0)
    assert custom["app_route_policies"] == ["mcp-test-app-route"]
    assert custom["centralized_policies"] == ["mcp-test-policy (not activated)"]
    voice = next(r for r in out["results"] if r["name"] == "Voice-And-Video")
    assert voice["default"] is True and voice["latency_max"] == 300.0 and "app_route_policies" not in voice
    only = await call("catsdwan_list_sla_classes", {"name": "voice"})
    assert "| Voice-And-Video | 2.0 | 300.0 | 60.0 | True |" in only


async def test_list_sla_classes_without_policy_reads(api: respx.MockRouter) -> None:
    api.get("/dataservice/template/policy/list/sla").respond(json=fixture("template_policy_list_sla"))
    api.get("/dataservice/template/policy/definition/approute").respond(
        403, json={"error": {"message": "denied"}}
    )
    api.get("/dataservice/template/policy/vsmart").respond(403, json={"error": {"message": "denied"}})
    out = await call("catsdwan_list_sla_classes", {"response_format": "json"})
    assert len(out["warnings"]) == 2 and out["total"] == 9
    assert out["results"][0]["app_route_policies"] == ["00000000-0000-4000-8000-000000000127"]


def test_sla_rows_activated_policy() -> None:
    policies = copy.deepcopy(fixture("template_policy_vsmart")["data"])
    policies[0]["isPolicyActivated"] = True
    rows = sla_rows(
        fixture("template_policy_list_sla")["data"],
        fixture("template_policy_definition_approute")["data"],
        policies,
    )
    assert rows[0]["centralized_policies"] == ["mcp-test-policy (activated)"]
    assert sla_rows([{"name": "x", "entries": []}])[0] == {"name": "x", "default": False}
