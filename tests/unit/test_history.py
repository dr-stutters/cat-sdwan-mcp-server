"""W13: SLA history, top applications and the site report.

Recorded on the lab Manager (20.18.3.1): POST /statistics/approute/aggregation with an hourly histogram over
6 hours (96 rows: 24 tunnels x 4 buckets; entryTimeList carries 7 bucket starts). The 09:00 bucket holds the
lab's link scenarios: br1's biz-internet tunnels at about 240 ms and br2's tunnels at about 5% loss, so the
recording itself misses the lab SLA class there. A raw DPI query returned nothing (application visibility is
off in the lab). The DPI aggregation's answer with rows follows
the approute aggregation's shape (not recorded).
"""

import copy
import json
import time
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import history as hist
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.client import last_hours
from cat_sdwan_mcp.spec import match_operation

from .conftest import fixture, make_server
from .test_inventory import mock_inventory
from .test_policy import mock_policies

AGG = "/dataservice/statistics/approute/aggregation"
DPI = "/dataservice/statistics/dpi/aggregation"
T0 = 1792742400000  # the first recorded bucket (08:00Z)
HOUR = 3600 * 1000
SLA = {"name": "mcp-test-sla", "loss_max": 2.0, "latency_max": 150.0, "jitter_max": 50.0}


def aggregation(slow: dict[tuple[str, int], float] | None = None) -> dict[str, Any]:
    """The recorded aggregation; `slow` sets the latency of (tunnel name, bucket index)."""
    body = copy.deepcopy(fixture("statistics_approute_aggregation"))
    for row in body["data"]:
        idx = (row["entry_time"] - T0) // HOUR
        if slow and (row["name"], idx) in slow:
            row["latency"] = slow[(row["name"], idx)]
    return body


def mock_sla_classes(api: respx.MockRouter) -> None:
    api.get("/dataservice/template/policy/list/sla").respond(json=fixture("template_policy_list_sla"))
    api.get("/dataservice/template/policy/definition/approute").respond(
        json=fixture("template_policy_definition_approute")
    )
    api.get("/dataservice/template/policy/vsmart").respond(json=fixture("template_policy_vsmart"))


async def run(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool(name, args, raise_on_error=False)
    if result.is_error:
        return {"error": str(result.content)}
    return result.structured_content


# --- helpers -------------------------------------------------------------------------------------


def test_histogram_body_is_the_recorded_shape() -> None:
    body = hist.histogram_body(last_hours(6), "hour", 1, size=50)
    assert body == {
        "query": {
            "condition": "AND",
            "rules": [{"value": ["6"], "field": "entry_time", "type": "date", "operator": "last_n_hours"}],
        },
        "aggregation": {
            "field": [{"property": "name", "sequence": 1, "size": 50}],
            "histogram": {"property": "entry_time", "type": "hour", "interval": 1, "order": "asc"},
            "metrics": [
                {"property": "latency", "type": "avg"},
                {"property": "loss_percentage", "type": "avg"},
                {"property": "jitter", "type": "avg"},
            ],
        },
    }
    assert hist.granularity(1, "auto") == ("hour", HOUR) and hist.granularity(7, "auto") == ("day", 24 * HOUR)
    assert hist.granularity(7, "hour") == ("hour", HOUR)


def test_tunnel_names_and_series() -> None:
    assert hist.parse_tunnel("10.0.0.3:biz-internet-10.0.0.1:mpls") == (
        "10.0.0.3",
        "biz-internet",
        "10.0.0.1",
        "mpls",
    )
    assert hist.parse_tunnel("10.0.0.1:mpls-10.0.0.2:biz-internet") == (
        "10.0.0.1",
        "mpls",
        "10.0.0.2",
        "biz-internet",
    )
    assert hist.parse_tunnel("nonsense") is None
    data = hist.series(fixture("statistics_approute_aggregation")["data"])
    assert len(data) == 24 and all(len(b) == 4 for b in data.values())
    buckets = data["10.0.0.3:mpls-10.0.0.1:biz-internet"]
    assert [b["ms"] for b in buckets] == [T0, T0 + HOUR, T0 + 2 * HOUR, T0 + 3 * HOUR]


def test_miss_periods_merge_consecutive_buckets() -> None:
    buckets = [
        {"ms": T0 + i * HOUR, "latency_ms": lat, "loss_percent": 0.0, "jitter_ms": 1.0}
        for i, lat in enumerate([10, 320, 180, 10, 400])
    ]
    periods = hist.miss_periods(buckets, SLA, HOUR)
    assert periods == [
        {
            "start": "2026-10-23T09:00:00Z",
            "end": "2026-10-23T11:00:00Z",
            "buckets": 2,
            "worst": "latency 320 ms > 150 ms",
        },
        {
            "start": "2026-10-23T12:00:00Z",
            "end": "2026-10-23T13:00:00Z",
            "buckets": 1,
            "worst": "latency 400 ms > 150 ms",
        },
    ]


def test_per_colour_availability() -> None:
    data = {
        "10.0.0.2:mpls-10.0.0.1:mpls": [
            {"ms": T0, "loss_percent": 0.0, "latency_ms": 5.0, "jitter_ms": 1.0},
            {"ms": T0 + HOUR, "loss_percent": 100.0, "latency_ms": 0.0, "jitter_ms": 0.0},
        ],
        "10.0.0.2:biz-internet-10.0.0.1:mpls": [
            {"ms": T0, "loss_percent": 0.0, "latency_ms": 200.0, "jitter_ms": 1.0},
            {"ms": T0 + HOUR, "loss_percent": 0.0, "latency_ms": 20.0, "jitter_ms": 1.0},
        ],
    }
    out = hist.per_colour(data, SLA, [T0, T0 + HOUR])
    assert out["mpls"]["availability_percent"] == 50.0 and out["mpls"]["buckets_without_traffic"] == 1
    assert out["biz-internet"]["availability_percent"] == 100.0
    assert out["biz-internet"]["sla_missed_percent"] == 50.0
    assert hist.colour_verdict(out["mpls"]).startswith("degraded: available 50.0%")
    assert hist.colour_verdict(out["biz-internet"]).startswith("degraded: missed the SLA")


# --- catsdwan_sla_history ------------------------------------------------------------------------


async def test_sla_history_finds_the_miss_periods(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sla_classes(api)
    slow = {("10.0.0.2:mpls-10.0.0.1:mpls", 1): 320.0, ("10.0.0.2:mpls-10.0.0.1:mpls", 2): 180.0}
    route = api.post(AGG).respond(json=aggregation(slow))
    out = await run(
        "catsdwan_sla_history", {"site": "200", "sla_class": "mcp-test-sla", "response_format": "json"}
    )
    sent = json.loads(route.calls[0].request.content)
    assert sent["aggregation"]["histogram"]["type"] == "hour"
    rules = sent["query"]["rules"]
    assert rules[0] == {"value": ["24"], "field": "entry_time", "type": "date", "operator": "last_n_hours"}
    assert {"value": ["10.0.0.2"], "field": "vdevice_name", "type": "string", "operator": "in"} in rules
    worst = out["results"][0]
    assert worst["host"] == "br1" and worst["local_colour"] == "mpls" and worst["remote"] == "hub1"
    assert worst["missed_buckets"] == 2 and worst["worst_latency_ms"] == 320.0
    periods = {p["tunnel"]: p for p in out["miss_periods"]}
    injected = periods["br1 mpls -> hub1 mpls"]
    assert injected["start"] == "2026-10-23T09:00:00Z" and injected["end"] == "2026-10-23T11:00:00Z"
    assert injected["worst"] == "latency 320 ms > 150 ms" and injected["buckets"] == 2
    # recorded: the satellite scenario on br1 biz-internet at 09:00
    recorded = periods["br1 biz-internet -> hub1 biz-internet"]
    assert recorded["start"] == "2026-10-23T09:00:00Z" and recorded["worst"].startswith("latency 238.167 ms")
    assert out["tunnels_missing"] > 1 and out["sla_class"]["latency_max"] == 150.0


async def test_sla_history_by_app_uses_the_policy_class(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_policies(api)
    api.post(AGG).respond(json=aggregation())
    out = await run("catsdwan_sla_history", {"app": "ftp", "days": 7, "response_format": "json"})
    assert out["sla_class"]["name"] == "Bulk-Data"
    assert (
        "ftp matches sequence 11 of mcp-test-app-route in mcp-test-policy (NOT activated)" in out["judged_by"]
    )
    # Bulk-Data allows 5% loss: only br2's lossy 09:00 bucket misses it
    assert {p["worst"].split(" ")[0] for p in out["miss_periods"]} == {"loss"}
    assert all("br2" in p["tunnel"] for p in out["miss_periods"])
    assert "per day" in out["source"]


async def test_sla_history_one_tunnel_and_a_colour(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = api.post(AGG).respond(json={"data": []})
    out = await run(
        "catsdwan_sla_history", {"tunnel": "br1:biz-internet-hub1:mpls", "response_format": "json"}
    )
    rules = json.loads(route.calls[0].request.content)["query"]["rules"]
    assert [(r["field"], r["value"]) for r in rules[1:]] == [
        ("vdevice_name", ["10.0.0.2"]),
        ("local_color", ["biz-internet"]),
        ("remote_system_ip", ["10.0.0.1"]),
        ("remote_color", ["mpls"]),
    ]
    assert "no app-route statistics" in out["note"] and "metrics only" in out["judged_by"]
    await run("catsdwan_sla_history", {"tunnel": "br1:biz-internet"})
    rules = json.loads(route.calls[1].request.content)["query"]["rules"]
    assert [(r["field"], r["value"]) for r in rules[1:]] == [
        ("vdevice_name", ["10.0.0.2"]),
        ("local_color", ["biz-internet"]),
    ]
    bad = await run("catsdwan_sla_history", {"tunnel": "nowhere"})
    assert "host:colour" in bad["error"]


async def test_sla_history_unknown_class(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sla_classes(api)
    out = await run("catsdwan_sla_history", {"sla_class": "Gold"})
    assert "No SLA class 'Gold'" in out["error"] and "Realtime" in out["error"]


# --- catsdwan_top_applications -------------------------------------------------------------------


async def test_top_applications_says_dpi_is_off(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = api.post(DPI).respond(json=fixture("statistics_dpi_last6h"))
    out = await run("catsdwan_top_applications", {"site": "200", "response_format": "json"})
    assert out["dpi_statistics"] == "none"
    assert out["note"].startswith("No DPI statistics from site 200 in the last 24 h. Application visibility")
    fields = sorted(json.loads(c.request.content)["aggregation"]["field"][0]["property"] for c in route.calls)
    assert fields == ["application", "family"]


async def test_top_applications_shares(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = api.post(DPI)
    route.side_effect = lambda request: respx.MockResponse(
        json={
            "data": [
                {"application": "webex", "octets": 3 * 1024 * 1024, "packets": 3000},
                {"application": "ssl", "octets": 1024 * 1024, "packets": 1000},
            ]
            if json.loads(request.content)["aggregation"]["field"][0]["property"] == "application"
            else [{"family": "audio-video", "octets": 4 * 1024 * 1024, "packets": 4000}]
        }
    )
    out = await run("catsdwan_top_applications", {"response_format": "json"})
    assert out["total"] == "4.0 MB"
    assert out["applications"][0] == {
        "application": "webex",
        "bytes": 3145728,
        "packets": 3000,
        "share_percent": 75.0,
        "volume": "3.0 MB",
    }
    assert out["families"][0]["family"] == "audio-video"


# --- catsdwan_site_report ------------------------------------------------------------------------


async def test_site_report(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.post(AGG).respond(json=aggregation({("10.0.0.2:mpls-10.0.0.1:mpls", 1): 320.0}))
    api.post("/dataservice/alarms").respond(json=fixture("alarms"))
    api.post(DPI).respond(json=fixture("statistics_dpi_last6h"))
    now = int(time.time() * 1000)
    api.get("/dataservice/device/control/connectionshistory", params={"deviceId": "10.0.0.2"}).respond(
        json={
            "data": [
                {"local-color": "mpls", "downtime-date": now - HOUR, "state": "tear_down"},
                {"local-color": "mpls", "downtime-date": now - 2 * HOUR, "state": "tear_down"},
                {"local-color": "biz-internet", "downtime-date": now - 40 * 24 * HOUR},
            ]
        }
    )
    out = await run("catsdwan_site_report", {"site": "200", "days": 1, "response_format": "json"})
    assert out["site"] == "200" and out["window"] == "last 1 day(s), per hour"
    assert [d["host"] for d in out["devices"]] == ["br1"]
    mpls = out["transports"]["mpls"]
    assert mpls["availability_percent"] == 100.0 and mpls["verdict"] == "healthy"
    assert set(out["transports"]) == {"mpls", "biz-internet"}
    assert out["control_connection_drops"] == {"br1": {"mpls": 2}}
    assert isinstance(out["top_alarms"], dict) and out["top_alarms"]
    assert out["top_applications"].startswith("No DPI statistics from site 200")
    assert out["summary"] == "site 200: every transport healthy; 0 of 1 device(s) unreachable now"


async def test_site_report_with_an_sla_class_and_a_failing_section(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sla_classes(api)
    api.post(AGG).respond(json=aggregation({("10.0.0.2:mpls-10.0.0.1:mpls", 1): 320.0}))
    api.post("/dataservice/alarms").respond(500, json={"error": {"message": "statistics database busy"}})
    api.post(DPI).respond(json=fixture("statistics_dpi_last6h"))
    api.get("/dataservice/device/control/connectionshistory", params={"deviceId": "10.0.0.2"}).respond(
        json={"data": []}
    )
    out = await run(
        "catsdwan_site_report",
        {"site": "200", "days": 1, "sla_class": "mcp-test-sla", "response_format": "json"},
    )
    misses = {m["tunnel"]: m for m in out["sla_misses"]}
    assert misses["10.0.0.2:mpls-10.0.0.1:mpls"]["worst"] == "latency 320 ms > 150 ms"
    assert out["transports"]["mpls"]["sla_missed_percent"] > 0
    assert out["top_alarms"].startswith("not read:") and "busy" in out["top_alarms"]
    assert out["control_connection_drops"] == {"br1": "none"}


def test_history_tools_are_reads() -> None:
    tiers = make_server()._stutters_tiers  # type: ignore[attr-defined]
    assert {
        tiers[n].value for n in ("catsdwan_sla_history", "catsdwan_top_applications", "catsdwan_site_report")
    } == {"read"}


@pytest.mark.parametrize("path", [hist.APPROUTE_AGG_PATH, hist.DPI_AGG_PATH])
def test_history_paths_are_in_the_spec(path: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, "POST", path)
    assert "POST" in methods
