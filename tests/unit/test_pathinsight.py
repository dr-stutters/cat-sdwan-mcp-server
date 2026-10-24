"""W19: Network Wide Path Insight.

Recorded on 20.18.3.1: the trace history (the Manager's built-in demo trace 16, two edges vm5/vm6 at sites
500/600), its finished flows (five of 491: bing over LTE with a TailDrop, DNS, a FirewallL4 drop with a TCP
reset), the empty task history and preloadinfo. The trace start and stop answers follow the spec's examples
(no trace was started on the lab).
"""

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import pathinsight as pi
from cat_sdwan_mcp.tools import pathinsight as pi_tools

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

STOP = "/dataservice/stream/device/nwpi/trace/stop/48"
START_OK = {
    "action": "success",
    "trace-id": 48,
    "trace-name": "t",
    "state": "running",
    "entry_time": 1792760000000,
    "traces": [{"device-ip": "10.0.0.2", "status": "success", "message": "Device Trace Start initiated"}],
}
STOP_OK = {"action": "success", "trace-id": "48", "state": "stopping", "message": "Trace Stop initiated"}


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pi_tools, "POLL_INTERVAL", 0.0)
    clock = iter(range(0, 10_000, 4))  # every reading of the wait's clock moves it 4 s on
    monkeypatch.setattr(pi_tools, "_now", lambda: float(next(clock)))


async def run(server: Any, name: str, args: dict[str, Any]) -> Any:
    result = await server.call_tool(name, args)
    return result.structured_content


def writes() -> Any:
    return make_server(mcp_enable_writes=True)


# --- helpers -------------------------------------------------------------------------------------


def test_flow_rows_from_the_demo_trace() -> None:
    rows = pi.sort_flows([pi.flow_row(f) for f in pi.flows_of(fixture("nwpi_fin_flows_demo_trim"))])
    assert [r["flow_id"] for r in rows][:2] == [18, 53]  # the two with drops first
    bing = rows[0]
    assert bing["flow"] == "10.20.24.112:55938 -> 10.20.35.103:443 TCP" and bing["app"] == "bing"
    assert bing["upstream"].startswith("vm5 (Gi5) -> vm6 (LTE/LTE)")
    assert bing["drops"] == ["vm5 (Gi5) -> vm6: local 2.86%, TailDrop x1"]
    assert bing["issues"] == ["QoS congestion (queue drops)"]
    assert "vm5: routing -> sdwan session via lte" in bing["decisions"]
    assert "app_route+demo_policy" in bing["policies"]
    fw = rows[1]
    assert "FirewallL4 x1" in fw["drops"][0] and "the TCP flow was reset" in fw["issues"]
    hop = bing["upstream_hops"][0]
    assert hop["encap"] == "IPSEC" and hop["latency"] == 182272.0
    summary = pi.flow_summary(rows)
    assert summary == {"flows": 5, "with_drops": 2, "with_issues": 2, "upstream_colours": {"LTE/LTE": 5}}


def test_trace_and_task_rows() -> None:
    row = pi.trace_row(fixture("nwpi_trace_history")["data"][0])
    assert row["trace_id"] == 16 and row["name"] == "nwpi_demo_example1" and row["site"] == "500"
    assert row["filter"] == "to 10.0.0.0/8" and row["duration_min"] == "10"
    assert "172.16.255.15 (completed)" in row["devices"]
    task = pi.task_row(
        {
            "taskId": 4,
            "taskName": "auto_on",
            "events": ["qos-congestion"],
            "sites": ["100"],
            "state": "active",
            "startTime": 1716795311226,
            "duration": "600",
        }
    )
    assert task["events"] == "qos-congestion" and task["started"].startswith("2024-05-27")


def test_start_body_is_the_ui_shape() -> None:
    dev = {"system_ip": "10.0.0.2", "chassis": "C8K-1", "version": "17.18.02.0.4112"}
    body = pi.start_body(
        site="200",
        devices=[dev],
        vpns=[10],
        duration=5,
        source=None,
        destination=pi.prefix("10.61.201.10"),
        app=None,
        protocol="1",
        dscp=46,
        name="t",
    )
    assert body["vpn-id"] == "10" and body["dst-pfx"] == "10.61.201.10/32" and body["dscp"] == "46"
    assert body["device-list"] == [
        {"local-system-ip": "10.0.0.2", "deviceId": "10.0.0.2", "uuid": "C8K-1", "version": "17.18.02.0.4112"}
    ]
    assert body["source-site-version"] == "17.18" and body["traceModel"] == "SDWAN_MANUAL"
    assert "src-pfx" not in body and "app" not in body
    two = pi.start_body(
        site="200",
        devices=[dev],
        vpns=[10, 20],
        duration=5,
        source=None,
        destination=None,
        app=None,
        protocol=None,
        dscp=None,
        name="t",
    )
    assert two["vpn-list"] == ["10", "20"] and "vpn-id" not in two
    with pytest.raises(ValueError):
        pi.prefix("not-an-ip")


# --- catsdwan_list_path_traces -------------------------------------------------------------------


async def test_list_path_traces(api: respx.MockRouter) -> None:
    mock_inventory(api)
    hist = api.get(pi.TRACE_HISTORY_PATH).respond(json=fixture("nwpi_trace_history"))
    api.get(pi.TASK_HISTORY_PATH).respond(json=fixture("nwpi_task_history"))
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_list_path_traces", {})
    assert out["total"] == 1 and out["results"][0]["name"] == "nwpi_demo_example1" and out["tasks"] == "none"
    params = hist.calls[0].request.url.params
    assert int(params["endTime"]) - int(params["startTime"]) == 7 * 24 * 3600 * 1000


async def test_read_one_trace_flows(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json=fixture("nwpi_trace_history"))
    flows = api.get(pi.FIN_FLOWS_PATH).respond(json=fixture("nwpi_fin_flows_demo_trim"))
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_list_path_traces", {"trace_id": 16, "limit": 2})
        with pytest.raises(ToolError, match="No path insight trace 99"):
            await c.call_tool("catsdwan_list_path_traces", {"trace_id": 99})
    assert flows.calls[0].request.url.params["timestamp"] == "1751414771255"
    assert out["summary"]["flows"] == 5 and out["returned"] == 2 and out["total"] == 5
    assert out["results"][0]["drops"] and out["trace"]["trace_id"] == 16


# --- catsdwan_path_insight -----------------------------------------------------------------------

DATASTREAM_ON = {"data": [{"enable": True, "ipType": "systemIp", "serverHostName": "systemIp", "vpn": 0}]}


async def test_path_insight_preview_then_trace_and_stop(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    api.get(pi.DATASTREAM_PATH).respond(json=DATASTREAM_ON)
    start = api.post(pi.TRACE_START_PATH).respond(json=START_OK)
    api.get(pi.FIN_FLOWS_PATH).mock(
        side_effect=[
            respx.MockResponse(json={"data": []}),
            respx.MockResponse(json=fixture("nwpi_fin_flows_demo_trim")),
        ]
    )
    stop = api.post(STOP).respond(json=STOP_OK)
    args = {"site": "200", "vpn": [10], "destination": "10.61.201.10", "protocol": "tcp", "wait_seconds": 30}
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_path_insight", args)
        assert prev["status"] == "preview" and not start.called
        assert [e["host"] for e in prev["preview"]["edges"]] == ["br1"] and prev["blast_radius"] == 1
        assert prev["preview"]["filter"] == {"vpn": [10], "destination": "10.61.201.10/32", "protocol": "6"}
        done = await run(c, "catsdwan_path_insight", {**args, "confirm": prev["confirm"]})
    body = json.loads(start.calls[0].request.content)
    assert body["source-site"] == "200" and body["device-list"][0]["deviceId"] == "10.0.0.2"
    assert body["protocol"] == "6"
    res = done["result"]
    assert res["trace_id"] == "48" and res["stopped"] == "stopping" and stop.called
    assert res["summary"]["flows"] == 5


async def test_path_insight_stops_even_when_the_read_fails(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    api.get(pi.DATASTREAM_PATH).respond(json=DATASTREAM_ON)
    api.post(pi.TRACE_START_PATH).respond(json=START_OK)
    api.get(pi.FIN_FLOWS_PATH).respond(500, json={"error": {"message": "boom"}})
    stop = api.post(STOP).respond(json=STOP_OK)
    args = {"site": "200", "vpn": [10], "wait_seconds": 10}
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_path_insight", args)
        done = await run(c, "catsdwan_path_insight", {**args, "confirm": prev["confirm"]})
    assert stop.called and "reading the flows failed" in done["result"]["error"]


async def test_path_insight_no_flows_and_keep_running(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    api.get(pi.DATASTREAM_PATH).respond(json=DATASTREAM_ON)
    api.post(pi.TRACE_START_PATH).respond(json=START_OK)
    api.get(pi.FIN_FLOWS_PATH).respond(json={"data": []})
    stop = api.post(STOP).respond(json=STOP_OK)
    args = {"site": "200", "vpn": [10], "wait_seconds": 10, "keep_running": True}
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_path_insight", args)
        done = await run(c, "catsdwan_path_insight", {**args, "confirm": prev["confirm"]})
    assert not stop.called and "trace_id=48" in done["result"]["note"]
    # live 2026-10-24: 0 flows although host-br1 pinged through br1; edges upload to the Data Stream address
    assert "systemIp in VPN 0" in done["result"]["check"]


def test_protocol_filter_numbers() -> None:
    # live 20.18.3: "6" and "17" start a trace; "1" and "ICMP" answer 'Invalid Protocol(...)'
    assert [pi.protocol_number(p) for p in ("tcp", "6", "UDP", " 17 ", None, "")] == [
        "6",
        "6",
        "17",
        "17",
        None,
        None,
    ]
    for bad in ("1", "icmp", "ICMP"):
        with pytest.raises(ValueError, match="TCP \\(6\\) or UDP \\(17\\) only"):
            pi.protocol_number(bad)
    with pytest.raises(ValueError, match="tcp \\(6\\) or udp \\(17\\) only"):
        pi.protocol_number("47")
    assert pi.datastream_target(DATASTREAM_ON) == "systemIp in VPN 0"
    assert pi.datastream_target({"data": [{}]}) is None


async def test_path_insight_refuses_icmp_protocol(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    api.get(pi.DATASTREAM_PATH).respond(json=DATASTREAM_ON)
    start = api.post(pi.TRACE_START_PATH).respond(json=START_OK)
    async with Client(writes()) as c:
        with pytest.raises(ToolError, match="leave protocol out"):
            await c.call_tool("catsdwan_path_insight", {"site": "200", "vpn": [10], "protocol": "1"})
    assert not start.called


async def test_path_insight_blocks_and_refuses(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br1": "unreachable"})
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    api.get(pi.DATASTREAM_PATH).respond(json=DATASTREAM_ON)
    async with Client(writes()) as c:
        blocked = await run(c, "catsdwan_path_insight", {"site": "200", "vpn": [10]})
        with pytest.raises(ToolError, match="No edge is at site '999'"):
            await c.call_tool("catsdwan_path_insight", {"site": "999", "vpn": [10]})
        with pytest.raises(ToolError, match="not at site 200"):
            await c.call_tool("catsdwan_path_insight", {"site": "200", "vpn": [10], "devices": ["br2"]})
    assert blocked["status"] == "blocked" and "unreachable" in blocked["blockers"][0]


async def test_path_insight_blocked_and_refused_without_data_stream(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(pi.TRACE_HISTORY_PATH).respond(json={"data": []})
    ds = api.get(pi.DATASTREAM_PATH).respond(json={"data": [{}]})
    async with Client(writes()) as c:
        blocked = await run(c, "catsdwan_path_insight", {"site": "200", "vpn": [10]})
    assert blocked["status"] == "blocked" and "Data Stream is off" in blocked["blockers"][0]
    # the Manager's own answer when the setting changed after the preview (live 2026-10-24)
    ds.respond(json=DATASTREAM_ON)
    api.post(pi.TRACE_START_PATH).respond(
        json={"state": "enable_datastream", "message": "Data Stream is disabled. Cannot start trace."}
    )
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_path_insight", {"site": "200", "vpn": [10]})
        with pytest.raises(ToolError, match="started no trace: Data Stream is disabled"):
            await c.call_tool(
                "catsdwan_path_insight", {"site": "200", "vpn": [10], "confirm": prev["confirm"]}
            )


async def test_path_insight_needs_writes() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catsdwan_list_path_traces" in names and "catsdwan_path_insight" not in names


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", pi.TRACE_START_PATH),
        ("POST", STOP),
        ("GET", pi.TRACE_HISTORY_PATH),
        ("GET", pi.TASK_HISTORY_PATH),
    ],
)
def test_path_insight_paths_are_in_the_spec(method: str, path: str) -> None:
    from cat_sdwan_mcp._core.spec import build_index
    from cat_sdwan_mcp.spec import match_operation

    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, path)
    assert method in methods
