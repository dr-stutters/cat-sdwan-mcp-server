"""W17: on-box troubleshooting.

Recorded on 20.18.3.1: the bring-up checklist and control check of br1 (joined) and of a never-joined slot,
the admin-tech list (empty) and in-progress count. Ping, traceroute and flow simulation are POSTs that were
not run against the lab: their answers here follow the spec's response schema and the Manager UI's template;
their request bodies are the ones the UI sends.
"""

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import troubleshooting as ts
from cat_sdwan_mcp.tools import troubleshooting as ts_tools

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

SLOT = "REDACTED-20"  # the first never-joined slot

PING_OK = {
    "packetsTransmitted": 5,
    "packetsReceived": 5,
    "lossPercentage": 0,
    "minRoundTrip": 1.1,
    "avgRoundTrip": 2.2,
    "maxRoundTrip": 3.3,
    "rawOutput": ["Type escape sequence to abort.", "!!!!!", "Success rate is 100 percent (5/5)"],
}
PING_LOST = {"packetsTransmitted": 5, "packetsReceived": 0, "lossPercentage": 100, "rawOutput": ["....."]}
TRACE = {
    "nexthops": [
        {"hopNumber": "1", "ipAddress": "10.61.201.1", "hopName": "10.61.201.1", "meanLatency": "2.1"},
        {"hopNumber": "2", "ipAddress": "10.61.201.10", "hopName": "host-201", "meanLatency": "3.4"},
    ],
    "rawOutput": ["1 10.61.201.1 2 msec", "2 10.61.201.10 3 msec"],
}
FLOW = {
    "status": "success",
    "nexthops": [
        {
            "type": "nh-ipsec",
            "sourceIp": "10.60.1.14",
            "destIp": "10.60.1.15",
            "localColor": "mpls",
            "remoteColor": "mpls",
            "remoteSystemIp": "10.0.0.3",
            "interface": "GigabitEthernet1",
        },
        {
            "type": "nh-ipsec",
            "sourceIp": "10.60.2.14",
            "destIp": "10.60.2.15",
            "localColor": "biz-internet",
            "remoteColor": "biz-internet",
            "remoteSystemIp": "10.0.0.3",
            "interface": "GigabitEthernet2",
        },
    ],
    "aar-policy": {},
    "data-policy": {},
}


async def run(server: Any, name: str, args: dict[str, Any]) -> Any:
    result = await server.call_tool(name, args)
    return result.structured_content


async def call(name: str, args: dict[str, Any], **kw: Any) -> Any:
    async with Client(make_server(**kw)) as c:
        return await run(c, name, args)


# --- helpers -------------------------------------------------------------------------------------


def test_ping_body_is_the_ui_shape() -> None:
    body = ts.ping_body(
        "10.61.201.10",
        10,
        source="GigabitEthernet3",
        count=5,
        size=None,
        rapid=True,
        probe="icmp",
        dest_port=None,
    )
    assert body == {
        "host": "10.61.201.10",
        "vpn": "10",
        "source": "GigabitEthernet3",
        "count": "5",
        "rapid": "true",
    }
    tcp = ts.ping_body(
        "10.61.201.10", 10, source=None, count=3, size=100, rapid=True, probe="tcp", dest_port=443
    )
    assert tcp["probeType"] == "tcp" and tcp["destPort"] == "443" and "source" not in tcp


def test_flow_result_plain_words() -> None:
    out = ts.flow_result(FLOW, {"10.0.0.3": "br2"})
    assert out["verdict"] == "2 tunnel path(s): biz-internet -> br2 (biz-internet); mpls -> br2 (mpls)"
    assert out["next_hops"][0]["type"] == "ipsec" and out["next_hops"][0]["remote_edge"] == "br2"
    dropped = ts.flow_result(
        {**FLOW, "policy-drop-reason": "Data policy drop", "data-policy": {"name": "p1"}}
    )
    assert dropped["verdict"] == "dropped by policy: Data policy drop"
    assert dropped["policies"] == [{"kind": "data", "name": "p1"}]
    hole = ts.flow_result({"nexthops": [{"type": "nh-blackhole"}]})
    assert hole["verdict"].startswith("blackholed")


def test_bringup_steps_for_a_joined_and_a_new_edge() -> None:
    steps, verdict = ts.bringup_steps(fixture("troubleshooting_devicebringup_br1"))
    assert [s["operation"] for s in steps] == ts.BRINGUP_ORDER
    assert verdict == "every bring-up step succeeded"
    steps, verdict = ts.bringup_steps(fixture("troubleshooting_devicebringup_unjoined"))
    assert steps[0]["status"] == "unknown" and "vBond" in steps[0]["step"]
    assert verdict.startswith("stuck at 'Authorized by vBond' (unknown: Unable to find vBond authorization")
    assert "WAN edge list" in verdict


def test_control_check_recorded() -> None:
    out = ts.control_check(fixture("troubleshooting_control_br1"))
    colours = {c["colour"]: c for c in out["colours"]}
    assert set(colours) == {"mpls", "biz-internet"}
    assert colours["mpls"]["connections"] == "1/1" and "problems" not in colours["mpls"]
    assert "controller (vsmart) up" in colours["biz-internet"]["peers"]


def test_admintech_rows_and_progress() -> None:
    assert ts.admintech_rows(fixture("device_tools_admintechs")) == []
    assert ts.in_progress(fixture("device_tools_admintechs_inprogress")) == 0
    rows = ts.admintech_rows(
        {
            "data": [
                {
                    "deviceIP": "10.0.0.2",
                    "fileName": "/home/admin/10.0.0.2-br1-admin-tech.tar.gz",
                    "creationTime": 1792752241087,
                    "size": 1000,
                    "state": "done",
                    "requestTokenId": "r1",
                },
                {"deviceIP": "10.0.0.3", "fileName": "x.tar.gz"},
            ]
        },
        "10.0.0.2",
    )
    assert len(rows) == 1 and rows[0]["file"] == "10.0.0.2-br1-admin-tech.tar.gz"
    assert rows[0]["download"].endswith("/admintech/download/10.0.0.2-br1-admin-tech.tar.gz")


# --- ping / traceroute ---------------------------------------------------------------------------


async def test_ping_br2_lan_host_from_br1(api: respx.MockRouter) -> None:
    mock_inventory(api)
    ping = api.post("/dataservice/device/tools/ping/10.0.0.2").respond(json=PING_OK)
    out = await call("catsdwan_ping", {"device": "br1", "destination": "10.61.201.10", "vpn": 10})
    assert json.loads(ping.calls[0].request.content) == {
        "host": "10.61.201.10",
        "vpn": "10",
        "count": "5",
        "rapid": "true",
    }
    assert out["verdict"] == "10.61.201.10 answered (5/5, 0% loss)" and out["rtt_ms"]["avg"] == 2.2
    assert out["device"] == "br1" and out["raw_output"][-1].startswith("Success rate")


async def test_ping_loss_and_nping(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.post("/dataservice/device/tools/ping/10.0.0.2").respond(json=PING_LOST)
    nping = api.post("/dataservice/device/tools/nping/10.0.0.2").respond(json=PING_OK)
    lost = await call("catsdwan_ping", {"device": "br1", "destination": "10.61.201.99", "vpn": 10})
    tcp = await call(
        "catsdwan_ping",
        {"device": "br1", "destination": "10.61.201.10", "vpn": 10, "probe": "tcp", "dest_port": 443},
    )
    assert lost["verdict"].endswith("did not answer (100% loss)")
    assert json.loads(nping.calls[0].request.content)["probeType"] == "tcp" and tcp["received"] == 5
    with pytest.raises(ToolError, match="dest_port"):
        await call("catsdwan_ping", {"device": "br1", "destination": "x", "probe": "udp"})


async def test_ping_refuses_an_unreachable_device(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    with pytest.raises(ToolError, match="unreachable"):
        await call("catsdwan_ping", {"device": "br2", "destination": "10.61.200.10"})


async def test_traceroute(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/device/interface").respond(json=fixture("device_interface_br1"))
    tr = api.post("/dataservice/device/tools/traceroute/10.0.0.2").respond(json=TRACE)
    out = await call(
        "catsdwan_traceroute",
        {"device": "br1", "destination": "10.61.201.10", "vpn": 10, "source_interface": "GigabitEthernet3"},
    )
    assert json.loads(tr.calls[0].request.content) == {
        "deviceIp": "10.0.0.2",
        "vpn": "10",
        "host": "10.61.201.10",
        "interface": "GigabitEthernet3",
        "interfaceIP": "10.61.200.1",
    }
    assert out["verdict"] == "reached 10.61.201.10 in 2 hops" and out["hops"][1]["name"] == "host-201"
    assert "name" not in out["hops"][0]


# --- tunnel path ---------------------------------------------------------------------------------


async def test_tunnel_path_picks_the_vpn_interface(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/device/interface").respond(json=fixture("device_interface_br1"))
    sp = api.post("/dataservice/device/tools/servicepath/10.0.0.2").respond(json=FLOW)
    out = await call(
        "catsdwan_tunnel_path", {"device": "br1", "destination": "10.61.201.10", "vpn": 10, "dscp": 46}
    )
    assert json.loads(sp.calls[0].request.content) == {
        "deviceIp": "10.0.0.2",
        "vpn": "10",
        "interface": "GigabitEthernet3",
        "sourceIp": "10.61.200.1",
        "destIp": "10.61.201.10",
        "protocol": "1",
        "all": "true",
        "dscp": "46",
    }
    assert out["verdict"].startswith("2 tunnel path(s)") and "br2" in out["verdict"]
    assert out["flow"]["dscp"] == "46" and out["path"] == "service"


async def test_tunnel_path_tunnel_kind_and_no_vpn_interface(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/device/interface").respond(json=fixture("device_interface_br1"))
    tp = api.post("/dataservice/device/tools/tunnelpath/10.0.0.2").respond(json=FLOW)
    await call(
        "catsdwan_tunnel_path",
        {
            "device": "br1",
            "destination": "10.61.200.10",
            "vpn": 10,
            "path_kind": "tunnel",
            "protocol": "tcp",
            "dest_port": 80,
        },
    )
    assert json.loads(tp.calls[0].request.content)["protocol"] == "6"
    with pytest.raises(ToolError, match="no interface with an address in VPN 20"):
        await call("catsdwan_tunnel_path", {"device": "br1", "destination": "10.61.201.10", "vpn": 20})


# --- bring-up ------------------------------------------------------------------------------------


async def test_device_bringup_joined(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(ts.BRINGUP_PATH).respond(json=fixture("troubleshooting_devicebringup_br1"))
    ctl = api.get(url__regex=r"/dataservice/troubleshooting/control/.+").respond(
        json=fixture("troubleshooting_control_br1")
    )
    out = await call("catsdwan_device_bringup", {"device": "br1"})
    assert out["verdict"] == "every bring-up step succeeded" and len(out["steps"]) == 5
    assert ctl.called and len(out["control_check"]["colours"]) == 2


async def test_device_bringup_never_joined(api: respx.MockRouter) -> None:
    mock_inventory(api)
    bring = api.get(ts.BRINGUP_PATH).respond(json=fixture("troubleshooting_devicebringup_unjoined"))
    ctl = api.get(url__regex=r"/dataservice/troubleshooting/control/.+").respond(
        400, json=fixture("troubleshooting_control_unjoined")
    )
    out = await call("catsdwan_device_bringup", {"device": SLOT})
    assert bring.calls[0].request.url.params["uuid"] == SLOT and not ctl.called
    assert out["verdict"].startswith("stuck at 'Authorized by vBond'") and "control_check" not in out


# --- admin-tech ----------------------------------------------------------------------------------


async def test_admin_tech_preview_then_confirm(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ts_tools, "POLL_INTERVAL", 0.0)
    mock_inventory(api)
    done_row = {
        "deviceIP": "10.0.0.2",
        "fileName": "10.0.0.2-br1-20261023-admin-tech.tar.gz",
        "size": 5,
        "state": "done",
        "requestTokenId": "new-1",
        "creationTime": 1792752241087,
    }
    api.get(ts.ADMINTECHS_PATH).mock(
        side_effect=[
            respx.MockResponse(json=fixture("device_tools_admintechs")),  # preview
            respx.MockResponse(json=fixture("device_tools_admintechs")),  # confirm's re-plan
            respx.MockResponse(json={"data": []}),  # first poll: not listed yet
            respx.MockResponse(json={"data": [done_row]}),
        ]
    )
    api.get(ts.ADMINTECH_PROGRESS_PATH).respond(json=fixture("device_tools_admintechs_inprogress"))
    post = api.post(ts.ADMINTECH_PATH).respond(json={})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = await run(c, "catsdwan_admin_tech", {"device": "br1"})
        assert prev["status"] == "preview" and prev["preview"]["existing_admin_techs"] == "none"
        assert not post.called
        done = await run(c, "catsdwan_admin_tech", {"device": "br1", "confirm": prev["confirm"]})
    assert json.loads(post.calls[0].request.content) == {
        "deviceIP": "10.0.0.2",
        "exclude-cores": True,
        "exclude-logs": False,
        "exclude-tech": False,
        "tech-filter": [],
        "custom-commands": [],
    }
    assert done["result"]["admin_tech"]["file"] == "10.0.0.2-br1-20261023-admin-tech.tar.gz"


async def test_troubleshooting_tiers() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert {
        "catsdwan_ping",
        "catsdwan_traceroute",
        "catsdwan_tunnel_path",
        "catsdwan_device_bringup",
    } <= names
    assert "catsdwan_admin_tech" not in names
    assert not {n for n in names if "reset" in n}


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("POST", ts.PING_PATH),
        ("POST", ts.NPING_PATH),
        ("POST", ts.TRACEROUTE_PATH),
        ("POST", ts.SERVICEPATH_PATH),
        ("POST", ts.TUNNELPATH_PATH),
        ("GET", ts.BRINGUP_PATH),
        ("GET", ts.CONTROL_TS_PATH),
        ("POST", ts.ADMINTECH_PATH),
        ("GET", ts.ADMINTECHS_PATH),
        ("GET", ts.ADMINTECH_PROGRESS_PATH),
        ("GET", ts.ADMINTECH_DOWNLOAD_PATH),
    ],
)
def test_troubleshooting_paths_are_in_the_spec(method: str, template: str) -> None:
    from cat_sdwan_mcp._core.spec import build_index
    from cat_sdwan_mcp.spec import match_operation

    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    p = template.replace("{ip}", "10.0.0.2").replace("{uuid}", "x").replace("{file}", "f.tar.gz")
    _, methods = match_operation(idx, method, p)
    assert method in methods
