"""W5: alarms, events, the audit log and the merged timeline on recorded 20.18.3.1 payloads (the lab's first
hour: edges joining, certificates, a seeded policy). Template-attach and reboot audit lines and a br2 outage
are hand-built on top, as marked."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.events import at_least, audit_details, by_type, parse_details

from .conftest import fixture
from .test_inventory import call, mock_inventory

BR2 = "10.0.0.3"


def mock_logs(api: respx.MockRouter, **bodies: Any) -> dict[str, respx.Route]:
    """POST /dataservice/alarms, /event and /auditlog answering with the recorded bodies (or `bodies`)."""
    out = {}
    for name, path in (("alarms", "alarms"), ("events", "event"), ("auditlog", "auditlog")):
        body = bodies.get(name, fixture(name))
        if isinstance(body, httpx.Response):
            out[name] = api.post(f"/dataservice/{path}").mock(return_value=body)
        else:
            out[name] = api.post(f"/dataservice/{path}").respond(json=body)
    return out


def query_of(route: respx.Route) -> dict[str, Any]:
    return json.loads(route.calls[0].request.content)


# Hand-built: br2 stopped (control and BFD down, active) and two audit lines that name it.
BR2_DOWN = [
    {
        "entry_time": 1792743400000,
        "type": "node_down",
        "rule_name_display": "Control_Node_Down",
        "severity": "Critical",
        "message": "All Control connections for the node are down",
        "active": True,
        "cleared_time": 0,
        "system_ip": BR2,
        "host_name": "br2",
        "site_id": "201",
        "values": [{"system-ip": BR2, "host-name": "br2", "site-id": "201"}],
        "devices": [{"system-ip": BR2}],
        "component": "Control",
    },
    {
        "entry_time": 1792743401000,
        "type": "bfd_node_down",
        "rule_name_display": "BFD_Node_Down",
        "severity": "Critical",
        "message": "All BFD sessions for the node are down",
        "active": True,
        "cleared_time": 0,
        "system_ip": "10.0.0.1",
        "host_name": "hub1",
        "site_id": "100",
        "values": [{"system-ip": BR2, "host-name": "br2"}],
        "devices": [],
        "component": "BFD",
    },
]
AUDIT_BR2 = [
    {
        "entry_time": 1792743450000,
        "loguser": "admin",
        "logusersrcip": "192.0.2.10",
        "logmodule": "template",
        "logfeature": "device",
        "logmessage": "Template mcp-test-br2 attached to device br2",
        "logdeviceid": "",
        "auditdetails": json.dumps(
            [json.dumps({"templateId": "t1", "device": "br2", "adminPassword": "s3cret"})]
        ),
    },
    {
        "entry_time": 1792743460000,
        "loguser": "admin",
        "logusersrcip": "192.0.2.10",
        "logmodule": "device",
        "logfeature": "reboot",
        "logmessage": "Reboot initiated for device 10.0.0.3",
        "logdeviceid": BR2,
        "auditdetails": '["Reboot requested"]',
    },
]


def with_rows(name: str, extra: list[dict[str, Any]]) -> dict[str, Any]:
    body = fixture(name)
    body["data"] = extra + body["data"]
    return body


# --- catsdwan_list_alarms ------------------------------------------------------------------------


async def test_list_alarms_active_newest_first(api: respx.MockRouter) -> None:
    mock_inventory(api)
    routes = mock_logs(api)
    out = await call("catsdwan_list_alarms", {"response_format": "json", "limit": 100})
    assert query_of(routes["alarms"])["query"]["rules"][0]["value"] == ["24"]
    assert out["total"] == 42 and out["active"] == 42
    assert all(r["state"] == "active" for r in out["results"])
    times = [r["time"] for r in out["results"]]
    assert times == sorted(times, reverse=True)
    first = out["results"][0]
    assert (
        first["alarm"] == "Memory_Usage"
        and first["devices"] == ["manager (1.1.1.1)"]
        and first["severity"] == "Major"
    )
    assert out["by_type"]["Control_Node_Down"] == "2 cleared"
    assert out["by_type"]["Control_Node_Up"] == "2 info"
    assert out["by_type"]["vEdge_Serial_File_Uploaded"] == "15 active"


async def test_list_alarms_for_a_device_with_cleared(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_logs(api)
    out = await call(
        "catsdwan_list_alarms",
        {"device": "br1", "active_only": False, "since_hours": 2, "response_format": "json"},
    )
    assert out["scope"] == "br1" and out["total"] == 9 and out["active"] == 3
    rows = {r["alarm"]: r for r in out["results"]}
    down = rows["Control_Node_Down"]
    assert down["state"] == "cleared" and down["cleared"].endswith("Z") and down["severity"] == "Critical"
    assert down["devices"] == ["br1 (10.0.0.2)"] and down["site_id"] == "200"
    assert rows["Control_Node_Up"]["state"] == "info" and "cleared" not in rows["Control_Node_Up"]
    crit = await call(
        "catsdwan_list_alarms",
        {
            "device": "br1",
            "active_only": False,
            "severity": "major",
            "alarm_type": "node",
            "response_format": "json",
        },
    )
    assert [r["alarm"] for r in crit["results"]] == ["Control_Node_Down"]


async def test_list_alarms_site_and_a_stopped_edge(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    mock_logs(api, alarms=with_rows("alarms", BR2_DOWN))
    out = await call("catsdwan_list_alarms", {"device": "br2", "response_format": "json"})
    assert [r["alarm"] for r in out["results"]][:2] == [
        "BFD_Node_Down",
        "Control_Node_Down",
    ]  # + recorded cert alarms
    assert out["results"][0]["devices"] == ["br2 (10.0.0.3)", "hub1 (10.0.0.1)"]
    site = await call(
        "catsdwan_list_alarms", {"site": "SITE_200", "active_only": False, "response_format": "json"}
    )
    assert site["scope"] == "site 200" and site["total"] == 9
    assert {"Control_Site_Down", "Control_Site_Up"} <= {r["alarm"] for r in site["results"]}
    with pytest.raises(ToolError, match="not both"):
        await call("catsdwan_list_alarms", {"site": "200", "device": "br1"})


async def test_list_alarms_partial_and_markdown(api: respx.MockRouter) -> None:
    mock_inventory(api)
    body = fixture("alarms")
    body["data"] = body["data"] * 40  # 2280 rows: more than the 2000 searched
    mock_logs(api, alarms=body)
    text = await call("catsdwan_list_alarms", {"severity": "critical", "limit": 3})
    assert "only the newest 2000 were searched" in text
    assert "| time | severity | alarm | state | devices | site_id | message |" in text


# --- catsdwan_list_events ------------------------------------------------------------------------


async def test_list_events_filters(api: respx.MockRouter) -> None:
    mock_inventory(api)
    routes = mock_logs(api)
    out = await call(
        "catsdwan_list_events", {"device": "hub1", "event_type": "bfd", "response_format": "json"}
    )
    assert query_of(routes["events"]) == {
        "query": {
            "condition": "AND",
            "rules": [{"value": ["1"], "field": "entry_time", "type": "date", "operator": "last_n_hours"}],
        },
        "size": 1000,
    }
    assert out["total"] == 17 and set(out["by_event"]) <= {"bfd-state-change", "bfd-scale-threshold"}
    ev = next(r for r in out["results"] if r["event"] == "bfd-state-change")
    assert ev["host"] == "hub1" and ev["component"] == "BFD" and "new-state=" in ev["details"]
    crit = await call("catsdwan_list_events", {"severity": "critical", "response_format": "json"})
    assert [r["event"] for r in crit["results"]] == ["control-vbond-state-change"] * 2
    omp = await call("catsdwan_list_events", {"component": "omp", "site": "201", "response_format": "json"})
    assert omp["total"] > 0 and {r["host"] for r in omp["results"]} == {"br2"}
    assert {r["component"] for r in omp["results"]} == {"OMP"}


def test_parse_details_and_severity() -> None:
    assert parse_details("host-name=br2; new-state=up; bad; =x") == {"host-name": "br2", "new-state": "up"}
    assert at_least("Critical", "major") and at_least("major", "major") and not at_least("minor", "medium")
    assert at_least("whatever", None) and not at_least("whatever", "minor")


# --- catsdwan_audit_log --------------------------------------------------------------------------


async def test_audit_log_changes_only(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_logs(api)
    everything = await call("catsdwan_audit_log", {"limit": 100, "response_format": "json"})
    assert everything["total"] == 50 and everything["by_user"] == {"admin": 25, "system": 25}
    changes = await call(
        "catsdwan_audit_log", {"changes_only": True, "limit": 100, "response_format": "json"}
    )
    assert changes["total"] == 36
    assert not any("Authentication" in r["message"] for r in changes["results"])
    assert any(r["message"] == "Created user mcp-ro - successfully" for r in changes["results"])
    groups = await call(
        "catsdwan_audit_log", {"module": "config-group", "user": "ADMIN", "response_format": "json"}
    )
    assert [r["message"] for r in groups["results"]][-1] == "Group mcp-test created"
    assert groups["total"] == 2 and groups["results"][0]["source_ip"] == "192.0.2.10"


async def test_audit_log_template_attach_and_reboot_for_a_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_logs(api, auditlog=with_rows("auditlog", AUDIT_BR2))
    out = await call(
        "catsdwan_audit_log",
        {"device": "br2", "include_details": True, "limit": 100, "response_format": "json"},
    )
    messages = [r["message"] for r in out["results"]]
    assert messages[:2] == [
        "Reboot initiated for device 10.0.0.3",
        "Template mcp-test-br2 attached to device br2",
    ]
    # + the six recorded certificate lines with logdeviceid 10.0.0.3 and the template whose details name br2
    assert out["total"] == 9 and out["scope"] == "br2"
    assert any(r["message"] == "Template mcp-test-br2 created" for r in out["results"])
    reboot, attach = out["results"][0], out["results"][1]
    assert reboot["device"] == "br2" and reboot["details"] == "Reboot requested"
    assert '"adminPassword":"********"' in attach["details"] and "s3cret" not in json.dumps(out)
    plain = await call("catsdwan_audit_log", {"device": "br2", "response_format": "json"})
    assert "details" not in plain["results"][0]


def test_audit_details_shapes() -> None:
    assert audit_details("") is None and audit_details("[]") is None
    assert audit_details('["a", "b"]') == "a | b"
    assert audit_details("not json") == "not json"
    long = audit_details(json.dumps(["x" * 2000]))
    assert long is not None and len(long) == 1003 and long.endswith("...")


# --- catsdwan_recent_activity --------------------------------------------------------------------


async def test_recent_activity_merges_one_timeline(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_logs(api)
    out = await call("catsdwan_recent_activity", {"device": "br1", "limit": 500, "response_format": "json"})
    assert out["scope"] == "br1" and out["by_source"] == {
        "alarm": 9,
        "event": 61,
        "audit": 2,
    }  # + "Group mcp-test created (hub1, br1)"
    times = [r["time"] for r in out["results"]]
    assert times == sorted(times, reverse=True) and out["total"] == 72
    sources = {r["source"] for r in out["results"]}
    assert sources == {"alarm", "event", "audit"}
    down = next(r for r in out["results"] if r["what"].startswith("Control_Node_Down"))
    assert (
        "(cleared 2026-" in down["what"]
        and down["severity"] == "critical"
        and down["device"] == "br1 (10.0.0.2)"
    )
    audit = next(r for r in out["results"] if r["source"] == "audit" and r.get("device"))
    assert audit["device"] == "br1" and audit["what"].startswith(
        "system [vedge-cloud]: Certificate Installation"
    )
    assert all("_ms" not in r for r in out["results"])


async def test_recent_activity_site_sources_and_failures(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_logs(api, events=httpx.Response(500, json={"error": {"message": "boom", "code": "SRV"}}))
    out = await call("catsdwan_recent_activity", {"site": "200", "response_format": "json", "limit": 500})
    assert out["scope"] == "site 200" and out["by_source"] == {"alarm": 9, "audit": 2}
    assert (
        out["warnings"][0].startswith("events: POST /dataservice/event failed")
        and "SRV" in out["warnings"][0]
    )
    only = await call("catsdwan_recent_activity", {"include": ["alarms"], "response_format": "json"})
    assert set(only["by_source"]) == {"alarm"} and only["total"] == 57 and only["scope"] == "the whole fabric"


async def test_recent_activity_all_sources_failing(api: respx.MockRouter) -> None:
    mock_inventory(api)
    err = httpx.Response(500, json={"error": {"message": "down"}})
    mock_logs(api, alarms=err, events=err, auditlog=err)
    with pytest.raises(ToolError, match="alarms: POST /dataservice/alarms failed"):
        await call("catsdwan_recent_activity", {"device": "br1"})


def test_by_type_ordering() -> None:
    rows = [
        {"type": "a", "active": True},
        {"type": "b", "active": False, "cleared_time": 5},
        {"type": "b", "active": True},
    ]
    assert by_type(rows) == {"b": "1 active, 1 cleared", "a": "1 active"}
