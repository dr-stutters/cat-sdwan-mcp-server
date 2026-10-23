"""W11: policies in plain words, the offline path walk and policy activation.

Recorded on the lab Manager (20.18.3.1): the centralised policy list (mcp-test-policy, not activated), its
definition record (an app-route part on site list mcp-test-sites and VPN list mcp-test-vpn10), the approute,
control and data definition lists, the site, VPN, app and SLA lists, and the (empty) localised policies and
policy groups. The app-route definition's sequences (GET .../definition/approute/{id}), the activate and
deactivate answers and the action status follow Cisco's documented shapes and the OpenAPI examples (not
recorded yet).
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import policy as pol
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation
from cat_sdwan_mcp.tools import changes as change_tools

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

POLICY_ID = "00000000-0000-4000-8000-000000000987"
DEF_ID = "00000000-0000-4000-8000-000000000127"
SLA_ID = "00000000-0000-4000-8000-000000000131"
APP_LIST = "00000000-0000-4000-8000-000000000988"  # APP_BULK_DATA (ftp, ...)
STATS = "/dataservice/statistics/approute"
STATUS = "/dataservice/device/action/status"


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


def approute_detail() -> dict[str, Any]:
    """GET /template/policy/definition/approute/{id} in Cisco's documented shape: voice (DSCP 46) on the
    lab's SLA class preferring mpls with biz-internet as the backup, SIP signalling on a port match, and bulk
    data on the Bulk-Data class."""
    return {
        "name": "mcp-test-app-route",
        "type": "appRoute",
        "description": "voice (DSCP 46) on the SLA class, mpls first",
        "definitionId": DEF_ID,
        "sequences": [
            {
                "sequenceId": 11,
                "sequenceName": "bulk",
                "sequenceType": "appRoute",
                "sequenceIpType": "ipv4",
                "match": {"entries": [{"field": "appList", "ref": APP_LIST}]},
                "actions": [
                    {
                        "type": "slaClass",
                        "parameter": [{"field": "name", "ref": "00000000-0000-4000-8000-000000001011"}],
                    }
                ],
            },
            {
                "sequenceId": 1,
                "sequenceName": "voice",
                "sequenceType": "appRoute",
                "sequenceIpType": "ipv4",
                "match": {"entries": [{"field": "dscp", "value": "46"}]},
                "actions": [
                    {
                        "type": "slaClass",
                        "parameter": [
                            {"field": "name", "ref": SLA_ID},
                            {"field": "preferredColor", "value": "mpls"},
                        ],
                    },
                    {"type": "backupSlaPreferredColor", "parameter": "biz-internet"},
                ],
            },
        ],
    }


def all_lists() -> dict[str, Any]:
    data = []
    for t in ("site", "vpn", "app", "sla"):
        data += fixture(f"template_policy_list_{t}")["data"]
    return {"data": data}


def mock_policies(api: respx.MockRouter, *, active: bool = False, lists_api: bool = True) -> None:
    vsmart = fixture("template_policy_vsmart")
    vsmart["data"][0]["isPolicyActivated"] = active
    api.get("/dataservice/template/policy/vsmart").respond(json=vsmart)
    api.get("/dataservice/template/policy/vedge").respond(json=fixture("template_policy_vedge"))
    api.get("/dataservice/v1/policy-group").respond(json=fixture("v1_policy_group"))
    for t in ("approute", "control", "data"):
        api.get(f"/dataservice/template/policy/definition/{t}").respond(
            json=fixture(f"template_policy_definition_{t}")
        )
    record = fixture("template_policy_vsmart_definition")
    record["isPolicyActivated"] = active
    api.get(f"/dataservice/template/policy/vsmart/definition/{POLICY_ID}").respond(json=record)
    api.get(f"/dataservice/template/policy/definition/approute/{DEF_ID}").respond(json=approute_detail())
    if lists_api:
        api.get("/dataservice/template/policy/list").respond(json=all_lists())
    else:
        api.get("/dataservice/template/policy/list").respond(404, json={"error": {"message": "not found"}})
        for t in pol.LIST_TYPES:
            body = (
                fixture(f"template_policy_list_{t}") if t in ("site", "vpn", "app", "sla") else {"data": []}
            )
            api.get(f"/dataservice/template/policy/list/{t}").respond(json=body)


def tunnel(
    local: str, lcol: str, remote: str, rcol: str, latency: float, loss: float = 0.0
) -> dict[str, Any]:
    return {
        "vdevice_name": local,
        "remote_system_ip": remote,
        "local_color": lcol,
        "remote_color": rcol,
        "latency": latency,
        "loss_percentage": loss,
        "jitter": 2,
        "entry_time": 1792744081970,
        "state": "Up",
    }


def stats(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"pageInfo": {"count": len(rows)}, "data": list(rows)}


async def run(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        result = await c.call_tool(name, args)
    return result.structured_content


# --- helpers -------------------------------------------------------------------------------------


def test_sequences_in_plain_words() -> None:
    lists = pol.by_id(all_lists()["data"])
    voice = pol.ordered(approute_detail()["sequences"])[0]
    row = pol.sequence_row(voice, lists)
    assert row["sequence"] == 1 and row["match"] == ["DSCP 46"]
    assert row["action"][0] == (
        "SLA class mcp-test-sla (loss <= 2%, latency <= 150 ms, jitter <= 50 ms), preferring mpls"
    )
    assert row["action"][1] == "when no tunnel meets the SLA: biz-internet"
    assert row["in_words"].startswith("if DSCP 46 -> SLA class mcp-test-sla")


def test_sequence_matches_app_lists_dscp_and_maybe() -> None:
    lists = pol.by_id(all_lists()["data"])
    bulk, voice = approute_detail()["sequences"]
    assert pol.sequence_matches(bulk, "ftp", None, lists)[0] == "yes"
    assert pol.sequence_matches(bulk, "APP_BULK_DATA", None, lists)[0] == "yes"
    assert pol.sequence_matches(bulk, "webex", None, lists)[0] == "no"
    assert pol.sequence_matches(bulk, None, 46, lists)[0] == "maybe"
    assert pol.sequence_matches(voice, None, 46, lists) == ("yes", "DSCP 46 matches")
    assert pol.sequence_matches(voice, None, 0, lists)[0] == "no"
    port = {"match": {"entries": [{"field": "destinationPort", "value": "5060"}]}}
    verdict, why = pol.sequence_matches(port, None, 46, lists)
    assert verdict == "maybe" and "destination port" in why
    assert pol.sequence_matches({"match": {}}, "x", None, lists)[0] == "yes"


def test_site_lists_and_ranges() -> None:
    lists = pol.by_id(all_lists()["data"])
    parts = pol.assembly(fixture("template_policy_vsmart")["data"][0])
    assert pol.site_ids(parts, lists) == {"100", "200", "201"}
    assert pol.in_site_list("205", {"type": "site", "entries": [{"siteId": "200-210"}]})
    assert not pol.in_site_list("300", {"type": "site", "entries": [{"siteId": "200-210"}]})
    ok, why = pol.entry_applies(parts[0]["entries"][0], "200", 10, lists)
    assert ok and "mcp-test-sites" in why
    ok, why = pol.entry_applies(parts[0]["entries"][0], "200", 20, lists)
    assert not ok and "VPN 20" in why
    assert pol.site_ids([{"entries": [{}]}], lists) is None


def test_tunnel_choice_cases() -> None:
    sla = {"name": "voice", "loss_max": 2.0, "latency_max": 150.0, "jitter_max": 50.0}
    steer = {"sla_class": "voice", "preferred_colours": ["mpls"], "backup_colours": ["biz-internet"]}

    def rows(mpls: float, inet: float) -> list[dict[str, Any]]:
        return [
            {
                "host": "br1",
                "local_colour": "mpls",
                "remote": "hub1",
                "remote_colour": "mpls",
                "latency_ms": mpls,
            },
            {
                "host": "br1",
                "local_colour": "biz-internet",
                "remote": "hub1",
                "remote_colour": "biz-internet",
                "latency_ms": inet,
            },
        ]

    met = pol.tunnel_choice(steer, rows(10, 20), sla)
    assert "preferred colour mpls meets voice" in met["verdict"] and len(met["tunnels"]) == 1
    moved = pol.tunnel_choice(steer, rows(300, 20), sla)
    assert "mpls misses voice" in moved["verdict"] and moved["colours_meeting_sla"] == ["biz-internet"]
    backup = pol.tunnel_choice(steer, rows(300, 400), sla)
    assert "backup colour biz-internet" in backup["verdict"]
    strict = pol.tunnel_choice({"strict": True}, rows(300, 400), sla)
    assert "DROPPED" in strict["verdict"]
    lb = pol.tunnel_choice(None, rows(1, 1), None)
    assert "load-balanced" in lb["verdict"]


# --- catsdwan_list_policies / catsdwan_get_policy -------------------------------------------------


async def test_list_policies(api: respx.MockRouter) -> None:
    mock_policies(api)
    out = await run("catsdwan_list_policies", {"response_format": "json"})
    (row,) = out["results"]
    assert row["name"] == "mcp-test-policy" and row["kind"] == "centralised"
    assert row["activated"] is False and row["type"] == "policy builder"
    assert row["parts"] == "mcp-test-app-route (application-aware routing)"
    assert out["active_centralised_policy"].startswith("none")


async def test_list_policies_survives_a_missing_source(api: respx.MockRouter) -> None:
    mock_policies(api)
    api.get("/dataservice/v1/policy-group").respond(404, json={"error": {"message": "Not found"}})
    out = await run("catsdwan_list_policies", {"response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["mcp-test-policy"]
    assert any("policy-group" in w for w in out["warnings"])


async def test_get_policy_in_plain_words(api: respx.MockRouter) -> None:
    mock_policies(api)
    out = await run("catsdwan_get_policy", {"policy": "mcp-test-policy", "response_format": "json"})
    (applies,) = out["applies"]
    assert applies["sites"] == ["site list mcp-test-sites (100, 200, 201)"]
    assert applies["vpns"] == ["vpn list mcp-test-vpn10 (10)"]
    (definition,) = out["definitions"]
    assert definition["name"] == "mcp-test-app-route" and definition["type"] == "application-aware routing"
    voice, bulk = definition["sequences"]
    assert voice["sequence"] == 1 and "preferring mpls" in voice["in_words"]
    assert bulk["match"][0].startswith("application list app list APP_BULK_DATA (ftp, ftp-data")
    assert bulk["action"] == ["SLA class Bulk-Data (loss <= 5%, latency <= 500 ms, jitter <= 500 ms)"]
    assert "not activated" in out["note"]


async def test_get_policy_reads_lists_by_type_without_the_all_lists_api(api: respx.MockRouter) -> None:
    mock_policies(api, lists_api=False)
    out = await run("catsdwan_get_policy", {"policy": POLICY_ID, "response_format": "json"})
    assert out["applies"][0]["sites"] == ["site list mcp-test-sites (100, 200, 201)"]
    assert any("lists read by type" in w for w in out["warnings"])


async def test_get_policy_did_you_mean(api: respx.MockRouter) -> None:
    mock_policies(api)
    async with Client(make_server()) as c:
        result = await c.call_tool("catsdwan_get_policy", {"policy": "mcp-tst-policy"}, raise_on_error=False)
    assert result.is_error and "mcp-test-policy" in str(result.content)


# --- catsdwan_explain_path ------------------------------------------------------------------------

EXPLAIN = {"source_site": "200", "destination": "100", "dscp": 46, "vpn": 10, "policy": "mcp-test-policy"}


async def test_explain_path_sla_met_takes_the_preferred_colour(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_policies(api)
    route = api.post(STATS).respond(
        json=stats(
            tunnel("10.0.0.2", "mpls", "10.0.0.1", "mpls", 12),
            tunnel("10.0.0.2", "biz-internet", "10.0.0.1", "biz-internet", 25),
        )
    )
    out = await run("catsdwan_explain_path", EXPLAIN)
    sent = json.loads(route.calls[0].request.content)["query"]["rules"]
    assert {"value": ["10.0.0.2"], "field": "vdevice_name", "type": "string", "operator": "in"} in sent
    assert {"value": ["10.0.0.1"], "field": "remote_system_ip", "type": "string", "operator": "in"} in sent
    assert out["policy"] == "mcp-test-policy (NOT activated)"
    app_route = next(s for s in out["steps"] if s["step"] == "app-route policy")
    assert app_route["matched"]["sequence"] == 1 and app_route["matched"]["why"] == "DSCP 46 matches"
    assert out["verdict"].startswith("the preferred colour mpls meets mcp-test-sla: traffic takes br1 mpls")
    assert any("WOULD do" in c for c in out["caveats"])


async def test_explain_path_sla_violated_falls_back(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_policies(api, active=True)
    route = api.post(STATS)
    route.side_effect = [
        respx.MockResponse(
            json=stats(
                tunnel("10.0.0.2", "mpls", "10.0.0.1", "mpls", 320),
                tunnel("10.0.0.2", "biz-internet", "10.0.0.1", "biz-internet", 30),
            )
        ),
        respx.MockResponse(
            json=stats(
                tunnel("10.0.0.2", "mpls", "10.0.0.1", "mpls", 320),
                tunnel("10.0.0.2", "biz-internet", "10.0.0.1", "biz-internet", 30, loss=5),
            )
        ),
    ]
    args = {k: v for k, v in EXPLAIN.items() if k != "policy"}
    moved = await run("catsdwan_explain_path", args)
    assert moved["policy"] == "mcp-test-policy (activated)"
    assert "mpls misses mcp-test-sla" in moved["verdict"] and "biz-internet meets it" in moved["verdict"]
    tunnels = next(s for s in moved["steps"] if s["step"] == "tunnels now")["tunnels"]
    assert any(t["sla"].startswith("misses: latency 320 ms > 150 ms") for t in tunnels)
    backup = await run("catsdwan_explain_path", args)
    assert "falls back to the backup colour biz-internet" in backup["verdict"]


async def test_explain_path_without_an_active_policy(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_policies(api)
    api.post(STATS).respond(json=stats(tunnel("10.0.0.2", "mpls", "10.0.0.1", "mpls", 12)))
    out = await run("catsdwan_explain_path", {"source_site": "200", "destination": "100", "app": "webex"})
    assert out["policy"] == "none activated" and "ECMP" in out["verdict"]
    assert any("policy=<name>" in c for c in out["caveats"])


async def test_explain_path_to_a_prefix_reads_omp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_policies(api, active=True)
    routes = api.get("/dataservice/device/omp/routes/received", params={"deviceId": "10.0.0.2"}).respond(
        json=fixture("device_omp_routes_received_hub1")
    )
    stats_route = api.post(STATS).respond(json=stats(tunnel("10.0.0.2", "mpls", "10.0.0.1", "mpls", 12)))
    out = await run(
        "catsdwan_explain_path",
        {"source_site": "200", "destination": "10.61.100.5", "app": "ftp", "vpn": 10},
    )
    assert routes.called
    omp = out["steps"][0]
    assert omp["step"] == "OMP routes" and omp["read_on"] == "br1"
    assert any(a.startswith("hub1") for a in omp["advertised_by"])
    sent = json.loads(stats_route.calls[0].request.content)["query"]["rules"]
    assert any(r["field"] == "remote_system_ip" and r["value"] == ["10.0.0.1"] for r in sent)
    app_route = next(s for s in out["steps"] if s["step"] == "app-route policy")
    assert app_route["matched"]["name"] == "bulk"


async def test_explain_path_needs_the_traffic(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        result = await c.call_tool(
            "catsdwan_explain_path", {"source_site": "200", "destination": "100"}, raise_on_error=False
        )
    assert result.is_error and "app" in str(result.content)


# --- catsdwan_activate_policy ---------------------------------------------------------------------


def controllers_in(mode: str) -> dict[str, Any]:
    body = copy.deepcopy(fixture("system_device_controllers"))
    for c in body["data"]:
        c["configOperationMode"] = mode
    return body


def mock_activation(api: respx.MockRouter, *, active: bool = False, mode: str = "vmanage") -> None:
    mock_inventory(api)
    mock_policies(api, active=active)
    api.get("/dataservice/system/device/controllers").respond(json=controllers_in(mode))
    api.get("/dataservice/template/policy/vsmart/connectivity/status").respond(json=[])


async def test_activate_refused_without_dangerous(api: respx.MockRouter) -> None:
    mock_activation(api)
    prev = await run("catsdwan_activate_policy", {"policy": "mcp-test-policy"}, mcp_enable_writes=True)
    assert prev["status"] == "blocked"
    assert any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])


async def test_activate_blocked_while_a_controller_is_in_cli_mode(api: respx.MockRouter) -> None:
    mock_activation(api, mode="cli")
    prev = await run(
        "catsdwan_activate_policy",
        {"policy": "mcp-test-policy"},
        mcp_enable_writes=True,
        mcp_enable_dangerous=True,
    )
    assert prev["status"] == "blocked"
    (blocker,) = prev["blockers"]
    assert "controller controller is in CLI mode" in blocker and "device template" in blocker


async def test_activate_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_activation(api)
    activate = api.post(f"/dataservice/template/policy/vsmart/activate/{POLICY_ID}").respond(
        json={"id": "vsmart_policy_config-1"}
    )
    status = api.get(f"{STATUS}/vsmart_policy_config-1")
    status.side_effect = [
        respx.MockResponse(json={"data": [{"host-name": "controller", "statusId": "in_progress"}]}),
        respx.MockResponse(
            json={"data": [{"host-name": "controller", "system-ip": "1.1.1.3", "statusId": "success"}]}
        ),
    ]
    settings = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
    async with Client(make_server(**settings)) as c:
        prev = (
            await c.call_tool("catsdwan_activate_policy", {"policy": "mcp-test-policy"})
        ).structured_content
        assert prev["status"] == "preview" and not activate.called
        details = prev["preview"]
        assert details["tier"] == "dangerous"
        assert details["controllers"] == [
            {
                "host": "controller",
                "system_ip": "1.1.1.3",
                "reachability": "reachable",
                "config_mode": "template",
            }
        ]
        assert details["sites"] == {"100": ["hub1"], "200": ["br1"], "201": ["br2"]}
        assert prev["blast_radius"] == 4
        assert "deactivate" in details["undo"]
        done = (
            await c.call_tool(
                "catsdwan_activate_policy", {"policy": "mcp-test-policy", "confirm": prev["confirm"]}
            )
        ).structured_content
    assert json.loads(activate.calls[0].request.content) == {"isEdited": False}
    assert done["result"]["outcome"] == "success" and status.call_count == 2


async def test_deactivate(api: respx.MockRouter) -> None:
    mock_activation(api, active=True)
    deactivate = api.post(f"/dataservice/template/policy/vsmart/deactivate/{POLICY_ID}").respond(
        json={"id": "vsmart_policy_config-2"}
    )
    api.get(f"{STATUS}/vsmart_policy_config-2").respond(
        json={"data": [{"host-name": "controller", "statusId": "success"}]}
    )
    settings = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
    args = {"policy": "mcp-test-policy", "action": "deactivate"}
    async with Client(make_server(**settings)) as c:
        prev = (await c.call_tool("catsdwan_activate_policy", args)).structured_content
        assert prev["status"] == "preview" and "action='activate'" in prev["preview"]["undo"]
        done = (
            await c.call_tool("catsdwan_activate_policy", {**args, "confirm": prev["confirm"]})
        ).structured_content
    assert json.loads(deactivate.calls[0].request.content) == {}
    assert done["result"]["outcome"] == "success"


async def test_activate_nothing_to_do(api: respx.MockRouter) -> None:
    mock_activation(api, active=True)
    settings = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
    prev = await run("catsdwan_activate_policy", {"policy": "mcp-test-policy"}, **settings)
    assert prev["status"] == "blocked" and "already activated" in prev["blockers"][0]
    mock_activation(api, active=False)
    prev = await run(
        "catsdwan_activate_policy", {"policy": "mcp-test-policy", "action": "deactivate"}, **settings
    )
    assert prev["status"] == "blocked" and "not activated" in prev["blockers"][0]


def test_activate_tiers() -> None:
    def tier(**kw: Any) -> str | None:
        t = make_server(**kw)._stutters_tiers.get("catsdwan_activate_policy")  # type: ignore[attr-defined]
        return t.value if t else None

    assert tier() is None
    assert tier(mcp_enable_writes=True) == "write"
    assert tier(mcp_enable_writes=True, mcp_enable_dangerous=True) == "dangerous"


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("GET", pol.VSMART_PATH),
        ("GET", pol.VSMART_DEFINITION_PATH),
        ("GET", pol.VEDGE_PATH),
        ("GET", pol.VEDGE_DEFINITION_PATH),
        ("GET", pol.LISTS_PATH),
        ("GET", "/dataservice/template/policy/definition/approute/{id}"),
        ("POST", pol.ACTIVATE_PATH),
        ("POST", pol.DEACTIVATE_PATH),
        ("GET", pol.CONNECTIVITY_PATH),
    ],
)
def test_policy_paths_are_in_the_spec(method: str, template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, template.replace("{id}", "x"))
    assert method in methods
