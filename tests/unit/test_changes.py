"""W8: preview-first configuration changes (device variables, configuration-group deploy, template attach).

The variables shapes are the lab Manager's (20.18.3.1, group mcp-test with a system and a CLI profile): GET
answers {family, groups, devices: [{device-id, variables: [{name, value?}]}]} with native types and no
"value" key for an empty variable; PUT must carry every variable with its original type. The deploy, action
status and template shapes follow Cisco's documentation and the OpenAPI examples (not recorded yet).
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import changes as ch
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation
from cat_sdwan_mcp.tools import changes as tools

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

GID = "00000000-0000-4000-8000-000000000124"
GROUP = f"/dataservice/v1/config-group/{GID}"
BR1, HUB1, BR2 = "REDACTED-16", "REDACTED-17", "REDACTED-22"
TID = "00000000-0000-4000-8000-000000000842"
STATUS = "/dataservice/device/action/status"
PID = "parent-task-1"

RUNNING_BR1 = "system\n system-ip 10.0.0.2\n site-id 200\n!\nhostname br1\nbanner motd ^Cold banner^C\n"
PREVIEW_BR1 = "system\n system-ip 10.0.0.2\n site-id 200\n!\nhostname br1\nbanner motd ^Cnew banner^C\n"


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "POLL_INTERVAL", 0.0)


def variables(chassis: str, host: str, ip: str, site: int, banner: str | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = [
        {"name": "system_ip", "value": ip},
        {"name": "host_name", "value": host},
        {"name": "site_id", "value": site},
        {"name": "ipv6_strict_control", "value": False},
        {"name": "pseudo_commit_timer", "value": 300},
        {"name": "mpls_ip"},
        {"name": "snmp_community", "value": "s3cr3t-comm"},
        {"name": "banner_motd", **({"value": banner} if banner is not None else {})},
    ]
    return {"device-id": chassis, "variables": rows}


def variables_body(*devices: dict[str, Any]) -> dict[str, Any]:
    return {
        "family": "sdwan",
        "groups": [{"name": "mcp-test", "group-variables": []}],
        "devices": list(devices),
    }


BR1_VARS = variables(BR1, "br1", "10.0.0.2", 200)
HUB1_VARS = variables(HUB1, "hub1", "10.0.0.1", 100)


def group_record() -> dict[str, Any]:
    rec = fixture("v1_config_group_detail")
    rec["profiles"] = [
        {"id": "p-sys", "name": "mcp-test-system", "type": "system"},
        {"id": "p-cli", "name": "mcp-test-cli", "type": "cli"},
    ]
    return rec


def mock_group(api: respx.MockRouter, rec: dict[str, Any] | None = None) -> None:
    rec = rec or group_record()
    api.get("/dataservice/v1/config-group").respond(json=[rec])
    api.get(f"{GROUP}/device/associate").respond(json=fixture("v1_config_group_associate"))
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})


def mock_configs(api: respx.MockRouter, chassis: str, running: str, preview: str | None) -> respx.Route:
    api.get(f"/dataservice/template/config/running/{chassis}").respond(json={"config": running})
    route = api.post(f"{GROUP}/device/{chassis}/preview")
    if preview is None:
        route.respond(404, json={"error": {"message": "Not found"}})
    else:
        route.respond(json={"config": preview})
    return route


def mock_variables(api: respx.MockRouter, *devices: dict[str, Any]) -> respx.Route:
    return api.get(f"{GROUP}/device/variables").respond(json=variables_body(*devices))


async def run(server: Any, name: str, args: dict[str, Any]) -> Any:
    result = await server.call_tool(name, args)
    return result.structured_content


def writes(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


# --- helpers -------------------------------------------------------------------------------------


def test_merge_variables_keeps_types_and_every_variable() -> None:
    merged, changes, unknown = ch.merge_variables(
        BR1_VARS["variables"], {"banner_motd": "hi", "site_id": "201", "ipv6_strict_control": "true"}
    )
    assert len(merged) == len(BR1_VARS["variables"]) and unknown == []
    by = {v["name"]: v for v in merged}
    assert by["site_id"]["value"] == 201 and by["ipv6_strict_control"]["value"] is True
    assert "value" not in by["mpls_ip"]
    assert changes == {
        "banner_motd": {"from": None, "to": "hi"},
        "site_id": {"from": 200, "to": 201},
        "ipv6_strict_control": {"from": False, "to": True},
    }
    _, same, _ = ch.merge_variables(BR1_VARS["variables"], {"site_id": 200})
    assert same == {}
    _, _, unknown = ch.merge_variables(BR1_VARS["variables"], {"nope": 1})
    assert unknown == ["nope"]


def test_action_outcome_success_partial_and_validation() -> None:
    body = {
        "data": [
            {"host-name": "br1", "uuid": BR1, "statusId": "success", "status": "Success"},
            {
                "host-name": "hub1",
                "uuid": HUB1,
                "statusId": "failure",
                "status": "Failure",
                "currentActivity": "Failed to update configuration",
                "activity": ["[1] Pushing", "[2] Failed to update configuration - Device is offline"],
            },
        ],
        "summary": {"status": "done"},
    }
    assert ch.action_done(body)
    out = ch.action_outcome(body, PID)
    assert out["outcome"] == "partial"
    hub = next(d for d in out["devices"] if d["host"] == "hub1")
    assert "Device is offline" in hub["reason"]
    running = {"data": [{"host-name": "br1", "status": "In progress", "statusId": "in_progress"}]}
    assert not ch.action_done(running)
    bad = {"data": running["data"], "validation": {"statusId": "validation_failure", "activity": ["bad cfg"]}}
    assert ch.action_done(bad) and ch.action_outcome(bad, PID)["outcome"] == "failed"
    # the root certificate force-sync lists no device rows, only the summary (live 2026-10-24)
    rowless = {"data": [], "summary": {"status": "done"}}
    assert ch.action_done(rowless) and ch.action_outcome(rowless, PID)["outcome"] == "done"
    assert not ch.action_done({"data": [], "summary": {"status": "in_progress"}})


def test_rowless_force_sync_status() -> None:
    # live 20.18.3 (2026-10-24): the root certificate force-sync's status is {header, data: []} from the
    # first read on, with no summary; only the running-tasks list says whether it is still going
    body = fixture("device_action_status_rootcert_sync")
    assert ch.rowless(body) and not ch.action_done(body)
    assert not ch.action_done(body, [PID], PID)
    assert ch.action_done(body, [], PID) and ch.action_done(body, ["other"], PID)
    assert ch.action_outcome(body, PID)["outcome"] == "failed"
    out = ch.action_outcome(body, PID, rowless_done=True)
    assert out["outcome"] == "done" and out["devices"] == []
    # the documented shapes keep their meaning when the caller opts in
    running = {"data": [{"host-name": "br1", "status": "In progress", "statusId": "in_progress"}]}
    assert not ch.rowless(running) and not ch.action_done(running, [], PID)
    assert not ch.rowless({"data": [], "summary": {"status": "in_progress"}})
    assert not ch.action_done({"data": [], "summary": {"status": "in_progress"}}, [], PID)


def test_preview_text_and_template_matching() -> None:
    assert ch.preview_text("hostname x\n") == "hostname x\n"
    assert ch.preview_text({"existingConfig": "a\nb", "newConfig": "c\nd"}) == "c\nd"
    assert ch.preview_text({"data": {"config": "x\ny"}}) == "x\ny"
    assert ch.preview_text({}) is None
    keys = ["//system/host-name", "{{banner_motd}}", "//system/site-id"]
    assert ch.match_variable("banner_motd", keys, {}) == "{{banner_motd}}"
    assert ch.match_variable("host-name", keys, {}) == "//system/host-name"
    assert ch.match_variable("Banner", keys, {"{{banner_motd}}": "Banner"}) == "{{banner_motd}}"
    assert ch.match_variable("nope", keys, {}) is None


def test_tier_reasons() -> None:
    br1 = {"host": "br1", "system_ip": "10.0.0.2", "chassis": BR1, "site_id": "200"}
    hub1 = {"host": "hub1", "system_ip": "10.0.0.1", "chassis": HUB1, "site_id": "100"}
    assert ch.tier_reasons([br1], None, None) == []
    assert ch.tier_reasons([br1, hub1], None, None) == ["2 devices"]
    assert ch.tier_reasons([hub1], "10.0.0.1", None) == ["hub1 is a hub (CATSDWAN_HUB_DEVICES)"]
    assert "protected site 200" in ch.tier_reasons([br1], None, "300, 200")[0]


# --- catsdwan_set_device_variables ---------------------------------------------------------------


async def test_set_variables_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    get = mock_variables(api, BR1_VARS)
    put = api.put(f"{GROUP}/device/variables").respond(json={})
    async with Client(writes()) as c:
        args = {"group": "mcp-test", "device": "br1", "values": {"banner_motd": "new banner"}}
        prev = await run(c, "catsdwan_set_device_variables", args)
        assert prev["status"] == "preview" and not put.called
        assert prev["preview"]["changes"] == {"banner_motd": {"from": None, "to": "new banner"}}
        assert prev["preview"]["unchanged_variables"] == 7
        assert get.calls[0].request.url.params["device-id"] == BR1
        assert "deploy" in prev["side_effects"][0]
        done = await run(c, "catsdwan_set_device_variables", {**args, "confirm": prev["confirm"]})
    assert done["status"] == "applied"
    sent = json.loads(put.calls[0].request.content)
    assert sent["solution"] == "sdwan"
    (dev,) = sent["devices"]
    assert dev["device-id"] == BR1
    by = {v["name"]: v for v in dev["variables"]}
    assert len(by) == 8 and by["banner_motd"]["value"] == "new banner"
    assert by["site_id"]["value"] == 200 and by["pseudo_commit_timer"]["value"] == 300
    assert "value" not in by["mpls_ip"] and by["snmp_community"]["value"] == "s3cr3t-comm"


async def test_set_variables_masks_secrets_and_blocks_unknown(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    async with Client(writes()) as c:
        prev = await run(
            c,
            "catsdwan_set_device_variables",
            {"group": "mcp-test", "device": "br1", "values": {"snmp_community": "n3w", "nope": 1}},
        )
    assert prev["status"] == "blocked"
    assert "no variable 'nope'" in prev["blockers"][0] and "banner_motd" in prev["blockers"][0]
    text = json.dumps(prev)
    assert "s3cr3t-comm" not in text and "n3w" not in text


async def test_set_variables_needs_a_system_profile(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    api.get(f"{GROUP}/device/variables").respond(
        400, json={"error": {"code": "CFGRP0012", "message": "system profile does not exist, can't proceed"}}
    )
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_set_device_variables", {"group": "mcp-test", "device": "br1", "values": {"x": 1}}
        )
    assert prev["status"] == "blocked" and "needs a system feature profile" in prev["blockers"][0]


async def test_set_variables_device_not_in_group(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_set_device_variables", {"group": "mcp-test", "device": "br2", "values": {"x": 1}}
        )
    assert prev["status"] == "blocked" and "not associated" in prev["blockers"][0]


async def test_writes_off_registers_no_change_tools() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert not names & {
        "catsdwan_set_device_variables",
        "catsdwan_deploy_config_group",
        "catsdwan_attach_device_template",
    }


# --- catsdwan_deploy_config_group ----------------------------------------------------------------


def status_body(*rows: tuple[str, str, str], done: bool = True) -> dict[str, Any]:
    data = []
    for host, chassis, state in rows:
        row: dict[str, Any] = {"host-name": host, "uuid": chassis, "statusId": state, "status": state.title()}
        if state == "failure":
            row["currentActivity"] = "Failed to update configuration"
            row["activity"] = ["Configuring", "Failed to update configuration - NETCONF timeout"]
        data.append(row)
    return {"data": data, "summary": {"status": "done" if done else "in_progress"}}


async def test_deploy_preview_with_cli_preview(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    preview = mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    deploy = api.post(f"{GROUP}/device/deploy").respond(json={"parentTaskId": PID})
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    assert prev["status"] == "preview" and not deploy.called and preview.called
    assert prev["blast_radius"] == 1 and prev["preview"]["tier"] == "write"
    (dev,) = prev["preview"]["devices"]
    assert dev["host"] == "br1" and dev["preview_source"].startswith("the Manager's CLI preview")
    diff = dev["diff_vs_running"]
    assert diff["only_on_device"] == ["banner motd ^Cold banner^C"]
    assert diff["only_intended"] == ["banner motd ^Cnew banner^C"]
    assert "new banner" in dev["cli"] and dev["variables"]["snmp_community"] == "********"
    assert "no undo" in prev["preview"]["rollback"]


async def test_deploy_preview_without_cli_preview_api(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, None)
    api.get(f"/dataservice/template/config/attached/{BR1}").respond(json={"config": PREVIEW_BR1})
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"], "show_cli": False}
        )
    (dev,) = prev["preview"]["devices"]
    assert dev["preview_source"].startswith("NOT a CLI preview") and "cli_preview_unavailable" in dev
    assert dev["diff_vs_running"]["only_intended"] == ["banner motd ^Cnew banner^C"]
    assert "cli" not in dev


async def test_deploy_confirm_polls_to_success(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    deploy = api.post(f"{GROUP}/device/deploy").respond(json={"parentTaskId": PID})
    status = api.get(f"{STATUS}/{PID}")
    status.side_effect = [
        respx.MockResponse(json=status_body(("br1", BR1, "in_progress"), done=False)),
        respx.MockResponse(json=status_body(("br1", BR1, "success"))),
    ]
    async with Client(writes()) as c:
        args = {"group": "mcp-test", "devices": ["br1"]}
        prev = await run(c, "catsdwan_deploy_config_group", args)
        done = await run(c, "catsdwan_deploy_config_group", {**args, "confirm": prev["confirm"]})
    assert json.loads(deploy.calls[0].request.content) == {"devices": [{"id": BR1}]}
    assert status.call_count == 2
    result = done["result"]
    assert result["outcome"] == "success" and result["process_id"] == PID
    assert result["devices"] == [{"host": "br1", "chassis": BR1, "status": "success", "detail": "Success"}]


async def test_deploy_confirm_reports_the_failing_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS, HUB1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    mock_configs(api, HUB1, RUNNING_BR1.replace("br1", "hub1"), PREVIEW_BR1.replace("br1", "hub1"))
    api.post(f"{GROUP}/device/deploy").respond(json={"parentTaskId": PID})
    api.get(f"{STATUS}/{PID}").respond(json=status_body(("br1", BR1, "success"), ("hub1", HUB1, "failure")))
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args = {"group": "mcp-test", "devices": ["br1", "hub1"]}
        prev = await run(c, "catsdwan_deploy_config_group", args)
        assert prev["preview"]["tier"] == "dangerous" and prev["blast_radius"] == 2
        done = await run(c, "catsdwan_deploy_config_group", {**args, "confirm": prev["confirm"]})
    result = done["result"]
    assert result["outcome"] == "partial"
    hub = next(d for d in result["devices"] if d["host"] == "hub1")
    assert hub["status"] == "failure" and "NETCONF timeout" in hub["reason"]


async def test_deploy_several_devices_needs_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS, HUB1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    mock_configs(api, HUB1, RUNNING_BR1, PREVIEW_BR1)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1", "hub1"]})
    assert prev["status"] == "blocked"
    assert any("2 devices" in b and "MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])


async def test_deploy_to_a_hub_is_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, HUB1_VARS)
    mock_configs(api, HUB1, RUNNING_BR1, PREVIEW_BR1)
    args = {"group": "mcp-test", "devices": ["hub1"]}
    async with Client(writes(hub_devices="hub1")) as c:
        prev = await run(c, "catsdwan_deploy_config_group", args)
    assert prev["status"] == "blocked"
    assert "hub1 is a hub (CATSDWAN_HUB_DEVICES)" in prev["blockers"][0]
    async with Client(writes(hub_devices="hub1", mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_deploy_config_group", args)
    assert prev["status"] == "preview" and prev["preview"]["tier"] == "dangerous"


async def test_deploy_to_a_protected_site_is_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    async with Client(writes(protected_sites="200")) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    assert prev["status"] == "blocked" and "protected site 200" in prev["blockers"][0]


async def test_deploy_blast_radius_cap(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS, HUB1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    mock_configs(api, HUB1, RUNNING_BR1, PREVIEW_BR1)
    server = writes(mcp_enable_dangerous=True, mcp_max_blast_radius=1)
    async with Client(server) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1", "hub1"]})
    assert prev["status"] == "blocked" and "blast" in json.dumps(prev["blockers"]).lower()


async def test_deploy_blocks_a_template_device(api: respx.MockRouter) -> None:
    mock_inventory(
        api, br1={"managed-by": "Unmanaged", "configOperationMode": "vmanage", "template": "old-tpl"}
    )
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    assert prev["status"] == "blocked"
    assert "attached to device template old-tpl" in prev["blockers"][0]


async def test_deploy_blocks_an_unreachable_device(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br1": "unreachable"})
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    assert prev["status"] == "blocked" and prev["blockers"] == [
        "br1 is unreachable: the Manager can't push to it"
    ]


async def test_deploy_blocks_a_pending_action_and_an_empty_group(api: respx.MockRouter) -> None:
    mock_inventory(api)
    rec = group_record()
    rec["profiles"] = []
    mock_group(api, rec)
    api.get(f"{STATUS}/tasks").respond(
        json={"runningTasks": [{"processId": "other-1", "status": "in_progress"}]}
    )
    api.get(f"{STATUS}/other-1").respond(
        json={"data": [{"uuid": BR1, "statusId": "in_progress"}], "summary": {"name": "Software install"}}
    )
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    text = " ".join(prev["blockers"])
    assert "no feature profiles" in text and "br1 has an action still running (Software install)" in text


async def test_deploy_fingerprint_drift_refuses(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1)
    deploy = api.post(f"{GROUP}/device/deploy").respond(json={"parentTaskId": PID})
    async with Client(writes()) as c:
        args = {"group": "mcp-test", "devices": ["br1"]}
        prev = await run(c, "catsdwan_deploy_config_group", args)
        mock_configs(api, BR1, RUNNING_BR1, PREVIEW_BR1.replace("new banner", "someone else's"))
        with pytest.raises(ToolError, match="changed since the preview"):
            await run(c, "catsdwan_deploy_config_group", {**args, "confirm": prev["confirm"]})
    assert not deploy.called


# --- catsdwan_attach_device_template -------------------------------------------------------------


def template_input(banner: str = "") -> dict[str, Any]:
    return {
        "header": {
            "columns": [
                {"property": "csv-status", "title": "Status"},
                {"property": "//system/host-name", "title": "Hostname"},
                {"property": "{{banner_motd}}", "title": "Banner"},
            ]
        },
        "data": [
            {
                "csv-status": "in_complete",
                "csv-deviceId": BR2,
                "csv-deviceIP": "10.0.0.3",
                "csv-host-name": "br2",
                "//system/host-name": "br2",
                "{{banner_motd}}": banner,
            }
        ],
    }


def mock_template(api: respx.MockRouter, banner: str = "") -> tuple[respx.Route, respx.Route]:
    api.get("/dataservice/template/device").respond(json=fixture("template_device"))
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})
    api.get(f"/dataservice/template/config/running/{BR2}").respond(
        json={"config": RUNNING_BR1.replace("br1", "br2")}
    )
    inp = api.post("/dataservice/template/device/config/input").respond(json=template_input(banner))
    cfg = api.post("/dataservice/template/device/config/config").respond(
        text=PREVIEW_BR1.replace("br1", "br2").replace("new banner", "lab only"),
        headers={"Content-Type": "text/plain"},
    )
    return inp, cfg


async def test_attach_cli_template_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    inp, cfg = mock_template(api)
    attach = api.post("/dataservice/template/device/config/attachcli").respond(
        json={"id": "push_file_template_configuration-1"}
    )
    feature = api.post("/dataservice/template/device/config/attachfeature")
    api.get(f"{STATUS}/push_file_template_configuration-1").respond(json=status_body(("br2", BR2, "success")))
    args = {"template": "mcp-test-br2", "devices": ["br2"], "variables": {"banner_motd": "lab only"}}
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_attach_device_template", args)
        assert prev["status"] == "preview" and not attach.called
        assert json.loads(inp.calls[0].request.content)["deviceIds"] == [BR2]
        sent = json.loads(cfg.calls[0].request.content)
        assert sent["templateId"] == TID and sent["device"]["{{banner_motd}}"] == "lab only"
        (dev,) = prev["preview"]["devices"]
        assert dev["changes"] == {"{{banner_motd}}": {"from": "", "to": "lab only"}}
        assert dev["diff_vs_running"]["only_intended"] == ["banner motd ^Clab only^C"]
        assert prev["preview"]["template"]["kind"] == "CLI"
        assert prev["preview"]["request"].endswith("attachcli")
        done = await run(c, "catsdwan_attach_device_template", {**args, "confirm": prev["confirm"]})
    assert not feature.called
    body = json.loads(attach.calls[0].request.content)
    (entry,) = body["deviceTemplateList"]
    (row,) = entry["device"]
    assert entry["templateId"] == TID and row["csv-status"] == "complete" and row["selected"] == "true"
    assert row["csv-templateId"] == TID and row["{{banner_motd}}"] == "lab only"
    assert done["result"]["outcome"] == "success"


async def test_attach_render_accepts_text_plain(api: respx.MockRouter) -> None:
    """Live 20.18.3: template/device/config/config answers text/plain and refuses Accept: application/json
    (406)."""
    mock_inventory(api)
    _, cfg = mock_template(api)
    args = {"template": "mcp-test-br2", "devices": ["br2"], "variables": {"banner_motd": "lab only"}}
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_attach_device_template", args)
    assert prev["status"] == "preview"
    assert cfg.calls[0].request.headers["Accept"] == "*/*"


async def test_deploy_blocks_when_the_manager_refuses_the_group(api: respx.MockRouter) -> None:
    """Live 20.18.3: the CLI preview validates the group like a deploy (CFGRP0012: a missing transport
    profile or a profile without its mandatory parcels); the deploy would fail the same way, so the preview
    blocks."""
    mock_inventory(api)
    mock_group(api)
    mock_variables(api, BR1_VARS)
    mock_configs(api, BR1, RUNNING_BR1, None)
    api.post(f"{GROUP}/device/{BR1}/preview").respond(
        400,
        json={
            "error": {
                "message": "Config Group validation error",
                "code": "CFGRP0012",
                "details": "Group validation error Reason: Missing mandatory feature profile for "
                "config-group Deploy operation, missing profile type: transport",
                "type": "error",
            }
        },
    )
    api.get(f"/dataservice/template/config/attached/{BR1}").respond(json={"config": PREVIEW_BR1})
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_deploy_config_group", {"group": "mcp-test", "devices": ["br1"]})
    assert prev["status"] == "blocked"
    assert any("refuses to deploy" in b and "transport" in b for b in prev["blockers"])


async def test_attach_blocks_a_missing_value(api: respx.MockRouter) -> None:
    mock_inventory(api)
    _, cfg = mock_template(api)
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_attach_device_template", {"template": "mcp-test-br2", "devices": ["br2"]}
        )
    assert prev["status"] == "blocked" and "br2: no value for {{banner_motd}}" in prev["blockers"][0]
    assert not cfg.called


async def test_attach_per_device_values_and_unknown_variable(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    async with Client(writes()) as c:
        prev = await run(
            c,
            "catsdwan_attach_device_template",
            {
                "template": "mcp-test-br2",
                "devices": ["br2"],
                "device_variables": {"br2": {"Banner": "per device", "colour": "red"}},
            },
        )
    assert prev["status"] == "blocked"
    assert "no variable 'colour'" in prev["blockers"][0]
    (dev,) = prev["preview"]["devices"]
    assert dev["variables"]["{{banner_motd}}"] == "per device"


async def test_attach_blocks_a_config_group_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    api.get(f"/dataservice/template/config/running/{BR1}").respond(json={"config": RUNNING_BR1})
    async with Client(writes()) as c:
        prev = await run(
            c,
            "catsdwan_attach_device_template",
            {"template": "mcp-test-br2", "devices": ["br1"], "variables": {"banner_motd": "x"}},
        )
    assert prev["status"] == "blocked"
    assert "br1 is in configuration group mcp-test" in prev["blockers"][0]


async def test_attach_unreachable_device(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    mock_template(api, banner="set")
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_attach_device_template", {"template": "mcp-test-br2", "devices": ["br2"]}
        )
    assert prev["blockers"] == ["br2 is unreachable: the Manager can't push to it"]


def test_status_fixture_is_not_mutated() -> None:
    a = copy.deepcopy(BR1_VARS)
    ch.merge_variables(BR1_VARS["variables"], {"banner_motd": "x"})
    assert a == BR1_VARS


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("GET", ch.ACTION_STATUS_PATH),
        ("GET", ch.RUNNING_TASKS_PATH),
        ("POST", ch.DEPLOY_PATH),
        ("POST", ch.GROUP_PREVIEW_PATH),
        ("PUT", "/dataservice/v1/config-group/{id}/device/variables"),
        ("POST", ch.TEMPLATE_INPUT_PATH),
        ("POST", ch.TEMPLATE_CONFIG_PATH),
        ("POST", ch.ATTACH_CLI_PATH),
        ("POST", ch.ATTACH_FEATURE_PATH),
    ],
)
def test_change_paths_are_in_the_spec(method: str, template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    concrete = template.replace("{id}", "x").replace("{device}", "y")
    _, methods = match_operation(idx, method, concrete)
    assert method in methods
