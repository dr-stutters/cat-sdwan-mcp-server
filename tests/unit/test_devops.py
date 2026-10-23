"""W12: device operations (software, upgrades, reboots, the Manager's action list).

Recorded on the lab Manager (20.18.3.1): the software repository and image list (both EMPTY: the lab has no
images), installed software on hub1 and br1, reboot history of br1 and br2, the system status of br1, the
action-type list (202 rows) and the running-task list (empty). The reboot, install and changepartition
answers and a running task's rows follow the OpenAPI schemas and Cisco's documented shapes (not recorded).
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import devops as ops
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation
from cat_sdwan_mcp.tools import changes as change_tools

from .conftest import fixture, make_server
from .test_inventory import device_body, mock_inventory

EDGES = {"hub1": "10.0.0.1", "br1": "10.0.0.2", "br2": "10.0.0.3"}
CHASSIS = {"hub1": "REDACTED-17", "br1": "REDACTED-16", "br2": "REDACTED-22"}
STATUS = "/dataservice/device/action/status"
DANGEROUS = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
REPO_ROW = {
    "versionId": "v-1",
    "versionName": "17.18.03.0.5000",
    "controllerVersionName": "20.18",
    "versionType": "vmanage",
    "availableFiles": "c8000v-universalk9.17.18.03.SPA.bin",
    "platformFamily": "c8000v",
    "updatedOn": 1792743507064,
}


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


def software(host: str, *versions: tuple[str, bool]) -> dict[str, Any]:
    body = copy.deepcopy(fixture("device_software_br1"))
    template = body["data"][0]
    body["data"] = [
        {
            **template,
            "vdevice-host-name": host,
            "vdevice-name": EDGES[host],
            "version": v,
            "active": str(a).lower(),
        }
        for v, a in versions
    ]
    return body


def system_status(host: str, free: str = "3341M") -> dict[str, Any]:
    body = copy.deepcopy(fixture("device_system_status_br1"))
    body["data"][0].update({"disk_avail": free, "vdevice-host-name": host, "vdevice-name": EDGES[host]})
    return body


def mock_realtime(api: respx.MockRouter, *, free: dict[str, str] | None = None) -> None:
    for host, ip in EDGES.items():
        api.get("/dataservice/device/software", params={"deviceId": ip}).respond(
            json=software(host, ("17.18.02.0.4112", True))
        )
        api.get("/dataservice/device/system/status", params={"deviceId": ip}).respond(
            json=system_status(host, (free or {}).get(host, "3341M"))
        )
    api.get("/dataservice/device/reboothistory", params={"deviceId": "10.0.0.3"}).respond(
        json=fixture("device_reboothistory_br2")
    )
    api.get("/dataservice/device/reboothistory", params={"deviceId": "10.0.0.2"}).respond(
        json=fixture("device_reboothistory_br1")
    )
    api.get("/dataservice/device/reboothistory", params={"deviceId": "10.0.0.1"}).respond(json={"data": []})
    api.get(f"{STATUS}/tasks").respond(json=fixture("device_action_status_tasks"))


def same_site(api: respx.MockRouter) -> None:
    """br2 moved to br1's site 200: a dual-edge site."""
    mock_inventory(api)
    body = device_body()
    for d in body["data"]:
        if d.get("host-name") == "br2":
            d["site-id"] = "200"
    api.get("/dataservice/device").respond(json=body)


def mock_repo(api: respx.MockRouter, *rows: dict[str, Any]) -> None:
    repo = fixture("device_action_software")
    repo["data"] = list(rows)
    api.get("/dataservice/device/action/software").respond(json=repo)
    api.get("/dataservice/device/action/software/images").respond(
        json=fixture("device_action_software_images")
    )


async def run(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        result = await c.call_tool(name, args, raise_on_error=False)
    if result.is_error:
        return {"error": str(result.content)}
    return result.structured_content


# --- helpers -------------------------------------------------------------------------------------


def test_release_trains_and_versions() -> None:
    assert ops.train("17.18.02.0.4112") == (20, 18) == ops.train("20.18.3.1")
    assert ops.train("26.1.1") == (26, 1)
    assert not ops.newer_than("17.18.03", "20.18.3.1")
    assert ops.newer_than("17.19.01", "20.18.3.1")
    assert ops.newer_than("26.1.1", "20.18.3.1")
    assert not ops.newer_than("17.18.03", "26.1.1")
    assert ops.same_version("17.18.02.0.4112", "17.18.02")
    assert not ops.same_version("17.18.02.0.4112", "17.18.03")
    assert ops.disk_mb("3341M") == 3341 and ops.disk_mb("5G") == 5120 and ops.disk_mb("n/a") is None
    assert ops.train_text((20, 18)) == "20.18 (IOS XE 17.18)"


def test_request_bodies() -> None:
    rows = [{"role": "edge", "system_ip": "10.0.0.3", "chassis": "C-3", "model": "vedge-C8000V"}]
    assert ops.reboot_body(rows) == {
        "action": "reboot",
        "deviceType": "vedge",
        "devices": [{"deviceIP": "10.0.0.3", "deviceId": "C-3"}],
    }
    body = ops.install_body(rows, REPO_ROW, "c8000v", activate=True)
    assert body == {
        "action": "install",
        "input": {
            "vEdgeVPN": 0,
            "vSmartVPN": 0,
            "data": [{"family": "c8000v", "version": "17.18.03.0.5000", "versionId": "v-1"}],
            "versionType": "vmanage",
            "reboot": True,
            "sync": True,
        },
        "devices": [{"deviceIP": "10.0.0.3", "deviceId": "C-3"}],
        "deviceType": "vedge",
    }
    assert ops.change_partition_body(rows, "17.18.03")["devices"] == [
        {"version": "17.18.03", "deviceIP": "10.0.0.3", "deviceId": "C-3"}
    ]
    assert ops.family_of(rows[0]) == "c8000v"
    assert ops.reboot_body([{"role": "controller", "system_ip": "1.1.1.3", "chassis": "x"}])[
        "deviceType"
    ] == ("controller")


def test_dual_edge_blockers() -> None:
    inv = [
        {"role": "edge", "host": "a", "site_id": "200"},
        {"role": "edge", "host": "b", "site_id": "200"},
        {"role": "edge", "host": "c", "site_id": "201"},
    ]
    (blocker,) = ops.dual_edge_blockers(inv, inv, "reboot")
    assert "a, b are edges of the same site 200 (every edge there)" in blocker
    assert ops.dual_edge_blockers([inv[0], inv[2]], inv, "reboot") == []


# --- catsdwan_list_software ----------------------------------------------------------------------


async def test_list_software_empty_repository(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    mock_repo(api)
    out = await run("catsdwan_list_software", {"response_format": "json"})
    assert out["manager"] == "20.18.3.1" and "20.18 (IOS XE 17.18)" in out["ceiling"]
    assert out["repository"].startswith("no versions: the software repository is empty")
    assert out["images"].startswith("no image files")
    hosts = {d["host"]: d for d in out["devices"]}
    assert set(hosts) == {"hub1", "br1", "br2"}
    assert hosts["br1"]["installed"] == ["17.18.02.0.4112"] and hosts["br1"]["active"] == "17.18.02.0.4112"


async def test_list_software_repository_and_one_site(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    mock_realtime(api)
    mock_repo(api, REPO_ROW)
    out = await run("catsdwan_list_software", {"site": "201", "response_format": "json"})
    (row,) = out["repository"]
    assert row["version"] == "17.18.03.0.5000" and row["needs_controllers"] == "20.18"
    (br2,) = out["devices"]
    assert br2["installed"].startswith("not read: br2 is unreachable")


# --- catsdwan_list_device_actions ----------------------------------------------------------------


async def test_list_device_actions_none_running(api: respx.MockRouter) -> None:
    api.get(f"{STATUS}/tasks").respond(json=fixture("device_action_status_tasks"))
    api.get("/dataservice/device/action/list").respond(json=fixture("device_action_list"))
    out = await run("catsdwan_list_device_actions", {"show_types": True, "response_format": "json"})
    assert out["results"] == [] and "No action is running" in out["note"]
    assert len(out["action_types"]) == 202
    assert {"name": "Reboot", "cancellable": True, "parallel": True} in out["action_types"]


async def test_list_device_actions_with_progress(api: respx.MockRouter) -> None:
    task = {
        "processId": "software_install-1",
        "name": "Software Install",
        "status": "In progress",
        "startTime": 1792743507064,
        "userSessionUserName": "admin",
    }
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": [task]})
    api.get(f"{STATUS}/software_install-1").respond(
        json={
            "data": [
                {"host-name": "br1", "statusId": "success"},
                {
                    "host-name": "br2",
                    "statusId": "failure",
                    "currentActivity": "Failed to install",
                    "activity": ["Downloading", "Failed to install: Not enough space on bootflash"],
                },
            ]
        }
    )
    out = await run("catsdwan_list_device_actions", {"name": "install", "response_format": "json"})
    (row,) = out["results"]
    assert row["action"] == "Software Install" and row["user"] == "admin"
    assert row["progress"] == "1 succeeded, 1 failed, 0 running of 2"
    failed = next(d for d in row["devices"] if d["host"] == "br2")
    assert "Not enough space" in failed["reason"]


# --- catsdwan_reboot_devices ---------------------------------------------------------------------


async def test_reboot_refused_without_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    prev = await run("catsdwan_reboot_devices", {"devices": ["br2"]}, mcp_enable_writes=True)
    assert prev["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in prev["blockers"][-1]
    assert prev["blast_radius"] == 1


async def test_reboot_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    reboot = api.post("/dataservice/device/action/reboot").respond(json={"id": "reboot-1"})
    status = api.get(f"{STATUS}/reboot-1")
    status.side_effect = [
        respx.MockResponse(
            json={"data": [{"host-name": "br2", "uuid": CHASSIS["br2"], "statusId": "in_progress"}]}
        ),
        respx.MockResponse(
            json={"data": [{"host-name": "br2", "uuid": CHASSIS["br2"], "statusId": "success"}]}
        ),
    ]
    async with Client(make_server(**DANGEROUS)) as c:
        prev = (await c.call_tool("catsdwan_reboot_devices", {"devices": ["br2"]})).structured_content
        assert prev["status"] == "preview" and not reboot.called and prev["blast_radius"] == 1
        (dev,) = prev["preview"]["devices"]
        assert dev["host"] == "br2" and dev["site"] == "201" and dev["role"] == "edge"
        assert dev["last_reboots"][0]["reason"] == "reload"
        done = (
            await c.call_tool("catsdwan_reboot_devices", {"devices": ["br2"], "confirm": prev["confirm"]})
        ).structured_content
    assert json.loads(reboot.calls[0].request.content) == {
        "action": "reboot",
        "deviceType": "vedge",
        "devices": [{"deviceIP": "10.0.0.3", "deviceId": CHASSIS["br2"]}],
    }
    result = done["result"]
    assert result["outcome"] == "success" and status.call_count == 2
    assert result["check"] == ["catsdwan_control_connections(device='br2')"]


async def test_reboot_names_a_hub(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    prev = await run("catsdwan_reboot_devices", {"devices": ["hub1"]}, hub_devices="hub1", **DANGEROUS)
    (dev,) = prev["preview"]["devices"]
    assert dev["role"] == "hub" and any("hub" in r for r in prev["preview"]["tier_reasons"])
    assert any("hub reboot" in s for s in prev["side_effects"])


async def test_reboot_refuses_both_edges_of_a_site(api: respx.MockRouter) -> None:
    same_site(api)
    mock_realtime(api)
    prev = await run("catsdwan_reboot_devices", {"devices": ["br1", "br2"]}, **DANGEROUS)
    assert prev["status"] == "blocked"
    assert any("same site 200" in b for b in prev["blockers"]) and prev["blast_radius"] == 2


async def test_reboot_refuses_unreachable_and_the_manager(api: respx.MockRouter) -> None:
    mock_inventory(api, reach={"br2": "unreachable"})
    mock_realtime(api)
    prev = await run("catsdwan_reboot_devices", {"devices": ["br2"]}, **DANGEROUS)
    assert prev["blockers"] == ["br2 is unreachable: the Manager can't push to it"]
    err = await run("catsdwan_reboot_devices", {"devices": ["manager"]}, **DANGEROUS)
    assert "doesn't reboot the Manager" in err["error"]
    err = await run("catsdwan_reboot_devices", {"devices": ["br1", "controller"]}, **DANGEROUS)
    assert "separate calls" in err["error"]


# --- catsdwan_upgrade_software -------------------------------------------------------------------


async def test_upgrade_blocks_on_the_empty_repository(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    mock_repo(api)
    prev = await run("catsdwan_upgrade_software", {"devices": ["br2"], "version": "17.18.03"}, **DANGEROUS)
    assert prev["status"] == "blocked"
    assert prev["blockers"] == [
        "the Manager's software repository is empty (GET /device/action/software and /software/images list "
        "no images): add the image under Maintenance > Software Repository first"
    ]


async def test_upgrade_preview_install_and_activate(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    mock_repo(api, REPO_ROW)
    install = api.post("/dataservice/device/action/install").respond(json={"id": "software_install-2"})
    api.get(f"{STATUS}/software_install-2").respond(
        json={
            "data": [
                {
                    "host-name": "br2",
                    "uuid": CHASSIS["br2"],
                    "statusId": "failure",
                    "currentActivity": "Failed to install software",
                    "activity": [
                        "Downloading image",
                        "Failed to install software: install add failed (20.15.4)",
                    ],
                }
            ]
        }
    )
    args = {"devices": ["br2"], "version": "17.18.03", "activate": True}
    async with Client(make_server(**DANGEROUS)) as c:
        prev = (await c.call_tool("catsdwan_upgrade_software", args)).structured_content
        assert prev["status"] == "preview" and prev["blast_radius"] == 1
        details = prev["preview"]
        assert details["request"].startswith("POST /dataservice/device/action/install (install, activate")
        assert details["body"]["input"]["reboot"] is True
        assert details["body"]["input"]["data"] == [
            {"family": "c8000v", "version": "17.18.03.0.5000", "versionId": "v-1"}
        ]
        (dev,) = details["devices"]
        assert dev["site"] == "201" and dev["bootflash_free_mb"] == 3341
        done = (
            await c.call_tool("catsdwan_upgrade_software", {**args, "confirm": prev["confirm"]})
        ).structured_content
    assert json.loads(install.calls[0].request.content)["devices"] == [
        {"deviceIP": "10.0.0.3", "deviceId": CHASSIS["br2"]}
    ]
    result = done["result"]
    assert result["outcome"] == "failed" and "install add failed" in result["devices"][0]["reason"]


async def test_upgrade_compatibility_disk_and_running_refusals(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api, free={"br2": "700M"})
    mock_repo(
        api,
        REPO_ROW,
        {**REPO_ROW, "versionId": "v-26", "versionName": "26.1.1.0.1"},
        {**REPO_ROW, "versionId": "v-cur", "versionName": "17.18.02.0.4112"},
    )
    newer = await run("catsdwan_upgrade_software", {"devices": ["br1"], "version": "26.1.1.0.1"}, **DANGEROUS)
    assert any("newer than the Manager" in b for b in newer["blockers"])
    disk = await run("catsdwan_upgrade_software", {"devices": ["br2"], "version": "17.18.03"}, **DANGEROUS)
    assert any("700 MB free on bootflash" in b for b in disk["blockers"])
    same = await run(
        "catsdwan_upgrade_software", {"devices": ["br1"], "version": "17.18.02.0.4112"}, **DANGEROUS
    )
    assert any("runs 17.18.02.0.4112 already" in b for b in same["blockers"])
    missing = await run("catsdwan_upgrade_software", {"devices": ["br1"], "version": "17.15.01"}, **DANGEROUS)
    assert any("not in the software repository" in b for b in missing["blockers"])


async def test_upgrade_refuses_both_edges_of_a_site_and_controllers(api: respx.MockRouter) -> None:
    same_site(api)
    mock_realtime(api)
    mock_repo(api, REPO_ROW)
    prev = await run(
        "catsdwan_upgrade_software", {"devices": ["br1", "br2"], "version": "17.18.03"}, **DANGEROUS
    )
    assert any("same site 200" in b for b in prev["blockers"])
    ctl = await run(
        "catsdwan_upgrade_software", {"devices": ["controller"], "version": "17.18.03"}, **DANGEROUS
    )
    assert any("only WAN edges" in b for b in ctl["blockers"])


async def test_upgrade_activates_an_installed_version(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_realtime(api)
    api.get("/dataservice/device/software", params={"deviceId": "10.0.0.3"}).respond(
        json=software("br2", ("17.18.02.0.4112", True), ("17.18.03.0.5000", False))
    )
    mock_repo(api, REPO_ROW)
    prev = await run(
        "catsdwan_upgrade_software",
        {"devices": ["br2"], "version": "17.18.03", "activate": True},
        **DANGEROUS,
    )
    assert prev["status"] == "preview"
    assert prev["preview"]["request"].startswith("POST /dataservice/device/action/changepartition")
    assert prev["preview"]["body"] == {
        "action": "changepartition",
        "devices": [{"version": "17.18.03.0.5000", "deviceIP": "10.0.0.3", "deviceId": CHASSIS["br2"]}],
        "deviceType": "vedge",
    }


def test_device_operation_tiers() -> None:
    def tiers(**kw: Any) -> dict[str, str]:
        reg = make_server(**kw)._stutters_tiers  # type: ignore[attr-defined]
        names = ("catsdwan_reboot_devices", "catsdwan_upgrade_software", "catsdwan_list_software")
        return {n: reg[n].value for n in names if n in reg}

    assert tiers() == {"catsdwan_list_software": "read"}
    assert tiers(mcp_enable_writes=True)["catsdwan_reboot_devices"] == "write"
    assert tiers(**DANGEROUS) == {
        "catsdwan_reboot_devices": "dangerous",
        "catsdwan_upgrade_software": "dangerous",
        "catsdwan_list_software": "read",
    }


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", ops.SOFTWARE_REPO_PATH),
        ("GET", ops.SOFTWARE_IMAGES_PATH),
        ("POST", ops.REBOOT_ACTION_PATH),
        ("POST", ops.INSTALL_PATH),
        ("POST", ops.CHANGE_PARTITION_PATH),
        ("GET", ops.ACTION_LIST_PATH),
        ("GET", "/dataservice/device/software"),
        ("GET", "/dataservice/device/reboothistory"),
    ],
)
def test_device_operation_paths_are_in_the_spec(method: str, path: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, path)
    assert method in methods
