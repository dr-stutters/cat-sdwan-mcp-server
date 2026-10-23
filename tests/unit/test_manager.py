"""W25: Manager health, backups and an on-demand backup.

Recorded on 20.18.3.1 (one node, no DR, no backup yet): cluster health status, summary and details, the
cluster list, resource use, server info, statistics settings, DR status and history, the empty backup and
schedule lists. A backup list with entries, the export answer and the backup-info states are hand-built from
the LocalBackupInfo schema in the Manager's OpenAPI document (the export runs live in the W0 test), and marked
so.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp.manager import (
    backup_addresses,
    backup_rows,
    cluster_ip_configured,
    cluster_nodes,
    export_error,
    export_id,
    resources,
    services,
)
from cat_sdwan_mcp.tools import manager as tools

from .conftest import fixture, make_server
from .test_inventory import call

RECORDED = {
    "/dataservice/clusterManagement/health/status": "cluster_health_status",
    "/dataservice/clusterManagement/health/summary": "cluster_health_summary",
    "/dataservice/clusterManagement/health/details": "cluster_health_details",
    "/dataservice/clusterManagement/list": "cluster_list",
    "/dataservice/management/vManageResourceUtilization": "management_resource_utilization",
    "/dataservice/server/info": "server_info",
    "/dataservice/statistics/settings/status": "statistics_settings_status",
    "/dataservice/disasterrecovery/status": "dr_status",
}


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "POLL_INTERVAL", 0.0)


def mock_health(api: respx.MockRouter, **bodies: Any) -> None:
    for path, name in RECORDED.items():
        body = bodies.get(name, fixture(name))
        status = 400 if isinstance(body, dict) and "error" in body else 200
        api.get(path).respond(status, json=body)


async def test_manager_health_recorded_single_node(api: respx.MockRouter) -> None:
    mock_health(api)
    out = await call("catsdwan_manager_health", {})
    assert out["nodes"] == [
        {
            "host": "manager",
            "vmanage_id": "0",
            "address": "localhost",
            "state": "Ready",
            "persona": "COMPUTE_AND_DATA",
        }
    ]
    [svc] = out["services"]
    assert (
        svc["node"] == "localhost" and "configuration-db" in svc["services_up"] and "services_down" not in svc
    )
    assert out["resources"]["jvm_memory"]["used_percent"] == 73.7
    assert out["resources"]["architecture"] == "amd64" and out["resources"]["cpus"] == 4
    assert out["statistics_processing"]["indexes"] == 37
    assert out["disaster_recovery"] == {"configured": False}
    assert out["verdict"].startswith("healthy: 1 node(s), 8 service(s) up, none down, JVM memory 73.7% used")
    assert out["verdict"].endswith("disaster recovery not configured")
    assert "reports 'error' with no reporter" in out["note"]
    assert out["cluster_ip_configured"] is False and "needs one" in out["cluster_ip_note"]


async def test_manager_health_service_down_and_failed_read(api: respx.MockRouter) -> None:
    status = fixture("cluster_health_status")
    status["data"][1]["messaging-server"] = False
    mock_health(
        api,
        cluster_health_status=status,
        management_resource_utilization={"error": {"message": "boom", "code": "X1"}},
    )
    out = await call("catsdwan_manager_health", {})
    assert out["services"][0]["services_down"] == ["messaging-server"]
    assert out["verdict"] == "attention: localhost: messaging-server down"
    assert "resources" not in out and out["errors"][0].startswith("GET /dataservice/management/")
    assert "note" not in out


async def test_list_backups_empty_and_full(api: respx.MockRouter) -> None:
    route = api.get("/dataservice/backup/list").respond(json=fixture("backup_list"))
    api.get("/dataservice/schedule/list").respond(json=fixture("schedule_list"))
    out = await call("catsdwan_list_backups", {"response_format": "json"})
    assert out["results"] == [] and out["schedules"] == "none"
    assert out["note"].startswith("No backup on the Manager yet")
    route.respond(json={"backupList": [backup("b-1", "ALL_SUCCESS", 1), backup("b-2", "FAILURE", 2)]})
    out = await call("catsdwan_list_backups", {"response_format": "json"})
    assert [r["id"] for r in out["results"]] == ["b-2", "b-1"]  # newest first
    assert out["results"][1]["file"].endswith(".tar.gz") and "note" not in out


def cluster_with_ip() -> dict[str, Any]:
    """The recorded cluster list with a cluster IP set (hand-built: the lab Manager has none)."""
    body = fixture("cluster_list")
    body["data"][0]["isIPConfigured"] = True
    body["data"][0]["data"][0]["configJson"]["deviceIP"] = "10.60.2.10"
    return body


def backup(bid: str, state: str, n: int, task: str = "nightly") -> dict[str, Any]:
    return {  # hand-built LocalBackupInfo
        "localBackupInfoId": bid,
        "taskName": task,
        "backupType": "ON_DEMAND",
        "backupState": state,
        "createTime": 1792758000000 + n * 60000,
        "downloadURL": f"/dataservice/tenantbackup/download/1792758000000/backup_{n}.tar.gz",
    }


async def test_create_backup_preview_then_follow(api: respx.MockRouter) -> None:
    api.get("/dataservice/backup/list").respond(json={"backupList": [backup("b-1", "ALL_SUCCESS", 1)]})
    api.get("/dataservice/clusterManagement/list").respond(json=cluster_with_ip())
    export = api.post("/dataservice/backup/export").respond(json={"localBackupInfoId": "b-9"})
    states = iter(["IN_PROGRESS", "STATS_DB_EXPORT_SUCCESS", "ALL_SUCCESS"])
    info = api.get("/dataservice/backup/backupinfo/b-9")
    info.side_effect = lambda request: httpx.Response(
        200, json=backup("b-9", next(states), 9, task="before upgrade")
    )
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (
            await c.call_tool("catsdwan_create_backup", {"task_name": "before upgrade"})
        ).structured_content
        assert prev["status"] == "preview" and not export.called
        assert prev["preview"]["newest_backup"]["id"] == "b-1"
        assert "GUI and API are slower" in prev["preview"]["warning"]
        args = {"task_name": "before upgrade", "confirm": prev["confirm"]}
        done = (await c.call_tool("catsdwan_create_backup", args)).structured_content["result"]
    assert json.loads(export.calls[0].request.content) == {
        "backupType": "ON_DEMAND",
        "taskName": "before upgrade",
        "srcIpAddress": "10.60.2.10",
        "followerIpAddressList": ["10.60.2.10"],
    }
    assert done["outcome"] == "success" and done["id"] == "b-9" and done["state"] == "ALL_SUCCESS"
    assert done["file"].endswith("backup_9.tar.gz") and info.call_count == 3


async def test_create_backup_blocked_while_one_runs(api: respx.MockRouter) -> None:
    api.get("/dataservice/backup/list").respond(json={"backupList": [backup("b-3", "IN_PROGRESS", 3)]})
    api.get("/dataservice/clusterManagement/list").respond(json=cluster_with_ip())
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
    assert prev["status"] == "blocked"
    [blocker] = prev["blockers"]
    assert blocker.startswith("backup nightly is still IN_PROGRESS")


async def test_create_backup_blocked_without_cluster_ip(api: respx.MockRouter) -> None:
    # Recorded: the lab Manager's cluster list (isIPConfigured false, deviceIP 'localhost').
    api.get("/dataservice/backup/list").respond(json=fixture("backup_list"))
    api.get("/dataservice/clusterManagement/list").respond(json=fixture("cluster_list"))
    export = api.post("/dataservice/backup/export").respond(json={})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
    assert prev["status"] == "blocked" and not export.called
    [blocker] = prev["blockers"]
    assert blocker.startswith(
        "the Manager has no cluster IP configured (Administration > Cluster Management): a backup needs it"
    )
    assert "isIPConfigured false" in blocker
    assert prev["preview"]["cluster"]["ip_configured"] is False


async def test_create_backup_export_failed_is_readable(api: respx.MockRouter) -> None:
    api.get("/dataservice/backup/list").respond(json=fixture("backup_list"))
    api.get("/dataservice/clusterManagement/list").respond(json=cluster_with_ip())
    # The lab's answer when the addresses pass validation but no cluster IP is set.
    api.post("/dataservice/backup/export").respond(
        400, json={"error": {"message": "Failed to export scheduled backup data", "code": "EXPORT_FAILED"}}
    )
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
        res = await c.call_tool("catsdwan_create_backup", {"confirm": prev["confirm"]}, raise_on_error=False)
    text = str(res.content)
    assert res.is_error and "Backup not started: the Manager refused the backup (EXPORT_FAILED" in text
    assert "Administration > Cluster Management" in text


async def test_create_backup_hidden_without_writes_and_name_checked(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catsdwan_create_backup" not in names and "catsdwan_list_backups" in names
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = await c.call_tool("catsdwan_create_backup", {"task_name": "bad;name"}, raise_on_error=False)
    assert res.is_error and "task_name may hold" in str(res.content)


def test_helpers() -> None:
    assert cluster_nodes({"data": [{"host-name": "m2", "deviceIP": "10.1.1.2", "state": "Ready"}]}) == [
        {"host": "m2", "address": "10.1.1.2", "state": "Ready"}
    ]
    three = [
        {"vmanage_id": "1", "address": "10.1.1.2"},
        {"vmanage_id": "0", "address": "10.1.1.1"},
        {"vmanage_id": "2", "address": "10.1.1.3"},
    ]
    assert backup_addresses(three) == ("10.1.1.1", ["10.1.1.2", "10.1.1.1", "10.1.1.3"])
    assert backup_addresses(cluster_nodes(fixture("cluster_list"))) == (None, [])
    assert cluster_ip_configured(fixture("cluster_list")) is False and cluster_ip_configured({}) is None
    refused = export_error("Validation failed for LocalBackupInfo object: InValid number of IP in List")
    assert refused is not None and "srcIpAddress" in refused
    assert export_error("other") is None
    assert services({"data": [{"deviceIP": "a", "olap-db": False}]}) == [
        {"node": "a", "services_up": [], "services_down": ["olap-db"]}
    ]
    assert (
        resources({"jvmMemoryAllocated": "512 MB", "jvmMemoryConsumed": "256 MB"})["jvm_memory"][
            "used_percent"
        ]
        == 50.0
    )
    assert export_id({"data": {"taskId": "t-1"}}) == "t-1" and export_id({}) is None
    assert backup_rows(fixture("backup_list")) == []
