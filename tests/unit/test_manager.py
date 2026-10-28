"""W25: Manager health, backups and an on-demand backup.

Recorded on 20.18.3.1 (one node, no DR, no backup yet): cluster health status, summary and details, the
cluster list, resource use, server info, statistics settings, DR status and history, the empty backup and
schedule lists. A backup list with entries, the export answer and the backup-info states are hand-built from
the LocalBackupInfo schema in the Manager's OpenAPI document (the export runs live in the W0 test), and marked
so.
"""

import json
import re
import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp.manager import (
    active_schedule,
    backup_addresses,
    backup_destination,
    backup_rows,
    cluster_ip_configured,
    cluster_nodes,
    export_error,
    export_id,
    resources,
    services,
    vm_version,
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


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SCHEDULE_ID = "00000000-0000-4000-8000-0000000b4c01"
INFO_ID = "00000000-0000-4000-8000-0000000b4c09"


def active_schedule_list(status: str = "ACTIVE") -> dict[str, Any]:
    """The /schedule/list row recorded on 20.18.3.1 after the l3 run (#132; id replaced, status CANCELLED
    there after the schedule was deleted: ACTIVE is how it answered while it existed)."""
    return {
        "scheduleList": [
            {
                "scheduleName": "mcp-r96-backup",
                "scheduleId": SCHEDULE_ID,
                "startDateTime": 1793250000000,
                "endDateTime": 1793336400000,
                "backupDurationInHour": 24,
                "status": status,
                "retryCount": 1,
                "lastSuccessBackupTime": -1,
                "destination": {
                    "backupDest": "LOCAL",
                    "vmVersion": "20.18",
                    "backupTTLInDays": 1,
                    "backupStorageInGB": 5,
                    "numOfReplica": 1,
                    "backupDir": "/backup",
                },
            }
        ]
    }


def mock_backup_reads(
    api: respx.MockRouter, rows: list[dict[str, Any]] | None = None, schedules: Any = None
) -> None:
    api.get("/dataservice/backup/list").respond(json={"backupList": rows or []})
    api.get("/dataservice/clusterManagement/list").respond(json=cluster_with_ip())
    api.get("/dataservice/schedule/list").respond(json=schedules or fixture("schedule_list"))


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
    mock_backup_reads(api, [backup("b-1", "ALL_SUCCESS", 1)], active_schedule_list())
    # Recorded (#132, l3): the 200 answer echoes the localBackupInfoId sent as backupInfoId.
    export = api.post("/dataservice/backup/export")
    export.side_effect = lambda request: httpx.Response(
        200,
        json={
            "taskId": "00000000-0000-4000-8000-0000000b4c0a",
            "backupInfoId": json.loads(request.content)["localBackupInfoId"],
            "status": "in_progress",
        },
    )
    states = iter(["IN_PROGRESS", "STATS_DB_EXPORT_SUCCESS", "ALL_SUCCESS"])
    info = api.get(url__regex=r"/dataservice/backup/backupinfo/[0-9a-f-]+$")
    info.side_effect = lambda request: httpx.Response(
        200, json=backup(request.url.path.rsplit("/", 1)[1], next(states), 9, task="before upgrade")
    )
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (
            await c.call_tool("catsdwan_create_backup", {"task_name": "before upgrade"})
        ).structured_content
        assert prev["status"] == "preview" and not export.called
        assert prev["preview"]["newest_backup"]["id"] == "b-1"
        assert prev["preview"]["schedule"] == {"id": SCHEDULE_ID, "name": "mcp-r96-backup"}
        assert "'localBackupInfoId': '<new uuid>'" in prev["preview"]["request"]
        assert "notes" not in prev["preview"]
        assert "GUI and API are slower" in prev["preview"]["warning"]
        args = {"task_name": "before upgrade", "confirm": prev["confirm"]}
        done = (await c.call_tool("catsdwan_create_backup", args)).structured_content["result"]
    sent = json.loads(export.calls[0].request.content)
    assert UUID_RE.match(sent.pop("taskId")) and UUID_RE.match(bid := sent.pop("localBackupInfoId"))
    assert abs(sent.pop("createTime") / 1000 - time.time()) < 60
    assert sent == {
        "backupType": "ON_DEMAND",
        "backupState": "SCHEDULED",
        "taskName": "before upgrade",
        "srcIpAddress": "10.60.2.10",
        "followerIpAddressList": ["10.60.2.10"],
        "scheduleId": SCHEDULE_ID,
        "destination": {
            "backupDest": "LOCAL",
            "backupDir": "/backup",
            "backupStorageInGB": 5,
            "backupTTLInDays": 1,
            "numOfReplica": 1,
            "vmVersion": "20.18",
        },
    }
    assert done["outcome"] == "success" and done["id"] == bid and done["state"] == "ALL_SUCCESS"
    assert info.calls[0].request.url.path == f"/dataservice/backup/backupinfo/{bid}"
    assert done["file"].endswith("backup_9.tar.gz") and info.call_count == 3


async def test_create_backup_without_schedule_tries_anyway(api: respx.MockRouter) -> None:
    # Recorded: the empty schedule list; a cancelled schedule is not active either.
    mock_backup_reads(api, schedules=active_schedule_list("CANCELLED"))
    export = api.post("/dataservice/backup/export").respond(
        200,
        json={"taskId": "t", "backupInfoId": INFO_ID, "status": "in_progress"},
    )
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {"wait": False})).structured_content
        assert prev["status"] == "preview" and prev["preview"]["schedule"] == "none active"
        [note] = prev["preview"]["notes"]
        assert note.startswith("no active backup schedule") and "/dataservice/schedule/create" in note
        args = {"wait": False, "confirm": prev["confirm"]}
        out = (await c.call_tool("catsdwan_create_backup", args)).structured_content["result"]
    sent = json.loads(export.calls[0].request.content)
    assert "scheduleId" not in sent and sent["destination"]["vmVersion"] == "20.18"
    assert sent["destination"]["backupDest"] == "LOCAL" and sent["backupState"] == "SCHEDULED"
    assert out["id"] == INFO_ID and out["check_with"] == "catsdwan_list_backups"


async def test_create_backup_blocked_while_one_runs(api: respx.MockRouter) -> None:
    mock_backup_reads(api, [backup("b-3", "IN_PROGRESS", 3)])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
    assert prev["status"] == "blocked"
    [blocker] = prev["blockers"]
    assert blocker.startswith("backup nightly is still IN_PROGRESS")


async def test_create_backup_blocked_without_cluster_ip(api: respx.MockRouter) -> None:
    # Recorded: the lab Manager's cluster list (isIPConfigured false, deviceIP 'localhost').
    api.get("/dataservice/backup/list").respond(json=fixture("backup_list"))
    api.get("/dataservice/clusterManagement/list").respond(json=fixture("cluster_list"))
    api.get("/dataservice/schedule/list").respond(json=fixture("schedule_list"))
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


# Recorded on 20.18.3.1 (#132): the answer to a body with `destination` but without the ids/createTime/state.
NPE_ANSWER = {
    "error": {
        "message": "Failed to export scheduled backup data",
        "code": "EXPORT_FAILED",
        "details": "java.lang.NullPointerException: Value in JsonObjects name/value pair cannot be null",
    }
}


@pytest.mark.parametrize("schedules", [None, "active"])
async def test_create_backup_export_failed_is_readable(api: respx.MockRouter, schedules: str | None) -> None:
    mock_backup_reads(api, schedules=active_schedule_list() if schedules else None)
    api.post("/dataservice/backup/export").respond(400, json=NPE_ANSWER)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
        res = await c.call_tool("catsdwan_create_backup", {"confirm": prev["confirm"]}, raise_on_error=False)
    text = str(res.content)
    assert res.is_error and "Backup not started: the Manager refused the backup before creating" in text
    assert "JsonObjects name/value pair cannot be null" in text  # the Manager's own text is quoted
    assert "Cluster Management" not in text  # the cluster IP is set: it is not blamed
    if schedules:
        assert "No active backup schedule" not in text and "vmanage-server.log" in text
    else:
        assert "No active backup schedule was found" in text and "/dataservice/schedule/create" in text


# Recorded on 20.18.3.1 (#165, l9): the first GET /backup/backupinfo/{id} right after the export call, before
# the Manager has written the record (code and message as quoted in the issue; the envelope is the Manager's).
RECORD_MISSING = {
    "error": {
        "message": "LocalBackUpInfo Id is missing in config-db: Exception occurred in creating "
        "LocalBackupInfo POJO from vertex for schedulerId",
        "code": "LOCALBK_ID_NOT_FOUND",
    }
}


def export_echo(request: httpx.Request) -> httpx.Response:
    sent = json.loads(request.content)["localBackupInfoId"]
    return httpx.Response(200, json={"taskId": "t", "backupInfoId": sent, "status": "in_progress"})


async def test_create_backup_waits_out_the_missing_record(api: respx.MockRouter) -> None:
    mock_backup_reads(api)  # no schedule: proven to need none (#165)
    api.post("/dataservice/backup/export").side_effect = export_echo
    answers = iter([(404, None), (200, "IN_PROGRESS"), (200, "ALL_SUCCESS")])

    def info_answer(request: httpx.Request) -> httpx.Response:
        status, state = next(answers)
        if state is None:
            return httpx.Response(status, json=RECORD_MISSING)
        return httpx.Response(status, json=backup(request.url.path.rsplit("/", 1)[1], state, 9, task="l9"))

    info = api.get(url__regex=r"/dataservice/backup/backupinfo/[0-9a-f-]+$")
    info.side_effect = info_answer
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {"task_name": "l9"})).structured_content
        [note] = prev["preview"]["notes"]
        assert "which the Manager accepts" in note
        assert note.index("accepts") < note.index("Only if it refuses")
        args = {"task_name": "l9", "confirm": prev["confirm"]}
        done = (await c.call_tool("catsdwan_create_backup", args)).structured_content["result"]
    assert done["outcome"] == "success" and done["state"] == "ALL_SUCCESS" and info.call_count == 3
    assert done["file"].endswith("backup_9.tar.gz")


async def test_create_backup_follows_the_list_while_the_record_is_missing(api: respx.MockRouter) -> None:
    sent: dict[str, str] = {}

    def export(request: httpx.Request) -> httpx.Response:
        sent["id"] = json.loads(request.content)["localBackupInfoId"]
        return export_echo(request)

    def listed(request: httpx.Request) -> httpx.Response:
        rows = [backup(sent["id"], "ALL_SUCCESS", 9)] if sent else []
        return httpx.Response(200, json={"backupList": rows})

    api.get("/dataservice/backup/list").side_effect = listed
    api.get("/dataservice/clusterManagement/list").respond(json=cluster_with_ip())
    api.get("/dataservice/schedule/list").respond(json=fixture("schedule_list"))
    api.post("/dataservice/backup/export").side_effect = export
    info = api.get(url__regex=r"/dataservice/backup/backupinfo/[0-9a-f-]+$").respond(404, json=RECORD_MISSING)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
        res = (await c.call_tool("catsdwan_create_backup", {"confirm": prev["confirm"]})).structured_content
    done = res["result"]
    assert done["outcome"] == "success" and done["id"] == sent["id"] and info.call_count == 1


async def test_create_backup_missing_record_past_the_grace_is_an_error(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools, "RECORD_GRACE", 0.05)
    mock_backup_reads(api)
    api.post("/dataservice/backup/export").side_effect = export_echo
    info = api.get(url__regex=r"/dataservice/backup/backupinfo/[0-9a-f-]+$").respond(404, json=RECORD_MISSING)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_create_backup", {})).structured_content
        res = await c.call_tool("catsdwan_create_backup", {"confirm": prev["confirm"]}, raise_on_error=False)
    text = str(res.content)
    assert res.is_error and "The backup was started" in text and "still has no record of it" in text
    assert "catsdwan_list_backups" in text and info.call_count >= 2  # it kept waiting first


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
    no_ip = export_error("400 EXPORT_FAILED: Failed to export scheduled backup data", cluster_ip=False)
    assert no_ip is not None and "Administration > Cluster Management" in no_ip
    assert vm_version("20.18.3.1") == "20.18" and vm_version("20.15.1, 20.18.3.1") == "20.15"
    assert vm_version("unknown") is None
    assert backup_destination(None, None) == {
        "backupDest": "LOCAL",
        "backupDir": "/backup",
        "backupStorageInGB": 5,
        "backupTTLInDays": 1,
        "numOfReplica": 1,
    }
    assert active_schedule(active_schedule_list("CANCELLED")["scheduleList"]) is None
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
