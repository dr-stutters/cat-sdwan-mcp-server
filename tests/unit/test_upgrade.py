"""W27: controller upgrades.

Recorded on 20.18.3.1: no version available (upgrade and patch), the version-compliance answer for 20.18.3.1,
the controller inventory, the empty backup list. A repository with 26.1.1 images, a compliance answer with a
too-old edge, a recent backup and the schedule answer are hand-built from the OpenAPI document's examples, and
marked so. Live, the tool is preview-only (no images in the lab).
"""

import json
from datetime import UTC, datetime
from typing import Any

import respx
from fastmcp import Client

from cat_sdwan_mcp.upgrade import compliance, compliance_problems, schedule_body, versions

from .conftest import fixture, make_server

VERSIONS = "/dataservice/v1/controllers-upgrade/available-versions"
COMPLIANCE = "/dataservice/v1/controllers-upgrade/version-compliance-info"
AVAILABLE = {  # hand-built (the OpenAPI example's shape)
    "availableVersions": [
        {"version": "26.1.1", "imageType": ["Manager", "Controller", "Validator"], "location": "vmanage",
         "tag": "recommended", "compatibleControllerTypes": ["Manager", "Controller", "Validator"]}
    ]
}  # fmt: skip


def recent_backup() -> dict[str, Any]:
    now = int(datetime.now(UTC).timestamp() * 1000)
    return {  # hand-built
        "backupList": [
            {"localBackupInfoId": "b-1", "taskName": "pre-upgrade", "backupState": "ALL_SUCCESS",
             "createTime": now - 3600_000}
        ]
    }  # fmt: skip


def mock(api: respx.MockRouter, available: Any = None, backups: Any = None, comp: Any = None) -> respx.Route:
    api.get(VERSIONS).respond(json=available or fixture("v1_controllers_upgrade_versions_upgrade"))
    api.get("/dataservice/backup/list").respond(json=backups or fixture("backup_list"))
    api.get(COMPLIANCE).respond(json=comp or fixture("v1_controllers_upgrade_compliance"))
    return api.post("/dataservice/v1/controllers-upgrade").respond(
        json={"processId": "controllers_upgrade-1"}
    )


async def preview(args: dict[str, Any], **kw: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **kw)) as c:
        return (await c.call_tool("catsdwan_upgrade_controllers", args)).structured_content


async def test_upgrade_blocked_no_images_in_repository(api: respx.MockRouter) -> None:
    post = mock(api)
    prev = await preview({"version": "26.1.1"})
    assert prev["status"] == "blocked" and not post.called
    blockers = prev["blockers"]
    assert blockers[0].startswith("the Manager's software repository has no controller image for an upgrade")
    assert any("no successful Manager backup from the last 24 h" in b for b in blockers)
    assert any("MCP_ENABLE_DANGEROUS" in b for b in blockers)
    p = prev["preview"]
    assert p["available_versions"] == "none in the repository"
    assert [c["type"] for c in p["upgrade_order"]] == ["Validator", "Controller", "Manager"]
    assert p["upgrade_order"][0]["version"] == "20.18.3.1"


async def test_upgrade_preview_without_version_lists_and_blocks(api: respx.MockRouter) -> None:
    mock(api, available=AVAILABLE, backups=recent_backup())
    prev = await preview({}, mcp_enable_dangerous=True)
    assert prev["blockers"] == ["name a version: 26.1.1"]


async def test_upgrade_compliance_blocks_old_edge(api: respx.MockRouter) -> None:
    comp = fixture("v1_controllers_upgrade_compliance")
    # As the lab answered for 26.1.1: the controllers and validators to be upgraded count as non-compliant
    # (never blocking), three edges are near the minimum (a warning); two too-old edges added by hand block.
    comp.update(
        {"version": "26.1.1", "minimumDeviceCompatibleVersion": "17.15", "nonCompliantDeviceCount": 2,
         "nonCompliantControllersCount": 1, "nonCompliantValidatorsCount": 1,
         "nearNonCompliantDeviceCount": 3}
    )  # fmt: skip
    mock(api, available=AVAILABLE, backups=recent_backup(), comp=comp)
    prev = await preview({"version": "26.1.1"}, mcp_enable_dangerous=True)
    assert prev["blockers"] == [
        "2 edge(s) run a release older than 26.1.1 supports (minimum 17.15): upgrade them first (edge "
        "upgrades), or remove them"
    ]
    assert prev["preview"]["warnings"] == [
        "3 edge(s) are near the minimum release 26.1.1 supports (17.15): plan their upgrade next"
    ]
    assert prev["preview"]["compliance"]["non_compliant_controllers"] == 1


async def test_upgrade_schedules_later_when_clear(api: respx.MockRouter) -> None:
    post = mock(api, available=AVAILABLE, backups=recent_backup())
    args = {"version": "26.1.1", "start": "2099-01-02T03:30", "timezone": "UTC"}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        prev = (await c.call_tool("catsdwan_upgrade_controllers", args)).structured_content
        assert prev["status"] == "preview" and prev["preview"]["newest_backup"]["id"] == "b-1"
        done = (
            await c.call_tool("catsdwan_upgrade_controllers", {**args, "confirm": prev["confirm"]})
        ).structured_content["result"]
    body = json.loads(post.calls[0].request.content)
    assert body["action"] == "controllers_upgrade" and body["targetVersion"] == "26.1.1"
    assert body["imageLocation"] == "vmanage" and body["isScheduleNow"] is False
    assert body["schedule"]["Manager"] == {
        "actionStartDate": "Jan 02 2099",
        "actionStartTime": "03:30:00 AM",
        "timeZone": "UTC",
    }
    assert done["outcome"] == "scheduled" and done["process_id"] == "controllers_upgrade-1"
    assert done["cancel_with"] == "catsdwan_upgrade_controllers(cancel='controllers_upgrade-1')"


async def test_upgrade_cancel(api: respx.MockRouter) -> None:
    api.get("/dataservice/v1/controllers-upgrade/status").respond(json={"status": "Scheduled"})
    put = api.put("/dataservice/v1/controllers-upgrade/cancel").respond(json={"status": "Success"})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        prev = (await c.call_tool("catsdwan_upgrade_controllers", {"cancel": "p-1"})).structured_content
        assert prev["status"] == "preview"
        args = {"cancel": "p-1", "confirm": prev["confirm"]}
        await c.call_tool("catsdwan_upgrade_controllers", args)
    assert json.loads(put.calls[0].request.content) == {"processId": "p-1"}


async def test_upgrade_past_start_refused(api: respx.MockRouter) -> None:
    mock(api)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        res = await c.call_tool(
            "catsdwan_upgrade_controllers",
            {"version": "26.1.1", "start": "2020-01-01T00:00"},
            raise_on_error=False,
        )
    assert res.is_error and "in the past" in str(res.content)


def test_helpers() -> None:
    assert versions(fixture("v1_controllers_upgrade_versions_patch")) == []
    c = compliance(fixture("v1_controllers_upgrade_compliance"))
    assert c["minimum_edge"] == "17.12" and c["non_compliant_edges"] == 0
    assert compliance_problems(c, "20.18.3.1") == ([], [])
    assert list(schedule_body(datetime(2026, 10, 24, 14, 5), "UTC")) == ["Validator", "Controller", "Manager"]
