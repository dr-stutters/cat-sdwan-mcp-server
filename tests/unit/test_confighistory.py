"""W20: configuration history (catsdwan_config_history).

Shapes recorded on the lab Manager (20.18.3.1, br1 = 10.0.0.2): the list with a system_ip rule and `fields`
(two versions: 'cli' at the first sync, 'cli/ztp' after the W8 deploy of mcp-test), one version as
{data: [[row]]}, and diff/list answering both texts ([{config_1}, {config_2}]), not a diff.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import confighistory as chh
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

HIST = "/dataservice/device/history/config"
NEW_ID = "00000000-0000-4000-8000-000000000172"  # cli/ztp, after the deploy
OLD_ID = "00000000-0000-4000-8000-000000000175"  # cli, the first sync


async def run(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server()) as c:
        result = await c.call_tool(name, args)
    return result.structured_content


def mock_history(api: respx.MockRouter) -> dict[str, respx.Route]:
    mock_inventory(api)
    return {
        "list": api.get(HIST).respond(json=fixture("device_history_config_list_br1")),
        "one": api.get(f"{HIST}/{NEW_ID}").respond(json=fixture("device_history_config_one_br1")),
        "diff": api.get(f"{HIST}/diff/list").respond(json=fixture("device_history_config_diff_br1")),
    }


# --- helpers -------------------------------------------------------------------------------------


def test_history_query_carries_the_device_rule_and_no_text() -> None:
    q = json.loads(chh.history_query("10.0.0.2", 48, 500))
    rules = q["query"]["rules"]
    assert rules[0]["operator"] == "last_n_hours" and rules[0]["value"] == ["48"]
    assert rules[1] == {"value": ["10.0.0.2"], "field": "system_ip", "type": "string", "operator": "in"}
    assert "configuration" not in q["fields"] and q["size"] == 500


def test_history_rows_newest_first_and_other_devices_dropped() -> None:
    body = fixture("device_history_config_br1")  # the recorded answer WITHOUT a system_ip rule: every device
    rows = chh.history_rows(body, "10.0.0.2")
    assert [r["config_id"] for r in rows] == [NEW_ID, OLD_ID]
    assert rows[0]["index"] == 0 and rows[0]["mode"] == "cli/ztp" and "pushed" in rows[0]["note"]
    assert rows[1]["time"].endswith("Z")


def test_pick_version_and_version_at() -> None:
    rows = chh.history_rows(fixture("device_history_config_list_br1"), "10.0.0.2")
    assert chh.pick_version(rows, "latest")["config_id"] == NEW_ID
    assert chh.pick_version(rows, "previous")["config_id"] == OLD_ID
    assert chh.pick_version(rows, "1")["config_id"] == OLD_ID
    assert chh.pick_version(rows, OLD_ID.upper())["config_id"] == OLD_ID
    with pytest.raises(Exception, match="out of range"):
        chh.pick_version(rows, "5")
    with pytest.raises(Exception, match="not one of"):
        chh.pick_version(rows, "nope")
    between = (rows[0]["entry_time"] + rows[1]["entry_time"]) // 2
    picked = chh.version_at(rows, between)
    assert picked is not None and picked["config_id"] == OLD_ID
    assert chh.version_at(rows, rows[1]["entry_time"] - 1) is None


def test_parse_when() -> None:
    assert chh.parse_when("1792742865322") == 1792742865322
    assert chh.parse_when("2026-10-22T00:00:00Z") == chh.parse_when("2026-10-22T00:00:00+00:00")
    assert chh.parse_when("2026-10-22") == chh.parse_when("2026-10-22T00:00:00Z")
    with pytest.raises(Exception, match="ISO 8601"):
        chh.parse_when("last tuesday")


def test_version_text_and_diff_texts() -> None:
    row = chh.version_text(fixture("device_history_config_one_br1"))
    assert row is not None and row["config_id"] == NEW_ID and "banner motd" in row["configuration"]
    assert chh.version_text({"data": [[]]}) is None
    one, two = chh.diff_texts(fixture("device_history_config_diff_br1"))
    assert one is not None and two is not None and "banner motd" in two and "banner motd" not in one


@pytest.mark.parametrize("template", [chh.HISTORY_PATH, chh.VERSION_PATH.replace("{id}", "x"), chh.DIFF_PATH])
def test_history_paths_are_in_the_spec(template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, "GET", template)
    assert "GET" in methods


# --- tool ----------------------------------------------------------------------------------------


async def test_list_versions(api: respx.MockRouter) -> None:
    routes = mock_history(api)
    out = await run("catsdwan_config_history", {"device": "br1"})
    assert out["host"] == "br1" and out["system_ip"] == "10.0.0.2" and out["versions_stored"] == 2
    assert [v["mode"] for v in out["versions"]] == ["cli/ztp", "cli"]
    req = routes["list"].calls.last.request
    assert req.url.params["deviceId"] == "10.0.0.2"
    q = json.loads(req.url.params["query"])
    assert {"value": ["10.0.0.2"], "field": "system_ip", "type": "string", "operator": "in"} in q["query"][
        "rules"
    ]
    assert not routes["one"].called and not routes["diff"].called


async def test_one_version_masked_with_section(api: respx.MockRouter) -> None:
    routes = mock_history(api)
    body = copy.deepcopy(fixture("device_history_config_one_br1"))
    body["data"][0][0]["configuration"] += "  snmp-server community s3cr3t-comm RO\n"
    routes["one"].respond(json=body)
    out = await run("catsdwan_config_history", {"device": "10.0.0.2", "version": "latest"})
    assert out["version"]["config_id"] == NEW_ID and "banner motd" in out["configuration"]
    assert "s3cr3t-comm" not in json.dumps(out) and out["masked_lines"] >= 1
    banner = await run("catsdwan_config_history", {"device": "br1", "version": "0", "section": "banner"})
    assert banner["configuration"].startswith("banner motd") and banner["lines"] == 1


async def test_at_picks_the_version_in_effect(api: respx.MockRouter) -> None:
    routes = mock_history(api)
    old = api.get(f"{HIST}/{OLD_ID}").respond(json=fixture("device_history_config_one_br1"))
    out = await run("catsdwan_config_history", {"device": "br1", "at": "1792750000000"})
    assert out["version"]["config_id"] == OLD_ID and old.called and not routes["one"].called
    with pytest.raises(ToolError, match="No stored configuration at or before"):
        await run("catsdwan_config_history", {"device": "br1", "at": "2020-01-01T00:00:00Z"})


async def test_diff_names_the_banner_line(api: respx.MockRouter) -> None:
    routes = mock_history(api)
    out = await run("catsdwan_config_history", {"device": "br1", "diff": True})
    assert out["diff_from"]["config_id"] == OLD_ID and out["diff_to"]["config_id"] == NEW_ID
    params = routes["diff"].calls.last.request.url.params
    assert params["config_id1"] == OLD_ID and params["config_id2"] == NEW_ID
    d = out["diff"]
    assert any(b.startswith("banner motd") for b in d["only_in_newer"])
    assert "only in the newer" in d["summary"] and "only_intended" not in d
    only_banner = await run(
        "catsdwan_config_history",
        {"device": "br1", "diff_between": ["latest", "previous"], "section": "banner"},
    )
    assert only_banner["diff"]["only_in_newer"] == [b for b in d["only_in_newer"] if "banner" in b]


async def test_diff_falls_back_to_the_two_versions(api: respx.MockRouter) -> None:
    routes = mock_history(api)
    routes["diff"].respond(
        400, json={"error": {"message": "Query param is empty/invlaid", "code": "INVALID_QUERY"}}
    )
    one = fixture("device_history_config_one_br1")
    older = copy.deepcopy(one)
    older["data"][0][0]["configuration"] = one["data"][0][0]["configuration"].replace("banner motd", "! no")
    api.get(f"{HIST}/{OLD_ID}").respond(json=older)
    out = await run("catsdwan_config_history", {"device": "br1", "diff": True})
    assert "for each version" in out["source"] and out["diff"]["in_sync"] is False


async def test_refusals(api: respx.MockRouter) -> None:
    mock_history(api)
    with pytest.raises(ToolError, match="at most one"):
        await run("catsdwan_config_history", {"device": "br1", "version": "latest", "at": "2026-10-22"})
    with pytest.raises(ToolError, match="same configuration"):
        await run("catsdwan_config_history", {"device": "br1", "diff_between": ["latest", "0"]})


async def test_empty_history(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(HIST).respond(json={"header": {}, "pageInfo": {"count": 0}, "data": []})
    out = await run("catsdwan_config_history", {"device": "br1", "since_hours": 1})
    assert out["versions_stored"] == 0 and "stored no configuration" in out["note"]
