"""W6: catsdwan_search_spec, catsdwan_get_definition and catsdwan_api_call on a subset of the recorded
20.18.3.1 OpenAPI document (GET /apidocs/vmanageapi.json; `scripts/spec_subset.py` cut 39 of its 2811
paths with the components they reference, same structure: OpenAPI 3.0.1, paths relative to
`servers: /dataservice`)."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp._core import InvalidRequest
from cat_sdwan_mcp.spec import SPEC_PATH, api_path, classify

from .conftest import fixture, make_server


def mock_spec(api: respx.MockRouter) -> respx.Route:
    return api.get(SPEC_PATH).respond(json=fixture("spec_subset"))


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        result = await c.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    text = "\n".join(getattr(x, "text", "") for x in result.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


# --- classification and paths --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "tier"),
    [
        ("GET", "/dataservice/device/action/reboot", "read"),
        ("GET", "/dataservice/template/device", "read"),
        ("POST", "/dataservice/statistics/approute", "read"),
        ("POST", "/dataservice/statistics/bfd/page", "read"),
        ("POST", "/dataservice/statistics/approute/aggregation", "read"),
        ("POST", "/dataservice/statistics/dynamic/collect", "write"),
        ("POST", "/dataservice/alarms", "read"),
        ("POST", "/dataservice/alarms/page", "read"),
        ("POST", "/dataservice/alarms/clear", "write"),
        ("POST", "/dataservice/alarms/markviewed", "write"),
        ("POST", "/dataservice/event", "read"),
        ("POST", "/dataservice/auditlog", "read"),
        ("POST", "/dataservice/v1/config-group", "write"),
        ("PUT", "/dataservice/v1/config-group/abc", "write"),
        ("DELETE", "/dataservice/v1/policy-group/abc", "write"),
        ("POST", "/dataservice/device/action/reboot", "dangerous"),
    ],
)
def test_classify(method: str, path: str, tier: str) -> None:
    assert classify(method, path) == tier


def test_api_path_prefixes_and_refuses_traversal() -> None:
    assert api_path("/device") == "/dataservice/device"
    assert api_path("device/bfd/sessions") == "/dataservice/device/bfd/sessions"
    assert api_path("/dataservice/v1/config-group") == "/dataservice/v1/config-group"
    for bad in ("/dataservice/../admin", "https://x/dataservice/device", "/device?deviceId=1", "/v1/{id}"):
        with pytest.raises(InvalidRequest):
            api_path(bad)


# --- search and definitions ----------------------------------------------------------------------


async def test_search_spec_finds_realtime_and_bulk_bfd(api: respx.MockRouter) -> None:
    route = mock_spec(api)
    out = await call("catsdwan_search_spec", {"query": "bfd", "limit": 50})
    names = [r["name"] for r in out["results"]]
    assert "GET /dataservice/device/bfd/sessions" in names  # real-time, from the device
    assert "POST /dataservice/statistics/bfd" in names  # bulk statistics
    assert route.call_count == 1
    # the spec needs the login: the request carried the JWT
    assert route.calls[0].request.headers["Authorization"] == "Bearer jwt-123"


async def test_get_definition_shows_the_variables_parameters(api: respx.MockRouter) -> None:
    mock_spec(api)
    out = await call(
        "catsdwan_get_definition",
        {"name": "GET /dataservice/v1/config-group/{configGroupId}/device/variables"},
    )
    params = {p["name"]: p for p in out["operations"][0]["params"]}
    assert params["configGroupId"]["required"] is True
    assert "device-id" in params and "suggestions" in params


async def test_status_lists_the_spec_source(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        result = await c.call_tool("catsdwan_status", {})
    assert "dataservice" in str(result.structured_content or result.content)


async def test_spec_index_is_cached_per_manager_version(api: respx.MockRouter, tmp_path: Path) -> None:
    route = mock_spec(api)
    await call("catsdwan_search_spec", {"query": "config group"}, mcp_cache_dir=str(tmp_path))
    files = list(tmp_path.glob("spec-dataservice-*.json"))  # noqa: ASYNC240
    assert len(files) == 1 and json.loads(files[0].read_text())["version"] == "20.18.3.1"
    await call("catsdwan_search_spec", {"query": "policy group"}, mcp_cache_dir=str(tmp_path))
    assert route.call_count == 1  # the second server read the cache


# --- api_call: read-only server ------------------------------------------------------------------


async def test_api_call_get_is_checked_and_sent(api: respx.MockRouter) -> None:
    mock_spec(api)
    route = api.get("/dataservice/device/bfd/sessions").respond(
        json={"data": [{"state": "up", "system-ip": "10.0.0.1"}]}
    )
    out = await call(
        "catsdwan_api_call", {"path": "/device/bfd/sessions", "params": {"deviceId": "10.0.0.1"}}
    )
    assert out["data"][0]["state"] == "up"
    req = route.calls[0].request
    assert req.url.params["deviceId"] == "10.0.0.1"
    assert req.headers["X-XSRF-TOKEN"] == "csrf-123"


async def test_api_call_unknown_path_did_you_mean(api: respx.MockRouter) -> None:
    mock_spec(api)
    with pytest.raises(
        ToolError, match=r"not in the Manager's API spec\. Did you mean: .*/dataservice/device/bfd/sessions"
    ):
        await call("catsdwan_api_call", {"path": "/dataservice/device/bfd/session"})


async def test_api_call_wrong_method(api: respx.MockRouter) -> None:
    mock_spec(api)
    with pytest.raises(ToolError, match="POST is not an operation on /dataservice/device/bfd/sessions"):
        await call("catsdwan_api_call", {"path": "/dataservice/device/bfd/sessions", "method": "POST"})


async def test_api_call_statistics_query_post_is_read_only(api: respx.MockRouter) -> None:
    mock_spec(api)
    route = api.post("/dataservice/statistics/approute").respond(json={"data": [{"loss_percentage": 0}]})
    body = {"query": {"condition": "AND", "rules": []}, "size": 10}
    out = await call("catsdwan_api_call", {"path": "/statistics/approute", "method": "POST", "body": body})
    assert out["data"] == [{"loss_percentage": 0}]
    assert json.loads(route.calls[0].request.content) == body


@pytest.mark.parametrize("path", ["/dataservice/alarms/clear", "/dataservice/device/action/reboot"])
async def test_api_call_read_only_refuses_writes(api: respx.MockRouter, path: str) -> None:
    mock_spec(api)
    sent = api.post(path).respond(json={})
    with pytest.raises(ToolError, match="this server is read-only"):
        await call("catsdwan_api_call", {"path": path, "method": "POST", "body": {}})
    assert not sent.called


async def test_api_call_masks_secrets(api: respx.MockRouter) -> None:
    mock_spec(api)
    api.get("/dataservice/admin/user").respond(
        json={"data": [{"userName": "ops", "password": "Sup3rS3cret!"}]}
    )
    out = await call("catsdwan_api_call", {"path": "/admin/user"})
    assert out["data"][0]["userName"] == "ops" and "Sup3rS3cret" not in json.dumps(out)


async def test_api_call_masks_secrets_in_configuration_text(api: respx.MockRouter) -> None:
    mock_spec(api)
    config = (
        "hostname br2\nusername admin privilege 15 secret 9 $9$synthetic\nsnmp-server community Publ1c RO\n"
    )
    api.get("/dataservice/template/config/running/REDACTED-22").respond(json={"config": config})
    out = await call("catsdwan_api_call", {"path": "/template/config/running/REDACTED-22"})
    assert (
        "hostname br2" in out["config"] and "synthetic" not in out["config"] and "Publ1c" not in out["config"]
    )


async def test_api_call_without_spec_allows_get_with_a_note(api: respx.MockRouter) -> None:
    api.get(SPEC_PATH).respond(404, json={"error": {"message": "Not found"}})
    api.get("/dataservice/device").respond(json=fixture("device"))
    out = await call("catsdwan_api_call", {"path": "/dataservice/device"})
    assert "could not be loaded" in out["notes"][0] and out["result"]["data"]


# --- api_call: writes and dangerous --------------------------------------------------------------


async def test_api_call_write_is_preview_first(api: respx.MockRouter) -> None:
    mock_spec(api)
    sent = api.put("/dataservice/v1/config-group/cg-1").respond(json={"id": "cg-1"})
    args = {
        "path": "/dataservice/v1/config-group/cg-1",
        "method": "PUT",
        "body": {"name": "mcp-test", "description": "x", "secret": "Sup3rS3cret!"},
    }
    async with Client(make_server(mcp_enable_writes=True)) as c:
        tools = {t.name: t for t in await c.list_tools()}
        assert tools["catsdwan_api_call"].annotations.read_only_hint is False
        preview = json.loads((await c.call_tool("catsdwan_api_call", args)).content[0].text)
        assert preview["status"] == "preview" and preview["action"] == "PUT /dataservice/v1/config-group/cg-1"
        assert "Sup3rS3cret" not in json.dumps(preview)
        assert not sent.called
        done = json.loads(
            (await c.call_tool("catsdwan_api_call", {**args, "confirm": preview["confirm"]})).content[0].text
        )
    assert done["status"] == "applied" and done["result"] == {"id": "cg-1"}
    assert json.loads(sent.calls[0].request.content)["secret"] == "Sup3rS3cret!"


async def test_api_call_device_action_needs_dangerous(api: respx.MockRouter) -> None:
    mock_spec(api)
    sent = api.post("/dataservice/device/action/reboot").respond(json={"id": "reboot-1"})
    args = {"path": "/device/action/reboot", "method": "POST", "body": {"action": "reboot", "devices": []}}
    with pytest.raises(ToolError, match="needs MCP_ENABLE_DANGEROUS"):
        await call("catsdwan_api_call", args, mcp_enable_writes=True)
    out = await call("catsdwan_api_call", args, mcp_enable_writes=True, mcp_enable_dangerous=True)
    assert out["status"] == "preview" and "reboot" in out["side_effects"][0]
    assert not sent.called


async def test_api_call_writes_on_still_runs_reads_at_once(api: respx.MockRouter) -> None:
    mock_spec(api)
    api.post("/dataservice/alarms").respond(json={"data": []})
    out = await call(
        "catsdwan_api_call",
        {"path": "/alarms", "method": "POST", "body": {"query": {}}},
        mcp_enable_writes=True,
    )
    assert out == {"data": []}


async def test_api_call_without_spec_refuses_writes(api: respx.MockRouter) -> None:
    api.get(SPEC_PATH).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(ToolError, match="could not be loaded"):
        await call(
            "catsdwan_api_call",
            {"path": "/v1/config-group", "method": "POST", "body": {}},
            mcp_enable_writes=True,
        )
