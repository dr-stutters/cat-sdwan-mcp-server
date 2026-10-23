"""W21: feature profiles and configuration-group authoring.

Shapes recorded on the lab Manager (20.18.3.1, group mcp-test: profiles mcp-test-system with global, aaa,
basic, omp and bfd parcels at schema defaults, mcp-test-transport with wan/vpn, mcp-test-cli
(its config parcel is a plain CLI string with {{variables}}); the basic parcel's PUT/POST schemas
(timezone enum cut short). The PUT and POST answers, the associate bodies and the policy-group preview and
deploy follow Cisco's documentation (not recorded: the lab has no policy group).
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import features as ft
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.spec import match_operation
from cat_sdwan_mcp.tools import changes as change_tools

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

GID = "00000000-0000-4000-8000-000000000124"
GID2 = "00000000-0000-4000-8000-00000000a124"
SYS = "00000000-0000-4000-8000-000000001031"
BASIC = "00000000-0000-4000-8000-000000001034"
CLI = "00000000-0000-4000-8000-000000001038"
CONFIG = "00000000-0000-4000-8000-000000001039"
TRANSPORT = "00000000-0000-4000-8000-000000001029"
FP = "/dataservice/v1/feature-profile/sdwan"
CG = "/dataservice/v1/config-group"
BR1, HUB1, BR2 = "REDACTED-16", "REDACTED-17", "REDACTED-22"
PGID = "00000000-0000-4000-8000-00000000b001"
PG = f"/dataservice/v1/policy-group/{PGID}"
STATUS = "/dataservice/device/action/status"


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


def group(gid: str = GID, name: str = "mcp-test", profiles: list[str] | None = None) -> dict[str, Any]:
    rec = copy.deepcopy(fixture("v1_config_group_detail"))
    every = {
        TRANSPORT: {"id": TRANSPORT, "name": "mcp-test-transport", "type": "transport"},
        SYS: {"id": SYS, "name": "mcp-test-system", "type": "system"},
        CLI: {"id": CLI, "name": "mcp-test-cli", "type": "cli"},
    }
    rec.update(id=gid, name=name, profiles=[every[p] for p in (profiles or list(every))])
    return rec


def basic_parcel(**data: Any) -> dict[str, Any]:
    body = copy.deepcopy(fixture("v1_feature_profile_system_basic_parcel"))
    body["payload"]["data"].update(data)
    return body


def mock_profiles(
    api: respx.MockRouter, *groups: dict[str, Any], basic: dict[str, Any] | None = None
) -> None:
    api.get(CG).respond(json=list(groups) or [group()])
    for g in groups or [group()]:
        api.get(f"{CG}/{g['id']}/device/associate").respond(json=fixture("v1_config_group_associate"))
    api.get(f"{FP}/system/{SYS}").respond(json=fixture("v1_feature_profile_system_detail"))
    api.get(f"{FP}/cli/{CLI}").respond(json=fixture("v1_feature_profile_cli_detail"))
    api.get(f"{FP}/transport/{TRANSPORT}").respond(json=fixture("v1_feature_profile_transport_detail"))
    api.get(f"{FP}/system/{SYS}/basic/{BASIC}").respond(json=basic or basic_parcel())
    api.get(f"{FP}/cli/{CLI}/config/{CONFIG}").respond(json=fixture("v1_feature_profile_cli_config_parcel"))
    api.get(f"{FP}/system/basic/schema").respond(json=fixture("v1_feature_profile_system_basic_schema_put"))
    api.get(f"{FP}/cli/config/schema").respond(json=fixture("v1_feature_profile_cli_config_schema_put"))


async def run(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        result = await c.call_tool(name, args)
    return result.structured_content


async def write(name: str, args: dict[str, Any], **settings: Any) -> Any:
    return await run(name, args, mcp_enable_writes=True, **settings)


async def confirmed(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


# --- helpers -------------------------------------------------------------------------------------


def schema() -> dict[str, Any]:
    return ft.data_schema(ft.request_schema(fixture("v1_feature_profile_system_basic_schema_put")))


def test_parcel_view_global_variable_and_default() -> None:
    body = basic_parcel(
        consoleBaudRate={"optionType": "global", "value": "115200"},
        location={"optionType": "variable", "value": "{{site_location}}"},
    )
    view = ft.parcel_view(body)
    assert view["configured"] == {"consoleBaudRate": "115200", "location": "{{site_location}}"}
    assert view["variables"] == ["site_location"]
    assert view["defaults"]["overlayId"] == 1 and view["defaults"]["description"] == "(no value)"
    assert "consoleBaudRate" not in view["defaults"]


def test_parcel_view_cli_text_and_its_variables() -> None:
    view = ft.parcel_view(fixture("v1_feature_profile_cli_config_parcel"))
    assert "banner motd #{{banner_motd}}#" in view["cli"] and view["cli_lines"] > 100
    assert {"banner_motd", "mpls_ip", "lan_ip"} <= set(view["variables"])


def test_schema_checks() -> None:
    s = schema()
    baud = ft.field_schema(s, "consoleBaudRate")
    assert baud is not None
    assert ft.check_leaf(baud, {"optionType": "global", "value": "115200"}) is None
    assert "not one of" in str(ft.check_leaf(baud, {"optionType": "global", "value": "1"}))
    assert "must be string" in str(ft.check_leaf(baud, {"optionType": "global", "value": 9600}))
    assert ft.check_leaf(baud, {"optionType": "variable", "value": "{{baud}}"}) is None
    assert "variable name" in str(ft.check_leaf(baud, {"optionType": "variable", "value": "baud"}))
    assert ft.default_leaf(baud) == {"optionType": "default", "value": "9600"}
    overlay = ft.field_schema(s, "overlayId")
    assert overlay is not None and "below the minimum" in str(
        ft.check_leaf(overlay, {"optionType": "global", "value": 0})
    )
    tz = ft.field_schema(s, "clock.timezone")
    assert tz is not None and ft.default_leaf(tz) == {"optionType": "default", "value": "UTC"}
    geo = ft.field_schema(s, "gpsLocation.geoFencing.enable")
    assert geo is not None and "can't be variable" in str(
        ft.check_leaf(geo, {"optionType": "variable", "value": "{{x}}"})
    )
    assert ft.field_schema(s, "nope") is None
    assert ft.is_required(s, "consoleBaudRate") and not ft.is_required(s, "controlSessionPps")


def test_to_leaf_and_set_at() -> None:
    s = schema()
    baud = ft.field_schema(s, "consoleBaudRate")
    assert ft.to_leaf(baud, ft.MISSING, "115200") == {"optionType": "global", "value": "115200"}
    assert ft.to_leaf(baud, ft.MISSING, "{{baud}}") == {"optionType": "variable", "value": "{{baud}}"}
    assert ft.to_leaf(baud, ft.MISSING, None) == {"optionType": "default", "value": "9600"}
    plain = {"type": "string"}
    assert ft.to_leaf(plain, "old cli", "new cli") == "new cli"
    data: dict[str, Any] = {}
    ft.set_at(data, "clock.timezone", {"optionType": "global", "value": "UTC"})
    assert ft.get_at(data, "clock.timezone") == {"optionType": "global", "value": "UTC"}
    lst = {"server": {"optionType": "global", "value": [{"name": {"optionType": "global", "value": "a"}}]}}
    ft.set_at(lst, "server[0].name", {"optionType": "global", "value": "b"})
    assert ft.get_at(lst, "server[0].name")["value"] == "b"
    with pytest.raises(Exception, match="no item 3"):
        ft.set_at(lst, "server[3].name", {})


def test_missing_required_and_defaults_for() -> None:
    s = schema()
    assert set(ft.missing_required(s, {})) >= {"consoleBaudRate", "clock", "overlayId"}
    data, unresolved = ft.defaults_for(s)
    assert data["consoleBaudRate"] == {"optionType": "default", "value": "9600"}
    assert data["clock"]["timezone"]["value"] == "UTC"
    assert ft.missing_required(s, data) == [] and unresolved == []
    del s["properties"]["consoleBaudRate"]["oneOf"][2]  # no default branch: can't be filled in
    assert ft.defaults_for(s)[1] == ["consoleBaudRate"]


def test_cli_replace_needs_one_match() -> None:
    text = "hostname a\nbanner motd #x#\n"
    out, problems = ft.cli_replace(text, {"banner motd #x#": "banner motd #y#"})
    assert out == "hostname a\nbanner motd #y#\n" and problems == []
    _, problems = ft.cli_replace(text, {"nothere": "y"})
    assert "occurs 0 times" in problems[0]


def test_parcel_url_keeps_the_parcel_type_slash() -> None:
    url = ft.parcel_url(ft.PARCEL_PATH, ptype="transport", parcel_type="wan/vpn", profile="p 1", parcel="x")
    assert url == f"{FP}/transport/p%201/wan/vpn/x"
    with pytest.raises(Exception, match="not a parcel type"):
        ft.parcel_url(ft.PARCEL_PATH, ptype="system", parcel_type="../x", profile="p", parcel="x")


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("GET", "/dataservice/v1/feature-profile/sdwan/system/{type}/basic/{parcel}"),
        ("PUT", "/dataservice/v1/feature-profile/sdwan/system/{type}/basic/{parcel}"),
        ("POST", "/dataservice/v1/feature-profile/sdwan/system/{type}/ntp"),
        ("GET", "/dataservice/v1/feature-profile/sdwan/system/basic/schema"),
        ("PUT", "/dataservice/v1/feature-profile/sdwan/cli/{type}/config/{parcel}"),
        ("GET", "/dataservice/v1/feature-profile/sdwan/cli/config/schema"),
        ("POST", "/dataservice/v1/config-group/{type}/device/associate"),
        ("DELETE", "/dataservice/v1/config-group/{type}/device/associate"),
        ("GET", ft.POLICY_ASSOCIATE_PATH),
        ("POST", ft.POLICY_PREVIEW_PATH),
        ("POST", ft.POLICY_DEPLOY_PATH),
    ],
)
def test_feature_paths_are_in_the_spec(method: str, template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    concrete = (
        template.replace("{type}", "x").replace("{parcel}", "y").replace("{id}", "x").replace("{device}", "y")
    )
    _, methods = match_operation(idx, method, concrete)
    assert method in methods


# --- get_feature_parcel --------------------------------------------------------------------------


async def test_get_lists_a_groups_parcels(api: respx.MockRouter) -> None:
    mock_profiles(api)
    out = await run("catsdwan_get_feature_parcel", {"profile": "mcp-test"})
    assert out["where"] == "configuration group mcp-test"
    assert {(p["profile"], p["type"]) for p in out["parcels"]} >= {
        ("mcp-test-system", "basic"),
        ("mcp-test-transport", "wan/vpn"),
        ("mcp-test-cli", "config"),
    }


async def test_get_parcel_values_reach_and_fields(api: respx.MockRouter) -> None:
    body = basic_parcel(consoleBaudRate={"optionType": "global", "value": "115200"})
    mock_profiles(api, basic=body)
    out = await run(
        "catsdwan_get_feature_parcel", {"profile": "mcp-test-system", "parcel": "basic", "fields": True}
    )
    assert out["name"] == "mcp-test-basic" and out["configured"] == {"consoleBaudRate": "115200"}
    assert out["used_by"] == [{"group": "mcp-test", "devices": ["br1", "hub1"]}]
    assert (
        out["fields"]["consoleBaudRate"]["default"] == "9600" and out["fields"]["consoleBaudRate"]["required"]
    )
    by_name = await run("catsdwan_get_feature_parcel", {"profile": "mcp-test", "parcel": "mcp-test-basic"})
    assert by_name["id"] == BASIC


async def test_get_unknown_profile_names_the_known_ones(api: respx.MockRouter) -> None:
    mock_profiles(api)
    for t in ft.LISTABLE_TYPES:
        api.get(f"{FP}/{t}").respond(
            json=fixture("v1_feature_profile_sdwan_system_list") if t == "system" else []
        )
    async with Client(make_server()) as c:
        result = await c.call_tool("catsdwan_get_feature_parcel", {"profile": "nope"}, raise_on_error=False)
    assert result.is_error and "mcp-test-system" in str(result.content)


# --- set_feature_parcel --------------------------------------------------------------------------


async def test_set_preview_old_new_reach_and_put_on_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    put = api.put(f"{FP}/system/{SYS}/basic/{BASIC}").respond(json={"parcelId": BASIC})
    args = {"profile": "mcp-test-system", "parcel": "basic", "values": {"consoleBaudRate": "115200"}}
    out = await write("catsdwan_set_feature_parcel", args)
    assert out["status"] == "preview" and out["blast_radius"] == 2
    p = out["preview"]
    assert p["changes"] == {"consoleBaudRate": {"from": "default: '9600'", "to": "global: '115200'"}}
    assert p["schema_check"] == "passed" and p["reaches"][0]["devices"] == ["br1", "hub1"]
    assert not put.called
    done = await confirmed("catsdwan_set_feature_parcel", args)
    sent = json.loads(put.calls.last.request.content)
    assert sent["name"] == "mcp-test-basic" and sent["data"]["consoleBaudRate"] == {
        "optionType": "global",
        "value": "115200",
    }
    assert sent["data"]["overlayId"] == {"optionType": "default", "value": 1}  # the rest unchanged
    assert "catsdwan_deploy_config_group" in done["result"]["next"]


async def test_set_schema_refusals_all_at_once(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    put = api.put(f"{FP}/system/{SYS}/basic/{BASIC}")
    args = {
        "profile": "mcp-test-system",
        "parcel": "basic",
        "values": {"consoleBaudRate": 9600, "overlayId": 0, "clock.timezone": "Mars/Olympus", "nope": 1},
    }
    out = await write("catsdwan_set_feature_parcel", args)
    assert out["status"] == "blocked" and len(out["blockers"]) == 4 and not put.called
    text = " ".join(out["blockers"])
    assert (
        "must be string" in text
        and "below the minimum" in text
        and "not one of" in text
        and "no field 'nope'" in text
    )


async def test_set_nothing_to_change_and_reset_to_default(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api, basic=basic_parcel(consoleBaudRate={"optionType": "global", "value": "115200"}))
    same = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test-system", "parcel": "basic", "values": {"overlayId": None}},
    )
    assert any("nothing to change" in b for b in same["blockers"])
    reset = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test-system", "parcel": "basic", "values": {"consoleBaudRate": None}},
    )
    assert reset["preview"]["changes"]["consoleBaudRate"]["to"] == "default: '9600'"


async def test_set_cli_replace(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    put = api.put(f"{FP}/cli/{CLI}/config/{CONFIG}").respond(json={"parcelId": CONFIG})
    args = {
        "profile": "mcp-test",
        "parcel": "config",
        "cli_replace": {"banner motd #{{banner_motd}}#": "banner motd #{{banner_motd}} (W21)#"},
    }
    out = await write("catsdwan_set_feature_parcel", args)
    p = out["preview"]
    assert p["cli_changes"] == ["-banner motd #{{banner_motd}}#", "+banner motd #{{banner_motd}} (W21)#"]
    assert p["undo"] == {
        "cli_replace": {"banner motd #{{banner_motd}} (W21)#": "banner motd #{{banner_motd}}#"}
    }
    await confirmed("catsdwan_set_feature_parcel", args)
    sent = json.loads(put.calls.last.request.content)
    assert (
        "banner motd #{{banner_motd}} (W21)#" in sent["data"]["config"] and sent["name"] == "mcp-test-config"
    )
    bad = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test", "parcel": "config", "cli_replace": {"no such": "x"}},
    )
    assert bad["status"] == "blocked"


async def test_set_blast_radius_over_two_groups_sharing_a_profile(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api, group(), group(GID2, "mcp-other", [SYS]))
    other = {
        "devices": [d for d in fixture("v1_config_group_associate")["devices"] if d["host-name"] == "hub1"]
    }
    api.get(f"{CG}/{GID2}/device/associate").respond(json=other)
    out = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test-system", "parcel": "basic", "values": {"portHop": False}},
    )
    reach = {g["group"]: g["devices"] for g in out["preview"]["reaches"]}
    assert reach == {"mcp-test": ["br1", "hub1"], "mcp-other": ["hub1"]}
    assert out["blast_radius"] == 2  # distinct devices


async def test_set_refused_with_a_small_blast_radius_cap(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    out = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test-system", "parcel": "basic", "values": {"portHop": False}},
        mcp_max_blast_radius=1,
    )
    assert out["status"] == "blocked"


async def test_create_parcel_fills_schema_defaults(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    api.get(f"{FP}/system/basic/schema", params={"schemaType": "post"}).respond(
        json=fixture("v1_feature_profile_system_basic_schema_post")
    )
    post = api.post(f"{FP}/system/{SYS}/basic").respond(json={"parcelId": "new-1"})
    args = {
        "profile": "mcp-test-system",
        "parcel": "basic",
        "new_parcel_name": "mcp-test-basic-2",
        "values": {"consoleBaudRate": "19200"},
    }
    out = await write("catsdwan_set_feature_parcel", args)
    assert out["status"] == "preview", out.get("blockers")
    done = await confirmed("catsdwan_set_feature_parcel", args)
    sent = json.loads(post.calls.last.request.content)
    assert sent["name"] == "mcp-test-basic-2" and sent["data"]["consoleBaudRate"]["value"] == "19200"
    assert done["result"]["parcel_id"] == "new-1"


async def test_create_refuses_a_duplicate_name(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_profiles(api)
    out = await write(
        "catsdwan_set_feature_parcel",
        {"profile": "mcp-test-system", "parcel": "basic", "new_parcel_name": "mcp-test-basic"},
    )
    assert any("already has a parcel" in b for b in out["blockers"])


# --- associate_config_group ----------------------------------------------------------------------


BR2_ON_TEMPLATE = {"configOperationMode": "vmanage", "template": "mcp-test-br2"}


async def test_associate_add_remove_and_blockers(api: respx.MockRouter) -> None:
    mock_inventory(api, br2=BR2_ON_TEMPLATE)
    mock_profiles(api)
    blocked = await write("catsdwan_associate_config_group", {"group": "mcp-test", "add": ["br2", "br1"]})
    text = " ".join(blocked["blockers"])
    assert "br2 is attached to device template" in text and "br1 is already in" in text
    post = api.post(f"{CG}/{GID}/device/associate").respond(200)
    delete = api.delete(f"{CG}/{GID}/device/associate").respond(200)
    out = await write("catsdwan_associate_config_group", {"group": "mcp-test", "remove": ["hub1"]})
    assert out["preview"]["devices_after"] == ["br1"] and out["blast_radius"] == 1
    done = await confirmed("catsdwan_associate_config_group", {"group": "mcp-test", "remove": ["hub1"]})
    assert json.loads(delete.calls.last.request.content) == {"devices": [{"id": HUB1}]}
    assert done["result"]["removed"] == ["hub1"] and not post.called


# --- deploy_policy_group -------------------------------------------------------------------------


def mock_policy(api: respx.MockRouter) -> respx.Route:
    rec = {**group(PGID, "mcp-policy"), "profiles": []}
    api.get("/dataservice/v1/policy-group").respond(json=[rec])
    api.get(f"{PG}/device/associate").respond(json=fixture("v1_config_group_associate"))
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})
    api.get(f"/dataservice/template/config/running/{BR1}").respond(json={"config": "hostname br1\n"})
    return api.post(f"{PG}/device/{BR1}/preview").respond(
        json={"config": "hostname br1\npolicy\n app-visibility\n!\n"}
    )


async def test_policy_preview_and_deploy(api: respx.MockRouter) -> None:
    mock_inventory(api)
    preview = mock_policy(api)
    deploy = api.post(f"{PG}/device/deploy").respond(json={"parentTaskId": "pt-1"})
    api.get(f"{STATUS}/pt-1").respond(
        json={"data": [{"host-name": "br1", "uuid": BR1, "statusId": "success", "status": "Success"}]}
    )
    args = {"group": "mcp-policy", "devices": ["br1"]}
    out = await write("catsdwan_deploy_policy_group", args)
    assert out["status"] == "preview" and preview.called and out["preview"]["tier"] == "write"
    dev = out["preview"]["devices"][0]
    assert dev["diff_vs_running"]["only_intended"] == ["policy"]
    done = await confirmed("catsdwan_deploy_policy_group", args)
    assert json.loads(deploy.calls.last.request.content) == {"devices": [{"id": BR1}]}
    assert done["result"]["outcome"] == "success"


async def test_policy_hub_is_dangerous_and_template_device_refused(api: respx.MockRouter) -> None:
    mock_inventory(api, br2=BR2_ON_TEMPLATE)
    mock_policy(api)
    api.post(f"{PG}/device/{HUB1}/preview").respond(json={"config": "hostname hub1\n"})
    api.get(f"/dataservice/template/config/running/{HUB1}").respond(json={"config": "hostname hub1\n"})
    out = await write(
        "catsdwan_deploy_policy_group", {"group": "mcp-policy", "devices": ["hub1"]}, hub_devices="hub1"
    )
    assert any("MCP_ENABLE_DANGEROUS" in b for b in out["blockers"])
    api.post(f"{PG}/device/{BR2}/preview").respond(json={"config": "hostname br2\n"})
    api.get(f"/dataservice/template/config/running/{BR2}").respond(json={"config": "hostname br2\n"})
    br2 = await write("catsdwan_deploy_policy_group", {"group": "mcp-policy", "devices": ["br2"]})
    assert any("device template" in b for b in br2["blockers"])
