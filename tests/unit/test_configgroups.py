"""W62 #134: configuration-group lifecycle (create from new or existing profiles, clone, delete).

The group records are the recorded W8 groups (v1_config_group_w8: mcp-w8-hub and mcp-test, their profile
ids) and the associate read (v1_config_group_associate: br1, hub1). The profile lists follow the recorded
v1_feature_profile_sdwan_system_list shape with those ids. The POST answers ({id}) follow the 20.18 spec's
CreateConfigGroup / CreateSdwanSystemFeatureProfile response and Cisco's documentation (not recorded on the
lab yet): every new id is a documentation UUID.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import configgroups as cg
from cat_sdwan_mcp import features as ft
from cat_sdwan_mcp.changes import RUNNING_TASKS_PATH

from .conftest import fixture, make_server

CGS = "/dataservice/v1/config-group"
FP = "/dataservice/v1/feature-profile/sdwan"
HUB_G = "00000000-0000-4000-8000-00000000f111"
TEST_G = "00000000-0000-4000-8000-000000000124"
SERVICE, HUB_CLI, TRANSPORT, SYSTEM, TEST_CLI = (
    "00000000-0000-4000-8000-00000000f110",
    "00000000-0000-4000-8000-00000000f112",
    "00000000-0000-4000-8000-00000000f113",
    "00000000-0000-4000-8000-00000000f114",
    "00000000-0000-4000-8000-000000001038",
)
NEW_G = "00000000-0000-4000-8000-00000000c001"
NEW_SYS = "00000000-0000-4000-8000-00000000c002"
NEW_TR = "00000000-0000-4000-8000-00000000c003"
NEW_VPN = "00000000-0000-4000-8000-00000000c004"
WAN_VPN = "00000000-0000-4000-8000-000000001030"
WAN_IF = "00000000-0000-4000-8000-00000000c010"
BR1, HUB1 = "REDACTED-16", "REDACTED-17"

PROFILES = {
    "system": [(SYSTEM, "mcp-test-system")],
    "transport": [(TRANSPORT, "mcp-test-transport")],
    "service": [(SERVICE, "mcp-w8-service")],
    "cli": [(HUB_CLI, "mcp-w8-hub-cli"), (TEST_CLI, "mcp-test-cli")],
}


def profile_list(t: str) -> list[dict[str, Any]]:
    base = fixture("v1_feature_profile_sdwan_system_list")[0]
    return [{**base, "profileId": i, "profileName": n, "profileType": t} for i, n in PROFILES.get(t, [])]


def groups(**edits: dict[str, Any]) -> list[dict[str, Any]]:
    rows = fixture("v1_config_group_w8")
    return [{**g, **edits.get(g["name"], {})} for g in rows]


def assoc(*chassis: str) -> dict[str, Any]:
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    return {"devices": [rows[c] for c in chassis]}


def mock(
    api: respx.MockRouter,
    rows: list[dict[str, Any]] | None = None,
    members: dict[str, list[str]] | None = None,
):
    rows = groups() if rows is None else rows
    api.get(CGS).respond(json=rows)
    for g in rows:
        api.get(f"{CGS}/{g['id']}").respond(json=g)
        api.get(f"{CGS}/{g['id']}/device/associate").respond(json=assoc(*(members or {}).get(g["id"], [])))
    for t in ft.LISTABLE_TYPES:
        api.get(f"{FP}/{t}").respond(json=profile_list(t))
    api.get(RUNNING_TASKS_PATH).respond(json={"runningTasks": []})


async def write(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        return (await c.call_tool(name, args)).structured_content


async def confirmed(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        assert not first.get("blockers"), first["blockers"]
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


def body(route: respx.Route, i: int = -1) -> Any:
    return json.loads(route.calls[i].request.content)


# --- helpers -------------------------------------------------------------------------------------


def test_helpers() -> None:
    assert cg.parse_profile_ref("new: mcp-w11-system") == ("new", "mcp-w11-system")
    assert cg.parse_profile_ref("mcp-test-system") == ("existing", "mcp-test-system")
    assert cg.group_body("g", "", [SYSTEM]) == {
        "name": "g",
        "description": "",
        "solution": "sdwan",
        "profiles": [{"id": SYSTEM}],
    }
    assert cg.copy_payload({"parcelId": "x", "payload": {"name": "n", "description": "d", "data": {}}}) == {
        "name": "n",
        "description": "d",
        "data": {},
    }
    tree = cg.parcel_tree(fixture("v1_feature_profile_transport_detail"))
    assert tree == [{"id": WAN_VPN, "type": "wan/vpn", "name": "mcp-test-wan-vpn", "subparcels": []}]
    assert cg.deploy_pending({"state": "Deploy  in progress"}) == "Deploy in progress"
    assert cg.deploy_pending({"state": None}) is None


# --- create --------------------------------------------------------------------------------------


async def test_create_from_new_and_existing_profiles(api: respx.MockRouter) -> None:
    mock(api)
    sys_post = api.post(f"{FP}/system").respond(json={"id": NEW_SYS})
    group_post = api.post(CGS).respond(json={"id": NEW_G})
    args = {
        "name": "mcp-w11-cg",
        "profiles": {"system": "new:mcp-w11-system", "transport": "mcp-test-transport"},
        "description": "W62",
    }
    out = await write("catsdwan_create_config_group", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    prof = out["preview"]["profiles"]
    assert [(p["type"], p["action"], p["name"]) for p in prof] == [
        ("system", "new", "mcp-w11-system"),
        ("transport", "existing", "mcp-test-transport"),
    ]
    assert out["preview"]["body"]["profiles"] == [
        {"id": "<new system profile mcp-w11-system>"},
        {"id": TRANSPORT},
    ]
    assert any("shared with mcp-w8-hub, mcp-test" in w for w in out["preview"]["warnings"])
    assert out["blast_radius"] == 0
    assert (
        out["undo"]
        == "back-out: catsdwan_delete_config_group(group=<from the result: id>, delete_profiles=false)"
    )
    assert not sys_post.called and not group_post.called
    done = await confirmed("catsdwan_create_config_group", args)
    assert body(sys_post) == {"name": "mcp-w11-system", "description": "W62"}
    assert body(group_post) == {
        "name": "mcp-w11-cg",
        "description": "W62",
        "solution": "sdwan",
        "profiles": [{"id": NEW_SYS}, {"id": TRANSPORT}],
    }
    assert done["result"]["id"] == NEW_G
    assert done["result"]["profiles"]["system"] == {"id": NEW_SYS, "name": "mcp-w11-system", "action": "new"}
    assert done["undo"]["tool"] == "catsdwan_delete_config_group"
    assert done["undo"]["args"] == {"group": NEW_G, "delete_profiles": False}


async def test_create_all_new_profiles_undo_deletes_them(api: respx.MockRouter) -> None:
    mock(api)
    api.post(f"{FP}/system").respond(json={"id": NEW_SYS})
    api.post(f"{FP}/transport").respond(json={"id": NEW_TR})
    api.post(CGS).respond(json={"id": NEW_G})
    args = {
        "name": "mcp-w11-cg",
        "profiles": {"system": "new:mcp-w11-system", "transport": "new:mcp-w11-wan"},
    }
    done = await confirmed("catsdwan_create_config_group", args)
    assert done["undo"]["args"] == {"group": NEW_G, "delete_profiles": True}


async def test_create_blockers(api: respx.MockRouter) -> None:
    mock(api)
    out = await write(
        "catsdwan_create_config_group",
        {
            "name": "mcp-test",
            "profiles": {
                "system": "nope",
                "transport": "mcp-test-system",
                "service": "new:mcp-w8-service",
                "other": "x",
                "cli": "new:bad name",
            },
        },
    )
    assert out["status"] == "blocked"
    text = " | ".join(out["blockers"])
    assert "a configuration group named mcp-test exists already" in text
    assert "no system feature profile is named 'nope'" in text
    assert "(it is a system profile)" in text
    assert "a feature profile named mcp-w8-service exists already" in text
    assert "'other' is not a configuration-group profile type" in text
    assert "space" in text
    none = await write("catsdwan_create_config_group", {"name": "mcp-w11-cg"})
    assert any("no feature profile" in b for b in none["blockers"])
    deep = await write("catsdwan_create_config_group", {"name": "mcp-w11-cg", "deep": True})
    assert any("deep=true needs clone_from" in b for b in deep["blockers"])


async def test_create_warns_without_system_or_transport(api: respx.MockRouter) -> None:
    mock(api)
    out = await write(
        "catsdwan_create_config_group", {"name": "mcp-w11-cg", "profiles": {"cli": "mcp-test-cli"}}
    )
    assert not out.get("blockers")
    warnings = " ".join(out["preview"]["warnings"])
    assert "no system profile" in warnings and "no transport profile" in warnings


async def test_clone_shares_the_source_profiles(api: respx.MockRouter) -> None:
    mock(api)
    group_post = api.post(CGS).respond(json={"id": NEW_G})
    profile_posts = api.post(url__startswith=FP).respond(json={"id": "unused"})
    args = {"name": "mcp-w11-cg", "clone_from": "mcp-test", "profiles": {"cli": "mcp-w8-hub-cli"}}
    out = await write("catsdwan_create_config_group", args)
    assert out["preview"]["clone_from"] == "mcp-test" and out["preview"]["deep"] is False
    assert [(p["type"], p["id"]) for p in out["preview"]["profiles"]] == [
        ("system", SYSTEM),
        ("transport", TRANSPORT),
        ("service", SERVICE),
        ("cli", HUB_CLI),
    ]
    await confirmed("catsdwan_create_config_group", args)
    assert [p["id"] for p in body(group_post)["profiles"]] == [SYSTEM, TRANSPORT, SERVICE, HUB_CLI]
    assert not profile_posts.called


async def test_deep_clone_copies_parcels_and_subparcels(api: respx.MockRouter) -> None:
    src = groups()[1]
    src["profiles"] = [p for p in src["profiles"] if p["type"] == "transport"]
    mock(api, [src])
    detail = fixture("v1_feature_profile_transport_detail")
    detail["associatedProfileParcels"][0]["subparcels"] = [
        {"parcelId": WAN_IF, "parcelType": "interface/ethernet", "payload": {"name": "mcp-test-wan-if"}}
    ]
    api.get(f"{FP}/transport/{TRANSPORT}").respond(json=detail)
    vpn_data = {"vpnId": {"optionType": "default", "value": 0}}
    if_data = {"interfaceName": {"optionType": "variable", "value": "{{wan_if}}"}}
    api.get(f"{FP}/transport/{TRANSPORT}/wan/vpn/{WAN_VPN}").respond(
        json={
            "parcelId": WAN_VPN,
            "payload": {"name": "mcp-test-wan-vpn", "description": "", "data": vpn_data},
        }
    )
    api.get(f"{FP}/transport/{TRANSPORT}/wan/vpn/{WAN_VPN}/interface/ethernet/{WAN_IF}").respond(
        json={"parcelId": WAN_IF, "payload": {"name": "mcp-test-wan-if", "description": "", "data": if_data}}
    )
    prof_post = api.post(f"{FP}/transport").respond(json={"id": NEW_TR})
    vpn_post = api.post(f"{FP}/transport/{NEW_TR}/wan/vpn").respond(json={"parcelId": NEW_VPN})
    if_post = api.post(f"{FP}/transport/{NEW_TR}/wan/vpn/{NEW_VPN}/interface/ethernet").respond(
        json={"parcelId": "00000000-0000-4000-8000-00000000c011"}
    )
    group_post = api.post(CGS).respond(json={"id": NEW_G})
    args = {"name": "mcp-w11-cg", "clone_from": "mcp-test", "deep": True}
    out = await write("catsdwan_create_config_group", args)
    row = out["preview"]["profiles"][0]
    assert row["action"] == "copy" and row["name"] == "mcp-w11-cg-transport"
    assert row["parcels"] == ["mcp-test-wan-vpn (wan/vpn) + 1 subparcel(s)"]
    assert any("2 parcel(s)" in r for r in out["preview"]["requests"])
    done = await confirmed("catsdwan_create_config_group", args)
    assert body(prof_post) == {"name": "mcp-w11-cg-transport", "description": ""}
    assert body(vpn_post) == {"name": "mcp-test-wan-vpn", "description": "", "data": vpn_data}
    assert body(if_post) == {"name": "mcp-test-wan-if", "description": "", "data": if_data}
    assert [p["id"] for p in body(group_post)["profiles"]] == [NEW_TR]
    assert done["result"]["parcels_copied"] == 2
    assert done["undo"]["args"] == {"group": NEW_G, "delete_profiles": True}


async def test_failed_group_post_takes_back_new_profiles(api: respx.MockRouter) -> None:
    mock(api)
    api.post(f"{FP}/system").respond(json={"id": NEW_SYS})
    api.post(CGS).mock(return_value=httpx.Response(400, json={"error": {"message": "Invalid name"}}))
    back = api.delete(f"{FP}/system/{NEW_SYS}").respond(200)
    args = {"name": "mcp-w11-cg", "profiles": {"system": "new:mcp-w11-system"}}
    async with Client(make_server(mcp_enable_writes=True)) as c:
        first = (await c.call_tool("catsdwan_create_config_group", args)).structured_content
        res = await c.call_tool(
            "catsdwan_create_config_group", {**args, "confirm": first["confirm"]}, raise_on_error=False
        )
    assert res.is_error and back.called
    text = " ".join(getattr(x, "text", "") for x in res.content)
    assert "took back the new profile(s) mcp-w11-system" in text


# --- delete --------------------------------------------------------------------------------------


async def test_delete_refused_while_devices_are_associated(api: respx.MockRouter) -> None:
    mock(api, members={TEST_G: [BR1]})
    out = await write("catsdwan_delete_config_group", {"group": "mcp-test"})
    assert out["status"] == "blocked"
    assert any("1 device(s) are associated (br1)" in b for b in out["blockers"])
    dangerous = await write("catsdwan_delete_config_group", {"group": "mcp-test", "dissociate": True})
    assert any("MCP_ENABLE_DANGEROUS" in b for b in dangerous["blockers"])
    assert dangerous["preview"]["tier"] == "dangerous"


async def test_delete_dissociates_with_dangerous_on(api: respx.MockRouter) -> None:
    mock(api, members={TEST_G: [BR1]})
    drop = api.delete(f"{CGS}/{TEST_G}/device/associate").respond(200)
    delete = api.delete(f"{CGS}/{TEST_G}").respond(200)
    done = await confirmed(
        "catsdwan_delete_config_group", {"group": "mcp-test", "dissociate": True}, mcp_enable_dangerous=True
    )
    assert body(drop) == {"devices": [{"id": BR1}]}
    assert "deleteProfiles" not in str(delete.calls.last.request.url)
    assert done["result"] == {"dissociated": ["br1"], "deleted": "mcp-test"}
    assert "not reversible" in done["undo"]["back_out"]


async def test_delete_blocked_while_a_deploy_runs(api: respx.MockRouter) -> None:
    mock(api, groups(**{"mcp-test": {"state": "Deploy in progress"}}), members={TEST_G: [BR1]})
    api.get(RUNNING_TASKS_PATH).respond(json={"runningTasks": [{"processId": "push-1"}]})
    api.get("/dataservice/device/action/status/push-1").respond(
        json={
            "summary": {"action": "push_feature_template_configuration"},
            "data": [{"uuid": BR1, "status": "In progress"}],
        }
    )
    out = await write(
        "catsdwan_delete_config_group", {"group": "mcp-test", "dissociate": True}, mcp_enable_dangerous=True
    )
    text = " | ".join(out["blockers"])
    assert "deploy is still running (Deploy in progress)" in text
    assert "br1 has an action still running" in text


async def test_delete_profiles_spares_shared_profiles(api: respx.MockRouter) -> None:
    mock(api)
    out = await write("catsdwan_delete_config_group", {"group": "mcp-test", "delete_profiles": True})
    text = " | ".join(out["blockers"])
    assert "profile mcp-test-system is used by configuration group mcp-w8-hub" in text
    assert "mcp-test-cli" not in text


async def test_delete_empty_group_with_its_profiles(api: respx.MockRouter) -> None:
    only = groups()[1]
    mock(api, [only])
    delete = api.delete(f"{CGS}/{TEST_G}").respond(200)
    out = await write("catsdwan_delete_config_group", {"group": "mcp-test", "delete_profiles": True})
    assert out["preview"]["tier"] == "write" and out["blast_radius"] == 0
    done = await confirmed("catsdwan_delete_config_group", {"group": "mcp-test", "delete_profiles": True})
    assert delete.calls.last.request.url.params["deleteProfiles"] == "true"
    assert len(done["result"]["profiles_deleted"]) == 4


@pytest.mark.parametrize("tool", ["catsdwan_create_config_group", "catsdwan_delete_config_group"])
async def test_hidden_without_writes(tool: str) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert tool not in names


def test_readme_rows() -> None:
    from pathlib import Path

    readme = (Path(__file__).parents[2] / "README.md").read_text()
    for tool in ("catsdwan_create_config_group", "catsdwan_delete_config_group"):
        assert f"| `{tool}` |" in readme
