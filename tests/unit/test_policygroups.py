"""#94: policy-group lifecycle (create, associate / dissociate, delete).

Recorded on the lab Manager (20.18.3.1): GET /v1/policy-group answers a bare list ([] today: the W7 group
mcp-w7-pg was removed); the policy-object profile Default_Policy_Object_Profile holds the shared lists. The
W7 #35 owner call created a policy group with only that profile, associated br1 (POST .../device/associate
{devices: [{id}]}) and saw the delete refused with PLGRP0003 while br1 was associated. The group records and
the create answer below follow that call and Cisco's documentation (ids are documentation UUIDs).
"""

import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import features as ft
from cat_sdwan_mcp import policygroups as pg

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

FP = "/dataservice/v1/feature-profile/sdwan"
PGS = "/dataservice/v1/policy-group"
PGID = "00000000-0000-4000-8000-00000000b101"
PGID2 = "00000000-0000-4000-8000-00000000b102"
OBJ = "00000000-0000-4000-8000-00000000b201"
SEC = "00000000-0000-4000-8000-00000000b202"
APP = "00000000-0000-4000-8000-00000000b203"
BR1, HUB1, BR2 = "REDACTED-16", "REDACTED-17", "REDACTED-22"
BR2_ON_TEMPLATE = {"configOperationMode": "vmanage", "template": "mcp-test-br2"}

PROFILES = {
    "policy-object": [
        {"profileId": OBJ, "profileName": "Default_Policy_Object_Profile", "profileType": "policy-object"}
    ],
    "embedded-security": [
        {"profileId": SEC, "profileName": "mcp-w8-security", "profileType": "embedded-security"}
    ],
    "application-priority": [
        {"profileId": APP, "profileName": "mcp-w8-app", "profileType": "application-priority"}
    ],
}


def pgroup(gid: str = PGID, name: str = "mcp-w8-pg", profiles: list[str] | None = None) -> dict[str, Any]:
    every = {
        OBJ: {"id": OBJ, "name": "Default_Policy_Object_Profile", "type": "policy-object"},
        SEC: {"id": SEC, "name": "mcp-w8-security", "type": "embedded-security"},
    }
    return {
        "id": gid,
        "name": name,
        "description": "",
        "solution": "sdwan",
        "profiles": [every[p] for p in (profiles if profiles is not None else [OBJ])],
        "numberOfDevices": 0,
        "lastUpdatedOn": 1792836509246,
        "version": 1,
    }


def assoc(*chassis: str) -> dict[str, Any]:
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    return {"devices": [rows[c] for c in chassis]}


def mock_groups(
    api: respx.MockRouter, *groups: dict[str, Any], members: dict[str, list[str]] | None = None
) -> None:
    api.get(PGS).respond(json=list(groups))
    for g in groups:
        api.get(f"{PGS}/{g['id']}").respond(json=g)
        api.get(f"{PGS}/{g['id']}/device/associate").respond(json=assoc(*(members or {}).get(g["id"], [])))
    for t in ft.LISTABLE_TYPES:
        api.get(f"{FP}/{t}").respond(json=PROFILES.get(t, []))


async def write(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        return (await c.call_tool(name, args)).structured_content


async def confirmed(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, **settings)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        assert not first.get("blockers"), first["blockers"]
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


# --- helpers -------------------------------------------------------------------------------------


def test_name_rules_and_bodies() -> None:
    assert pg.name_problem("mcp-w8-pg") is None
    assert "space" in str(pg.name_problem("mcp w8"))
    assert "empty" in str(pg.name_problem(" "))
    assert pg.create_body("a", "", [OBJ]) == {
        "name": "a",
        "description": "",
        "solution": "sdwan",
        "profiles": [{"id": OBJ}],
    }
    assert pg.devices_body([BR1]) == {"devices": [{"id": BR1}]}
    assert pg.created_id({"id": "x"}) == "x" and pg.created_id(None) is None
    assert pg.duplicate_types([{"type": "a"}, {"type": "a"}, {"type": "b"}]) == ["a"]


def test_recorded_policy_group_list_is_a_bare_list() -> None:
    assert fixture("v1_policy_group") == []


# --- create --------------------------------------------------------------------------------------


async def test_create_adds_the_policy_object_profile_and_posts(api: respx.MockRouter) -> None:
    mock_groups(api)
    post = api.post(PGS).respond(json={"id": PGID})
    args = {"name": "mcp-w8-pg", "profiles": ["mcp-w8-security"]}
    out = await write("catsdwan_create_policy_group", args)
    assert out["status"] == "preview" and not out.get("blockers")
    prof = out["preview"]["profiles"]
    assert [p["type"] for p in prof] == ["policy-object", "embedded-security"]
    assert "Default_Policy_Object_Profile" in out["preview"]["warnings"][0]
    assert out["undo"] == "back-out: catsdwan_delete_policy_group(group=<from the result: id>)"
    done = await confirmed("catsdwan_create_policy_group", args)
    assert done["undo"]["tool"] == "catsdwan_delete_policy_group" and done["undo"]["args"] == {"group": PGID}
    assert json.loads(post.calls.last.request.content) == {
        "name": "mcp-w8-pg",
        "description": "",
        "solution": "sdwan",
        "profiles": [{"id": OBJ}, {"id": SEC}],
    }
    assert done["result"]["id"] == PGID


async def test_create_blockers(api: respx.MockRouter) -> None:
    mock_groups(api, pgroup())
    out = await write(
        "catsdwan_create_policy_group",
        {"name": "mcp-w8-pg", "profiles": ["nope", "Default_Policy_Object_Profile", OBJ]},
    )
    text = " ".join(out["blockers"])
    assert "exists already" in text and "'nope'" in text
    bad = await write("catsdwan_create_policy_group", {"name": "bad name!"})
    assert any("space" in b for b in bad["blockers"])


# --- associate -----------------------------------------------------------------------------------


async def test_associate_add_and_remove(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_groups(api, pgroup(), members={PGID: [HUB1]})
    post = api.post(f"{PGS}/{PGID}/device/associate").respond(200)
    delete = api.delete(f"{PGS}/{PGID}/device/associate").respond(200)
    args = {"group": "mcp-w8-pg", "add": ["br1"], "remove": ["hub1"]}
    out = await write("catsdwan_associate_policy_group", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    assert out["preview"]["devices_before"] == ["hub1"] and out["preview"]["devices_after"] == ["br1"]
    assert out["blast_radius"] == 2
    assert out["undo"] == (
        'back-out: catsdwan_associate_policy_group(group="mcp-w8-pg", add=["hub1"], remove=["br1"])'
    )
    await confirmed("catsdwan_associate_policy_group", args)
    assert json.loads(post.calls.last.request.content) == {"devices": [{"id": BR1}]}
    assert json.loads(delete.calls.last.request.content) == {"devices": [{"id": HUB1}]}


async def test_associate_blockers(api: respx.MockRouter) -> None:
    mock_inventory(api, br2=BR2_ON_TEMPLATE)
    mock_groups(api, pgroup(), pgroup(PGID2, "mcp-other"), members={PGID: [BR1], PGID2: [HUB1]})
    out = await write(
        "catsdwan_associate_policy_group", {"group": "mcp-w8-pg", "add": ["br1", "br2", "hub1"]}
    )
    text = " ".join(out["blockers"])
    assert "br1 is already in policy group mcp-w8-pg" in text
    assert "br2 is on device template" in text
    assert "hub1 is in policy group mcp-other" in text
    rm = await write("catsdwan_associate_policy_group", {"group": "mcp-w8-pg", "remove": ["hub1"]})
    assert any("hub1 is not in policy group" in b for b in rm["blockers"])


# --- delete --------------------------------------------------------------------------------------


async def test_delete_refused_while_associated_then_dissociates(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_groups(api, pgroup(), members={PGID: [BR1]})
    delete_assoc = api.delete(f"{PGS}/{PGID}/device/associate").respond(200)
    delete = api.delete(f"{PGS}/{PGID}").respond(200)
    out = await write("catsdwan_delete_policy_group", {"group": "mcp-w8-pg"})
    assert any("PLGRP0003" in b for b in out["blockers"])
    done = await confirmed("catsdwan_delete_policy_group", {"group": "mcp-w8-pg", "dissociate": True})
    assert json.loads(delete_assoc.calls.last.request.content) == {"devices": [{"id": BR1}]}
    assert delete.called and "deleteProfiles" not in str(delete.calls.last.request.url)
    assert done["result"] == {"dissociated": ["br1"], "deleted": "mcp-w8-pg"}
    assert done["undo"]["tool"] == "catsdwan_create_policy_group"
    assert done["undo"]["args"] == {
        "name": "mcp-w8-pg",
        "profiles": ["Default_Policy_Object_Profile"],
        "description": "",
    }


async def test_delete_profiles_spares_shared_profiles(api: respx.MockRouter) -> None:
    mock_groups(api, pgroup(profiles=[OBJ, SEC]), pgroup(PGID2, "mcp-other", profiles=[SEC]))
    out = await write("catsdwan_delete_policy_group", {"group": "mcp-w8-pg", "delete_profiles": True})
    text = " ".join(out["blockers"])
    assert "shared policy-object profile" in text and "used by another policy group" in text


async def test_delete_empty_group_with_its_profiles(api: respx.MockRouter) -> None:
    mock_groups(api, pgroup(profiles=[SEC]))
    delete = api.delete(f"{PGS}/{PGID}").respond(200)
    done = await confirmed("catsdwan_delete_policy_group", {"group": "mcp-w8-pg", "delete_profiles": True})
    assert delete.calls.last.request.url.params["deleteProfiles"] == "true"
    assert done["undo"]["back_out"].startswith("not reversible: the deleted profiles are gone")
    assert "tool" not in done["undo"]


@pytest.mark.parametrize("tool", ["catsdwan_create_policy_group", "catsdwan_delete_policy_group"])
async def test_hidden_without_writes(tool: str) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert tool not in names
