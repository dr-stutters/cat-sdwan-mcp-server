"""W47: edge firewall writes (security objects, NGFW policy with zone pairs) and the policy-group read.

Recorded on the lab Manager (20.18.3.1, read only): the POST schemas of the policy-object list types
security-zone, security-identity, security-scalablegrouptag and security-data-ip-prefix (documentation
`details-*` lines trimmed), an empty security-zone list ({header, data: []}) and a system data-prefix parcel.
The embedded-security profile, NGFW and security-policy parcel shapes follow Cisco's published models (the lab
has none and the 20.18 OpenAPI document carries no body schema for them); ids are documentation UUIDs.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp import edgefirewall as fw
from cat_sdwan_mcp import features as ft

from .conftest import fixture, make_server, mock_service_vpns

FP = "/dataservice/v1/feature-profile/sdwan"
PGS = "/dataservice/v1/policy-group"
PGID = "00000000-0000-4000-8000-00000000b101"
OBJ = "00000000-0000-4000-8000-00000000b201"
SEC = "00000000-0000-4000-8000-00000000b202"
ZIN, ZOUT = "00000000-0000-4000-8000-00000000d001", "00000000-0000-4000-8000-00000000d002"
IDL = "00000000-0000-4000-8000-00000000d003"
NG = "00000000-0000-4000-8000-00000000d004"
POL = "00000000-0000-4000-8000-00000000d005"
BR1 = "REDACTED-16"
PO = f"{FP}/policy-object/{OBJ}"
ES = f"{FP}/embedded-security/{SEC}"

OBJ_PROFILE = {"id": OBJ, "name": "Default_Policy_Object_Profile", "type": "policy-object"}
SEC_PROFILE = {"id": SEC, "name": "mcp-w8-pg-security", "type": "embedded-security"}


def listed(*rows: dict[str, Any]) -> dict[str, Any]:
    """A parcel list as the Manager answers it (recorded: {header, data: []})."""
    body = copy.deepcopy(fixture("v1_feature_profile_policy_object_security_zone_list"))
    body["data"] = list(rows)
    return body


def parcel(pid: str, ptype: str, name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"parcelId": pid, "parcelType": ptype, "lastUpdatedOn": 1, "payload": {"name": name, "data": data}}


def zone(pid: str, name: str, vpn: str) -> dict[str, Any]:
    return parcel(pid, "security-zone", name, {"entries": [{"vpn": fw.g(vpn)}]})


def mock_manager(
    api: respx.MockRouter,
    *,
    with_security: bool = True,
    ngfw: list[dict[str, Any]] | None = None,
    policy: list[dict[str, Any]] | None = None,
    members: list[str] | None = None,
    converted: bool = True,
) -> None:
    mock_service_vpns(api, converted=converted, more=(20,))
    profiles = [OBJ_PROFILE, *([SEC_PROFILE] if with_security else [])]
    group = {"id": PGID, "name": "mcp-w8-pg", "description": "", "profiles": profiles, "lastUpdatedOn": 5}
    api.get(PGS).respond(json=[group])
    api.get(f"{PGS}/{PGID}").respond(json=group)
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    api.get(f"{PGS}/{PGID}/device/associate").respond(json={"devices": [rows[c] for c in members or []]})
    lists = {
        "policy-object": [
            {"profileId": OBJ, "profileName": OBJ_PROFILE["name"], "profileType": "policy-object"}
        ],
        "embedded-security": [
            {"profileId": SEC, "profileName": SEC_PROFILE["name"], "profileType": "embedded-security"}
        ]
        if with_security
        else [],
    }
    for t in ft.LISTABLE_TYPES:
        api.get(f"{FP}/{t}").respond(json=lists.get(t, []))
    api.get(f"{PO}/security-zone").respond(
        json=listed(zone(ZIN, "lan", "mcp-w8-vpn10"), zone(ZOUT, "guest", "mcp-w8-vpn20"))
    )
    api.get(f"{PO}/security-identity").respond(
        json=listed(parcel(IDL, "security-identity", "alice-only", {"entries": [{"user": fw.g("alice")}]}))
    )
    api.get(f"{PO}/security-scalablegrouptag").respond(json=listed())
    api.get(f"{PO}/security-data-ip-prefix").respond(json=listed())
    api.get(f"{PO}/app-list").respond(json=listed())
    for t in ("security-zone", "security-identity", "security-scalablegrouptag", "security-data-ip-prefix"):
        api.get(f"{FP}/policy-object/{t}/schema").respond(
            json=fixture(f"v1_feature_profile_policy_object_{t.replace('-', '_')}_schema_post")
        )
    api.get(f"{FP}/embedded-security/unified/ngfirewall/schema").respond(
        404, json={"error": {"message": "nf"}}
    )
    api.get(f"{ES}/unified/ngfirewall").respond(json=listed(*(ngfw or [])))
    api.get(f"{ES}/policy").respond(json=listed(*(policy or [])))
    api.get("/dataservice/ise/credentials").respond(json={})


async def preview(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)) as c:
        return (await c.call_tool(name, args)).structured_content


async def confirmed(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        assert not first.get("blockers"), first["blockers"]
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


# --- helpers on the recorded schemas -------------------------------------------------------------


def schema(list_type: str) -> dict[str, Any]:
    return fw.request_schema(
        fixture(f"v1_feature_profile_policy_object_{list_type.replace('-', '_')}_schema_post")
    )


def test_object_entries_fit_the_recorded_schemas() -> None:
    cases = {
        "zone": ["10", "20"],
        "identity": ["alice", "group:LAB/Users/Sales"],
        "sgt": ["Employees:4", "17"],
        "prefix": ["192.0.2.0/24"],
    }
    for kind, values in cases.items():
        entries, problems = fw.object_entries(kind, values)
        assert not problems, problems
        body = fw.object_body("obj1", "", entries)
        assert fw.schema_problems(schema(fw.OBJECT_TYPES[kind]), body) == [], kind
    entries, _ = fw.object_entries("zone", ["GigabitEthernet3"])
    assert entries == [{"interface": fw.g("GigabitEthernet3")}]
    assert fw.object_values(
        "identity", {"entries": fw.object_entries("identity", ["group:G", "bob"])[0]}
    ) == [
        "group:G",
        "user:bob",
    ]


def test_object_problems_and_schema_refusals() -> None:
    assert "not both" in fw.object_entries("zone", ["10", "GigabitEthernet3"])[1][0]
    assert "IPv4 prefix" in fw.object_entries("prefix", ["192.0.2.1/24"])[1][0]
    assert "give '<name>:<tag>'" in fw.object_entries("sgt", ["Unknown"])[1][0]
    assert fw.object_entries("sgt", ["Employees"], {"Employees": "4"})[0] == [
        {"sgtName": fw.g("Employees"), "tag": fw.g("4")}
    ]
    assert "at most 16" in fw.object_entries("identity", [f"u{i}" for i in range(17)])[1][0]
    # The Manager's own rules: a zone may not be called 'self'; interface names follow its pattern.
    bad = fw.object_body("self", "", [{"interface": fw.g("eth0")}])
    text = " ".join(fw.schema_problems(schema("security-zone"), bad))
    assert "name" in text and "pattern" in text
    assert fw.schema_problems(schema("security-zone"), {"name": "x"}) == ["body: data is required"]


def test_recorded_parcel_shapes() -> None:
    rows = fw.parcels(fixture("v1_feature_profile_policy_object_security_zone_list"))
    assert rows == []
    one = fw.parcels([fixture("v1_feature_profile_policy_object_data_prefix_parcel")])[0]
    assert one["name"] == "rfc1918_default_dataprefixes" and len(one["data"]["entries"]) == 3


def test_ngfw_body_and_words() -> None:
    rules = [
        {
            "name": "alice-web",
            "action": "inspect",
            "identities": ["alice-only"],
            "protocols": ["TCP"],
            "log": True,
        },
        {"name": "lan-dns", "action": "pass", "destination_prefixes": ["198.51.100.53/32"]},
    ]
    body = fw.ngfw_body("br-fw", "", "drop", rules, {"identity": {"alice-only": IDL}})
    seq = body["data"]["sequences"]
    assert seq[0]["match"]["entries"] == [
        {"sourceIdentityList": {"refId": fw.g([IDL])}},
        {"protocolName": fw.g(["tcp"])},
    ]
    assert seq[0]["actions"] == [fw.LOG_ACTION] and seq[1]["actions"] == []
    assert seq[1]["match"]["entries"] == [{"destinationIp": {"ipv4Value": fw.g(["198.51.100.53/32"])}}]
    words = fw.describe_rules(body["data"], {IDL: "alice-only"})
    assert words == [
        "1 alice-web: identity alice-only; protocol tcp -> inspect, log",
        "2 lan-dns: destination 198.51.100.53/32 -> pass",
        "default -> drop",
    ]


def test_log_action_is_the_20_18_shape() -> None:
    # #126: 0.6.2 sent parameter {optionType: default}; its own check against the Manager's NGFW schema
    # refused it ("actions[0].parameter value is required / 'default' is not one of ['global']"). The shape is
    # Cisco's example in the Manager's 20.18.3 OpenAPI document.
    example = fixture("spec_example_ngfirewall_parcel")["payload"]["data"]["sequences"][0]["actions"]
    log = next(a for a in example if a["type"]["value"] == "log")
    assert log == fw.LOG_ACTION
    # The parameter rule the live check applied (reconstructed from its two messages).
    action_schema = {
        "type": "object",
        "required": ["type", "parameter"],
        "properties": {
            "parameter": {
                "type": "object",
                "required": ["optionType", "value"],
                "properties": {
                    "optionType": {"type": "string", "enum": ["global"]},
                    "value": {"type": "string"},
                },
            }
        },
    }
    assert fw.schema_problems(action_schema, fw.LOG_ACTION) == []
    old = {"type": fw.LOG_ACTION["type"], "parameter": {"optionType": "default"}}
    assert fw.schema_problems(action_schema, old) == [
        "parameter: value is required",
        "parameter.optionType: 'default' is not one of ['global']",
    ]


def test_assembly_merge_keeps_other_policies() -> None:
    other = fw.assembly_item("other", [("a", "b")])
    data = {"assembly": [other], "settings": {"auditTrail": fw.g("on")}}
    merged = fw.merge_assembly(data, NG, fw.assembly_item(NG, [(ZIN, ZOUT)]))
    assert merged["assembly"][0] == other and fw.zone_pairs_of(merged, NG) == [(NG, ZIN, ZOUT)]
    assert merged["settings"] == data["settings"]
    assert fw.merge_assembly(merged, NG, None)["assembly"] == [other]


# --- catsdwan_set_security_object ----------------------------------------------------------------


async def test_object_create_is_checked_and_posted(api: respx.MockRouter) -> None:
    mock_manager(api, members=[BR1])
    post = api.post(f"{PO}/security-identity").respond(json={"parcelId": "new-1"})
    args = {"kind": "identity", "name": "bob-only", "values": ["bob", "group:LAB/Users/Sales"]}
    out = await preview("catsdwan_set_security_object", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["after"] == ["user:bob", "group:LAB/Users/Sales"] and p["before"] is None
    assert p["reaches"] == [{"group": "mcp-w8-pg", "devices": ["br1"]}] and out["blast_radius"] == 1
    assert any("no ISE on the Manager" in w for w in p["warnings"])
    done = await confirmed("catsdwan_set_security_object", args)
    sent = json.loads(post.calls.last.request.content)
    assert sent["data"]["entries"][1] == {"userGroup": fw.g("LAB/Users/Sales")}
    assert done["result"]["id"] == "new-1"


async def test_object_replace_and_remove(api: respx.MockRouter) -> None:
    mock_manager(api)
    api.get(f"{FP}/policy-object/security-zone/schema").respond(
        json=fixture("v1_feature_profile_policy_object_security_zone_schema_post")
    )
    put = api.put(f"{PO}/security-zone/{ZIN}").respond(200)
    out = await preview(
        "catsdwan_set_security_object", {"kind": "zone", "name": "lan", "values": ["10", "20"]}
    )
    # #126: VPN ids are stored as the LAN VPN parcel names the controller looks up.
    assert out["preview"]["before"] == ["mcp-w8-vpn10"]
    assert out["preview"]["after"] == ["mcp-w8-vpn10", "mcp-w8-vpn20"]
    await confirmed("catsdwan_set_security_object", {"kind": "zone", "name": "lan", "values": ["10", "20"]})
    assert put.called
    assert json.loads(put.calls.last.request.content)["data"]["entries"] == [
        {"vpn": fw.g("mcp-w8-vpn10")},
        {"vpn": fw.g("mcp-w8-vpn20")},
    ]
    delete = api.delete(f"{PO}/security-zone/{ZOUT}").respond(200)
    done = await confirmed("catsdwan_set_security_object", {"kind": "zone", "name": "guest", "remove": True})
    assert delete.called and done["result"]["deleted"] == "guest"
    missing = await preview("catsdwan_set_security_object", {"kind": "zone", "name": "dmz", "remove": True})
    assert any("no zone object named dmz" in b for b in missing["blockers"])


async def test_object_refused_without_dangerous(api: respx.MockRouter) -> None:
    mock_manager(api)
    async with Client(make_server(mcp_enable_writes=True)) as c:
        out = (
            await c.call_tool(
                "catsdwan_set_security_object", {"kind": "prefix", "name": "srv", "values": ["192.0.2.0/24"]}
            )
        ).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in b for b in out["blockers"])


# --- catsdwan_set_firewall_policy ----------------------------------------------------------------

RULES = [
    {"name": "allow-alice", "action": "inspect", "identities": ["alice-only"]},
    {"name": "deny-rest", "action": "drop", "source_prefixes": ["192.0.2.0/24"], "log": True},
]
PAIRS = [{"source": "lan", "destination": "guest"}]


async def test_firewall_create_in_the_groups_profile(api: respx.MockRouter) -> None:
    mock_manager(api, members=[BR1])
    post_ngfw = api.post(f"{ES}/unified/ngfirewall").respond(json={"parcelId": NG})
    post_pol = api.post(f"{ES}/policy").respond(json={"parcelId": POL})
    args = {"group": "mcp-w8-pg", "name": "br-fw", "rules": RULES, "zone_pairs": PAIRS}
    out = await preview("catsdwan_set_firewall_policy", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["after"]["rules"] == [
        "1 allow-alice: identity alice-only -> inspect",
        "2 deny-rest: source 192.0.2.0/24 -> drop, log",
        "default -> drop",
    ]
    assert p["after"]["zone_pairs"] == ["lan -> guest"] and p["profile"] == "mcp-w8-pg-security"
    assert out["blast_radius"] == 1
    assert any("not checked against the Manager's schema" in w for w in p["warnings"])
    done = await confirmed("catsdwan_set_firewall_policy", args)
    ngfw = json.loads(post_ngfw.calls.last.request.content)
    assert ngfw["data"]["sequences"][0]["match"]["entries"] == [
        {"sourceIdentityList": {"refId": fw.g([IDL])}}
    ]
    pol = json.loads(post_pol.calls.last.request.content)
    assert pol["data"]["assembly"] == [fw.assembly_item(NG, [(ZIN, ZOUT)])]
    assert done["result"]["id"] == NG


async def test_firewall_replace_merges_the_security_policy(api: respx.MockRouter) -> None:
    old = parcel(NG, "unified/ngfirewall", "br-fw", fw.ngfw_body("br-fw", "", "pass", [], {})["data"])
    other = fw.assembly_item("00000000-0000-4000-8000-00000000d0ff", [(ZOUT, ZIN)])
    pol = parcel(
        POL, "policy", "mcp-w8-pg-policy", {"assembly": [other, fw.assembly_item(NG, [(ZOUT, ZIN)])]}
    )
    mock_manager(api, ngfw=[old], policy=[pol])
    put_ngfw = api.put(f"{ES}/unified/ngfirewall/{NG}").respond(200)
    put_pol = api.put(f"{ES}/policy/{POL}").respond(200)
    args = {"group": "mcp-w8-pg", "name": "br-fw", "rules": RULES, "zone_pairs": PAIRS}
    out = await preview("catsdwan_set_firewall_policy", args)
    assert out["preview"]["before"] == {"rules": ["default -> pass"], "zone_pairs": ["guest -> lan"]}
    await confirmed("catsdwan_set_firewall_policy", args)
    assert put_ngfw.called
    sent = json.loads(put_pol.calls.last.request.content)
    assert sent["data"]["assembly"] == [other, fw.assembly_item(NG, [(ZIN, ZOUT)])]


async def test_firewall_creates_and_attaches_a_profile(api: respx.MockRouter) -> None:
    mock_manager(api, with_security=False)
    create = api.post(f"{FP}/embedded-security").respond(json={"id": SEC})
    put_group = api.put(f"{PGS}/{PGID}").respond(200)
    api.post(f"{ES}/unified/ngfirewall").respond(json={"parcelId": NG})
    api.post(f"{ES}/policy").respond(json={"parcelId": POL})
    args = {"group": "mcp-w8-pg", "name": "br-fw", "rules": RULES[:1], "zone_pairs": PAIRS}
    out = await preview("catsdwan_set_firewall_policy", args)
    assert out["preview"]["profile"] == "mcp-w8-pg-security (new)"
    done = await confirmed("catsdwan_set_firewall_policy", args)
    assert json.loads(create.calls.last.request.content)["name"] == "mcp-w8-pg-security"
    assert json.loads(put_group.calls.last.request.content)["profiles"] == [{"id": OBJ}, {"id": SEC}]
    assert done["result"]["profile_created"] == "mcp-w8-pg-security"


async def test_firewall_blockers(api: respx.MockRouter) -> None:
    mock_manager(api)
    rules = [
        {"name": "r", "action": "pass", "identities": ["nobody"]},
        {"name": "r", "action": "drop", "source_prefixes": ["192.0.2.1/24"]},
    ]
    out = await preview(
        "catsdwan_set_firewall_policy",
        {
            "group": "mcp-w8-pg",
            "name": "br-fw",
            "rules": rules,
            "zone_pairs": [{"source": "lan", "destination": "dmz"}],
        },
    )
    text = " ".join(out["blockers"])
    assert "no identity object named 'nobody'" in text and "no zone object named 'dmz'" in text
    assert "used twice" in text and "IPv4 prefix" in text
    none = await preview("catsdwan_set_firewall_policy", {"group": "mcp-w8-pg", "name": "x"})
    assert any("zone pair" in b for b in none["blockers"])
    second = await preview(
        "catsdwan_set_firewall_policy",
        {"group": "mcp-w8-pg", "name": "br-fw", "zone_pairs": PAIRS, "profile": "another-security"},
    )
    assert any("one per group" in b for b in second["blockers"])


async def test_firewall_remove(api: respx.MockRouter) -> None:
    old = parcel(NG, "unified/ngfirewall", "br-fw", fw.ngfw_body("br-fw", "", "drop", [], {})["data"])
    pol = parcel(POL, "policy", "mcp-w8-pg-policy", {"assembly": [fw.assembly_item(NG, [(ZIN, ZOUT)])]})
    mock_manager(api, ngfw=[old], policy=[pol])
    del_pol = api.delete(f"{ES}/policy/{POL}").respond(200)
    del_ngfw = api.delete(f"{ES}/unified/ngfirewall/{NG}").respond(200)
    args = {"group": "mcp-w8-pg", "name": "br-fw", "remove": True}
    out = await preview("catsdwan_set_firewall_policy", args)
    assert out["preview"]["before"]["zone_pairs"] == ["lan -> guest"]
    done = await confirmed("catsdwan_set_firewall_policy", args)
    assert del_pol.called and del_ngfw.called and done["result"]["removed"] == "br-fw"


# --- catsdwan_get_firewall_policy ----------------------------------------------------------------


async def test_get_firewall_policy_in_words(api: respx.MockRouter) -> None:
    rules = [{"name": "allow-alice", "action": "inspect", "identities": ["alice-only"]}]
    ng = parcel(
        NG,
        "unified/ngfirewall",
        "br-fw",
        fw.ngfw_body("br-fw", "", "drop", rules, {"identity": {"alice-only": IDL}})["data"],
    )
    pol = parcel(POL, "policy", "p", {"assembly": [fw.assembly_item(NG, [(ZIN, ZOUT)])]})
    mock_manager(api, ngfw=[ng], policy=[pol])
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_get_firewall_policy", {"group": "mcp-w8-pg"})).structured_content
    fwp = out["firewall_policies"][0]
    assert fwp["rules"] == ["1 allow-alice: identity alice-only -> inspect", "default -> drop"]
    assert fwp["zone_pairs"] == ["lan -> guest"]
    assert out["objects"]["zone"] == {"lan": ["mcp-w8-vpn10"], "guest": ["mcp-w8-vpn20"]}
    assert out["objects"]["identity"] == {"alice-only": ["user:alice"]}


async def test_get_firewall_policy_without_security_profile(api: respx.MockRouter) -> None:
    mock_manager(api, with_security=False)
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_get_firewall_policy", {"group": "mcp-w8-pg"})).structured_content
    assert "no embedded-security profile" in out["verdict"]


@pytest.mark.parametrize("tool", ["catsdwan_set_security_object", "catsdwan_set_firewall_policy"])
async def test_writes_hidden_without_writes(tool: str) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert tool not in names and "catsdwan_get_firewall_policy" in names
