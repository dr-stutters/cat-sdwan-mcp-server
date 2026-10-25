"""W45: WAN-edge containment in two paths: the standing quarantine baseline (ISE quarantine SGT rules in the
policy group's NGFW), the no-ISE fallback as a per-edge CLI ACL (catsdwan_set_containment_acl once, then
catsdwan_contain_at_edge / catsdwan_release_at_edge on one edge), the status, and the prompt
catsdwan_contain_host.

Recorded (20.18.3.1, read only): the inventory, hub1's ARP table (host 10.61.100.10 learned on Gi3 in VPN
10; br1's own table gets a host the same way), the configuration groups after the W8 live run (mcp-test with
CLI add-on mcp-test-cli, mcp-w8-hub), the mcp-test CLI parcel and its profile detail, the device
association, the config-group device variables shape, the security-scalablegrouptag POST schema, the ISE SGT
answer without ISE, the edge TrustSec tables without ISE and the audit log row shape. The l65 CLI parcel and
variables (br1's FTD leg as {{fw_*}} variables, br2 neutral, Gi3 moved to the LAN VPN parcel) are the
recorded parcel with the l65-wiring / w8-live edits from notes/w8-fixtures/l65-wiring (management addresses
replaced). Not recorded: the NGFW / security-policy parcels (W47's shapes) and the CLI parcel PUT answer.
"""

import copy
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import containment as ct
from cat_sdwan_mcp import edgefirewall as fw
from cat_sdwan_mcp.tools import changes as change_tools
from cat_sdwan_mcp.tools import containment as tc

from .conftest import W8_HUB_GROUP, W8_TEST_GROUP, fixture, make_server
from .test_edgefirewall import ES, NG, PO, POL, ZIN, ZOUT, listed, mock_manager, parcel
from .test_findhost import mock_edges
from .test_inventory import mock_inventory

HUB1 = "REDACTED-17"
BR1 = "REDACTED-16"
BR2 = "REDACTED-22"
HOST = "10.61.200.10"  # behind br1 Gi3
SGT_ID = "00000000-0000-4000-8000-00000000e002"
STATUS = "/dataservice/device/action/status"
CG = "/dataservice/v1/config-group"
VARS = f"{CG}/{W8_TEST_GROUP}/device/variables"
HUB_VARS = f"{CG}/{W8_HUB_GROUP}/device/variables"
CLI_PROFILE = "00000000-0000-4000-8000-000000001038"
CLI_PARCEL = "00000000-0000-4000-8000-000000001039"
HUB_CLI = "00000000-0000-4000-8000-00000000f112"
CLI_URL = f"/dataservice/v1/feature-profile/sdwan/cli/{CLI_PROFILE}/config/{CLI_PARCEL}"
RULES = [
    {"name": "allow-web", "action": "inspect", "protocols": ["tcp"]},
    {"name": "deny-guest", "action": "drop", "source_prefixes": ["192.0.2.0/24"], "log": True},
]
IFS = ["GigabitEthernet3", "{{fw_if}}"]
REM = ["198.51.100.53/32"]


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


# --- recorded shapes -----------------------------------------------------------------------------


def cli_text(acl: bool = True) -> str:
    text = str(fixture("v1_feature_profile_cli_config_parcel_l65")["payload"]["data"]["config"])
    return ct.with_acl(text, ct.acl_block(REM, IFS)) if acl else text


def cli_parcel(text: str) -> dict[str, Any]:
    body = copy.deepcopy(fixture("v1_feature_profile_cli_config_parcel_l65"))
    body["payload"]["data"]["config"] = text
    return body


def l65_variables(**held: dict[str, str]) -> dict[str, Any]:
    """mcp-test's device variables (br1, br2) with neutral slots, or as `held` gives {chassis: {var: value}};
    `held` with value None drops the slot variables (the Manager has not listed them yet)."""
    body = copy.deepcopy(fixture("v1_config_group_device_variables_l65"))
    for d in body["devices"]:
        extra = {**ct.neutral(), **held.get(d["device-id"], {})}
        d["variables"] += [{"name": k, **({"value": v} if v is not None else {})} for k, v in extra.items()]
    return body


def unset_slots() -> dict[str, Any]:
    body = copy.deepcopy(fixture("v1_config_group_device_variables_l65"))
    for d in body["devices"]:
        d["variables"] += [{"name": k} for k in ct.neutral()]
    return body


def assoc_row(chassis: str, host: str, ip: str, site: str, up: str = "True") -> dict[str, Any]:
    row = copy.deepcopy(fixture("v1_config_group_associate")["devices"][0])
    row.update({"id": chassis, "host-name": host, "deviceIP": ip, "site-id": site, "configGroupUpToDate": up})
    return row


def mock_cfg(
    api: respx.MockRouter,
    *,
    text: str | None = None,
    var_body: dict[str, Any] | None = None,
    br1_arp: bool = True,
    br1_up: str = "True",
) -> dict[str, respx.Route]:
    """Inventory, edge tables (br1's ARP with HOST on Gi3), the W8 configuration groups (mcp-test: br1, br2,
    CLI add-on with or without the ACL; mcp-w8-hub: hub1, no ACL) and the write endpoints."""
    mock_inventory(api)
    arp = copy.deepcopy(fixture("devstate_arp_br1"))
    if br1_arp:
        hub_host = next(r for r in fixture("devstate_arp_hub1")["data"] if r.get("address") == "10.61.100.10")
        arp["data"].append(
            {
                **hub_host,
                "address": HOST,
                "vdevice-name": "10.0.0.2",
                "vdevice-host-name": "br1",
                "hardware": "52:54:00:00:02:10",
            }
        )
    mock_edges(api, arp={"br1": arp})
    api.get(CG).respond(json=fixture("v1_config_group_w8"))
    api.get(f"{CG}/{W8_TEST_GROUP}/device/associate").respond(
        json={
            "devices": [
                assoc_row(BR1, "br1", "10.0.0.2", "200", br1_up),
                assoc_row(BR2, "br2", "10.0.0.3", "201"),
            ]
        }
    )
    api.get(f"{CG}/{W8_HUB_GROUP}/device/associate").respond(
        json={"devices": [assoc_row(HUB1, "hub1", "10.0.0.1", "100")]}
    )
    api.get(f"/dataservice/v1/feature-profile/sdwan/cli/{CLI_PROFILE}").respond(
        json=fixture("v1_feature_profile_cli_detail")
    )
    api.get(f"/dataservice/v1/feature-profile/sdwan/cli/{HUB_CLI}").respond(
        json={"profileId": HUB_CLI, "profileType": "cli", "associatedProfileParcels": []}
    )
    api.get(CLI_URL).respond(json=cli_parcel(cli_text() if text is None else text))
    api.get(VARS).respond(json=l65_variables() if var_body is None else var_body)
    api.get(HUB_VARS).respond(
        json={"family": "sdwan", "devices": [{"device-id": HUB1, "variables": [{"name": "host_name"}]}]}
    )
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})
    api.get(f"{STATUS}/pt-1").respond(
        json={"data": [{"host-name": "br1", "uuid": BR1, "statusId": "success", "status": "Success"}]}
    )
    audit = copy.deepcopy(fixture("auditlog"))
    now = int(datetime.now(UTC).timestamp() * 1000)
    audit["data"] = [
        {
            **audit["data"][0],
            "entry_time": now + 5_000,
            "logmodule": "config group",
            "logfeature": "deploy",
            "logmessage": "Deploy config group mcp-test to br1",
            "auditdetails": "[]",
        },
        audit["data"][0],
    ]
    return {
        "cli_put": api.put(CLI_URL).respond(json={"parcelId": CLI_PARCEL}),
        "vars_put": api.put(VARS).respond(json=[{"device-id": BR1}]),
        "deploy": api.post(f"{CG}/{W8_TEST_GROUP}/device/deploy").respond(json={"parentTaskId": "pt-1"}),
        "audit": api.post("/dataservice/auditlog").respond(json=audit),
    }


def user_data() -> dict[str, Any]:
    return fw.ngfw_body("br-fw", "", "pass", RULES, {})["data"]


def ngfw_row(data: dict[str, Any] | None = None) -> dict[str, Any]:
    row = parcel(NG, "unified/ngfirewall", "br-fw", data or user_data())
    row["payload"]["description"] = "branch firewall"
    return row


def policy_row(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    return parcel(
        POL, "policy", "mcp-w8-pg-policy", {"assembly": [fw.assembly_item(NG, pairs)], "settings": {}}
    )


REFS = {"sgt": {ct.QUARANTINE_OBJECT: SGT_ID}}


def baselined(remediation: list[str] | None = None) -> dict[str, Any]:
    rules = ct.baseline_rules(remediation=remediation or [])
    return ct.with_baseline(user_data(), [ct.sequence(r, REFS) for r in rules])[0]


def sgt_obj(value: str = "255") -> dict[str, Any]:
    entries = [{"sgtName": fw.g("Quarantined_Systems"), "tag": fw.g(value)}]
    return parcel(SGT_ID, "security-scalablegrouptag", ct.QUARANTINE_OBJECT, {"entries": entries})


def mock_pg(
    api: respx.MockRouter,
    *,
    ngfw: list[dict[str, Any]] | None = None,
    sgts: list[dict[str, Any]] | None = None,
) -> dict[str, respx.Route]:
    """The policy group mcp-w8-pg (br1, hub1) for the quarantine baseline."""
    mock_inventory(api)
    mock_manager(
        api,
        ngfw=[ngfw_row(baselined())] if ngfw is None else ngfw,
        policy=[policy_row([(ZIN, ZOUT)])],
        members=[HUB1, BR1],
    )
    api.get(f"{PO}/security-scalablegrouptag").respond(json=listed(*([sgt_obj()] if sgts is None else sgts)))
    api.get("/dataservice/template/policy/ise/identity/sgt").respond(
        400, json=fixture("template_policy_ise_identity_sgt")
    )
    return {
        "ngfw_put": api.put(f"{ES}/unified/ngfirewall/{NG}").respond(200),
        "sgt_post": api.post(f"{PO}/security-scalablegrouptag").respond(json={"parcelId": SGT_ID}),
    }


def mock_trustsec(api: respx.MockRouter, **tables: Any) -> None:
    """hub1's and br1's TrustSec tables as recorded without ISE (environment stuck, no bindings)."""
    recorded = {
        "environment": fixture("device_environmentdata_br1"),
        "sgt_map": fixture("device_rolebasedsgtmap_br1"),
    }
    for ip in ("10.0.0.1", "10.0.0.2"):
        for key, p in tc.TRUSTSEC_TABLES.items():
            body = tables.get(key, recorded.get(key, fixture("device_interface_trustsec_br1")))
            api.get(p, params={"deviceId": ip}).respond(json=body)


async def preview(name: str, args: dict[str, Any], **settings: Any) -> Any:
    kw = {"mcp_enable_writes": True, "mcp_enable_dangerous": True, **settings}
    async with Client(make_server(**kw)) as c:
        return (await c.call_tool(name, args)).structured_content


async def confirmed(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        assert not first.get("blockers"), first["blockers"]
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


def names_of(data: dict[str, Any]) -> list[str]:
    return [fw.leaf_value(s["sequenceName"]) for s in data["sequences"]]


def put_values(route: respx.Route) -> dict[str, dict[str, Any]]:
    body = json.loads(route.calls.last.request.content)
    return {d["device-id"]: {v["name"]: v.get("value") for v in d["variables"]} for d in body["devices"]}


# --- helpers -------------------------------------------------------------------------------------


def test_host_ip() -> None:
    assert ct.host_ip(" 10.61.100.10 ") == "10.61.100.10"
    for bad in ("10.61.100.0/24", "2001:db8::1", "printer", "0.0.0.0", "224.0.0.5", "192.0.2.242"):
        with pytest.raises(ValueError):
            ct.host_ip(bad)


def test_acl_block_is_ios_xe_with_sequence_numbers() -> None:
    block = ct.acl_block(["198.51.100.53/32", "198.51.100.0/24"], IFS).splitlines()
    assert block[:3] == [
        "ip access-list extended mcp-contain",
        " 10 permit ip any host 198.51.100.53",
        " 11 permit ip any 198.51.100.0 0.0.0.255",
    ]
    assert block[3:5] == [" 110 remark {{mcp_contain_1_note}}", " 111 deny ip host {{mcp_contain_1}} any"]
    assert block[9:13] == [
        " 140 remark {{mcp_contain_4_note}}",
        " 141 deny ip host {{mcp_contain_4}} any",
        " 1000 permit ip any any",
        "!",
    ]
    assert block[13:] == [
        "interface GigabitEthernet3",
        " ip access-group mcp-contain in",
        "exit",
        "interface {{fw_if}}",
        " ip access-group mcp-contain in",
        "exit",
    ]


def test_acl_round_trip_on_the_recorded_cli() -> None:
    plain = cli_text(acl=False)
    assert ct.acl_state(plain) is None
    with_it = cli_text()
    state = ct.acl_state(with_it)
    assert state == {"interfaces": IFS, "remediation": REM, "slots": ct.SLOT_VARS, "intact": True}
    # Everything else keeps its place; the block sits at the end and comes out exactly.
    assert with_it.startswith(plain.rstrip("\n")) and ct.without_acl(with_it) == plain
    # Replacing it does not duplicate it.
    again = ct.with_acl(with_it, ct.acl_block([], ["GigabitEthernet3"]))
    assert again.count("ip access-list extended mcp-contain") == 1
    assert ct.acl_state(again)["interfaces"] == ["GigabitEthernet3"]  # type: ignore[index]
    edited = with_it.replace(" 1000 permit ip any any", " 1000 deny ip any any")
    assert ct.acl_state(edited)["intact"] is False  # type: ignore[index]
    # The secret line is untouched (the tools mask it, the PUT keeps the stored hash).
    assert [ln for ln in with_it.splitlines() if "secret 9" in ln] == [
        ln for ln in plain.splitlines() if "secret 9" in ln
    ]


def test_interface_problems() -> None:
    text = cli_text(acl=False)
    assert ct.interface_problems(IFS, text) == []
    probs = ct.interface_problems(["{{nope_if}}", "Gi 3", "GigabitEthernet3", "GigabitEthernet3"], text)
    assert any("no variable nope_if" in p for p in probs)
    assert any("not an interface name" in p for p in probs)
    assert any("given twice" in p for p in probs)
    taken = text.replace(
        " vrf forwarding Mgmt-intf\n", " vrf forwarding Mgmt-intf\n ip access-group MGMT in\n"
    )
    assert any(
        "already applies an inbound ACL" in p for p in ct.interface_problems(["GigabitEthernet4"], taken)
    )


def test_slots_notes_and_expiry() -> None:
    values = {
        "mcp_contain_1": "10.61.100.11",
        "mcp_contain_2": ct.INERT["mcp_contain_2"],
        "mcp_contain_3": None,
    }
    assert ct.pick_slot(values, HOST) == ("mcp_contain_2", False)
    assert ct.pick_slot(values, "10.61.100.11") == ("mcp_contain_1", True)
    assert ct.contained_at(values) == {"mcp_contain_1": "10.61.100.11"}
    full = {s: f"10.61.100.{i}" for i, s in enumerate(ct.SLOT_VARS, start=20)}
    assert ct.pick_slot(full, HOST) == (None, False)
    now = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    exp = ct.expiry(24, now)
    assert exp == "2026-10-25T10:00Z"
    text = ct.note(exp, "INC-1 beaconing; {{x}} " + "y" * 200)
    assert len(text) <= ct.REMARK_CHARS and "{" not in text and ";" not in text
    assert ct.parse_note(text)["expires"] == exp and ct.parse_note(text)["reason"].startswith(
        "INC-1 beaconing"
    )
    assert ct.parse_note(ct.NOTE_FREE) == {}
    assert ct.is_expired(exp, now) is False and ct.is_expired(exp, datetime(2026, 10, 25, 10, 0, tzinfo=UTC))
    assert ct.is_expired("soon") is None
    assert len(set(ct.INERT.values())) == ct.SLOTS
    assert ct.resolve_interfaces(IFS, [{"name": "fw_if", "value": "GigabitEthernet5"}]) == [
        "GigabitEthernet3",
        "GigabitEthernet5",
    ]


def test_quarantine_baseline_goes_on_top_and_comes_out_exactly() -> None:
    data = user_data()
    new = baselined(["198.51.100.53/32"])
    assert names_of(new) == [*ct.QUARANTINE_RULES, "allow-web", "deny-guest"]
    assert [fw.leaf_value(s["sequenceId"]) for s in new["sequences"]] == [str(i) for i in range(1, 7)]
    assert {**new["sequences"][4], "sequenceId": None} == {**data["sequences"][0], "sequenceId": None}
    words = fw.describe_rules(new, {SGT_ID: ct.QUARANTINE_OBJECT})
    assert words[2] == "3 mcp-quarantine-out: source SGT mcp-quarantine-sgt -> drop, log"
    assert words[0] == (
        "1 mcp-quarantine-allow-out: destination 198.51.100.53/32; source SGT mcp-quarantine-sgt -> pass"
    )
    assert ct.baseline_state(new) == {"quarantine": True}
    assert ct.baseline_state(data) == {"quarantine": False}
    back, removed = ct.without_baseline(new)
    assert back == data and len(removed) == 4


def test_trustsec_readiness() -> None:
    recorded = {
        "environment": fixture("device_environmentdata_br1")["data"],
        "sgt_map": [],
        "sxp": [],
        "inline": [],
    }
    out = tc.readiness(recorded, [])
    assert out["ready"] is False and len(out["missing"]) == 2
    env = copy.deepcopy(recorded["environment"])
    env[0]["status"] = "env-download-complete"
    sxp = [{"peer-ip": "198.51.100.35", "listener-state": "On"}]
    ok = tc.readiness({**recorded, "environment": env, "sxp": sxp}, [])
    assert ok["ready"] is True and ok["sxp_up"] == 1 and "missing" not in ok


def test_remediation_problems() -> None:
    assert ct.remediation_problems(["198.51.100.0/24"]) == []
    assert "everything" in ct.remediation_problems(["0.0.0.0/0"])[0]
    assert "not an IPv4 prefix" in ct.remediation_problems(["198.51.100.1/24"])[0]


def test_quarantine_tag_problems() -> None:
    ok = [{"sgtName": fw.g("Quarantined_Systems"), "tag": fw.g("255")}]
    assert ct.quarantine_tag_problems(ok) == []
    assert ct.quarantine_tag_problems([{"tag": fw.g("3")}]) == []
    assert ct.quarantine_tag_problems([{"tag": fw.g("65519")}]) == []
    for bad in ("0", "1", "2", "65520", "65535", "x"):
        assert ct.quarantine_tag_problems([{"tag": fw.g(bad)}]), bad


# --- catsdwan_set_containment_baseline (quarantine SGT only) -------------------------------------


async def test_baseline_preview_and_confirm(api: respx.MockRouter) -> None:
    r = mock_pg(api, ngfw=[ngfw_row()], sgts=[])
    mock_trustsec(api)
    args = {
        "group": "mcp-w8-pg",
        "quarantine_sgt": "Quarantined_Systems:255",
        "remediation": ["198.51.100.53/32"],
    }
    out = await preview("catsdwan_set_containment_baseline", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["objects"][ct.QUARANTINE_OBJECT] == {"before": None, "after": ["Quarantined_Systems:255"]}
    assert "mcp-contain-slots" not in json.dumps(p)  # the prefix-list slot design is gone (#126)
    (pol,) = p["policies"]
    assert pol["after"][2] == "3 mcp-quarantine-out: source SGT mcp-quarantine-sgt -> drop, log"
    assert pol["after"][4].startswith("5 allow-web") and pol["before"][0].startswith("1 allow-web")
    assert out["blast_radius"] == 2
    assert p["trustsec"]["hub1"]["ready"] is False
    assert any("TrustSec is not ready on hub1" in w for w in p["warnings"])
    assert not r["ngfw_put"].called and not r["sgt_post"].called
    done = await confirmed("catsdwan_set_containment_baseline", args)
    sgt_body = json.loads(r["sgt_post"].calls.last.request.content)
    assert sgt_body["data"]["entries"] == [{"sgtName": fw.g("Quarantined_Systems"), "tag": fw.g("255")}]
    seqs = json.loads(r["ngfw_put"].calls.last.request.content)["data"]["sequences"]
    assert seqs[2]["match"]["entries"] == [{"sourceSecurityGroup": fw.ref([SGT_ID])}]
    assert [fw.leaf_value(s["sequenceName"]) for s in seqs[4:]] == ["allow-web", "deny-guest"]
    assert "catsdwan_deploy_policy_group" in done["result"]["next"]


async def test_baseline_in_place_says_so(api: respx.MockRouter) -> None:
    r = mock_pg(api, ngfw=[ngfw_row(baselined(["198.51.100.53/32"]))])
    mock_trustsec(api)
    args = {
        "group": "mcp-w8-pg",
        "quarantine_sgt": "Quarantined_Systems:255",
        "remediation": ["198.51.100.53/32"],
    }
    out = await preview("catsdwan_set_containment_baseline", args)
    assert "in place" in out["action"] and out["preview"]["policies"] == [] and not out.get("blockers")
    await confirmed("catsdwan_set_containment_baseline", args)
    assert not r["ngfw_put"].called and not r["sgt_post"].called


async def test_baseline_blockers_and_remove(api: respx.MockRouter) -> None:
    mock_pg(api, ngfw=[])
    mock_trustsec(api)
    out = await preview(
        "catsdwan_set_containment_baseline",
        {"group": "mcp-w8-pg", "quarantine_sgt": "255", "remediation": ["0.0.0.0/0"]},
    )
    b = " | ".join(out["blockers"])
    assert "has no NGFW policy" in b and "everything" in b
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        with pytest.raises(ToolError, match="catsdwan_set_containment_acl"):
            await c.call_tool("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg"})
    async with Client(make_server(mcp_enable_writes=True)) as c:
        off = (
            await c.call_tool("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "remove": True})
        ).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in x for x in off["blockers"])


async def test_baseline_remove_takes_the_rules_out(api: respx.MockRouter) -> None:
    r = mock_pg(api)
    await confirmed("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "remove": True})
    assert json.loads(r["ngfw_put"].calls.last.request.content)["data"] == user_data()


@pytest.mark.parametrize("tag", ["0", "2", "65535", "Unknown:0"])
async def test_baseline_refuses_a_reserved_quarantine_tag(api: respx.MockRouter, tag: str) -> None:
    mock_pg(api, ngfw=[ngfw_row()], sgts=[])
    mock_trustsec(api)
    out = await preview("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "quarantine_sgt": tag})
    assert any("can't be the Quarantine SGT" in b for b in out["blockers"]), out.get("blockers")


# --- catsdwan_set_containment_acl ----------------------------------------------------------------


async def test_acl_preview_and_confirm(api: respx.MockRouter) -> None:
    r = mock_cfg(api, text=cli_text(acl=False), var_body=unset_slots())
    args = {"group": "mcp-test", "interfaces": IFS, "remediation": REM}
    out = await preview("catsdwan_set_containment_acl", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["cli_addon"] == {"profile": "mcp-test-cli", "parcel": "mcp-test-config"}
    assert "+ 111 deny ip host {{mcp_contain_1}} any" in p["cli_changes"]
    assert "+interface {{fw_if}}" in p["cli_changes"] and not any(c.startswith("-") for c in p["cli_changes"])
    assert p["reaches"] == [{"group": "mcp-test", "devices": ["br1", "br2"]}] and out["blast_radius"] == 2
    assert p["neutral_values"]["mcp_contain_1"] == "192.0.2.241"
    assert "not_yet_proven" in p and "catsdwan_deploy_config_group" in p["next"]
    assert not r["cli_put"].called and not r["vars_put"].called
    _moving(api, unset_slots(), lambda b: b, after=99)  # values read back unchanged for the others
    done = await confirmed("catsdwan_set_containment_acl", args)
    put = json.loads(r["cli_put"].calls.last.request.content)
    assert put["name"] == "mcp-test-config" and put["data"]["config"] == cli_text()
    assert (
        "<redacted>" in put["data"]["config"]
    )  # the stored secret hash goes back as read, never masked text
    values = put_values(r["vars_put"])
    assert sorted(values) == [BR1, BR2]
    assert values[BR1]["mcp_contain_2"] == "192.0.2.242" and values[BR1]["mcp_contain_2_note"] == ct.NOTE_FREE
    assert values[BR1]["fw_if"] == "GigabitEthernet5"  # every other variable written back as it was
    assert done["result"]["neutral_filled"] == {"mcp-test": ["br1", "br2"]}
    assert not r["deploy"].called


async def test_acl_in_place_says_so(api: respx.MockRouter) -> None:
    r = mock_cfg(api)
    args = {"group": "mcp-test", "interfaces": IFS, "remediation": REM}
    out = await preview("catsdwan_set_containment_acl", args)
    assert "in place" in out["action"] and out["blast_radius"] == 0
    await confirmed("catsdwan_set_containment_acl", args)
    assert not r["cli_put"].called and not r["vars_put"].called


async def test_acl_in_place_fills_a_device_without_values(api: respx.MockRouter) -> None:
    """A device that joined the group after the ACL (or a fill that did not finish) lists the slot
    variables with no value: running the tool again fills them, and only them."""
    body = l65_variables(**{BR2: dict.fromkeys(ct.neutral())})
    r = mock_cfg(api, var_body=body)
    args = {"group": "mcp-test", "interfaces": IFS, "remediation": REM}
    out = await preview("catsdwan_set_containment_acl", args)
    assert "fill the neutral slot values of br2" in out["action"] and out["blast_radius"] == 1
    assert out["preview"]["unset_values"] == ["br2"] and not out["preview"]["cli_changes"]
    done = await confirmed("catsdwan_set_containment_acl", args)
    assert not r["cli_put"].called
    values = put_values(r["vars_put"])
    assert sorted(values) == [BR2] and values[BR2]["mcp_contain_4_note"] == ct.NOTE_FREE
    assert done["result"]["neutral_filled"] == {"mcp-test": ["br2"]}


async def test_acl_blockers(api: respx.MockRouter) -> None:
    mock_cfg(api, text=cli_text(acl=False))
    out = await preview(
        "catsdwan_set_containment_acl",
        {"group": "mcp-test", "interfaces": ["{{nope}}"], "remediation": ["0.0.0.0/0"]},
    )
    b = " | ".join(out["blockers"])
    assert "no variable nope" in b and "everything" in b
    hub = await preview("catsdwan_set_containment_acl", {"group": "mcp-w8-hub", "interfaces": ["Gi3"]})
    assert any("has no CLI add-on" in x for x in hub["blockers"])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        off = (
            await c.call_tool("catsdwan_set_containment_acl", {"group": "mcp-test", "interfaces": IFS})
        ).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in x for x in off["blockers"])


async def test_acl_remove_waits_for_held_slots(api: respx.MockRouter) -> None:
    r = mock_cfg(api, var_body=l65_variables(**{BR1: {"mcp_contain_1": HOST}}))
    out = await preview("catsdwan_set_containment_acl", {"group": "mcp-test", "remove": True})
    assert any("release them first" in b and HOST in b for b in out["blockers"])
    api.get(VARS).respond(json=l65_variables())
    await confirmed("catsdwan_set_containment_acl", {"group": "mcp-test", "remove": True})
    put = json.loads(r["cli_put"].calls.last.request.content)
    assert put["data"]["config"] == cli_text(acl=False) and not r["vars_put"].called


async def test_acl_fill_stops_when_a_device_outside_the_write_moved(api: respx.MockRouter) -> None:
    body = l65_variables()
    for d in body["devices"]:
        if d["device-id"] == BR1:
            for v in d["variables"]:
                if v["name"].startswith("mcp_contain"):
                    v.pop("value")
    r = mock_cfg(api, text=cli_text(acl=False), var_body=body)

    def move_br2(b: dict[str, Any]) -> dict[str, Any]:
        for d in b["devices"]:
            if d["device-id"] == BR2:
                d["variables"][0]["value"] = "10.0.0.99"
        return b

    _moving(api, body, move_br2, after=3)  # preview, confirm's preview, apply's read, then the check
    args = {"group": "mcp-test", "interfaces": IFS}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool("catsdwan_set_containment_acl", args)).structured_content
        assert not first.get("blockers"), first.get("blockers")
        with pytest.raises(ToolError, match="differ from before: stopped"):
            await c.call_tool("catsdwan_set_containment_acl", {**args, "confirm": first["confirm"]})
    assert sorted(put_values(r["vars_put"])) == [BR1] and not r["deploy"].called


# --- catsdwan_contain_at_edge --------------------------------------------------------------------


async def test_contain_at_edge_changes_one_device_only(api: respx.MockRouter) -> None:
    r = mock_cfg(api)
    args = {"ip": HOST, "reason": "INC-1 beaconing", "hours": 12}
    out = await preview("catsdwan_contain_at_edge", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["device"]["host"] == "br1" and p["where"]["vpn"] == "10" and out["blast_radius"] == 1
    assert p["group"] == "mcp-test"
    assert p["slot"] == {
        "variable": "mcp_contain_1",
        "from": "192.0.2.241",
        "to": HOST,
        "already_held": False,
    }
    assert p["record"]["variable"] == "mcp_contain_1_note" and p["record"]["from"] == ct.NOTE_FREE
    assert p["record"]["to"].startswith(f"mcp-contain until {p['expires']} INC-1 beaconing")
    assert p["acl_entries"][1] == f"111 deny ip host {HOST} any"
    assert p["applied_on"] == {
        "acl": "mcp-contain",
        "direction": "in",
        "interfaces": ["GigabitEthernet3", "GigabitEthernet5"],
    }
    assert p["proof"]["devices_changed"] == ["br1"] and p["proof"]["group_parcels_changed"] == []
    assert list(p["proof"]["other_devices"]) == ["br2"]
    assert p["deployed_to"] == ["br1"] and p["undo"] == f"catsdwan_release_at_edge(ip='{HOST}')"
    assert not r["vars_put"].called and not r["deploy"].called
    done = await confirmed("catsdwan_contain_at_edge", args)
    values = put_values(r["vars_put"])
    assert list(values) == [BR1]  # this device only
    before = {v["name"]: v.get("value") for v in l65_variables()["devices"][0]["variables"]}
    assert values[BR1] == {**before, "mcp_contain_1": HOST, "mcp_contain_1_note": p["record"]["to"]}
    assert json.loads(r["deploy"].calls.last.request.content) == {"devices": [{"id": BR1}]}
    assert not r["cli_put"].called  # no parcel of the group changes
    res = done["result"]
    assert res["edge"] == "br1" and res["slot"] == "mcp_contain_1" and res["deploy"]["outcome"] == "success"
    assert res["audit"]["manager"][0]["message"] == "Deploy config group mcp-test to br1"
    assert "applied" in res["audit"]["mcp"] and "show ip access-lists mcp-contain" in res["verify"]


async def test_contain_at_edge_stops_before_deploy_when_another_device_moved(api: respx.MockRouter) -> None:
    r = mock_cfg(api)

    def move_br2(b: dict[str, Any]) -> dict[str, Any]:
        for d in b["devices"]:
            if d["device-id"] == BR2:
                for v in d["variables"]:
                    if v["name"] == "mcp_contain_2":
                        v["value"] = "10.61.201.50"
        return b

    _moving(api, l65_variables(), move_br2, after=2)
    args = {"ip": HOST, "reason": "INC-1"}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool("catsdwan_contain_at_edge", args)).structured_content
        with pytest.raises(ToolError, match="nothing was deployed"):
            await c.call_tool("catsdwan_contain_at_edge", {**args, "confirm": first["confirm"]})
    assert r["vars_put"].called and not r["deploy"].called


async def test_contain_again_renews_the_note_in_the_same_slot(api: respx.MockRouter) -> None:
    held = {BR1: {"mcp_contain_1": HOST, "mcp_contain_1_note": "mcp-contain until 2026-10-01T00:00Z old"}}
    r = mock_cfg(api, var_body=l65_variables(**held))
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "INC-1", "deploy": False})
    p = out["preview"]
    assert p["slot"]["already_held"] is True and p["record"]["from"].endswith("old")
    assert out["blast_radius"] == 0 and p["deployed_to"] == []
    await confirmed("catsdwan_contain_at_edge", {"ip": HOST, "reason": "INC-1", "deploy": False})
    assert put_values(r["vars_put"])[BR1]["mcp_contain_1"] == HOST and not r["deploy"].called


async def test_contain_at_edge_blockers(api: respx.MockRouter) -> None:
    mock_cfg(api, text=cli_text(acl=False))
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any(
        "no standing containment ACL" in b and "catsdwan_set_containment_acl" in b for b in out["blockers"]
    )
    full = {s: f"10.61.200.{i}" for i, s in enumerate(ct.SLOT_VARS, start=20)}
    api.get(CLI_URL).respond(json=cli_parcel(cli_text()))
    api.get(VARS).respond(json=l65_variables(**{BR1: full}))
    busy = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("all 4 slots of br1" in b for b in busy["blockers"])
    api.get(VARS).respond(json=l65_variables(**{BR2: {"mcp_contain_3": HOST}}))
    elsewhere = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("already contained at br2" in b for b in elsewhere["blockers"])
    api.get(VARS).respond(json=l65_variables(**{BR1: {"mcp_contain_3": None, "mcp_contain_3_note": None}}))
    unset = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("mcp_contain_3, mcp_contain_3_note" in b and "fills them" in b for b in unset["blockers"])
    api.get(VARS).respond(json=l65_variables())
    only_gi5 = ct.with_acl(cli_text(acl=False), ct.acl_block([], ["{{fw_if}}"]))
    api.get(CLI_URL).respond(json=cli_parcel(only_gi5))
    wrong_if = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("sits on br1 GigabitEthernet3" in b and "GigabitEthernet5" in b for b in wrong_if["blockers"])
    mgmt = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x", "edge": "br1", "vpn": 512})
    assert any("transport, management or internal VPN" in b for b in mgmt["blockers"])
    nowhere = await preview("catsdwan_contain_at_edge", {"ip": "10.61.99.9", "reason": "x"})
    assert any("in no service-VPN ARP table" in b for b in nowhere["blockers"])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        off = (await c.call_tool("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in b for b in off["blockers"])


async def test_contain_a_routed_host_behind_the_branch_firewall(api: respx.MockRouter) -> None:
    """alice (10.61.220.10) sits behind br1-ftd, so br1 has no ARP entry for her: edge and VPN are given,
    and the preview says her traffic must enter on the ACL's interfaces (Gi5 = {{fw_if}} on br1)."""
    mock_cfg(api, br1_up="False")
    out = await preview(
        "catsdwan_contain_at_edge", {"ip": "10.61.220.10", "reason": "x", "edge": "br1", "vpn": 10}
    )
    assert not out.get("blockers"), out.get("blockers")
    w = " | ".join(out["preview"]["warnings"])
    assert "not located on an interface" in w and "GigabitEthernet5" in w
    assert "not up to date with configuration group mcp-test" in w


async def test_contain_at_edge_needs_a_configuration_group(api: respx.MockRouter) -> None:
    mock_cfg(api)
    api.get(f"{CG}/{W8_TEST_GROUP}/device/associate").respond(json={"devices": []})
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("is in no configuration group" in b for b in out["blockers"])


# --- catsdwan_release_at_edge --------------------------------------------------------------------


async def test_release_resets_exactly_its_slot(api: respx.MockRouter) -> None:
    rec = "mcp-contain until 2099-01-01T00:00Z INC-1"
    held = {BR1: {"mcp_contain_1": HOST, "mcp_contain_1_note": rec, "mcp_contain_2": "10.61.200.11"}}
    r = mock_cfg(api, var_body=l65_variables(**held))
    out = await preview("catsdwan_release_at_edge", {"ip": HOST})
    assert not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["slots"] == [
        {
            "device": "br1",
            "group": "mcp-test",
            "slots": {
                "mcp_contain_1": {"from": HOST, "to": "192.0.2.241", "record": rec, "record_to": ct.NOTE_FREE}
            },
        }
    ]
    assert p["deployed_to"] == ["br1"] and out["blast_radius"] == 1
    done = await confirmed("catsdwan_release_at_edge", {"ip": HOST})
    values = put_values(r["vars_put"])
    assert list(values) == [BR1]
    assert values[BR1]["mcp_contain_1"] == "192.0.2.241" and values[BR1]["mcp_contain_1_note"] == ct.NOTE_FREE
    assert values[BR1]["mcp_contain_2"] == "10.61.200.11"
    assert json.loads(r["deploy"].calls.last.request.content) == {"devices": [{"id": BR1}]}
    assert done["result"]["released"] is True and done["result"]["edges"] == ["br1"]


async def test_release_of_a_host_not_contained_changes_nothing(api: respx.MockRouter) -> None:
    r = mock_cfg(api)
    out = await preview("catsdwan_release_at_edge", {"ip": HOST})
    assert out["preview"]["was_contained"] is False and "nothing to change" in out["action"]
    done = await confirmed("catsdwan_release_at_edge", {"ip": HOST})
    assert done["result"]["released"] is False
    assert not r["vars_put"].called and not r["deploy"].called


async def test_release_stops_before_deploy_when_another_device_moved(api: respx.MockRouter) -> None:
    held = {BR1: {"mcp_contain_1": HOST}}
    r = mock_cfg(api, var_body=l65_variables(**held))

    def move_br2(b: dict[str, Any]) -> dict[str, Any]:
        for d in b["devices"]:
            if d["device-id"] == BR2:
                d["variables"][-1]["value"] = "changed"
        return b

    _moving(api, l65_variables(**held), move_br2, after=2)  # preview, confirm's preview, then the check
    args = {"ip": HOST}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool("catsdwan_release_at_edge", args)).structured_content
        assert not first.get("blockers"), first.get("blockers")
        with pytest.raises(ToolError, match="nothing was deployed"):
            await c.call_tool("catsdwan_release_at_edge", {**args, "confirm": first["confirm"]})
    assert r["vars_put"].called and not r["deploy"].called


# --- catsdwan_containment_status -----------------------------------------------------------------


async def test_status_lists_slots_acl_and_baseline(api: respx.MockRouter) -> None:
    held = {
        BR1: {"mcp_contain_1": HOST, "mcp_contain_1_note": "mcp-contain until 2099-01-01T00:00Z INC-1"},
        BR2: {
            "mcp_contain_2": "10.61.201.12",
            "mcp_contain_2_note": "mcp-contain until 2020-01-01T00:00Z old",
        },
    }
    mock_cfg(api, var_body=l65_variables(**held), br1_up="False")
    mock_pg(api)
    mock_cfg(api, var_body=l65_variables(**held), br1_up="False")  # mock_pg's config-group list is replaced
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_containment_status", {})).structured_content
    rows = {c["ip"]: c for c in out["contained"]}
    assert rows[HOST]["device"] == "br1" and rows[HOST]["slot"] == "mcp_contain_1"
    assert rows[HOST]["expired"] is False and rows[HOST]["reason"] == "INC-1"
    assert (
        rows[HOST]["deployed"] is False and rows[HOST]["release"] == f"catsdwan_release_at_edge(ip='{HOST}')"
    )
    assert rows["10.61.201.12"]["expired"] is True and out["expired"] == ["10.61.201.12"]
    acl = {e["group"]: e for e in out["edge_acl"]}
    assert acl["mcp-test"]["acl"] == {"interfaces": IFS, "remediation": REM, "intact": True}
    assert acl["mcp-test"]["devices"]["br1"] == {
        "applied_on": ["GigabitEthernet3", "GigabitEthernet5"],
        "free_slots": 3,
    }
    assert acl["mcp-test"]["devices"]["br2"]["applied_on"] == ["GigabitEthernet3", "Loopback210"]
    assert acl["mcp-w8-hub"]["cli_addon"] is None and acl["mcp-w8-hub"]["acl"].startswith("none")
    (base,) = out["baseline"]
    assert base["policies"][0]["quarantine"] is True
    assert base["objects"][ct.QUARANTINE_OBJECT] == ["Quarantined_Systems:255"]


@pytest.mark.parametrize(
    "tool",
    [
        "catsdwan_set_containment_baseline",
        "catsdwan_set_containment_acl",
        "catsdwan_contain_at_edge",
        "catsdwan_release_at_edge",
    ],
)
async def test_writes_hidden_without_writes(tool: str) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert tool not in names and "catsdwan_containment_status" in names


def _moving(api: respx.MockRouter, first: dict[str, Any], change: Any, after: int) -> None:
    """mcp-test's device variables as `first` for the first `after` reads, then `change(copy)`."""
    reads: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        reads.append(request)
        if len(reads) <= after:
            return httpx.Response(200, json=first)
        return httpx.Response(200, json=change(copy.deepcopy(first)))

    api.get(VARS).mock(side_effect=answer)
