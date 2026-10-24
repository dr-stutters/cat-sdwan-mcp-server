"""W45: WAN-edge containment in two paths: the standing baseline (ISE quarantine SGT rules + per-device
edge slots), the no-ISE fallback scoped to one edge (catsdwan_contain_at_edge / catsdwan_release_at_edge),
the list, and the prompt catsdwan_contain_host.

Recorded (20.18.3.1, read only): the inventory, hub1's ARP table (host 10.61.100.10 learned on Gi3 in VPN
10), the policy-group device association, the security-data-ip-prefix and security-scalablegrouptag POST
schemas (the prefix schema takes `{optionType: variable, value: '{{name}}'}` per entry: the slots rest on
that), the ISE SGT answer without ISE, the edge TrustSec tables without ISE and the audit log row shape. Not
recorded: the embedded-security / NGFW / security-policy parcels (W47's shapes, Cisco's published models)
and the policy-group device-variables body (the config-group one, same API family); ids are documentation
UUIDs.
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

from .conftest import fixture, make_server
from .test_edgefirewall import ES, NG, PGID, PGS, PO, POL, ZIN, ZOUT, listed, mock_manager, parcel
from .test_findhost import mock_edges
from .test_inventory import mock_inventory

HUB1 = "REDACTED-17"
BR1 = "REDACTED-16"
HOST = "10.61.100.10"
SLOTS_ID = "00000000-0000-4000-8000-00000000e001"
SGT_ID = "00000000-0000-4000-8000-00000000e002"
REC_ID = "00000000-0000-4000-8000-00000000e003"
STATUS = "/dataservice/device/action/status"
VARS = f"{PGS}/{PGID}/device/variables"
RULES = [
    {"name": "allow-web", "action": "inspect", "protocols": ["tcp"]},
    {"name": "deny-guest", "action": "drop", "source_prefixes": ["192.0.2.0/24"], "log": True},
]


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


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


OTHER = "10.61.100.9/32"
UNSET = [{"name": s} for s in ct.SLOT_VARS]
REFS = {"sgt": {ct.QUARANTINE_OBJECT: SGT_ID}, "prefix": {ct.SLOT_OBJECT: SLOTS_ID}}


def baselined(remediation: list[str] | None = None, quarantine: bool = True) -> dict[str, Any]:
    rules = ct.baseline_rules(slots=True, quarantine=quarantine, remediation=remediation or [])
    return ct.with_baseline(user_data(), [ct.sequence(r, REFS) for r in rules])[0]


def slot_obj() -> dict[str, Any]:
    return parcel(SLOTS_ID, "security-data-ip-prefix", ct.SLOT_OBJECT, {"entries": ct.slot_entries()})


def sgt_obj(value: str = "255") -> dict[str, Any]:
    entries = [{"sgtName": fw.g("Quarantined_Systems"), "tag": fw.g(value)}]
    return parcel(SGT_ID, "security-scalablegrouptag", ct.QUARANTINE_OBJECT, {"entries": entries})


def record(
    ip: str = HOST, edge: str = "hub1", chassis: str = HUB1, expires: str = "2099-01-01T00:00Z"
) -> dict[str, Any]:
    row = parcel(
        REC_ID, "security-data-ip-prefix", ct.record_name(ip), {"entries": [{"ipPrefix": fw.g(f"{ip}/32")}]}
    )
    row["payload"]["description"] = ct.record_description(
        edge=edge,
        chassis=chassis,
        group="mcp-w8-pg",
        slot="mcp_contain_1",
        vpn="10",
        expires=expires,
        reason="INC-1",
    )
    return row


def variables(**held: dict[str, str]) -> dict[str, Any]:
    """The policy group's device variables: every slot inert unless `held` gives {chassis: {slot: value}}."""
    devices = []
    for ch in (BR1, HUB1):
        values = {**ct.INERT, **held.get(ch, {})}
        devices.append(
            {
                "device-id": ch,
                "variables": [{"name": "host_name", "value": "x"}]
                + [{"name": k, "value": v} for k, v in values.items()],
            }
        )
    return {"family": "sdwan", "devices": devices}


def mock_all(
    api: respx.MockRouter,
    *,
    ngfw: list[dict[str, Any]] | None = None,
    pairs: list[tuple[str, str]] | None = None,
    members: list[str] | None = None,
    prefixes: list[dict[str, Any]] | None = None,
    sgts: list[dict[str, Any]] | None = None,
    held: dict[str, dict[str, str]] | None = None,
    var_body: dict[str, Any] | None = None,
) -> dict[str, respx.Route]:
    mock_inventory(api)
    mock_edges(api)
    mock_manager(
        api,
        ngfw=[ngfw_row(baselined())] if ngfw is None else ngfw,
        policy=[policy_row(pairs or [(ZIN, ZOUT)])],
        members=[HUB1, BR1] if members is None else members,
    )
    api.get(f"{PO}/security-data-ip-prefix").respond(
        json=listed(*([slot_obj()] if prefixes is None else prefixes))
    )
    api.get(f"{PO}/security-scalablegrouptag").respond(json=listed(*([sgt_obj()] if sgts is None else sgts)))
    api.get("/dataservice/template/policy/ise/identity/sgt").respond(
        400, json=fixture("template_policy_ise_identity_sgt")
    )
    api.get(VARS).respond(json=var_body if var_body is not None else variables(**(held or {})))
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})
    api.get(f"{STATUS}/pt-1").respond(
        json={"data": [{"host-name": "hub1", "uuid": HUB1, "statusId": "success", "status": "Success"}]}
    )
    audit = copy.deepcopy(fixture("auditlog"))
    now = int(datetime.now(UTC).timestamp() * 1000)
    audit["data"] = [
        {
            **audit["data"][0],
            "entry_time": now + 5_000,
            "logmodule": "policy group",
            "logfeature": "deploy",
            "logmessage": "Deploy policy group mcp-w8-pg to hub1",
            "auditdetails": "[]",
        },
        audit["data"][0],
    ]
    return {
        "ngfw_put": api.put(f"{ES}/unified/ngfirewall/{NG}").respond(200),
        "deploy": api.post(f"{PGS}/{PGID}/device/deploy").respond(json={"parentTaskId": "pt-1"}),
        "vars_put": api.put(VARS).respond(json=[{"device-id": HUB1}]),
        "prefix_post": api.post(f"{PO}/security-data-ip-prefix").respond(json={"parcelId": SLOTS_ID}),
        "prefix_put": api.put(f"{PO}/security-data-ip-prefix/{REC_ID}").respond(200),
        "prefix_delete": api.delete(f"{PO}/security-data-ip-prefix/{REC_ID}").respond(200),
        "sgt_post": api.post(f"{PO}/security-scalablegrouptag").respond(json={"parcelId": SGT_ID}),
        "audit": api.post("/dataservice/auditlog").respond(json=audit),
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


# --- helpers -------------------------------------------------------------------------------------


def test_host_ip_and_record_names() -> None:
    assert ct.host_ip(" 10.61.100.10 ") == HOST
    for bad in ("10.61.100.0/24", "2001:db8::1", "printer", "0.0.0.0", "224.0.0.5", "192.0.2.242"):
        with pytest.raises(ValueError):
            ct.host_ip(bad)
    assert ct.record_name(HOST) == "mcp-contain-10-61-100-10" and len(ct.record_name("255.255.255.255")) <= 32
    assert ct.record_ip("mcp-contain-10-61-100-10") == HOST
    assert ct.record_ip(ct.SLOT_OBJECT) is None and ct.record_ip("mcp-contain-10-61-100-10-out") is None


def test_record_description_round_trip_and_expiry() -> None:
    now = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    exp = ct.expiry(24, now)
    assert exp == "2026-10-25T10:00Z"
    desc = ct.record_description(
        edge="hub1",
        chassis=HUB1,
        group="g",
        slot="mcp_contain_2",
        vpn="10",
        expires=exp,
        reason="INC-1; a=b c",
    )
    rec = ct.parse_record(desc)
    assert rec == {
        "edge": "hub1", "chassis": HUB1, "group": "g", "slot": "mcp_contain_2", "vpn": "10",
        "expires": exp, "reason": "INC-1, a=b c",
    }  # fmt: skip
    assert ct.is_expired(exp, now) is False and ct.is_expired(exp, datetime(2026, 10, 25, 10, 0, tzinfo=UTC))
    assert ct.parse_record("branch firewall") == {} and ct.is_expired("soon") is None


def test_baseline_goes_on_top_and_comes_out_exactly() -> None:
    data = user_data()
    new = baselined(["198.51.100.53/32"])
    assert names_of(new) == [*ct.SLOT_RULES, *ct.QUARANTINE_RULES, "allow-web", "deny-guest"]
    assert [fw.leaf_value(s["sequenceId"]) for s in new["sequences"]] == [str(i) for i in range(1, 11)]
    assert {**new["sequences"][8], "sequenceId": None} == {**data["sequences"][0], "sequenceId": None}
    words = fw.describe_rules(new, {SLOTS_ID: ct.SLOT_OBJECT, SGT_ID: ct.QUARANTINE_OBJECT})
    assert words[2] == "3 mcp-contain-slots-out: source list mcp-contain-slots -> drop, log"
    assert words[6] == "7 mcp-quarantine-out: source SGT mcp-quarantine-sgt -> drop, log"
    assert words[4] == (
        "5 mcp-quarantine-allow-out: destination 198.51.100.53/32; source SGT mcp-quarantine-sgt -> pass"
    )
    assert ct.baseline_state(new) == {"edge_slots": True, "quarantine": True}
    assert ct.baseline_state(data) == {"edge_slots": False, "quarantine": False}
    back, removed = ct.without_baseline(new)
    assert back == data and len(removed) == 8
    # A user rule that merely starts with mcp- is not ours.
    own = fw.ngfw_body("x", "", "drop", [{"name": "mcp-contain-me", "action": "drop"}], {})["data"]
    assert ct.without_baseline(own)[1] == []


def test_slot_and_record_objects_fit_the_recorded_schema() -> None:
    schema = fw.request_schema(
        fixture("v1_feature_profile_policy_object_security_data_ip_prefix_schema_post")
    )
    slots = fw.object_body(ct.SLOT_OBJECT, "slots", ct.slot_entries())
    assert fw.schema_problems(schema, slots) == []
    rec = fw.object_body(ct.record_name(HOST), "mcp-contain; ...", [{"ipPrefix": fw.g(f"{HOST}/32")}])
    assert fw.schema_problems(schema, rec) == []
    assert ct.is_slot_object(slots["data"]) and not ct.is_slot_object(rec["data"])
    assert len(set(ct.INERT.values())) == ct.SLOTS


def test_slots() -> None:
    values = {
        "mcp_contain_1": "10.61.100.11/32",
        "mcp_contain_2": ct.INERT["mcp_contain_2"],
        "mcp_contain_3": None,
    }
    assert ct.pick_slot(values, HOST) == ("mcp_contain_2", False)
    assert ct.pick_slot(values, "10.61.100.11") == ("mcp_contain_1", True)
    assert ct.contained_at(values) == {"mcp_contain_1": "10.61.100.11"}
    full = {s: f"10.61.100.{i}/32" for i, s in enumerate(ct.SLOT_VARS, start=20)}
    assert ct.pick_slot(full, HOST) == (None, False)


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


# --- catsdwan_set_containment_baseline -----------------------------------------------------------


async def test_baseline_preview_and_confirm(api: respx.MockRouter) -> None:
    r = mock_all(api, ngfw=[ngfw_row()], prefixes=[], sgts=[], var_body={
        "family": "sdwan",
        "devices": [
            {"device-id": HUB1, "variables": [{"name": "host_name", "value": "hub1"}, *UNSET]},
            {"device-id": BR1, "variables": [{"name": "mcp_contain_1", "value": OTHER}, *UNSET[1:]]},
        ],
    })  # fmt: skip
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
    assert p["objects"][ct.SLOT_OBJECT]["state"] == "created"
    (pol,) = p["policies"]
    assert pol["after"][2] == "3 mcp-contain-slots-out: source list mcp-contain-slots -> drop, log"
    assert pol["after"][8].startswith("9 allow-web") and pol["before"][0].startswith("1 allow-web")
    assert (
        sorted(r for g in p["reaches"] for r in g["devices"]) == ["br1", "hub1"] and out["blast_radius"] == 2
    )
    assert p["trustsec"]["hub1"]["ready"] is False
    assert any("TrustSec is not ready on hub1" in w for w in p["warnings"])
    assert "TrustSec propagation" in p["needs"]
    assert not r["ngfw_put"].called and not r["sgt_post"].called
    done = await confirmed("catsdwan_set_containment_baseline", args)
    sgt_body = json.loads(r["sgt_post"].calls.last.request.content)
    assert sgt_body["data"]["entries"] == [{"sgtName": fw.g("Quarantined_Systems"), "tag": fw.g("255")}]
    slot_body = json.loads(r["prefix_post"].calls.last.request.content)
    assert slot_body["name"] == ct.SLOT_OBJECT and slot_body["data"]["entries"] == ct.slot_entries()
    seqs = json.loads(r["ngfw_put"].calls.last.request.content)["data"]["sequences"]
    assert seqs[2]["match"]["entries"] == [{"sourceDataPrefixList": fw.ref([SLOTS_ID])}]
    assert seqs[6]["match"]["entries"] == [{"sourceSecurityGroup": fw.ref([SGT_ID])}]
    assert [fw.leaf_value(s["sequenceName"]) for s in seqs[8:]] == ["allow-web", "deny-guest"]
    # Inert values only where a slot is unset; br1's held slot is left alone.
    vars_body = json.loads(r["vars_put"].calls.last.request.content)
    by_dev = {
        d["device-id"]: {v["name"]: v.get("value") for v in d["variables"]} for d in vars_body["devices"]
    }
    assert by_dev[HUB1] == {"host_name": "hub1", **ct.INERT}
    assert by_dev[BR1]["mcp_contain_1"] == OTHER and by_dev[BR1]["mcp_contain_2"] == ct.INERT["mcp_contain_2"]
    assert done["result"]["inert_slots_filled"] == {"mcp-w8-pg": ["hub1", "br1"]}
    assert not r["deploy"].called and "catsdwan_deploy_policy_group" in done["result"]["next"]


async def test_baseline_in_place_says_so(api: respx.MockRouter) -> None:
    r = mock_all(api, ngfw=[ngfw_row(baselined(["198.51.100.53/32"]))])
    mock_trustsec(api)
    args = {
        "group": "mcp-w8-pg",
        "quarantine_sgt": "Quarantined_Systems:255",
        "remediation": ["198.51.100.53/32"],
    }
    out = await preview("catsdwan_set_containment_baseline", args)
    assert "in place" in out["action"] and out["preview"]["policies"] == [] and not out.get("blockers")
    await confirmed("catsdwan_set_containment_baseline", args)
    assert not r["ngfw_put"].called and not r["sgt_post"].called and not r["vars_put"].called


async def test_baseline_blockers(api: respx.MockRouter) -> None:
    theirs = parcel(
        SLOTS_ID, "security-data-ip-prefix", ct.SLOT_OBJECT, {"entries": [{"ipPrefix": fw.g("192.0.2.0/24")}]}
    )
    mock_all(api, ngfw=[], prefixes=[theirs])
    out = await preview(
        "catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "remediation": ["0.0.0.0/0"]}
    )
    b = " | ".join(out["blockers"])
    assert "has no NGFW policy" in b and "not this tool's" in b and "everything" in b
    async with Client(make_server(mcp_enable_writes=True)) as c:
        off = (
            await c.call_tool("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg"})
        ).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in x for x in off["blockers"])


async def test_baseline_remove_waits_for_held_slots(api: respx.MockRouter) -> None:
    r = mock_all(api, held={HUB1: {"mcp_contain_1": f"{HOST}/32"}})
    out = await preview("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "remove": True})
    assert any("release them first" in b and HOST in b for b in out["blockers"])
    api.get(VARS).respond(json=variables())
    await confirmed("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "remove": True})
    put = json.loads(r["ngfw_put"].calls.last.request.content)
    assert put["data"] == user_data() and not r["vars_put"].called


async def test_baseline_never_drops_held_slots_or_quarantine_silently(api: respx.MockRouter) -> None:
    mock_all(api, held={HUB1: {"mcp_contain_1": f"{HOST}/32"}})
    mock_trustsec(api)
    args = {"group": "mcp-w8-pg", "edge_slots": False, "quarantine_sgt": "Quarantined_Systems:255"}
    no_slots = await preview("catsdwan_set_containment_baseline", args)
    assert any("takes the slot rules out" in b for b in no_slots["blockers"])
    only_slots = await preview("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg"})
    assert any("no quarantine_sgt given" in w for w in only_slots["preview"]["warnings"])
    assert not only_slots.get("blockers")


# --- catsdwan_contain_at_edge --------------------------------------------------------------------


async def test_contain_at_edge_changes_one_device_only(api: respx.MockRouter) -> None:
    r = mock_all(api)
    args = {"ip": HOST, "reason": "INC-1 beaconing", "hours": 12}
    out = await preview("catsdwan_contain_at_edge", args)
    assert out["status"] == "preview" and not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["device"]["host"] == "hub1" and p["where"]["vpn"] == "10" and out["blast_radius"] == 1
    assert p["slot"] == {
        "variable": "mcp_contain_1",
        "from": "192.0.2.241/32",
        "to": f"{HOST}/32",
        "already_held": False,
    }
    assert p["proof"]["devices_changed"] == ["hub1"] and p["proof"]["group_parcels_changed"] == []
    assert list(p["proof"]["other_devices"]) == ["br1"]
    assert (
        p["record"]["name"] == "mcp-contain-10-61-100-10"
        and "slot=mcp_contain_1" in p["record"]["description"]
    )
    assert p["enforced_by"][0]["ngfw_policy"] == "br-fw" and p["deployed_to"] == ["hub1"]
    assert p["undo"] == f"catsdwan_release_at_edge(ip='{HOST}')"
    assert not r["vars_put"].called and not r["deploy"].called and not r["prefix_post"].called
    done = await confirmed("catsdwan_contain_at_edge", args)
    rec = json.loads(r["prefix_post"].calls.last.request.content)
    assert rec["name"] == "mcp-contain-10-61-100-10" and rec["data"]["entries"] == [
        {"ipPrefix": fw.g(f"{HOST}/32")}
    ]
    fields = ct.parse_record(rec["description"])
    assert fields["edge"] == "hub1" and fields["chassis"] == HUB1 and fields["reason"] == "INC-1 beaconing"
    body = json.loads(r["vars_put"].calls.last.request.content)
    assert [d["device-id"] for d in body["devices"]] == [HUB1]  # this device only
    values = {v["name"]: v.get("value") for v in body["devices"][0]["variables"]}
    assert values == {"host_name": "x", **ct.INERT, "mcp_contain_1": f"{HOST}/32"}
    assert json.loads(r["deploy"].calls.last.request.content) == {"devices": [{"id": HUB1}]}
    assert not r["ngfw_put"].called  # no parcel of the group changes
    res = done["result"]
    assert res["edge"] == "hub1" and res["slot"] == "mcp_contain_1" and res["deploy"]["outcome"] == "success"
    assert res["audit"]["manager"][0]["message"] == "Deploy policy group mcp-w8-pg to hub1"
    assert "applied" in res["audit"]["mcp"]


async def test_contain_at_edge_stops_before_deploy_when_another_device_moved(api: respx.MockRouter) -> None:
    r = mock_all(api)
    reads = []

    def answer(request: httpx.Request) -> httpx.Response:
        reads.append(request)
        moved = {BR1: {"mcp_contain_2": "10.61.100.50/32"}} if len(reads) > 2 else {}
        return httpx.Response(200, json=variables(**moved))

    api.get(VARS).mock(side_effect=answer)
    args = {"ip": HOST, "reason": "INC-1"}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool("catsdwan_contain_at_edge", args)).structured_content
        with pytest.raises(ToolError, match="nothing was deployed"):
            await c.call_tool("catsdwan_contain_at_edge", {**args, "confirm": first["confirm"]})
    assert r["vars_put"].called and not r["deploy"].called


async def test_contain_again_renews_the_record_in_the_same_slot(api: respx.MockRouter) -> None:
    r = mock_all(api, prefixes=[slot_obj(), record()], held={HUB1: {"mcp_contain_1": f"{HOST}/32"}})
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "INC-1", "deploy": False})
    p = out["preview"]
    assert p["slot"]["already_held"] is True and p["record"]["state"].startswith("replaced")
    assert out["blast_radius"] == 0 and p["deployed_to"] == []
    await confirmed("catsdwan_contain_at_edge", {"ip": HOST, "reason": "INC-1", "deploy": False})
    assert r["prefix_put"].called and not r["prefix_post"].called and not r["deploy"].called


async def test_contain_at_edge_blockers(api: respx.MockRouter) -> None:
    mock_all(api, ngfw=[ngfw_row()])
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any(
        "no standing edge slot" in b and "catsdwan_set_containment_baseline" in b for b in out["blockers"]
    )
    full = {s: f"10.61.100.{i}/32" for i, s in enumerate(ct.SLOT_VARS, start=20)}
    api.get(f"{ES}/unified/ngfirewall").respond(json=listed(ngfw_row(baselined())))
    api.get(VARS).respond(json=variables(**{HUB1: full}))
    busy = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("all 4 slots of hub1" in b for b in busy["blockers"])
    api.get(VARS).respond(json=variables())
    api.get(f"{PO}/security-data-ip-prefix").respond(json=listed(slot_obj(), record(edge="br1", chassis=BR1)))
    elsewhere = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("already contained at br1" in b for b in elsewhere["blockers"])
    mgmt = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x", "edge": "hub1", "vpn": 512})
    assert any("transport, management or internal VPN" in b for b in mgmt["blockers"])
    nowhere = await preview("catsdwan_contain_at_edge", {"ip": "10.61.99.9", "reason": "x"})
    assert any("in no service-VPN ARP table" in b for b in nowhere["blockers"])
    async with Client(make_server(mcp_enable_writes=True)) as c:
        off = (await c.call_tool("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})).structured_content
    assert any("MCP_ENABLE_DANGEROUS" in b for b in off["blockers"])


async def test_contain_at_edge_needs_a_policy_group(api: respx.MockRouter) -> None:
    mock_all(api, members=[])
    out = await preview("catsdwan_contain_at_edge", {"ip": HOST, "reason": "x"})
    assert any("is in no policy group" in b for b in out["blockers"])


# --- catsdwan_release_at_edge --------------------------------------------------------------------


async def test_release_resets_exactly_its_slot_and_record(api: respx.MockRouter) -> None:
    held = {HUB1: {"mcp_contain_1": f"{HOST}/32", "mcp_contain_2": "10.61.100.11/32"}}
    r = mock_all(api, prefixes=[slot_obj(), record()], held=held)
    out = await preview("catsdwan_release_at_edge", {"ip": HOST})
    assert not out.get("blockers"), out.get("blockers")
    p = out["preview"]
    assert p["slots"] == [
        {
            "device": "hub1",
            "group": "mcp-w8-pg",
            "slots": {"mcp_contain_1": {"from": f"{HOST}/32", "to": "192.0.2.241/32"}},
        }
    ]
    assert p["record"]["record"] == "mcp-contain-10-61-100-10" and p["deployed_to"] == ["hub1"]
    assert out["blast_radius"] == 1
    done = await confirmed("catsdwan_release_at_edge", {"ip": HOST})
    body = json.loads(r["vars_put"].calls.last.request.content)
    assert [d["device-id"] for d in body["devices"]] == [HUB1]
    values = {v["name"]: v.get("value") for v in body["devices"][0]["variables"]}
    assert values["mcp_contain_1"] == "192.0.2.241/32" and values["mcp_contain_2"] == "10.61.100.11/32"
    assert r["prefix_delete"].called and json.loads(r["deploy"].calls.last.request.content) == {
        "devices": [{"id": HUB1}]
    }
    assert done["result"]["released"] is True and done["result"]["edges"] == ["hub1"]


async def test_release_of_a_host_not_contained_changes_nothing(api: respx.MockRouter) -> None:
    r = mock_all(api)
    out = await preview("catsdwan_release_at_edge", {"ip": HOST})
    assert out["preview"]["was_contained"] is False and "nothing to change" in out["action"]
    done = await confirmed("catsdwan_release_at_edge", {"ip": HOST})
    assert done["result"]["released"] is False
    assert not r["vars_put"].called and not r["deploy"].called and not r["prefix_delete"].called


async def test_release_finds_a_slot_without_a_record(api: respx.MockRouter) -> None:
    r = mock_all(api, held={HUB1: {"mcp_contain_3": f"{HOST}/32"}})
    out = await preview("catsdwan_release_at_edge", {"ip": HOST, "deploy": False})
    assert out["preview"]["record"] is None and out["blast_radius"] == 0
    await confirmed("catsdwan_release_at_edge", {"ip": HOST, "deploy": False})
    assert r["vars_put"].called and not r["prefix_delete"].called and not r["deploy"].called


# --- catsdwan_containment_status ---------------------------------------------------------------------


async def test_list_contained(api: respx.MockRouter) -> None:
    other = record("10.61.100.12", expires="2020-01-01T00:00Z")
    other["parcelId"] = "00000000-0000-4000-8000-00000000e004"
    mock_all(
        api,
        prefixes=[slot_obj(), record(), other],
        held={HUB1: {"mcp_contain_1": f"{HOST}/32", "mcp_contain_2": "10.61.100.13/32"}},
    )
    async with Client(make_server()) as c:
        out = (await c.call_tool("catsdwan_containment_status", {})).structured_content
    rows = {c["ip"]: c for c in out["contained"]}
    assert rows[HOST]["state"].startswith("enforced") and rows[HOST]["held_by"]["device"] == "hub1"
    assert (
        rows[HOST]["expired"] is False and rows[HOST]["release"] == f"catsdwan_release_at_edge(ip='{HOST}')"
    )
    assert rows["10.61.100.12"]["state"].startswith("record only") and rows["10.61.100.12"]["expired"] is True
    assert out["expired"] == ["10.61.100.12"]
    assert rows["10.61.100.13"]["state"].startswith("slot only")
    (base,) = out["baseline"]
    assert base["policies"][0]["edge_slots"] and base["policies"][0]["quarantine"]
    assert base["objects"][ct.QUARANTINE_OBJECT] == ["Quarantined_Systems:255"]


@pytest.mark.parametrize(
    "tool", ["catsdwan_set_containment_baseline", "catsdwan_contain_at_edge", "catsdwan_release_at_edge"]
)
async def test_writes_hidden_without_writes(tool: str) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert tool not in names and "catsdwan_containment_status" in names
