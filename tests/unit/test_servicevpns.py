"""#118: policy-group VPN references resolve to the LAN VPN parcel names the 20.18 controller matches.

Recorded on the lab Manager (20.18.3.1, read only, 2026-10-25, ids replaced by documentation UUIDs): the two
configuration groups after the W8 live run (mcp-test with br1, mcp-w8-hub with hub1) sharing service profile
mcp-w8-service, its LAN VPN parcel mcp-w8-vpn10 (vpnId 10, data.name Discovered_VPN_10) and the one segment
Discovered_VPN_10 (GET /dataservice/segment). The controller's refusal and the accepted target
(["mcp-w8-vpn10"]) are from the live run (#118).
"""

import json
from typing import Any

import respx
from fastmcp import Client

from cat_sdwan_mcp import serviceinsertion as si
from cat_sdwan_mcp import servicevpns as sv
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.serviceinsertion import vpn_parcels
from cat_sdwan_mcp.tools.features import controller_outcome

from .conftest import fixture, make_server, make_settings, mock_service_vpns
from .test_edgefirewall import PGID, PGS, PO, ZIN, mock_manager
from .test_inventory import mock_inventory

BR1, HUB1 = "REDACTED-16", "REDACTED-17"
SVC = "00000000-0000-4000-8000-00000000f110"
FP = "/dataservice/v1/feature-profile/sdwan"
AP = "00000000-0000-4000-8000-00000000e001"
TP = "00000000-0000-4000-8000-00000000e002"
STATUS = "/dataservice/device/action/status"
REFUSED = "Please configure the VPN's 10"


def ctx(converted: bool = True, scope: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """The context vpn_context builds, from the recorded shapes."""
    groups = fixture("v1_config_group_w8")
    lan = fixture("v1_feature_profile_service_lan_vpn_list") if converted else {"data": []}
    return {
        "index": sv.group_index(groups, {SVC: vpn_parcels(lan)}),
        "scope": {"mcp-test": ["br1"]} if scope is None else scope,
        "segments": sv.segment_rows(fixture("segment")),
        "warnings": [],
        "devices_given": True,
    }


# --- pure helpers on the recorded shapes -------------------------------------------------------------


def test_index_and_segments_read_the_recorded_shapes() -> None:
    c = ctx()
    assert c["index"]["mcp-test"] == [
        {"vpn": 10, "name": "mcp-w8-vpn10", "profile": "mcp-w8-service", "vpn_name": "Discovered_VPN_10"}
    ]
    assert c["index"]["mcp-w8-hub"][0]["name"] == "mcp-w8-vpn10"
    assert c["segments"] == [{"name": "Discovered_VPN_10", "vpn": "10"}]


def test_a_vpn_id_resolves_to_the_parcel_name() -> None:
    for ref in (10, "10"):
        r = sv.resolve_vpns([ref], ctx())
        assert r["names"] == ["mcp-w8-vpn10"] and r["ids"] == [10]
        assert not r["blockers"] and not r["warnings"]


def test_the_parcel_name_is_kept_and_other_names_are_translated() -> None:
    assert sv.resolve_vpns(["mcp-w8-vpn10"], ctx())["names"] == ["mcp-w8-vpn10"]
    # The live run's failed attempts: the parcel's data.name and the segment name (both refused by the
    # controller) now become the parcel name, with a note.
    for ref in ("Discovered_VPN_10", "discovered_vpn_10"):
        r = sv.resolve_vpns([ref], ctx())
        assert r["names"] == ["mcp-w8-vpn10"] and not r["blockers"]
        assert any("does not match" in w for w in r["warnings"])
    seg_only = ctx()
    seg_only["index"]["mcp-test"][0]["vpn_name"] = "corp"
    seg_only["index"]["mcp-w8-hub"][0]["vpn_name"] = "corp"
    r = sv.resolve_vpns(["Discovered_VPN_10"], seg_only)
    assert r["names"] == ["mcp-w8-vpn10"] and any("segment name" in w for w in r["warnings"])


def test_a_cli_only_vpn_is_blocked_with_the_fix() -> None:
    r = sv.resolve_vpns([10], ctx(converted=False))
    assert r["names"] == []
    (b,) = r["blockers"]
    assert "VPN 10 has no LAN VPN parcel in configuration group mcp-test (br1)" in b
    assert "Please configure the VPN's 10" in b and "convert VPN 10 to a LAN VPN parcel" in b
    assert "deploy mcp-test" in b


def test_unknown_and_reserved_vpns() -> None:
    r = sv.resolve_vpns(["corp-lan", 512], ctx())
    text = " | ".join(r["blockers"])
    assert "'corp-lan' is no VPN id, LAN VPN parcel name or segment name" in text and "mcp-w8-vpn10" in text
    assert "VPN 512 is not a service VPN" in text


def test_groups_naming_the_vpn_differently_get_every_name() -> None:
    c = ctx(scope={"mcp-test": ["br1"], "mcp-w8-hub": ["hub1"]})
    c["index"]["mcp-w8-hub"] = [{"vpn": 10, "name": "hub-vpn10", "profile": "hub-svc", "vpn_name": None}]
    r = sv.resolve_vpns([10], c)
    assert r["names"] == ["mcp-w8-vpn10", "hub-vpn10"] and not r["blockers"]
    c["index"]["mcp-w8-hub"] = []
    r = sv.resolve_vpns([10], c)
    assert r["names"] == ["mcp-w8-vpn10"]
    assert len(r["blockers"]) == 1 and "configuration group mcp-w8-hub (hub1)" in r["blockers"][0]


def test_without_devices_one_group_holding_the_vpn_is_enough() -> None:
    c = ctx(scope={})
    c["index"]["mcp-w8-hub"] = []
    r = sv.resolve_vpns([10], c)
    assert r["names"] == ["mcp-w8-vpn10"] and not r["blockers"]
    assert any("every configuration group" in w for w in r["warnings"])
    none = ctx(converted=False, scope={})
    assert "no LAN VPN parcel in any configuration group" in sv.resolve_vpns([10], none)["blockers"][0]


def test_stored_targets_are_checked_like_the_controller() -> None:
    assert sv.target_problems(["mcp-w8-vpn10"], ctx()) == []
    for bad in ("10", "Discovered_VPN_10"):
        (p,) = sv.target_problems([bad], ctx())
        assert f"target VPN '{bad}' is not a LAN VPN parcel name" in p and "'mcp-w8-vpn10'" in p
    (p,) = sv.target_problems(["mcp-w8-vpn10"], ctx(converted=False))
    assert "matches no LAN VPN parcel" in p
    (p,) = sv.target_problems(["10"], ctx(converted=False))
    assert "convert VPN 10" in p


def test_zones_hold_vpn_numbers() -> None:
    vals, notes = sv.zone_value_ids(["mcp-w8-vpn10", "Discovered_VPN_10", "20", "GigabitEthernet3"], ctx())
    assert vals == ["10", "10", "20", "GigabitEthernet3"] and len(notes) == 2
    assert sv.zone_vpn_ids({"entries": [{"vpn": si.g("10")}, {"interface": si.g("Gi3")}]}) == [10]
    assert sv.zone_vpn_problems({"lan": [10]}, ctx()) == []
    assert sv.zone_vpn_problems({"outside": [0], "mgmt": [512]}, ctx(converted=False)) == []
    (p,) = sv.zone_vpn_problems({"lan": [10]}, ctx(converted=False))
    assert p.startswith("zone lan: VPN 10 has no LAN VPN parcel in configuration group mcp-test")


def test_vpn_ids_by_name() -> None:
    assert sv.vpn_ids_by_name(ctx()) == {"Discovered_VPN_10": 10, "mcp-w8-vpn10": 10}


async def test_vpn_context_scopes_the_devices_groups(api: respx.MockRouter) -> None:
    mock_service_vpns(api)
    app = SdwanApp(make_settings())
    try:
        c = await sv.vpn_context(app, [BR1])
        assert c["scope"] == {"mcp-test": ["br1"]} and not c["warnings"]
        both = await sv.vpn_context(app, [BR1, HUB1, "REDACTED-99"])
        assert both["scope"] == {"mcp-test": ["br1"], "mcp-w8-hub": ["hub1"]}
        assert any("1 device(s) are in no configuration group" in w for w in both["warnings"])
        assert (await sv.vpn_context(app, None))["scope"] == {}
    finally:
        await app.aclose()


def test_controller_failure_is_a_failure() -> None:
    partial = {
        "outcome": "partial",
        "devices": [
            {"host": "br1", "chassis": BR1, "status": "success"},
            {
                "host": "vsmart",
                "chassis": "ctrl-1",
                "status": "failure",
                "reason": "Please configure the VPN's 10",
            },
        ],
    }
    out = controller_outcome(partial, [BR1])
    assert out["outcome"] == "failed" and out["controller_failure"] == [REFUSED]
    edge = {**partial, "devices": [{**partial["devices"][0], "status": "failure"}, partial["devices"][1]]}
    assert controller_outcome(edge, [BR1])["outcome"] == "partial"
    assert controller_outcome({"outcome": "success"}, [BR1]) == {"outcome": "success"}


# --- tools -----------------------------------------------------------------------------------------


def mock_deploy(api: respx.MockRouter, targets: list[str] | None, *, converted: bool = True) -> respx.Route:
    """Policy group mcp-w8-pg (br1) with an application-priority profile holding one steering policy whose
    target is `targets` (None: no profile), on the recorded configuration groups."""
    mock_inventory(api)
    mock_service_vpns(api, converted=converted)
    profiles = [{"id": "00000000-0000-4000-8000-00000000b201", "name": "Default_Policy_Object_Profile",
                 "type": "policy-object"}]  # fmt: skip
    if targets is not None:
        profiles.append({"id": AP, "name": "mcp-w8-pg-app-priority", "type": "application-priority"})
        body = si.traffic_policy_body("mcp-w8-br1-to-hub-fw", "", [10], "service", "accept", [], {}, targets)
        api.get(f"{FP}/application-priority/{AP}").respond(
            json={"associatedProfileParcels": [{"parcelId": TP, "parcelType": "traffic-policy",
                                                "payload": {"name": "mcp-w8-br1-to-hub-fw"}}]}
        )  # fmt: skip
        api.get(f"{FP}/application-priority/{AP}/traffic-policy/{TP}").respond(
            json={"parcelId": TP, "payload": body}
        )
    group = {"id": PGID, "name": "mcp-w8-pg", "profiles": profiles, "lastUpdatedOn": 5}
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    api.get(PGS).respond(json=[group])
    api.get(f"{PGS}/{PGID}").respond(json=group)
    api.get(f"{PGS}/{PGID}/device/associate").respond(json={"devices": [rows[BR1]]})
    api.get(f"{STATUS}/tasks").respond(json={"runningTasks": []})
    api.get(f"/dataservice/template/config/running/{BR1}").respond(json={"config": "hostname br1\n"})
    api.post(f"{PGS}/{PGID}/device/{BR1}/preview").respond(json={"config": "hostname br1\n"})
    return api.post(f"{PGS}/{PGID}/device/deploy").respond(json={"parentTaskId": "pt-1"})


async def preview(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        return (await c.call_tool(name, args)).structured_content


async def test_deploy_precheck_blocks_a_vpn_id_target(api: respx.MockRouter) -> None:
    mock_deploy(api, ["10"])
    out = await preview("catsdwan_deploy_policy_group", {"group": "mcp-w8-pg", "devices": ["br1"]})
    (b,) = out["blockers"]
    assert b.startswith("traffic policy mcp-w8-br1-to-hub-fw: target VPN '10' is not a LAN VPN parcel name")
    step = out["preview"]["controller_step"]
    assert step["traffic_policy_targets"] == {"mcp-w8-br1-to-hub-fw": ["10"]}
    assert step["configuration_groups"] == {"mcp-test": ["br1"]}


async def test_deploy_precheck_passes_the_parcel_name(api: respx.MockRouter) -> None:
    deploy = mock_deploy(api, ["mcp-w8-vpn10"])
    api.get(f"{STATUS}/pt-1").respond(
        json={"data": [
            {"host-name": "br1", "uuid": BR1, "statusId": "success", "status": "Success"},
            {"host-name": "vsmart", "uuid": "ctrl-1", "statusId": "failure", "status": "Failure",
             "activity": ["Please configure the VPN's mcp-w8-vpn10"]},
        ]}
    )  # fmt: skip
    args = {"group": "mcp-w8-pg", "devices": ["br1"]}
    async with Client(make_server(mcp_enable_writes=True)) as c:
        first = (await c.call_tool("catsdwan_deploy_policy_group", args)).structured_content
        assert not first.get("blockers"), first["blockers"]
        done = await c.call_tool("catsdwan_deploy_policy_group", {**args, "confirm": first["confirm"]})
    result = done.structured_content["result"]
    assert json.loads(deploy.calls.last.request.content) == {"devices": [{"id": BR1}]}
    # The controller row failing while br1 succeeded: failed, not partial.
    assert result["outcome"] == "failed" and result["controller_failure"]


async def test_deploy_precheck_blocks_an_unconverted_vpn(api: respx.MockRouter) -> None:
    mock_deploy(api, ["mcp-w8-vpn10"], converted=False)
    out = await preview("catsdwan_deploy_policy_group", {"group": "mcp-w8-pg", "devices": ["br1"]})
    assert any("matches no LAN VPN parcel in configuration group mcp-test" in b for b in out["blockers"])


async def test_deploy_without_vpn_references_has_no_vpn_blocker(api: respx.MockRouter) -> None:
    mock_deploy(api, None)
    out = await preview("catsdwan_deploy_policy_group", {"group": "mcp-w8-pg", "devices": ["br1"]})
    assert not out.get("blockers")


async def test_zone_object_takes_a_parcel_name(api: respx.MockRouter) -> None:
    mock_manager(api)
    put = api.put(f"{PO}/security-zone/{ZIN}").respond(200)
    args = {"kind": "zone", "name": "lan", "values": ["mcp-w8-vpn10"]}
    out = await preview("catsdwan_set_security_object", args)
    assert out["preview"]["after"] == ["10"] and not out.get("blockers")
    assert any("'mcp-w8-vpn10' -> VPN 10" in w for w in out["preview"]["warnings"])
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool("catsdwan_set_security_object", args)).structured_content
        await c.call_tool("catsdwan_set_security_object", {**args, "confirm": first["confirm"]})
    assert json.loads(put.calls.last.request.content)["data"]["entries"] == [{"vpn": si.g("10")}]
    warn = await preview("catsdwan_set_security_object", {"kind": "zone", "name": "lan", "values": ["30"]})
    assert any("VPN 30 has no LAN VPN parcel in any configuration group" in w
               for w in warn["preview"]["warnings"])  # fmt: skip


async def test_firewall_policy_blocks_a_zone_vpn_without_parcel(api: respx.MockRouter) -> None:
    mock_manager(api, members=[BR1], converted=False)
    args = {
        "group": "mcp-w8-pg",
        "name": "br-fw",
        "rules": [{"name": "deny", "action": "drop"}],
        "zone_pairs": [{"source": "lan", "destination": "guest"}],
    }
    out = await preview("catsdwan_set_firewall_policy", args)
    text = " | ".join(out["blockers"])
    assert "zone lan: VPN 10 has no LAN VPN parcel in configuration group mcp-test (br1)" in text
    assert "zone guest: VPN 20" in text


async def test_baseline_blocks_a_zone_vpn_without_parcel(api: respx.MockRouter) -> None:
    from .test_containment import mock_all

    mock_all(api)
    # Re-register the configuration groups' service VPNs as before the conversion (the later route wins).
    mock_service_vpns(api, converted=False)
    out = await preview("catsdwan_set_containment_baseline", {"group": "mcp-w8-pg", "edge_slots": True})
    assert any(b.startswith("zone lan: VPN 10 has no LAN VPN parcel") for b in out["blockers"])
