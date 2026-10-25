"""W50: service insertion (catsdwan_service_chains, catsdwan_set_service_chain, catsdwan_set_service_steering)
and the catsdwan_trace_through_firewall prompt.

Recorded on the lab Manager (20.18.3.1, read only): no service profile
(GET /v1/feature-profile/sdwan/service = []), an empty service-chain mapping, hub1's OMP services (VPN routes
only), the mcp-test configuration group and its CLI profile. Hand-built from Cisco's published parcel models
(the lab has none; marked where used): a LAN VPN parcel with a FW service, the LAN VPN schema's `service`
subtree, a traffic-policy parcel, an application-priority profile and the FW row in OMP services. Addresses
follow the L65 recipe (hub-ftd inside 10.61.110.2, br1-lan 10.61.220.0/24); ids are documentation UUIDs.
Recorded in the W50 live run (20.18.3.1, 2026-10-24, #119): the traffic-policy POST schema (ids replaced by
documentation UUIDs) and hub1's running `sdwan` block with `service firewall vrf 10`.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import edgefirewall as fw
from cat_sdwan_mcp import features as ft
from cat_sdwan_mcp import serviceinsertion as si
from cat_sdwan_mcp._core.prompts import rendered_text

from .conftest import fixture, make_server
from .test_inventory import mock_inventory

FP = "/dataservice/v1/feature-profile/sdwan"
CG = "/dataservice/v1/config-group"
PGS = "/dataservice/v1/policy-group"
CGID = "00000000-0000-4000-8000-000000000124"
PGID = "00000000-0000-4000-8000-00000000b101"
OBJ = "00000000-0000-4000-8000-00000000b201"
AP = "00000000-0000-4000-8000-00000000e001"
TP = "00000000-0000-4000-8000-00000000e002"
SVC = "00000000-0000-4000-8000-00000000e003"
VPN10 = "00000000-0000-4000-8000-00000000e004"
DPL = "00000000-0000-4000-8000-00000000e005"
CLI = "00000000-0000-4000-8000-000000001038"
CLI_PARCEL = "00000000-0000-4000-8000-000000001039"
g = fw.g


def lan_vpn(services: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Hand-built LAN VPN parcel (Cisco's model): VPN 10 with optional services."""
    data: dict[str, Any] = {"vpnId": g(10), "name": g("corp"), "ompAdminDistance": {"optionType": "default"}}
    if services is not None:
        data["service"] = services
    return {
        "parcelId": VPN10,
        "parcelType": "lan/vpn",
        "lastUpdatedOn": 7,
        "payload": {"name": "vpn10", "description": "", "data": data},
    }


FW_SERVICE = si.service_entry("FW", ["10.61.110.2"], True)

# Hand-built: the LAN VPN schema's `service` subtree (Cisco's model); the rest of data is left open.
LAN_VPN_SCHEMA = {
    "request": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 128},
            "description": {"type": "string"},
            "data": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "serviceType": {
                                    "type": "object",
                                    "properties": {
                                        "optionType": {"type": "string", "enum": ["global"]},
                                        "value": {"type": "string", "enum": [*si.SERVICE_TYPES, "TE"]},
                                    },
                                },
                                "ipv4Addresses": {
                                    "type": "object",
                                    "properties": {
                                        "value": {"type": "array", "minItems": 1, "maxItems": 4},
                                    },
                                },
                                "tracking": {"type": "object"},
                            },
                            "required": ["serviceType", "ipv4Addresses"],
                            "additionalProperties": False,
                        },
                    }
                },
            },
        },
        "required": ["name", "data"],
    }
}

STEERING_RULE = {
    "name": "br1-to-dc",
    "source_prefixes": ["10.61.220.0/24"],
    "destination_lists": ["dc-prefixes"],
    "protocols": [6],
    "destination_ports": [22],
}


# Recorded: hub1's running `sdwan` block after the live run stored the service in its CLI profile (trimmed to
# the service and the first tunnel interface).
HUB1_SDWAN = (
    "sdwan\n service firewall vrf 10\n  ipv4 address 10.61.110.2\n interface GigabitEthernet1\n"
    "  tunnel-interface\n   encapsulation ipsec\n   color mpls\n  exit\n exit\n appqoe\n"
    "  no tcpopt enable\n omp\n  no shutdown\n  address-family ipv4 vrf 10\n   advertise connected\n"
)
TP_SCHEMA = fixture("v1_feature_profile_application_priority_traffic_policy_schema_post")


def cli_parcel(extra: str = "") -> dict[str, Any]:
    body = copy.deepcopy(fixture("v1_feature_profile_cli_config_parcel"))
    body["payload"]["data"]["config"] += extra
    return body


def traffic_policy(rules: list[dict[str, Any]]) -> dict[str, Any]:
    body = si.traffic_policy_body("mcp-w8-chain", "", [10], "service", "accept", rules, {"dc-prefixes": DPL})
    return {"parcelId": TP, "parcelType": "traffic-policy", "lastUpdatedOn": 3, "payload": body}


def mock_lab(
    api: respx.MockRouter,
    *,
    service_profile: bool = True,
    services: list[dict[str, Any]] | None = None,
    cli_extra: str = "",
    app_priority: bool = True,
    steering: list[dict[str, Any]] | None = None,
    omp_fw: bool = False,
) -> None:
    profiles = [{"id": CLI, "name": "mcp-test-cli", "type": "cli"}]
    if service_profile:
        profiles.append({"id": SVC, "name": "mcp-w8-service", "type": "service"})
    api.get(CG).respond(json=[{"id": CGID, "name": "mcp-test", "profiles": profiles}])
    api.get(f"{CG}/{CGID}/device/associate").respond(json=fixture("v1_config_group_associate"))
    api.get(f"{FP}/service").respond(
        json=[{"profileId": SVC, "profileName": "mcp-w8-service", "profileType": "service"}]
        if service_profile
        else fixture("v1_feature_profile_sdwan_service_list")
    )
    api.get(f"{FP}/service/{SVC}/lan/vpn").respond(json={"data": [lan_vpn(services)]})
    api.get(f"{FP}/service/lan/vpn/schema").respond(json=LAN_VPN_SCHEMA)
    cli_detail = fixture("v1_feature_profile_cli_detail")
    api.get(f"{FP}/cli/{CLI}").respond(json=cli_detail)
    api.get(f"{FP}/cli/{CLI}/config/{CLI_PARCEL}").respond(json=cli_parcel(cli_extra))

    pg_profiles = [{"id": OBJ, "name": "Default_Policy_Object_Profile", "type": "policy-object"}]
    if app_priority:
        pg_profiles.append({"id": AP, "name": "mcp-w8-pg-app-priority", "type": "application-priority"})
    group = {"id": PGID, "name": "mcp-w8-pg", "description": "", "profiles": pg_profiles, "lastUpdatedOn": 5}
    api.get(PGS).respond(json=[group])
    api.get(f"{PGS}/{PGID}").respond(json=group)
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    api.get(f"{PGS}/{PGID}/device/associate").respond(json={"devices": [rows["REDACTED-16"]]})
    lists = {
        "policy-object": [{"profileId": OBJ, "profileName": "Default_Policy_Object_Profile"}],
        "application-priority": [{"profileId": AP, "profileName": "mcp-w8-pg-app-priority"}]
        if app_priority
        else [],
    }
    for t in ft.LISTABLE_TYPES:
        if t != "service":
            api.get(f"{FP}/{t}").respond(json=lists.get(t, []))
    dpl = {"parcelId": DPL, "parcelType": "data-prefix", "payload": {"name": "dc-prefixes", "data": {}}}
    api.get(f"{FP}/policy-object/{OBJ}/data-prefix").respond(json={"data": [dpl]})
    tps = [traffic_policy(steering)] if steering else []
    api.get(f"{FP}/application-priority/{AP}").respond(
        json={
            "profileId": AP,
            "associatedProfileParcels": [
                {
                    "parcelId": p["parcelId"],
                    "parcelType": "traffic-policy",
                    "payload": {"name": "mcp-w8-chain"},
                }
                for p in tps
            ],
        }
    )
    for p in tps:
        api.get(f"{FP}/application-priority/{AP}/traffic-policy/{p['parcelId']}").respond(json=p)
    api.get(f"{FP}/application-priority/traffic-policy/schema").respond(
        404, json={"error": {"message": "nf"}}
    )
    api.get(si.CHAIN_MAPPING_PATH).respond(json=fixture("v1_service_insertion_service_chain_mapping"))
    omp = copy.deepcopy(fixture("device_omp_services_hub1"))
    if omp_fw:  # hand-built: the FW service hub1 would advertise
        omp["data"].append({**omp["data"][0], "service": "FW", "label": "1005", "path-id": "70"})
    api.get(si.OMP_SERVICES_PATH).respond(json=omp)
    api.get("/dataservice/segment").respond(json=fixture("segment"))
    mock_inventory(api)


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(make_server(**settings)) as c:
        return (await c.call_tool(name, args)).structured_content


async def confirmed(name: str, args: dict[str, Any]) -> Any:
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        first = (await c.call_tool(name, args)).structured_content
        assert first["status"] == "preview", first
        assert not first.get("blockers"), first["blockers"]
        return (await c.call_tool(name, {**args, "confirm": first["confirm"]})).structured_content


def details(preview: dict[str, Any]) -> dict[str, Any]:
    return preview["preview"]


# --- helpers ---------------------------------------------------------------------------------------


def test_service_rows_and_merge_keep_other_services() -> None:
    ids = si.service_entry("IDS", ["192.0.2.9"], False)
    data = {"vpnId": g(10), "service": [ids, si.service_entry("FW", ["192.0.2.1"], True)]}
    merged = si.with_service(data, "FW", FW_SERVICE)
    assert merged["vpnId"] == g(10)
    assert si.service_rows(merged) == [
        {"type": "IDS", "addresses": ["192.0.2.9"], "tracking": False},
        {"type": "FW", "addresses": ["10.61.110.2"], "tracking": True},
    ]
    assert "service" not in si.with_service({"service": [FW_SERVICE]}, "FW", None)
    dflt = {"serviceType": g("FW"), "ipv4Addresses": g(["192.0.2.4"]), "tracking": {"optionType": "default"}}
    assert si.service_rows({"service": [dflt]})[0]["tracking"] is True


def test_problems() -> None:
    assert si.vpn_problem(512) and si.vpn_problem(0) and si.vpn_problem(10) is None
    assert si.address_problems([]) and "IPv4" in si.address_problems(["10.61.110.300"])[0]
    assert si.address_problems(["10.61.110.2"]) == []


def test_cli_services_read_the_recorded_firewall_line() -> None:
    assert si.cli_services(HUB1_SDWAN) == [
        {"type": "FW", "vpn": 10, "addresses": ["10.61.110.2"], "tracking": True}
    ]


def test_cli_lines_use_the_ios_xe_keyword() -> None:
    lines = si.cli_lines("FW", 10, ["10.61.110.2"], True)
    assert lines == ["sdwan", " service firewall vrf 10", "  ipv4 address 10.61.110.2"]
    assert si.cli_services("\n".join(lines))[0]["type"] == "FW"
    assert si.cli_lines("netsvc1", 20, ["192.0.2.5"], False)[1:] == [
        " service netsvc1 vrf 20",
        "  ipv4 address 192.0.2.5",
        "  no track-enable",
    ]


def test_cli_services_parse_the_ios_xe_form() -> None:
    text = (
        "sdwan\n service FW vrf 10\n  ipv4 address 10.61.110.2 10.61.110.3\n  no track-enable\n!\n"
        "line con 0\n"
    )
    assert si.cli_services(text) == [
        {"type": "FW", "vpn": 10, "addresses": ["10.61.110.2", "10.61.110.3"], "tracking": False}
    ]
    assert si.cli_services(" service IDS vpn 20 address 192.0.2.5\n")[0]["addresses"] == ["192.0.2.5"]
    # The recorded CLI profile has `service timestamps ...` lines: not services.
    assert si.cli_services(fixture("v1_feature_profile_cli_config_parcel")["payload"]["data"]["config"]) == []
    assert si.cli_services("\n".join(si.cli_lines("FW", 10, ["10.61.110.2"], True)))[0]["vpn"] == 10


def test_omp_services_recorded() -> None:
    rows = si.omp_service_rows(fixture("device_omp_services_hub1")["data"], 10)
    assert {r["service"] for r in rows} == {"VPN"}
    assert [r["direction"] for r in rows] == ["local", "local", "sent"]
    assert si.omp_service_rows(fixture("device_omp_services_hub1")["data"], 20) == []


def test_traffic_policy_body_and_words() -> None:
    rules = [
        {**STEERING_RULE, "restrict": True},
        {"name": "guest", "source_lists": ["dc-prefixes"], "chain": "SC1", "service_vpn": 10, "local": True},
    ]
    body = si.traffic_policy_body("p", "", [10], "service", "accept", rules, {"dc-prefixes": DPL})
    data = body["data"]
    assert data["target"] == {"vpn": g(["10"]), "direction": g("service")}
    seq = data["sequences"][0]
    assert seq["match"]["entries"] == [
        {"sourceIp": g("10.61.220.0/24")},
        {"destinationDataPrefixList": {"refId": g(DPL)}},
        {"protocol": g(["6"])},
        {"destinationPort": g(["22"])},
    ]
    # service.vpn is required on 20.18: the policy's one target VPN when the rule names none.
    assert seq["actions"] == [
        {"set": [{"service": {"type": g("FW"), "local": g(False), "restrict": g(True), "vpn": g(10)}}]}
    ]
    assert data["sequences"][1]["actions"][0]["set"][0]["serviceChain"]["type"] == g("SC1")
    rows = si.steering_rows(data, {DPL: "dc-prefixes"})
    assert rows[0]["match"] == [
        "from 10.61.220.0/24",
        "to list dc-prefixes",
        "protocol 6",
        "destinationPort 22",
    ]
    assert rows[0]["service"] == "FW" and rows[0]["if_down"] == "dropped (restrict)"
    assert rows[1]["chain"] == "SC1" and rows[1]["vpn"] == 10 and "bypassing" in rows[1]["if_down"]
    assert si.target_of(data) == {"vpns": ["10"], "direction": "service", "default_action": "accept"}
    assert si.steering_rows({"sequences": [{"actions": [{"set": [{"dscp": g(46)}]}]}]}) == []


def test_steering_body_fits_the_recorded_20_18_schema() -> None:
    schema = fw.request_schema(TP_SCHEMA)
    rules = [
        {**STEERING_RULE, "restrict": True},
        {"name": "dc-chain", "destination_prefixes": ["10.61.100.0/24"], "chain": "SC2", "service_vpn": 10},
    ]
    body = si.traffic_policy_body("p", "", [10], "service", "accept", rules, {"dc-prefixes": DPL})
    assert fw.schema_problems(schema, body) == []
    # What 0.6.1 sent (the nested match form, no service vpn) is what the Manager's schema refused.
    old = copy.deepcopy(body)
    seq = old["data"]["sequences"][0]
    seq["match"]["entries"][0] = {"sourceDataPrefix": {"sourceIpPrefix": g("10.61.220.0/24")}}
    del seq["actions"][0]["set"][0]["service"]["vpn"]
    problems = " | ".join(fw.schema_problems(schema, old))
    assert "sourceDataPrefix is not allowed" in problems and "vpn is required" in problems
    # Several target VPNs: the service VPN comes from the rule only.
    multi = si.traffic_policy_body(
        "p", "", [10, 20], "service", "accept", [STEERING_RULE], {"dc-prefixes": DPL}
    )
    assert "vpn" not in multi["data"]["sequences"][0]["actions"][0]["set"][0]["service"]


def test_match_words_read_both_forms() -> None:
    names = {DPL: "dc-prefixes"}
    new = [{"sourceIp": g("10.61.220.0/24")}, {"destinationDataPrefixList": {"refId": g(DPL)}}]
    old = [
        {"sourceDataPrefix": {"sourceIpPrefix": g("10.61.220.0/24")}},
        {"destinationDataPrefix": {"destinationDataPrefixList": {"refId": g(DPL)}}},
    ]
    assert (
        si._match_words(new, names)
        == si._match_words(old, names)
        == [
            "from 10.61.220.0/24",
            "to list dc-prefixes",
        ]
    )
    legacy_chain = {"sequences": [{"actions": [{"set": [{"serviceChain": {"serviceChainType": g("SC3")}}]}]}]}
    assert si.steering_rows(legacy_chain)[0]["chain"] == "SC3"


def test_body_fits_the_hand_built_schema() -> None:
    body = {"name": "vpn10", "description": "", "data": si.with_service({"vpnId": g(10)}, "FW", FW_SERVICE)}
    assert fw.schema_problems(fw.request_schema(LAN_VPN_SCHEMA), body) == []
    bad = {"name": "vpn10", "data": {"service": [{"serviceType": g("XX"), "ipv4Addresses": g([])}]}}
    assert len(fw.schema_problems(fw.request_schema(LAN_VPN_SCHEMA), bad)) == 2


def test_chain_mapping() -> None:
    assert si.chain_mapping(fixture("v1_service_insertion_service_chain_mapping")) == {}
    assert si.chain_mapping([{"serviceChainName": "SC-Firewall", "serviceChainNumber": "SC1"}]) == {
        "SC1": "SC-Firewall"
    }


# --- catsdwan_service_chains -------------------------------------------------------------------------


async def test_service_chains_on_the_recorded_lab(api: respx.MockRouter) -> None:
    """The lab today: no service profile, nothing steered, hub1 advertises only VPN routes."""
    mock_lab(api, service_profile=False, app_priority=False)
    out = await call("catsdwan_service_chains", {"vpn": 10, "device": "hub1"})
    assert out["services"] == [] and out["steering"] == []
    assert out["verdict"].startswith("No service chain in VPN 10")
    assert out["omp_services"] == {"device": "hub1", "services": [], "vpn_routes_advertised": 3}


async def test_service_chains_names_the_chain(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE], steering=[STEERING_RULE], omp_fw=True)
    out = await call("catsdwan_service_chains", {"vpn": 10, "device": "hub1"})
    assert out["services"] == [
        {
            "vpn": 10,
            "type": "FW",
            "addresses": ["10.61.110.2"],
            "tracking": True,
            "source": "service profile (LAN VPN parcel)",
            "profile": "mcp-w8-service",
            "parcel": "vpn10",
            "groups": ["mcp-test"],
        }
    ]
    st = out["steering"][0]
    assert st["group"] == "mcp-w8-pg" and st["policy"] == "mcp-w8-chain" and st["vpns"] == ["10"]
    assert st["sequences"][0]["match"][:2] == ["from 10.61.220.0/24", "to list dc-prefixes"]
    v = out["verdict"]
    assert "FW at 10.61.110.2 in VPN 10" in v and "seq br1-to-dc" in v and "hub1 knows FW (VPN 10" in v
    assert out["omp_services"]["services"][0]["service"] == "FW"


async def test_service_chains_reads_cli_profile_services(api: respx.MockRouter) -> None:
    mock_lab(api, service_profile=False, cli_extra=HUB1_SDWAN)
    out = await call("catsdwan_service_chains", {})
    assert out["services"][0]["source"] == "CLI profile" and out["services"][0]["profile"] == "mcp-test-cli"
    assert out["services"][0]["type"] == "FW" and out["services"][0]["addresses"] == ["10.61.110.2"]
    assert "no policy-group traffic policy steers" in out["verdict"]
    out20 = await call("catsdwan_service_chains", {"vpn": 20})
    assert out20["services"] == []


# --- catsdwan_set_service_chain ------------------------------------------------------------------------


async def test_set_service_chain_preview_and_apply(api: respx.MockRouter) -> None:
    mock_lab(api, services=[])
    put = api.put(f"{FP}/service/{SVC}/lan/vpn/{VPN10}").respond(json={"parcelId": VPN10})
    args = {"profile": "mcp-test", "vpn": 10, "addresses": ["10.61.110.2"]}
    pre = await call("catsdwan_set_service_chain", args, mcp_enable_writes=True)
    assert pre["status"] == "preview" and not pre.get("blockers")
    d = details(pre)
    assert d["before"] == [] and d["after"] == [
        {"type": "FW", "addresses": ["10.61.110.2"], "tracking": True}
    ]
    assert d["reaches"][0]["group"] == "mcp-test"
    done = await confirmed("catsdwan_set_service_chain", args)
    assert done["result"]["services"] == [{"type": "FW", "addresses": ["10.61.110.2"], "tracking": True}]
    sent = json.loads(put.calls.last.request.content)
    assert sent["name"] == "vpn10" and sent["data"]["vpnId"] == g(10)
    assert sent["data"]["service"] == [FW_SERVICE]


async def test_set_service_chain_blockers(api: respx.MockRouter) -> None:
    mock_lab(api, services=[])
    pre = await call(
        "catsdwan_set_service_chain",
        {"profile": "mcp-w8-service", "vpn": 10, "addresses": ["10.61.110.999"]},
        mcp_enable_writes=True,
    )
    assert any("IPv4" in b for b in pre["blockers"])
    pre = await call(
        "catsdwan_set_service_chain", {"profile": SVC, "vpn": 10, "remove": True}, mcp_enable_writes=True
    )
    assert any("no FW service to remove" in b for b in pre["blockers"])
    with pytest.raises(ToolError, match="no LAN VPN parcel for VPN 20"):
        await call("catsdwan_set_service_chain", {"profile": SVC, "vpn": 20, "addresses": ["192.0.2.1"]},
                   mcp_enable_writes=True)  # fmt: skip


async def test_set_service_chain_cli_group_gives_the_lines(api: respx.MockRouter) -> None:
    mock_lab(api, service_profile=False)
    with pytest.raises(ToolError, match="service firewall vrf 10 /   ipv4 address 10.61.110.2"):
        await call(
            "catsdwan_set_service_chain",
            {"profile": "mcp-test", "vpn": 10, "addresses": ["10.61.110.2"]},
            mcp_enable_writes=True,
        )


async def test_set_service_chain_without_schema_warns(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    api.get(f"{FP}/service/lan/vpn/schema").respond(500, json={"error": {"message": "x"}})
    pre = await call(
        "catsdwan_set_service_chain",
        {"profile": SVC, "vpn": 10, "addresses": ["10.61.110.2", "10.61.110.3"], "tracking": False},
        mcp_enable_writes=True,
    )
    d = details(pre)
    assert any("LAN VPN schema" in w for w in d["warnings"])
    assert d["before"][0]["addresses"] == ["10.61.110.2"] and d["after"][0]["tracking"] is False


async def test_set_service_chain_hidden_without_writes() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catsdwan_service_chains" in names
    assert not {"catsdwan_set_service_chain", "catsdwan_set_service_steering"} & names


# --- catsdwan_set_service_steering ------------------------------------------------------------------------


STEER_ARGS = {"group": "mcp-w8-pg", "name": "mcp-w8-chain", "vpns": [10], "rules": [STEERING_RULE]}


async def test_set_service_steering_creates_profile_and_policy(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE], app_priority=False)
    post_ap = api.post(f"{FP}/application-priority").respond(json={"id": AP})
    put_group = api.put(f"{PGS}/{PGID}").respond(json={"id": PGID})
    post_tp = api.post(f"{FP}/application-priority/{AP}/traffic-policy").respond(json={"parcelId": TP})
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", STEER_ARGS)).structured_content
    d = details(pre)
    assert not pre.get("blockers") and d["profile"] == "mcp-w8-pg-app-priority (new)"
    assert d["after"]["sequences"][0]["match"][1] == "to list dc-prefixes"
    assert any("schema" in w for w in d["warnings"])
    assert not any("no configuration group gives" in w for w in d["warnings"])
    done = await confirmed("catsdwan_set_service_steering", STEER_ARGS)
    assert json.loads(post_ap.calls.last.request.content)["name"] == "mcp-w8-pg-app-priority"
    assert {"id": AP} in json.loads(put_group.calls.last.request.content)["profiles"]
    sent = json.loads(post_tp.calls.last.request.content)
    assert sent["data"]["sequences"][0]["actions"][0]["set"][0]["service"]["type"] == g("FW")
    assert done["result"]["profile_created"] == "mcp-w8-pg-app-priority" and done["result"]["id"] == TP


async def test_set_service_steering_replaces_and_warns(api: respx.MockRouter) -> None:
    mock_lab(api, services=[], steering=[STEERING_RULE])
    put_tp = api.put(f"{FP}/application-priority/{AP}/traffic-policy/{TP}").respond(json={"parcelId": TP})
    args = {**STEER_ARGS, "rules": [{**STEERING_RULE, "restrict": True}]}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", args)).structured_content
    d = details(pre)
    assert d["before"]["sequences"][0]["name"] == "br1-to-dc"
    assert any("no configuration group gives an edge a FW service in VPN 10" in w and "dropped" in w
               for w in d["warnings"])  # fmt: skip
    assert pre["blast_radius"] == 1
    await confirmed("catsdwan_set_service_steering", args)
    assert json.loads(put_tp.calls.last.request.content)["data"]["sequences"][0]["actions"][0]["set"][0][
        "service"
    ]["restrict"] == g(True)


async def test_set_service_steering_blockers(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    bad = {
        **STEER_ARGS,
        "vpns": [512],
        "rules": [
            {"name": "a", "destination_lists": ["nope"]},
            {"name": "a", "source_prefixes": ["10.61.220.1/24"], "chain": "SC99"},
        ],
    }
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", bad)).structured_content
    text = " | ".join(pre["blockers"])
    for want in (
        "not a service VPN",
        "no data-prefix list named 'nope'",
        "used twice",
        "IPv4 prefix",
        "SC99",
    ):
        assert want in text, want
    # A new profile while the group has one: one per group.
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (
            await c.call_tool("catsdwan_set_service_steering", {**STEER_ARGS, "profile": "other"})
        ).structured_content
    assert any("one per" in b for b in pre["blockers"])


async def test_set_service_steering_checks_the_recorded_schema(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    api.get(f"{FP}/application-priority/traffic-policy/schema").respond(json=TP_SCHEMA)
    post_tp = api.post(f"{FP}/application-priority/{AP}/traffic-policy").respond(json={"parcelId": TP})
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", STEER_ARGS)).structured_content
    assert not pre.get("blockers"), pre["blockers"]
    assert not any("schema" in w for w in details(pre).get("warnings", []))
    await confirmed("catsdwan_set_service_steering", STEER_ARGS)
    seq = json.loads(post_tp.calls.last.request.content)["data"]["sequences"][0]
    assert seq["match"]["entries"][0] == {"sourceIp": g("10.61.220.0/24")}
    assert seq["actions"][0]["set"][0]["service"]["vpn"] == g(10)


async def test_set_service_steering_several_vpns_need_service_vpn(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    args = {**STEER_ARGS, "vpns": [10, 20]}
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", args)).structured_content
        assert any("give service_vpn" in b for b in pre["blockers"])
        ok = {**args, "rules": [{**STEERING_RULE, "service_vpn": 10}]}
        pre = (await c.call_tool("catsdwan_set_service_steering", ok)).structured_content
    assert not any("service_vpn" in b for b in pre.get("blockers", []))


async def test_set_service_steering_is_dangerous(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    pre = await call("catsdwan_set_service_steering", STEER_ARGS, mcp_enable_writes=True)
    assert any("MCP_ENABLE_DANGEROUS" in b for b in pre["blockers"])


async def test_set_service_steering_remove(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE], steering=[STEERING_RULE])
    delete = api.delete(f"{FP}/application-priority/{AP}/traffic-policy/{TP}").respond(json={})
    done = await confirmed(
        "catsdwan_set_service_steering", {"group": "mcp-w8-pg", "name": "mcp-w8-chain", "remove": True}
    )
    assert delete.called and done["result"]["deleted"] == "mcp-w8-chain"


# --- the prompt ----------------------------------------------------------------------------------------


async def test_trace_through_firewall_prompt() -> None:
    async with Client(make_server()) as c:
        text = rendered_text(
            await c.get_prompt(
                "catsdwan_trace_through_firewall",
                {"source": "10.61.220.10", "destination": "10.61.100.10", "app": "tcp/22", "vpn": "10"},
            )
        )
    order = [
        "catsdwan_find_host",
        "catsdwan_explain_path",
        "catsdwan_service_chains",
        "fmc_list_device_interfaces",
        "fmc_packet_tracer",
        "fmc_rule_lookup",
    ]
    positions = [text.index(f"`{ref}`") for ref in order]
    assert positions == sorted(positions)
    assert "with vpn=10, device=<the source edge>" in text and "tcp/22" in text
    for verdict in ("allowed by <rule> on <FTD>", "blocked by <rule> on <FTD>", "not chained"):
        assert verdict in text
    assert "Read-only" in text


# --- #118: target VPNs are the LAN VPN parcel names ----------------------------------------------------


async def test_set_service_steering_targets_the_lan_vpn_parcel_name(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    api.get(f"{FP}/application-priority/traffic-policy/schema").respond(json=TP_SCHEMA)
    post_tp = api.post(f"{FP}/application-priority/{AP}/traffic-policy").respond(json={"parcelId": TP})
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", STEER_ARGS)).structured_content
    d = details(pre)
    assert d["vpns"][0]["vpn"] == 10 and d["vpns"][0]["parcel_names"] == ["vpn10"]
    assert d["after"]["vpns"] == ["vpn10"]
    await confirmed("catsdwan_set_service_steering", STEER_ARGS)
    sent = json.loads(post_tp.calls.last.request.content)["data"]
    assert sent["target"]["vpn"] == g(["vpn10"])  # the controller matches this, not "10"
    assert sent["sequences"][0]["actions"][0]["set"][0]["service"]["vpn"] == g(10)
    # The parcel's VPN name (data.name, here "corp") and the parcel name itself resolve the same way.
    for ref in ("corp", "vpn10"):
        async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
            pre = (
                await c.call_tool("catsdwan_set_service_steering", {**STEER_ARGS, "vpns": [ref]})
            ).structured_content
        assert not pre.get("blockers") and details(pre)["after"]["vpns"] == ["vpn10"]


async def test_set_service_steering_blocks_a_cli_only_vpn(api: respx.MockRouter) -> None:
    mock_lab(api, service_profile=False)
    async with Client(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)) as c:
        pre = (await c.call_tool("catsdwan_set_service_steering", STEER_ARGS)).structured_content
    text = " | ".join(pre["blockers"])
    assert "VPN 10 has no LAN VPN parcel in configuration group mcp-test (br1)" in text
    assert "convert VPN 10 to a LAN VPN parcel" in text
    assert "body" not in details(pre)


async def test_service_chains_maps_parcel_name_targets_to_the_vpn(api: respx.MockRouter) -> None:
    mock_lab(api, services=[FW_SERVICE])
    tp = si.traffic_policy_body("mcp-w8-chain", "", [10], "service", "accept", [STEERING_RULE],
                                {"dc-prefixes": DPL}, ["vpn10"])  # fmt: skip
    api.get(f"{FP}/application-priority/{AP}").respond(
        json={"associatedProfileParcels": [{"parcelId": TP, "parcelType": "traffic-policy",
                                            "payload": {"name": "mcp-w8-chain"}}]}
    )  # fmt: skip
    api.get(f"{FP}/application-priority/{AP}/traffic-policy/{TP}").respond(
        json={"parcelId": TP, "payload": tp}
    )
    out = await call("catsdwan_service_chains", {"vpn": 10})
    assert out["steering"][0]["vpns"] == ["vpn10"] and out["steering"][0]["vpn_ids"] == [10]
    assert (await call("catsdwan_service_chains", {"vpn": 20}))["steering"] == []
