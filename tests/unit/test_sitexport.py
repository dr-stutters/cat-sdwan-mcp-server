"""W55 (#77): catsdwan_export_site on recorded 20.18.3.1 payloads plus hand-built ones in the recorded shapes.

br1 (site 200) is in configuration group mcp-test (v1_config_group_w8: service, transport, system and cli
profiles) and policy group mcp-pg (`managed-by` "Config-Group mcp-test, Policy-Group mcp-pg", as recorded
on 2026-10-28). For the template case br2 (site 201) is put on the feature device template branch-b. The
variables and intended configurations are built here with documentation addresses (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24); the TLOCs are device_omp_tlocs_received_hub1 with br1's rows added.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import sitexport as sx
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.inventory import config_mode, policy_group_of
from cat_sdwan_mcp.spec import match_operation

from .conftest import W8_TEST_GROUP, fixture
from .test_inventory import call, mock_inventory
from .test_policy import mock_policies

BR1 = "REDACTED-16"
BR2 = "REDACTED-22"
PG = "00000000-0000-4000-8000-00000000a001"
TPL = "00000000-0000-4000-8000-00000000b001"
SECRET = "Sup3rS3cret!"
CLI_PROFILE = "00000000-0000-4000-8000-000000001038"
CLI_PARCEL = "00000000-0000-4000-8000-000000001039"
CLI_PARCEL_PATH = f"/dataservice/v1/feature-profile/sdwan/cli/{CLI_PROFILE}/config/{CLI_PARCEL}"
# An add-on whose lines are all in INTENDED_BR1 (no warning).
ADDON_IN_INTENDED = "interface GigabitEthernet3\n description LAN (VPN 10)\n vrf forwarding 10\n"

INTENDED_BR1 = """no config
config
  sdwan
   interface GigabitEthernet1
    tunnel-interface
     encapsulation ipsec
     color mpls restrict
    exit
   exit
   interface GigabitEthernet2
    tunnel-interface
     encapsulation ipsec
     color biz-internet
    exit
   exit
   omp
    no shutdown
   !
  !
  hostname br1
  username admin privilege 15 secret 9 $9$abcdefghijklmnop
  vrf definition 10
   rd 1:10
  !
  vrf definition Mgmt-intf
  !
  interface GigabitEthernet1
   description mpls transport
   ip address 192.0.2.14 255.255.255.0
  exit
  interface GigabitEthernet2
   ip address 198.51.100.14 255.255.255.0
  exit
  interface GigabitEthernet3
   description LAN (VPN 10)
   vrf forwarding 10
   ip address 203.0.113.1 255.255.255.0
  exit
  interface GigabitEthernet4
   vrf forwarding Mgmt-intf
   ip address 198.51.100.200 255.255.255.0
  exit
"""


def _profiles(api: respx.MockRouter) -> None:
    groups = fixture("v1_config_group_w8")
    api.get("/dataservice/v1/config-group").respond(json=groups)
    test = next(g for g in groups if g["id"] == W8_TEST_GROUP)
    api.get(f"/dataservice/v1/config-group/{W8_TEST_GROUP}").respond(json=test)
    system = fixture("v1_feature_profile_system_detail")
    system["associatedProfileParcels"].append(
        {
            "parcelId": "parcel-aaa",
            "parcelType": "aaa",
            "payload": {
                "name": "aaa",
                "data": {
                    "user": [
                        {
                            "name": {"optionType": "global", "value": "ops"},
                            "password": {"optionType": "global", "value": SECRET},
                        }
                    ]
                },
            },
        }
    )
    bodies = {
        "service": {
            "profileName": "mcp-w8-service",
            "profileType": "service",
            "associatedProfileParcels": [],
        },
        "transport": fixture("v1_feature_profile_transport_detail"),
        "system": system,
        "cli": fixture("v1_feature_profile_cli_detail"),
    }
    for p in test["profiles"]:
        api.get(f"/dataservice/v1/feature-profile/sdwan/{p['type']}/{p['id']}").respond(
            json=bodies[p["type"]]
        )


def _tlocs() -> dict[str, Any]:
    """The recording with br1's TLOCs at documentation addresses, each received twice (from two peers)."""
    body = fixture("device_omp_tlocs_received_hub1")
    public = {"mpls": "192.0.2.14", "biz-internet": "198.51.100.14"}
    for row in body["data"]:
        if row["ip"] == "10.0.0.2":
            row["tloc-public-ip"] = row["tloc-private-ip"] = public[row["color"]]
    copies = [dict(r, **{"from-peer": "1.1.1.4"}) for r in body["data"] if r["ip"] == "10.0.0.2"]
    body["data"] += copies
    return body


def _cli_parcel(cli: str) -> dict[str, Any]:
    """The recorded config parcel (v1_feature_profile_cli_config_parcel) with `cli` as its text."""
    body = copy.deepcopy(fixture("v1_feature_profile_cli_config_parcel"))
    body["payload"]["data"]["config"] = cli
    return body


def mock_site(
    api: respx.MockRouter,
    *,
    tlocs: bool = True,
    cli: str = ADDON_IN_INTENDED,
    intended: str = INTENDED_BR1,
    extra_vars: list[dict[str, Any]] | None = None,
) -> respx.Route:
    mock_inventory(api, br1={"managed-by": "Config-Group mcp-test, Policy-Group mcp-pg"})
    _profiles(api)
    parcel = api.get(CLI_PARCEL_PATH).respond(json=_cli_parcel(cli))
    api.get(f"/dataservice/v1/config-group/{W8_TEST_GROUP}/device/variables").respond(
        json={
            "family": "sdwan",
            "groups": [],
            "devices": [
                {
                    "device-id": BR1,
                    "variables": [
                        {"name": "host_name", "value": "br1"},
                        {"name": "site_id", "value": 200},
                        {"name": "mpls_ip", "value": "192.0.2.14"},
                        {"name": "ipsec_pre_shared_key", "value": SECRET},
                        {"name": "snmp_community", "value": SECRET},
                        {"name": "admin_password"},
                        *(extra_vars or []),
                    ],
                }
            ],
        }
    )
    api.get(f"/dataservice/template/config/attached/{BR1}").respond(json={"config": intended})
    mock_policies(api, active=True)
    api.get("/dataservice/v1/policy-group").respond(
        json=[
            {
                "id": PG,
                "name": "mcp-pg",
                "solution": "sdwan",
                "profiles": [{"id": "pp1", "name": "Default_Policy_Object_Profile", "type": "policy-object"}],
                "numberOfDevices": 1,
                "numberOfDevicesUpToDate": 1,
            },
            {"id": "pg-empty", "name": "unused", "numberOfDevices": 0},
        ]
    )
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    api.get(f"/dataservice/v1/policy-group/{PG}/device/associate").respond(json={"devices": [rows[BR1]]})
    if tlocs:
        api.get("/dataservice/device/omp/tlocs/received").respond(json=_tlocs())
    else:
        api.get("/dataservice/device/omp/tlocs/received").respond(500, json={"error": {"message": "boom"}})
    return parcel


def _all_strings(v: Any) -> list[str]:
    if isinstance(v, dict):
        return [s for x in v.values() for s in _all_strings(x)]
    if isinstance(v, list):
        return [s for x in v for s in _all_strings(x)]
    return [str(v)]


async def test_export_config_group_site(api: respx.MockRouter) -> None:
    mock_site(api)
    out = await call("catsdwan_export_site", {"site": "SITE_200", "include_config": True})
    assert out["kind"] == "cat-sdwan-twin-site" and out["spec_version"] == 1
    assert out["site"] == {"id": "200", "name": "SITE_200"} and out["mode"] == "configuration group"
    assert out["source"]["manager_release"] == "20.18.3.1"
    (br1,) = out["devices"]
    assert br1["host"] == "br1" and br1["config_group"] == "mcp-test" and br1["chassis"] == BR1
    # transports from the intended configuration, TLOCs from the controller
    assert br1["transports"] == [
        {
            "interface": "GigabitEthernet1",
            "colour": "mpls",
            "restrict": True,
            "encap": "ipsec",
            "address": "192.0.2.14/24",
        },
        {
            "interface": "GigabitEthernet2",
            "colour": "biz-internet",
            "encap": "ipsec",
            "address": "198.51.100.14/24",
        },
    ]
    assert [t["colour"] for t in br1["tlocs"]] == ["biz-internet", "mpls"]
    assert br1["tlocs"][1]["public"] == "192.0.2.14:12426"
    assert br1["service_vpns"] == [
        {
            "vpn": 10,
            "interfaces": [
                {"interface": "GigabitEthernet3", "address": "203.0.113.1/24", "description": "LAN (VPN 10)"}
            ],
        }
    ]
    assert out["colours"] == ["biz-internet", "mpls"] and out["service_vpns"] == [
        {"vpn": 10, "devices": ["br1"]}
    ]
    # variables: values kept, secrets as refs, an empty secret left empty
    v = br1["variables"]
    assert v["host_name"] == "br1" and v["site_id"] == 200 and v["mpls_ip"] == "192.0.2.14"
    assert v["ipsec_pre_shared_key"] == {"secret_ref": "br1/ipsec_pre_shared_key"}
    assert v["snmp_community"] == {"secret_ref": "br1/snmp_community"}
    assert v["admin_password"] is None
    # the configuration group with its profiles; the parcel password is a ref too
    (group,) = out["config_groups"]
    assert group["name"] == "mcp-test" and group["id"] == W8_TEST_GROUP
    profiles = {p["type"]: p for p in group["feature_profiles"]}
    assert set(profiles) == {"service", "transport", "system", "cli"}
    assert profiles["cli"]["parcels"][0]["cli"] == ADDON_IN_INTENDED.rstrip("\n")
    assert "cli_addon_not_in_intended" not in br1
    aaa = next(p for p in profiles["system"]["parcels"] if p.get("name") == "aaa")
    assert aaa["values"]["user[0].password"] == {
        "secret_ref": "config-group/mcp-test/mcp-test-system/user/0/password"
    }
    refs = {s["ref"] for s in out["secrets"]}
    assert refs == {
        "br1/ipsec_pre_shared_key",
        "br1/snmp_community",
        "config-group/mcp-test/mcp-test-system/user/0/password",
    }
    # policy: the policy group of the site's edge, and the activated policy's parts touching site 200
    (pg,) = out["policy_groups"]
    assert (
        pg["name"] == "mcp-pg" and pg["devices"] == ["br1"] and pg["profiles"][0]["type"] == "policy-object"
    )
    pol = out["centralised_policy"]
    assert pol["name"] == "mcp-test-policy" and pol["parts_not_touching_site"] == 0
    assert pol["parts"][0]["type"] == "application-aware routing"
    assert "mcp-test-sites" in pol["parts"][0]["sites"][0]
    # the intended configuration is masked, and no secret value appears anywhere
    assert "$9$abcdefghijklmnop" not in br1["intended_config"]
    assert not [s for s in _all_strings(out) if SECRET in s or "$9$abcdefghijklmnop" in s]
    assert out["devices"][0].get("policy_group") is None  # the policy group is in policy_groups
    assert "warnings" not in out


# The firewall leg the add-on adds (#166): the Manager's intended text has the interface as only
# 'no shutdown / negotiation auto', as recorded on br1 in the W55 proof (2026-10-28).
ADDON_FW = """banner motd ^Cmcp twin branch^C
ip access-list extended mcp-contain
 10 deny ip any host 203.0.113.66
 20 permit ip any any
interface GigabitEthernet5
 description firewall leg (VPN 10)
 vrf forwarding 10
 ip address {{fw_ip}} 255.255.255.252
 ip access-group mcp-contain in
username ops privilege 15 secret 9 $9$zyxwvutsrqponmlk
snmp-server community {{snmp_community}} RO
"""


async def test_export_includes_the_cli_addon(api: respx.MockRouter) -> None:
    intended = INTENDED_BR1 + "  interface GigabitEthernet5\n   no shutdown\n   negotiation auto\n  exit\n"
    parcel = mock_site(
        api, cli=ADDON_FW, intended=intended, extra_vars=[{"name": "fw_ip", "value": "203.0.113.9"}]
    )
    out = await call("catsdwan_export_site", {"site": "200", "include_config": True})
    assert parcel.called
    (br1,) = out["devices"]
    # the add-on's interface is in VPN 10 with its rendered address
    (vpn10,) = br1["service_vpns"]
    assert vpn10["vpn"] == 10
    assert vpn10["interfaces"] == [
        {"interface": "GigabitEthernet3", "address": "203.0.113.1/24", "description": "LAN (VPN 10)"},
        {
            "interface": "GigabitEthernet5",
            "address": "203.0.113.9/30",
            "description": "firewall leg (VPN 10)",
        },
    ]
    assert [t["interface"] for t in br1["transports"]] == ["GigabitEthernet1", "GigabitEthernet2"]
    # the parcel's CLI text: masked, {{variables}} kept (a secret variable is never filled in)
    (group,) = out["config_groups"]
    cli_profile = next(p for p in group["feature_profiles"] if p["type"] == "cli")
    (cfg,) = cli_profile["parcels"]
    assert cfg["name"] == "mcp-test-config" and "values" not in cfg
    assert "ip address {{fw_ip}} 255.255.255.252" in cfg["cli"]
    assert (
        "ip access-list extended mcp-contain" in cfg["cli"] and "ip access-group mcp-contain in" in cfg["cli"]
    )
    assert "snmp-server community {{snmp_community}} RO" in cfg["cli"]
    assert "secret 9 ********" in cfg["cli"]
    assert not [s for s in _all_strings(out) if "$9$zyxwvutsrqponmlk" in s or SECRET in s]
    # the lines the intended text lacks are counted and named; the twin is told to apply the add-on
    assert br1["cli_addon_not_in_intended"] >= 6
    (warning,) = out["warnings"]
    assert warning.startswith("br1: ") and "mcp-test-cli" in warning and "banner motd" in warning
    assert "{{" not in warning and SECRET not in warning
    assert any("parcels[].cli" in n for n in out["twin_notes"])
    assert out["service_vpns"] == [{"vpn": 10, "devices": ["br1"]}]


async def test_export_cli_addon_rendered_secret_is_masked(api: respx.MockRouter) -> None:
    # a variable whose name is not a secret name, used after `secret` / `password` in the add-on
    addon = "username ops privilege 15 secret 0 {{pw}}\nline vty 0 4\n password {{pw}}\n"
    mock_site(api, cli=addon, extra_vars=[{"name": "pw", "value": "Plain1Value"}])
    out = await call("catsdwan_export_site", {"site": "200"})
    (warning,) = out["warnings"]
    assert "Plain1Value" not in warning and "secret 0 ********" in warning


async def test_export_cli_parcel_read_failure_is_a_warning(api: respx.MockRouter) -> None:
    mock_site(api)
    api.get(CLI_PARCEL_PATH).respond(500, json={"error": {"message": "boom"}})
    out = await call("catsdwan_export_site", {"site": "200"})
    assert any("CLI parcel mcp-test-cli/mcp-test-config: not read" in w for w in out["warnings"])
    cfg = next(p for p in out["config_groups"][0]["feature_profiles"] if p["type"] == "cli")["parcels"][0]
    assert "cli" not in cfg
    assert not any("parcels[].cli" in n for n in out["twin_notes"])
    assert out["devices"][0]["service_vpns"][0]["vpn"] == 10


async def test_export_tloc_failure_is_a_warning(api: respx.MockRouter) -> None:
    mock_site(api, tlocs=False)
    out = await call("catsdwan_export_site", {"site": "200"})
    assert "tlocs" not in out["devices"][0] and "intended_config" not in out["devices"][0]
    assert any("live TLOCs not read" in w for w in out["warnings"])
    assert out["colours"] == ["biz-internet", "mpls"]  # from the intended configuration


async def test_export_template_site(api: respx.MockRouter) -> None:
    mock_inventory(
        api, br2={"managed-by": "Unmanaged", "configOperationMode": "vmanage", "template": "branch-b"}
    )
    templates = fixture("template_device")
    templates["data"].append(
        {
            "templateId": TPL,
            "templateName": "branch-b",
            "configType": "template",
            "deviceType": "vedge-C8000V",
        }
    )
    api.get("/dataservice/template/device").respond(json=templates)
    inp = api.post("/dataservice/template/device/config/input").respond(
        json={
            "header": {"columns": []},
            "data": [
                {
                    "csv-status": "complete",
                    "csv-deviceId": BR2,
                    "csv-deviceIP": "10.0.0.3",
                    "csv-host-name": "br2",
                    "//system/host-name": "br2",
                    "//system/site-id": "201",
                    "/0/GigabitEthernet1/interface/ip/address": "192.0.2.15/24",
                    "/0/vpn-instance/ipsec/ike/authentication-type/pre-shared-key/pre-shared-secret": SECRET,
                    "{{ike_key}}": SECRET,
                }
            ],
        }
    )
    api.get(f"/dataservice/template/config/attached/{BR2}").respond(
        json={"config": INTENDED_BR1.replace("hostname br1", "hostname br2")}
    )
    mock_policies(api, active=False)
    api.get("/dataservice/device/omp/tlocs/received").respond(json=fixture("device_omp_tlocs_received_hub1"))
    out = await call("catsdwan_export_site", {"site": "201"})
    assert out["mode"] == "template" and out["config_groups"] == []
    (tpl,) = out["device_templates"]
    assert tpl == {"name": "branch-b", "id": TPL, "kind": "feature", "device_type": "vedge-C8000V"}
    body = json.loads(inp.calls[0].request.content)
    assert body == {"templateId": TPL, "deviceIds": [BR2], "isEdited": False, "isMasterEdited": False}
    (br2,) = out["devices"]
    assert br2["device_template"] == "branch-b" and br2["config_mode"] == "template"
    v = br2["variables"]
    assert v["//system/site-id"] == "201" and "csv-status" not in v
    assert v["{{ike_key}}"] == {"secret_ref": "br2/ike_key"}
    assert v["/0/vpn-instance/ipsec/ike/authentication-type/pre-shared-key/pre-shared-secret"] == {
        "secret_ref": "br2/pre-shared-secret"
    }
    assert out["centralised_policy"] is None and out["policy_groups"] == []
    assert [t["colour"] for t in br2["tlocs"]] == ["biz-internet", "mpls"]
    assert br2["transports"][0]["colour"] == "mpls"
    assert not [s for s in _all_strings(out) if SECRET in s]


async def test_export_unknown_site(api: respx.MockRouter) -> None:
    mock_inventory(api)
    with pytest.raises(ToolError, match=r"No WAN edge at site '999'.*100, 200, 201"):
        await call("catsdwan_export_site", {"site": "999"})


# --- pure helpers --------------------------------------------------------------------------------


def test_policy_group_in_managed_by() -> None:
    rec = {"managed-by": "Config-Group mcp-test, Policy-Group mcp-w8-pg", "configOperationMode": "cli"}
    assert config_mode(rec) == ("configuration group", "mcp-test")
    assert policy_group_of(rec) == "mcp-w8-pg"
    assert policy_group_of({"managed-by": "Config-Group mcp-test"}) is None
    assert policy_group_of(None) is None


def test_secret_names() -> None:
    for name in (
        "ipsec_key",
        "ike-key",
        "admin_password",
        "snmp_community",
        "{{psk}}",
        "//x/pre-shared-secret",
    ):
        assert sx.secret_name(name), name
    for name in ("site_id", "host_name", "mpls_ip", "keyword", "//system/host-name", "encryption"):
        assert not sx.secret_name(name), name


def test_scrub_masks_leftover_secret_values_and_keeps_refs() -> None:
    spec = {"a": {"password": "x", "ref": {"secret_ref": "br1/password"}, "key_count": 2}, "community": ""}
    assert sx.scrub(spec) == {
        "a": {"password": "********", "ref": {"secret_ref": "br1/password"}, "key_count": 2},
        "community": "",
    }


def test_parts_for_site_keeps_only_entries_naming_the_site() -> None:
    lists = {
        "L1": {"type": "site", "entries": [{"siteId": "100"}]},
        "L2": {"type": "site", "entries": [{"siteId": "200-210"}]},
    }
    parts = [
        {"definitionId": "d1", "type": "data", "entries": [{"siteLists": ["L1"]}, {"siteLists": ["L2"]}]},
        {"definitionId": "d2", "type": "control", "entries": [{"siteLists": ["L1"]}]},
        {"definitionId": "d3", "type": "appRoute", "entries": [{"vpnLists": ["V"]}]},
    ]
    mine = sx.parts_for_site(parts, "205", lists)
    assert [p["definitionId"] for p in mine] == ["d1", "d3"]
    assert mine[0]["entries"] == [{"siteLists": ["L2"]}]


def test_parse_intended_running_style_and_no_sdwan() -> None:
    text = (
        "sdwan\n interface Gi1\n  tunnel-interface\n   encapsulation gre\n   encapsulation ipsec\n"
        "interface Gi1\n ip address 192.0.2.1 255.255.255.252\n"
    )
    got = sx.parse_intended(text)
    assert got["transports"] == [
        {"interface": "Gi1", "colour": "default", "encap": "gre, ipsec", "address": "192.0.2.1/30"}
    ]
    assert sx.parse_intended("hostname x\n") == {"transports": [], "service_vpns": []}


def test_render_cli_and_missing_lines() -> None:
    text = "interface Gi5\n ip address {{ip}} 255.255.255.0\n description {{desc}}\n shutdown {{flag}}\n"
    got = sx.render_cli(text, {"ip": "192.0.2.5", "desc": {"secret_ref": "x"}, "flag": False})
    assert (
        got == "interface Gi5\n ip address 192.0.2.5 255.255.255.0\n description {{desc}}\n shutdown false\n"
    )
    intended = "  interface Gi5\n   ip address 192.0.2.5 255.255.255.0\n  exit\n"
    assert sx.missing_from(got, intended) == ["interface Gi5 / shutdown false"]


def test_parse_addon_wins_and_vrfs_are_not_repeated() -> None:
    base = "vrf definition 10\ninterface Gi3\n vrf forwarding 20\n ip address 192.0.2.1 255.255.255.0\n"
    addon = "vrf definition 10\ninterface Gi3\n vrf forwarding 10\n ip address 198.51.100.1 255.255.255.0\n"
    got = sx.parse_intended(base, addon)
    assert got["service_vpns"] == [
        {"vpn": 10, "interfaces": [{"interface": "Gi3", "address": "198.51.100.1/24"}]}
    ]


def test_paths_are_in_the_bundled_spec() -> None:
    index = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    for method, p in (
        ("GET", "/dataservice/v1/config-group/{configGroupId}/device/variables"),
        ("GET", "/dataservice/v1/policy-group/{policyGroupId}/device/associate"),
        ("POST", "/dataservice/template/device/config/input"),
        ("GET", "/dataservice/template/config/attached/{deviceId}"),
        ("GET", "/dataservice/template/policy/vsmart/definition/{policyId}"),
        ("GET", "/dataservice/v1/feature-profile/sdwan/transport/{transportId}"),
        ("GET", "/dataservice/v1/feature-profile/sdwan/cli/{cliId}/config/{configId}"),
    ):
        _, methods = match_operation(index, method, p.replace("{", "").replace("}", ""))
        assert method in methods, p
