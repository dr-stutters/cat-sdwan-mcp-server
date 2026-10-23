"""W7: configuration groups, policy groups, templates and device configurations on recorded 20.18.3.1
payloads.

The lab's group `mcp-test` has hub1 and br1 associated, no feature profiles and was never deployed; br2 is
in CLI mode with a CLI device template `mcp-test-br2` that is not attached. The recordings were redacted file
by file, so the copies here use the chassis numbers of system_device_vedges.json (associate: hub1 REDACTED-17,
br1 REDACTED-16; br2's intended config: REDACTED-22). template_feature.json keeps 8 of the 127 factory-default
feature templates (one per type, device-model lists cut to 8, definitions dropped). A group with feature
profiles and variables is built here in the spec's shape (getSingleSdwanSystemPayload) since the lab has none.
"""

import copy
import json
from typing import Any

import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import configuration
from cat_sdwan_mcp._core.spec import build_index
from cat_sdwan_mcp.configuration import blocks, config_diff, mask_config, sections
from cat_sdwan_mcp.spec import match_operation

from .conftest import fixture
from .test_inventory import call, mock_inventory

GID = "00000000-0000-4000-8000-000000000124"
GROUP = f"/dataservice/v1/config-group/{GID}"
RUNNING_BR2 = "/dataservice/template/config/running/REDACTED-22"
INTENDED_BR2 = "/dataservice/template/config/attached/REDACTED-22"


def mock_groups(api: respx.MockRouter, *, group: dict[str, Any] | None = None) -> None:
    rec = group or fixture("v1_config_group_detail")
    api.get("/dataservice/v1/config-group").respond(json=[rec])
    api.get(GROUP).respond(json=rec)
    api.get(f"{GROUP}/device/associate").respond(json=fixture("v1_config_group_associate"))


# --- configuration groups ------------------------------------------------------------------------


async def test_list_config_groups(api: respx.MockRouter) -> None:
    mock_groups(api)
    out = await call("catsdwan_list_config_groups", {"response_format": "json"})
    (row,) = out["results"]
    assert row["name"] == "mcp-test" and row["solution"] == "sdwan" and row["profiles"] == "none"
    assert row["devices"] == 2 and row["up_to_date"] == "0/2"
    assert row["deploy_state"].startswith("not deployed")
    assert row["device_names"] == "br1, hub1"
    assert row["last_updated_by"] == "admin" and row["last_updated"].endswith("Z")


async def test_list_config_groups_associate_failure_is_a_warning(api: respx.MockRouter) -> None:
    api.get("/dataservice/v1/config-group").respond(json=fixture("v1_config_group"))
    api.get(f"{GROUP}/device/associate").respond(500, json={"error": {"message": "boom"}})
    out = await call("catsdwan_list_config_groups", {"response_format": "json"})
    assert "device_names" not in out["results"][0] and "devices not read" in out["warnings"][0]


async def test_get_config_group_lab(api: respx.MockRouter) -> None:
    mock_groups(api)
    variables = api.get(f"{GROUP}/device/variables").respond(
        400, json={"error": {"message": "Invalid request"}}
    )
    out = await call("catsdwan_get_config_group", {"group": "MCP-TEST"})
    assert out["name"] == "mcp-test" and out["config_mode"] == "configuration group"
    assert out["feature_profiles_note"] == "the group has no feature profiles yet"
    devs = {d["host"]: d for d in out["associated_devices"]}
    assert devs["hub1"]["chassis"] == "REDACTED-17" and devs["hub1"]["config_status"] == "In Sync"
    assert devs["br1"]["group_up_to_date"] is False and devs["br1"]["deployable"] is True
    assert variables.calls[0].request.url.params["device-id"] == "REDACTED-16,REDACTED-17"
    assert "device variables not read" in out["warnings"][0]


async def test_get_config_group_did_you_mean(api: respx.MockRouter) -> None:
    mock_groups(api)
    with pytest.raises(ToolError, match="Did you mean: mcp-test"):
        await call("catsdwan_get_config_group", {"group": "mcp-tset"})


SYSTEM_PROFILE = {
    "profileId": "prof-sys",
    "profileName": "branch-system",
    "profileType": "system",
    "solution": "sdwan",
    "lastUpdatedBy": "admin",
    "lastUpdatedOn": 1792743023024,
    "associatedProfileParcels": [
        {
            "parcelId": "parcel-basic",
            "parcelType": "basic",
            "payload": {
                "name": "basic",
                "data": {
                    "timezone": {"optionType": "global", "value": "UTC"},
                    "trackTransport": {"optionType": "default", "value": True},
                    "siteId": {"optionType": "variable", "value": "{{site_id}}"},
                },
            },
        },
        {
            "parcelId": "parcel-aaa",
            "parcelType": "aaa",
            "payload": {
                "name": "aaa",
                "data": {
                    "user": [
                        {
                            "name": {"optionType": "global", "value": "ops"},
                            "password": {"optionType": "global", "value": "Sup3rS3cret!"},
                        }
                    ]
                },
            },
            "subparcels": [],
        },
    ],
}


async def test_get_config_group_with_profiles_and_variables(api: respx.MockRouter) -> None:
    group = copy.deepcopy(fixture("v1_config_group_detail"))
    group["profiles"] = [
        {"id": "prof-sys", "name": "branch-system", "type": "system", "solution": "sdwan"},
        {"id": "prof-x", "name": "mystery", "type": "application-priority", "solution": "sdwan"},
    ]
    mock_groups(api, group=group)
    api.get("/dataservice/v1/feature-profile/sdwan/system/prof-sys").respond(json=SYSTEM_PROFILE)
    api.get(f"{GROUP}/device/variables").respond(
        json={
            "family": "cedge",
            "devices": [
                {
                    "device-id": "REDACTED-17",
                    "variables": [
                        {"name": "site_id", "value": "100"},
                        {"name": "admin_password", "value": "Hunter2!"},
                    ],
                }
            ],
        }
    )
    out = await call("catsdwan_get_config_group", {"group": GID})
    assert out["profiles"] == "branch-system (system), mystery (application-priority)"
    system, other = out["feature_profiles"]
    assert system["variables"] == ["{{site_id}}"]
    basic, aaa = system["parcels"]
    assert basic["values"] == {"timezone": "UTC", "siteId": "{{{{site_id}}}}"}
    assert aaa["values"]["user[0].name"] == "ops" and aaa["values"]["user[0].password"] == "********"
    assert "not read" in other["note"]
    devs = {d["host"]: d for d in out["associated_devices"]}
    assert devs["hub1"]["variables"] == {"site_id": "100", "admin_password": "********"}
    assert "variables" not in devs["br1"]
    text = json.dumps(out)
    assert "Sup3rS3cret" not in text and "Hunter2" not in text


# --- policy groups -------------------------------------------------------------------------------


async def test_list_policy_groups_empty(api: respx.MockRouter) -> None:
    api.get("/dataservice/v1/policy-group").respond(json=fixture("v1_policy_group"))
    out = await call("catsdwan_list_policy_groups", {"response_format": "json"})
    assert out["results"] == [] and out["note"] == "No policy groups on this Manager."


async def test_list_policy_groups(api: respx.MockRouter) -> None:
    rec = {**fixture("v1_config_group_detail"), "name": "branch-policy", "state": "DEPLOYED"}
    api.get("/dataservice/v1/policy-group").respond(json=[rec])
    out = await call("catsdwan_list_policy_groups", {"name": "branch", "response_format": "json"})
    assert out["results"][0]["name"] == "branch-policy" and out["results"][0]["deploy_state"] == "DEPLOYED"


# --- templates -----------------------------------------------------------------------------------


async def test_list_device_templates_hides_defaults(api: respx.MockRouter) -> None:
    route = api.get("/dataservice/template/device").respond(json=fixture("template_device"))
    out = await call("catsdwan_list_templates", {"response_format": "json"})
    (row,) = out["results"]
    assert row["name"] == "mcp-test-br2" and row["kind"] == "CLI" and row["device_type"] == "vedge-C8000V"
    assert row["devices_attached"] == 0 and "attached_to" not in row
    assert out["factory_defaults_hidden"] == 17
    assert route.calls[0].request.url.params["feature"] == "all"
    every = await call("catsdwan_list_templates", {"include_defaults": True, "response_format": "json"})
    assert every["total"] == 18


async def test_list_device_templates_names_attached_devices(api: respx.MockRouter) -> None:
    body = fixture("template_device")
    body["data"][0]["devicesAttached"] = 1
    api.get("/dataservice/template/device").respond(json=body)
    tid = body["data"][0]["templateId"]
    api.get(f"/dataservice/template/device/config/attached/{tid}").respond(
        json={"data": [{"host-name": "br2", "deviceIP": "10.0.0.3", "uuid": "REDACTED-22"}]}
    )
    out = await call("catsdwan_list_templates", {"attached_only": True, "response_format": "json"})
    assert out["results"][0]["attached_to"] == "br2"


async def test_list_feature_templates(api: respx.MockRouter) -> None:
    api.get("/dataservice/template/feature").respond(json=fixture("template_feature"))
    hidden = await call("catsdwan_list_templates", {"type": "feature", "response_format": "json"})
    assert hidden["results"] == [] and hidden["factory_defaults_hidden"] == 8
    out = await call(
        "catsdwan_list_templates",
        {"type": "feature", "include_defaults": True, "device_type": "c8000v", "response_format": "json"},
    )
    rows = {r["name"]: r for r in out["results"]}
    vpn = rows["Default_Azure_vWAN_C8000V_VPN0_INTF_GE2_V01"]
    assert vpn["type"] == "cisco_vpn_interface" and vpn["factory_default"] is True
    every = await call(
        "catsdwan_list_templates", {"type": "feature", "include_defaults": True, "response_format": "json"}
    )
    boot = next(r for r in every["results"] if r["name"] == "Default_BootStrap_Cisco_Static_VPN_Template")
    assert boot["device_types"].endswith("(+3 more)")


# --- device configuration ------------------------------------------------------------------------


async def test_get_device_config_running(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(RUNNING_BR2).respond(json=fixture("template_config_running_br2"))
    out = await call("catsdwan_get_device_config", {"device": "br2"})
    assert out["host"] == "br2" and out["chassis"] == "REDACTED-22" and out["config_mode"] == "cli"
    assert out["mode_note"].startswith("CLI mode")
    assert (
        "hostname br2" in out["config"]
        and out["source"] == "GET /dataservice/template/config/running/{chassis}"
    )


async def test_get_device_config_masks_real_secrets(api: respx.MockRouter) -> None:
    mock_inventory(api)
    body = fixture("template_config_running_br2")
    body["config"] = body["config"].replace(
        "username admin privilege 15 secret 9 <redacted>",
        "username admin privilege 15 secret 9 $9$synthetic.hash\nenable secret 5 $1$abc\n"
        "snmp-server community Publ1cRO RO\n"
        "snmp-server user mon grp v3 auth sha AuthKey1 priv aes 128 PrivKey1\n"
        "key chain K\n key 1\n  key-string 7 0822455D0A16\ncrypto isakmp key Psk-Value address 0.0.0.0",
    )
    api.get(RUNNING_BR2).respond(json=body)
    out = await call("catsdwan_get_device_config", {"device": "10.0.0.3"})
    text = out["config"]
    for secret in (
        "synthetic.hash",
        "$1$abc",
        "Publ1cRO",
        "AuthKey1",
        "PrivKey1",
        "0822455D0A16",
        "Psk-Value",
    ):
        assert secret not in text
    assert "snmp-server community ******** RO" in text and "key chain K" in text
    assert out["masked_lines"] == 6


async def test_get_device_config_intended_and_section(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(INTENDED_BR2).respond(json=fixture("template_config_attached_br2"))
    out = await call(
        "catsdwan_get_device_config", {"device": "br2", "source": "intended", "section": "system"}
    )
    assert out["config"].startswith("system\n") and "chassis-number" not in out["config"]
    assert "system-ip 10.0.0.3" in out["config"] and "hostname" not in out["config"]


async def test_get_device_config_diff_in_lab(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(RUNNING_BR2).respond(json=fixture("template_config_running_br2"))
    api.get(INTENDED_BR2).respond(json=fixture("template_config_attached_br2"))
    out = await call("catsdwan_get_device_config", {"device": "br2", "diff": True})
    d = out["diff"]
    # Same configuration in two renderings: only the default lines the device hides differ.
    assert d["only_intended"] == [
        "no ip dhcp use class-deprecated",
        "no ip forward-protocol udp",
        "no ip http ctc authentication",
        "no crypto isakmp diagnose error",
    ]
    assert "only_on_device" not in d and "changed" not in d and "config" not in out


async def test_get_device_config_diff_shows_a_hand_change(api: respx.MockRouter) -> None:
    mock_inventory(api)
    running = fixture("template_config_running_br2")
    running["config"] = (
        running["config"].replace(" description LAN (VPN 10) to host-br2", " description changed by hand")
        + "ip domain name example.test\n"
    )
    api.get(RUNNING_BR2).respond(json=running)
    api.get(INTENDED_BR2).respond(json=fixture("template_config_attached_br2"))
    out = await call("catsdwan_get_device_config", {"device": "br2", "diff": True})
    d = out["diff"]
    assert d["in_sync"] is False and d["only_on_device"] == ["ip domain name example.test"]
    assert d["changed"] == {
        "interface GigabitEthernet3": [
            "-description changed by hand",
            "+description LAN (VPN 10) to host-br2",
        ]
    }
    only_int = await call(
        "catsdwan_get_device_config", {"device": "br2", "diff": True, "section": "interface"}
    )
    assert "only_on_device" not in only_int["diff"] or only_int["diff"]["only_on_device"] == []


async def test_get_device_config_group_mode(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/template/config/running/REDACTED-17").respond(json={"config": ""})
    out = await call("catsdwan_get_device_config", {"device": "hub1"})
    assert out["config_mode"] == "configuration group" and out["config_name"] == "mcp-test"
    assert "overwrites" in out["mode_note"] and "returned no running" in out["note"]


async def test_get_device_config_unknown_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    with pytest.raises(ToolError, match="Did you mean"):
        await call("catsdwan_get_device_config", {"device": "br3"})


# --- helpers -------------------------------------------------------------------------------------


def test_mask_config_leaves_non_secrets() -> None:
    text = "crypto key generate rsa\nservice password-encryption\nrsa-key-modulus 2048\n tunnel-interface"
    assert mask_config(text) == (text, 0)


def test_blocks_normalise_both_renderings() -> None:
    running = blocks(fixture("template_config_running_br2")["config"])
    intended = blocks(fixture("template_config_attached_br2")["config"])
    assert running["system"] == intended["system"]  # personality / device-model / chassis-number dropped
    assert running["sdwan"] == intended["sdwan"]
    assert "exit" not in running and "config" not in intended


def test_config_diff_in_sync_and_sections() -> None:
    text = fixture("template_config_running_br2")["config"]
    assert config_diff(text, text)["in_sync"] is True
    assert (
        sections(text, "vrf definition 10")
        == "vrf definition 10\n rd 1:10\n address-family ipv4\n  exit-address-family"
    )


@pytest.mark.parametrize(
    "template",
    [
        configuration.CONFIG_GROUPS_PATH,
        configuration.CONFIG_GROUP_PATH,
        configuration.ASSOCIATE_PATH,
        configuration.VARIABLES_PATH,
        configuration.POLICY_GROUPS_PATH,
        configuration.PROFILE_PATH.replace("{type}", "system"),
        configuration.DEVICE_TEMPLATES_PATH,
        configuration.FEATURE_TEMPLATES_PATH,
        configuration.TEMPLATE_DEVICES_PATH,
        configuration.RUNNING_PATH,
        configuration.INTENDED_PATH,
    ],
)
def test_every_read_is_a_get_in_the_spec(template: str) -> None:
    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    concrete = template.replace("{id}", "x")
    best, methods = match_operation(idx, "GET", concrete)
    assert "GET" in methods and best.count("/") == concrete.count("/")
