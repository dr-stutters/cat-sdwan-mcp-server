"""W9: edge onboarding (WAN edge list, bootstrap, onboard, validity) on the recorded 20.18.3.1 WAN edge list.

The recorded /system/device/vedges has 25 C8000V slots: hub1, br1 and br2 joined (certinstalled, org
mcp-lab-org), 22 never joined (tokengenerated, serialNumber = the one-time token; redacted REDACTED-nn).
The bootstrap shape is the lab Manager's; the validity save/push and association bodies follow Cisco's
documentation (not recorded yet).
"""

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp import onboarding as ob
from cat_sdwan_mcp.tools import changes as change_tools

from .conftest import fixture, make_server
from .test_changes import GROUP, STATUS, mock_group, status_body
from .test_inventory import device_body, mock_inventory, vedges_body

SLOT, SLOT_TOKEN = "REDACTED-20", "REDACTED-40"  # the first never-joined slot and its token
BR2, BR2_SERIAL = "REDACTED-22", "REDACTED-48"
NEW = "C8K-00000000-0000-4000-8000-00000000a001"  # a chassis not in the list
VEDGES = "/dataservice/system/device/vedges"
SAVE = "/dataservice/certificate/save/vedge/list"
PUSH = "/dataservice/certificate/vedge/list"
PUSH_ID = "push_vedge_list-1"


def cloud_init(chassis: str = SLOT, token: str = SLOT_TOKEN, org: str = "mcp-lab-org") -> str:
    return (
        "#cloud-config\nvinitparam:\n"
        f" - uuid : {chassis}\n - otp : {token}\n - vbond : 10.60.2.11\n - org : {org}\n - rcc : true\n"
        "ca-certs:\n  remove-defaults: false\n"
    )


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_tools, "POLL_INTERVAL", 0.0)


def slot_edit(**fields: Any) -> dict[str, Any]:
    """The WAN edge list with the first never-joined slot edited."""
    body = vedges_body()
    body["data"][0].update(fields)
    return body


async def run(server: Any, name: str, args: dict[str, Any]) -> Any:
    result = await server.call_tool(name, args)
    return result.structured_content


def writes(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


def slot_variables(chassis: str = SLOT) -> dict[str, Any]:
    names = ["host_name", "system_ip", "site_id", "pseudo_commit_timer", "banner_motd"]
    rows: list[dict[str, Any]] = [{"name": n} for n in names]
    rows[2]["value"] = 0
    rows[3]["value"] = 300
    return {"family": "sdwan", "devices": [{"device-id": chassis, "variables": rows}]}


# --- helpers -------------------------------------------------------------------------------------


def test_edge_row_masks_the_token_and_flags_the_org() -> None:
    rows = vedges_body()["data"]
    slot = ob.edge_row(rows[0], "mcp-lab-org")
    assert slot["token"] == ob.MASK and "serial" not in slot and slot["joined"] is False
    assert SLOT_TOKEN not in json.dumps(slot)
    br2 = next(r for r in rows if r.get("host-name") == "br2")
    row = ob.edge_row(br2, "mcp-lab-org")
    assert row["joined"] is True and row["serial"] == BR2_SERIAL and "token" not in row
    assert row["org"] == "mcp-lab-org" and "org_mismatch" not in row
    assert "org_mismatch" in ob.edge_row(br2, "other-org")


def test_bootstrap_masking_and_params() -> None:
    text = cloud_init()
    masked = ob.mask_otp(text, SLOT_TOKEN)
    assert SLOT_TOKEN not in masked and " - otp : ********" in masked
    assert ob.vinit_params(text) == {
        "uuid": SLOT,
        "otp": SLOT_TOKEN,
        "vbond": "10.60.2.11",
        "org": "mcp-lab-org",
        "rcc": "true",
    }
    assert ob.decode_bootstrap(base64.b64encode(text.encode()).decode()) == text
    assert ob.decode_bootstrap("not base64 !") is None


def test_serial_file_multipart_body() -> None:
    body, ctype = ob.serial_file_body("serial.viptela", b"SIGNED-SERIAL-FILE")
    assert ctype.startswith("multipart/form-data; boundary=")
    text = body.decode()
    assert 'name="file"; filename="serial.viptela"' in text and "SIGNED-SERIAL-FILE" in text
    assert 'name="validity"\r\n\r\nvalid\r\n' in text
    assert 'name="upload"\r\n\r\ntrue\r\n' in text


def test_unjoined_inventory_rows_hide_the_token() -> None:
    from cat_sdwan_mcp.inventory import join_inventory

    inv = join_inventory(device_body()["data"], vedges_body()["data"], None)
    slot = next(r for r in inv.unjoined if r["chassis"] == SLOT)
    assert "board_serial" not in slot and slot["token"] == ob.MASK


# --- catsdwan_list_wan_edges ---------------------------------------------------------------------


async def test_list_wan_edges_masks_tokens(api: respx.MockRouter) -> None:
    mock_inventory(api)
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_list_wan_edges", {"limit": 500, "response_format": "json"})
        joined = await run(c, "catsdwan_list_wan_edges", {"state": "joined", "response_format": "json"})
    assert out["total"] == 25 and out["slots"] == 25 and out["joined"] == 3
    assert out["overlay_org"] == "mcp-lab-org"
    text = json.dumps(out)
    tokens = [v["serialNumber"] for v in vedges_body()["data"] if not v.get("host-name")]
    assert tokens and not any(t in text for t in tokens)
    assert [r["host"] for r in joined["results"]] == ["br1", "br2", "hub1"]
    assert joined["results"][0]["serial"] and joined["results"][0]["org"] == "mcp-lab-org"


async def test_list_wan_edges_flags_an_org_mismatch_and_validity(api: respx.MockRouter) -> None:
    api.get("/dataservice/system/device/controllers").respond(json=fixture("system_device_controllers"))
    api.get(VEDGES).respond(
        json=vedges_body(br2={"organization-name": "someone-else", "validity": "staging"})
    )
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_list_wan_edges", {"state": "staging", "response_format": "json"})
    (br2,) = out["results"]
    assert br2["host"] == "br2" and "someone-else" in br2["org_mismatch"]


# --- catsdwan_bootstrap_config -------------------------------------------------------------------


def mock_bootstrap(api: respx.MockRouter, chassis: str = SLOT, body: str | None = None) -> respx.Route:
    return api.get(f"/dataservice/system/device/bootstrap/device/{chassis}").respond(
        json={"bootstrapConfig": body if body is not None else cloud_init(chassis)}
    )


async def test_bootstrap_masks_the_otp_by_default(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = mock_bootstrap(api)
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_bootstrap_config", {"chassis": SLOT})
    params = route.calls[0].request.url.params
    assert params["configtype"] == "cloudinit" and params["inclDefRootCert"] == "false"
    assert SLOT_TOKEN not in json.dumps(out)
    assert out["vinitparam"]["otp"] == ob.MASK and out["vinitparam"]["vbond"] == "10.60.2.11"
    assert " - otp : ********" in out["bootstrap_config"]
    assert out["activate_command"].endswith(f"chassis-number {SLOT} token <token>")
    assert any("cml_build_lab" in h for h in out["how_to_use"]) and "warnings" not in out


async def test_bootstrap_reveal_returns_the_token_with_a_warning(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_bootstrap(api)
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_bootstrap_config", {"chassis": SLOT, "reveal_otp": True})
    assert out["bootstrap_config"] == cloud_init()
    assert out["vinitparam"]["otp"] == SLOT_TOKEN
    assert out["activate_command"].endswith(f"token {SLOT_TOKEN}")
    assert "one-time token" in out["warnings"][0]


async def test_bootstrap_encoded(api: respx.MockRouter) -> None:
    mock_inventory(api)
    route = mock_bootstrap(api, body=base64.b64encode(cloud_init().encode()).decode())
    async with Client(make_server()) as c:
        out = await run(c, "catsdwan_bootstrap_config", {"chassis": SLOT, "type": "encoded"})
    assert route.calls[0].request.url.params["configtype"] == "encodedstring"
    assert out["bootstrap_config"] == ob.MASK and SLOT_TOKEN not in json.dumps(out)
    assert "vbond : 10.60.2.11" in out["decoded_masked"]


async def test_bootstrap_refuses_a_joined_edge(api: respx.MockRouter) -> None:
    """Live 20.18.3: the Manager answers 400 'not in "Token Generated" ... state' for a joined edge."""
    mock_inventory(api, br2={"validity": "invalid"})
    route = mock_bootstrap(api, BR2, cloud_init(BR2, "otp-x"))
    async with Client(make_server()) as c:
        with pytest.raises(ToolError, match="already joined"):
            await c.call_tool("catsdwan_bootstrap_config", {"chassis": "br2"})
    assert not route.called


async def test_bootstrap_unknown_chassis_names_the_ways_in(api: respx.MockRouter) -> None:
    mock_inventory(api)
    async with Client(make_server()) as c:
        with pytest.raises(ToolError, match="fileupload.*smartaccount/sync"):
            await c.call_tool("catsdwan_bootstrap_config", {"chassis": NEW})


# --- catsdwan_onboard_edge -----------------------------------------------------------------------

ONBOARD = {"chassis": SLOT, "hostname": "br3", "system_ip": "10.0.0.4", "site_id": 400}


async def test_onboard_not_in_the_list_is_refused_with_the_ways_in(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_onboard_edge", {**ONBOARD, "chassis": NEW, "config_group": "mcp-test"})
    assert prev["status"] == "blocked"
    (why,) = [b for b in prev["blockers"] if "not in the Manager's WAN edge list" in b]
    assert "/dataservice/system/device/fileupload" in why and "smartaccount/sync" in why


async def test_onboard_needs_one_of_group_or_template(api: respx.MockRouter) -> None:
    async with Client(writes()) as c:
        with pytest.raises(ToolError, match="exactly one"):
            await c.call_tool("catsdwan_onboard_edge", ONBOARD)


async def test_onboard_config_group_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    assoc = api.post(f"{GROUP}/device/associate").respond(json={})
    api.get(f"{GROUP}/device/variables").respond(json=slot_variables())
    put = api.put(f"{GROUP}/device/variables").respond(json={})
    save = api.post(SAVE)
    async with Client(writes()) as c:
        args = {**ONBOARD, "config_group": "mcp-test", "variables": {"banner_motd": "Lab"}}
        prev = await run(c, "catsdwan_onboard_edge", args)
        assert prev["status"] == "preview" and not assoc.called
        steps = {s["step"]: s for s in prev["preview"]["steps"]}
        assert steps["validity"]["status"] == "done already"
        assert steps["variables"]["set"] == {
            "host_name": "br3",
            "system_ip": "10.0.0.4",
            "site_id": 400,
            "banner_motd": "Lab",
        }
        assert prev["preview"]["tier"] == "write" and SLOT_TOKEN not in json.dumps(prev)
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    assert not save.called
    assert json.loads(assoc.calls[0].request.content) == {"devices": [{"id": SLOT}]}
    sent = json.loads(put.calls[0].request.content)
    by = {v["name"]: v.get("value") for v in sent["devices"][0]["variables"]}
    assert by == {
        "host_name": "br3",
        "system_ip": "10.0.0.4",
        "site_id": 400,
        "pseudo_commit_timer": 300,
        "banner_motd": "Lab",
    }
    result = done["result"]
    assert result["outcome"] == "done" and [s["step"] for s in result["steps"]] == ["associate", "variables"]
    nxt = " ".join(result["next"])
    assert "catsdwan_deploy_config_group" in nxt and "catsdwan_bootstrap_config" in nxt
    assert f"vedge_cloud activate chassis-number {SLOT} token <token>" in nxt


async def test_onboard_a_staging_edge_sets_valid_first(api: respx.MockRouter) -> None:
    api.get("/dataservice/device").respond(json=device_body())
    api.get(VEDGES).respond(json=slot_edit(validity="staging"))
    mock_group(api)
    api.post(f"{GROUP}/device/associate").respond(json={})
    api.get(f"{GROUP}/device/variables").respond(json=slot_variables())
    api.put(f"{GROUP}/device/variables").respond(json={})
    save = api.post(SAVE).respond(json={"id": "save-1"})
    push = api.post(PUSH).respond(json={"id": PUSH_ID})
    api.get(f"{STATUS}/{PUSH_ID}").respond(json=status_body(("vbond", "x", "success")))
    async with Client(writes()) as c:
        args = {**ONBOARD, "config_group": "mcp-test"}
        prev = await run(c, "catsdwan_onboard_edge", args)
        step = next(s for s in prev["preview"]["steps"] if s["step"] == "validity")
        assert step["action"].startswith("staging -> valid") and "no data plane" in step["note"]
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    assert json.loads(save.calls[0].request.content) == [
        {"chasisNumber": SLOT, "serialNumber": SLOT_TOKEN, "validity": "valid"}
    ]
    assert push.calls[0].request.url.params["action"] == "push"
    steps = done["result"]["steps"]
    assert [s["step"] for s in steps] == ["validity", "associate", "variables"]
    assert steps[0]["sent_to_controllers"]["outcome"] == "success"
    assert SLOT_TOKEN not in json.dumps(done)


async def test_onboard_stops_at_the_failing_step(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    api.post(f"{GROUP}/device/associate").respond(
        400, json={"error": {"message": "Device model not supported by the group", "code": "CFGRP0001"}}
    )
    put = api.put(f"{GROUP}/device/variables")
    async with Client(writes()) as c:
        args = {**ONBOARD, "config_group": "mcp-test"}
        prev = await run(c, "catsdwan_onboard_edge", args)
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    result = done["result"]
    assert result["outcome"] == "stopped" and result["failed_step"] == "associate"
    assert "not supported" in result["reason"] and result["not_run"] == ["variables"]
    assert not put.called


async def test_onboard_unknown_group_variable_stops(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    api.post(f"{GROUP}/device/associate").respond(json={})
    api.get(f"{GROUP}/device/variables").respond(json=slot_variables())
    async with Client(writes()) as c:
        args = {**ONBOARD, "config_group": "mcp-test", "variables": {"colour": "red"}}
        prev = await run(c, "catsdwan_onboard_edge", args)
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    assert done["result"]["failed_step"] == "variables" and "'colour'" in done["result"]["reason"]


async def test_onboard_org_mismatch_and_failed_certificate_block(api: respx.MockRouter) -> None:
    mock_inventory(api, br2={"organization-name": "someone-else", "vedgeCertificateState": "csrfailed"})
    mock_group(api)
    async with Client(writes()) as c:
        prev = await run(
            c,
            "catsdwan_onboard_edge",
            {
                "chassis": BR2,
                "hostname": "br2",
                "system_ip": "10.0.0.3",
                "site_id": 300,
                "config_group": "mcp-test",
            },
        )
    text = " ".join(prev["blockers"])
    assert prev["status"] == "blocked"
    assert "org 'someone-else'" in text and "'mcp-lab-org'" in text
    assert "certificate signing request failed" in text


async def test_onboard_system_ip_in_use_and_hub_tier(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    async with Client(writes()) as c:
        prev = await run(
            c, "catsdwan_onboard_edge", {**ONBOARD, "system_ip": "10.0.0.1", "config_group": "mcp-test"}
        )
    assert any("10.0.0.1 is already hub1's" in b for b in prev["blockers"])
    async with Client(writes(protected_sites="400")) as c:
        prev = await run(c, "catsdwan_onboard_edge", {**ONBOARD, "config_group": "mcp-test"})
    assert prev["status"] == "blocked" and any("MCP_ENABLE_DANGEROUS" in b for b in prev["blockers"])


async def test_onboard_with_a_template(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dataservice/template/device").respond(json=fixture("template_device"))
    inp = api.post("/dataservice/template/device/config/input").respond(
        json={
            "header": {"columns": [{"property": "//system/host-name", "title": "Hostname"}]},
            "data": [
                {
                    "csv-status": "in_complete",
                    "csv-deviceId": SLOT,
                    "//system/host-name": "",
                    "//system/system-ip": "",
                    "//system/site-id": "",
                }
            ],
        }
    )
    attach = api.post("/dataservice/template/device/config/attachcli").respond(json={"id": "push_tpl-1"})
    api.get(f"{STATUS}/push_tpl-1").respond(json=status_body(("br3", SLOT, "success")))
    async with Client(writes()) as c:
        args = {**ONBOARD, "template": "mcp-test-br2"}
        prev = await run(c, "catsdwan_onboard_edge", args)
        assert prev["status"] == "preview", prev.get("blockers")
        assert json.loads(inp.calls[0].request.content)["deviceIds"] == [SLOT]
        step = next(s for s in prev["preview"]["steps"] if s["step"] == "attach template")
        assert step["values"]["//system/system-ip"] == "10.0.0.4" and "when the edge joins" in step["note"]
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    (row,) = json.loads(attach.calls[0].request.content)["deviceTemplateList"][0]["device"]
    assert row["//system/host-name"] == "br3" and row["//system/site-id"] == 400 and row["selected"] == "true"
    assert done["result"]["outcome"] == "done"


async def test_onboard_uploads_a_serial_file_first(api: respx.MockRouter, tmp_path: Path) -> None:
    serial = tmp_path / "serialFile.viptela"
    serial.write_bytes(b"SIGNED-SERIAL-FILE")
    api.get("/dataservice/device").respond(json=device_body())
    api.get("/dataservice/system/device/controllers").respond(json=fixture("system_device_controllers"))
    after = vedges_body()
    after["data"].append({**after["data"][0], "chasisNumber": NEW, "uuid": NEW, "serialNumber": "tok-new"})
    vedges = api.get(VEDGES)
    vedges.side_effect = [
        respx.MockResponse(json=vedges_body()),
        respx.MockResponse(json=vedges_body()),
        respx.MockResponse(json=after),
    ]
    mock_group(api)
    upload = api.post("/dataservice/system/device/fileupload").respond(
        json={
            "vedgeListUploadStatus": "vEdge list uploaded successfully",
            "vedgeListUploadMsg": "Number of vEdges uploaded successfully: 26",
            "activityList": f"[Uploaded vEdges (chassisId, serial number): - {NEW}, tok-new]",
            "id": "upload-1",
        }
    )
    api.post(f"{GROUP}/device/associate").respond(json={})
    api.get(f"{GROUP}/device/variables").respond(json=slot_variables(NEW))
    api.put(f"{GROUP}/device/variables").respond(json={})
    async with Client(writes()) as c:
        args = {**ONBOARD, "chassis": NEW, "config_group": "mcp-test", "serial_file": str(serial)}
        prev = await run(c, "catsdwan_onboard_edge", args)
        assert prev["status"] == "preview" and prev["preview"]["steps"][0]["step"] == "upload serial file"
        done = await run(c, "catsdwan_onboard_edge", {**args, "confirm": prev["confirm"]})
    req = upload.calls[0].request
    assert req.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'filename="serialFile.viptela"' in req.content and b"SIGNED-SERIAL-FILE" in req.content
    result = done["result"]
    assert result["outcome"] == "done" and result["steps"][0]["status"] == "done"
    assert "tok-new" not in json.dumps(done)


# --- catsdwan_set_edge_validity ------------------------------------------------------------------


async def test_invalidate_a_joined_edge_is_dangerous(api: respx.MockRouter) -> None:
    mock_inventory(api)
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_set_edge_validity", {"chassis": "br2", "validity": "invalid"})
    assert prev["status"] == "blocked"
    assert "br2 at site 201" in prev["blockers"][0] and "MCP_ENABLE_DANGEROUS" in prev["blockers"][0]


async def test_invalidate_then_confirm(api: respx.MockRouter) -> None:
    mock_inventory(api)
    save = api.post(SAVE).respond(json={"id": "save-1"})
    push = api.post(PUSH).respond(json={"id": PUSH_ID})
    api.get(f"{STATUS}/{PUSH_ID}").respond(json=status_body(("vbond", "x", "success")))
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        args = {"chassis": "br2", "validity": "invalid"}
        prev = await run(c, "catsdwan_set_edge_validity", args)
        assert prev["status"] == "preview" and prev["preview"]["tier"] == "dangerous"
        assert prev["preview"]["site"] == "201" and "valid" in prev["preview"]["undo"]
        assert not save.called
        done = await run(c, "catsdwan_set_edge_validity", {**args, "confirm": prev["confirm"]})
    assert json.loads(save.calls[0].request.content) == [
        {"chasisNumber": BR2, "serialNumber": BR2_SERIAL, "validity": "invalid"}
    ]
    assert push.calls[0].request.url.params["action"] == "push"
    result = done["result"]
    assert result["validity"] == {"from": "valid", "to": "invalid"}
    assert result["sent_to_controllers"]["outcome"] == "success" and "go down" in result["check"]


async def test_validate_an_unjoined_slot_is_write_tier(api: respx.MockRouter) -> None:
    api.get("/dataservice/device").respond(json=device_body())
    api.get(VEDGES).respond(json=slot_edit(validity="invalid"))
    async with Client(writes()) as c:
        prev = await run(c, "catsdwan_set_edge_validity", {"chassis": SLOT, "validity": "valid"})
        same = await run(c, "catsdwan_set_edge_validity", {"chassis": SLOT, "validity": "invalid"})
    assert prev["status"] == "preview" and prev["preview"]["tier"] == "write"
    assert SLOT_TOKEN not in json.dumps(prev)
    assert same["status"] == "blocked" and "invalid already" in same["blockers"][0]


# --- catsdwan_remove_device ----------------------------------------------------------------------

BR1 = "REDACTED-16"
BFD = "/dataservice/device/bfd/sessions"
CONTROL = "/dataservice/device/control/connections"


def mock_live(api: respx.MockRouter) -> None:
    api.get(CONTROL).respond(json=fixture("device_control_connections_hub1"))
    api.get(BFD).respond(json=fixture("device_bfd_sessions_hub1"))


def mock_removal(api: respx.MockRouter) -> dict[str, respx.Route]:
    return {
        "dissociate": api.delete(f"{GROUP}/device/associate").respond(json={}),
        "save": api.post(SAVE).respond(json={"id": "save-1"}),
        "push": api.post(PUSH).respond(json={"id": PUSH_ID}),
        "status": api.get(f"{STATUS}/{PUSH_ID}").respond(json=status_body(("vbond", "x", "success"))),
        "decommission": api.put(f"/dataservice/system/device/decommission/{BR1}").respond(
            json={"id": "dec-1"}
        ),
        "delete": api.delete(f"/dataservice/system/device/{BR1}").respond(json={"status": "success"}),
    }


async def test_remove_is_dangerous_and_listed_with_writes_only(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_live(api)
    async with Client(writes()) as c:
        names = {t.name for t in await c.list_tools()}
        prev = await run(c, "catsdwan_remove_device", {"chassis": "br1"})
    assert "catsdwan_remove_device" in names
    assert prev["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in prev["blockers"][0]
    assert "br1 at site 200" in prev["blockers"][0]


async def test_remove_preview_names_group_sessions_and_the_way_back(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_live(api)
    routes = mock_removal(api)
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": "br1"})
    assert prev["status"] == "preview"
    p = prev["preview"]
    assert p["tier"] == "dangerous" and p["site"] == "200"
    assert p["association"] == {"mode": "configuration group", "configuration_group": "mcp-test"}
    assert [s["step"] for s in p["steps"]] == ["dissociate", "invalidate", "decommission", "delete"]
    assert p["steps"][-1]["action"] == f"DELETE /dataservice/system/device/{BR1}"
    stops = p["stops"]
    assert len(stops["control_connections"]) == 3 and len(stops["bfd_sessions"]) == 8
    assert "3 control connection(s) and 8 BFD session(s)" in stops["summary"]
    assert "serial file" in p["comes_back"] and "Smart Account" in p["comes_back"]
    assert not any(r.called for r in routes.values())


async def test_remove_confirm_runs_the_steps_in_order(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_live(api)
    routes = mock_removal(api)
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": BR1})
        done = await run(c, "catsdwan_remove_device", {"chassis": BR1, "confirm": prev["confirm"]})
    result = done["result"]
    assert result["outcome"] == "done"
    assert [s["step"] for s in result["steps"]] == ["dissociate", "invalidate", "decommission", "delete"]
    assert json.loads(routes["dissociate"].calls[0].request.content) == {"devices": [{"id": BR1}]}
    assert json.loads(routes["save"].calls[0].request.content)[0]["validity"] == "invalid"
    assert routes["decommission"].called and routes["delete"].called
    order = [c.request.method + " " + c.request.url.path for c in api.calls]
    writes_seen = [o for o in order if o.split()[1].startswith("/dataservice") and not o.startswith("GET")]
    assert writes_seen == [
        f"DELETE {GROUP}/device/associate",
        f"POST {SAVE}",
        f"POST {PUSH}",
        f"PUT /dataservice/system/device/decommission/{BR1}",
        f"DELETE /dataservice/system/device/{BR1}",
    ]


async def test_remove_stops_at_the_failing_step(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_live(api)
    routes = mock_removal(api)
    routes["decommission"].respond(400, json={"error": {"message": "Device is not decommissionable"}})
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": BR1})
        done = await run(c, "catsdwan_remove_device", {"chassis": BR1, "confirm": prev["confirm"]})
    result = done["result"]
    assert result["outcome"] == "stopped" and result["failed_step"] == "decommission"
    assert result["not_run"] == ["delete"] and not routes["delete"].called


async def test_remove_a_hub_names_it(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_group(api)
    mock_live(api)
    async with Client(writes(mcp_enable_dangerous=True, hub_devices="hub1", protected_sites="100")) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": "hub1"})
    reasons = " ".join(prev["preview"]["tier_reasons"])
    assert "hub1 is" in reasons and "hub" in reasons and "100" in reasons


async def test_remove_an_unjoined_slot_skips_decommission_and_live_reads(api: respx.MockRouter) -> None:
    api.get("/dataservice/device").respond(json=device_body())
    api.get(VEDGES).respond(json=slot_edit(validity="invalid"))
    delete = api.delete(f"/dataservice/system/device/{SLOT}").respond(json={"status": "success"})
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": SLOT})
        p = prev["preview"]
        assert [s["step"] for s in p["steps"]] == ["invalidate", "delete"]
        assert p["steps"][0]["status"] == "done already" and "has not joined" in p["stops"]["summary"]
        assert SLOT_TOKEN not in json.dumps(prev)
        done = await run(c, "catsdwan_remove_device", {"chassis": SLOT, "confirm": prev["confirm"]})
    assert done["result"]["outcome"] == "done" and delete.called
    assert not any(c.request.url.path in (BFD, CONTROL) for c in api.calls)


async def test_remove_a_template_edge_detaches_it_first(api: respx.MockRouter) -> None:
    mock_inventory(api, br2={"configOperationMode": "vmanage", "managed-by": "Template branch-tpl"})
    mock_live(api)
    detach = api.post("/dataservice/template/config/device/mode/cli").respond(json={"id": "cli-1"})
    api.get(f"{STATUS}/cli-1").respond(json=status_body(("br2", BR2, "success")))
    api.post(SAVE).respond(json={"id": "save-1"})
    api.post(PUSH).respond(json={"id": PUSH_ID})
    api.get(f"{STATUS}/{PUSH_ID}").respond(json=status_body(("vbond", "x", "success")))
    api.put(f"/dataservice/system/device/decommission/{BR2}").respond(json={})
    api.delete(f"/dataservice/system/device/{BR2}").respond(json={"status": "success"})
    async with Client(writes(mcp_enable_dangerous=True)) as c:
        prev = await run(c, "catsdwan_remove_device", {"chassis": "br2"})
        assert prev["preview"]["association"] == {"mode": "template", "device_template": "branch-tpl"}
        assert prev["preview"]["steps"][0]["step"] == "detach template"
        done = await run(c, "catsdwan_remove_device", {"chassis": "br2", "confirm": prev["confirm"]})
    assert json.loads(detach.calls[0].request.content) == {
        "deviceType": "vedge",
        "devices": [{"deviceId": BR2, "deviceIP": "10.0.0.3"}],
    }
    assert done["result"]["outcome"] == "done"


async def test_onboarding_tools_need_writes() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
    assert {"catsdwan_list_wan_edges", "catsdwan_bootstrap_config"} <= names
    assert not names & {"catsdwan_onboard_edge", "catsdwan_set_edge_validity", "catsdwan_remove_device"}


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("GET", ob.BOOTSTRAP_PATH),
        ("POST", ob.FILEUPLOAD_PATH),
        ("POST", ob.SMART_SYNC_PATH),
        ("POST", ob.SAVE_VALIDITY_PATH),
        ("POST", ob.PUSH_VEDGES_PATH),
        ("POST", "/dataservice/v1/config-group/{id}/device/associate"),
        ("DELETE", "/dataservice/v1/config-group/{id}/device/associate"),
        ("PUT", ob.DECOMMISSION_PATH),
        ("DELETE", ob.DELETE_DEVICE_PATH),
        ("POST", ob.CLI_MODE_PATH),
    ],
)
def test_onboarding_paths_are_in_the_spec(method: str, template: str) -> None:
    from cat_sdwan_mcp._core.spec import build_index
    from cat_sdwan_mcp.spec import match_operation

    idx = build_index(fixture("spec_subset"), source="dataservice", path_prefix="/dataservice")
    _, methods = match_operation(idx, method, template.replace("{id}", "x"))
    assert method in methods
