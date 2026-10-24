"""W48: the security profile writes (IPS, URL filtering, AMP, advanced inspection, the embedded-security
policy) and their delete.

Recorded on 20.18.3.1: the policy-object profile is Default_Policy_Object_Profile (app-list and data-prefix
parcels only), no embedded-security profile, no policy group; the six security parcel schemas (POST) whose
enums and required fields the builders follow. The security parcels in the profile listing, their bodies and
the POST/PUT answers ({parcelId}) are hand-built from those schemas and the spec's examples, and marked so.
"""

import json
from typing import Any

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.securityprofiles import (
    aip_data,
    changes,
    check_categories,
    check_name,
    parcels_in,
    policy_data,
    url_data,
)

from .conftest import make_server
from .test_utd import IMAGES, REPO_ROW, mock_edges, repo_body

PO = "a1a1a1a1-0000-4000-8000-000000000001"
BASE = "/dataservice/v1/feature-profile/sdwan/policy-object"
EMB = "/dataservice/v1/feature-profile/sdwan/embedded-security"
IPS_ID = "b2b2b2b2-0000-4000-8000-000000000002"
URL_ID = "c3c3c3c3-0000-4000-8000-000000000003"
AIP_ID = "d4d4d4d4-0000-4000-8000-000000000004"
ESP = "e5e5e5e5-0000-4000-8000-000000000005"
POL = "f6f6f6f6-0000-4000-8000-000000000006"
FW_ID = "0a0a0a0a-0000-4000-8000-00000000000a"


def parcel(pid: str, ptype: str, name: str) -> dict[str, Any]:
    return {"parcelId": pid, "parcelType": ptype, "payload": {"name": name, "description": ""}}


RECORDED = [parcel("25fd2396-bd64-45da-af11-799366cdbf3b", "app-list", "box_net_apps")]
SECURITY = [  # hand-built
    parcel(IPS_ID, "unified/intrusion-prevention", "mcp-ips"),
    parcel(URL_ID, "unified/url-filtering", "mcp-url"),
    parcel(AIP_ID, "unified/advanced-inspection-profile", "mcp-aip"),
]


def mock_po(api: respx.MockRouter, parcels: list[dict[str, Any]] | None = None) -> None:
    api.get(BASE).respond(
        json=[
            {"profileId": PO, "profileName": "Default_Policy_Object_Profile", "profileType": "policy-object"}
        ]
    )
    api.get(f"{BASE}/{PO}").respond(
        json={
            "profileId": PO,
            "profileName": "Default_Policy_Object_Profile",
            "associatedProfileParcels": RECORDED + (parcels or []),
        }  # fmt: skip
    )


def ips_body(mode: str = "protection") -> dict[str, Any]:
    return {
        "parcelId": IPS_ID,
        "payload": {
            "name": "mcp-ips",
            "data": {
                "signatureSet": {"optionType": "global", "value": "balanced"},
                "inspectionMode": {"optionType": "global", "value": mode},
                "logLevel": {"optionType": "global", "value": "error"},
                "customSignature": {"optionType": "global", "value": False},
            },
        },
    }


def server(**kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, **kw)


async def run(c: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    out = (await c.call_tool(name, args)).structured_content
    assert out is not None
    return out


def test_names_categories_and_bodies() -> None:
    assert check_name("mcp-ips") == "mcp-ips"
    for bad in ("has space", "x" * 33, "a&b", ""):
        with pytest.raises(Exception, match="1-32 characters"):
            check_name(bad)
    assert check_categories(["Gambling", "malware_sites", "gambling"], "c") == ["gambling", "malware-sites"]
    with pytest.raises(Exception, match="Did you mean: gambling"):
        check_categories(["gamblin"], "c")
    data = url_data(action="block", categories=["gambling"], reputation="moderate-risk", block_page_text=None,
                    redirect_url=None, alerts=[], allowed_list=None, blocked_list=None)  # fmt: skip
    assert data["blockPageAction"] == {"optionType": "global", "value": "text"}
    assert data["enableAlerts"]["value"] is False and "alerts" not in data
    assert "Access to the requested page has been denied" in data["blockPageContents"]["value"]
    red = url_data(action="block", categories=[], reputation="high-risk", block_page_text=None,
                   redirect_url="https://block.example.com", alerts=["blacklist"], allowed_list=None,
                   blocked_list=None)  # fmt: skip
    assert red["blockPageAction"]["value"] == "redirect-url" and "blockPageContents" not in red
    assert red["alerts"]["value"] == ["blacklist"] and "webCategories" not in red
    with pytest.raises(Exception, match="at least one of ips"):
        aip_data(tls_action="neverDecrypt", refs={})
    with pytest.raises(Exception, match="needs ssl_decryption_profile"):
        aip_data(tls_action="decrypt", refs={"intrusionPrevention": IPS_ID})
    rows = parcels_in({"associatedProfileParcels": SECURITY})
    assert [r["kind"] for r in rows] == [
        "intrusion-prevention",
        "url-filtering",
        "advanced-inspection-profile",
    ]
    assert changes(ips_body()["payload"]["data"], ips_body("detection")["payload"]["data"]) == {
        "inspectionMode": {"from": "protection", "to": "detection"}
    }


def test_policy_data_keeps_firewall_entries() -> None:
    current = {
        "assembly": [
            {"advancedInspectionProfile": {"refId": {"optionType": "global", "value": "old"}}},
            {"ngfirewall": {"refId": {"optionType": "global", "value": FW_ID}, "entries": []}},
        ],
        "settings": {"auditTrail": {"optionType": "global", "value": "on"}},
    }
    data = policy_data(current, inspection_id=AIP_ID, ssl_decryption_id=None, failure_mode="close",
                       resource_profile="low", url_database=False)  # fmt: skip
    assert data["assembly"][0] == {
        "advancedInspectionProfile": {"refId": {"optionType": "global", "value": AIP_ID}}
    }
    assert data["assembly"][1]["ngfirewall"]["refId"]["value"] == FW_ID and len(data["assembly"]) == 2
    assert (
        data["settings"]["auditTrail"]["value"] == "on"
        and data["settings"]["failureMode"]["value"] == "close"
    )
    assert data["appHosting"]["resourceProfile"]["value"] == "low"


async def test_ips_create_preview_and_confirm(api: respx.MockRouter) -> None:
    mock_po(api)
    post = api.post(f"{BASE}/{PO}/unified/intrusion-prevention").respond(json={"parcelId": IPS_ID})
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ips_profile", {"name": "mcp-ips"})
        assert prev["status"] == "preview" and not post.called
        p = prev["preview"]
        assert p["action"] == "create" and p["profile"] == "Default_Policy_Object_Profile"
        assert p["values"] == {
            "signatureSet": "balanced",
            "inspectionMode": "protection",
            "logLevel": "error",
            "customSignature": False,
        }
        assert p["undo"] == "catsdwan_delete_security_profile(kind='intrusion-prevention', name='mcp-ips')"
        assert "catsdwan_create_policy_group" in p["next"]
        done = (await run(c, "catsdwan_set_ips_profile", {"name": "mcp-ips", "confirm": prev["confirm"]}))[
            "result"
        ]
    assert done == {"outcome": "created", "parcel_id": IPS_ID, "name": "mcp-ips", "next": done["next"]}
    sent = json.loads(post.calls.last.request.content)
    assert sent["name"] == "mcp-ips" and sent["data"]["inspectionMode"] == {
        "optionType": "global",
        "value": "protection",
    }
    assert sent["description"]


async def test_ips_update_and_no_change(api: respx.MockRouter) -> None:
    mock_po(api, SECURITY)
    api.get(f"{BASE}/{PO}/unified/intrusion-prevention/{IPS_ID}").respond(json=ips_body("detection"))
    put = api.put(f"{BASE}/{PO}/unified/intrusion-prevention/{IPS_ID}").respond(json={"parcelId": IPS_ID})
    async with Client(server()) as c:
        prev = await run(c, "catsdwan_set_ips_profile", {"name": "MCP-IPS"})
        assert prev["preview"]["action"] == "update"
        assert prev["preview"]["changes"] == {"inspectionMode": {"from": "detection", "to": "protection"}}
        await run(c, "catsdwan_set_ips_profile", {"name": "MCP-IPS", "confirm": prev["confirm"]})
        assert put.called
        same = await run(c, "catsdwan_set_ips_profile", {"name": "mcp-ips", "mode": "detection"})
    assert same["status"] == "blocked" and "nothing to change" in same["blockers"][0]


async def test_url_filtering_checks_categories(api: respx.MockRouter) -> None:
    mock_po(api)
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="Did you mean: gambling"):
            await c.call_tool("catsdwan_set_url_filtering_profile", {"name": "u", "categories": ["gamblng"]})
        with pytest.raises(ToolError, match="No URL list policy object"):
            await c.call_tool(
                "catsdwan_set_url_filtering_profile",
                {"name": "u", "categories": ["gambling"], "blocked_list": "x"},
            )
        prev = await run(
            c, "catsdwan_set_url_filtering_profile", {"name": "u", "categories": ["gambling", "games"]}
        )
    v = prev["preview"]["values"]
    assert v["webCategories"] == ["gambling", "games"] and v["webCategoriesAction"] == "block"
    assert v["webReputation"] == "moderate-risk"


async def test_amp_needs_file_types_for_analysis(api: respx.MockRouter) -> None:
    mock_po(api)
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="needs file_types"):
            await c.call_tool("catsdwan_set_amp_profile", {"name": "a", "file_analysis": True})
        prev = await run(
            c, "catsdwan_set_amp_profile", {"name": "a", "file_analysis": True, "file_types": ["pdf"]}
        )
    v = prev["preview"]["values"]
    assert (
        v["matchAllVpn"] is True
        and v["fileAnalysisFileTypes"] == ["pdf"]
        and v["fileReputationEstServer"] == "nam"
    )


async def test_inspection_profile_resolves_names(api: respx.MockRouter) -> None:
    mock_po(api, SECURITY[:2])
    async with Client(server()) as c:
        with pytest.raises(
            ToolError, match=r"No AMP profile 'nope'. Existing: none \(catsdwan_set_amp_profile"
        ):
            await c.call_tool(
                "catsdwan_set_inspection_profile", {"name": "aip", "ips": "mcp-ips", "amp": "nope"}
            )
        prev = await run(
            c, "catsdwan_set_inspection_profile", {"name": "aip", "ips": "mcp-ips", "url_filtering": URL_ID}
        )
    v = prev["preview"]["values"]
    assert v == {"tlsDecryptionAction": "neverDecrypt", "intrusionPrevention": f"ref {IPS_ID}",
                 "urlFiltering": f"ref {URL_ID}"}  # fmt: skip


async def test_security_policy_creates_profile_and_policy(api: respx.MockRouter) -> None:
    mock_po(api, SECURITY)
    mock_edges(api)
    api.get(EMB).respond(json=[])
    make = api.post(EMB).respond(json={"id": ESP})
    pol = api.post(f"{EMB}/{ESP}/policy").respond(json={"parcelId": POL})
    async with Client(server()) as c:
        prev = await run(
            c,
            "catsdwan_set_security_policy",
            {"name": "mcp-sec", "inspection_profile": "mcp-aip", "check_devices": ["br1"]},
        )
        p = prev["preview"]
        assert p["requests"] == [
            f"POST {EMB} {{name: 'mcp-sec'}} (embedded-security profile)",
            "POST /dataservice/v1/feature-profile/sdwan/embedded-security/<new profile>/policy",
        ]
        assert p["values"]["inspection_profile"] == "mcp-aip"
        assert p["values"]["appHosting"] == {"nat": True, "databaseUrl": False, "resourceProfile": "low"}
        assert p["utd_readiness"]["repository"] == "no UTD image (catsdwan_upload_utd_image first)"
        assert any("has no UTD image" in w for w in p["warnings"])
        assert any(w.startswith("br1: ") and "UTD needs 8 GB" in w for w in p["warnings"])
        assert "catsdwan_associate_policy_group" in p["next"]
        done = (
            await run(
                c,
                "catsdwan_set_security_policy",
                {
                    "name": "mcp-sec",
                    "inspection_profile": "mcp-aip",
                    "check_devices": ["br1"],
                    "confirm": prev["confirm"],
                },
            )
        )["result"]
    assert make.called and done["profile_created"] == ESP and done["parcel_id"] == POL
    body = json.loads(pol.calls.last.request.content)
    assert body["data"]["assembly"] == [
        {"advancedInspectionProfile": {"refId": {"optionType": "global", "value": AIP_ID}}}
    ]


async def test_security_policy_update_keeps_firewall(api: respx.MockRouter) -> None:
    mock_po(api, SECURITY)
    api.get(IMAGES).respond(json=repo_body(REPO_ROW))
    api.get(EMB).respond(
        json=[{"profileId": ESP, "profileName": "mcp-sec", "profileType": "embedded-security"}]
    )
    existing = {"parcelId": POL, "payload": {"name": "mcp-sec", "data": {
        "assembly": [{"ngfirewall": {"refId": {"optionType": "global", "value": FW_ID}, "entries": []}}],
        "settings": {"failureMode": {"optionType": "global", "value": "open"}}}}}  # fmt: skip
    api.get(f"{EMB}/{ESP}/policy").respond(json=[existing])
    put = api.put(f"{EMB}/{ESP}/policy/{POL}").respond(json={"parcelId": POL})
    async with Client(server()) as c:
        prev = await run(
            c, "catsdwan_set_security_policy", {"name": "mcp-sec", "inspection_profile": "mcp-aip"}
        )
        assert prev["preview"]["action"] == "update"
        assert prev["preview"]["values"]["other_assembly_entries_kept"] == 1
        assert "warnings" not in prev["preview"]
        await run(c, "catsdwan_set_security_policy", {"name": "mcp-sec", "inspection_profile": "mcp-aip",
                                                      "confirm": prev["confirm"]})  # fmt: skip
    sent = json.loads(put.calls.last.request.content)["data"]["assembly"]
    assert sent[0]["advancedInspectionProfile"]["refId"]["value"] == AIP_ID
    assert sent[1]["ngfirewall"]["refId"]["value"] == FW_ID


async def test_delete_is_blocked_while_referenced(api: respx.MockRouter) -> None:
    mock_po(api, SECURITY)
    api.get(f"{BASE}/{PO}/unified/advanced-inspection-profile/{AIP_ID}").respond(
        json={
            "payload": {
                "name": "mcp-aip",
                "data": {"intrusionPrevention": {"refId": {"optionType": "global", "value": IPS_ID}}},
            }
        }
    )
    delete = api.delete(f"{BASE}/{PO}/unified/intrusion-prevention/{IPS_ID}").respond(200)
    async with Client(server()) as c:
        prev = await run(
            c, "catsdwan_delete_security_profile", {"kind": "intrusion-prevention", "name": "mcp-ips"}
        )
        assert prev["status"] == "blocked" and "mcp-aip" in prev["blockers"][0]
        ok = await run(c, "catsdwan_delete_security_profile", {"kind": "url-filtering", "name": "mcp-url"})
        assert ok["status"] == "preview" and ok["preview"]["referenced_by"] == []
    assert not delete.called
