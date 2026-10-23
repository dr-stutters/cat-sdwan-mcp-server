"""W24: TrustSec on an edge and the Manager's integrations.

Recorded on 20.18.3.1 (no ISE configured): br1's environment data (stuck in env-download-in-progress, no
server), empty SGT map and PAC tables, the 400 'Invalid data type CEdgeIptoSgtbindings' answer, empty ISE and
pxGrid credentials, the ISE connect and SGT-list errors, no partners, the SD-Access VPN list. The bodies with
data (environment downloaded, SGT bindings, SGACLs with counters, SXP, ISE credentials with a password, a
Catalyst Center partner) are hand-built from the field names the same Manager lists, and marked so.
"""

from typing import Any

import respx

from cat_sdwan_mcp.trustsec import EDGE_PATHS, environment, partners, rows_of

from .conftest import fixture
from .test_inventory import call, mock_inventory

BR1 = "10.0.0.2"
EMPTY: dict[str, Any] = {"data": []}


def mock_edge(api: respx.MockRouter, **tables: Any) -> dict[str, respx.Route]:
    recorded = {
        "environment": fixture("device_environmentdata_br1"),
        "sgt_map": fixture("device_rolebasedsgtmap_br1"),
        "pac": fixture("device_ctspac_br1"),
    }
    routes = {}
    for key, path in EDGE_PATHS.items():
        route = api.get(path, params={"deviceId": BR1})
        if key == "pxgrid_ip_sgt" and key not in tables:
            routes[key] = route.respond(400, json=fixture("device_policy_iptosgtbindings_br1"))
        else:
            routes[key] = route.respond(json=tables.get(key, recorded.get(key, EMPTY)))
    return routes


async def test_trustsec_not_configured(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_edge(api)
    out = await call("catsdwan_trustsec", {"device": "br1"})
    env = out["environment"]
    assert env["status"] == "env-download-in-progress" and env["downloaded"] is False
    assert "last_updated" not in env  # the epoch means never
    assert "no RADIUS server" in env["meaning"]
    assert not any(out["in_use"].values())
    assert out["verdict"].startswith("TrustSec is not configured on br1: no environment data from ISE")
    assert out["not_supported"] == ["pxgrid_ip_sgt (GET /dataservice/device/policy/iptosgtbindings)"]
    assert "errors" not in out


async def test_trustsec_with_bindings_sgacls_and_sxp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    env = fixture("device_environmentdata_br1")
    env["data"][0].update(
        {"status": "env-download-complete", "total-num-servers": 1, "device-sgt": 2,
         "last-updated-time": "2026-10-23T01:00:00+00:00"}
    )  # fmt: skip
    mock_edge(
        api,
        environment=env,
        sgt_map={"data": [{"vdevice-name": BR1, "ip": "10.61.200.10/32", "vrf-name": "10", "sgt": "17",
                           "source": "CLI"}]},
        permissions={"data": [{"src-sgt": "17", "dst-sgt": "18", "sgacl-name": "Deny_IP_Log-00",
                               "monitor-mode": "FALSE"}]},
        counters={"data": [{"src-sgt": "17", "dst-sgt": "18", "total-deny-count": "9",
                            "total-permit-count": "0"}]},
        sxp={"data": [{"peer-ip": "198.18.133.27", "source-ip": "10.0.0.2", "speaker-state": "Off",
                       "listener-state": "On", "local-mode": "Listener"}]},
        pac={"data": [{"pac-type": "Cisco Trustsec", "authority-id": "abc", "pac-opaque": "000200b8000300"}]},
    )  # fmt: skip
    out = await call("catsdwan_trustsec", {"device": "br1"})
    assert out["environment"]["downloaded"] is True and out["environment"]["device_sgt"] == 2
    assert out["sgt_bindings"] == [{"ip": "10.61.200.10/32", "vrf": "10", "sgt": "17", "learned_from": "CLI"}]
    [acl] = out["sgacls"]
    assert acl["sgacl"] == "Deny_IP_Log-00" and acl["denied"] == "9"
    assert out["sxp"][0]["listener"] == "On"
    assert out["pac"][0]["pac-opaque"] == "********"
    assert out["verdict"] == (
        "br1 uses environment data, sgt bindings, sgacls, sxp; attention: SGACLs denied 9 packet(s)."
    )


def mock_manager_integrations(api: respx.MockRouter, **bodies: Any) -> dict[str, respx.Route]:
    paths = {
        "creds": ("/dataservice/ise/credentials", fixture("ise_credentials")),
        "pxgrid": ("/dataservice/ise/credentials/pxgrid", fixture("ise_credentials_pxgrid")),
        "partner": ("/dataservice/partner", fixture("partner")),
        "vpn": ("/dataservice/partner/dnac/sda/vpn", fixture("partner_dnac_sda_vpn")),
        "connect": ("/dataservice/ise/connect", fixture("ise_connect")),
        "sgt": ("/dataservice/template/policy/ise/identity/sgt", fixture("template_policy_ise_identity_sgt")),
    }
    routes = {}
    for k, (path, body) in paths.items():
        body = bodies.get(k, body)
        status = 400 if isinstance(body, dict) and "error" in body else 200
        routes[k] = api.get(path).respond(status, json=body)
    return routes


async def test_integrations_none_configured(api: respx.MockRouter) -> None:
    routes = mock_manager_integrations(api)
    out = await call("catsdwan_integrations", {})
    assert out["ise"]["configured"] is False and "no ISE is configured" in out["ise"]["meaning"]
    assert out["pxgrid"] == {"configured": False}
    assert out["partners"] == "none registered" and out["sda_vpns"] == ["10"]
    assert out["verdict"].startswith("No ISE, pxGrid or partner integration is configured on this Manager")
    # Not configured: the connection test and the SGT list (both errors on this Manager) aren't asked.
    assert routes["connect"].call_count == 0 and routes["sgt"].call_count == 0
    assert "errors" not in out


async def test_integrations_ise_and_catalyst_center(api: respx.MockRouter) -> None:
    creds = {  # hand-built
        "data": [{"iseIP": "198.18.133.27", "username": "ers-admin", "password": "s3cret-pw", "vpn": "512"}]
    }
    partner = [  # hand-built
        {"partnerType": "dnac", "partners": [{"partnerId": "p-1", "name": "catc-lab", "deviceCount": 2}]}
    ]
    routes = mock_manager_integrations(
        api,
        creds=creds,
        partner=partner,
        connect={"data": {"status": "success"}},
        sgt={"data": [{"name": "Employees", "value": "4"}]},
    )
    api.get("/dataservice/partner/dnac/sda/site/p-1").respond(json={"data": [{"siteId": "Global/Lab"}]})
    api.get("/dataservice/partner/dnac/sda/device/p-1").respond(json={"data": [{"uuid": "d-1"}]})
    out = await call("catsdwan_integrations", {})
    ise = out["ise"]
    assert ise["configured"] is True and ise["credentials"][0]["password"] == "********"
    assert ise["connection"]["ok"] is True and ise["sgts"]["count"] == 1
    assert out["partners"] == [{"type": "dnac", "id": "p-1", "name": "catc-lab", "devices": 2}]
    assert out["catalyst_center"][0]["sites"] == [{"siteId": "Global/Lab"}]
    assert out["verdict"] == "Configured: ISE, dnac partner catc-lab."
    assert routes["connect"].call_count == 1
    assert "s3cret-pw" not in str(out)


async def test_integrations_ise_connection_failing(api: respx.MockRouter) -> None:
    mock_manager_integrations(api, creds={"data": [{"iseIP": "198.18.133.27", "username": "x"}]})
    out = await call("catsdwan_integrations", {})
    assert out["ise"]["connection"]["ok"] is False
    assert "ISEERRORR0016" in out["ise"]["connection"]["error"]
    assert "ISEERRORR0025" in out["ise"]["sgts_error"]
    assert out["verdict"] == "Configured: ISE (ISE connection test failed)."


def test_helpers() -> None:
    assert rows_of(fixture("device_ctspac_br1")["data"]) == []
    assert environment([]) is None
    assert partners([{"partnerId": "x", "partnerType": "aci", "name": "a"}]) == [
        {"type": "aci", "id": "x", "name": "a"}
    ]
