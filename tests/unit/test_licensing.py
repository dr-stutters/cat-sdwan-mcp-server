"""W28: licensing reads.

Recorded on 20.18.3.1 (no Smart Account sync configured): Smart Licensing user settings, association and sync
status, the 25 licensing device rows (3 joined), the empty licence pool, the compliance and licensed-device
count, br1's empty licence usage and registration. A configured Smart Account with a licensed edge is
hand-built (marked so).
"""

from typing import Any

import respx

from cat_sdwan_mcp.licensing import compliance, device_row, smart_account

from .conftest import fixture
from .test_inventory import call, mock_inventory

RECORDED = {
    "/dataservice/v1/smart-licensing/user-settings": "v1_smart_licensing_user_settings",
    "/dataservice/v1/smart-licensing/association": "v1_smart_licensing_association",
    "/dataservice/v1/smart-licensing/ea/fetch-sync-status": "v1_smart_licensing_ea_sync_status",
    "/dataservice/v1/licensing/devices": "v1_licensing_devices",
    "/dataservice/msla/licenses": "msla_licenses",
    "/dataservice/msla/licenses/compliance": "msla_licenses_compliance",
    "/dataservice/msla/monitoring/licensedDeviceCount": "msla_monitoring_count",
}


def mock_licensing(api: respx.MockRouter, **bodies: Any) -> None:
    for path, name in RECORDED.items():
        api.get(path).respond(json=bodies.get(name, fixture(name)))


async def test_licenses_no_smart_account_sync(api: respx.MockRouter) -> None:
    mock_licensing(api)
    out = await call("catsdwan_licenses", {})
    sa = out["smart_account"]
    assert (
        sa["credentials"] is False
        and sa["virtual_accounts"] == "none associated"
        and sa["configured"] is False
    )
    assert out["verdict"].startswith(
        "No Smart Account sync is configured on this Manager (no Smart Account credentials, no virtual "
        "account associated)"
    )
    assert out["verdict"].endswith("Licensed: 0 of 3 device(s).")
    assert out["compliance"] == {
        "status": "Out Of Compliance",
        "reasons": ["Unassigned", "Unreported Licenses"],
    }
    assert out["licence_pool"] == "empty"
    assert sorted(d["host"] for d in out["devices"]) == ["br1", "br2", "hub1"]
    assert out["by_compliance"] == {"Out Of Compliance": 3}
    assert out["unjoined_slots"].startswith("22 ")
    hub1 = next(d for d in out["devices"] if d["host"] == "hub1")
    assert hub1["reason"] == "Unassigned" and hub1["site_id"] == "100" and "licences" not in hub1


async def test_licenses_one_device_with_its_own_view(api: respx.MockRouter) -> None:
    mock_licensing(api)
    mock_inventory(api)
    for path, name in (
        ("/dataservice/device/license/usage", "device_license_usage_br1"),
        ("/dataservice/device/license/registration", "device_license_registration_br1"),
    ):
        api.get(path, params={"deviceId": "10.0.0.2"}).respond(json=fixture(name))
    out = await call("catsdwan_licenses", {"device": "br1"})
    [row] = out["devices"]
    assert row["host"] == "br1" and row["system_ip"] == "10.0.0.2"
    edge = out["edge_view"]
    assert edge["usage"] == "none reported" and "managed and reported by the Manager" in edge["note"]


async def test_licenses_configured_and_unjoined(api: respx.MockRouter) -> None:
    devices = fixture("v1_licensing_devices")
    hub = next(d for d in devices["devices"] if d["hostName"] == "hub1")
    hub.update(  # hand-built: a licensed edge
        {
            "complianceStatus": "In Compliance",
            "inCompliantReason": "-",
            "licenses": [{"licenseName": "DNA Advantage"}],
        }
    )
    mock_licensing(
        api,
        v1_smart_licensing_user_settings={"isPresentCredentials": True},
        v1_smart_licensing_association={"association": [{"virtualAccount": "lab-va"}]},
        v1_licensing_devices=devices,
    )
    out = await call("catsdwan_licenses", {"include_unjoined": True})
    assert out["smart_account"]["configured"] is True
    assert out["verdict"] == "Smart Account sync configured; compliance Out Of Compliance, licensed 0 of 3"
    assert len(out["devices"]) == 25
    hub1 = next(d for d in out["devices"] if d.get("host") == "hub1")
    assert hub1["licences"] == ["DNA Advantage"] and "reason" not in hub1


def test_helpers() -> None:
    assert device_row({"hostName": "-", "uuid": "C8K-1", "licenses": []}) == {"chassis": "C8K-1"}
    assert compliance({}) == {}
    assert smart_account(None, None, None)["credentials"] == "unknown"
