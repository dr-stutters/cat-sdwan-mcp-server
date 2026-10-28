"""Shared fixtures: settings without .env, the recorded 20.18 payloads, a respx router on a fake Manager."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import FastMCP

from cat_sdwan_mcp.config import Settings
from cat_sdwan_mcp.server import create_server

BASE = "https://catsdwan.test"
HUB_SPOKE_PATH = "/dataservice/template/policy/definition/hubandspoke"
BULK_BFD_PATH = "/dataservice/data/device/state/BFDSessions"
FIXTURES = Path(__file__).parent.parent / "fixtures"


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "url": BASE,
        "username": "admin",
        "password": "pw",
        "retries": 0,
        "mcp_cache_dir": "",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


def make_server(**kw: Any) -> FastMCP[Any]:
    return create_server(make_settings(**kw))


def fixture(name: str, release: str = "20.18") -> Any:
    """A recorded (redacted) Manager response body, e.g. fixture("device")."""
    return json.loads((FIXTURES / release / f"{name}.json").read_text())


JWT = {"token": "jwt-123", "csrf": "csrf-123", "refresh": "refresh-123"}
SESSION_COOKIE = "JSESSIONID=sess-1; Path=/; Secure; HttpOnly"


def mock_manager(router: respx.MockRouter, *, jwt: bool = True) -> None:
    """A 20.18 Manager: the JWT login (or a 404 on it and the session login) and the two status reads."""
    if jwt:
        router.post("/jwt/login").respond(json=JWT)
    else:
        router.post("/jwt/login").respond(404)
        router.post("/j_security_check").respond(200, headers={"Set-Cookie": SESSION_COOKIE})
        router.get("/dataservice/client/token").respond(200, text="xsrf-1")
    router.post("/logout").respond(200)
    router.get("/dataservice/device").respond(json=fixture("device"))
    router.get("/dataservice/system/device/controllers").respond(json=fixture("system_device_controllers"))
    # the change tools' hub evidence (#102): no hub-and-spoke topology, no BFD sessions recorded
    router.get(HUB_SPOKE_PATH).respond(json={"data": []})
    router.get(BULK_BFD_PATH).respond(json={"data": []})


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        mock_manager(router)
        yield router


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    """An empty router: the test mocks the Manager itself."""
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        yield r


W8_SERVICE = "00000000-0000-4000-8000-00000000f110"
W8_HUB_GROUP = "00000000-0000-4000-8000-00000000f111"
W8_TEST_GROUP = "00000000-0000-4000-8000-000000000124"


def mock_service_vpns(
    router: respx.MockRouter, *, converted: bool = True, segments: bool = True, more: tuple[int, ...] = ()
) -> None:
    """#118: the configuration groups after the W8 live run (recorded 2026-10-25, ids replaced): mcp-test
    (br1) and mcp-w8-hub (hub1) share service profile mcp-w8-service, whose LAN VPN parcel mcp-w8-vpn10 is
    VPN 10 (converted=False: no LAN VPN parcel, VPN 10 only in the CLI profiles as before the conversion);
    the one segment Discovered_VPN_10. `more`: hand-built parcel copies for other VPNs (mcp-w8-vpn<n>)."""
    rows = {r["id"]: r for r in fixture("v1_config_group_associate")["devices"]}
    router.get("/dataservice/v1/config-group").respond(json=fixture("v1_config_group_w8"))
    router.get(f"/dataservice/v1/config-group/{W8_TEST_GROUP}/device/associate").respond(
        json={"devices": [rows["REDACTED-16"]]}
    )
    router.get(f"/dataservice/v1/config-group/{W8_HUB_GROUP}/device/associate").respond(
        json={"devices": [rows["REDACTED-17"]]}
    )
    lan = fixture("v1_feature_profile_service_lan_vpn_list")
    for n in more:
        extra = json.loads(json.dumps(lan["data"][0]))
        extra["parcelId"] = f"00000000-0000-4000-8000-0000000{n:05d}"
        extra["payload"]["name"] = f"mcp-w8-vpn{n}"
        extra["payload"]["data"]["vpnId"]["value"] = n
        extra["payload"]["data"]["name"]["value"] = f"vpn{n}"
        lan["data"].append(extra)
    router.get(f"/dataservice/v1/feature-profile/sdwan/service/{W8_SERVICE}/lan/vpn").respond(
        json=lan if converted else {"header": {}, "data": []}
    )
    if segments:
        router.get("/dataservice/segment").respond(json=fixture("segment"))
    else:
        router.get("/dataservice/segment").respond(404, json={"error": {"message": "nf"}})
