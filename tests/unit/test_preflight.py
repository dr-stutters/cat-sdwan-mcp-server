"""W1: `cat-sdwan-mcp-server check` against a mocked Manager, one test per failure mode."""

from typing import Any

import httpx
import pytest
import respx

from cat_sdwan_mcp._core.preflight import run_preflight
from cat_sdwan_mcp.preflight import preflight
from tests.unit.conftest import SESSION_COOKIE, fixture, make_settings, mock_manager


async def _run(**kw: Any) -> dict[str, Any]:
    return await run_preflight(
        make_settings(**kw),
        preflight,
        server="cat-sdwan-mcp-server",
        product="SD-WAN Manager",
        env_prefix="CATSDWAN_",
    )


def _rows(report: dict[str, Any], check: str) -> list[dict[str, Any]]:
    return [c for c in report["instances"][0]["checks"] if c["check"] == check]


def _one(report: dict[str, Any], check: str) -> dict[str, Any]:
    (row,) = _rows(report, check)
    return row


def _with_version(version: str) -> dict[str, Any]:
    body = fixture("device")
    body["data"] = [{**d, "version": version} for d in body["data"]]
    return body


async def test_healthy_jwt(router: respx.MockRouter) -> None:
    mock_manager(router)
    report = await _run()
    assert report["ok"]
    reach = _rows(report, "reachability")
    assert [r["surface"] for r in reach] == ["login", "dataservice"]
    assert "JWT" in reach[0]["detail"] and "20.18.3.1" in reach[1]["detail"]
    assert _one(report, "auth")["outcome"] == "ok"
    assert _one(report, "tls")["outcome"] == "ok"
    version = _one(report, "version")
    assert version["outcome"] == "ok" and "tested" in version["detail"]
    assert _one(report, "role")["outcome"] == "skip"


async def test_session_fallback(router: respx.MockRouter) -> None:
    mock_manager(router, jwt=False)
    report = await _run()
    assert report["ok"]
    auth = _one(report, "auth")
    assert auth["outcome"] == "ok" and "no JWT login" in auth["detail"]


async def test_wrong_password_jwt_is_auth(router: respx.MockRouter) -> None:
    mock_manager(router)
    router.routes[0].respond(401, json={"error": {"message": "Authentication failed", "code": "AUTH0001"}})
    report = await _run()
    assert not report["ok"]
    auth = _one(report, "auth")
    assert auth["outcome"] == "fail" and "CATSDWAN_PASSWORD" in auth["hint"]
    assert _one(report, "version")["outcome"] == "skip"


async def test_wrong_password_session_is_auth(router: respx.MockRouter) -> None:
    """The HTML login page (200) is a credentials failure, never a parse error."""
    mock_manager(router, jwt=False)
    router.routes[1].respond(
        200,
        headers={"Content-Type": "text/html", "Set-Cookie": SESSION_COOKIE},
        text="<html><body>login</body></html>",
    )
    report = await _run(auth="session")
    auth = _one(report, "auth")
    assert auth["outcome"] == "fail" and "rejected the session login" in auth["detail"]
    assert not _rows(report, "role") or _one(report, "role")["outcome"] == "skip"


async def test_unreachable(router: respx.MockRouter) -> None:
    router.post("/jwt/login").mock(side_effect=httpx.ConnectError("connection refused"))
    report = await _run()
    row = _one(report, "reachability")
    assert row["outcome"] == "fail" and "CATSDWAN_URL" in row["hint"]
    assert _one(report, "tls")["outcome"] == "skip"


async def test_tls_failure(router: respx.MockRouter) -> None:
    router.post("/jwt/login").mock(side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"))
    report = await _run()
    tls = _one(report, "tls")
    assert tls["outcome"] == "fail" and "CATSDWAN_CA_BUNDLE" in tls["hint"]


@pytest.mark.parametrize(
    ("version", "outcome"),
    [("20.18.3.1", "ok"), ("26.1.1", "ok"), ("20.15.4", "warn"), ("20.12.6", "fail")],
)
async def test_version_matrix(router: respx.MockRouter, version: str, outcome: str) -> None:
    mock_manager(router)
    router.get("/dataservice/device").respond(json=_with_version(version))
    report = await _run()
    assert _one(report, "version")["outcome"] == outcome


async def test_tenant_row(router: respx.MockRouter) -> None:
    mock_manager(router)
    router.get("/dataservice/tenant").respond(json={"data": [{"tenantId": "t-9", "name": "customer-a"}]})
    router.post("/dataservice/tenant/t-9/vsessionid").respond(json={"VSessionId": "vs-1"})
    report = await _run(tenant="customer-a")
    assert report["ok"]
    assert "t-9" in _one(report, "tenant")["detail"]
