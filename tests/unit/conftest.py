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
