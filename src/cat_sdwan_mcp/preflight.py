"""`cat-sdwan-mcp-server check` (W1): what an operator needs to know before connecting a client.

Rows: the login (JWT or session, CATSDWAN_AUTH) and a /dataservice read, TLS trust, credentials (a wrong
password is `auth`: the session login's HTML page never becomes a parse error), and the Manager release
against the tested matrix. The account's user groups vs the enabled tiers (`role`) wait for a recorded
payload (W1 live).
"""

from __future__ import annotations

from cat_sdwan_mcp._core.preflight import Preflight
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings

TESTED = ("20.18", "26")  # 20.18.3.1 in the lab; 26.x (IOS XE year numbering) planned
MINIMUM = "20.15"  # best effort; 20.12 and older have no maintenance releases after 2026-03-30


async def preflight(settings: Settings, pf: Preflight) -> None:
    app = SdwanApp(settings)
    try:
        token = await pf.reach(
            "login",
            app.auth.headers(app.api),
            detail=lambda _: f"logged in: {app.login_description()}",
            seconds=settings.timeout * 2,
        )
        if token is None:
            return
        found = await pf.reach(
            "dataservice",
            app.version(),
            detail=lambda v: f"GET /dataservice/device answered (Manager {v})",
            seconds=settings.timeout * 2,
        )
        if found is None:
            return
        if app.login_style == "session" and settings.auth == "auto":
            pf.ok(
                "auth",
                "credentials accepted with the session login (this Manager has no JWT login, before "
                "20.18.1); the session is renewed on 401 or the login page",
            )
        else:
            pf.ok("auth", f"credentials accepted: {app.login_description()}")
        if settings.tenant:
            pf.ok(
                "tenant",
                f"tenant {settings.tenant!r} (id {app.tenant_id}) entered: requests carry its VSessionId",
            )
        pf.version(None if found == "unknown" else found, tested=TESTED, minimum=MINIMUM)
    finally:
        await app.aclose()
