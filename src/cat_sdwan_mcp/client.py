"""The SD-WAN Manager client ("app" object) shared by the tools.

Scaffold only: the login flow, paging and API surfaces are roadmap items (ROADMAP.md), to be built against a
live instance. Until then the client is configured but never called.
"""

from typing import Any

import httpx

from cat_sdwan_mcp._core.http import ApiClient
from cat_sdwan_mcp.config import Settings

STAGE = "scaffold (plan only)"


class SdwanApp:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.api = ApiClient(
            settings.url,
            product="SD-WAN Manager",
            env_prefix="CATSDWAN_",
            verify=settings.verify,
            timeout=settings.timeout,
            retries=settings.retries,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self.api.aclose()

    async def status(self) -> dict[str, Any]:
        """What catsdwan_status reports. No API call yet: the login and version probe are roadmap items."""
        return {
            "stage": STAGE,
            "api": "not implemented yet: no SD-WAN Manager calls are made",
            "roadmap": "ROADMAP.md: W0 (lab fabric), then the client, login and status probe",
        }
