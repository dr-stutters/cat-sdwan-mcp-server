"""Runtime settings: CATSDWAN_* for the SD-WAN Manager.

MCP_* settings for this server come from stutters-mcp-core.
"""

from typing import ClassVar, Literal

from pydantic import Field

from cat_sdwan_mcp._core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CATSDWAN_")

    # A tenant belongs to one Manager: a named instance (CATSDWAN_<NAME>_TENANT) never inherits it.
    per_instance_fields: ClassVar[frozenset[str]] = frozenset({"tenant"})

    # CATSDWAN_AUTH: how to log in. "jwt" is POST /jwt/login (20.18.1 and later); "session" is the form login
    # (POST /j_security_check, a JSESSIONID cookie and an XSRF token); "auto" tries JWT and falls back to the
    # session login when the Manager has no JWT endpoint (404/405).
    auth: Literal["auto", "jwt", "session"] = "auto"

    # CATSDWAN_SESSION_SECONDS: the JWT lifetime asked for at login. 20.18.3 refuses more than 1800 s
    # (an HTML 400: 'Duration must be ... less than or equal to 1800 seconds'); it is refreshed before expiry.
    session_seconds: int = Field(default=1800, ge=300, le=1800)

    # CATSDWAN_TENANT: a tenant name or id for a provider login on a multi-tenant Manager; requests then carry
    # that tenant's VSessionId. Off by default (single-tenant Managers).
    tenant: str | None = None
