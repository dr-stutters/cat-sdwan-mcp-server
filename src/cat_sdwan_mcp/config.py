"""Runtime settings: CATSDWAN_* for the SD-WAN Manager.

MCP_* settings for this server come from stutters-mcp-core.
"""

from cat_sdwan_mcp._core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CATSDWAN_")
    # Product-specific settings arrive with the roadmap items that need them (ROADMAP.md).
