import respx
from fastmcp import Client

from cat_sdwan_mcp._core.testing import assert_prompt_contract, assert_tool_contract
from tests.unit.conftest import make_server


async def test_contract_all_tiers() -> None:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    await assert_tool_contract(server, "catsdwan")
    await assert_prompt_contract(server, "catsdwan")


async def test_contract_read_only() -> None:
    server = make_server()
    await assert_tool_contract(server, "catsdwan")
    await assert_prompt_contract(server, "catsdwan")


async def test_status_tool_reports_the_manager(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
        result = await c.call_tool("catsdwan_status", {})
    assert "catsdwan_status" in names
    text = str(result.data or result.structured_content or result.content)
    assert "20.18.3.1" in text and "JWT" in text and "validator" in text
    assert "jwt-123" not in text and "csrf-123" not in text
