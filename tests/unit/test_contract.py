from fastmcp import Client

from cat_sdwan_mcp._core.testing import assert_prompt_contract, assert_tool_contract
from tests.unit.conftest import make_server


async def test_contract_all_tiers() -> None:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    await assert_tool_contract(server, "sdwan")
    await assert_prompt_contract(server, "sdwan")


async def test_contract_read_only() -> None:
    server = make_server()
    await assert_tool_contract(server, "sdwan")
    await assert_prompt_contract(server, "sdwan")


async def test_status_reports_the_scaffold() -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
        result = await c.call_tool("sdwan_status", {})
    assert "sdwan_status" in names
    assert "scaffold" in str(result.data or result.structured_content or result.content)
