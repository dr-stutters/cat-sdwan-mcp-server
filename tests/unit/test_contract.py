import logging

import pytest
import respx
from fastmcp import Client

from cat_sdwan_mcp._core.testing import (
    SurfaceBudget,
    assert_prompt_contract,
    assert_surface_budget,
    assert_tool_contract,
    undo_problems,
)
from tests.unit.conftest import make_server

# C81: tools whose Plan (with its undo) is built in a shared helper (tools/securityprofiles.plan_unified), so
# their own source never says `undo=`; their previews' back-out lines are checked in test_securityprofiles
# and test_sslproxy.
PLAN_IN_HELPER = {
    "catsdwan_set_amp_profile",
    "catsdwan_set_inspection_profile",
    "catsdwan_set_ips_profile",
    "catsdwan_set_ssl_decryption",
    "catsdwan_set_ssl_decryption_profile",
    "catsdwan_set_url_filtering_profile",
}


async def test_contract_all_tiers() -> None:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    await assert_tool_contract(server, "catsdwan", undo_allow=PLAN_IN_HELPER)
    await assert_prompt_contract(server, "catsdwan")


async def test_contract_read_only() -> None:
    server = make_server()
    await assert_tool_contract(server, "catsdwan")
    await assert_prompt_contract(server, "catsdwan")


def test_every_write_tool_sets_plan_undo() -> None:
    """C81: every write and dangerous tool names its back-out step (an Undo call or a text)."""
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    tiers = server._stutters_tiers  # type: ignore[attr-defined]
    writes = {n for n, t in tiers.items() if getattr(t, "value", t) in ("write", "dangerous")}
    assert len(writes) >= 42 and writes >= PLAN_IN_HELPER
    assert undo_problems(server, "catsdwan", allow=PLAN_IN_HELPER) == []


async def test_status_tool_reports_the_manager(api: respx.MockRouter) -> None:
    async with Client(make_server()) as c:
        names = {t.name for t in await c.list_tools()}
        result = await c.call_tool("catsdwan_status", {})
    assert "catsdwan_status" in names
    text = str(result.data or result.structured_content or result.content)
    assert "20.18.3.1" in text and "JWT" in text and "validator" in text
    assert "jwt-123" not in text and "csrf-123" not in text


# Core C31 tool-surface budget: ceilings ~10% above use at core v0.20.0 (110 tools, ~69.1k description chars,
# ~10.5k instruction chars, largest description 1469). Raise one on purpose when a release needs it.
BUDGET = SurfaceBudget(descriptions=76_000, instructions=11_500, tools=121, per_tool=1500)


async def test_surface_budget() -> None:
    await assert_surface_budget(make_server(mcp_enable_writes=True, mcp_enable_dangerous=True), BUDGET)


def test_no_unknown_toolset_warning_by_default(caplog: pytest.LogCaptureFixture) -> None:
    """Core C31 reads CATSDWAN_TOOLSETS itself; cat-sdwan declares no toolsets, so with the setting unset
    core must not warn about unknown toolsets (the fmc #376 fit bug) and every tool stays registered."""
    caplog.set_level(logging.WARNING)
    make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    assert "unknown toolset" not in caplog.text
