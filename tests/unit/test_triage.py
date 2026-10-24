"""W51: branch triage prompts (catsdwan_wifi_lan_or_wan, catsdwan_network_or_ise, catsdwan_site_down,
catsdwan_brownout_drill). The contract, `uses` and snapshots are checked with the other prompts in
test_prompts.py; these check each prompt's order of steps and verdicts."""

from fastmcp import Client

from cat_sdwan_mcp._core.prompts import rendered_text

from .conftest import make_server


async def text_of(name: str, args: dict[str, str], *, writes: bool = True) -> str:
    server = make_server(mcp_enable_writes=writes, mcp_enable_dangerous=writes)
    async with Client(server) as c:
        return rendered_text(await c.get_prompt(name, args))


def in_order(text: str, refs: list[str], start: str = "1. ") -> bool:
    """Each ref appears after the previous one, counting from the first step."""
    pos = text.index(start)
    for ref in refs:
        found = text.find(f"`{ref}`", pos)
        if found < 0:
            return False
        pos = found
    return True


async def test_triage_prompts_are_listed_without_writes() -> None:
    async with Client(make_server()) as c:
        names = {p.name for p in await c.list_prompts()}
    assert {
        "catsdwan_wifi_lan_or_wan",
        "catsdwan_network_or_ise",
        "catsdwan_site_down",
        "catsdwan_brownout_drill",
    } <= names


async def test_wifi_lan_or_wan_starts_from_find_host_and_judges_each_layer() -> None:
    text = await text_of("catsdwan_wifi_lan_or_wan", {"host": "10.61.200.10", "site": "200"})
    assert in_order(
        text,
        [
            "catsdwan_find_host",
            "catc_client_360",
            "catc_site_health_report",
            "catsdwan_site_health",
            "catsdwan_tunnel_health",
            "catsdwan_app_route_stats",
            "cml_get_link_scenarios",
        ],
    )
    assert 'host="10.61.200.10"' in text and 'site="200"' in text
    flat = " ".join(text.split())
    assert "one line per layer (Wi-Fi, LAN, WAN)" in flat and 'is "not checked", never "fine"' in flat
    assert "does not manage this site's access layer" in text and "Read-only" in text


async def test_wifi_lan_or_wan_without_site() -> None:
    text = await text_of("catsdwan_wifi_lan_or_wan", {"host": "alice"})
    assert "site=<the site found in step 1>" in text and 'lab="mcp-cat-sdwan"' in text


async def test_network_or_ise_walks_overlay_then_radius_then_policy() -> None:
    text = await text_of(
        "catsdwan_network_or_ise", {"site": "200", "nad": "br1-sw1", "host": "aa:bb:cc:00:02:00"}
    )
    assert in_order(
        text,
        [
            "ise_deployment_health",
            "catsdwan_find_host",
            "catsdwan_omp_routes",
            "catsdwan_bfd_sessions",
            "catsdwan_app_route_stats",
            "ise_nad_radius_stats",
            "ise_why_auth_failed",
        ],
    )
    assert 'nad="br1-sw1"' in text and "since_minutes=60" in text and "compare_previous=true" in text
    assert 'for "aa:bb:cc:00:02:00"' in text
    for verdict in ("- the network:", "- ISE:", "- the policy:", "- none of these:"):
        assert verdict in text


async def test_network_or_ise_defaults() -> None:
    text = await text_of("catsdwan_network_or_ise", {"site": "200", "minutes": "30"})
    assert "nad=<each NAD at the site>" in text and "since_minutes=30" in text
    assert "`ise_recent_auth_failures`" in text


async def test_site_down_names_power_underlay_overlay() -> None:
    text = await text_of("catsdwan_site_down", {"site": "200"})
    assert in_order(
        text,
        [
            "catsdwan_list_devices",
            "catsdwan_control_connections",
            "catsdwan_bfd_sessions",
            "catsdwan_list_alarms",
            "catc_list_device_health",
            "ise_get_auth_list",
            "cml_get_node_console_log",
        ],
    )
    for verdict in ("- power", "- underlay:", "- overlay:", "- not down:"):
        assert verdict in text
    assert 'lab="mcp-cat-sdwan"' in text and "include_history=true" in text


async def test_brownout_drill_is_preview_first_and_always_clears() -> None:
    text = await text_of(
        "catsdwan_brownout_drill",
        {"site": "200", "lab": "mcp-cat-sdwan", "scenario": "wan-satellite", "sla_class": "Realtime"},
    )
    assert in_order(
        text,
        [
            "catsdwan_list_sla_classes",
            "cml_get_lab_topology",
            "cml_apply_link_scenario",
            "catsdwan_tunnel_path",
            "cml_check_reachability",
            "cml_clear_link_scenarios",
        ],
    )
    assert "CHANGES THE LAB" in text and "PREVIEW-FIRST" in text and "still\nclear the scenario" in text
    assert 'scenario="wan-satellite"' in text and 'sla_class="Realtime"' in text
    assert "Everything on the SD-WAN Manager is read-only" in text


async def test_brownout_drill_defaults_and_is_visible_without_writes() -> None:
    text = await text_of("catsdwan_brownout_drill", {"site": "201"}, writes=False)
    assert 'scenario="brownout"' in text and "each class the site's app-route policy uses" in text
