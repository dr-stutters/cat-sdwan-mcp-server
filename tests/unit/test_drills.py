"""W54: catsdwan_hub_failover_drill. Contract, `uses` and the snapshot are checked with the other prompts in
test_prompts.py; these check the order of the steps, the lab and no-lab renderings, the restore step and
the hub resolution."""

from fastmcp import Client

from cat_sdwan_mcp._core.prompts import rendered_text

from .conftest import make_server

NAME = "catsdwan_hub_failover_drill"


async def text_of(args: dict[str, str], **settings: object) -> str:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)
    async with Client(server) as c:
        return rendered_text(await c.get_prompt(NAME, args))


def in_order(text: str, refs: list[str]) -> bool:
    pos = text.index("1. Before")
    for ref in refs:
        found = text.find(f"`{ref}`", pos)
        if found < 0:
            return False
        pos = found
    return True


async def test_listed_without_writes() -> None:
    async with Client(make_server()) as c:
        names = {p.name for p in await c.list_prompts()}
    assert NAME in names


async def test_with_cml_lab_links_snapshot_down_paths_sla_services_restore_compare() -> None:
    text = await text_of({"hub": "hub1", "lab": "mcp-cat-sdwan", "vpns": "10,20"})
    assert in_order(
        text,
        [
            "catsdwan_snapshot",
            "catsdwan_omp_routes",
            "catsdwan_list_tlocs",
            "catsdwan_explain_path",
            "catsdwan_app_route_stats",
            "catsdwan_ping",
            "cml_get_lab_topology",
            "cml_set_link_state",
            "catsdwan_bfd_sessions",
            "catsdwan_omp_routes",
            "catsdwan_app_route_stats",
            "catsdwan_ping",
            "cml_check_reachability",
            "cml_set_link_state",
            "catsdwan_control_connections",
            "catsdwan_snapshot",
            "catsdwan_compare_snapshot",
        ],
    )
    flat = " ".join(text.split())
    assert 'The hub to fail is "hub1" (given)' in flat
    assert 'lab="mcp-cat-sdwan"' in text and 'state="down"' in text and 'state="up"' in text
    assert "PREVIEW-FIRST" in text and "never a Manager, Controller or Validator" in flat
    assert "per service VPN (10, 20)" in text and "graceful restart" in text
    assert "cml_set_node_state` with" not in text  # links method: no power-off step


async def test_with_cml_lab_node_method_powers_off_and_back_on() -> None:
    text = await text_of({"hub": "hub1", "lab": "mcp-cat-sdwan", "method": "node"})
    assert 'node=<hub>, state="stop"' in text and 'state="start"' in text
    assert "`cml_wait_for_converged`" in text


async def test_unknown_method_falls_back_to_links() -> None:
    text = await text_of({"hub": "hub1", "lab": "mcp-cat-sdwan", "method": "reboot"})
    assert 'state="down"' in text and 'state="stop"' not in text


async def test_without_cml_lab_the_operator_takes_the_hub_down() -> None:
    text = await text_of({"hub": "hub1"})
    assert "cml_set_link_state" not in text and "cml_set_node_state" not in text
    assert "cml_check_reachability" not in text and "No CML lab" in text
    assert "Ask the user to take the hub down" in text and "Ask the user to bring the hub back" in text
    assert in_order(text, ["catsdwan_snapshot", "catsdwan_bfd_sessions", "catsdwan_compare_snapshot"])


async def test_restore_step_is_always_present() -> None:
    for args in (
        {"hub": "hub1", "lab": "mcp-cat-sdwan"},
        {"hub": "hub1", "lab": "mcp-cat-sdwan", "method": "node"},
        {"hub": "hub1"},
        {},
    ):
        text = await text_of(args)
        assert "7. Restore (ALWAYS, also after a failure)" in text
        assert "ALWAYS run step 7 (restore) before you stop" in " ".join(text.split())
        assert text.index("7. Restore") < text.index("`catsdwan_compare_snapshot`")


async def test_hub_from_heuristics_when_setting_unset() -> None:
    text = await text_of({"lab": "mcp-cat-sdwan"})
    flat = " ".join(text.split())
    assert "CATSDWAN_HUB_DEVICES is not set" in flat and "(#102)" in flat
    assert "`catsdwan_list_policies`" in text and "`catsdwan_get_policy`" in text
    assert "hub site list of each hub-and-spoke definition" in flat
    assert "reach every other site seen in BFD (at least two) is a hub" in flat
    assert "full mesh with no hub to fail" in flat and '"hub by heuristic"' in flat


async def test_hub_from_setting() -> None:
    text = await text_of({}, hub_devices="hub1, hub2")
    flat = " ".join(text.split())
    assert '(CATSDWAN_HUB_DEVICES): "hub1", "hub2"' in flat and "ask the user which one to fail" in flat
    assert "hub by heuristic" not in flat


async def test_given_hub_wins_over_setting() -> None:
    text = await text_of({"hub": "hub2"}, hub_devices="hub1")
    assert 'The hub to fail is "hub2" (given)' in " ".join(text.split())


async def test_dc_services_given_or_found() -> None:
    given = await text_of({"hub": "hub1", "dc_services": "ISE 192.0.2.20, DHCP 192.0.2.30, FTD 192.0.2.40"})
    assert "ISE 192.0.2.20; DHCP 192.0.2.30; FTD 192.0.2.40" in given
    assert "`ise_deployment_health`" in given  # still checked during the drill
    found = await text_of({"hub": "hub1"})
    assert "`fmc_list_devices`" in found and "ask the user for the DHCP server" in found


async def test_sites_and_default_vpns() -> None:
    text = await text_of({"hub": "hub1", "sites": "200, 201"})
    assert '"200", "201"' in text and "service VPN (every one" in text
