"""W10: workflow prompts (core prompt test kit): contract against the cml, ise and fmc manifests and a
hand-written netbox manifest, snapshots, rendering and tier gating."""

from pathlib import Path

from fastmcp import Client

from cat_sdwan_mcp._core.prompts import rendered_text
from cat_sdwan_mcp._core.testing import (
    assert_prompt_contract,
    assert_prompt_snapshots,
    assert_suite_pack,
    load_tool_manifests,
)

from .conftest import make_server

TESTS = Path(__file__).resolve().parents[1]
MANIFESTS = TESTS / "manifests"
SNAPSHOTS = TESTS / "snapshots" / "prompts-rw"
KNOWN = {"cml", "ise", "fmc", "catc", "netbox", "win", "catsdwan"}

SAMPLES = {
    "catsdwan_admin_access_via_ise": {
        "manager_ip": "192.0.2.10",
        "ise_ip": "192.0.2.20",
        "ad_group": "mcp-sdwan-admins",
        "ad_user": "mcp-sdwan-op1",
        "sdwan_group": "operator",
        "vpn": "0",
        "keep_enabled": "false",
    },
    "catsdwan_branch_health": {"site": "200", "lab": "mcp-cat-sdwan"},
    "catsdwan_onboard_branch": {
        "site": "201",
        "chassis": "C8K-00000000-0000-4000-8000-000000000001",
        "config_group": "mcp-test",
        "hostname": "br2",
        "lab": "mcp-cat-sdwan",
    },
    "catsdwan_sgt_path": {"source": "10.61.200.10", "destination": "10.61.100.10", "vpn": "10"},
    "catsdwan_why_is_app_slow": {
        "host": "10.61.200.10",
        "app": "ssh to 10.61.100.10",
        "lab": "mcp-cat-sdwan",
    },
}


def all_tiers() -> object:
    return make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)


async def text_of(name: str, args: dict[str, str], server: object | None = None) -> str:
    async with Client(server or all_tiers()) as c:  # type: ignore[arg-type]
        return rendered_text(await c.get_prompt(name, args))


def test_manifests_cover_the_other_servers() -> None:
    manifests = load_tool_manifests(MANIFESTS)
    assert set(manifests) == {"catsdwan", "catc", "cml", "ise", "fmc", "netbox"}
    assert {"cml_get_link_scenarios", "cml_check_reachability", "cml_build_recipe"} <= manifests["cml"]
    assert {"netbox_site_summary", "netbox_add_journal_entry"} <= manifests["netbox"]
    # This server's own manifest (`cat-sdwan-mcp-server tools --json --out tests/manifests/catsdwan.json`),
    # for peers checking their catsdwan legs.
    assert {"catsdwan_snapshot", "catsdwan_compare_snapshot", "suite_change_check"} <= manifests["catsdwan"]


async def test_manifest_of_this_server_is_current() -> None:
    async with Client(all_tiers()) as c:  # type: ignore[arg-type]
        names = {t.name for t in await c.list_tools()} | {p.name for p in await c.list_prompts()}
    assert load_tool_manifests(MANIFESTS / "catsdwan.json")["catsdwan"] == names


async def test_suite_pack() -> None:
    await assert_suite_pack(all_tiers(), "catsdwan", MANIFESTS)  # type: ignore[arg-type]


async def test_prompt_contract_against_the_manifests() -> None:
    await assert_prompt_contract(
        all_tiers(),  # type: ignore[arg-type]
        "catsdwan",
        samples=SAMPLES,
        known_prefixes=KNOWN,
        external_tools=load_tool_manifests(MANIFESTS),
    )


async def test_prompt_snapshots() -> None:
    await assert_prompt_snapshots(all_tiers(), SNAPSHOTS, samples=SAMPLES)  # type: ignore[arg-type]


async def test_prompts_declare_their_servers() -> None:
    async with Client(all_tiers()) as c:  # type: ignore[arg-type]
        prompts = {p.name: p for p in await c.list_prompts()}
    uses = {n: (p.meta or {}).get("uses") for n, p in prompts.items()}
    assert uses == {
        "catsdwan_admin_access_via_ise": ["catsdwan", "ise", "win"],
        "catsdwan_branch_health": ["catsdwan", "cml", "netbox"],
        "catsdwan_onboard_branch": ["catsdwan", "netbox", "cml"],
        "catsdwan_why_is_app_slow": ["catsdwan", "ise", "fmc", "cml", "netbox"],
        "catsdwan_sgt_path": ["catsdwan", "ise"],
        "suite_change_check": ["catsdwan", "ise", "catc", "fmc"],
        "catsdwan_wifi_lan_or_wan": ["catsdwan", "catc", "ise", "cml"],
        "catsdwan_network_or_ise": ["catsdwan", "ise"],
        "catsdwan_site_down": ["catsdwan", "catc", "ise", "cml"],
        "catsdwan_brownout_drill": ["catsdwan", "cml"],
    }


async def test_branch_health_renders_a_verdict_per_transport() -> None:
    text = await text_of("catsdwan_branch_health", SAMPLES["catsdwan_branch_health"])
    for ref in (
        "catsdwan_device_health",
        "catsdwan_control_connections",
        "catsdwan_bfd_sessions",
        "catsdwan_app_route_stats",
        "catsdwan_list_alarms",
        "catsdwan_recent_activity",
        "cml_get_link_scenarios",
    ):
        assert f"`{ref}`" in text
    assert 'site="200"' in text and 'lab="mcp-cat-sdwan"' in text
    assert "healthy" in text and "degraded" in text and "down" in text
    assert "skipped if that server is not connected" in text


async def test_branch_health_default_lab() -> None:
    text = await text_of("catsdwan_branch_health", {"site": "SITE_100"})
    assert 'lab="mcp-cat-sdwan"' in text


async def test_onboard_branch_is_preview_first_and_chains_the_servers() -> None:
    text = await text_of("catsdwan_onboard_branch", SAMPLES["catsdwan_onboard_branch"])
    order = [
        "netbox_site_summary",
        "netbox_next_available_ips",
        "catsdwan_list_wan_edges",
        "catsdwan_onboard_edge",
        "catsdwan_bootstrap_config",
        "cml_configure_node",
        "catsdwan_control_connections",
        "catsdwan_deploy_config_group",
        "catsdwan_bfd_sessions",
        "cml_check_reachability",
        "netbox_add_journal_entry",
    ]
    positions = [text.index(f"`{ref}`") for ref in order]
    assert positions == sorted(positions)
    assert "PREVIEW-FIRST" in text and 'use chassis "C8K-00000000-0000-4000-8000-000000000001"' in text
    assert 'config_group="mcp-test"' in text and "hostname=br2" in text
    assert 'recipe "cat-sdwan-fabric"' in text and "one-time token" in text


async def test_onboard_branch_without_optional_arguments() -> None:
    text = await text_of("catsdwan_onboard_branch", {"site": "201"})
    assert "pick a free chassis" in text and "ask the user which group" in text


async def test_onboard_branch_hidden_without_writes() -> None:
    async with Client(make_server()) as c:
        names = {p.name for p in await c.list_prompts()}
    assert "catsdwan_onboard_branch" not in names
    assert {"catsdwan_branch_health", "catsdwan_why_is_app_slow", "suite_change_check"} <= names


async def test_why_is_app_slow_renders() -> None:
    text = await text_of("catsdwan_why_is_app_slow", SAMPLES["catsdwan_why_is_app_slow"])
    for ref in (
        "ise_find_session",
        "netbox_lookup_ip",
        "catsdwan_app_route_stats",
        "catsdwan_list_sla_classes",
        "fmc_packet_tracer",
        "cml_get_link_scenarios",
    ):
        assert f"`{ref}`" in text
    assert "10.61.200.10" in text and "ssh to 10.61.100.10" in text and "ONE sentence" in text


async def test_sgt_path_walks_edge_overlay_and_ise() -> None:
    text = await text_of("catsdwan_sgt_path", SAMPLES["catsdwan_sgt_path"])
    order = [
        "catsdwan_find_host",
        "ise_find_session",
        "ise_list_sgts",
        "catsdwan_trustsec_path",
        "ise_get_egress_matrix",
    ]
    positions = [text.index(f"`{ref}`") for ref in order]
    assert positions == sorted(positions)
    assert 'host="10.61.200.10", vpn="10"' in text and 'destination_ip="10.61.100.10"' in text
    for verdict in ("enforced as ISE intends", "tag lost on <tunnel>", "no policy at <edge>"):
        assert verdict in text
    assert "Read-only" in text


async def test_sgt_path_without_vpn() -> None:
    text = await text_of("catsdwan_sgt_path", {"source": "alice", "destination": "10.61.100.10"})
    assert 'host="alice")' not in text and 'host="alice"' in text and "vpn=" not in text


async def test_admin_access_via_ise_local_first_and_lockout() -> None:
    text = await text_of("catsdwan_admin_access_via_ise", SAMPLES["catsdwan_admin_access_via_ise"])
    assert "order=['local', 'radius']" in text and "never falls back to local" in text
    assert 'sdwan_group="operator"' in text and 'sdwan_group="netadmin"' in text
    assert "Viptela-Group-Name" in text and 'scope="policyset"' in text
    assert text.index("6. Baseline") < text.index("8. External authentication") < text.index("9. Right after")
    assert "`catsdwan_test_login`" in text and "run the preview's `undo` (preview, approval)" in text
    # W40: a single-tenant Manager's own logins are its system AAA (template), a provider's /admin/radius.
    assert "single-tenant" in text and "mcp-manager-system-aaa" in text and "section='system'" in text
    assert "servers=[] on a single-tenant Manager" in text[text.index("12. Switch off") :]
    kept = await text_of(
        "catsdwan_admin_access_via_ise", {**SAMPLES["catsdwan_admin_access_via_ise"], "keep_enabled": "true"}
    )
    assert "Leave it on" in kept and "ise_delete_object" not in kept and "mcp_sdwan_admins" in kept
    # The undo removes the identity sequence step 5 created; no password is ever asked through the client.
    undo = text[text.index("12. Switch off") :]
    assert "mcp_sdwan_admins" in undo and "`ise_delete_policy_set`" in undo
    assert "CATSDWAN_TEST_LOGIN_PASSWORDS" in text and "prompts the user" not in text


async def test_admin_access_via_ise_needs_dangerous_and_valid_ips() -> None:
    async with Client(make_server(mcp_enable_writes=True)) as c:  # type: ignore[arg-type]
        assert "catsdwan_admin_access_via_ise" not in {p.name for p in await c.list_prompts()}
    async with Client(all_tiers()) as c:  # type: ignore[arg-type]
        try:
            await c.get_prompt("catsdwan_admin_access_via_ise", {"manager_ip": "mgr", "ise_ip": "192.0.2.20"})
        except Exception as e:  # noqa: BLE001
            assert "IP addresses" in str(e)
        else:
            raise AssertionError("a host name for manager_ip must be refused")
