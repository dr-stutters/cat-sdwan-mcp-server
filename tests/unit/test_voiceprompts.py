"""W56: catsdwan_why_is_voice_bad. The contract, `uses` and snapshot are checked with the other prompts in
test_prompts.py; these check the order of the legs, the optional catc/ise legs and the verdict."""

from fastmcp import Client

from cat_sdwan_mcp._core.prompts import rendered_text

from .conftest import make_server

NAME = "catsdwan_why_is_voice_bad"
SDWAN = [
    "catsdwan_list_devices",
    "catsdwan_list_sla_classes",
    "catsdwan_app_route_stats",
    "catsdwan_sla_history",
    "catsdwan_tunnel_path",
    "catsdwan_get_device_config",
    "catsdwan_device_state",
    "catsdwan_interface_stats",
]


async def text_of(args: dict[str, str]) -> str:
    async with Client(make_server()) as c:
        return rendered_text(await c.get_prompt(NAME, args))


def in_order(text: str, refs: list[str]) -> bool:
    pos = text.index("1. ")
    for ref in refs:
        found = text.find(f"`{ref}`", pos)
        if found < 0:
            return False
        pos = found
    return True


async def test_listed_without_writes() -> None:
    async with Client(make_server()) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
    assert NAME in prompts
    assert {a.name for a in prompts[NAME].arguments or []} == {"site", "host", "sla_class", "lab"}


async def test_with_host_walks_overlay_edge_wifi_and_ise() -> None:
    text = await text_of({"site": "200", "host": "198.51.100.10", "sla_class": "Voice-And-Video"})
    assert in_order(
        text,
        ["catsdwan_find_host", *SDWAN, "catc_client_360", "catc_get_wlc_config", "ise_find_session"],
    )
    assert in_order(text, ["ise_find_session", "cml_get_link_scenarios"])
    assert 'host="198.51.100.10" and site="200"' in text
    assert 'sla_class="Voice-And-Video"' in text and 'name="Voice-And-Video"' in text
    assert 'feature="qos"' in text and "qos=true" in text and "dscp=46" in text
    assert "platinum" in text and "WMM" in text and "dACL" in text
    assert "does not manage this site's access layer" in text
    assert "not checked" in text and "Read-only" in text and 'lab="mcp-lab-sdwan"' in text
    flat = " ".join(text.split())
    for cause in ("a transport, a queue on the edge, the Wi-Fi or ISE", "ONE sentence naming the cause"):
        assert cause in flat


async def test_without_host_skips_the_client_legs() -> None:
    text = await text_of({"site": "SITE_200"})
    assert in_order(text, [*SDWAN, "cml_get_link_scenarios"])
    for ref in ("catc_client_360", "catc_get_wlc_config", "catsdwan_find_host", "ise_find_session"):
        assert f"`{ref}`" not in text
    flat = " ".join(text.split())
    assert '"Wi-Fi: not checked", "ISE: not checked"' in flat
    assert "sla_class=<the voice class from step 2>" in text and "Voice-And-Video, Realtime" in flat
    assert 'site="SITE_200"' in text and " for " not in text.splitlines()[0]
