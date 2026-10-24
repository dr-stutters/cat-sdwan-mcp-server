"""W42: an SGT from br1 across the overlay to hub1 (catsdwan_trustsec_path) and the catsdwan_sgt_path prompt.

Recorded on 20.18.3.1 (TrustSec not configured): br1's BFD sessions (four tunnels to hub1, two colours each
side), hub1's interfaces (WAN interface and TunnelN share the address), br1's empty interface/trustsec table,
br1's and hub1's environment data stuck in env-download-in-progress. The bodies with TrustSec configured
(interface/trustsec rows, IP-to-SGT bindings, SGACLs with counters, SXP) are hand-built from the field names
the same Manager lists (interface/trustsec: the OpenAPI example), and marked so.
"""

from typing import Any

import pytest
import respx
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.sgtpath import binding_for, inline_state, interfaces_with

from .conftest import fixture
from .test_inventory import call, mock_inventory

BR1, HUB1 = "10.0.0.2", "10.0.0.1"
SRC, DST = "10.61.200.10", "10.61.100.10"
EMPTY: dict[str, Any] = {"data": []}


def cts(*rows: tuple[str, str, str]) -> dict[str, Any]:
    """Hand-built interface/trustsec rows: (if-name, sgt-propagate, trusted)."""
    return {"data": [{"if-name": n, "mode": "cts-ndac-mode-manual", "sgt-propagate": p, "trusted": t,
                      "peer-sgt": 0} for n, p, t in rows]}  # fmt: skip


ON, OFF = "cts-sgt-propagate-enabled", "cts-sgt-propagate-disabled"
TRUSTED, UNTRUSTED = "cts-manual-trusted", "cts-manual-untrusted"
ALL_ON = cts(("GigabitEthernet1", ON, TRUSTED), ("GigabitEthernet2", ON, TRUSTED))
SRC_MAP = {"data": [{"ip": "10.61.200.10/32", "vrf-name": "10", "sgt": "17", "source": "LOCAL"}]}
DST_MAP = {"data": [{"ip": "10.61.100.0/24", "vrf-name": "10", "sgt": "18", "source": "CLI"},
                    {"ip": "10.61.100.10/32", "vrf-name": "10", "sgt": "19", "source": "CLI"}]}  # fmt: skip
PERMS = {
    "data": [{"src-sgt": "17", "dst-sgt": "19", "sgacl-name": "Deny_IP_Log-00", "monitor-mode": "FALSE"}]
}
COUNTERS = {"data": [{"src-sgt": "17", "dst-sgt": "19", "total-deny-count": "9", "total-permit-count": "0"}]}
ARGS = {
    "source_edge": "br1",
    "destination_edge": "hub1",
    "source_ip": SRC,
    "destination_ip": DST,
    "vpn": "10",
}


def env_done() -> dict[str, Any]:
    env = fixture("device_environmentdata_br1")
    env["data"][0].update({"status": "env-download-complete", "total-num-servers": 1})
    return env


def mock_edges(
    api: respx.MockRouter, *, src: dict[str, Any] | None = None, dst: dict[str, Any] | None = None
) -> None:
    mock_inventory(api)
    s = {
        "/dataservice/device/interface": fixture("device_interface_br1"),
        "/dataservice/device/interface/trustsec": ALL_ON,
        "/dataservice/device/bfd/sessions": fixture("device_bfd_sessions_br1"),
        "/dataservice/device/roleBasedSgtMap": SRC_MAP,
        "/dataservice/device/sxpConnections": EMPTY,
        **(src or {}),
    }
    d = {
        "/dataservice/device/interface": fixture("device_interface_hub1"),
        "/dataservice/device/interface/trustsec": ALL_ON,
        "/dataservice/device/roleBasedSgtMap": DST_MAP,
        "/dataservice/device/roleBasedPermissions": PERMS,
        "/dataservice/device/roleBasedCounters": COUNTERS,
        "/dataservice/device/sxpConnections": EMPTY,
        "/dataservice/device/environmentData": env_done(),
        **(dst or {}),
    }
    for ip, table in ((BR1, s), (HUB1, d)):
        for path, body in table.items():
            api.get(path, params={"deviceId": ip}).respond(json=body)


async def test_enforced_inline_on_every_tunnel(api: respx.MockRouter) -> None:
    mock_edges(api)
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "enforced"
    assert out["verdict"] == (
        "SGT 17 reaches hub1 inline on mpls -> mpls, mpls -> biz-internet, biz-internet -> mpls, "
        "biz-internet -> biz-internet; enforced at hub1 by Deny_IP_Log-00 for SGT 17 -> 19 "
        "(permitted 0, denied 9)"
    )
    assert out["source"] == {"edge": "br1", "ip": SRC, "sgt": 17, "sgt_from": "binding",
                             "binding": "10.61.200.10/32", "learned_from": "LOCAL", "vrf": "10"}  # fmt: skip
    assert out["destination"]["sgt"] == 19  # the /32 beats the /24
    assert len(out["tunnels"]) == 4 and all(t["carries_tag"] for t in out["tunnels"])
    first = out["tunnels"][0]
    assert (
        first["source_interface"] == "GigabitEthernet1"
        and first["destination_interface"] == "GigabitEthernet1"
    )
    assert out["policy"]["environment_downloaded"] is True and out["policy"]["denied"] == "9"
    assert "ise_get_egress_matrix" in out["compare_with_ise"]


async def test_tag_lost_on_one_colour(api: respx.MockRouter) -> None:
    br1 = cts(("GigabitEthernet1", ON, TRUSTED), ("GigabitEthernet2", OFF, TRUSTED))
    mock_edges(api, src={"/dataservice/device/interface/trustsec": br1})
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "partly_lost"
    assert "tag lost on biz-internet -> mpls: `propagate sgt` is off on GigabitEthernet2" in out["verdict"]
    lost = [t["tunnel"] for t in out["tunnels"] if not t["carries_tag"]]
    assert lost == ["biz-internet -> mpls", "biz-internet -> biz-internet"]


async def test_tag_lost_everywhere_without_sxp(api: respx.MockRouter) -> None:
    mock_edges(api, src={"/dataservice/device/interface/trustsec": fixture("device_interface_trustsec_br1")})
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "tag_lost"
    assert out["verdict"].startswith(
        "SGT 17 is lost between br1 and hub1 on mpls -> mpls: no `cts manual` on "
    )
    assert "GigabitEthernet1/Tunnel1 at the source edge" in out["verdict"]
    assert "policy" in out and "source_sgt" not in out["policy"]


async def test_untrusted_ingress_but_sxp_delivers(api: respx.MockRouter) -> None:
    hub = cts(("GigabitEthernet1", ON, UNTRUSTED), ("GigabitEthernet2", ON, UNTRUSTED))
    dst_map = {
        "data": [*DST_MAP["data"], {"ip": "10.61.200.10/32", "vrf-name": "10", "sgt": "17", "source": "SXP"}]
    }
    sxp = {
        "data": [
            {"peer-ip": "198.51.100.35", "source-ip": HUB1, "listener-state": "On", "local-mode": "Listener"}
        ]
    }
    mock_edges(
        api,
        dst={
            "/dataservice/device/interface/trustsec": hub,
            "/dataservice/device/roleBasedSgtMap": dst_map,
            "/dataservice/device/sxpConnections": sxp,
        },
    )
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "enforced"
    assert out["verdict"].startswith(
        "SGT 17 reaches hub1 by SXP (10.61.200.10/32), not inline; enforced at hub1"
    )
    assert "untrusted" in out["tunnels"][0]["why_not"][0]
    assert out["delivery"]["sxp"]["destination_edge"][0]["listener"] == "On"


async def test_no_policy_at_destination(api: respx.MockRouter) -> None:
    env = fixture("device_environmentdata_br1")  # recorded: env-download-in-progress
    mock_edges(
        api,
        dst={
            "/dataservice/device/roleBasedPermissions": EMPTY,
            "/dataservice/device/roleBasedCounters": EMPTY,
            "/dataservice/device/environmentData": env,
        },
    )
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "no_policy"
    assert out["verdict"].endswith(
        "no policy at hub1 for SGT 17 -> 19 (its environment data from ISE was never downloaded)"
    )
    assert out["policy"]["sgacls"] is None


async def test_no_source_sgt_and_given_sgts(api: respx.MockRouter) -> None:
    mock_edges(api, src={"/dataservice/device/roleBasedSgtMap": EMPTY})
    out = await call("catsdwan_trustsec_path", ARGS)
    assert out["verdict_kind"] == "no_source_sgt" and "has no SGT at br1" in out["verdict"]


async def test_given_sgts_override_bindings(api: respx.MockRouter) -> None:
    mock_edges(
        api,
        src={"/dataservice/device/roleBasedSgtMap": EMPTY},
        dst={"/dataservice/device/roleBasedSgtMap": EMPTY},
    )
    out = await call("catsdwan_trustsec_path", {**ARGS, "source_sgt": 17, "destination_sgt": 19})
    assert out["verdict_kind"] == "enforced" and out["source"]["sgt_from"] == "given"


async def test_same_edge_is_refused(api: respx.MockRouter) -> None:
    mock_inventory(api)
    with pytest.raises(ToolError, match="same edge"):
        await call("catsdwan_trustsec_path", {**ARGS, "destination_edge": "br1"})


def test_helpers() -> None:
    rows = fixture("device_interface_hub1")["data"]
    assert interfaces_with(rows, "10.60.1.13") == ["GigabitEthernet1", "Tunnel1"]
    assert interfaces_with(rows, "203.0.113.1") == []
    assert inline_state([], ["GigabitEthernet1"]) == {
        "configured": False,
        "propagate": False,
        "trusted": False,
    }
    tun = inline_state(cts(("Tunnel1", ON, TRUSTED))["data"], ["GigabitEthernet1", "Tunnel1"])
    assert tun["propagate"] and tun["interface"] == "Tunnel1"
    assert binding_for(DST_MAP["data"], "10.61.100.20", "10") == {
        "binding": "10.61.100.0/24", "sgt": 18, "learned_from": "CLI", "vrf": "10"}  # fmt: skip
    assert binding_for(DST_MAP["data"], "10.61.100.20", "20") is None
    assert binding_for(DST_MAP["data"], "not-an-ip") is None
