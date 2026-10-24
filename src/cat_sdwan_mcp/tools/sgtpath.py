"""W42 an SGT across the overlay: catsdwan_trustsec_path (read), the prompt catsdwan_sgt_path (uses ise)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client, tool_ref
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.dataplane import BFD_SESSIONS_PATH
from cat_sdwan_mcp.fabric import device_rows, require_reachable
from cat_sdwan_mcp.inventory import INTERFACE_PATH, load_inventory, resolve
from cat_sdwan_mcp.sgtpath import INTERFACE_TRUSTSEC_PATH, binding_for, policy_for, tunnel_row
from cat_sdwan_mcp.trustsec import EDGE_PATHS, environment, rows_of, sxp_row, unsupported

OPTIONAL = "skipped if that server is not connected: say so in one line and go on"

SRC_TABLES = {
    "interfaces": INTERFACE_PATH,
    "interface_trustsec": INTERFACE_TRUSTSEC_PATH,
    "bfd": BFD_SESSIONS_PATH,
    "sgt_map": EDGE_PATHS["sgt_map"],
    "sxp": EDGE_PATHS["sxp"],
}
DST_TABLES = {
    "interfaces": INTERFACE_PATH,
    "interface_trustsec": INTERFACE_TRUSTSEC_PATH,
    "sgt_map": EDGE_PATHS["sgt_map"],
    "permissions": EDGE_PATHS["permissions"],
    "counters": EDGE_PATHS["counters"],
    "sxp": EDGE_PATHS["sxp"],
    "environment": EDGE_PATHS["environment"],
}

Sgt = Annotated[
    int | None,
    Field(ge=0, le=65535, description="Use this SGT number instead of the edge's IP-to-SGT binding"),
]


async def _tables(
    app: SdwanApp, ip: str, name: str, tables: dict[str, str], errors: list[str], missing: list[str]
) -> dict[str, list[dict[str, Any]]]:
    keys = list(tables)
    got = await asyncio.gather(*(device_rows(app, tables[k], ip) for k in keys), return_exceptions=True)
    out: dict[str, list[dict[str, Any]]] = {}
    for k, res in zip(keys, got, strict=True):
        out[k] = []
        if isinstance(res, UpstreamError):
            (missing if unsupported(str(res)) else errors).append(
                f"{name}: GET {tables[k]}: {str(res)[:200]}"
            )
        elif isinstance(res, BaseException):
            raise res
        else:
            out[k] = res if k in ("interfaces", "bfd", "interface_trustsec") else rows_of(res)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SGT path across the SD-WAN overlay")
    async def catsdwan_trustsec_path(
        ctx: Context,
        source_edge: Annotated[str, Field(description="The source host's edge (host name or system IP)")],
        destination_edge: Annotated[str, Field(description="The destination host's edge")],
        source_ip: Annotated[str, Field(description="The source host's IP address, e.g. 10.61.200.10")],
        destination_ip: Annotated[str, Field(description="The destination host's IP address")],
        vpn: Annotated[
            str | None, Field(description="Service VPN / VRF of the hosts (e.g. '10'); default any")
        ] = None,
        source_sgt: Sgt = None,
        destination_sgt: Sgt = None,
    ) -> dict[str, Any]:
        """Follow a source host's SGT across the overlay to the destination edge, read live on both edges:
        the source edge's IP-to-SGT binding (how it was learned), each tunnel between the two edges with
        inline tagging on the sending and the receiving interface (`cts manual`, propagate, trusted), SXP or
        pxGrid as the way the source tag reaches the destination edge when no tunnel carries it, the
        destination host's SGT, and the destination edge's SGACL for that pair with its permit and deny
        counters. `verdict` is one line: enforced at <edge> by <SGACL> / tag lost on <tunnel> / no policy at
        <edge> / no SGT for the source. Compare with ise_get_egress_matrix for what ISE intends (the prompt
        catsdwan_sgt_path walks it all). Find the edges with catsdwan_find_host."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        src_row, dst_row = resolve(inv, source_edge), resolve(inv, destination_edge)
        if src_row is dst_row:
            raise InvalidRequest("Both hosts are behind the same edge: no overlay tunnel to follow.")
        hint = "catsdwan_list_devices shows each device's reachability."
        src_ip_sys, dst_ip_sys = require_reachable(src_row, hint), require_reachable(dst_row, hint)
        src_name = str(src_row.get("host") or src_ip_sys)
        dst_name = str(dst_row.get("host") or dst_ip_sys)
        errors: list[str] = []
        missing: list[str] = []
        s, d = await asyncio.gather(
            _tables(app, src_ip_sys, src_name, SRC_TABLES, errors, missing),
            _tables(app, dst_ip_sys, dst_name, DST_TABLES, errors, missing),
        )

        # 1. The source tag.
        src_bind = binding_for(s["sgt_map"], source_ip, vpn)
        src_sgt = source_sgt if source_sgt is not None else (src_bind or {}).get("sgt")
        source: dict[str, Any] = {"edge": src_name, "ip": source_ip, "sgt": src_sgt}
        if source_sgt is not None:
            source["sgt_from"] = "given"
        elif src_bind:
            source |= {"sgt_from": "binding", **src_bind}

        # 2. The tunnels between the two edges.
        tunnels = [
            tunnel_row(b, s["interfaces"], s["interface_trustsec"], d["interfaces"], d["interface_trustsec"])
            for b in s["bfd"]
            if str(b.get("system-ip")) == dst_ip_sys
        ]
        up = [t for t in tunnels if str(t.get("state", "")).lower() == "up"]
        carrying = [t for t in up if t.get("carries_tag")]
        lost = [t for t in up if not t.get("carries_tag")]

        # 3. SXP / pxGrid: the source host's binding as the destination edge has it.
        far_bind = binding_for(d["sgt_map"], source_ip, vpn)
        delivery: dict[str, Any] = {"inline_tunnels": len(carrying), "up_tunnels": len(up)}
        if far_bind:
            delivery["binding_at_destination"] = far_bind
        sxp = {
            "source_edge": [sxp_row(r) for r in s["sxp"]],
            "destination_edge": [sxp_row(r) for r in d["sxp"]],
        }
        sxp = {k: v for k, v in sxp.items() if v}
        if sxp:
            delivery["sxp"] = sxp
        seen_sgt = src_sgt if carrying else (far_bind or {}).get("sgt")

        # 4. The destination tag and the policy there.
        dst_bind = binding_for(d["sgt_map"], destination_ip, vpn)
        dst_sgt = destination_sgt if destination_sgt is not None else (dst_bind or {}).get("sgt")
        destination: dict[str, Any] = {"edge": dst_name, "ip": destination_ip, "sgt": dst_sgt}
        if destination_sgt is not None:
            destination["sgt_from"] = "given"
        elif dst_bind:
            destination |= {"sgt_from": "binding", **dst_bind}
        env = environment(d["environment"])
        policy: dict[str, Any] = {"edge": dst_name}
        if env:
            policy["environment_downloaded"] = env.get("downloaded")
        found = None
        if seen_sgt is not None and dst_sgt is not None:
            found = policy_for(d["permissions"], d["counters"], int(seen_sgt), int(dst_sgt))
            policy |= {"source_sgt": seen_sgt, "destination_sgt": dst_sgt}
            policy |= found or {
                "sgacls": None,
                "meaning": "no SGACL for this pair: the edge's default applies",
            }

        kind, verdict = _verdict(
            src_name, dst_name, source_ip, src_sgt, tunnels, up, carrying, lost, far_bind, dst_sgt, found, env
        )
        out: dict[str, Any] = {
            "verdict": verdict,
            "verdict_kind": kind,
            "source": source,
            "tunnels": tunnels,
            "delivery": delivery,
            "destination": destination,
            "policy": policy,
        }
        if seen_sgt is not None and dst_sgt is not None:
            out["compare_with_ise"] = (
                f"ise_list_sgts for the names of SGT {seen_sgt} and {dst_sgt}, then ise_get_egress_matrix("
                "source=<its name>, destination=<its name>): the SGACLs ISE intends for this cell"
            )
        if missing:
            out["not_supported"] = missing
        if errors:
            out["errors"] = errors
        return out

    @reg.prompt(
        title="SGT path across the SD-WAN overlay",
        uses=["catsdwan", "ise"],
        example={"source": "10.61.200.10", "destination": "10.61.100.10", "vpn": "10"},
    )
    def catsdwan_sgt_path(
        source: Annotated[str, Field(description="Source host IP (or a user name ISE has a session for)")],
        destination: Annotated[str, Field(description="Destination host IP, e.g. '10.61.100.10'")],
        vpn: Annotated[str, Field(description="Service VPN of the hosts (blank = find it)")] = "",
    ) -> str:
        """Does SGT segmentation hold from this source to this destination across the SD-WAN? Source host ->
        its edge -> the SGT it is given (802.1X/MAB, SXP, pxGrid, static) -> inline tagging on each tunnel ->
        the destination edge's SGACL -> what ISE's egress matrix intends; verdict: enforced as ISE intends /
        tag lost on <tunnel> / no policy at <edge>."""
        vpn_arg = f', vpn="{vpn.strip()}"' if vpn.strip() else ""
        return f"""Check that SGT policy from {source} to {destination} is enforced across the SD-WAN as
ISE intends. Read-only: change nothing; suggest fixes, don't apply them.

1. Where are the hosts? {tool_ref("catsdwan_find_host")} with host="{source}"{vpn_arg}, then with
   host="{destination}"{vpn_arg}: the edge, site and VPN of each. If {source} is a user name, find
   the IP first with ISE's {tool_ref("ise_find_session")} ({OPTIONAL}). Both behind one edge: say
   so and check that edge only with {tool_ref("catsdwan_trustsec")}.
2. What ISE gives the source (ISE, {OPTIONAL}): {tool_ref("ise_find_session")} for the source
   (the authorization result and its SGT), {tool_ref("ise_list_sgts")} (SGT names and numbers),
   and, when the edges learn bindings over SXP or static mappings,
   {tool_ref("ise_list_sxp_bindings")} / {tool_ref("ise_list_ip_sgt_mappings")}.
3. Each edge's TrustSec state: {tool_ref("catsdwan_trustsec")} with device=<each edge>: the
   environment data from ISE (downloaded or not: without it an edge has no SGACLs), bindings,
   SXP, pxGrid.
4. The overlay: {tool_ref("catsdwan_trustsec_path")} with source_edge, destination_edge,
   source_ip="{source}", destination_ip="{destination}"{vpn_arg} (add source_sgt / destination_sgt
   from step 2 when an edge has no binding). Per tunnel and colour: does the source edge send the
   tag (propagate) and does the destination edge keep it (trusted); SXP or pxGrid as the other
   way the tag arrives; the destination edge's SGACL and its counters.
5. What ISE intends (ISE, {OPTIONAL}): {tool_ref("ise_get_egress_matrix")} with
   source=<the source SGT's name> and destination=<the destination SGT's name>: the SGACLs and the
   catch-all; no cell = the ANY-ANY default.

Verdict, ONE line first, one of:
- enforced as ISE intends: the tag arrives (name the tunnels or SXP) and the destination edge's
  SGACL matches ISE's cell (name it, with the deny/permit counters);
- tag lost on <tunnel>: the colour and the reason (inline tagging off on <interface>, untrusted
  ingress), and whether another colour still carries it (then it depends on the path the policy
  picks: {tool_ref("catsdwan_explain_path")});
- no policy at <edge>: no SGACL for the pair, or the edge's environment data was never
  downloaded, while ISE has a cell;
- differs from ISE: the edge enforces another SGACL than ISE's cell (stale environment data:
  refresh it on the edge);
- the source has no SGT: classification is missing at the source edge or in ISE's authorization.
Then the evidence per step and the next action (which interface to tag, which SXP peer, which
ISE cell)."""


def _verdict(
    src: str,
    dst: str,
    source_ip: str,
    src_sgt: Any,
    tunnels: list[dict[str, Any]],
    up: list[dict[str, Any]],
    carrying: list[dict[str, Any]],
    lost: list[dict[str, Any]],
    far_bind: dict[str, Any] | None,
    dst_sgt: Any,
    found: dict[str, Any] | None,
    env: dict[str, Any] | None,
) -> tuple[str, str]:
    if src_sgt is None:
        return "no_source_sgt", (
            f"{source_ip} has no SGT at {src}: no IP-to-SGT binding covers it (classification is missing: "
            "an 802.1X/MAB authorization with an SGT, a static mapping or SXP); give source_sgt to check the "
            "rest of the path"
        )
    if not tunnels:
        return "no_tunnel", f"{src} has no tunnel (BFD session) to {dst}: traffic doesn't cross the overlay"
    if not up:
        return "no_tunnel", f"no tunnel from {src} to {dst} is up: nothing carries the traffic"
    lost_txt = "; ".join(f"{t['tunnel']}: {t['why_not'][0]}" for t in lost)
    if not carrying and not far_bind:
        return (
            "tag_lost",
            f"SGT {src_sgt} is lost between {src} and {dst} on {lost_txt}, and {dst} has no SXP or "
            "pxGrid binding for the source",
        )
    far = far_bind or {}
    via = (
        f"inline on {', '.join(t['tunnel'] for t in carrying)}"
        if carrying
        else f"by {far.get('learned_from') or 'a binding'} ({far.get('binding')}), not inline"
    )
    seen = src_sgt if carrying else far.get("sgt")
    head = f"SGT {src_sgt} reaches {dst} {via}"
    if not carrying and seen != src_sgt:
        head += f", but as SGT {seen}"
    partly = f"; tag lost on {lost_txt}" if carrying and lost else ""
    if dst_sgt is None:
        return "no_destination_sgt", (
            f"{head}{partly}; the destination has no SGT at {dst} (no binding covers it): give "
            "destination_sgt"
        )
    if not found:
        why = (
            " (its environment data from ISE was never downloaded)"
            if env and not env.get("downloaded")
            else ""
        )
        return "no_policy", f"{head}{partly}; no policy at {dst} for SGT {seen} -> {dst_sgt}{why}"
    acls = ", ".join(found.get("sgacls") or []) or "an SGACL"
    counts = f" (permitted {found.get('permitted', 0)}, denied {found.get('denied', 0)})"
    kind = "partly_lost" if partly else "enforced"
    return kind, f"{head}{partly}; enforced at {dst} by {acls} for SGT {seen} -> {dst_sgt}{counts}"
