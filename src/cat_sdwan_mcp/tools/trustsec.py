"""W24 TrustSec and integrations: catsdwan_trustsec, catsdwan_integrations."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any
from urllib.parse import quote

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import ResponseFormat, ToolRegistrar, UpstreamError, get_client, object_result
from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.fabric import device_rows, find_device, require_reachable
from cat_sdwan_mcp.trustsec import (
    DNAC_DEVICES_PATH,
    DNAC_SITES_PATH,
    DNAC_VPN_PATH,
    EDGE_PATHS,
    ISE_CONNECT_PATH,
    ISE_CREDENTIALS_PATH,
    ISE_PXGRID_PATH,
    ISE_SGT_PATH,
    PARTNER_PATH,
    configured,
    counter_index,
    environment,
    is_dnac,
    partners,
    permission_row,
    rows_of,
    sgt_row,
    sxp_row,
    unsupported,
)

SHOW = 50  # rows shown per table (the count is always given)


async def _get(app: SdwanApp, path: str) -> Any:
    """The body, or {"error": ...} when the Manager answers with an error."""
    try:
        return await app.api.get(path)
    except UpstreamError as e:
        return {"error": f"GET {path} failed: {str(e)[:300]}"}


def _err(body: Any) -> str | None:
    return body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else None


def _table(rows: list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
    return rows if len(rows) <= SHOW else {"count": len(rows), "first": rows[:SHOW]}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN edge TrustSec state")
    async def catsdwan_trustsec(
        ctx: Context,
        device: Annotated[str, Field(description="The edge: host name, system IP, chassis or serial")],
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """An edge's TrustSec state, read live: the environment data from ISE (download status, device SGT,
        RADIUS servers, refresh), the PAC (opaque value masked), IP-to-SGT bindings and where each was learned
        (CLI, SXP, pxGrid, ...), SGACLs per source/destination SGT with their permit and deny counters, SXP
        connections, pxGrid status with the IP-to-user bindings and sessions, and 802.1X clients, interfaces
        and RADIUS servers. A table this edge model or release doesn't have is listed under `not_supported`.
        `verdict` says in one line whether SGT-based policy can work on this edge (no environment data, no
        bindings, no SXP and no pxGrid = TrustSec not configured). Compare with ise_list_sgts and
        ise_get_egress_matrix for what ISE intends."""
        app: SdwanApp = get_client(ctx)
        row, _ = await find_device(app, device)
        ip = require_reachable(row, "catsdwan_list_devices shows each device's reachability.")
        name = str(row.get("host") or ip)
        keys = list(EDGE_PATHS)
        got = await asyncio.gather(
            *(device_rows(app, EDGE_PATHS[k], ip) for k in keys), return_exceptions=True
        )
        t: dict[str, list[dict[str, Any]]] = {}
        errors: list[str] = []
        missing: list[str] = []
        for k, res in zip(keys, got, strict=True):
            t[k] = []
            if isinstance(res, UpstreamError):
                if unsupported(str(res)):
                    missing.append(f"{k} (GET {EDGE_PATHS[k]})")
                else:
                    errors.append(f"{k}: GET {EDGE_PATHS[k]} failed: {str(res)[:200]}")
            elif isinstance(res, BaseException):
                raise res
            else:
                t[k] = rows_of(res)
        out: dict[str, Any] = {"device": name, "system_ip": ip}
        env = environment(t["environment"])
        if env:
            out["environment"] = env
        if t["environment_servers"]:
            out["environment_servers"] = t["environment_servers"]
        if t["pac"]:
            out["pac"] = t["pac"]
        bindings = [sgt_row(r) for r in t["sgt_map"]]
        if bindings:
            out["sgt_bindings"] = _table(bindings)
        counters = counter_index(t["counters"])
        perms = [permission_row(r, counters) for r in t["permissions"]]
        if perms:
            out["sgacls"] = _table(perms)
        sxp = [sxp_row(r) for r in t["sxp"]]
        if sxp:
            out["sxp"] = sxp
        pxgrid = {
            k: _table(t[f"pxgrid_{k}"])
            for k in ("status", "ip_sgt", "ip_user", "sessions")
            if t[f"pxgrid_{k}"]
        }
        if pxgrid:
            out["pxgrid"] = pxgrid
        dot1x = {k: _table(t[f"dot1x_{k}"]) for k in ("clients", "interfaces", "radius") if t[f"dot1x_{k}"]}
        if dot1x:
            out["dot1x"] = dot1x
        in_use = {
            "environment_data": bool(env and env.get("downloaded")),
            "sgt_bindings": bool(bindings),
            "sgacls": bool(perms),
            "sxp": bool(sxp),
            "pxgrid": bool(pxgrid),
            "dot1x": bool(dot1x),
        }
        out["in_use"] = in_use
        if not any(in_use.values()):
            out["verdict"] = (
                f"TrustSec is not configured on {name}: no environment data from ISE"
                + (f" (status {env.get('status')})" if env and env.get("status") else "")
                + ", no SGT bindings, SGACLs, SXP, pxGrid or 802.1X. SGT-based policy has nothing to match "
                "here."
            )
        else:
            parts = [k.replace("_", " ") for k, on in in_use.items() if on]
            gaps = []
            if not in_use["environment_data"]:
                gaps.append("no environment data from ISE (SGT names and SGACLs are not downloaded)")
            denied = sum(int(p.get("denied") or 0) for p in perms)
            if denied:
                gaps.append(f"SGACLs denied {denied} packet(s)")
            out["verdict"] = f"{name} uses {', '.join(parts)}" + (
                f"; attention: {'; '.join(gaps)}." if gaps else "."
            )
        if missing:
            out["not_supported"] = missing
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)

    @reg.read(title="SD-WAN Manager integrations (ISE, pxGrid, partners)")
    async def catsdwan_integrations(
        ctx: Context,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """The Manager's identity and partner integrations: the ISE connection (GET /ise/credentials, secrets
        masked; /ise/connect to test it), pxGrid (/ise/credentials/pxgrid), the SGT list learned from ISE
        (/template/policy/ise/identity/sgt), registered partners (/partner) and, for a Catalyst Center
        partner, its SD-Access sites and devices (/partner/dnac/sda/site and /sda/device) plus the VPNs
        offered to SD-Access (/partner/dnac/sda/vpn). When no ISE is configured it says so plainly (identity
        lists and user-based policy then have no source) instead of quoting the Manager's errors. Reads only:
        ISE credentials, pxGrid activation and partner onboarding stay in the GUI or catsdwan_api_call."""
        app: SdwanApp = get_client(ctx)
        creds, pxgrid_creds, partner_body, vpns = await asyncio.gather(
            _get(app, ISE_CREDENTIALS_PATH),
            _get(app, ISE_PXGRID_PATH),
            _get(app, PARTNER_PATH),
            _get(app, DNAC_VPN_PATH),
        )
        errors = [e for e in (_err(creds), _err(pxgrid_creds), _err(partner_body)) if e]
        ise_on = not _err(creds) and configured(creds)
        pxgrid_on = not _err(pxgrid_creds) and configured(pxgrid_creds)
        ise: dict[str, Any] = {"configured": ise_on}
        if ise_on:
            ise["credentials"] = mask_secrets(creds.get("data", creds) if isinstance(creds, dict) else creds)
            connect, sgts = await asyncio.gather(_get(app, ISE_CONNECT_PATH), _get(app, ISE_SGT_PATH))
            ise["connection"] = (
                {"ok": False, "error": _err(connect)} if _err(connect) else {"ok": True, "answer": connect}
            )
            if _err(sgts):
                ise["sgts_error"] = _err(sgts)
            else:
                rows = [s for s in _as_list(sgts.get("data", sgts) if isinstance(sgts, dict) else sgts)]
                ise["sgts"] = {"count": len(rows), "first": rows[:SHOW]}
        elif not _err(creds):
            ise["meaning"] = (
                f"no ISE is configured on the Manager (GET {ISE_CREDENTIALS_PATH} is empty): identity lists "
                "(users, user groups, SGTs from ISE) and user-based policy have no source"
            )
        pxgrid: dict[str, Any] = {"configured": pxgrid_on}
        if pxgrid_on:
            pxgrid["credentials"] = mask_secrets(
                pxgrid_creds.get("data", pxgrid_creds) if isinstance(pxgrid_creds, dict) else pxgrid_creds
            )
        out: dict[str, Any] = {"ise": ise, "pxgrid": pxgrid}
        plist = [] if _err(partner_body) else partners(partner_body)
        out["partners"] = plist or "none registered"
        dnac = [p for p in plist if is_dnac(p) and p.get("id")]
        if dnac:
            centres = []
            for p in dnac:
                pid = quote(str(p["id"]), safe="")
                sites, devices = await asyncio.gather(
                    _get(app, DNAC_SITES_PATH.format(id=pid)), _get(app, DNAC_DEVICES_PATH.format(id=pid))
                )
                centres.append(
                    {
                        "partner": p.get("name") or p["id"],
                        "sites": _err(sites)
                        or _as_list(sites.get("data", sites) if isinstance(sites, dict) else sites),
                        "devices": _err(devices)
                        or _as_list(devices.get("data", devices) if isinstance(devices, dict) else devices),
                    }
                )
            out["catalyst_center"] = centres
        if not _err(vpns):
            vpn_rows = _as_list(vpns.get("data", vpns) if isinstance(vpns, dict) else vpns)
            out["sda_vpns"] = [
                v.get("vpnId")
                for v in vpn_rows
                if isinstance(v, dict) and v.get("vpnType") == "configuredVPN"
            ] or "none"
        if not ise_on and not pxgrid_on and not plist:
            out["verdict"] = (
                "No ISE, pxGrid or partner integration is configured on this Manager: identity-based "
                "policy, SGT lists from ISE and the Catalyst Center SD-Access hand-off are not in use. "
                "Connect ISE in Administration > Integration Management (or catsdwan_api_call POST "
                f"{ISE_CREDENTIALS_PATH})."
            )
        else:
            parts = [n for n, on in (("ISE", ise_on), ("pxGrid", pxgrid_on)) if on]
            parts += [f"{p.get('type')} partner {p.get('name') or p.get('id')}" for p in plist]
            bad = (
                " (ISE connection test failed)" if ise_on and not ise.get("connection", {}).get("ok") else ""
            )
            out["verdict"] = f"Configured: {', '.join(parts)}{bad}."
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)
