"""W28 licensing reads: catsdwan_licenses."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import ResponseFormat, ToolRegistrar, UpstreamError, get_client, object_result
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.fabric import device_rows, find_device, unreachable_reason
from cat_sdwan_mcp.licensing import (
    ASSOCIATION_PATH,
    DEVICES_PATH,
    EDGE_REGISTRATION_PATH,
    EDGE_USAGE_PATH,
    MSLA_COMPLIANCE_PATH,
    MSLA_COUNT_PATH,
    MSLA_LICENSES_PATH,
    SYNC_STATUS_PATH,
    USER_SETTINGS_PATH,
    compliance,
    counts,
    device_row,
    smart_account,
)
from cat_sdwan_mcp.security import records

SHOW = 100


async def _get(app: SdwanApp, path: str) -> Any:
    try:
        return await app.api.get(path)
    except UpstreamError as e:
        return {"error": f"GET {path} failed: {str(e)[:300]}"}


def _err(body: Any) -> str | None:
    return body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN licences")
    async def catsdwan_licenses(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Only this edge (host name, system IP, chassis or serial), plus its own view"),
        ] = None,
        include_unjoined: Annotated[
            bool, Field(description="Also list WAN edge slots that never joined (no host name)")
        ] = False,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Is every edge licensed, and is the sync with the Smart Account working? The Manager's Smart
        Licensing state (Smart Account credentials present, virtual accounts associated, sync status), the
        licence compliance (status and reasons), licensed vs total devices, the licences in the pool, and per
        device its compliance, reason and assigned licences (/v1/licensing/devices); with `device`, also the
        edge's own licence usage and registration (live). When no Smart Account sync is configured it says so
        plainly: licences can't be fetched or assigned until it is. Assigning and releasing licences stay in
        the GUI."""
        app: SdwanApp = get_client(ctx)
        paths = [
            USER_SETTINGS_PATH,
            ASSOCIATION_PATH,
            SYNC_STATUS_PATH,
            DEVICES_PATH,
            MSLA_LICENSES_PATH,
            MSLA_COMPLIANCE_PATH,
            MSLA_COUNT_PATH,
        ]
        settings, assoc, sync, devs, pool, comp, count = await asyncio.gather(*(_get(app, p) for p in paths))
        errors = [e for e in (_err(b) for b in (settings, assoc, sync, devs, pool, comp, count)) if e]
        sa = smart_account(
            None if _err(settings) else settings, None if _err(assoc) else assoc, None if _err(sync) else sync
        )
        out: dict[str, Any] = {"smart_account": sa}
        if not _err(comp):
            out["compliance"] = compliance(comp)
        if not _err(count) and isinstance(count, dict):
            c = count.get("data", count)
            if isinstance(c, dict):
                out["licensed_devices"] = f"{c.get('licensedDevice', '?')} of {c.get('totalDevices', '?')}"
        if not _err(pool):
            licences = _as_list(pool.get("data", pool) if isinstance(pool, dict) else pool)
            out["licence_pool"] = licences[:SHOW] or "empty"
        rows: list[dict[str, Any]] = []
        if not _err(devs):
            raw = devs.get("devices", devs.get("data")) if isinstance(devs, dict) else devs
            rows = [device_row(d) for d in _as_list(raw) if isinstance(d, dict)]
        unjoined = [r for r in rows if not r.get("host")]
        joined = [r for r in rows if r.get("host")]
        if device:
            inv_row, _ = await find_device(app, device)
            # A joined edge by host name or system IP; a slot that never joined by its chassis.
            ip, host = inv_row.get("system_ip"), inv_row.get("host")
            mine = [r for r in rows if (ip and r.get("system_ip") == ip) or (host and r.get("host") == host)]
            rows = mine or [
                r for r in rows if inv_row.get("chassis") and r.get("chassis") == inv_row["chassis"]
            ]
            edge: dict[str, Any] = {}
            why = unreachable_reason(inv_row)
            if why:
                edge["not_read"] = why
            else:
                ip = str(inv_row["system_ip"])
                for label, p in (("usage", EDGE_USAGE_PATH), ("registration", EDGE_REGISTRATION_PATH)):
                    try:
                        edge[label] = records(await device_rows(app, p, ip)) or "none reported"
                    except UpstreamError as e:
                        edge[label] = f"GET {p} failed: {str(e)[:200]}"
                if all(v == "none reported" for v in edge.values()):
                    edge["note"] = (
                        "the edge reports no licence usage or registration itself: in controller mode its "
                        "licences are managed and reported by the Manager (the rows above)"
                    )
            out["edge_view"] = edge
        else:
            out["by_compliance"] = counts(joined)
            if not include_unjoined:
                rows = joined
                if unjoined:
                    out["unjoined_slots"] = f"{len(unjoined)} (include_unjoined=true lists them)"
        out["devices"] = rows[:SHOW]
        if len(rows) > SHOW:
            out["devices_note"] = f"first {SHOW} of {len(rows)}"
        if sa["configured"] is not True:
            out["verdict"] = (
                "No Smart Account sync is configured on this Manager ("
                + ("no Smart Account credentials" if sa["credentials"] is False else "credentials present")
                + (", no virtual account associated" if sa["virtual_accounts"] == "none associated" else "")
                + "): licences can't be fetched from Cisco or assigned to edges until it is "
                "(Administration > "
                "License Management, or an offline licence file)."
                + (f" Licensed: {out['licensed_devices']} device(s)." if "licensed_devices" in out else "")
            )
        else:
            status = out.get("compliance", {}).get("status")
            out["verdict"] = f"Smart Account sync configured; compliance {status or 'unknown'}" + (
                f", licensed {out['licensed_devices']}" if "licensed_devices" in out else ""
            )
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)
