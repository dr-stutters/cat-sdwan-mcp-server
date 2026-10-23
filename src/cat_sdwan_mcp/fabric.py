"""Shared helpers for the per-device tools (W3 onwards): resolve a `device` argument with W2's inventory,
refuse a real-time read the Manager cannot answer, and read one real-time table.

Real-time reads (GET /dataservice/device/<what>?deviceId=<system-ip>) go from the Manager to the device over
its control connection: an unreachable or never-joined device has no answer, so the tools say that instead
of waiting for the Manager's timeout.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest, UpstreamError
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve

FANOUT = 4  # concurrent real-time reads when a tool asks several devices


async def find_device(app: SdwanApp, ref: str) -> tuple[dict[str, Any], Inventory]:
    """The inventory row for `ref` (host name, system IP, chassis or serial; 'did you mean' when unknown)."""
    inv = await load_inventory(app)
    return resolve(inv, ref), inv


def is_reachable(row: dict[str, Any]) -> bool:
    return bool(row.get("system_ip")) and str(row.get("reachability", "")).lower() == "reachable"


def unreachable_reason(row: dict[str, Any]) -> str | None:
    """Why the Manager cannot read this device in real time, or None when it can."""
    name = row.get("host") or row.get("chassis") or row.get("system_ip")
    if not row.get("system_ip"):
        return f"{name} has not joined the fabric (no system IP), so it has no real-time state"
    if not is_reachable(row):
        return (
            f"the Manager reports {name} {row.get('reachability') or 'unreachable'}; real-time reads go over "
            "its control connection"
        )
    return None


def require_reachable(row: dict[str, Any], hint: str = "") -> str:
    """The device's system IP, or InvalidRequest saying why it has no real-time state."""
    why = unreachable_reason(row)
    if why:
        raise InvalidRequest(f"Not read: {why}.{(' ' + hint) if hint else ''}")
    return str(row["system_ip"])


async def device_rows(app: SdwanApp, path: str, system_ip: str) -> list[dict[str, Any]]:
    """One real-time table from one device, as a list of records."""
    data = await app.get_data(path, {"deviceId": system_ip})
    return [r for r in _as_list(data) if isinstance(r, dict)]


async def safely[T](coro: Awaitable[T], what: str) -> T | dict[str, str]:
    """`coro`'s result, or {"error": ...} when the Manager answers with an error (an optional section)."""
    try:
        return await coro
    except UpstreamError as e:
        return {"error": f"{what} failed: {str(e)[:300]}"}


async def fan_out[T](
    items: list[T], read: Callable[[T], Awaitable[list[dict[str, Any]]]]
) -> list[list[dict[str, Any]] | UpstreamError]:
    """`read(item)` for every item, at most FANOUT at a time; an UpstreamError is returned in its place."""
    sem = asyncio.Semaphore(FANOUT)

    async def one(item: T) -> list[dict[str, Any]] | UpstreamError:
        async with sem:
            try:
                return await read(item)
            except UpstreamError as e:
                return e

    return list(await asyncio.gather(*(one(i) for i in items)))


def host_map(inv: Inventory) -> dict[str, str]:
    """System IP -> host name, for naming peers and remote ends."""
    return {str(r["system_ip"]): str(r["host"]) for r in inv.rows if r.get("system_ip") and r.get("host")}


def reachable(inv: Inventory, role: str | None = None) -> list[dict[str, Any]]:
    return [r for r in inv.rows if is_reachable(r) and (role is None or r.get("role") == role)]


def site_ips(inv: Inventory, site: str) -> set[str]:
    """The system IPs of every device at a site (site id or name); InvalidRequest when there are none."""
    want = site.strip().lower()
    ips = {
        str(r["system_ip"])
        for r in inv.rows
        if r.get("system_ip")
        and want in (str(r.get("site_id", "")).lower(), str(r.get("site_name", "")).lower())
    }
    if not ips:
        known = sorted({str(r["site_id"]) for r in inv.rows if r.get("site_id")})
        raise InvalidRequest(f"No device is at site {site!r}. Sites: {', '.join(known) or 'none'}.")
    return ips
