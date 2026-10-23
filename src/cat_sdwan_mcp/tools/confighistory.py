"""W20 configuration history: catsdwan_config_history."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client, object_result
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.confighistory import (
    DIFF_PATH,
    HISTORY_PATH,
    VERSION_PATH,
    diff_texts,
    history_query,
    history_rows,
    parse_when,
    pick_version,
    version_at,
    version_text,
)
from cat_sdwan_mcp.configuration import config_diff, mask_config, path, sections
from cat_sdwan_mcp.inventory import load_inventory, resolve

LIST_SIZE = 500  # versions read per call (the list carries no configuration text, so it stays small)


async def _version(app: SdwanApp, config_id: str) -> str | None:
    row = version_text(await app.api.get(path(VERSION_PATH, id=config_id)))
    text = row.get("configuration") if row else None
    return text if isinstance(text, str) and text.strip() else None


async def _pair(app: SdwanApp, old: str, new: str) -> tuple[str | None, str | None, str]:
    """(older text, newer text, source): the Manager's diff/list (both texts), else the two versions."""
    try:
        one, two = diff_texts(await app.api.get(DIFF_PATH, {"config_id1": old, "config_id2": new}))
        if one is not None and two is not None:
            return one, two, f"GET {DIFF_PATH} (the Manager returns both texts; the diff is computed here)"
    except UpstreamError:
        pass
    a, b = await asyncio.gather(_version(app, old), _version(app, new))
    return a, b, f"GET {VERSION_PATH.format(id='{config_id}')} for each version"


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN configuration history")
    async def catsdwan_config_history(
        ctx: Context,
        device: Annotated[str, Field(description="Host name, system IP, chassis number or serial number")],
        since_hours: Annotated[
            int,
            Field(ge=1, le=8760, description="How far back to list stored configurations (default 30 days)"),
        ] = 720,
        version: Annotated[
            str | None,
            Field(
                description="Show one stored configuration: its config_id, its index (0 = newest), 'latest' "
                "or 'previous'"
            ),
        ] = None,
        at: Annotated[
            str | None,
            Field(
                description="Show the configuration in effect at this time (ISO 8601, e.g. "
                "'2026-10-22T21:00:00Z'): the newest version stored at or before it"
            ),
        ] = None,
        diff: Annotated[
            bool, Field(description="Diff two versions (newest against the one before, unless diff_between)")
        ] = False,
        diff_between: Annotated[
            list[str] | None,
            Field(
                min_length=2,
                max_length=2,
                description="Two versions to diff (config ids, indexes, 'latest', 'previous'); the older is "
                "'-', the newer '+'",
            ),
        ] = None,
        section: Annotated[
            str | None,
            Field(description="Only top-level blocks whose first line contains this, e.g. 'banner'"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Versions listed")] = 50,
    ) -> ToolResult:
        """The running configurations the Manager stored for a device over time (each with its time, config id
        and how it was stored: 'cli' = taken from the device, 'cli/ztp' = after the Manager pushed a
        configuration group or template). Answers 'what was this edge's configuration before last night's
        deploy?': at='<time>' shows the version in effect then, version='previous' the one before the newest,
        diff=true what changed between the newest two (or diff_between any two), block by block, '-' older,
        '+' newer. Passwords, keys and SNMP communities are masked. A W8 deploy's undo starts here: the older
        version is the configuration to restore."""
        app: SdwanApp = get_client(ctx)
        if sum(x is not None for x in (version, at, diff_between)) > 1:
            raise InvalidRequest("Give at most one of version, at and diff_between.")
        inv = await load_inventory(app)
        row = resolve(inv, device)
        sip = str(row.get("system_ip") or "")
        if not sip:
            raise InvalidRequest(f"{device!r} has no system IP in the inventory, so it has no history.")
        body = await app.api.get(
            HISTORY_PATH, {"deviceId": sip, "query": history_query(sip, since_hours, LIST_SIZE)}
        )
        rows = history_rows(body, sip)
        out: dict[str, Any] = {
            "host": row.get("host"),
            "system_ip": sip,
            "window_hours": since_hours,
            "versions_stored": len(rows),
            "versions": [{k: v for k, v in r.items() if k != "entry_time"} for r in rows[:limit]],
        }
        if len(rows) > limit:
            out["versions_note"] = (
                f"the newest {limit} of {len(rows)} listed: raise limit or shorten since_hours"
            )
        if not rows:
            out["note"] = (
                f"The Manager stored no configuration for {row.get('host') or sip} in the last "
                f"{since_hours} h (it stores one when the device's configuration changes or the Manager "
                "pushes one)."
            )
        masked = 0

        def show(text: str) -> str:
            nonlocal masked
            t, n = mask_config(text)
            masked += n
            return sections(t, section) if section else t

        picked: dict[str, Any] | None = None
        if version is not None:
            picked = pick_version(rows, version)
        elif at is not None:
            when = parse_when(at)
            picked = version_at(rows, when)
            if picked is None:
                oldest = rows[-1]["time"] if rows else "none"
                raise InvalidRequest(
                    f"No stored configuration at or before {at} in the last {since_hours} h "
                    f"(oldest: {oldest}). Widen since_hours."
                )
        if picked is not None:
            text = await _version(app, picked["config_id"])
            sel = {k: v for k, v in picked.items() if k != "entry_time"}
            out["version"] = sel
            if text is None:
                out["configuration"] = None
                out["configuration_note"] = "the Manager returned no text for this version"
            else:
                shown = show(text)
                out["configuration"] = shown
                out["lines"] = len(shown.splitlines())
            out["source"] = f"GET {VERSION_PATH.format(id='{config_id}')}"
        elif diff or diff_between:
            refs = diff_between or ["previous", "latest"]
            a, b = (pick_version(rows, r) for r in refs)
            if a["config_id"] == b["config_id"]:
                raise InvalidRequest("Both diff versions are the same configuration.")
            old, new = sorted((a, b), key=lambda r: r.get("entry_time") or 0)
            old_text, new_text, source = await _pair(app, old["config_id"], new["config_id"])
            out["diff_from"] = {k: v for k, v in old.items() if k != "entry_time"}
            out["diff_to"] = {k: v for k, v in new.items() if k != "entry_time"}
            if old_text is None or new_text is None:
                out["diff"] = "not compared: the Manager returned no text for one of the versions"
            else:
                (old_m, n_old), (new_m, n_new) = mask_config(old_text), mask_config(new_text)
                masked += n_old + n_new
                d = config_diff(old_m, new_m)
                if section:
                    want = section.lower()
                    for k in ("only_on_device", "only_intended"):
                        if k in d:
                            d[k] = [x for x in d[k] if want in x.lower()]
                    if "changed" in d:
                        d["changed"] = {x: v for x, v in d["changed"].items() if want in x.lower()}
                # config_diff names its sides for running vs intended; here they are older vs newer.
                renamed = {"only_on_device": "only_in_older", "only_intended": "only_in_newer"}
                out["diff"] = {renamed.get(k, k): v for k, v in d.items()}
                summary = str(out["diff"]["summary"])
                out["diff"]["summary"] = summary.replace("only on the device", "only in the older").replace(
                    "only intended", "only in the newer"
                )
                out["diff_note"] = "'-' = older, '+' = newer; block order is ignored; secrets masked."
            out["source"] = source
        if masked:
            out["masked_lines"] = masked
        if inv.warnings:
            out["warnings"] = inv.warnings
        return object_result(out, fmt="json")
