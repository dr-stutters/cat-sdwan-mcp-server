"""W13 SLA history and reports: catsdwan_sla_history, catsdwan_top_applications, catsdwan_site_report.

History comes from the Manager's statistics database with server-side aggregation (an hourly or daily
histogram per tunnel), so a week is a few hundred rows instead of thousands of 10-minute samples. The
aggregations run on the statistics semaphore (two at a time, as the Manager allows) and the two long tools
are core tasks (MCP_TASKS), so a client can poll them.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import time
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, last_hours, rule
from cat_sdwan_mcp.control import HISTORY_PATH
from cat_sdwan_mcp.events import ALARMS_PATH, alarm_ips, alarm_sites, by_type
from cat_sdwan_mcp.fabric import device_rows, fan_out, host_map, is_reachable, site_ips
from cat_sdwan_mcp.history import (
    APPROUTE_AGG_PATH,
    DPI_AGG_PATH,
    DPI_OFF,
    colour_verdict,
    dpi_body,
    histogram_body,
    human_bytes,
    miss_periods,
    per_colour,
    rows,
    series,
    sort_summaries,
    tunnel_summary,
    usage_rows,
)
from cat_sdwan_mcp.history import granularity as bucket_size
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve
from cat_sdwan_mcp.policy import is_active, ordered, sequence_matches, sla_action
from cat_sdwan_mcp.tools.dataplane import _sla_classes
from cat_sdwan_mcp.tools.policy import _centralised_parts, _definitions, _lists, _policies

HISTORY_COLUMNS = [
    "host",
    "local_colour",
    "remote",
    "remote_colour",
    "loss_percent",
    "latency_ms",
    "jitter_ms",
    "worst_latency_ms",
    "missed_buckets",
]
ALARM_CAP = 2000
DEVICE_KEYS = ("host", "role", "system_ip", "reachability", "version", "up_since")
Days = Annotated[int, Field(ge=1, le=30, description="How many days back (1-30)")]
Granularity = Annotated[
    Literal["auto", "hour", "day"],
    Field(description="Bucket size: hour, day, or auto (hourly up to 3 days, daily beyond)"),
]


async def _sla(
    app: SdwanApp, sla_class: str | None, app_name: str | None
) -> tuple[dict[str, Any] | None, str]:
    """The SLA class (limits) to judge the history by: by name, or the class the app-route policy gives the
    application (the activated policy first). (None, why) when neither is given."""
    if sla_class:
        classes, _ = await _sla_classes(app)
        found = next(
            (c for c in classes if str(c.get("name", "")).lower() == sla_class.strip().lower()), None
        )
        if found is None:
            names = ", ".join(str(c.get("name")) for c in classes)
            raise NotFound(f"No SLA class {sla_class!r}. SLA classes: {names or 'none'}.")
        return found, f"SLA class {found['name']}"
    if not app_name:
        return None, "no SLA class given: metrics only (give sla_class or app for the misses)"
    policies, _ = await _policies(app, "centralised")
    central = sorted((r for _, r in policies), key=lambda r: not is_active(r))
    lists = None
    for p in central:
        _, parts = await _centralised_parts(app, p)
        if lists is None:
            lists, _ = await _lists(app)
        defs, _ = await _definitions(app, [a for a in parts if a.get("type") == "appRoute"])
        for d in defs.values():
            for seq in ordered(d.get("sequences")):
                if sequence_matches(seq, app_name, None, lists)[0] == "yes":
                    steering = sla_action(seq.get("actions"), lists) or {}
                    if steering.get("sla"):
                        state = "activated" if is_active(p) else "NOT activated"
                        return steering["sla"], (
                            f"SLA class {steering['sla']['name']}: {app_name} matches sequence "
                            f"{seq.get('sequenceId')} of {d.get('name')} in {p.get('policyName')} ({state})"
                        )
    raise NotFound(
        f"No app-route sequence matches {app_name!r} in the centralised policies; give sla_class instead "
        "(catsdwan_list_sla_classes)."
    )


def _tunnel_rules(inv: Inventory, tunnel: str) -> list[dict[str, Any]]:
    """'br1:mpls-hub1:mpls' or '10.0.0.2:mpls-10.0.0.1:mpls' (one tunnel), or 'br1:mpls' (every tunnel leaving
    br1 on mpls) -> query rules. Host names and colours may contain '-': every split is tried."""
    text = tunnel.strip()

    def ip_of(ref: str) -> str | None:
        try:
            row = resolve(inv, ref)
        except (NotFound, InvalidRequest):
            return None
        return str(row["system_ip"]) if row.get("system_ip") else None

    for i, ch in enumerate(text):
        if ch != "-":
            continue
        left, right = text[:i], text[i + 1 :]
        if ":" in left and ":" in right:
            a, lcol = left.split(":", 1)
            c, rcol = right.split(":", 1)
            ia, ic = ip_of(a), ip_of(c)
            if ia and ic:
                return [
                    rule("vdevice_name", [ia]),
                    rule("local_color", [lcol]),
                    rule("remote_system_ip", [ic]),
                    rule("remote_color", [rcol]),
                ]
    if ":" in text:
        dev, colour = text.split(":", 1)
        if ia := ip_of(dev):
            return [rule("vdevice_name", [ia]), rule("local_color", [colour])]
    raise InvalidRequest(
        f"Tunnel {tunnel!r}: give 'host:colour' (every tunnel leaving on that colour) or "
        "'host:colour-remote:colour' (one tunnel), e.g. 'br1:mpls-hub1:mpls'."
    )


async def _histogram(
    app: SdwanApp, hours: int, rules_: list[dict[str, Any]], kind: str
) -> tuple[dict[str, list[dict[str, Any]]], list[int]]:
    body = await app.api.post(APPROUTE_AGG_PATH, histogram_body(last_hours(hours, *rules_), kind), retry=True)
    data = rows(body)
    by_tunnel = series(data)
    seen = sorted({b["ms"] for buckets in by_tunnel.values() for b in buckets})
    listed = (body.get("entryTimeList") if isinstance(body, dict) else None) or []
    # The window's buckets between the first and the last one with statistics: buckets before the fabric (or
    # the site) existed and the current, still empty bucket are not outages. A bucket in between in which a
    # colour carried nothing is.
    times = sorted({int(t) for t in listed if seen and seen[0] <= int(t) <= seen[-1]} | set(seen))
    return by_tunnel, times


async def _dpi(
    app: SdwanApp, hours: int, rules_: list[dict[str, Any]], size: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    query = last_hours(hours, *rules_)
    apps, families = await asyncio.gather(
        app.api.post(DPI_AGG_PATH, dpi_body(query, "application", size), retry=True),
        app.api.post(DPI_AGG_PATH, dpi_body(query, "family", size), retry=True),
    )
    return usage_rows(rows(apps), "application"), usage_rows(rows(families), "family")


def _scope_rules(inv: Inventory, site: str | None, device: str | None) -> tuple[list[dict[str, Any]], str]:
    if site and device:
        raise InvalidRequest("Give site or device, not both.")
    if device:
        row = resolve(inv, device)
        if not row.get("system_ip"):
            raise InvalidRequest(f"{device!r} has not joined the fabric (no system IP).")
        return [rule("vdevice_name", [row["system_ip"]])], f" from {row.get('host')}"
    if site:
        return [rule("vdevice_name", sorted(site_ips(inv, site)))], f" from site {site}"
    return [], ""


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN SLA history", task=True)
    async def catsdwan_sla_history(
        ctx: Context,
        site: Annotated[
            str | None, Field(description="Tunnels from the edges of this site (id or name)")
        ] = None,
        device: Annotated[
            str | None, Field(description="Tunnels from this edge (host name or system IP)")
        ] = None,
        tunnel: Annotated[
            str | None,
            Field(
                description="One tunnel 'br1:mpls-hub1:mpls' (or by system IP), or 'br1:mpls' for a colour"
            ),
        ] = None,
        sla_class: Annotated[
            str | None,
            Field(description="Judge every bucket against this SLA class (catsdwan_list_sla_classes)"),
        ] = None,
        app: Annotated[
            str | None,
            Field(description="Or: the application whose app-route SLA class to use, e.g. 'webex'"),
        ] = None,
        days: Days = 1,
        granularity: Granularity = "auto",
        include_series: Annotated[
            bool, Field(description="Add each tunnel's buckets (time, loss, latency, jitter)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Is this site getting worse? App-route loss, latency and jitter per tunnel over 1-30 days,
        aggregated by the Manager per hour or per day (POST /statistics/approute/aggregation with a
        histogram), and, with an SLA class (by name, or the one the app-route policy gives `app`), the periods
        each tunnel missed it ('2026-10-23T09:00Z-11:00Z, latency 320 ms > 150 ms'), merged across consecutive
        buckets. Tunnels that missed most first; `miss_periods` lists every period newest first. Scope: site,
        device or one tunnel (default the whole fabric)."""
        sdwan: SdwanApp = get_client(ctx)
        inv = await load_inventory(sdwan)
        hosts = host_map(inv)
        if tunnel and (site or device):
            raise InvalidRequest("Give tunnel, or site/device, not both.")
        rules_, scope = _scope_rules(inv, site, device)
        if tunnel:
            rules_, scope = _tunnel_rules(inv, tunnel), f" on tunnel {tunnel}"
        sla, how = await _sla(sdwan, sla_class, app)
        kind, step = bucket_size(days, granularity)
        data, times = await _histogram(sdwan, days * 24, rules_, kind)
        out = [tunnel_summary(n, b, sla, step, hosts) for n, b in data.items()]
        if include_series:
            by_name = {r["tunnel"]: r for r in out}
            for n, buckets in data.items():
                by_name[n]["series"] = [
                    {
                        "time": b["ms"],
                        "loss_percent": b["loss_percent"],
                        "latency_ms": b["latency_ms"],
                        "jitter_ms": b["jitter_ms"],
                    }
                    for b in buckets
                ]
        out = sort_summaries(out)
        extra: dict[str, Any] = {
            "source": f"POST {APPROUTE_AGG_PATH}, last {days} day(s), per {kind}{scope}",
            "buckets": len(times),
            "judged_by": how,
        }
        if sla is not None:
            extra["sla_class"] = {k: sla.get(k) for k in ("name", "loss_max", "latency_max", "jitter_max")}
            periods = [{"tunnel": _tunnel_text(r), **p} for r in out for p in r.get("miss_periods") or []]
            periods.sort(key=lambda p: str(p["start"]), reverse=True)
            extra["miss_periods"] = periods[:50] or "none: every bucket met the SLA class"
            extra["tunnels_missing"] = sum(1 for r in out if r.get("missed_buckets"))
        if not data:
            extra["note"] = f"no app-route statistics{scope} in the last {days} day(s)"
        if response_format == "markdown":
            for r in out:
                r.pop("miss_periods", None)
        return list_result(
            page_of(out, limit=limit, offset=offset),
            fmt=response_format,
            columns=HISTORY_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN top applications")
    async def catsdwan_top_applications(
        ctx: Context,
        site: Annotated[str | None, Field(description="Only the edges of this site (id or name)")] = None,
        device: Annotated[str | None, Field(description="Only this edge (host name or system IP)")] = None,
        window_hours: Annotated[int, Field(ge=1, le=168, description="How far back, in hours")] = 24,
        limit: Annotated[int, Field(ge=1, le=100, description="Applications and families to show")] = 20,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """What is using the link: bytes and packets per application and per application family from the
        Manager's DPI statistics (POST /statistics/dpi/aggregation), biggest first with each one's share.
        Needs application visibility (DPI/NBAR) on the edges: when there are no DPI statistics the answer says
        so and how to enable it, instead of an empty list."""
        sdwan: SdwanApp = get_client(ctx)
        inv = await load_inventory(sdwan)
        rules_, scope = _scope_rules(inv, site, device)
        apps, families = await _dpi(sdwan, window_hours, rules_, limit)
        out: dict[str, Any] = {"source": f"POST {DPI_AGG_PATH}, last {window_hours} h{scope}"}
        if not apps and not families:
            out["dpi_statistics"] = "none"
            out["note"] = DPI_OFF.format(scope=scope, hours=window_hours)
            return object_result(out, fmt=response_format)
        total = sum(a["bytes"] for a in apps)
        out["total"] = human_bytes(total)
        out["applications"] = [{**a, "volume": human_bytes(a["bytes"])} for a in apps[:limit]]
        out["families"] = [{**f, "volume": human_bytes(f["bytes"])} for f in families[:limit]]
        return object_result(out, fmt=response_format)

    @reg.read(title="SD-WAN site report", task=True)
    async def catsdwan_site_report(
        ctx: Context,
        site: Annotated[str, Field(description="Site id or name")],
        days: Days = 7,
        sla_class: Annotated[
            str | None, Field(description="SLA class to count misses against (default: none, metrics only)")
        ] = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """One summary of a site over 1-30 days (like catc_site_health_report): its devices, availability
        per transport (share of buckets in which the colour carried traffic, from the app-route history) with
        loss, latency, jitter and SLA misses and a verdict per transport, control-connection drops per colour
        (the edges' connection history, live), the top alarms (by type, active and cleared), and the top
        applications (DPI; says so when application visibility is off). A section that can't be read says
        why; the others still answer."""
        sdwan: SdwanApp = get_client(ctx)
        inv = await load_inventory(sdwan)
        ips = site_ips(inv, site)
        at = [r for r in inv.rows if str(r.get("system_ip")) in ips]
        site_id = next((str(r["site_id"]) for r in at if r.get("site_id")), site)
        sla, how = await _sla(sdwan, sla_class, None)
        kind, step = bucket_size(days, "auto")
        hours = days * 24
        rules_ = [rule("vdevice_name", sorted(ips))]
        out: dict[str, Any] = {
            "site": site_id,
            "window": f"last {days} day(s), per {kind}",
            "devices": [{k: r.get(k) for k in DEVICE_KEYS if r.get(k)} for r in at],
        }
        hist, alarms, dpi, control = await asyncio.gather(
            _safe(_histogram(sdwan, hours, rules_, kind)),
            _safe(sdwan.query(ALARMS_PATH, last_hours(hours), limit=ALARM_CAP)),
            _safe(_dpi(sdwan, hours, rules_, 10)),
            _control_drops(sdwan, at, hours),
        )
        if isinstance(hist, str):
            out["transports"] = hist
        else:
            data, times = hist
            colours = per_colour(data, sla, times)
            for row in colours.values():
                row["verdict"] = colour_verdict(row)
            out["transports"] = colours or f"no app-route statistics in the last {days} day(s)"
            if sla is not None:
                periods = [
                    {"tunnel": n, **p}
                    for n, buckets in data.items()
                    for p in miss_periods(buckets, sla, step)
                ]
                periods.sort(key=lambda p: str(p["start"]), reverse=True)
                out["sla_misses"] = periods[:20] or f"none against {sla['name']}"
            out["judged_by"] = how
        out["control_connection_drops"] = control
        if isinstance(alarms, str):
            out["top_alarms"] = alarms
        else:
            mine = [a for a in alarms.rows if site_id in alarm_sites(a) or alarm_ips(a) & ips]
            top = by_type(mine)
            out["top_alarms"] = dict(list(top.items())[:10]) or "none"
            if alarms.more:
                out["alarms_note"] = f"only the newest {ALARM_CAP} alarms of the fabric were searched"
        if isinstance(dpi, str):
            out["top_applications"] = dpi
        else:
            apps, _ = dpi
            top_apps = [
                {
                    "application": a["application"],
                    "volume": human_bytes(a["bytes"]),
                    "share": a["share_percent"],
                }
                for a in apps[:10]
            ]
            out["top_applications"] = top_apps or DPI_OFF.format(scope=f" from site {site_id}", hours=hours)
        transports = out["transports"]
        verdicts = {c: r["verdict"] for c, r in transports.items()} if isinstance(transports, dict) else {}
        bad = [c for c, v in verdicts.items() if v != "healthy"]
        state = (
            f"{', '.join(bad)} degraded"
            if bad
            else "every transport healthy"
            if verdicts
            else "no transport data"
        )
        down = sum(1 for r in at if not is_reachable(r))
        out["summary"] = f"site {site_id}: {state}; {down} of {len(at)} device(s) unreachable now"
        return object_result(out, fmt=response_format)


def _tunnel_text(r: dict[str, Any]) -> str:
    return f"{r.get('host')} {r.get('local_colour')} -> {r.get('remote')} {r.get('remote_colour')}"


async def _safe(coro: Any) -> Any:
    try:
        return await coro
    except UpstreamError as e:
        return f"not read: {str(e)[:200]}"


async def _control_drops(app: SdwanApp, at: list[dict[str, Any]], hours: int) -> Any:
    """Control-connection history entries in the window, per edge and local colour (live from each edge)."""
    edges = [r for r in at if r.get("role") == "edge" and is_reachable(r)]
    if not edges:
        return "no reachable edge at the site to read the connection history from"
    got = await fan_out(edges, lambda r: device_rows(app, HISTORY_PATH, str(r["system_ip"])))
    cutoff = (time.time() - hours * 3600) * 1000
    out: dict[str, Any] = {}
    for r, res in zip(edges, got, strict=True):
        if isinstance(res, UpstreamError):
            out[str(r.get("host"))] = f"not read: {str(res)[:150]}"
            continue
        recent = [h for h in res if _ms(h.get("downtime-date") or h.get("lastupdated")) >= cutoff]
        counts = Counter(str(h.get("local-color") or "?") for h in recent)
        out[str(r.get("host"))] = dict(sorted(counts.items())) or "none"
    return out


def _ms(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0
