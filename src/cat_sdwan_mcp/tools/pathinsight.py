"""W19 Network Wide Path Insight: catsdwan_path_insight (write), catsdwan_list_path_traces (read).

A trace turns on flow tracing on the edges of a site: write tier, preview-first. The confirm starts it, waits
for finished flows, reads them and always stops the trace again (also when the read fails), unless
keep_running. Exports (/nwpi/exportTrace) are left to catsdwan_api_call.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.fabric import host_map, is_reachable
from cat_sdwan_mcp.inventory import load_inventory, matches_site, resolve
from cat_sdwan_mcp.pathinsight import (
    DATASTREAM_PATH,
    FIN_FLOWS_PATH,
    TASK_HISTORY_PATH,
    TRACE_HISTORY_PATH,
    TRACE_START_PATH,
    TRACE_STOP_PATH,
    datastream_enabled,
    flow_row,
    flow_summary,
    flows_of,
    prefix,
    short_version,
    sort_flows,
    start_body,
    start_problems,
    start_refusal,
    task_row,
    trace_id_of,
    trace_row,
)

TRACE_COLUMNS = ["trace_id", "name", "started", "state", "site", "vpn", "filter", "duration_min", "devices"]
FLOW_COLUMNS = ["flow_id", "flow", "app", "upstream", "drops", "issues"]
POLL_INTERVAL = 15.0  # seconds between flow reads while a trace runs (tests set it to 0)
MIN_VERSION = (17, 6)  # NWPI flow tracing on IOS XE edges
_now = time.monotonic  # the wait's clock (tests replace it)


def _ms(hours: float) -> tuple[int, int]:
    now = int(time.time() * 1000)
    return now - int(hours * 3600 * 1000), now


def _old(version: Any) -> bool:
    v = short_version(version)
    if not v:
        return False
    major, minor = (int(x) for x in v.split("."))
    return (major, minor) < MIN_VERSION


async def _history(app: SdwanApp, since_hours: float) -> list[dict[str, Any]]:
    start, end = _ms(since_hours)
    body = await app.api.get(TRACE_HISTORY_PATH, {"startTime": start, "endTime": end})
    data = body.get("data") if isinstance(body, dict) else body
    return [r for r in _as_list(data) if isinstance(r, dict)]


async def _flows(app: SdwanApp, trace_id: str, ts: int) -> list[dict[str, Any]]:
    body = await app.api.get(FIN_FLOWS_PATH, {"traceId": trace_id, "timestamp": ts})
    return flows_of(body)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN path insight traces")
    async def catsdwan_list_path_traces(
        ctx: Context,
        trace_id: Annotated[
            int | None,
            Field(
                description="Read this trace's flows (hop by hop, drops, policies) instead of listing traces"
            ),
        ] = None,
        since_hours: Annotated[
            float, Field(gt=0, le=24 * 365, description="How far back to list traces (default 7 days)")
        ] = 24 * 7,
        limit: Annotated[int, Field(ge=1, le=500, description="Traces or flows to return")] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Network Wide Path Insight traces, including ones started in the GUI (GET
        /stream/device/nwpi/traceHistory) and the auto-on tasks (/nwpi/tasks/taskHistory): trace id, name,
        start, state, site, VPN, filter, duration, devices. With trace_id: that trace's finished flows (GET
        /nwpi/traceFinFlowWithQuery), drops first: each flow's hops upstream and downstream with edge, colour
        and encapsulation, the forwarding decision per edge, the policies that matched, drop rates with their
        causes (e.g. TailDrop) and what went wrong (SLA violated, QoS congestion, path changed, server no
        response, ...)."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        hosts = host_map(inv)
        if trace_id is None:
            traces, tasks = await asyncio.gather(
                _history(app, since_hours), app.api.get(TASK_HISTORY_PATH), return_exceptions=False
            )
            rows = sorted((trace_row(r, hosts) for r in traces), key=lambda r: -(r.get("timestamp") or 0))
            task_data = tasks.get("data") if isinstance(tasks, dict) else tasks
            extra = {
                "tasks": [task_row(t) for t in _as_list(task_data) if isinstance(t, dict)] or "none",
                "next": "catsdwan_list_path_traces(trace_id=...) reads a trace's flows",
            }
            return list_result(
                page_of(rows, limit=limit, offset=offset),
                fmt=response_format,
                columns=TRACE_COLUMNS,
                extra=extra,
            )
        traces = await _history(app, 24 * 365 * 5)
        match = next((r for r in traces if str(r.get("trace-id")) == str(trace_id)), None)
        if match is None:
            known = ", ".join(str(r.get("trace-id")) for r in traces[:20])
            raise NotFound(f"No path insight trace {trace_id}. Traces: {known or 'none'}.")
        flows = sort_flows([flow_row(f) for f in await _flows(app, str(trace_id), int(match["entry_time"]))])
        return list_result(
            page_of(flows, limit=limit, offset=offset),
            fmt=response_format,
            columns=FLOW_COLUMNS,
            extra={"trace": trace_row(match, hosts), "summary": flow_summary(flows)},
        )

    @reg.write(title="Run an SD-WAN path insight trace", task=True)
    async def catsdwan_path_insight(
        ctx: Context,
        site: Annotated[
            str, Field(description="Source site id (or name) whose edges trace the flows, e.g. 200")
        ],
        vpn: Annotated[list[int], Field(min_length=1, description="Service VPN(s) to trace, e.g. [10]")],
        devices: Annotated[
            list[str] | None,
            Field(description="Only these edges of the site (default: every reachable edge there)"),
        ] = None,
        source: Annotated[
            str | None, Field(description="Source address or prefix, e.g. 10.61.200.0/24")
        ] = None,
        destination: Annotated[
            str | None, Field(description="Destination address or prefix, e.g. 10.61.201.10")
        ] = None,
        app_name: Annotated[
            str | None,
            Field(description="Application name(s), comma-separated (needs DPI/NBAR on the edges)"),
        ] = None,
        protocol: Annotated[
            str | None, Field(description="IP protocol number, e.g. 1 (ICMP), 6 (TCP)")
        ] = None,
        dscp: Annotated[int | None, Field(ge=0, le=63, description="DSCP of the flows, e.g. 46")] = None,
        duration_minutes: Annotated[
            int,
            Field(ge=1, le=60, description="How long the edges trace at most (the Manager stops it then)"),
        ] = 5,
        wait_seconds: Annotated[
            int,
            Field(
                ge=10, le=3600, description="How long to wait for finished flows before reading and stopping"
            ),
        ] = 120,
        keep_running: Annotated[
            bool, Field(description="Leave the trace running after reading (it still expires at duration)")
        ] = False,
        name: Annotated[str | None, Field(description="Trace name (default mcp_<site>_<time>)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Trace live flows hop by hop across the overlay with the Manager's Network Wide Path Insight. The
        preview names the edges that will trace, the filter (VPN, source, destination, application,
        protocol, DSCP) and the duration. The confirm starts the trace (POST /stream/device/nwpi/trace/start),
        waits up to wait_seconds for finished flows, reads them (each flow's hops with edge, colour,
        encapsulation, the forwarding decision and matched policies, drops with their causes, SLA and QoS
        problems) and stops the trace (POST /nwpi/trace/stop/{traceId}), even when reading fails. Generate
        the traffic meanwhile (catsdwan_ping, a CML host). Write tier: tracing loads the edges' CPU. Past
        traces: catsdwan_list_path_traces."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        at_site = [r for r in inv.rows if r.get("role") == "edge" and matches_site(r, site)]
        if not at_site:
            sites = sorted({str(r.get("site_id")) for r in inv.rows if r.get("role") == "edge"})
            raise InvalidRequest(f"No edge is at site {site!r}. Edge sites: {', '.join(sites) or 'none'}.")
        site_id = str(at_site[0].get("site_id"))
        if devices:
            chosen = [resolve(inv, d) for d in devices]
            if stray := [str(r.get("host")) for r in chosen if r not in at_site]:
                raise InvalidRequest(f"{', '.join(stray)} not at site {site_id}: a trace runs at one site.")
        else:
            chosen = at_site
        blockers = [
            f"{r.get('host') or r.get('chassis')} is {r.get('reachability') or 'not joined'}: it can't trace"
            for r in chosen
            if not is_reachable(r)
        ]
        try:
            if not datastream_enabled(await app.api.get(DATASTREAM_PATH)):
                blockers.append(
                    "Data Stream is off on the Manager (Administration > Settings > Data Stream): no path "
                    "insight trace starts until it is enabled"
                )
        except UpstreamError:
            pass
        warnings = [
            f"{r.get('host')} runs {r.get('version')}: path insight needs 17.6 or later"
            for r in chosen
            if _old(r.get("version"))
        ]
        try:
            src, dst = prefix(source), prefix(destination)
        except ValueError as e:
            raise InvalidRequest(str(e)) from e
        trace_name = name or f"mcp_{site_id}_{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
        reachable = [r for r in chosen if is_reachable(r)]
        body = start_body(
            site=site_id,
            devices=reachable,
            vpns=vpn,
            duration=duration_minutes,
            source=src,
            destination=dst,
            app=app_name,
            protocol=protocol,
            dscp=dscp,
            name=trace_name,
        )
        try:
            running = [
                trace_row(r)
                for r in await _history(app, 2)
                if str((r.get("data") or {}).get("summary", {}).get("state", "")).lower() == "running"
            ]
        except UpstreamError:
            running = []
        if running:
            warnings.append(f"{len(running)} trace(s) already running: {[t.get('name') for t in running]}")
        plan = Plan(
            f"Trace flows at site {site_id} on {len(reachable)} edge(s) for up to {duration_minutes} min",
            details={
                "edges": [
                    {"host": r.get("host"), "system_ip": r.get("system_ip"), "version": r.get("version")}
                    for r in chosen
                ],
                "filter": {
                    k: v
                    for k, v in {
                        "vpn": vpn,
                        "source": src,
                        "destination": dst,
                        "app": app_name,
                        "protocol": protocol,
                        "dscp": dscp,
                    }.items()
                    if v not in (None, [])
                },
                "duration_minutes": duration_minutes,
                "wait_seconds": wait_seconds,
                "then": "the trace is left running until it expires"
                if keep_running
                else "the trace is stopped after the read",
                "request": f"POST {TRACE_START_PATH}",
                "body": body,
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                f"flow tracing runs on {', '.join(str(r.get('host')) for r in reachable)} (more CPU on the "
                "edges while it runs); nothing in the configuration changes"
            ],
            fingerprint=None,
            blockers=blockers,
            blast_radius=len(reachable),
        )

        async def apply() -> Any:
            answer = await app.api.post(TRACE_START_PATH, body)
            tid, ts = trace_id_of(answer)
            out: dict[str, Any] = {"trace_name": trace_name}
            if problems := start_problems(answer):
                out["start_problems"] = problems
            if tid is None or ts is None:
                raise UpstreamError(f"The Manager started no trace: {start_refusal(answer)}")
            out["trace_id"] = tid
            flows: list[dict[str, Any]] = []
            read_error = None
            deadline = _now() + wait_seconds
            try:
                while True:
                    flows = await _flows(app, tid, ts)
                    if flows or _now() >= deadline:
                        break
                    await ctx.report_progress(
                        int(wait_seconds - (deadline - _now())), wait_seconds, "waiting for flows"
                    )
                    await asyncio.sleep(min(POLL_INTERVAL, max(0.0, deadline - _now())))
            except UpstreamError as e:
                read_error = f"reading the flows failed: {str(e)[:300]}"
            finally:
                if not keep_running:
                    try:
                        stop = await app.api.post(TRACE_STOP_PATH.format(trace_id=tid), None)
                        out["stopped"] = (
                            (stop or {}).get("state") or (stop or {}).get("action") or "requested"
                        )
                    except UpstreamError as e:
                        out["stop_failed"] = (
                            f"{str(e)[:200]}: stop it in the GUI or with catsdwan_api_call(path="
                            f"'{TRACE_STOP_PATH.format(trace_id=tid)}', method='POST'); it expires after "
                            f"{duration_minutes} min"
                        )
            rows = sort_flows([flow_row(f) for f in flows])
            if read_error:
                out["error"] = read_error
            out["summary"] = flow_summary(rows)
            out["flows"] = rows[:50]
            if not rows and not read_error:
                out["note"] = (
                    f"no finished flows within {wait_seconds} s: generate matching traffic during the trace, "
                    f"or read it later with catsdwan_list_path_traces(trace_id={tid})"
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_path_insight",
            args={
                "site": site,
                "vpn": vpn,
                "devices": devices,
                "source": source,
                "destination": destination,
                "app_name": app_name,
                "protocol": protocol,
                "dscp": dscp,
                "duration_minutes": duration_minutes,
                "wait_seconds": wait_seconds,
                "keep_running": keep_running,
                "name": name,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
