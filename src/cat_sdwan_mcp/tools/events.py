"""W5 alarms, events and the audit log: catsdwan_list_alarms, catsdwan_list_events, catsdwan_audit_log,
catsdwan_recent_activity. Pull-only (ADR-003): every call queries the Manager."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import QueryResult, SdwanApp, last_hours
from cat_sdwan_mcp.events import (
    ALARMS_PATH,
    AUDIT_PATH,
    EVENTS_PATH,
    alarm_ips,
    alarm_row,
    alarm_sites,
    alarm_state,
    at_least,
    audit_mentions,
    audit_row,
    by_type,
    event_row,
    is_session_noise,
    sort_alarms,
    timeline_line,
)
from cat_sdwan_mcp.fabric import host_map
from cat_sdwan_mcp.inventory import load_inventory, resolve

Severity = Literal["critical", "major", "medium", "minor"]
FETCH_CAP = 2000  # newest rows read per source and call, before the client-side filters
SinceHours = Annotated[int, Field(ge=1, le=168, description="How far back, in hours (up to 7 days)")]
DeviceRef = Annotated[
    str | None, Field(description="Only this device (host name, system IP, chassis or serial)")
]
SiteRef = Annotated[str | None, Field(description="Only this site (site id, e.g. '200', or site name)")]

ALARM_COLUMNS = ["time", "severity", "alarm", "state", "devices", "site_id", "message"]
EVENT_COLUMNS = ["time", "host", "event", "severity", "component", "details"]
AUDIT_COLUMNS = ["time", "user", "source_ip", "module", "message", "device"]
TIMELINE_COLUMNS = ["time", "source", "severity", "device", "what"]


@dataclass
class Scope:
    """What a device/site filter matches: system IPs, names (host, chassis) and site ids."""

    label: str | None = None
    ips: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    sites: set[str] = field(default_factory=set)

    @property
    def everything(self) -> bool:
        return self.label is None

    def alarm(self, a: dict[str, Any]) -> bool:
        if self.everything:
            return True
        hosts = {str(v.get("host-name")) for v in a.get("values") or [] if isinstance(v, dict)}
        hosts.add(str(a.get("host_name") or ""))
        return bool(alarm_ips(a) & self.ips or alarm_sites(a) & self.sites or hosts & self.names)

    def event(self, e: dict[str, Any]) -> bool:
        if self.everything:
            return True
        return str(e.get("system_ip")) in self.ips or str(e.get("host_name")) in self.names

    def audit(self, a: dict[str, Any]) -> bool:
        return self.everything or audit_mentions(a, self.ips, self.names)


async def _scope(app: SdwanApp, device: str | None, site: str | None) -> tuple[Scope, dict[str, str]]:
    if device and site:
        raise InvalidRequest("Give device or site, not both.")
    inv = await load_inventory(app)
    hosts = host_map(inv)
    if device:
        row = resolve(inv, device)
        names = {str(row[k]) for k in ("host", "chassis") if row.get(k)}
        ips = {str(row["system_ip"])} if row.get("system_ip") else set()
        return Scope(str(row.get("host") or row.get("chassis")), ips, names), hosts
    if site:
        want = site.strip().lower()
        rows = [
            r
            for r in inv.rows
            if want in (str(r.get("site_id", "")).lower(), str(r.get("site_name", "")).lower())
        ]
        sites = {str(r["site_id"]) for r in rows if r.get("site_id")} or {site.strip()}
        ips = {str(r["system_ip"]) for r in rows if r.get("system_ip")}
        names = {str(r["host"]) for r in rows if r.get("host")}
        return Scope(f"site {', '.join(sorted(sites))}", ips, names, sites), hosts
    return Scope(), hosts


async def _read(app: SdwanApp, path: str, hours: int) -> QueryResult:
    return await app.query(path, last_hours(hours), limit=FETCH_CAP)


def _partial(result: QueryResult, what: str, hours: int) -> str | None:
    if not result.more:
        return None
    return (
        f"the Manager has more than {FETCH_CAP} {what} in the last {hours} h; only the newest {FETCH_CAP} "
        "were searched: shorten since_hours"
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN alarms")
    async def catsdwan_list_alarms(
        ctx: Context,
        severity: Annotated[
            Severity | None, Field(description="This severity or worse (critical > major > medium > minor)")
        ] = None,
        device: DeviceRef = None,
        site: SiteRef = None,
        active_only: Annotated[
            bool,
            Field(description="Only alarms still active; false adds cleared ones and the '..._up' alarms"),
        ] = True,
        alarm_type: Annotated[
            str | None, Field(description="Alarm type or name contains, e.g. 'node_down', 'bfd', 'tloc'")
        ] = None,
        since_hours: SinceHours = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's alarms (control/BFD/TLOC/site down and up, interface state, certificates, memory and
        CPU, ...), newest first: time raised, severity, alarm name and type, active/cleared (with the time
        cleared), the devices and site, and the message. `by_type` counts active and cleared per alarm
        name before paging. Filters combine (AND); `severity` means that severity or worse. For one device's
        alarms, events and audit lines on one timeline use catsdwan_recent_activity."""
        app: SdwanApp = get_client(ctx)
        scope, _ = await _scope(app, device, site)
        result = await _read(app, ALARMS_PATH, since_hours)
        raw = [a for a in result.rows if scope.alarm(a)]
        if alarm_type:
            want = alarm_type.strip().lower()
            raw = [
                a
                for a in raw
                if want in f"{a.get('type')} {a.get('rule_name_display')} {a.get('rulename')}".lower()
            ]
        raw = [a for a in raw if at_least(a.get("severity"), severity)]
        extra: dict[str, Any] = {"by_type": by_type(raw)}
        extra["active"] = sum(1 for a in raw if alarm_state(a) == "active")
        if active_only:
            raw = [a for a in raw if alarm_state(a) == "active"]
        if scope.label:
            extra["scope"] = scope.label
        if note := _partial(result, "alarms", since_hours):
            extra["partial"] = note
        rows = [alarm_row(a) for a in sort_alarms(raw)]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=ALARM_COLUMNS, extra=extra
        )

    @reg.read(title="List SD-WAN events")
    async def catsdwan_list_events(
        ctx: Context,
        device: DeviceRef = None,
        site: SiteRef = None,
        event_type: Annotated[
            str | None,
            Field(description="Event name contains, e.g. 'bfd-state-change', 'control-connection', 'reboot'"),
        ] = None,
        component: Annotated[
            str | None, Field(description="Only this component: System, Control, BFD, OMP, VPN, Security")
        ] = None,
        severity: Annotated[
            Literal["critical", "major", "minor"] | None, Field(description="This severity or worse")
        ] = None,
        since_hours: SinceHours = 1,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Device events the Manager collected (interface and BFD state changes, control connection and OMP
        peer changes, reboots, process restarts, logins, certificate installs, validator rejections with
        their reason, ...), newest first: time, device, event name, component, severity and the event's
        details ('key=value; ...'). Busy: a small fabric logs hundreds per hour, so keep since_hours short and
        filter; `by_event` counts what matched before paging."""
        app: SdwanApp = get_client(ctx)
        scope, _ = await _scope(app, device, site)
        result = await _read(app, EVENTS_PATH, since_hours)
        raw = [e for e in result.rows if scope.event(e)]
        if event_type:
            raw = [e for e in raw if event_type.strip().lower() in str(e.get("eventname", "")).lower()]
        if component:
            raw = [e for e in raw if str(e.get("component", "")).lower() == component.strip().lower()]
        raw = [e for e in raw if at_least(e.get("severity_level"), severity)]
        raw.sort(key=lambda e: int(e.get("entry_time") or 0), reverse=True)
        extra: dict[str, Any] = {
            "by_event": dict(Counter(str(e.get("eventname")) for e in raw).most_common(15))
        }
        if scope.label:
            extra["scope"] = scope.label
        if note := _partial(result, "events", since_hours):
            extra["partial"] = note
        return list_result(
            page_of([event_row(e) for e in raw], limit=limit, offset=offset),
            fmt=response_format,
            columns=EVENT_COLUMNS,
            extra=extra,
        )

    @reg.read(title="SD-WAN audit log")
    async def catsdwan_audit_log(
        ctx: Context,
        user: Annotated[
            str | None, Field(description="Only this user ('system' for the Manager itself)")
        ] = None,
        module: Annotated[
            str | None,
            Field(
                description="Module or feature contains, e.g. 'template', 'config-group', 'device', 'user'"
            ),
        ] = None,
        device: DeviceRef = None,
        changes_only: Annotated[
            bool, Field(description="Drop logins, logouts and token creation (session noise)")
        ] = False,
        include_details: Annotated[
            bool,
            Field(description="Add the entry's details (config bodies, secrets masked, cut at 1000 chars)"),
        ] = False,
        since_hours: SinceHours = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Who did what on the Manager, newest first: time, user, source IP, module and feature, the
        message (template or configuration group created, attached or deployed, policy activated, device
        rebooted, certificates installed, users created, logins) and the device it concerns. Answers 'what
        changed and who did it?'; changes_only=true drops logins and logouts. `by_user` counts the matching
        entries before paging."""
        app: SdwanApp = get_client(ctx)
        scope, hosts = await _scope(app, device, None)
        result = await _read(app, AUDIT_PATH, since_hours)
        raw = [a for a in result.rows if scope.audit(a)]
        if user:
            raw = [a for a in raw if str(a.get("loguser", "")).lower() == user.strip().lower()]
        if module:
            want = module.strip().lower()
            raw = [a for a in raw if want in f"{a.get('logmodule')} {a.get('logfeature')}".lower()]
        if changes_only:
            raw = [a for a in raw if not is_session_noise(a)]
        raw.sort(key=lambda a: int(a.get("entry_time") or 0), reverse=True)
        extra: dict[str, Any] = {"by_user": dict(Counter(str(a.get("loguser")) for a in raw).most_common(10))}
        if scope.label:
            extra["scope"] = scope.label
        if note := _partial(result, "audit entries", since_hours):
            extra["partial"] = note
        rows = [audit_row(a, hosts, details=include_details) for a in raw]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, columns=AUDIT_COLUMNS, extra=extra
        )

    @reg.read(title="SD-WAN recent activity")
    async def catsdwan_recent_activity(
        ctx: Context,
        device: DeviceRef = None,
        site: SiteRef = None,
        since_hours: Annotated[int, Field(ge=1, le=168, description="How far back, in hours")] = 24,
        include: Annotated[
            list[Literal["alarms", "events", "audit"]] | None,
            Field(description="Sources to merge (default all three)"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """One timeline, newest first, of what happened to a device or site (or the whole fabric): alarms
        (raised, with active or the time cleared), device events and audit-log lines that name the device,
        each with its source and severity. Answers 'what has been breaking at this site?' and 'what changed
        just before it broke?'. A source that fails is reported in `warnings` and the others still answer;
        `by_source` counts each before paging."""
        app: SdwanApp = get_client(ctx)
        scope, hosts = await _scope(app, device, site)
        sources = list(dict.fromkeys(include or ["alarms", "events", "audit"]))
        paths = {"alarms": ALARMS_PATH, "events": EVENTS_PATH, "audit": AUDIT_PATH}
        got = await asyncio.gather(
            *(_read(app, paths[s], since_hours) for s in sources), return_exceptions=True
        )
        lines: list[dict[str, Any]] = []
        warnings: list[str] = []
        partial: list[str] = []
        for name, res in zip(sources, got, strict=True):
            if isinstance(res, UpstreamError):
                warnings.append(f"{name}: POST {paths[name]} failed: {str(res)[:200]}")
                continue
            if isinstance(res, BaseException):
                raise res
            if note := _partial(res, name, since_hours):
                partial.append(note)
            if name == "alarms":
                lines += [timeline_line("alarm", a, hosts) for a in res.rows if scope.alarm(a)]
            elif name == "events":
                lines += [timeline_line("event", e, hosts) for e in res.rows if scope.event(e)]
            else:
                lines += [timeline_line("audit", a, hosts) for a in res.rows if scope.audit(a)]
        if warnings and len(warnings) == len(sources):
            raise UpstreamError("; ".join(warnings))
        lines.sort(key=lambda x: x["_ms"], reverse=True)
        for line in lines:
            line.pop("_ms")
        extra: dict[str, Any] = {
            "scope": scope.label or "the whole fabric",
            "by_source": dict(Counter(str(x.get("source")) for x in lines)),
        }
        if warnings:
            extra["warnings"] = warnings
        if partial:
            extra["partial"] = partial
        return list_result(
            page_of(lines, limit=limit, offset=offset),
            fmt=response_format,
            columns=TIMELINE_COLUMNS,
            extra=extra,
        )
