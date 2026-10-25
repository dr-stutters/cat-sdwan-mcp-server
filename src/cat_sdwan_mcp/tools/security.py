"""W23 edge security reads: catsdwan_security_status, catsdwan_security_events."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
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
    object_result,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, last_hours, rule
from cat_sdwan_mcp.fabric import device_rows, find_device, host_map, require_reachable, site_ips
from cat_sdwan_mcp.inventory import load_inventory, resolve
from cat_sdwan_mcp.security import (
    EMBEDDED_PROFILES_PATH,
    EVENT_PATHS,
    LEGACY_POLICIES_PATH,
    STATUS_PATHS,
    aggregate,
    drop_check,
    engine_row,
    nonzero_drops,
    policy_names,
    records,
    sig_row,
    ssl_proxy_row,
    utd_version,
    zone_pair_rows,
)

Kind = Literal["ips", "url", "connection", "dns"]
FETCH_CAP = 2000  # newest records of one index aggregated per call
COLUMNS = {
    "ips": ["signature", "message", "classification", "priority", "hits", "actions", "edges"],
    "url": ["edge", "records", "category_action_block", "reputation_action_block", "blacklist_hit_cnt"],
    "connection": ["policy", "zone_pair", "action", "drop_reason", "connections", "edges"],
    "dns": ["edge", "records", "redirect_pkts", "local_domain_bypass_total_pkts"],
}
KIND_WORDS = {
    "ips": "IPS alerts",
    "url": "URL-filtering records",
    "connection": "unified-logging connection records",
    "dns": "DNS-security (Umbrella) records",
}
NO_POLICY = (
    "No security policy: the Manager has no security policy ({legacy}) and no embedded-security profile "
    "({embedded})"
)


async def _policies(app: SdwanApp) -> tuple[list[str] | None, list[str]]:
    """The Manager's security policies by name (None when neither list could be read), plus read errors."""
    got = await asyncio.gather(
        app.get_data(LEGACY_POLICIES_PATH), app.get_data(EMBEDDED_PROFILES_PATH), return_exceptions=True
    )
    errors = [
        f"GET {p} failed: {str(r)[:200]}"
        for p, r in zip((LEGACY_POLICIES_PATH, EMBEDDED_PROFILES_PATH), got, strict=True)
        if isinstance(r, UpstreamError)
    ]
    for r in got:
        if isinstance(r, BaseException) and not isinstance(r, UpstreamError):
            raise r
    if len(errors) == 2:
        return None, errors
    legacy, embedded = (None if isinstance(r, BaseException) else r for r in got)
    return policy_names(legacy, embedded), errors


def _no_policy() -> str:
    return NO_POLICY.format(legacy=f"GET {LEGACY_POLICIES_PATH}", embedded=f"GET {EMBEDDED_PROFILES_PATH}")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN edge security status")
    async def catsdwan_security_status(
        ctx: Context,
        device: Annotated[str, Field(description="The edge: host name, system IP, chassis or serial")],
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Is the edge's own security stack inspecting or blocking traffic? Read live from one edge: the UTD
        container (Snort engine status, memory, the UTD image supported and recommended, IPS signature
        package and updates, URL-filtering cloud connection), the zone-based firewall (zone pairs with policy,
        class, action, packets and sessions, one row per class; the data plane's drop counters that are not
        zero, and dropped_by_policy, the policy drops counted when read, which the per-class counters can
        trail by a minute), the SSL proxy and the Secure Internet Gateway tunnels (Umbrella, Zscaler), plus
        the Manager's security policies. `features` says which are running and `verdict` says it in one line;
        when there is no security policy at all, it says so plainly (nothing on the edge filters traffic: look
        at the WAN or the firewall behind it). Reads only: the edge firewall is written with
        catsdwan_set_firewall_policy (W47), the FTD in FMC."""
        app: SdwanApp = get_client(ctx)
        row, _ = await find_device(app, device)
        ip = require_reachable(row, "catsdwan_list_devices shows each device's reachability.")
        name = str(row.get("host") or ip)
        keys = list(STATUS_PATHS)
        got, (policies, policy_errors) = await asyncio.gather(
            asyncio.gather(*(device_rows(app, STATUS_PATHS[k], ip) for k in keys), return_exceptions=True),
            _policies(app),
        )
        tables: dict[str, list[dict[str, Any]]] = {}
        errors = list(policy_errors)
        for k, res in zip(keys, got, strict=True):
            if isinstance(res, UpstreamError):
                errors.append(f"{k}: GET {STATUS_PATHS[k]} failed: {str(res)[:200]}")
                tables[k] = []
            elif isinstance(res, BaseException):
                raise res
            else:
                tables[k] = records(res)
        engines = [engine_row(r) for r in tables["utd_engine"]]
        zone_pairs = zone_pair_rows(tables["zone_pairs"])
        drops = nonzero_drops(tables["zbfw_drops"])
        sig = [sig_row(r) for r in tables["sig_tunnels"] + tables["umbrella_tunnels"]]
        ssl = [ssl_proxy_row(r) for r in tables["ssl_proxy"]]
        features = {
            "utd": bool(engines),
            "zone_based_firewall": bool(zone_pairs or tables["zbfw_statistics"] or drops),
            "ssl_proxy": bool(ssl),
            "sig_tunnels": bool(sig),
        }
        out: dict[str, Any] = {
            "device": name,
            "system_ip": ip,
            "security_policies": policies or ("none" if policies == [] else "not read"),
            "features": features,
        }
        utd: dict[str, Any] = {}
        if engines:
            utd["engine"] = engines
        if version := utd_version(tables["utd_version"]):
            utd["image"] = version
        for k in ("ips_signatures", "ips_updates", "url_filtering_cloud"):
            if tables[k]:
                utd[k] = tables[k]
        if utd:
            out["utd"] = utd
        firewall: dict[str, Any] = {}
        if zone_pairs:
            firewall["zone_pairs"] = zone_pairs
        if tables["zone_pair_sessions"]:
            firewall["active_sessions"] = len(tables["zone_pair_sessions"])
        if drops:
            firewall["drops"] = drops
        if zone_pairs or drops:
            firewall.update(drop_check(zone_pairs, drops))
        if firewall:
            out["zone_based_firewall"] = firewall
        if ssl:
            out["ssl_proxy"] = ssl
        if sig:
            out["sig_tunnels"] = sig
        running = [k.replace("_", " ") for k, on in features.items() if on]
        if not running and not policies:
            out["verdict"] = (
                f"{_no_policy() if policies is not None else 'No security feature runs'}, and {name} runs no "
                "UTD (IPS / URL filtering), zone-based firewall, SSL proxy or SIG tunnel. Nothing on this "
                "edge inspects or blocks traffic: look at the WAN (catsdwan_app_route_stats) or a firewall "
                "behind it (fmc_packet_tracer)."
            )
        elif not running:
            out["verdict"] = (
                f"The Manager has security policies, but none runs on {name} (no UTD, zone-based firewall, "
                "SSL proxy or SIG tunnel): is the policy attached to this edge's device template or group?"
            )
        else:
            issues = [
                f"UTD engine {e.get('status')}{': ' + str(e['reason']) if e.get('reason') else ''}"
                for e in engines
                if e.get("status") and e.get("status") != "green"
            ]
            if drops:
                top = ", ".join(f"{k} {v}" for k, v in list(drops.items())[:3])
                issues.append(f"the zone-based firewall dropped packets ({top})")
            issues += [
                f"SIG tunnel {t.get('tunnel')} is {t.get('state')}"
                for t in sig
                if t.get("state") and str(t["state"]).lower() not in ("up", "active")
            ]
            out["verdict"] = f"{name} runs {', '.join(running)}" + (
                f"; attention: {'; '.join(issues)}." if issues else "; nothing is reported down or dropping."
            )
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)

    @reg.read(title="SD-WAN security events")
    async def catsdwan_security_events(
        ctx: Context,
        kind: Annotated[
            Kind,
            Field(
                description="ips (IPS alerts by signature), url (URL-filtering counters per edge), "
                "connection (unified-logging connections by firewall policy, action and drop reason), dns "
                "(Umbrella DNS redirects per edge)"
            ),
        ],
        device: Annotated[
            str | None, Field(description="Only this edge (host name, system IP, chassis or serial)")
        ] = None,
        site: Annotated[str | None, Field(description="Only the edges at this site (id or name)")] = None,
        hours: Annotated[int, Field(ge=1, le=168, description="How far back, in hours")] = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Security events the edges reported, from the Manager's statistics (POST /statistics/ipsalert,
        /statistics/urlf, /statistics/sul/connections, /statistics/umbrella), aggregated: IPS alerts by
        signature (message, classification, priority, hits, action, edges, top sources and destinations),
        URL filtering per edge (block and pass counters), connections by firewall policy, zone pair, action
        and drop reason (with the edges and applications), DNS security per edge. Biggest first; the newest
        2000 records are aggregated. With no records it says why: no security policy on the Manager means
        no events are expected (the edges have nothing that logs them)."""
        if device and site:
            raise InvalidRequest("Give a device or a site, not both.")
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        rules: list[dict[str, Any]] = []
        scope = "every edge"
        if device:
            row = resolve(inv, device)
            if not row.get("system_ip"):
                raise InvalidRequest(
                    f"{device!r} has not joined the fabric (no system IP), so it has no events."
                )
            rules.append(rule("vdevice_name", [row["system_ip"]]))
            scope = str(row.get("host") or row["system_ip"])
        elif site:
            rules.append(rule("vdevice_name", sorted(site_ips(inv, site))))
            scope = f"site {site}"
        path = EVENT_PATHS[kind]
        result = await app.query(path, last_hours(hours, *rules), limit=FETCH_CAP)
        groups = aggregate(kind, result.rows, host_map(inv), keep=FETCH_CAP)
        extra: dict[str, Any] = {
            "kind": kind,
            "scope": scope,
            "window_hours": hours,
            "records": len(result.rows),
            "source": f"POST {path}",
        }
        if result.more:
            extra["partial"] = f"only the newest {FETCH_CAP} records were aggregated; narrow the window"
        if not result.rows:
            policies, _ = await _policies(app)
            if policies == []:
                extra["note"] = (
                    f"{_no_policy()}, so the edges log no IPS, URL-filtering, firewall or DNS-security "
                    "events: none is expected. catsdwan_security_status(device) shows what runs on an edge."
                )
            else:
                extra["note"] = f"No {KIND_WORDS[kind]} for {scope} in the last {hours} h."
                if policies:
                    extra["security_policies"] = policies
        return list_result(
            page_of(groups, limit=limit, offset=offset),
            fmt=response_format,
            columns=COLUMNS[kind],
            extra=extra,
        )
