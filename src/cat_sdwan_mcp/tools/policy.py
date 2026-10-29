"""W11 policy: catsdwan_list_policies, catsdwan_get_policy, catsdwan_explain_path, catsdwan_activate_policy.

The reads walk the Manager's policy objects (centralised and localised policies, their definitions and the
lists they reference) and say what they do in plain words. catsdwan_explain_path is offline like
fmc_rule_lookup: it walks the policy for a source site, a destination and an application, then joins the
app-route sequence with the tunnels' loss, latency and jitter now (W4) to say which tunnel the traffic takes.

catsdwan_activate_policy is always dangerous (a centralised policy changes every controller, and so the
whole fabric, at once): dangerous tier with MCP_ENABLE_DANGEROUS; with writes on but dangerous changes off it
is listed and its preview refuses with the reason.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp, _as_list, last_hours, rule
from cat_sdwan_mcp.configuration import POLICY_GROUPS_PATH, mask_config, path, resolve_group
from cat_sdwan_mcp.control import OMP_ROUTES_PATH, prefix_matches
from cat_sdwan_mcp.dataplane import APPROUTE_STATS_PATH, aggregate_approute
from cat_sdwan_mcp.fabric import device_rows, host_map, is_reachable, safely, site_ips
from cat_sdwan_mcp.inventory import Inventory, load_inventory
from cat_sdwan_mcp.policy import (
    ACTIVATE_PATH,
    CONNECTIVITY_PATH,
    DEACTIVATE_PATH,
    LIST_TYPE_PATH,
    LIST_TYPES,
    LISTS_PATH,
    VEDGE_DEFINITION_PATH,
    VEDGE_PATH,
    VSMART_DEFINITION_PATH,
    VSMART_PATH,
    assembly,
    assembly_view,
    by_id,
    centralised_row,
    connectivity_rows,
    controller_mode_blockers,
    definition_path,
    definition_view,
    entry_applies,
    group_policy_row,
    in_site_list,
    is_active,
    list_text,
    localised_row,
    ordered,
    parse_definition,
    rows,
    sequence_matches,
    sequence_row,
    site_ids,
    sla_action,
    tunnel_choice,
)
from cat_sdwan_mcp.tools.changes import _started, dangerous_blockers, dangerous_tool

POLICY_COLUMNS = ["name", "kind", "type", "activated", "parts", "devices", "updated"]
DEFINITION_LISTS = ("approute", "control", "data")  # definition lists read to name a policy's parts
STATS_CAP = 5000
Kind = Literal["all", "centralised", "localised", "policy_group"]
PolicyRef = Annotated[str, Field(description="Policy name or id (catsdwan_list_policies)")]


async def _policies(app: SdwanApp, kind: str = "all") -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """[(kind, record)] for centralised, localised policies and policy groups; a source that fails is a
    warning (policy groups exist only on configuration-group Managers)."""
    want = {
        "centralised": kind in ("all", "centralised"),
        "localised": kind in ("all", "localised"),
        "policy group": kind in ("all", "policy_group"),
    }
    sources = {"centralised": VSMART_PATH, "localised": VEDGE_PATH, "policy group": POLICY_GROUPS_PATH}
    picked = [k for k, on in want.items() if on]
    got = await asyncio.gather(*(safely(app.api.get(sources[k]), f"GET {sources[k]}") for k in picked))
    out: list[tuple[str, dict[str, Any]]] = []
    warnings: list[str] = []
    for k, body in zip(picked, got, strict=True):
        if isinstance(body, dict) and "error" in body and len(body) == 1:
            warnings.append(str(body["error"]))
            continue
        out += [(k, r) for r in rows(body)]
    return out, warnings


def _resolve(policies: list[tuple[str, dict[str, Any]]], ref: str) -> tuple[str, dict[str, Any]]:
    named = [
        {
            "id": r.get("policyId") or r.get("id"),
            "name": r.get("policyName") or r.get("name"),
            "_kind": k,
            "_row": r,
        }
        for k, r in policies
    ]
    found = resolve_group(named, ref, "policy")
    return str(found["_kind"]), found["_row"]


async def _lists(app: SdwanApp) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Every policy list by id: GET /template/policy/list, or the common types one by one."""
    try:
        return by_id(rows(await app.api.get(LISTS_PATH))), []
    except UpstreamError as e:
        first = f"GET {LISTS_PATH} failed ({str(e)[:120]}); lists read by type"
    got = await asyncio.gather(
        *(safely(app.api.get(path(LIST_TYPE_PATH, type=t)), f"list {t}") for t in LIST_TYPES)
    )
    out: list[dict[str, Any]] = []
    for body in got:
        if not (isinstance(body, dict) and "error" in body and len(body) == 1):
            out += rows(body)
    return by_id(out), [first]


async def _definitions(
    app: SdwanApp, parts: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Each part's full definition (with sequences) by definition id."""
    todo = {str(a.get("definitionId")): str(a.get("type")) for a in parts if a.get("definitionId")}

    async def one(def_id: str, kind: str) -> Any:
        return await safely(
            app.api.get(definition_path(kind, def_id)), f"GET {definition_path(kind, def_id)}"
        )

    got = await asyncio.gather(*(one(i, k) for i, k in todo.items()))
    defs: dict[str, dict[str, Any]] = {}
    warnings = []
    for (def_id, kind), body in zip(todo.items(), got, strict=True):
        if isinstance(body, dict) and "error" in body and len(body) == 1:
            warnings.append(str(body["error"]))
            continue
        if isinstance(body, dict):
            defs[def_id] = {"type": kind, **body}
    return defs, warnings


async def _definition_names(app: SdwanApp) -> dict[str, dict[str, Any]]:
    got = await asyncio.gather(
        *(safely(app.api.get(f"/dataservice/template/policy/definition/{t}"), t) for t in DEFINITION_LISTS)
    )
    out: dict[str, dict[str, Any]] = {}
    for body in got:
        if isinstance(body, dict) and "error" in body and len(body) == 1:
            continue
        for d in rows(body):
            if d.get("definitionId"):
                out[str(d["definitionId"])] = d
    return out


async def _centralised_parts(
    app: SdwanApp, row: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The policy's definition record (GET .../vsmart/definition/{id}) and its assembly."""
    body = await app.api.get(path(VSMART_DEFINITION_PATH, id=str(row.get("policyId"))))
    record = body if isinstance(body, dict) else {}
    parts = assembly(record) or assembly(row)
    return record, parts


def _site_devices(inv: Inventory, sites: set[str] | None) -> dict[str, list[str]]:
    """{site id: [edges there]} for the sites a policy names (every edge's site when None)."""
    out: dict[str, list[str]] = {}
    for r in inv.rows:
        if r.get("role") != "edge" or not r.get("site_id"):
            continue
        sid = str(r["site_id"])
        if sites is None or any(in_site_list(sid, {"entries": [{"siteId": s}]}) for s in sites):
            out.setdefault(sid, []).append(str(r.get("host") or r.get("system_ip")))
    return dict(sorted(out.items()))


def _is_prefix(text: str) -> bool:
    try:
        ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return False
    return "." in text or ":" in text


def _site_of(inv: Inventory, site: str) -> str:
    want = site.strip().lower()
    for r in inv.rows:
        if want in (str(r.get("site_id", "")).lower(), str(r.get("site_name", "")).lower()) and r.get(
            "site_id"
        ):
            return str(r["site_id"])
    return site.strip()


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN policies")
    async def catsdwan_list_policies(
        ctx: Context,
        kind: Annotated[
            Kind,
            Field(
                description="centralised (pushed to the controllers: app-route, data, control, topology), "
                "localised (on the edges with their device templates), policy_group (20.12+ "
                "configuration-group Managers), or all"
            ),
        ] = "all",
        name: Annotated[str | None, Field(description="Name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's policies: centralised policies (GET /template/policy/vsmart: whether activated and
        their parts, e.g. 'mcp-test-app-route (application-aware routing)'), localised policies
        (/template/policy/vedge: devices and device templates using them) and policy groups (/v1/policy-group:
        application priority, SLA and security profiles). Only one centralised policy is active at a time.
        Read one with catsdwan_get_policy; test it with catsdwan_explain_path."""
        app: SdwanApp = get_client(ctx)
        policies, warnings = await _policies(app, kind)
        names = await _definition_names(app) if any(k == "centralised" for k, _ in policies) else {}
        out = []
        for k, r in policies:
            if k == "centralised":
                out.append(centralised_row(r, names))
            elif k == "localised":
                out.append(localised_row(r))
            else:
                out.append(group_policy_row(r))
        if name:
            out = [r for r in out if name.lower() in str(r.get("name", "")).lower()]
        out.sort(
            key=lambda r: (not r.get("activated", False), str(r.get("kind")), str(r.get("name", "")).lower())
        )
        extra: dict[str, Any] = {}
        active = [r["name"] for r in out if r.get("activated")]
        if any(r.get("kind") == "centralised" for r in out):
            extra["active_centralised_policy"] = (
                active[0] if active else "none (no centralised policy is activated)"
            )
        if warnings:
            extra["warnings"] = warnings
        if not out:
            extra["note"] = "No policies of this kind on this Manager."
        return list_result(
            page_of(out, limit=limit, offset=offset), fmt=response_format, columns=POLICY_COLUMNS, extra=extra
        )

    @reg.read(title="Get SD-WAN policy")
    async def catsdwan_get_policy(
        ctx: Context, policy: PolicyRef, response_format: ResponseFormat = "markdown"
    ) -> ToolResult:
        """One policy in plain words: where each part applies (site and VPN lists resolved to their sites and
        VPNs, direction), and each definition's sequences as 'if <match> -> <action>' (app-route: SLA class
        with its loss/latency/jitter limits, preferred and backup colours; data policy: accept/drop, set TLOC,
        NAT, counters; control policy: route and TLOC matches and what they set; hub-and-spoke and mesh
        topologies), with the default action. CLI policies are shown as their text (secrets masked)."""
        app: SdwanApp = get_client(ctx)
        policies, warnings = await _policies(app)
        kind, row = _resolve(policies, policy)
        out: dict[str, Any] = {}
        if kind == "policy group":
            out = {
                **group_policy_row(row),
                "note": "a policy group's profiles are read with catsdwan_api_call "
                "('/dataservice/v1/feature-profile/sdwan/application-priority/{id}', ...)",
            }
            return object_result(out, fmt=response_format)
        lists, lw = await _lists(app)
        warnings += lw
        if kind == "centralised":
            record, parts = await _centralised_parts(app, row)
            out = centralised_row(row)
            definition = record.get("policyDefinition") or row.get("policyDefinition")
        else:
            body = await app.api.get(path(VEDGE_DEFINITION_PATH, id=str(row.get("policyId"))))
            record = body if isinstance(body, dict) else {}
            definition = record.get("policyDefinition") or row.get("policyDefinition")
            parts = [a for a in _as_list(parse_definition(definition).get("assembly")) if isinstance(a, dict)]
            out = localised_row(row)
        if str(row.get("policyType")) == "cli" and isinstance(definition, str):
            out["cli"] = mask_config(definition)[0]
            return object_result(out, fmt=response_format)
        defs, dw = await _definitions(app, parts)
        warnings += dw
        out["applies"] = assembly_view(parts, defs, lists)
        out["definitions"] = [
            definition_view(defs[str(a.get("definitionId"))], lists)
            for a in parts
            if str(a.get("definitionId")) in defs
        ]
        # the sequences again as one line each: the markdown view flattens nested definitions to their names
        out["sequences"] = [
            f"{d.get('name')} #{s.get('sequence') or i + 1}: {s['in_words']}"
            for d in out["definitions"]
            for i, s in enumerate(d.get("sequences") or [])
            if s.get("in_words")
        ]
        settings = parse_definition(definition).get("settings")
        if settings:
            out["settings"] = settings
        if kind == "centralised" and not out.get("activated"):
            out["note"] = "not activated: the controllers don't apply it (catsdwan_activate_policy)"
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt=response_format)

    @reg.read(title="Explain SD-WAN path")
    async def catsdwan_explain_path(
        ctx: Context,
        source_site: Annotated[
            str, Field(description="The site the traffic enters the fabric at (id or name)")
        ],
        destination: Annotated[
            str,
            Field(description="Destination site (id or name), or a prefix or address, e.g. '10.61.100.0/24'"),
        ],
        app: Annotated[
            str | None,
            Field(
                description="Application name or application-list name as the policy names it, e.g. 'webex'"
            ),
        ] = None,
        dscp: Annotated[
            int | None, Field(ge=0, le=63, description="DSCP of the traffic, e.g. 46 for voice")
        ] = None,
        vpn: Annotated[int | None, Field(ge=1, le=65530, description="Service VPN, e.g. 10")] = None,
        policy: Annotated[
            str | None,
            Field(
                description="Centralised policy to walk (default: the activated one). Name a policy that "
                "is not activated to see what it WOULD do"
            ),
        ] = None,
        window_hours: Annotated[
            int, Field(ge=1, le=24, description="App-route statistics window for 'now' (default 1 h)")
        ] = 1,
    ) -> ToolResult:
        """Which path traffic takes, worked out offline (like fmc_rule_lookup): (1) the control policies and
        topologies applied to the two sites, (2) for a prefix, which edges advertise it (OMP routes received
        at a source edge, read live), (3) data-policy sequences that may override the path, (4) the first
        app-route sequence that matches the application/DSCP (and the ones that might, when the policy
        matches on things not given), with its SLA class and preferred and backup colours, (5) each tunnel's
        loss, latency and jitter now against that SLA class, and so (6) which tunnel(s) the traffic takes and
        why ('the preferred colour mpls misses Realtime: latency 320 ms > 150 ms; biz-internet meets it').
        Answers 'why does voice take the internet link at this branch?'."""
        sdwan: SdwanApp = get_client(ctx)
        if app is None and dscp is None:
            raise InvalidRequest("Give the traffic: an `app` (name or app-list name) or a `dscp`, or both.")
        inv = await load_inventory(sdwan)
        hosts = host_map(inv)
        src_ips = site_ips(inv, source_site)
        src_site = _site_of(inv, source_site)
        steps: list[dict[str, Any]] = []
        caveats: list[str] = []
        warnings: list[str] = list(inv.warnings)
        dest_ips: set[str] | None
        dest_site: str | None = None
        if _is_prefix(destination):
            dest_ips, step = await _prefix_owners(sdwan, inv, src_ips, destination, vpn, hosts)
            steps.append(step)
        else:
            dest_ips = site_ips(inv, destination)
            dest_site = _site_of(inv, destination)
        policies, pw = await _policies(sdwan, "centralised")
        warnings += pw
        central = [r for _, r in policies]
        chosen: dict[str, Any] | None = None
        if policy:
            _, chosen = _resolve([("centralised", r) for r in central], policy)
        else:
            chosen = next((r for r in central if is_active(r)), None)
        steering: dict[str, Any] | None = None
        sla: dict[str, Any] | None = None
        out: dict[str, Any] = {
            "source_site": src_site,
            "destination": destination if dest_site is None else f"site {dest_site}",
            "traffic": {k: v for k, v in {"app": app, "dscp": dscp, "vpn": vpn}.items() if v is not None},
        }
        if chosen is None:
            names = ", ".join(str(r.get("policyName")) for r in central) or "none"
            out["policy"] = "none activated"
            caveats.append(
                f"no centralised policy is activated (policies: {names}); pass policy=<name> to see what "
                "one would do"
            )
        else:
            out["policy"] = f"{chosen.get('policyName')} ({'' if is_active(chosen) else 'NOT '}activated)"
            if not is_active(chosen):
                caveats.append(f"{chosen.get('policyName')} is not activated: this is what it WOULD do")
            _, parts = await _centralised_parts(sdwan, chosen)
            lists, lw = await _lists(sdwan)
            defs, dw = await _definitions(sdwan, parts)
            warnings += lw + dw
            steps += _topology_steps(parts, defs, lists, src_site, dest_site, vpn)
            steps += _data_steps(parts, defs, lists, src_site, vpn, app, dscp, caveats)
            steering, sla, step = _approute_step(parts, defs, lists, src_site, vpn, app, dscp, caveats)
            steps.append(step)
        rules_ = [rule("vdevice_name", sorted(src_ips))]
        if dest_ips:
            rules_.append(rule("remote_system_ip", sorted(dest_ips)))
        result = await sdwan.query(APPROUTE_STATS_PATH, last_hours(window_hours, *rules_), limit=STATS_CAP)
        tunnels = aggregate_approute(result.rows, hosts)
        for t in tunnels:
            t.setdefault("state", "up")
        if not result.rows:
            caveats.append(
                f"no app-route statistics from site {src_site} in the last {window_hours} h: tunnel quality "
                "unknown"
            )
        choice = tunnel_choice(steering, tunnels, sla)
        steps.append(
            {
                "step": "tunnels now",
                "source": f"POST {APPROUTE_STATS_PATH}, last {window_hours} h",
                "tunnels": [
                    {
                        k: t.get(k)
                        for k in (
                            "host",
                            "local_colour",
                            "remote",
                            "remote_colour",
                            "loss_percent",
                            "latency_ms",
                            "jitter_ms",
                            "sla",
                        )
                        if t.get(k) is not None
                    }
                    for t in tunnels
                ],
            }
        )
        out["steps"] = steps
        out["verdict"] = choice["verdict"]
        if "colours_meeting_sla" in choice:
            out["colours_meeting_sla"] = choice["colours_meeting_sla"]
        if caveats:
            out["caveats"] = caveats
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt="json")

    @dangerous_tool(reg, title="Activate SD-WAN centralised policy", task=True)
    async def catsdwan_activate_policy(
        ctx: Context,
        policy: PolicyRef,
        action: Annotated[
            Literal["activate", "deactivate"],
            Field(description="activate (replaces the active centralised policy) or deactivate"),
        ] = "activate",
        wait: Annotated[
            bool, Field(description="Wait for every controller to report success or failure (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Activate or deactivate a centralised policy (POST /template/policy/vsmart/activate/{id}
        {"isEdited": false}, or .../deactivate/{id}), then follow the action (GET
        /device/action/status/{id}) to success or failure per controller. Always dangerous: a centralised
        policy is pushed to every controller and changes routing for every site it names at once.
        Preview-first: the controllers it is pushed to, every site the policy matches with the edges there,
        the policy it replaces, and blockers (a controller unreachable or in CLI mode: the Manager activates
        centralised policy only on controllers with a device template). Undo: the opposite action (or
        activate the previous policy again)."""
        app: SdwanApp = get_client(ctx)
        policies, _ = await _policies(app, "centralised")
        central = [r for _, r in policies]
        _, row = _resolve([("centralised", r) for r in central], policy)
        pid, name = str(row.get("policyId")), str(row.get("policyName"))
        inv = await load_inventory(app)
        controllers = [r for r in inv.rows if r.get("role") == "controller"]
        others = [r for r in central if is_active(r) and str(r.get("policyId")) != pid]
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        if action == "activate" and is_active(row):
            blockers.append(f"{name} is already activated: nothing to do")
        if action == "deactivate" and not is_active(row):
            blockers.append(f"{name} is not activated: nothing to deactivate")
        if not controllers:
            blockers.append("the Manager lists no controllers to push the policy to")
        if action == "activate":
            blockers += controller_mode_blockers(controllers)
        _, parts = await _centralised_parts(app, row)
        lists, lw = await _lists(app)
        defs, dw = await _definitions(app, parts)
        warnings += lw + dw
        sites = site_ids(parts, lists)
        at_sites = _site_devices(inv, sites)
        check: Any = None
        try:
            check = connectivity_rows(await app.api.get(CONNECTIVITY_PATH))
        except UpstreamError as e:
            warnings.append(f"the Manager's controller check ({CONNECTIVITY_PATH}) failed: {str(e)[:200]}")
        reasons = [
            "a centralised policy is pushed to every controller and changes routing for every site it names "
            "at once"
        ]
        blockers += dangerous_blockers(ctx, app, reasons)
        edges = sum(len(v) for v in at_sites.values())
        verb = "Activate" if action == "activate" else "Deactivate"
        plan = Plan(
            f"{verb} centralised policy {name} on {len(controllers)} controller(s)",
            details={
                "policy": centralised_row(row, defs),
                "tier": "dangerous",
                "tier_reasons": reasons,
                "controllers": [
                    {k: c.get(k) for k in ("host", "system_ip", "reachability", "config_mode") if c.get(k)}
                    for c in controllers
                ],
                "sites": (
                    {s: devs for s, devs in at_sites.items()}
                    if sites is not None
                    else {"every site": [d for devs in at_sites.values() for d in devs]}
                ),
                "sites_named_without_edges": sorted(
                    s
                    for s in (sites or set())
                    if not any(in_site_list(x, {"entries": [{"siteId": s}]}) for x in at_sites)
                )
                or None,
                "applies": assembly_view(parts, defs, lists),
                **(
                    {"replaces": [str(r.get("policyName")) for r in others]}
                    if action == "activate" and others
                    else {}
                ),
                **({"manager_check": check} if check else {}),
                "request": f"POST {ACTIVATE_PATH if action == 'activate' else DEACTIVATE_PATH}".replace(
                    "{id}", pid
                ),
                "undo": (
                    f"catsdwan_activate_policy(policy={name!r}, action='deactivate')"
                    + (f", then activate {others[0].get('policyName')!r} again" if others else "")
                    if action == "activate"
                    else f"catsdwan_activate_policy(policy={name!r}, action='activate')"
                ),
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Every controller re-evaluates routes and policy at once: app-route steering, data policy "
                "and route/TLOC filtering change for every site the policy names"
                + (
                    " (every site)"
                    if sites is None
                    else f" ({len(at_sites)} site(s) with edges, {edges} edge(s))"
                ),
                *(
                    [f"Replaces the active policy {', '.join(str(r.get('policyName')) for r in others)}"]
                    if action == "activate" and others
                    else []
                ),
            ],
            fingerprint={
                "policy": [row.get("lastUpdatedOn"), is_active(row), row.get("policyVersion")],
                "active": sorted(str(r.get("policyId")) for r in central if is_active(r)),
            },
            blockers=blockers,
            blast_radius=len(controllers) + edges,
            # activating the policy it replaced puts that one back; with none, deactivate this one again
            undo=Undo(
                "catsdwan_activate_policy", {"policy": str(others[0].get("policyName")), "action": "activate"}
            )
            if action == "activate" and others
            else Undo(
                "catsdwan_activate_policy",
                {"policy": name, "action": "deactivate" if action == "activate" else "activate"},
            ),
        )

        async def apply() -> Any:
            if action == "activate":
                answer = await app.api.post(path(ACTIVATE_PATH, id=pid), {"isEdited": False})
            else:
                answer = await app.api.post(path(DEACTIVATE_PATH, id=pid), {})
            res = await _started(app, ctx, answer, wait, f"{action} of {name}")
            res["check"] = (
                "catsdwan_list_policies (activated column), then catsdwan_explain_path or "
                "catsdwan_app_route_stats for the sites it names"
            )
            return res

        return await preview_or_apply(
            ctx,
            tool="catsdwan_activate_policy",
            args={"policy": policy, "action": action, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )


# --- explain-path steps ------------------------------------------------------------------------------


async def _prefix_owners(
    app: SdwanApp,
    inv: Inventory,
    src_ips: set[str],
    prefix: str,
    vpn: int | None,
    hosts: dict[str, str],
) -> tuple[set[str] | None, dict[str, Any]]:
    """The edges that advertise `prefix`, from the OMP routes received at the first reachable source edge."""
    edge = next((r for r in inv.rows if str(r.get("system_ip")) in src_ips and is_reachable(r)), None)
    step: dict[str, Any] = {"step": "OMP routes", "prefix": prefix}
    if edge is None:
        step["note"] = (
            "no reachable edge at the source site to read OMP routes from: every remote tunnel is shown"
        )
        return None, step
    route_path = OMP_ROUTES_PATH.format(direction="received")
    try:
        got = await device_rows(app, route_path, str(edge["system_ip"]))
    except UpstreamError as e:
        step["note"] = f"OMP routes not read from {edge.get('host')}: {str(e)[:200]}"
        return None, step
    matches = [
        r
        for r in got
        if prefix_matches(r.get("prefix"), prefix) and (vpn is None or str(r.get("vpn-id")) == str(vpn))
    ]
    installed = [r for r in matches if {"C", "I"} & set(str(r.get("status", "")).split())] or matches
    owners = {str(r.get("originator")) for r in installed if r.get("originator")}
    step["read_on"] = edge.get("host")
    step["source"] = f"GET {route_path} (live)"
    if not owners:
        step["note"] = f"{edge.get('host')} has no OMP route for {prefix}: the traffic has no overlay path"
        return set(), step
    step["advertised_by"] = sorted(
        f"{hosts.get(o, o)} (site {r.get('site-id')})" for r in installed for o in [str(r.get("originator"))]
    )
    step["tlocs"] = sorted(
        {f"{hosts.get(str(r.get('ip')), r.get('ip'))} {r.get('color')}" for r in installed}
    )
    return owners, step


def _topology_steps(
    parts: list[dict[str, Any]],
    defs: dict[str, dict[str, Any]],
    lists: dict[str, dict[str, Any]],
    src: str,
    dest: str | None,
    vpn: int | None,
) -> list[dict[str, Any]]:
    out = []
    for a in parts:
        kind = str(a.get("type"))
        if kind not in ("control", "hubAndSpoke", "mesh", "vpnMembershipGroup"):
            continue
        d = defs.get(str(a.get("definitionId")))
        applies = []
        for e in _as_list(a.get("entries")) or [{}]:
            for site in [s for s in (src, dest) if s]:
                ok, why = entry_applies(e if isinstance(e, dict) else {}, site, vpn, lists)
                if ok:
                    applies.append(
                        f"site {site}: {why}" + (f" ({e.get('direction')})" if e.get("direction") else "")
                    )
        if kind != "control" or applies:
            view = definition_view(d, lists) if d else {"name": a.get("definitionId"), "type": kind}
            out.append(
                {
                    "step": "control policy" if kind == "control" else "topology",
                    "definition": view.get("name"),
                    "applies": applies or ["the topology's own site lists"],
                    **{k: view[k] for k in ("sequences", "topology", "default_action") if k in view},
                    "effect": "shapes which routes and TLOCs the sites learn, so which tunnels exist for "
                    "the traffic",
                }
            )
    return out


def _data_steps(
    parts: list[dict[str, Any]],
    defs: dict[str, dict[str, Any]],
    lists: dict[str, dict[str, Any]],
    src: str,
    vpn: int | None,
    app: str | None,
    dscp: int | None,
    caveats: list[str],
) -> list[dict[str, Any]]:
    out = []
    for a in parts:
        if str(a.get("type")) != "data":
            continue
        d = defs.get(str(a.get("definitionId")))
        if d is None:
            continue
        for e in _as_list(a.get("entries")) or [{}]:
            ok, why = entry_applies(e if isinstance(e, dict) else {}, src, vpn, lists)
            if not ok:
                continue
            hits = []
            for seq in ordered(d.get("sequences")):
                verdict, reason = sequence_matches(seq, app, dscp, lists)
                if verdict == "no":
                    continue
                hits.append({**sequence_row(seq, lists), "matches": verdict, "why": reason})
                if verdict == "yes":
                    break
            if hits:
                out.append(
                    {"step": "data policy", "definition": d.get("name"), "applies": why, "sequences": hits}
                )
                if any(
                    any(
                        w == "drop" or "TLOC" in w or "localTloc" in w or w.startswith("NAT")
                        for w in h["action"]
                    )
                    for h in hits
                ):
                    caveats.append(
                        f"data policy {d.get('name')} may override the app-route choice (see its step)"
                    )
    return out


def _approute_step(
    parts: list[dict[str, Any]],
    defs: dict[str, dict[str, Any]],
    lists: dict[str, dict[str, Any]],
    src: str,
    vpn: int | None,
    app: str | None,
    dscp: int | None,
    caveats: list[str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any]]:
    """(the SLA steering, the SLA class limits, the step) of the first app-route part applying to the site."""
    skipped = []
    for a in parts:
        if str(a.get("type")) != "appRoute":
            continue
        d = defs.get(str(a.get("definitionId")))
        if d is None:
            skipped.append(f"app-route definition {a.get('definitionId')} could not be read")
            continue
        for e in _as_list(a.get("entries")) or [{}]:
            ok, why = entry_applies(e if isinstance(e, dict) else {}, src, vpn, lists)
            if not ok:
                skipped.append(f"{d.get('name')}: {why}")
                continue
            maybe = []
            for seq in ordered(d.get("sequences")):
                verdict, reason = sequence_matches(seq, app, dscp, lists)
                if verdict == "maybe":
                    maybe.append(f"sequence {seq.get('sequenceId')} ({seq.get('sequenceName')}) {reason}")
                    continue
                if verdict == "yes":
                    steering = sla_action(seq.get("actions"), lists)
                    if maybe:
                        caveats.append("earlier app-route sequences may match first: " + "; ".join(maybe))
                    step = {
                        "step": "app-route policy",
                        "definition": d.get("name"),
                        "applies": why,
                        "matched": {**sequence_row(seq, lists), "why": reason},
                    }
                    return steering, (steering or {}).get("sla"), step
            raw_default = d.get("defaultAction")
            default: dict[str, Any] = raw_default if isinstance(raw_default, dict) else {}
            steering = None
            if default.get("type") == "slaClass" and default.get("ref"):
                steering = sla_action(
                    [{"type": "slaClass", "parameter": [{"field": "name", "ref": default["ref"]}]}], lists
                )
            if maybe:
                caveats.append("app-route sequences that may match: " + "; ".join(maybe))
            step = {
                "step": "app-route policy",
                "definition": d.get("name"),
                "applies": why,
                "matched": "no sequence matches: the default action applies"
                + (
                    f" ({list_text(lists.get(str(default.get('ref'))), default.get('ref'))})"
                    if steering
                    else " (no SLA steering)"
                ),
            }
            return steering, (steering or {}).get("sla"), step
    return (
        None,
        None,
        {
            "step": "app-route policy",
            "matched": f"no app-route policy applies to site {src}" + (f" in VPN {vpn}" if vpn else ""),
            **({"skipped": skipped} if skipped else {}),
        },
    )
