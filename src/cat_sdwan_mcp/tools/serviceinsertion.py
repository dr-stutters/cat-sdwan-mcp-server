"""W50 service insertion: catsdwan_service_chains (read), catsdwan_set_service_chain (write, store only),
catsdwan_set_service_steering (always dangerous, store only) and the prompt catsdwan_trace_through_firewall
(uses fmc).

Tiers: a service in a LAN VPN parcel only advertises the firewall into OMP; no traffic moves until a policy
steers it, so set_service_chain is write tier. set_service_steering redirects live traffic once deployed (a
firewall that drops, or `restrict` with the service down, cuts the flow), so it is dangerous like the W47 edge
firewall. Both store on the Manager only: catsdwan_deploy_config_group / catsdwan_deploy_policy_group push.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
    tool_ref,
)
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    CONFIG_GROUPS_PATH,
    POLICY_GROUPS_PATH,
    PROFILE_PATH,
    path,
    resolve_group,
)
from cat_sdwan_mcp.edgefirewall import by_name, literal_prefix_problems, request_schema, schema_problems
from cat_sdwan_mcp.fabric import device_rows, require_reachable
from cat_sdwan_mcp.features import PARCEL_PATH, parcel_url, parcels_of
from cat_sdwan_mcp.inventory import load_inventory, resolve
from cat_sdwan_mcp.policygroups import created_id, group_profiles, update_body
from cat_sdwan_mcp.serviceinsertion import (
    APP_PRIORITY_PATH,
    APP_PRIORITY_PROFILE_PATH,
    CHAIN_MAPPING_PATH,
    CHAINS,
    DIRECTIONS,
    LAN_VPN_LIST_PATH,
    LAN_VPN_PATH,
    LAN_VPN_SCHEMA_PATH,
    OMP_SERVICES_PATH,
    SERVICE_PROFILES_PATH,
    TRAFFIC_POLICY_LIST_PATH,
    TRAFFIC_POLICY_PATH,
    TRAFFIC_POLICY_SCHEMA_PATH,
    address_problems,
    chain_mapping,
    cli_lines,
    cli_services,
    omp_service_rows,
    service_entry,
    service_rows,
    steering_rows,
    target_of,
    traffic_policy_body,
    vpn_parcels,
    vpn_problem,
    with_service,
)
from cat_sdwan_mcp.tools.changes import dangerous_blockers, dangerous_tool
from cat_sdwan_mcp.tools.configuration import _groups
from cat_sdwan_mcp.tools.edgefirewall import _group_detail, list_objects, reach
from cat_sdwan_mcp.tools.features import _reach
from cat_sdwan_mcp.tools.policygroups import policy_profiles

ServiceType = Literal["FW", "IDS", "IDP", "netsvc1", "netsvc2", "netsvc3", "netsvc4", "appqoe"]
TIER_REASON = "a traffic-steering policy (W50): deployed, it sends live traffic through a firewall"
OPTIONAL = "skipped if that server is not connected: say so in one line and go on"


class SteeringRule(BaseModel):
    """One traffic-policy sequence that sends matching traffic to a service (in order; first match)."""

    name: str = Field(min_length=1, max_length=64, description="Sequence name, e.g. 'br1-to-dc'")
    source_prefixes: list[str] = Field(default_factory=list, description="Source IPv4 prefixes")
    destination_prefixes: list[str] = Field(default_factory=list, description="Destination IPv4 prefixes")
    source_lists: list[str] = Field(
        default_factory=list, description="Source data-prefix lists by name (policy-object profile)"
    )
    destination_lists: list[str] = Field(
        default_factory=list, description="Destination data-prefix lists by name (policy-object profile)"
    )
    protocols: list[int] = Field(
        default_factory=list, description="IP protocol numbers (6 tcp, 17 udp, 1 icmp)"
    )
    destination_ports: list[int] = Field(default_factory=list, description="Destination ports")
    service: ServiceType = Field(default="FW", description="The service to send it to")
    chain: str | None = Field(
        default=None, description="A service chain SC1-SC16 instead of a single service (20.13+ chains)"
    )
    service_vpn: int | None = Field(
        default=None,
        description="The VPN the service is in (default the policy's VPN; required when it targets several)",
    )
    local: bool = Field(default=False, description="Only a service on this edge (a branch's own firewall)")
    restrict: bool = Field(
        default=False, description="Drop the traffic when the service is down, instead of routing around it"
    )


# --- reads ---------------------------------------------------------------------------------------


async def _profiles_of(app: SdwanApp, base: str) -> list[dict[str, Any]]:
    try:
        body = await app.api.get(base)
    except UpstreamError:
        return []
    rows = body.get("data") if isinstance(body, dict) and "data" in body else body
    return [
        {"id": str(r["profileId"]), "name": r.get("profileName")}
        for r in _as_list(rows)
        if isinstance(r, dict) and r.get("profileId")
    ]


async def service_inventory(
    app: SdwanApp, vpn: int | None, groups: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Every service in a service VPN that configuration groups give their edges: from the service profiles'
    LAN VPN parcels and from CLI profiles. [{vpn, type, addresses, tracking, source, profile, parcel,
    groups}], read problems."""
    out: list[dict[str, Any]] = []
    warnings: list[str] = []
    by_profile: dict[str, list[str]] = {}
    for gr in groups:
        for p in _as_list(gr.get("profiles")):
            if isinstance(p, dict) and p.get("id"):
                by_profile.setdefault(str(p["id"]), []).append(str(gr.get("name")))

    svc_profiles = await _profiles_of(app, SERVICE_PROFILES_PATH)
    got = await asyncio.gather(
        *(app.api.get(path(LAN_VPN_LIST_PATH, profile=p["id"])) for p in svc_profiles), return_exceptions=True
    )
    for p, body in zip(svc_profiles, got, strict=True):
        if isinstance(body, UpstreamError):
            warnings.append(f"service profile {p['name']}: LAN VPNs not read: {str(body)[:150]}")
            continue
        if isinstance(body, BaseException):
            raise body
        for v in vpn_parcels(body):
            if vpn is not None and str(v["vpn"]) != str(vpn):
                continue
            for s in service_rows(v["data"]):
                out.append(
                    {
                        "vpn": v["vpn"],
                        **s,
                        "source": "service profile (LAN VPN parcel)",
                        "profile": p["name"],
                        "parcel": v["name"],
                        "groups": by_profile.get(p["id"], []),
                    }
                )

    cli = [
        (gr, p)
        for gr in groups
        for p in _as_list(gr.get("profiles"))
        if isinstance(p, dict) and p.get("type") == "cli" and p.get("id")
    ]
    seen: set[str] = set()
    for gr, p in cli:
        if str(p["id"]) in seen:
            continue
        seen.add(str(p["id"]))
        try:
            detail = await app.api.get(path(PROFILE_PATH, type="cli", id=str(p["id"])))
            for parcel in parcels_of(detail):
                if parcel["type"] != "config":
                    continue
                body = await app.api.get(
                    parcel_url(
                        PARCEL_PATH,
                        ptype="cli",
                        parcel_type="config",
                        profile=str(p["id"]),
                        parcel=parcel["id"],
                    )
                )
                data = ((body or {}).get("payload") or {}).get("data") or {}
                text = data.get("config")
                text = text.get("value") if isinstance(text, dict) else text
                for s in cli_services(text if isinstance(text, str) else ""):
                    if vpn is not None and s["vpn"] != vpn:
                        continue
                    out.append(
                        {
                            **s,
                            "source": "CLI profile",
                            "profile": p.get("name"),
                            "parcel": parcel["name"],
                            "groups": by_profile.get(str(p["id"]), [str(gr.get("name"))]),
                        }
                    )
        except UpstreamError as e:
            warnings.append(f"CLI profile {p.get('name')}: not read: {str(e)[:150]}")
    return out, warnings


async def _data_prefix_names(app: SdwanApp, profs: list[dict[str, Any]]) -> dict[str, str]:
    po = next((p for p in profs if p["type"] == "policy-object"), None)
    if not po:
        return {}
    try:
        return {r["id"]: str(r.get("name")) for r in await list_objects(app, po["id"], "data-prefix")}
    except UpstreamError:
        return {}


async def traffic_policies(app: SdwanApp, profile_id: str) -> list[dict[str, Any]]:
    """[{id, name, data, raw}] of an application-priority profile's traffic-policy parcels."""
    detail = await app.api.get(path(APP_PRIORITY_PROFILE_PATH, id=profile_id))
    out = []
    for p in parcels_of(detail):
        if p["type"] != "traffic-policy":
            continue
        body = await app.api.get(path(TRAFFIC_POLICY_PATH, id=profile_id, parcel=p["id"]))
        payload = (body or {}).get("payload") if isinstance(body, dict) else {}
        payload = payload if isinstance(payload, dict) else {}
        out.append(
            {
                "id": p["id"],
                "name": payload.get("name") or p.get("name"),
                "data": payload.get("data") if isinstance(payload.get("data"), dict) else {},
                "raw": body if isinstance(body, dict) else {},
            }
        )
    return out


async def steering_inventory(app: SdwanApp, vpn: int | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Per policy group, its traffic policies' service / service-chain sequences (filtered to a VPN)."""
    groups = await _groups(app, POLICY_GROUPS_PATH)
    details = list(await asyncio.gather(*(_group_detail(app, gr) for gr in groups)))
    out: list[dict[str, Any]] = []
    warnings: list[str] = []
    for gr in details:
        profs = group_profiles(gr)
        names = await _data_prefix_names(app, profs)
        for p in profs:
            if p["type"] != "application-priority":
                continue
            try:
                pols = await traffic_policies(app, p["id"])
            except UpstreamError as e:
                warnings.append(f"profile {p['name']}: traffic policies not read: {str(e)[:150]}")
                continue
            for tp in pols:
                tgt = target_of(tp["data"])
                if vpn is not None and tgt["vpns"] and str(vpn) not in tgt["vpns"]:
                    continue
                rows = steering_rows(tp["data"], names)
                if rows:
                    out.append(
                        {
                            "group": gr.get("name"),
                            "profile": p["name"],
                            "policy": tp["name"],
                            **tgt,
                            "sequences": rows,
                        }
                    )
    return out, warnings


def _verdict(
    vpn: int | None,
    services: list[dict[str, Any]],
    steering: list[dict[str, Any]],
    live: list[dict[str, Any]] | None,
    device: str | None,
) -> str:
    where = f"VPN {vpn}" if vpn is not None else "the service VPNs"
    if not services and not steering:
        return (
            f"No service chain in {where}: no edge is given a firewall service and no policy steers to one."
        )
    parts = []
    if services:
        parts.append(
            "; ".join(
                f"{s['type']} at {', '.join(map(str, s['addresses'])) or '?'} in VPN {s['vpn']} "
                f"({s['source']} {s['profile']}, groups {', '.join(s['groups']) or 'none'}, tracking "
                f"{'on' if s.get('tracking') else 'off'})"
                for s in services
            )
        )
    else:
        parts.append(f"no configuration group gives an edge a service in {where}")
    if steering:
        seqs = [
            f"{st['policy']} ({st['group']}) seq {q['name']}: {' '.join(q['match'])} -> "
            f"{q.get('service') or q.get('chain')}{' local' if q.get('local') else ''}"
            f"{' restrict' if q.get('restrict') else ''}"
            for st in steering
            for q in st["sequences"]
        ]
        parts.append("steered by " + "; ".join(seqs))
    else:
        parts.append(
            "no policy-group traffic policy steers to it (a centralised data policy may: catsdwan_get_policy)"
        )
    if live is not None and device:
        adv = sorted(
            {
                f"{r['service']} (VPN {r['vpn']}, from {r['originator']})"
                for r in live
                if r["service"] != "VPN"
            }
        )
        parts.append(
            f"{device} knows {', '.join(adv)} in OMP"
            if adv
            else f"{device} has no non-VPN service in OMP: the service is not advertised (not deployed, or "
            "tracking took it down)"
        )
    return ". ".join(parts) + "."


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN service chains")
    async def catsdwan_service_chains(
        ctx: Context,
        vpn: Annotated[
            int | None, Field(ge=1, le=65527, description="Service VPN, e.g. 10 (default all)")
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="An edge (host name or system IP): add the services it knows in OMP, read live"
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Service insertion per service VPN: which firewall (or IDS, IDP, netsvc, AppQoE) services the
        configuration groups give their edges (the service profile's LAN VPN parcel: type, the firewall's
        addresses, tracking; or `service firewall vrf <n>` lines in a CLI profile), the policy-group traffic
        policies that steer traffic into them (sequence, match, service or chain SC1-SC16, local, restrict
        and what happens when the service is down), the Manager's service-chain numbering, and with `device`
        the services that edge knows in OMP right now (a tracked firewall that stopped answering is
        withdrawn). `verdict` names the chain in one line. Change it with catsdwan_set_service_chain and
        catsdwan_set_service_steering; trace a flow through it with the prompt
        catsdwan_trace_through_firewall."""
        app: SdwanApp = get_client(ctx)
        warnings: list[str] = []
        cfg_groups = await _groups(app, CONFIG_GROUPS_PATH)
        (services, w1), (steering, w2) = await asyncio.gather(
            service_inventory(app, vpn, cfg_groups), steering_inventory(app, vpn)
        )
        warnings += w1 + w2
        out: dict[str, Any] = {"vpn": vpn, "services": services, "steering": steering}
        try:
            mapping = chain_mapping(await app.api.get(CHAIN_MAPPING_PATH))
            if mapping:
                out["chain_numbers"] = mapping
        except UpstreamError as e:
            warnings.append(f"service-chain mapping not read: {str(e)[:150]}")
        live: list[dict[str, Any]] | None = None
        name = None
        if device:
            row = resolve(await load_inventory(app), device)
            ip = require_reachable(row, "catsdwan_list_devices shows each device's reachability.")
            name = str(row.get("host") or ip)
            try:
                live = omp_service_rows(await device_rows(app, OMP_SERVICES_PATH, ip), vpn)
                out["omp_services"] = {
                    "device": name,
                    "services": [r for r in live if r["service"] != "VPN"],
                    "vpn_routes_advertised": sum(1 for r in live if r["service"] == "VPN"),
                }
            except UpstreamError as e:
                warnings.append(f"{name}: OMP services not read: {str(e)[:150]}")
        out["verdict"] = _verdict(vpn, services, steering, live, name)
        out["also"] = (
            "centralised (template-world) data policies with `set service`: catsdwan_get_policy; the path a "
            "flow takes: catsdwan_explain_path"
        )
        if warnings:
            out["warnings"] = warnings
        return {k: v for k, v in out.items() if v is not None}

    @reg.write(title="Set SD-WAN service chain (firewall service)", idempotent=True)
    async def catsdwan_set_service_chain(
        ctx: Context,
        profile: Annotated[
            str,
            Field(
                description="Service feature profile name or id, or a configuration group name "
                "(its service profile)"
            ),
        ],
        vpn: Annotated[int, Field(ge=1, le=65527, description="Service VPN, e.g. 10")],
        addresses: Annotated[
            list[str] | None,
            Field(
                description="The firewall's IPv4 address(es) facing the edge in that VPN, e.g. the FTD "
                "inside interface '10.61.110.2'"
            ),
        ] = None,
        service: Annotated[ServiceType, Field(description="Service type")] = "FW",
        tracking: Annotated[
            bool,
            Field(description="Track the service: withdraw it from OMP when the firewall stops answering"),
        ] = True,
        remove: Annotated[bool, Field(description="Remove this service from the VPN instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Give a service VPN a firewall (or other) service: the `service` entry of the VPN's LAN VPN
        parcel in a service feature profile (PUT /v1/feature-profile/sdwan/service/{id}/lan/vpn/{parcel}):
        the type, the firewall's address(es) and tracking. Once deployed the edge advertises the service
        into OMP so a traffic policy can steer to it (catsdwan_set_service_steering). Preview-first: the
        VPN's services before and after, the body checked against the Manager's LAN VPN schema, the
        configuration groups and devices the profile reaches. Other services and every other VPN setting
        are kept. A VPN configured by a CLI profile can't be changed here: the error gives the CLI lines for
        catsdwan_set_feature_parcel. Stores only: deploy with catsdwan_deploy_config_group."""
        app: SdwanApp = get_client(ctx)
        addrs = [a.strip() for a in addresses or [] if a and a.strip()]
        blockers: list[str] = []
        warnings: list[str] = []
        if (p := vpn_problem(vpn)) is not None:
            blockers.append(p)
        if not remove:
            blockers += address_problems(addrs)
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        svc_profiles = await _profiles_of(app, SERVICE_PROFILES_PATH)
        want = profile.strip().lower()
        prof = next(
            (p for p in svc_profiles if want in (p["id"].lower(), str(p.get("name") or "").lower())), None
        )
        if prof is None:
            grp = next(
                (
                    gr
                    for gr in groups
                    if want in (str(gr.get("id", "")).lower(), str(gr.get("name", "")).lower())
                ),
                None,
            )
            if grp is not None:
                gprofs = [p for p in _as_list(grp.get("profiles")) if isinstance(p, dict)]
                sp = [p for p in gprofs if p.get("type") == "service"]
                if sp:
                    prof = {"id": str(sp[0]["id"]), "name": sp[0].get("name")}
                else:
                    cli = next((p for p in gprofs if p.get("type") == "cli"), None)
                    hint = (
                        f"catsdwan_set_feature_parcel(profile='{cli.get('name')}', parcel='config', "
                        "cli_replace=...) with these lines: "
                        + " / ".join(cli_lines(service, vpn, addrs or ["<ip>"], tracking))
                        + " (they reach every device of the group: use a {{variable}} for the address, or a "
                        "group of its own)"
                        if cli
                        else "add a service profile with a LAN VPN parcel for this VPN first"
                    )
                    raise InvalidRequest(
                        f"Configuration group {grp.get('name')} has no service feature profile, so VPN "
                        f"{vpn} is not a LAN VPN parcel: {hint}."
                    )
            if prof is None:
                names = ", ".join(str(p.get("name")) for p in svc_profiles) or "none"
                raise NotFound(
                    f"No service feature profile or configuration group {profile!r} (service profiles: "
                    f"{names})."
                )

        parcels = vpn_parcels(await app.api.get(path(LAN_VPN_LIST_PATH, profile=prof["id"])))
        parcel = next((v for v in parcels if str(v["vpn"]) == str(vpn)), None)
        if parcel is None:
            have = ", ".join(f"{v['name']} (VPN {v['vpn']})" for v in parcels) or "none"
            raise InvalidRequest(
                f"{prof['name']} has no LAN VPN parcel for VPN {vpn} (its LAN VPNs: {have})."
            )
        before = service_rows(parcel["data"])
        current = next((s for s in before if s["type"] == service), None)
        if remove and current is None:
            blockers.append(f"VPN {vpn} in {prof['name']} has no {service} service to remove")
        entry = None if remove else service_entry(service, addrs, tracking)
        data = with_service(parcel["data"], service, entry)
        body = {"name": parcel["name"], "description": parcel.get("description") or "", "data": data}
        try:
            schema = request_schema(await app.api.get(LAN_VPN_SCHEMA_PATH, {"schemaType": "put"}))
        except UpstreamError as e:
            schema = {}
            warnings.append(f"not checked against the Manager's LAN VPN schema: {str(e)[:150]}")
        if schema:
            blockers += [f"LAN VPN parcel: {p}" for p in schema_problems(schema, body)]
        else:
            warnings.append("not checked: the Manager returned no LAN VPN schema")
        reached, read_warn = await _reach(app, groups, prof["id"])
        warnings += read_warn
        devices = sorted({d for r in reached for d in r["devices"]})
        after = service_rows(data)
        plan = Plan(
            f"{'Remove' if remove else 'Replace' if current else 'Add'} {service} service in VPN {vpn} of "
            f"{prof['name']}",
            details={
                "tier": "write",
                "profile": prof["name"],
                "parcel": parcel["name"],
                "vpn": vpn,
                "before": before,
                "after": after,
                "request": f"PUT {LAN_VPN_PATH}",
                "body": body,
                "reaches": reached,
                "undo": "the same call with the old addresses"
                if current
                else "the same call with remove=true",
                "next": "catsdwan_deploy_config_group(group, devices=[the edge]), then "
                "catsdwan_service_chains(vpn, device=<edge>) to see the service in OMP",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the parcel on the Manager only: the edges of the groups using the profile advertise "
                "the service after catsdwan_deploy_config_group. Nothing is steered until a traffic policy "
                "sends traffic to it."
            ],
            fingerprint={"parcel": parcel["raw"].get("lastUpdatedOn"), "services": before},
            blockers=blockers,
            blast_radius=len(devices),
        )

        async def apply() -> Any:
            await app.api.put(path(LAN_VPN_PATH, profile=prof["id"], parcel=parcel["id"]), body)
            return {
                "saved": f"VPN {vpn} in {prof['name']}",
                "services": after,
                "next": plan.details["next"],
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_service_chain",
            args={
                "profile": profile,
                "vpn": vpn,
                "addresses": addrs,
                "service": service,
                "tracking": tracking,
                "remove": remove,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @dangerous_tool(reg, title="Set SD-WAN service steering policy")
    async def catsdwan_set_service_steering(
        ctx: Context,
        group: Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")],
        name: Annotated[str, Field(description="Traffic policy name (created, or replaced when it exists)")],
        vpns: Annotated[
            list[int] | None, Field(description="Service VPNs the policy applies to, e.g. [10]")
        ] = None,
        rules: Annotated[
            list[SteeringRule] | None,
            Field(
                description="Sequences in order; the first match decides. Traffic matching none is routed "
                "normally"
            ),
        ] = None,
        direction: Annotated[
            Literal["service", "tunnel", "all"],
            Field(description="service: traffic from the LAN side; tunnel: from the overlay; all: both"),
        ] = "service",
        profile: Annotated[
            str | None,
            Field(
                description="Application-priority profile name: default the group's, or a new "
                "'<group>-app-priority' added to the group"
            ),
        ] = None,
        description: Annotated[str, Field(description="Description")] = "",
        remove: Annotated[bool, Field(description="Delete this traffic policy instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Steer traffic into a service chain: a traffic-policy parcel in a policy group's
        application-priority profile (POST / PUT .../application-priority/{id}/traffic-policy) whose
        sequences match source and destination prefixes (literal or data-prefix lists), protocols and ports
        and set `service FW` (or a chain SC1-SC16) with local and restrict. The group gets an
        application-priority profile when it has none (POST .../application-priority, PUT
        /v1/policy-group/{id}). Preview-first: the sequences in plain words, before and after, every list
        name resolved, a warning when no edge is given that service in the VPN (unrestricted traffic then
        routes around it, restricted traffic is dropped), the body checked against the Manager's schema when
        it gives one, the policy groups and devices reached. Stores only: deploy with
        catsdwan_deploy_policy_group (one edge first). Dangerous."""
        app: SdwanApp = get_client(ctx)
        rule_rows = [r.model_dump() for r in rules or []]
        vpn_list = list(dict.fromkeys(vpns or []))
        groups = await _groups(app, POLICY_GROUPS_PATH)
        found = resolve_group(groups, group, "policy group")
        detail = await _group_detail(app, found)
        gname = str(found.get("name"))
        profs = group_profiles(detail)
        blockers = dangerous_blockers(ctx, app, [TIER_REASON])
        warnings: list[str] = []

        # The application-priority profile: the group's, a named one, or a new one.
        in_group = [p for p in profs if p["type"] == "application-priority"]
        all_ap = [p for p in await policy_profiles(app) if p["type"] == "application-priority"]
        ap: dict[str, Any] | None = None
        attach = False
        new_profile: str | None = None
        if profile:
            ap = by_name(all_ap, profile)
            if ap is None:
                new_profile = profile.strip()
            elif all(p["id"] != ap["id"] for p in in_group):
                attach = True
            if in_group and (new_profile or attach):
                blockers.append(
                    f"{gname} already has application-priority profile {in_group[0]['name']} (one per "
                    "group): leave `profile` out to use it"
                )
        elif in_group:
            ap = in_group[0]
        else:
            new_profile = f"{gname}-app-priority"
        if remove and ap is None:
            blockers.append(f"{gname} has no application-priority profile with a traffic policy to remove")

        existing: dict[str, Any] | None = None
        if ap:
            try:
                existing = by_name(await traffic_policies(app, ap["id"]), name)
            except UpstreamError as e:
                blockers.append(f"profile {ap['name']} was not read: {str(e)[:200]}")
        if remove and ap and not existing:
            blockers.append(f"no traffic policy named {name} in {ap['name']}")

        # Data-prefix list names -> ids.
        refs: dict[str, str] = {}
        id_names = await _data_prefix_names(app, profs)
        wanted = sorted({n for r in rule_rows for n in (r["source_lists"] + r["destination_lists"])})
        if wanted:
            po = next((p for p in profs if p["type"] == "policy-object"), None)
            if po is None:
                blockers.append(
                    f"{gname} has no policy-object profile: its rules can't use data-prefix lists"
                )
            else:
                rows = await list_objects(app, po["id"], "data-prefix")
                for n in wanted:
                    hit = by_name(rows, n)
                    if hit:
                        refs[n] = hit["id"]
                    else:
                        known = ", ".join(sorted(str(r.get("name")) for r in rows)[:15]) or "none"
                        blockers.append(f"no data-prefix list named {n!r} in {po['name']} (known: {known})")

        body: dict[str, Any] | None = None
        if not remove:
            if not vpn_list:
                blockers.append("give the service VPNs the policy applies to (`vpns`)")
            blockers += [p for v in vpn_list if (p := vpn_problem(v))]
            if not rule_rows:
                blockers.append("give at least one rule: a steering policy without one steers nothing")
            seen: set[str] = set()
            for r in rule_rows:
                if r["name"] in seen:
                    blockers.append(f"rule name {r['name']} is used twice")
                seen.add(r["name"])
                for f in ("source_prefixes", "destination_prefixes"):
                    blockers += [f"rule {r['name']}: {p}" for p in literal_prefix_problems(r[f])]
                if r.get("chain") and r["chain"] not in CHAINS:
                    blockers.append(f"rule {r['name']}: chain {r['chain']!r} is not SC1-SC16")
                if r.get("service_vpn") is not None and (p := vpn_problem(int(r["service_vpn"]))):
                    blockers.append(f"rule {r['name']}: {p}")
                if (
                    r.get("service_vpn") is None
                    and len(vpn_list) > 1
                    and not (r.get("chain") and r.get("local"))
                ):
                    blockers.append(
                        f"rule {r['name']}: give service_vpn (the VPN the service is in): the policy targets "
                        "several VPNs and the Manager needs the service's VPN"
                    )
                if not any(
                    r[f]
                    for f in ("source_prefixes", "destination_prefixes", "source_lists", "destination_lists")
                ):
                    warnings.append(f"rule {r['name']} matches on no prefix: every flow of the VPN takes it")
            if direction not in DIRECTIONS:
                blockers.append(f"direction {direction!r}")
            if not [b for b in blockers if "not read" in b] and all(n in refs for n in wanted):
                body = traffic_policy_body(
                    name.strip(), description, vpn_list, direction, "accept", rule_rows, refs
                )
                try:
                    schema = request_schema(
                        await app.api.get(TRAFFIC_POLICY_SCHEMA_PATH, {"schemaType": "post"})
                    )
                except UpstreamError as e:
                    schema = {}
                    warnings.append(
                        "traffic policy not checked against the Manager's schema (not read: "
                        f"{str(e)[:120]}); the Manager validates it on confirm"
                    )
                blockers += [f"traffic policy: {p}" for p in schema_problems(schema, body)]
            # Is the service there to steer to?
            cfg_groups = await _groups(app, CONFIG_GROUPS_PATH)
            for v in vpn_list:
                svcs, _ = await service_inventory(app, v, cfg_groups)
                types = {str(s["type"]) for s in svcs}
                for r in rule_rows:
                    if r.get("chain"):
                        continue
                    svc_vpn = r.get("service_vpn") or v
                    if svc_vpn == v and r["service"] not in types:
                        warnings.append(
                            f"rule {r['name']}: no configuration group gives an edge a {r['service']} "
                            f"service in VPN {v} (catsdwan_set_service_chain): "
                            + (
                                "restricted traffic is dropped"
                                if r["restrict"]
                                else "the traffic routes around it"
                            )
                        )

        before = None
        if existing:
            before = {**target_of(existing["data"]), "sequences": steering_rows(existing["data"], id_names)}
        after = None
        if body:
            names_after = {**id_names, **{v: k for k, v in refs.items()}}
            after = {**target_of(body["data"]), "sequences": steering_rows(body["data"], names_after)}
        requests: list[str] = []
        if new_profile and not remove:
            requests += [
                f"POST {APP_PRIORITY_PATH} {{name: {new_profile}}}",
                "PUT /dataservice/v1/policy-group/{id}",
            ]
        elif attach and not remove:
            requests.append(
                f"PUT /dataservice/v1/policy-group/{{id}} (add profile {ap['name'] if ap else '?'})"
            )
        if remove:
            requests.append(f"DELETE {TRAFFIC_POLICY_PATH}")
        else:
            requests.append(f"PUT {TRAFFIC_POLICY_PATH}" if existing else f"POST {TRAFFIC_POLICY_LIST_PATH}")
        details_groups = list(await asyncio.gather(*(_group_detail(app, gr) for gr in groups)))
        reached, read_warn = await reach(app, details_groups, ap["id"] if ap else None, detail)
        warnings += read_warn
        devices = sorted({d for r in reached for d in r["devices"]})
        plan = Plan(
            ("Delete" if remove else "Replace" if existing else "Create")
            + f" traffic policy {name} (service steering) in policy group {gname}",
            details={
                "tier": "dangerous",
                "group": gname,
                "profile": (ap or {}).get("name") or f"{new_profile} (new)",
                "before": before,
                "after": after,
                "requests": requests,
                **({"body": body} if body else {}),
                "reaches": reached,
                "undo": "remove=true" if not existing else "the same call with the old sequences",
                "next": "catsdwan_deploy_policy_group(group, devices=[one edge]), then "
                "catsdwan_service_chains(vpn, device=<edge>) and the prompt catsdwan_trace_through_firewall",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Stores the policy on the Manager only: the group's edges steer with it after "
                "catsdwan_deploy_policy_group. Steered traffic then meets the firewall's access policy "
                "(fmc_packet_tracer shows the verdict), so deploy to one edge first."
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "policy": existing["raw"].get("lastUpdatedOn") if existing else None,
                "refs": refs,
            },
            blockers=blockers,
            blast_radius=len(devices),
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            if remove and ap and existing:
                await app.api.delete(path(TRAFFIC_POLICY_PATH, id=ap["id"], parcel=existing["id"]))
                return {"deleted": name, "profile": ap["name"]}
            ap_id = ap["id"] if ap else None
            if new_profile:
                ap_id = created_id(
                    await app.api.post(
                        APP_PRIORITY_PATH, {"name": new_profile, "description": f"{gname} service steering"}
                    )
                )
                if not ap_id:
                    raise UpstreamError("The Manager created the application-priority profile without an id.")
                done["profile_created"] = new_profile
            if new_profile or attach:
                ids = [p["id"] for p in profs] + [str(ap_id)]
                await app.api.put(f"{POLICY_GROUPS_PATH}/{found.get('id')}", update_body(detail, ids))
                done["profile_added_to_group"] = gname
            if existing:
                await app.api.put(path(TRAFFIC_POLICY_PATH, id=str(ap_id), parcel=existing["id"]), body)
                pid: str | None = existing["id"]
            else:
                pid = created_id(await app.api.post(path(TRAFFIC_POLICY_LIST_PATH, id=str(ap_id)), body))
            done.update(saved=name, id=pid, sequences=after["sequences"] if after else [])
            done["next"] = plan.details["next"]
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_service_steering",
            args={
                "group": group,
                "name": name,
                "vpns": vpn_list,
                "rules": rule_rows,
                "direction": direction,
                "profile": profile,
                "description": description,
                "remove": remove,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.prompt(
        title="Trace a flow through the SD-WAN service chain and the firewall",
        uses=["catsdwan", "fmc"],
        example={"source": "10.61.220.10", "destination": "10.61.100.10", "app": "tcp/22", "vpn": "10"},
    )
    def catsdwan_trace_through_firewall(
        source: Annotated[str, Field(description="Source host IP, e.g. '10.61.220.10'")],
        destination: Annotated[str, Field(description="Destination host IP, e.g. '10.61.100.10'")],
        app: Annotated[
            str,
            Field(description="Protocol/port or application, e.g. 'tcp/22', 'icmp', 'webex' (blank = icmp)"),
        ] = "",
        vpn: Annotated[str, Field(description="Service VPN of the hosts (blank = find it)")] = "10",
    ) -> str:
        """Which firewall does this flow cross, and what does it decide? Source host -> its edge -> the
        SD-WAN path (catsdwan_explain_path) -> the service-chain hop (the FW service and the steering rule
        that matches, or none) -> fmc_packet_tracer on the hub FTD (chained) or the branch FTD (inline) ->
        verdict: allowed / blocked by <rule> on <FTD>, or not chained."""
        what = app.strip() or "icmp"
        vpn_arg = f', vpn="{vpn.strip()}"' if vpn.strip() else ""
        vpn_num = f", vpn={vpn.strip()}" if vpn.strip().isdigit() else ""
        chain_args = f"vpn={vpn.strip()}, " if vpn.strip().isdigit() else ""
        return f"""Trace {what} from {source} to {destination} through the SD-WAN service chain and the
firewall(s) it crosses, and give the firewall's verdict with the rule that decides. Read-only: change
nothing; suggest fixes, don't apply them.

1. Where are the hosts? {tool_ref("catsdwan_find_host")} with host="{source}"{vpn_arg}, then
   host="{destination}"{vpn_arg}: each one's edge, site, VPN and interface. A host behind a branch
   firewall (an FTD between the edge's LAN interface and the hosts, e.g. alice/bob behind br1-ftd) is
   found by the route the edge has to its subnet: note that FTD as the branch firewall.
2. The SD-WAN path: {tool_ref("catsdwan_explain_path")} with source_site=<the source edge's site>,
   destination="{destination}"{vpn_num}, app or dscp when {what} names one: the data-policy sequences that
   may override the path, the tunnels the flow takes, and the edge that delivers it.
3. The chain hop: {tool_ref("catsdwan_service_chains")} with {chain_args}device=<the source edge>:
   the FW service (type, the firewall's address, tracking, the edge that advertises it) and the
   steering sequence that matches {source} -> {destination} (local, restrict).
   Then device=<the hub edge> to see the service in OMP. A centralised data policy may steer instead:
   {tool_ref("catsdwan_get_policy")}. No sequence matches: the flow is NOT chained (say so, and still
   trace the branch firewall if there is one).
4. Map the service address to an FTD (FMC, {OPTIONAL}): {tool_ref("fmc_find_address")} or
   {tool_ref("fmc_list_devices")} then {tool_ref("fmc_list_device_interfaces")}: which FTD owns the
   service address (e.g. hub-ftd inside 10.61.110.2), its ingress interface for the chained traffic, and
   its egress back to the edge.
5. The firewall's verdict (FMC, {OPTIONAL}): {tool_ref("fmc_packet_tracer")} on that FTD with the ingress
   interface from step 4, source {source}, destination {destination} and {what}: the verdict, the drop
   reason and the access rule that decides. For a branch firewall, trace there too (ingress = its inside
   interface). Cross-check offline with {tool_ref("fmc_rule_lookup")} and whether the rule is hit with
   {tool_ref("fmc_get_hit_counts")}; is the FTD itself healthy: {tool_ref("fmc_device_health")}.

Verdict, ONE line first, one of:
- allowed by <rule> on <FTD>: chained at <edge> by <traffic policy / sequence> (and through <branch FTD>
  when there is one);
- blocked by <rule> on <FTD>: the drop reason, and which firewall (hub chain or branch);
- not chained: no steering sequence matches (the flow goes <path> without a firewall), or the service is
  not advertised (tracking withdrew it: restrict drops the flow, otherwise it routes around the firewall);
- chain broken: the service address is on no FTD interface, or the FTD's interface is down.
Then the evidence per step (path, chain, FTD, rule) and the next action (which rule, which sequence)."""
