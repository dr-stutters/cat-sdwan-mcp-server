"""W55 (#77): catsdwan_export_site, a site as a twin spec (read tier)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from cat_sdwan_mcp.changes import TEMPLATE_INPUT_PATH
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    CONFIG_GROUP_PATH,
    CONFIG_GROUPS_PATH,
    DEVICE_TEMPLATES_PATH,
    INTENDED_PATH,
    POLICY_GROUPS_PATH,
    VARIABLES_PATH,
    associated,
    device_template_row,
    group_row,
    mask_config,
    path,
)
from cat_sdwan_mcp.control import OMP_TLOCS_PATH, tloc_row
from cat_sdwan_mcp.fabric import device_rows, host_map, reachable
from cat_sdwan_mcp.features import PARCEL_PATH, POLICY_ASSOCIATE_PATH, parcel_view
from cat_sdwan_mcp.inventory import Inventory, load_inventory, matches_site
from cat_sdwan_mcp.policy import VSMART_PATH, is_active, rows
from cat_sdwan_mcp.sitexport import (
    CLI_ADDON_NOTE,
    KIND,
    SPEC_VERSION,
    TWIN_NOTES,
    Secrets,
    colours,
    group_variables,
    missing_from,
    parse_intended,
    policy_view,
    refs_for_masked,
    render_cli,
    scrub,
    service_vpns,
    spec_mode,
    template_variables,
    tloc_view,
    variables_with_refs,
)
from cat_sdwan_mcp.tools.configuration import _groups, _read_profiles
from cat_sdwan_mcp.tools.policy import _centralised_parts, _definitions, _lists

MAX_GROUPS = 25  # policy groups whose devices are read to find the site's
# A CLI add-on parcel as the export carries it: {profile, parcel, cli (masked, {{variables}} kept)}.
Addon = dict[str, str]


def _site_edges(inv: Inventory, site: str) -> list[dict[str, Any]]:
    return [
        r
        for r in [*inv.rows, *inv.unjoined]
        if (r.get("role") or "edge") == "edge" and r.get("site_id") and matches_site(r, site)
    ]


def _device_head(r: dict[str, Any]) -> dict[str, Any]:
    keys = ("host", "system_ip", "chassis", "model", "version", "reachability", "config_mode", "config")
    out = {k: r[k] for k in keys if r.get(k) not in (None, "")}
    if out.get("config_mode") == "configuration group":
        out["config_group"] = out.pop("config", None)
    elif out.get("config_mode") == "template":
        out["device_template"] = out.pop("config", None)
    return {k: v for k, v in out.items() if v is not None}


async def _config_group_part(
    app: SdwanApp,
    name: str,
    devices: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    secrets: Secrets,
    warnings: list[str],
) -> tuple[dict[str, Any], list[Addon]]:
    """The group with its profiles (secret values as refs) and the CLI add-on parcels' text, and each
    device's variables set in place."""
    found = next((g for g in groups if str(g.get("name")) == name), None)
    if found is None:
        warnings.append(f"configuration group {name!r} is not in GET {CONFIG_GROUPS_PATH}")
        return {"name": name}, []
    gid = str(found.get("id"))
    detail = await app.api.get(path(CONFIG_GROUP_PATH, id=gid))
    record = detail if isinstance(detail, dict) and detail.get("id") else found
    head = group_row(record)
    out: dict[str, Any] = {
        k: head[k] for k in ("name", "id", "solution", "description", "version", "deploy_state") if k in head
    }
    profiles = [p for p in _as_list(record.get("profiles")) if isinstance(p, dict)]
    read = await _read_profiles(app, profiles) if profiles else []
    addons = await _cli_addons(app, name, read, warnings)
    out["feature_profiles"] = [
        refs_for_masked(p, f"config-group/{name}/{p.get('name')}", f"configuration group {name}", secrets)
        for p in read
    ]
    chassis = [str(d["chassis"]) for d in devices if d.get("chassis")]
    if chassis:
        try:
            body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": ",".join(chassis)})
            values = group_variables(body)
        except UpstreamError as e:
            warnings.append(f"configuration group {name}: device variables not read: {str(e)[:200]}")
            values = {}
        for d in devices:
            if (v := values.get(str(d.get("chassis")))) is not None:
                host = str(d.get("host") or d.get("chassis"))
                d["variables"] = variables_with_refs(v, host, f"variables of {host}", secrets)
    return out, addons


async def _cli_addons(
    app: SdwanApp, group: str, profiles: list[dict[str, Any]], warnings: list[str]
) -> list[Addon]:
    """Each CLI profile parcel's text (#166): the profile read leaves the parcel's data out on 20.18, so
    each parcel is read on its own. The masked text goes on the parcel (`cli`) in place."""
    todo = [
        (p, parcel)
        for p in profiles
        if p.get("type") == "cli" and p.get("id")
        for parcel in _as_list(p.get("parcels"))
        if isinstance(parcel, dict) and parcel.get("id") and parcel.get("type")
    ]

    async def one(p: dict[str, Any], parcel: dict[str, Any]) -> Any:
        return await app.api.get(
            path(
                PARCEL_PATH,
                type="cli",
                profile=str(p["id"]),
                parcel_type=str(parcel["type"]),
                parcel=str(parcel["id"]),
            )
        )

    got = await asyncio.gather(*(one(p, x) for p, x in todo), return_exceptions=True)
    out: list[Addon] = []
    for (p, parcel), res in zip(todo, got, strict=True):
        where = f"configuration group {group}: CLI parcel {p.get('name')}/{parcel.get('name')}"
        values: dict[str, Any] = parcel["values"] if isinstance(parcel.get("values"), dict) else {}
        raw = values.pop("config", None)  # never the profile read's unmasked text
        if not values:
            parcel.pop("values", None)
        if isinstance(res, UpstreamError):
            warnings.append(f"{where}: not read: {str(res)[:200]}")
            res = {"payload": {"data": {"config": raw}}} if isinstance(raw, str) else None
        elif isinstance(res, BaseException):
            raise res
        cli = parcel_view(res).get("cli") if res is not None else None
        if not isinstance(cli, str) or not cli.strip():
            continue
        parcel["cli"] = cli
        out.append({"profile": str(p.get("name")), "parcel": str(parcel.get("name")), "cli": cli})
    return out


async def _template_part(
    app: SdwanApp,
    name: str,
    devices: list[dict[str, Any]],
    templates: list[dict[str, Any]],
    secrets: Secrets,
    warnings: list[str],
) -> dict[str, Any]:
    found = next((t for t in templates if str(t.get("templateName")) == name), None)
    if found is None:
        warnings.append(f"device template {name!r} is not in GET {DEVICE_TEMPLATES_PATH}")
        return {"name": name}
    head = device_template_row(found)
    out: dict[str, Any] = {
        k: head[k] for k in ("name", "id", "kind", "device_type", "description") if k in head
    }
    chassis = [str(d["chassis"]) for d in devices if d.get("chassis")]
    try:
        body = await app.api.post(
            TEMPLATE_INPUT_PATH,
            {"templateId": head.get("id"), "deviceIds": chassis, "isEdited": False, "isMasterEdited": False},
        )
        values = template_variables(body)
    except UpstreamError as e:
        warnings.append(f"device template {name}: device variables not read: {str(e)[:200]}")
        values = {}
    for d in devices:
        if (v := values.get(str(d.get("chassis")))) is not None:
            host = str(d.get("host") or d.get("chassis"))
            d["variables"] = variables_with_refs(v, host, f"variables of {host}", secrets)
    return out


async def _intended(
    app: SdwanApp,
    devices: list[dict[str, Any]],
    include_config: bool,
    warnings: list[str],
    addons: dict[str, list[Addon]],
) -> None:
    async def one(d: dict[str, Any]) -> Any:
        return await app.api.get(path(INTENDED_PATH, id=str(d["chassis"])))

    todo = [d for d in devices if d.get("chassis")]
    got = await asyncio.gather(*(one(d) for d in todo), return_exceptions=True)
    for d, res in zip(todo, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"{d.get('host')}: intended configuration not read: {str(res)[:200]}")
            continue
        if isinstance(res, BaseException):
            raise res
        mine = addons.get(str(d.get("config_group")), [])
        rendered = [render_cli(a["cli"], d.get("variables") or {}) for a in mine]
        text = res.get("config") if isinstance(res, dict) else res
        if not isinstance(text, str) or not text.strip():
            warnings.append(f"{d.get('host')}: the Manager holds no intended configuration")
            if rendered:
                d.update(parse_intended("", *rendered))
            continue
        d.update(parse_intended(text, *rendered))
        if include_config:
            d["intended_config"] = mask_config(text)[0]
        masked = mask_config(text)[0]
        missing = [m for r in rendered for m in missing_from(r, masked)]
        if missing:
            d["cli_addon_not_in_intended"] = len(missing)
            names = ", ".join(sorted({a["profile"] for a in mine}))
            warnings.append(
                f"{d.get('host')}: {len(missing)} line(s) of the CLI add-on ({names}) are not in the "
                f"Manager's intended configuration (e.g. {'; '.join(missing[:3])}); transports and service "
                "VPNs include them, and config_groups[].feature_profiles[].parcels[].cli holds the text"
            )


async def _policy_groups(app: SdwanApp, chassis: set[str], warnings: list[str]) -> list[dict[str, Any]]:
    try:
        groups = await _groups(app, POLICY_GROUPS_PATH)
    except UpstreamError as e:
        warnings.append(f"policy groups not read: {str(e)[:200]}")
        return []
    todo = [g for g in groups if g.get("id") and g.get("numberOfDevices") != 0][:MAX_GROUPS]
    if len(groups) > MAX_GROUPS:
        warnings.append(f"devices read for the first {MAX_GROUPS} policy groups only")
    got = await asyncio.gather(
        *(app.api.get(path(POLICY_ASSOCIATE_PATH, id=str(g["id"]))) for g in todo), return_exceptions=True
    )
    out = []
    for g, res in zip(todo, got, strict=True):
        if isinstance(res, UpstreamError):
            warnings.append(f"policy group {g.get('name')}: devices not read: {str(res)[:150]}")
            continue
        if isinstance(res, BaseException):
            raise res
        mine = [d for d in associated(res) if str(d.get("chassis")) in chassis]
        if mine:
            head: dict[str, Any] = group_row(g)
            row: dict[str, Any] = {
                k: head[k] for k in ("name", "id", "solution", "deploy_state") if k in head
            }
            row["profiles"] = [
                {"name": p.get("name"), "type": p.get("type"), "id": p.get("id")}
                for p in _as_list(g.get("profiles"))
                if isinstance(p, dict)
            ]
            row["devices"] = sorted(str(d.get("host") or d.get("chassis")) for d in mine)
            out.append(row)
    return out


async def _centralised(app: SdwanApp, site: str, warnings: list[str]) -> dict[str, Any] | None:
    try:
        active = [p for p in rows(await app.api.get(VSMART_PATH)) if is_active(p)]
    except UpstreamError as e:
        warnings.append(f"centralised policies not read: {str(e)[:200]}")
        return None
    if not active:
        return None
    policy = active[0]
    _, parts = await _centralised_parts(app, policy)
    (defs, w1), (lists, w2) = await asyncio.gather(_definitions(app, parts), _lists(app))
    warnings += w1 + w2
    return policy_view(policy, parts, site, defs, lists)


async def _tlocs(app: SdwanApp, inv: Inventory, devices: list[dict[str, Any]], warnings: list[str]) -> None:
    controllers = reachable(inv, "controller")
    if not controllers:
        warnings.append("no reachable controller: live TLOCs not read")
        return
    try:
        got = await device_rows(app, OMP_TLOCS_PATH, str(controllers[0]["system_ip"]))
    except UpstreamError as e:
        warnings.append(f"live TLOCs not read: {str(e)[:200]}")
        return
    hosts = host_map(inv)
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for t in got:
        row = tloc_row(t, hosts)
        if row.get("system_ip"):
            mine = by_ip.setdefault(str(row["system_ip"]), [])
            view = tloc_view(row)
            if view not in mine:  # one copy per TLOC, whichever controller peer it came from
                mine.append(view)
    for d in devices:
        if (got_tlocs := by_ip.get(str(d.get("system_ip")))) is not None:
            d["tlocs"] = sorted(got_tlocs, key=lambda r: (str(r.get("colour")), str(r.get("encap"))))


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export an SD-WAN site as a twin spec")
    async def catsdwan_export_site(
        ctx: Context,
        site: Annotated[str, Field(description="Site id (e.g. '200') or site name (e.g. 'SITE_200')")],
        live_tlocs: Annotated[
            bool, Field(description="Add the TLOCs a controller holds for the site's edges (live read)")
        ] = True,
        include_config: Annotated[
            bool,
            Field(description="Add each edge's intended configuration text (secrets masked)"),
        ] = False,
    ) -> ToolResult:
        """One site as a versioned twin spec (kind cat-sdwan-twin-site, spec_version 1; schema in
        docs/twin-spec.md) for the cml recipe cat-sdwan-twin: the site's WAN edges (host, system IP, chassis,
        model, version, configuration mode), the configuration group with its feature profiles or the device
        template, each edge's variables, the policy groups and the parts of the activated centralised policy
        that touch the site, each edge's transports (tunnel interface, colour, restrict, encapsulation,
        address) and service VPNs from its intended configuration plus the group's CLI add-on (whose text is
        exported on the CLI profile's parcels, {{variables}} kept), and the TLOCs the controllers hold.
        Secret values are never exported: each becomes {"secret_ref": ...}, listed under `secrets`.
        Certificates, the serial file and one-time tokens are left out. Changes nothing."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        edges = _site_edges(inv, site)
        if not edges:
            known = sorted(
                {str(r["site_id"]) for r in inv.rows if r.get("role") == "edge" and r.get("site_id")}
            )
            raise NotFound(f"No WAN edge at site {site!r}. Sites with edges: {', '.join(known) or 'none'}.")
        site_id = str(edges[0]["site_id"])
        site_name = next((str(r["site_name"]) for r in edges if r.get("site_name")), None)
        warnings: list[str] = list(inv.warnings)
        secrets = Secrets()
        edges.sort(key=lambda r: str(r.get("host") or r.get("chassis")))
        devices = [_device_head(r) for r in edges]

        groups_used = sorted({str(d["config_group"]) for d in devices if d.get("config_group")})
        templates_used = sorted({str(d["device_template"]) for d in devices if d.get("device_template")})
        config_groups: list[dict[str, Any]] = []
        device_templates: list[dict[str, Any]] = []
        addons: dict[str, list[Addon]] = {}
        if groups_used:
            all_groups = await _groups(app, CONFIG_GROUPS_PATH)
            for name in groups_used:
                mine = [d for d in devices if d.get("config_group") == name]
                part, addons[name] = await _config_group_part(app, name, mine, all_groups, secrets, warnings)
                config_groups.append(part)
        if templates_used:
            body = await app.api.get(DEVICE_TEMPLATES_PATH, {"feature": "all"})
            templates = [t for t in rows(body)]
            for name in templates_used:
                mine = [d for d in devices if d.get("device_template") == name]
                device_templates.append(await _template_part(app, name, mine, templates, secrets, warnings))
        if any(d.get("config_mode") == "cli" for d in devices):
            warnings.append(
                "an edge is in CLI mode: no configuration group or template to rebuild it from; its intended "
                "configuration (include_config=true) is the only source"
            )

        chassis = {str(d["chassis"]) for d in devices if d.get("chassis")}
        await _intended(app, devices, include_config, warnings, addons)
        policy_groups = await _policy_groups(app, chassis, warnings)
        centralised = await _centralised(app, site_id, warnings)
        if live_tlocs:
            await _tlocs(app, inv, devices, warnings)

        spec: dict[str, Any] = {
            "kind": KIND,
            "spec_version": SPEC_VERSION,
            "exported_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "source": {"manager_release": await app.version(), "tool": "catsdwan_export_site"},
            "site": {k: v for k, v in {"id": site_id, "name": site_name}.items() if v},
            "mode": spec_mode(devices),
            "devices": devices,
            "config_groups": config_groups,
            "device_templates": device_templates,
            "policy_groups": policy_groups,
            "centralised_policy": centralised,
            "colours": colours(devices),
            "service_vpns": service_vpns(devices),
            "secrets": secrets.listed(),
            "twin_notes": [*TWIN_NOTES, CLI_ADDON_NOTE] if any(addons.values()) else TWIN_NOTES,
        }
        if warnings:
            spec["warnings"] = warnings
        # Unshaped: the core's mask-by-key pass would mask the secret refs too; scrub() is the safety net.
        return object_result(scrub(spec), fmt="json", shape=False)
