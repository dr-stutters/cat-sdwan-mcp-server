"""W7 configuration reads: catsdwan_list_config_groups, catsdwan_get_config_group,
catsdwan_list_policy_groups, catsdwan_list_templates, catsdwan_get_device_config."""

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
from cat_sdwan_mcp._core.http.paging import Page
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    ASSOCIATE_PATH,
    CONFIG_GROUP_PATH,
    CONFIG_GROUPS_PATH,
    DEVICE_TEMPLATES_PATH,
    FEATURE_TEMPLATES_PATH,
    INTENDED_PATH,
    POLICY_GROUPS_PATH,
    PROFILE_PATH,
    PROFILE_TYPES,
    RUNNING_PATH,
    TEMPLATE_DEVICES_PATH,
    VARIABLES_PATH,
    associated,
    config_diff,
    device_template_row,
    feature_template_row,
    group_row,
    mask_config,
    path,
    profile_detail,
    resolve_group,
    sections,
    template_devices,
    variables_by_device,
)
from cat_sdwan_mcp.inventory import load_inventory, resolve

GROUP_COLUMNS = ["name", "solution", "profiles", "devices", "up_to_date", "deploy_state", "device_names"]
DEVICE_TEMPLATE_COLUMNS = [
    "name",
    "kind",
    "device_type",
    "devices_attached",
    "attached_to",
    "last_updated_by",
]
FEATURE_TEMPLATE_COLUMNS = ["name", "type", "device_types", "devices_attached", "device_templates"]
MAX_LOOKUPS = 25  # per-group / per-template follow-up reads in one list call

MODE_NOTE = {
    "configuration group": "configured by a configuration group: the next deploy of the group overwrites "
    "changes made on the device",
    "template": "attached to a device template: the next template push overwrites changes made on the device",
    "cli": "CLI mode: no configuration group or device template; the device is configured directly",
}


async def _groups(app: SdwanApp, base: str) -> list[dict[str, Any]]:
    body = await app.api.get(base)
    rows = body.get("data") if isinstance(body, dict) else body
    return [g for g in _as_list(rows) if isinstance(g, dict)]


async def _associated(app: SdwanApp, group_id: str) -> list[dict[str, Any]]:
    return associated(await app.api.get(path(ASSOCIATE_PATH, id=group_id)))


def _mode(row: dict[str, Any]) -> dict[str, Any]:
    mode = row.get("config_mode")
    out: dict[str, Any] = {"config_mode": mode}
    if row.get("config"):
        out["config_name"] = row["config"]
    if row.get("config_status"):
        out["config_status"] = row["config_status"]
    if note := MODE_NOTE.get(str(mode)):
        out["mode_note"] = note
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN configuration groups")
    async def catsdwan_list_config_groups(
        ctx: Context,
        name: Annotated[str | None, Field(description="Group name contains (case-insensitive)")] = None,
        devices: Annotated[
            bool, Field(description="Name each group's associated devices (one extra read per group)")
        ] = True,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Configuration groups (IOS XE WAN edges, 20.12+): name, solution, feature profiles, how many devices
        are associated and how many are up to date with the group, the deploy state (never deployed, partly,
        up to date), last change and who made it, and the associated devices by host name. A device is in a
        configuration group or on a device template, never both: catsdwan_list_templates for the template
        side, catsdwan_get_config_group for one group's profiles, values and per-device variables."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, CONFIG_GROUPS_PATH)
        if name:
            groups = [g for g in groups if name.lower() in str(g.get("name", "")).lower()]
        page = groups[offset : offset + limit]
        rows = [group_row(g) for g in page]
        extra: dict[str, Any] = {}
        if devices and page:
            lookup = [g for g in page[:MAX_LOOKUPS] if g.get("id") and g.get("numberOfDevices") != 0]
            got = await asyncio.gather(
                *(_associated(app, str(g["id"])) for g in lookup), return_exceptions=True
            )
            by_id = dict(zip((str(g["id"]) for g in lookup), got, strict=True))
            for row in rows:
                res = by_id.get(str(row.get("id")))
                if isinstance(res, list):
                    row["device_names"] = ", ".join(str(d.get("host") or d.get("chassis")) for d in res)
                elif isinstance(res, UpstreamError):
                    extra.setdefault("warnings", []).append(f"{row.get('name')}: devices not read: {res}")
                elif isinstance(res, BaseException):
                    raise res
            if len(page) > MAX_LOOKUPS:
                extra["note"] = f"devices named for the first {MAX_LOOKUPS} groups of this page"
        if not groups:
            extra["note"] = "No configuration groups on this Manager (devices use templates or CLI)."
        return list_result(
            _paged(rows, len(groups), offset),
            fmt=response_format,
            columns=GROUP_COLUMNS,
            extra=extra or None,
        )

    @reg.read(title="Get SD-WAN configuration group")
    async def catsdwan_get_config_group(
        ctx: Context,
        group: Annotated[str, Field(description="Configuration group name or id")],
        variables: Annotated[bool, Field(description="Read each associated device's variable values")] = True,
        profiles: Annotated[
            bool, Field(description="Read each feature profile with its parcels and values")
        ] = True,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """One configuration group: its record and deploy state, each feature profile (system, transport,
        service, cli, ...) with its parcels and their values (variables shown as {{name}}, defaults left out,
        secrets masked), the associated devices (host, chassis, system IP, site, in sync, up to date with
        the group, deployable) and each device's variable values. Accepts the name ('did you mean') or id."""
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, CONFIG_GROUPS_PATH), group)
        gid = str(found.get("id"))
        detail = await app.api.get(path(CONFIG_GROUP_PATH, id=gid))
        record = detail if isinstance(detail, dict) and detail.get("id") else found
        out: dict[str, Any] = {**group_row(record), "config_mode": "configuration group"}
        warnings: list[str] = []
        devs: list[dict[str, Any]] = []
        try:
            devs = await _associated(app, gid)
        except UpstreamError as e:
            warnings.append(f"associated devices not read: {e}")
        prof_list = [p for p in _as_list(record.get("profiles")) if isinstance(p, dict)]
        if profiles:
            out["feature_profiles"] = await _read_profiles(app, prof_list) if prof_list else []
            if not prof_list:
                out["feature_profiles_note"] = "the group has no feature profiles yet"
        else:
            out["feature_profiles"] = [{"name": p.get("name"), "type": p.get("type")} for p in prof_list]
        if variables and devs:
            ids = [str(d["chassis"]) for d in devs if d.get("chassis")]
            try:
                body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": ",".join(ids)})
                values = variables_by_device(body)
                for d in devs:
                    if (v := values.get(str(d.get("chassis")))) is not None:
                        d["variables"] = v
            except UpstreamError as e:
                warnings.append(f"device variables not read: {e}")
        out["associated_devices"] = devs
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt=response_format)

    @reg.read(title="List SD-WAN policy groups")
    async def catsdwan_list_policy_groups(
        ctx: Context,
        name: Annotated[str | None, Field(description="Group name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Policy groups (the 20.12+ policy counterpart of configuration groups: application priority, NGFW,
        SIG and DNS security profiles): name, solution, profiles, associated and up-to-date devices, deploy
        state, last change. Centralized policies of the template world are listed by
        catsdwan_list_sla_classes (app-route) or catsdwan_api_call."""
        app: SdwanApp = get_client(ctx)
        groups = await _groups(app, POLICY_GROUPS_PATH)
        if name:
            groups = [g for g in groups if name.lower() in str(g.get("name", "")).lower()]
        rows = [group_row(g) for g in groups[offset : offset + limit]]
        extra = None if groups else {"note": "No policy groups on this Manager."}
        return list_result(
            _paged(rows, len(groups), offset), fmt=response_format, columns=GROUP_COLUMNS[:-1], extra=extra
        )

    @reg.read(title="List SD-WAN templates")
    async def catsdwan_list_templates(
        ctx: Context,
        type: Annotated[
            Literal["device", "feature"],
            Field(
                description="device templates (attached to devices) or feature templates (their building "
                "blocks)"
            ),
        ] = "device",
        name: Annotated[str | None, Field(description="Template name contains (case-insensitive)")] = None,
        device_type: Annotated[str | None, Field(description="Device model contains, e.g. 'C8000V'")] = None,
        attached_only: Annotated[bool, Field(description="Only templates in use by a device")] = False,
        include_defaults: Annotated[
            bool,
            Field(description="Include the Manager's factory-default templates (many; hidden by default)"),
        ] = False,
        devices: Annotated[
            bool,
            Field(
                description="Device templates: name the attached devices (one extra read per template in use)"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Device templates (CLI or feature-based: name, device model, devices attached and which, last
        change and by whom) or feature templates (type, device models, devices attached, device templates
        using them). Factory-default templates are hidden unless include_defaults (the count is given). A
        device on a template is in template mode; configuration groups are the other mode
        (catsdwan_list_config_groups)."""
        app: SdwanApp = get_client(ctx)
        if type == "device":
            body = await app.api.get(DEVICE_TEMPLATES_PATH, {"feature": "all"})
        else:
            body = await app.api.get(FEATURE_TEMPLATES_PATH)
        raw = [
            t for t in _as_list(body.get("data") if isinstance(body, dict) else body) if isinstance(t, dict)
        ]
        defaults = sum(1 for t in raw if t.get("factoryDefault") is True)
        if not include_defaults:
            raw = [t for t in raw if t.get("factoryDefault") is not True]
        if name:
            raw = [t for t in raw if name.lower() in str(t.get("templateName", "")).lower()]
        if device_type:
            want = device_type.lower()
            raw = [t for t in raw if any(want in str(x).lower() for x in _as_list(t.get("deviceType")))]
        if attached_only:
            raw = [t for t in raw if (t.get("devicesAttached") or 0) > 0]
        raw.sort(key=lambda t: str(t.get("templateName", "")).lower())
        page = raw[offset : offset + limit]
        shape = device_template_row if type == "device" else feature_template_row
        rows = [shape(t) for t in page]
        extra: dict[str, Any] = {}
        if defaults and not include_defaults:
            extra["factory_defaults_hidden"] = defaults
        if type == "device" and devices:
            used = [r for r in rows if (r.get("devices_attached") or 0) > 0][:MAX_LOOKUPS]
            got = await asyncio.gather(
                *(app.api.get(path(TEMPLATE_DEVICES_PATH, id=str(r["id"]))) for r in used),
                return_exceptions=True,
            )
            for r, res in zip(used, got, strict=True):
                if isinstance(res, UpstreamError):
                    extra.setdefault("warnings", []).append(f"{r.get('name')}: devices not read: {res}")
                elif isinstance(res, BaseException):
                    raise res
                else:
                    r["attached_to"] = ", ".join(template_devices(res))
        return list_result(
            _paged(rows, len(raw), offset),
            fmt=response_format,
            columns=DEVICE_TEMPLATE_COLUMNS if type == "device" else FEATURE_TEMPLATE_COLUMNS,
            extra=extra or None,
        )

    @reg.read(title="Get SD-WAN device configuration")
    async def catsdwan_get_device_config(
        ctx: Context,
        device: Annotated[str, Field(description="Host name, system IP, chassis number or serial number")],
        source: Annotated[
            Literal["running", "intended"],
            Field(description="running: the device's configuration; intended: what the Manager holds for it"),
        ] = "running",
        diff: Annotated[
            bool,
            Field(description="Compare running with intended instead (by block, order-independent)"),
        ] = False,
        section: Annotated[
            str | None,
            Field(description="Only top-level blocks whose first line contains this, e.g. 'sdwan'"),
        ] = None,
    ) -> ToolResult:
        """A WAN edge's configuration: the running configuration, or the intended one (what the Manager
        would push: from its configuration group, device template or its last copy), with passwords,
        secrets, keys, pre-shared keys and SNMP communities masked. diff=true compares running with intended
        block by block (blocks only on the device, only intended, changed lines; the Manager renders blocks
        in another order, so order is ignored): a device changed by hand shows here. Also says which mode the
        device is in (configuration group, template or CLI) and the Manager's sync status."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        row = resolve(inv, device)
        chassis = row.get("chassis")
        if not chassis:
            raise InvalidRequest(
                f"{device!r} has no chassis number in the inventory, so it has no configuration."
            )
        out: dict[str, Any] = {
            "host": row.get("host"),
            "system_ip": row.get("system_ip"),
            "chassis": chassis,
            **_mode(row),
        }
        out = {k: v for k, v in out.items() if v is not None}
        wanted = ["running", "intended"] if diff else [source]
        paths = {"running": RUNNING_PATH, "intended": INTENDED_PATH}
        got = await asyncio.gather(*(app.api.get(path(paths[w], id=str(chassis))) for w in wanted))
        texts: dict[str, str] = {}
        for w, body in zip(wanted, got, strict=True):
            text = body.get("config") if isinstance(body, dict) else body
            texts[w] = text if isinstance(text, str) else ""
        masked_lines = 0
        for w in wanted:
            texts[w], n = mask_config(texts[w])
            masked_lines += n
        if diff:
            empty = [w for w in wanted if not texts[w].strip()]
            if empty:
                out["diff"] = f"not compared: the Manager returned no {' and no '.join(empty)} configuration"
            else:
                d = config_diff(texts["running"], texts["intended"])
                if section:
                    want = section.lower()
                    for k in ("only_on_device", "only_intended"):
                        if k in d:
                            d[k] = [b for b in d[k] if want in b.lower()]
                    if "changed" in d:
                        d["changed"] = {b: v for b, v in d["changed"].items() if want in b.lower()}
                out["diff"] = d
                out["diff_note"] = (
                    "'-' = running, '+' = intended. The device hides some default lines ('no ...') that the "
                    "Manager's copy shows; those appear as intended-only."
                )
        else:
            text = texts[source]
            if not text.strip():
                out["config"] = None
                out["note"] = f"the Manager returned no {source} configuration for this device"
            else:
                out["config"] = sections(text, section) if section else text
                out["lines"] = len(out["config"].splitlines())
        out["source"] = ", ".join(f"GET {paths[w].format(id='{chassis}')}" for w in wanted)
        if masked_lines:
            out["masked_lines"] = masked_lines
        if inv.warnings:
            out["warnings"] = inv.warnings
        return object_result(out, fmt="json")


def _paged(rows: list[dict[str, Any]], total: int, offset: int) -> Page:
    """A page of rows already cut from a filtered list of `total` (follow-up reads ran for this page only)."""
    return Page(rows, offset, total)


async def _read_profiles(app: SdwanApp, profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    async def one(p: dict[str, Any]) -> dict[str, Any]:
        ptype, pid = str(p.get("type") or ""), str(p.get("id") or "")
        head = {"name": p.get("name"), "type": ptype, "id": pid}
        if ptype not in PROFILE_TYPES or not pid:
            return {**head, "note": f"not read: no feature-profile read for type {ptype!r} in the 20.18 API"}
        try:
            return {**head, **profile_detail(await app.api.get(path(PROFILE_PATH, type=ptype, id=pid)))}
        except UpstreamError as e:
            return {**head, "error": str(e)[:300]}

    return list(await asyncio.gather(*(one(p) for p in profiles)))
