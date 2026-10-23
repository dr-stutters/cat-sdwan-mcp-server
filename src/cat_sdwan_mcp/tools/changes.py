"""W8 configuration changes, preview-first: catsdwan_set_device_variables, catsdwan_deploy_config_group,
catsdwan_attach_device_template.

Tiers: set_device_variables only stores values (write). The deploy and the attach are registered at write
tier so a one-device change needs only MCP_ENABLE_WRITES; a change to more than one device, or to a hub
(CATSDWAN_HUB_DEVICES) or a device at a protected site (CATSDWAN_PROTECTED_SITES), is dangerous: its preview
is blocked unless MCP_ENABLE_DANGEROUS is on (and, with per-user roles, the caller is admin). Every deploy
reports `blast_radius` = its devices, so MCP_MAX_BLAST_RADIUS caps it.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    current_caller,
    get_client,
    poll_until,
    preview_or_apply,
)
from cat_sdwan_mcp.changes import (
    ACTION_STATUS_PATH,
    ATTACH_CLI_PATH,
    ATTACH_FEATURE_PATH,
    DEPLOY_PATH,
    GROUP_PREVIEW_PATH,
    RUNNING_TASKS_PATH,
    TEMPLATE_CONFIG_PATH,
    TEMPLATE_INPUT_PATH,
    action_done,
    action_outcome,
    action_progress,
    busy_devices,
    device_brief,
    input_rows,
    masked,
    match_variable,
    merge_variables,
    preview_text,
    process_id,
    running_process_ids,
    shown_changes,
    template_columns,
    text_hash,
    tier_reasons,
    variable_keys,
)
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    CONFIG_GROUPS_PATH,
    DEVICE_TEMPLATES_PATH,
    INTENDED_PATH,
    RUNNING_PATH,
    VARIABLES_PATH,
    config_diff,
    device_variable_lists,
    mask_config,
    path,
    resolve_group,
)
from cat_sdwan_mcp.inventory import Inventory, load_inventory, resolve
from cat_sdwan_mcp.tools.configuration import _associated, _groups

POLL_INTERVAL = 3.0  # seconds between action-status reads (tests set it to 0)
MAX_BUSY_CHECKS = 10  # running actions read for the pending-action blocker

GroupRef = Annotated[str, Field(description="Configuration group name or id")]
DeviceList = Annotated[
    list[str],
    Field(
        min_length=1,
        description="Devices by host name, system IP or chassis number. One device is write tier; more than "
        "one, or a hub / protected-site device, is dangerous",
    ),
]
Wait = Annotated[bool, Field(description="Wait for every device to report success or failure (default true)")]
ShowCli = Annotated[
    bool, Field(description="Include the full intended CLI per device in the preview (secrets masked)")
]

DEPLOY_ROLLBACK = (
    "The Manager has no undo. To roll back, set the previous variable values again "
    "(catsdwan_set_device_variables: its preview shows them) and deploy again; the running configuration "
    "before this change is what the preview's diff shows as '-' lines."
)


def dangerous_blockers(ctx: Context, app: SdwanApp, reasons: list[str]) -> list[str]:
    """A change for the dangerous tier: refused unless MCP_ENABLE_DANGEROUS (and an admin caller)."""
    if not reasons:
        return []
    why = "; ".join(reasons)
    if not app.settings.mcp_enable_dangerous:
        return [
            f"This change is dangerous tier ({why}): it needs MCP_ENABLE_DANGEROUS. Deploy to one "
            "non-hub device at a time, or have the operator enable dangerous changes."
        ]
    roles = ctx.lifespan_context.get("roles") if hasattr(ctx, "lifespan_context") else None
    if roles is not None and not roles.allows(current_caller(), "dangerous"):
        return [f"This change is dangerous tier ({why}): your role may not make dangerous changes."]
    return []


def _resolve_devices(inv: Inventory, refs: list[str]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for ref in refs:
        row = resolve(inv, ref)
        if not row.get("chassis"):
            raise InvalidRequest(
                f"{ref!r} has no chassis number in the inventory, so it can't be configured."
            )
        out[str(row["chassis"])] = row
    return list(out.values())


def _reachability_blockers(rows: list[dict[str, Any]]) -> list[str]:
    out = []
    for r in rows:
        reach = str(r.get("reachability") or "unknown")
        if reach.lower() != "reachable":
            out.append(f"{r.get('host') or r.get('chassis')} is {reach}: the Manager can't push to it")
    return out


async def _pending_blockers(app: SdwanApp, rows: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(blockers for devices with an action still running, warnings when that couldn't be checked)."""
    keys: dict[str, str] = {}
    for r in rows:
        host = str(r.get("host") or r.get("chassis"))
        for k in ("chassis", "system_ip"):
            if r.get(k):
                keys[str(r[k])] = host
    try:
        ids = running_process_ids(await app.api.get(RUNNING_TASKS_PATH))[:MAX_BUSY_CHECKS]
        got = await asyncio.gather(*(app.api.get(path(ACTION_STATUS_PATH, id=i)) for i in ids))
    except UpstreamError as e:
        return [], [f"pending actions not checked: {str(e)[:200]}"]
    busy: dict[str, str] = {}
    for body in got:
        busy.update(busy_devices(body, keys))
    return [f"{h} has an action still running ({a}): wait for it to finish" for h, a in busy.items()], []


async def _wait_action(app: SdwanApp, ctx: Context, pid: str, what: str) -> dict[str, Any]:
    body = await poll_until(
        lambda: app.api.get(path(ACTION_STATUS_PATH, id=pid)),
        done=action_done,
        describe=action_progress,
        timeout=app.settings.mcp_task_timeout,
        interval=POLL_INTERVAL,
        ctx=ctx,
        what=what,
    )
    return action_outcome(body, pid)


async def _started(app: SdwanApp, ctx: Context, answer: Any, wait: bool, what: str) -> dict[str, Any]:
    pid = process_id(answer)
    if pid is None:
        return {"answer": answer, "note": "the Manager returned no action id, so the outcome isn't tracked"}
    if not wait:
        return {
            "process_id": pid,
            "check_with": f"catsdwan_api_call('/dataservice/device/action/status/{pid}')",
        }
    return await _wait_action(app, ctx, pid, what)


async def _running(app: SdwanApp, chassis: str) -> tuple[str | None, str | None]:
    try:
        body = await app.api.get(path(RUNNING_PATH, id=chassis))
    except UpstreamError as e:
        return None, f"running configuration not read: {str(e)[:200]}"
    text = body.get("config") if isinstance(body, dict) else body
    return (text if isinstance(text, str) and text.strip() else None), None


def _device_view(new: str | None, running: str | None, show_cli: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if new is None:
        return out
    masked_new, _ = mask_config(new)
    if running is not None:
        out["diff_vs_running"] = config_diff(mask_config(running)[0], masked_new)
    if show_cli:
        out["cli"] = masked_new
    out["cli_lines"] = len(new.splitlines())
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Set SD-WAN device variables", idempotent=True)
    async def catsdwan_set_device_variables(
        ctx: Context,
        group: GroupRef,
        device: Annotated[str, Field(description="Host name, system IP or chassis of an associated device")],
        values: Annotated[
            dict[str, Any],
            Field(
                description="Variable name -> new value, e.g. {'banner_motd': 'Authorised use only'}; "
                "null clears a value. Names as catsdwan_get_config_group lists them"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a device's variable values in a configuration group (the {{name}} placeholders of its
        feature profiles, e.g. host_name, site_id, banner_motd). Preview-first: the preview shows each changed
        variable old -> new (secrets masked) and the old values to undo it. Confirm only STORES the values on
        the Manager: nothing reaches the device until catsdwan_deploy_config_group. The Manager needs every
        variable of the device in one write, so the tool reads them all, merges the change and writes them
        back with their original types."""
        if not values:
            raise InvalidRequest("Give at least one variable in `values`.")
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, CONFIG_GROUPS_PATH), group)
        gid, gname = str(found.get("id")), str(found.get("name"))
        inv = await load_inventory(app)
        row = resolve(inv, device)
        chassis = str(row.get("chassis") or "")
        host = str(row.get("host") or chassis)
        blockers: list[str] = []
        assoc = await _associated(app, gid)
        if chassis not in {str(a.get("chassis")) for a in assoc}:
            names = ", ".join(str(a.get("host") or a.get("chassis")) for a in assoc) or "none"
            blockers.append(
                f"{host} is not associated with configuration group {gname} (associated: {names})"
            )
        current: list[dict[str, Any]] = []
        if not blockers:
            try:
                body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": chassis})
                current = device_variable_lists(body).get(chassis, [])
                if not current:
                    blockers.append(f"the Manager returned no variables for {host} in {gname}")
            except UpstreamError as e:
                hint = (
                    " (the group needs a system feature profile before it has device variables)"
                    if "system profile" in str(e).lower()
                    else ""
                )
                blockers.append(f"device variables not read: {str(e)[:300]}{hint}")
        merged, changes, unknown = merge_variables(current, values)
        if current and unknown:
            have = ", ".join(sorted(str(v["name"]) for v in current))
            blockers.append(f"{host} has no variable {', '.join(map(repr, unknown))} (its variables: {have})")
        if current and not changes and not unknown:
            blockers.append("nothing to change: every value is already set as given")
        body_out = {
            "solution": found.get("solution") or "sdwan",
            "devices": [{"device-id": chassis, "variables": merged}],
        }
        plan = Plan(
            f"Set {len(changes)} variable(s) of {host} in configuration group {gname}",
            details={
                "group": gname,
                "device": device_brief(row),
                "changes": shown_changes(changes),
                "unchanged_variables": len(current) - len(changes),
                "request": f"PUT {VARIABLES_PATH} (all {len(merged)} variables of the device)",
                "undo": {n: masked(n, c["from"]) for n, c in changes.items()},
            },
            side_effects=[
                "Stores the values on the Manager only: the device changes when the group is deployed "
                "(catsdwan_deploy_config_group)."
            ],
            fingerprint={"group": found.get("lastUpdatedOn"), "variables": current},
            blockers=blockers,
        )

        async def apply() -> Any:
            await app.api.put(path(VARIABLES_PATH, id=gid), body_out)
            return {
                "stored": shown_changes(changes),
                "next": f"catsdwan_deploy_config_group(group={gname!r}, devices=[{host!r}]) pushes them "
                "(preview first)",
                "undo": "catsdwan_set_device_variables with the preview's `undo` values, then deploy",
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_device_variables",
            args={"group": group, "device": device, "values": values},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Deploy SD-WAN configuration group", task=True)
    async def catsdwan_deploy_config_group(
        ctx: Context,
        group: GroupRef,
        devices: DeviceList,
        show_cli: ShowCli = True,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push a configuration group to some of its devices. Preview-first: per device the intended CLI
        from the Manager's CLI preview (POST .../device/{id}/preview) and its diff against the running
        configuration ('-' running, '+' after the deploy), secrets masked; when the Manager has no CLI preview
        the preview is the intended-vs-running diff of the Manager's stored copy and says so. Blocked for a
        device not in the group, on a device template, unreachable, or with an action still running, and for
        a group without feature profiles. Confirm deploys, then follows the Manager's action status until
        every device reports success or failure (with the failing device's reason). One device is write tier;
        several devices, a hub or a protected-site device need MCP_ENABLE_DANGEROUS."""
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, CONFIG_GROUPS_PATH), group)
        gid, gname = str(found.get("id")), str(found.get("name"))
        inv = await load_inventory(app)
        rows = _resolve_devices(inv, devices)
        assoc = {str(a.get("chassis")): a for a in await _associated(app, gid)}
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        if not _as_list(found.get("profiles")):
            blockers.append(
                f"configuration group {gname} has no feature profiles: a deploy would replace the devices' "
                "configuration with nothing"
            )
        for r in rows:
            host = r.get("host") or r.get("chassis")
            a = assoc.get(str(r["chassis"]))
            if r.get("config_mode") == "template":
                blockers.append(
                    f"{host} is attached to device template {r.get('config') or '?'}: a device is in a "
                    "configuration group or on a template, never both (detach it first)"
                )
            elif a is None:
                blockers.append(f"{host} is not associated with configuration group {gname}")
            elif a.get("deployable") is False:
                blockers.append(f"{host}: the Manager says it is not deployable ({a.get('config_status')})")
            if a and a.get("unsupported_features"):
                warnings.append(f"{host}: unsupported features {a['unsupported_features']}")
        blockers += _reachability_blockers(rows)
        busy, busy_warn = await _pending_blockers(app, rows)
        blockers += busy
        warnings += busy_warn
        blockers += dangerous_blockers(
            ctx, app, reasons := tier_reasons(rows, app.settings.hub_devices, app.settings.protected_sites)
        )
        chassis = [str(r["chassis"]) for r in rows]
        variables: dict[str, list[dict[str, Any]]] = {}
        try:
            body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": ",".join(chassis)})
            variables = device_variable_lists(body)
        except UpstreamError as e:
            warnings.append(f"device variables not read: {str(e)[:200]}")

        async def one(r: dict[str, Any]) -> tuple[dict[str, Any], Any]:
            c = str(r["chassis"])
            view: dict[str, Any] = device_brief(r)
            new: str | None = None
            try:
                new = preview_text(await app.api.post(path(GROUP_PREVIEW_PATH, id=gid, device=c), {}))
                source = (
                    "the Manager's CLI preview (POST /dataservice/v1/config-group/{id}/device/{id}/preview)"
                )
                if new is None:
                    raise ValueError("the CLI preview returned no configuration text")
            except (UpstreamError, ValueError) as e:
                view["cli_preview_unavailable"] = str(e)[:200]
                source = (
                    "NOT a CLI preview: the Manager's stored intended configuration (GET "
                    "/dataservice/template/config/attached/{chassis}), as last rendered; pending variable "
                    "or profile changes may not be in it"
                )
                try:
                    got = await app.api.get(path(INTENDED_PATH, id=c))
                    text = got.get("config") if isinstance(got, dict) else got
                    new = text if isinstance(text, str) and text.strip() else None
                except UpstreamError as e2:
                    view["intended_unavailable"] = str(e2)[:200]
            view["preview_source"] = source
            running, note = await _running(app, c)
            if note:
                view["note"] = note
            view.update(_device_view(new, running, show_cli))
            if c in variables:
                view["variables"] = {
                    str(v["name"]): masked(str(v["name"]), v.get("value")) for v in variables[c]
                }
            return view, {"cli": text_hash(new), "variables": variables.get(c)}

        got = await asyncio.gather(*(one(r) for r in rows))
        plan = Plan(
            f"Deploy configuration group {gname} to {len(rows)} device(s): "
            + ", ".join(str(r.get("host") or r.get("chassis")) for r in rows),
            details={
                "group": gname,
                "tier": "dangerous" if reasons else "write",
                **({"tier_reasons": reasons} if reasons else {}),
                "devices": [v for v, _ in got],
                "request": f"POST {DEPLOY_PATH} {{devices: [{{id: <chassis>}}]}}",
                "rollback": DEPLOY_ROLLBACK,
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Replaces each device's configuration with the group's rendering: changes made on the "
                "device by hand are overwritten.",
                "A wrong transport or system value can cut the device off the Manager; on a hub, every "
                "branch behind it.",
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "devices": dict(zip(chassis, (f for _, f in got), strict=True)),
            },
            blockers=blockers,
            blast_radius=len(rows),
        )

        async def apply() -> Any:
            answer = await app.api.post(path(DEPLOY_PATH, id=gid), {"devices": [{"id": c} for c in chassis]})
            return await _started(app, ctx, answer, wait, f"deploy of {gname}")

        return await preview_or_apply(
            ctx,
            tool="catsdwan_deploy_config_group",
            args={"group": group, "devices": devices, "show_cli": show_cli, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Attach SD-WAN device template", task=True)
    async def catsdwan_attach_device_template(
        ctx: Context,
        template: Annotated[str, Field(description="Device template name or id (catsdwan_list_templates)")],
        devices: DeviceList,
        variables: Annotated[
            dict[str, Any] | None,
            Field(
                description="Variable name -> value for every device, e.g. {'banner_motd': 'Lab'} (names "
                "as the template's variables, '//system/host-name' or 'host-name')"
            ),
        ] = None,
        device_variables: Annotated[
            dict[str, dict[str, Any]] | None,
            Field(description="Per-device values, keyed by the device as in `devices`; win over `variables`"),
        ] = None,
        show_cli: ShowCli = True,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Attach a device template (legacy templates, CLI or feature-based) to devices and push it.
        Preview-first: the variables the template needs per device (POST /template/device/config/input),
        checked before anything is sent (a variable without a value blocks), then the intended CLI per device
        (POST /template/device/config/config) and its diff against the running configuration, secrets
        masked. Blocked for a device in a configuration group, unreachable, of another model, or with an
        action still running. Confirm attaches (attachcli for CLI templates, attachfeature for feature
        templates) and follows the action status to success or failure per device. A CLI-mode device leaves
        CLI mode: the Manager owns its configuration from then on. One device is write tier; several devices,
        a hub or a protected-site device need MCP_ENABLE_DANGEROUS."""
        app: SdwanApp = get_client(ctx)
        body = await app.api.get(DEVICE_TEMPLATES_PATH, {"feature": "all"})
        raw = [
            t for t in _as_list(body.get("data") if isinstance(body, dict) else body) if isinstance(t, dict)
        ]
        tpl = resolve_group(
            [{**t, "id": t.get("templateId"), "name": t.get("templateName")} for t in raw],
            template,
            "device template",
        )
        tid, tname = str(tpl["id"]), str(tpl["name"])
        is_cli = str(tpl.get("configType")) == "file"
        inv = await load_inventory(app)
        rows = _resolve_devices(inv, devices)
        by_ref = {ref: str(resolve(inv, ref)["chassis"]) for ref in devices}
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        for r in rows:
            host = r.get("host") or r.get("chassis")
            if r.get("config_mode") == "configuration group":
                blockers.append(
                    f"{host} is in configuration group {r.get('config') or '?'}: a device is in a group "
                    "or on a template, never both (remove it from the group first)"
                )
            if tpl.get("deviceType") and r.get("model") and str(r["model"]) != str(tpl["deviceType"]):
                blockers.append(f"{host} is a {r['model']}; template {tname} is for {tpl['deviceType']}")
        blockers += _reachability_blockers(rows)
        busy, busy_warn = await _pending_blockers(app, rows)
        blockers += busy
        warnings += busy_warn
        blockers += dangerous_blockers(
            ctx, app, reasons := tier_reasons(rows, app.settings.hub_devices, app.settings.protected_sites)
        )
        unknown_refs = [k for k in (device_variables or {}) if k not in by_ref]
        if unknown_refs:
            raise InvalidRequest(
                f"device_variables names {', '.join(map(repr, unknown_refs))}, not in `devices` as given."
            )
        chassis = [str(r["chassis"]) for r in rows]
        answer = await app.api.post(
            TEMPLATE_INPUT_PATH,
            {"templateId": tid, "deviceIds": chassis, "isEdited": False, "isMasterEdited": False},
        )
        titles = template_columns(answer)
        inputs = {str(i.get("csv-deviceId")): i for i in input_rows(answer)}
        ready: list[dict[str, Any]] = []
        views: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for r in rows:
            c, host = str(r["chassis"]), str(r.get("host") or r["chassis"])
            row = inputs.get(c)
            if row is None:
                blockers.append(f"the Manager returned no template input for {host}")
                continue
            keys = variable_keys(row, titles)
            given = dict(variables or {})
            for ref, vals in (device_variables or {}).items():
                if by_ref.get(ref) == c:
                    given.update(vals)
            changes: dict[str, dict[str, Any]] = {}
            for name, value in given.items():
                key = match_variable(name, keys, titles)
                if key is None:
                    blockers.append(
                        f"template {tname} has no variable {name!r} (its variables: {', '.join(keys)})"
                    )
                elif isinstance(key, list):
                    blockers.append(f"{name!r} matches several template variables: {', '.join(key)}")
                else:
                    old = row.get(key)
                    if old != value:
                        changes[key] = {"from": old, "to": value}
                    row[key] = value
            missing = [k for k in keys if row.get(k) in (None, "")]
            if missing:
                blockers.append(f"{host}: no value for {', '.join(missing)} (give them in variables)")
            row["csv-status"] = "complete" if not missing else row.get("csv-status", "in_complete")
            row["csv-templateId"] = tid
            ready.append(row)
            shown = {k: masked(k, row.get(k)) for k in keys}
            views.append(({**device_brief(r), "variables": shown, "changes": shown_changes(changes)}, row))

        async def render(view: dict[str, Any], row: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
            c = str(row.get("csv-deviceId"))
            new: str | None = None
            try:
                new = preview_text(
                    await app.api.post(
                        TEMPLATE_CONFIG_PATH,
                        {"templateId": tid, "device": row, "isEdited": False, "isMasterEdited": False},
                    )
                )
            except UpstreamError as e:
                view["cli_unavailable"] = str(e)[:300]
            running, note = await _running(app, c)
            if note:
                view["note"] = note
            view.update(_device_view(new, running, show_cli))
            return view, text_hash(new)

        rendered = await asyncio.gather(*(render(v, row) for v, row in views)) if not blockers else []
        if blockers:
            device_views = [v for v, _ in views]
        else:
            device_views = [v for v, _ in rendered]
            for v, h in rendered:
                if h is None:
                    blockers.append(
                        f"{v.get('host')}: the Manager rendered no configuration (see cli_unavailable)"
                    )
        attach_path = ATTACH_CLI_PATH if is_cli else ATTACH_FEATURE_PATH
        plan = Plan(
            f"Attach device template {tname} to {len(rows)} device(s): "
            + ", ".join(str(r.get("host") or r.get("chassis")) for r in rows),
            details={
                "template": {
                    "name": tname,
                    "kind": "CLI" if is_cli else "feature",
                    "device_type": tpl.get("deviceType"),
                },
                "tier": "dangerous" if reasons else "write",
                **({"tier_reasons": reasons} if reasons else {}),
                "devices": device_views,
                "request": f"POST {attach_path}",
                "rollback": "The Manager has no undo: attach again with the previous values, or detach the "
                "device (it keeps the pushed configuration in CLI mode). The '-' lines of the diff are the "
                "running configuration before this change.",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Replaces each device's configuration with the template's rendering.",
                "The devices leave CLI mode or their previous template: the Manager owns their config.",
            ],
            fingerprint={
                "template": tpl.get("lastUpdatedOn"),
                "devices": {str(v.get("chassis")): h for v, h in rendered},
                "values": [row for _, row in views],
            },
            blockers=blockers,
            blast_radius=len(rows),
        )

        async def apply() -> Any:
            push = {
                "deviceTemplateList": [
                    {
                        "templateId": tid,
                        "device": [{**row, "selected": "true"} for row in ready],
                        "isEdited": False,
                        "isMasterEdited": False,
                        "isDraftDisabled": False,
                    }
                ]
            }
            started = await app.api.post(attach_path, push)
            return await _started(app, ctx, started, wait, f"attach of {tname}")

        return await preview_or_apply(
            ctx,
            tool="catsdwan_attach_device_template",
            args={
                "template": template,
                "devices": devices,
                "variables": variables,
                "device_variables": device_variables,
                "show_cli": show_cli,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
