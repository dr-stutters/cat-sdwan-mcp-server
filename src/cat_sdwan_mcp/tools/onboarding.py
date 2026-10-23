"""W9 edge onboarding: catsdwan_list_wan_edges, catsdwan_bootstrap_config, catsdwan_onboard_edge,
catsdwan_set_edge_validity.

The one-time token (the serialNumber of a software edge that has not joined, the otp of its bootstrap) is a
secret: masked in every result, except catsdwan_bootstrap_config(reveal_otp=true), which hands it to the
operator with a warning. Tokens read from the Manager are registered with the secret scrubber, so they never
reach a log line or an error message either.

Tiers: the list and the bootstrap are reads. catsdwan_onboard_edge and catsdwan_set_edge_validity are write
tier; an onboarding of a hub or a protected-site edge, and a validity change to invalid (or staging on a
joined edge), are dangerous: blocked unless MCP_ENABLE_DANGEROUS (as the W8 deploys).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from pathlib import Path
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
    UpstreamError,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp._core.secrets import register_secret
from cat_sdwan_mcp.changes import (
    ATTACH_CLI_PATH,
    ATTACH_FEATURE_PATH,
    TEMPLATE_INPUT_PATH,
    input_rows,
    masked,
    match_variable,
    merge_variables,
    shown_changes,
    template_columns,
    tier_reasons,
    variable_keys,
)
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    ASSOCIATE_PATH,
    CONFIG_GROUPS_PATH,
    DEVICE_TEMPLATES_PATH,
    VARIABLES_PATH,
    device_variable_lists,
    path,
    resolve_group,
)
from cat_sdwan_mcp.inventory import config_mode
from cat_sdwan_mcp.onboarding import (
    BOOTSTRAP_PATH,
    CONFIG_TYPES,
    FAILED_CERT_STATES,
    FILEUPLOAD_PATH,
    GROUP_KEYS,
    MASK,
    MAX_SERIAL_FILE,
    PUSH_VEDGES_PATH,
    SAVE_VALIDITY_PATH,
    TEMPLATE_KEYS,
    WAYS_IN,
    activate_command,
    boot_routes,
    bootstrap_text,
    chassis_of,
    check_system_ip,
    decode_bootstrap,
    edge_or_not_found,
    edge_row,
    find_edge,
    is_joined,
    manager_org,
    mask_otp,
    matches_state,
    protected_row,
    serial_file_body,
    token_of,
    upload_summary,
    validity_payload,
    vinit_params,
)
from cat_sdwan_mcp.tools.changes import _started, dangerous_blockers
from cat_sdwan_mcp.tools.configuration import _associated, _groups

EDGE_COLUMNS = [
    "chassis",
    "host",
    "system_ip",
    "site_id",
    "model",
    "validity",
    "joined",
    "certificate_state",
    "org",
    "managed_by",
]
Chassis = Annotated[
    str,
    Field(
        description="The edge's chassis number (e.g. 'C8K-...', as catsdwan_list_wan_edges lists it), or "
        "the host name / system IP of an edge that has joined"
    ),
]
Validity = Literal["valid", "invalid", "staging"]

VALIDITY_EFFECT = {
    "valid": "the validator and controllers accept the edge: it can join and build tunnels",
    "invalid": "the validator refuses the edge: it cannot join, and a joined edge loses its control "
    "connections (and with them its tunnels) once the list reaches the controllers",
    "staging": "the edge may join the controllers (control connections) but builds no data plane: no "
    "tunnels, no traffic between sites",
}


async def _wan_edges(app: SdwanApp) -> list[dict[str, Any]]:
    rows = await app.vedges()
    for v in rows:
        if tok := token_of(v):
            register_secret(tok)
    return rows


async def _org(app: SdwanApp) -> tuple[str | None, str | None]:
    """(the overlay's org name, a warning when the controllers' records could not be read)."""
    try:
        return manager_org(await app.controllers()), None
    except UpstreamError as e:
        return None, f"the overlay's org name was not read (controllers): {str(e)[:200]}"


def _site_note(v: dict[str, Any]) -> str:
    site = v.get("site-id") or v.get("configuredSiteId")
    host = v.get("host-name") or chassis_of(v)
    return f"{host}" + (f" at site {site}" if site else " (no site: it has not joined)")


async def _push_validity(app: SdwanApp, ctx: Context, v: dict[str, Any], validity: str, wait: bool) -> Any:
    """Save the validity in the WAN edge list, then send the list to the controllers (an action)."""
    saved = await app.api.post(SAVE_VALIDITY_PATH, validity_payload(v, validity))
    pushed = await app.api.post(PUSH_VEDGES_PATH, None, params={"action": "push"})
    out: dict[str, Any] = {"saved": saved if isinstance(saved, dict) and "id" in saved else "ok"}
    out["sent_to_controllers"] = await _started(app, ctx, pushed, wait, "send WAN edge list to controllers")
    return out


def _failed(result: Any) -> str | None:
    if isinstance(result, dict):
        sent = result.get("sent_to_controllers")
        if isinstance(sent, dict) and sent.get("outcome") in ("failed", "partial"):
            return str(
                sent.get("summary") or sent.get("validation") or "the controllers did not all accept it"
            )
        if result.get("outcome") in ("failed", "partial"):
            return str(result.get("summary") or result.get("validation") or "the action failed")
    return None


def _read_serial_file(name: str) -> tuple[str, bytes]:
    p = Path(name).expanduser()
    if not p.is_file():
        raise InvalidRequest(f"serial_file {name!r} is not a file on the server's host.")
    size = p.stat().st_size
    if size == 0 or size > MAX_SERIAL_FILE:
        raise InvalidRequest(f"serial_file {name!r} is {size} bytes: not a serial file (0 < size <= 4 MB).")
    return p.name, p.read_bytes()


async def _template_row(
    app: SdwanApp,
    tid: str,
    tname: str,
    chassis: str,
    values: dict[str, Any],
    variables: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str]]:
    """(the device's template input row filled with the onboarding values, the values shown with secrets
    masked, what is wrong). POST /template/device/config/input works for an edge that has not joined."""
    answer = await app.api.post(
        TEMPLATE_INPUT_PATH,
        {"templateId": tid, "deviceIds": [chassis], "isEdited": False, "isMasterEdited": False},
    )
    titles = template_columns(answer)
    row = next((r for r in input_rows(answer) if str(r.get("csv-deviceId")) == chassis), None)
    if row is None:
        return None, {}, [f"the Manager returned no template input for {chassis}"]
    problems: list[str] = []
    keys = variable_keys(row, titles)
    given: dict[str, Any] = {}
    for what, names in TEMPLATE_KEYS.items():
        key = next((k for n in names if isinstance(k := match_variable(n, keys, titles), str)), None)
        if key is None:
            problems.append(f"template {tname} has no {what} variable (its variables: {', '.join(keys)})")
        else:
            given[key] = values[what]
    for name, value in (variables or {}).items():
        got = match_variable(name, keys, titles)
        if not isinstance(got, str):
            problems.append(
                f"template {tname} has no single variable {name!r} (its variables: {', '.join(keys)})"
            )
        else:
            given[got] = value
    row.update(given)
    missing = [k for k in keys if row.get(k) in (None, "")]
    if missing:
        problems.append(f"{chassis}: no value for {', '.join(missing)} (give them in variables)")
    row["csv-status"] = "complete"
    row["csv-templateId"] = tid
    return row, {k: masked(k, row.get(k)) for k in keys}, problems


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN WAN edges")
    async def catsdwan_list_wan_edges(
        ctx: Context,
        state: Annotated[
            Literal["joined", "not_joined", "valid", "invalid", "staging"] | None,
            Field(description="Only edges that have joined / not joined, or with this validity"),
        ] = None,
        model: Annotated[str | None, Field(description="Model contains, e.g. 'C8000V'")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's WAN edge list (the serial file / Smart Account slots, joined or not): chassis, model,
        hardware or software, validity (valid, invalid, staging), whether it has joined (host, system IP,
        site), certificate state (tokengenerated, certinstalled, ...), the org name in its certificate (an
        org that differs from the overlay's is flagged org_mismatch), the configuration it is managed by,
        and the certificate serial. A software edge that has not joined has a one-time token instead of a
        serial: always shown as ********; catsdwan_bootstrap_config hands it over. Use catsdwan_onboard_edge
        to bring a slot into the fabric."""
        app: SdwanApp = get_client(ctx)
        vedges, (org, warn) = await asyncio.gather(_wan_edges(app), _org(app))
        rows = [edge_row(v, org) for v in vedges]
        rows = [r for r in rows if matches_state(r, state)]
        if model:
            rows = [r for r in rows if model.lower() in str(r.get("model", "")).lower()]
        rows.sort(key=lambda r: (not r.get("joined"), str(r.get("host") or ""), str(r.get("chassis"))))
        extra: dict[str, Any] = {
            "overlay_org": org,
            "joined": sum(1 for v in vedges if is_joined(v)),
            "slots": len(vedges),
        }
        if warn:
            extra["warnings"] = [warn]
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=EDGE_COLUMNS,
            extra={k: v for k, v in extra.items() if v is not None},
        )

    @reg.read(title="SD-WAN edge bootstrap configuration")
    async def catsdwan_bootstrap_config(
        ctx: Context,
        chassis: Chassis,
        type: Annotated[
            Literal["cloud-init", "encoded"],
            Field(
                description="cloud-init (the #cloud-config text a C8000V boots with) or encoded (one string)"
            ),
        ] = "cloud-init",
        include_root_cert: Annotated[
            bool, Field(description="Include the Manager's default root certificate (ca-certs)")
        ] = False,
        reveal_otp: Annotated[
            bool,
            Field(
                description="Return the one-time token (otp) in full. Off by default: the configuration "
                "comes back with the otp masked. Only turn on to hand the day-0 to the edge"
            ),
        ] = False,
    ) -> ToolResult:
        """The day-0 bootstrap a WAN edge boots with (GET /dataservice/system/device/bootstrap/device/{uuid}):
        cloud-init with vinitparam uuid (the chassis), otp (the one-time token), vbond (the validator), org
        and rcc. Use it as the day-0 configuration of a C8000V (in CML: the node configuration in
        cml_build_lab), or take the chassis and token to `request platform software sdwan vedge_cloud
        activate` on a running edge. The otp is masked unless reveal_otp=true: then the result carries the
        token in full, with a warning to keep it out of tickets and chat logs. Says when the edge has already
        joined (its token is spent), is not valid (the validator would refuse it) or is not in the list."""
        app: SdwanApp = get_client(ctx)
        vedges, (org, org_warn) = await asyncio.gather(_wan_edges(app), _org(app))
        v = edge_or_not_found(vedges, chassis)
        c = chassis_of(v)
        token = token_of(v)
        if is_joined(v):
            # live, 20.18.3: the Manager answers 400 'not in "Token Generated" or "Bootstrap Config Generated"
            # state. Bootstrap not allowed' for a joined edge, so say why instead of passing that on
            raise InvalidRequest(
                f"{c} has already joined ({v.get('host-name') or 'no host name'}): its token is spent and "
                "the Manager generates no bootstrap for it. To rebuild it with the same chassis, "
                "decommission it on the Manager first (it then gets a new token), or use a free chassis "
                "(catsdwan_list_wan_edges(state='not_joined'))."
            )
        body = await app.api.get(
            path(BOOTSTRAP_PATH, id=c),
            {"configtype": CONFIG_TYPES[type], "inclDefRootCert": str(include_root_cert).lower()},
        )
        raw = bootstrap_text(body)
        if raw is None:
            raise UpstreamError(f"The Manager returned no bootstrap configuration for {c}.")
        text = raw if type == "cloud-init" else decode_bootstrap(raw)
        params = vinit_params(text or "")
        if otp := params.get("otp"):
            register_secret(otp)
        warnings: list[str] = []
        if org_warn:
            warnings.append(org_warn)
        if is_joined(v):
            warnings.append(
                f"{c} has already joined ({v.get('host-name') or 'no host name'}): its token is spent. To "
                "rebuild it with the same chassis, decommission it on the Manager first (it then gets a new "
                "token)."
            )
        if str(v.get("validity")) != "valid":
            warnings.append(
                f"{c} is {v.get('validity')}: the validator refuses it until it is valid "
                "(catsdwan_onboard_edge or catsdwan_set_edge_validity)."
            )
        if org and params.get("org") and params["org"] != org:
            warnings.append(f"the bootstrap's org {params['org']!r} is not the overlay's {org!r}")
        if (state := str(v.get("vedgeCertificateState") or "").lower()) in FAILED_CERT_STATES:
            warnings.append(f"{c}: {FAILED_CERT_STATES[state]}")
        out: dict[str, Any] = {
            "chassis": c,
            "type": type,
            "validity": v.get("validity"),
            "certificate_state": v.get("vedgeCertificateState"),
            "vinitparam": {k: (MASK if k == "otp" and not reveal_otp else x) for k, x in params.items()},
        }
        if reveal_otp:
            out["bootstrap_config"] = raw
            warnings.insert(
                0,
                "This result holds the edge's one-time token (otp) in full: it lets a device join the "
                "overlay as this chassis. Pass it to the edge only; keep it out of tickets, chat and logs.",
            )
            out["activate_command"] = activate_command(c, params.get("otp") or token)
        else:
            shown = mask_otp(text, token) if text is not None else None
            out["bootstrap_config"] = shown if type == "cloud-init" else MASK
            if type == "encoded" and shown is not None:
                out["decoded_masked"] = shown
            out["otp"] = "masked: call again with reveal_otp=true to hand the day-0 to the edge"
            out["activate_command"] = activate_command(c)
        out["how_to_use"] = boot_routes(c)
        if warnings:
            out["warnings"] = warnings
        return object_result(out, shape=False)

    @reg.write(title="Onboard SD-WAN WAN edge", task=True)
    async def catsdwan_onboard_edge(
        ctx: Context,
        chassis: Annotated[
            str, Field(description="The edge's chassis number, e.g. 'C8K-...' (catsdwan_list_wan_edges)")
        ],
        hostname: Annotated[str, Field(min_length=1, max_length=63, description="Host name, e.g. 'br2'")],
        system_ip: Annotated[
            str, Field(description="System IP (IPv4), unique in the overlay, e.g. '10.0.0.3'")
        ],
        site_id: Annotated[int, Field(ge=1, le=4294967295, description="Site id, e.g. 300")],
        config_group: Annotated[
            str | None, Field(description="Configuration group to associate it with (name or id)")
        ] = None,
        template: Annotated[
            str | None, Field(description="Device template to attach instead of a configuration group")
        ] = None,
        variables: Annotated[
            dict[str, Any] | None,
            Field(description="Other variable values for the group or template, e.g. {'banner_motd': 'Lab'}"),
        ] = None,
        serial: Annotated[
            str | None,
            Field(
                description="A hardware edge's certificate serial, checked against the list (not needed for "
                "a C8000V: never pass its token)"
            ),
        ] = None,
        serial_file: Annotated[
            str | None,
            Field(
                description="Path on the server's host of a signed serial file (PnP) to upload first, when "
                "the chassis is not in the WAN edge list yet"
            ),
        ] = None,
        wait: Annotated[
            bool, Field(description="Wait for each Manager action to finish (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Bring a WAN edge slot into the fabric, in order: (0) upload the serial file when the chassis is
        not in the WAN edge list and serial_file is given, (1) set its validity to valid and send the list
        to the controllers, (2) associate it with the configuration group and store its host name, system IP
        and site id (and `variables`) as its variables, or attach the device template with those values.
        Preview-first: the preview lists every step (done already / to do) and what blocks. A chassis not in
        the list is refused with the two ways in (serial file or Smart Account). Confirm runs the steps in
        order and stops at the first failing step with its reason. It deploys nothing to a configuration-
        group edge: once it has joined, catsdwan_deploy_config_group pushes the group. The result says how
        the edge joins: catsdwan_bootstrap_config at first boot, or the `request platform software sdwan
        vedge_cloud activate` exec command on a running C8000V. Onboarding a hub or a protected-site edge
        needs MCP_ENABLE_DANGEROUS."""
        if bool(config_group) == bool(template):
            raise InvalidRequest("Give exactly one of config_group or template.")
        ip = check_system_ip(system_ip)
        app: SdwanApp = get_client(ctx)
        vedges, (org, org_warn), devices = await asyncio.gather(_wan_edges(app), _org(app), app.devices())
        v = find_edge(vedges, chassis)
        blockers: list[str] = []
        warnings: list[str] = [org_warn] if org_warn else []
        steps: list[dict[str, Any]] = []
        upload: tuple[str, bytes] | None = None
        if v is None:
            if serial_file:
                upload = _read_serial_file(serial_file)
                steps.append(
                    {
                        "step": "upload serial file",
                        "action": f"POST {FILEUPLOAD_PATH} (multipart {upload[0]!r}, "
                        "validity=valid, upload=true)",
                        "note": f"{chassis} must be in the file: checked after the upload",
                    }
                )
            else:
                blockers.append(f"{chassis} is not in the Manager's WAN edge list. {WAYS_IN}")
            v = {"chasisNumber": chassis, "validity": "valid"}
        c = chassis_of(v)
        joined = is_joined(v)
        if serial and not upload and str(v.get("serialNumber") or "") != serial.strip():
            blockers.append(f"the serial given does not match {c}'s in the WAN edge list")
        if (state := str(v.get("vedgeCertificateState") or "").lower()) in FAILED_CERT_STATES:
            blockers.append(
                f"{c}: {FAILED_CERT_STATES[state]}; check the edge's clock and its root certificate, then "
                "bootstrap it again (catsdwan_bootstrap_config)"
            )
        if joined and org and v.get("organization-name") and str(v["organization-name"]) != org:
            blockers.append(
                f"{c}'s certificate is for org {v['organization-name']!r}, the overlay's is {org!r}: the "
                "controllers refuse it. Its day-0 (vinitparam org) must name the overlay's org."
            )
        validity = str(v.get("validity") or "")
        if validity == "valid":
            steps.append({"step": "validity", "status": "done already", "validity": "valid"})
        else:
            step = {
                "step": "validity",
                "action": f"{validity or '?'} -> valid: POST {SAVE_VALIDITY_PATH}, then POST "
                f"{PUSH_VEDGES_PATH}?action=push (send to controllers)",
            }
            if validity == "staging":
                step["note"] = "staging: it could join the controllers but had no data plane"
            steps.append(step)
        for other in devices:
            if str(other.get("system-ip")) == ip and str(other.get("uuid")) != c:
                blockers.append(f"system IP {ip} is already {other.get('host-name') or other.get('uuid')}'s")
            if str(other.get("host-name")) == hostname and str(other.get("uuid")) != c:
                warnings.append(f"host name {hostname} is already used by {other.get('system-ip')}")
        if joined:
            for k, want, have in (
                ("host name", hostname, v.get("host-name")),
                ("system IP", ip, v.get("system-ip")),
                ("site id", str(site_id), v.get("site-id")),
            ):
                if have not in (None, "") and str(have) != str(want):
                    warnings.append(
                        f"{c} has joined as {k} {have}; this sets {want}, applied at the next push"
                    )
        mode, mode_name = config_mode(v) if find_edge(vedges, c) else (None, None)
        values = {
            GROUP_KEYS["hostname"]: hostname,
            GROUP_KEYS["system_ip"]: ip,
            GROUP_KEYS["site_id"]: site_id,
        }
        values.update(variables or {})
        fingerprint: dict[str, Any] = {
            "edge": {
                k: v.get(k)
                for k in ("validity", "vedgeCertificateState", "managed-by", "configOperationMode")
            }
        }
        group_ctx: dict[str, Any] = {}
        tpl_ctx: dict[str, Any] = {}
        if config_group:
            found = resolve_group(await _groups(app, CONFIG_GROUPS_PATH), config_group)
            gid, gname = str(found.get("id")), str(found.get("name"))
            group_ctx = {"id": gid, "name": gname, "solution": found.get("solution") or "sdwan"}
            assoc = {str(a.get("chassis")) for a in await _associated(app, gid)}
            if mode == "template":
                blockers.append(
                    f"{c} is attached to device template {mode_name or '?'}: a device is in a configuration "
                    "group or on a template, never both (detach it first)"
                )
            elif mode == "configuration group" and mode_name and mode_name != gname:
                blockers.append(f"{c} is in configuration group {mode_name}: remove it from that group first")
            if c in assoc:
                steps.append({"step": "associate", "status": "done already", "group": gname})
                try:
                    body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": c})
                    current = device_variable_lists(body).get(c, [])
                except UpstreamError as e:
                    current = []
                    warnings.append(f"device variables not read: {str(e)[:200]}")
                _, changes, unknown = merge_variables(current, values) if current else ({}, {}, [])
                if unknown:
                    have = ", ".join(sorted(str(x["name"]) for x in current))
                    blockers.append(f"group {gname} has no variable {', '.join(map(repr, unknown))} ({have})")
                steps.append(
                    {
                        "step": "variables",
                        "action": f"PUT {VARIABLES_PATH} (every variable of the device)",
                        "changes": shown_changes(changes)
                        if current
                        else {n: masked(n, x) for n, x in values.items()},
                    }
                )
                fingerprint["variables"] = current
            else:
                steps.append(
                    {
                        "step": "associate",
                        "action": f"POST {ASSOCIATE_PATH} {{devices: [{{id: {c}}}]}}",
                        "group": gname,
                    }
                )
                steps.append(
                    {
                        "step": "variables",
                        "action": f"GET then PUT {VARIABLES_PATH} (after the association: every variable)",
                        "set": {n: masked(n, x) for n, x in values.items()},
                        "note": "a variable the group doesn't have stops the run at this step",
                    }
                )
            fingerprint["group"] = [found.get("lastUpdatedOn"), sorted(assoc)]
        else:
            body = await app.api.get(DEVICE_TEMPLATES_PATH, {"feature": "all"})
            raw = [
                t
                for t in _as_list(body.get("data") if isinstance(body, dict) else body)
                if isinstance(t, dict)
            ]
            tpl = resolve_group(
                [{**t, "id": t.get("templateId"), "name": t.get("templateName")} for t in raw],
                str(template),
                "device template",
            )
            tid, tname = str(tpl["id"]), str(tpl["name"])
            is_cli = str(tpl.get("configType")) == "file"
            if mode == "configuration group":
                blockers.append(
                    f"{c} is in configuration group {mode_name or '?'}: a device is in a group or on a "
                    "template, never both (remove it from the group first)"
                )
            if (
                tpl.get("deviceType")
                and v.get("deviceModel")
                and str(v["deviceModel"]) != str(tpl["deviceType"])
            ):
                blockers.append(f"{c} is a {v['deviceModel']}; template {tname} is for {tpl['deviceType']}")
            row: dict[str, Any] | None = None
            onboard_values = {"hostname": hostname, "system_ip": ip, "site_id": site_id}
            if not upload and not blockers:
                row, shown, problems = await _template_row(app, tid, tname, c, onboard_values, variables)
                blockers += problems
                if shown:
                    tpl_ctx["shown"] = shown
            tpl_ctx.update({"id": tid, "name": tname, "cli": is_cli, "row": row, "values": onboard_values})
            steps.append(
                {
                    "step": "attach template",
                    "action": f"POST {ATTACH_CLI_PATH if is_cli else ATTACH_FEATURE_PATH} ({tname})",
                    **({"values": tpl_ctx["shown"]} if tpl_ctx.get("shown") else {}),
                    "note": "the Manager keeps the configuration and pushes it when the edge joins"
                    if not joined
                    else "pushes the template to the running edge now",
                }
            )
            fingerprint["template"] = [tpl.get("lastUpdatedOn"), tpl_ctx.get("shown")]
        blockers += dangerous_blockers(
            ctx,
            app,
            reasons := tier_reasons(
                [protected_row({**v, "site-id": site_id}, hostname, ip)],
                app.settings.hub_devices,
                app.settings.protected_sites,
            ),
        )
        plan = Plan(
            f"Onboard {c} as {hostname} ({ip}, site {site_id}) with "
            + (
                f"configuration group {group_ctx['name']}"
                if group_ctx
                else f"device template {tpl_ctx['name']}"
            ),
            details={
                "edge": edge_row(v, org) if find_edge(vedges, c) else {"chassis": c, "in_list": False},
                "tier": "dangerous" if reasons else "write",
                **({"tier_reasons": reasons} if reasons else {}),
                "steps": steps,
                "then": boot_routes(c),
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Validity valid lets the chassis join the overlay as soon as a device presents its token.",
                "Configuration-group edges get no configuration until catsdwan_deploy_config_group.",
            ],
            fingerprint=fingerprint,
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            done: list[dict[str, Any]] = []
            todo = [s["step"] for s in steps if s.get("status") != "done already"]

            def stop(step: str, reason: str) -> dict[str, Any]:
                rest = todo[todo.index(step) + 1 :] if step in todo else []
                return {
                    "outcome": "stopped",
                    "failed_step": step,
                    "reason": reason,
                    "steps": done,
                    "not_run": rest,
                }

            edge = v
            if upload:
                content, ctype = serial_file_body(*upload)
                try:
                    answer = await app.api.post(
                        FILEUPLOAD_PATH, None, content=content, headers={"Content-Type": ctype}
                    )
                except UpstreamError as e:
                    return stop("upload serial file", str(e)[:300])
                done.append({"step": "upload serial file", "status": "done", **upload_summary(answer)})
                found_now = find_edge(await _wan_edges(app), chassis)
                if found_now is None:
                    return stop(
                        "upload serial file",
                        f"{chassis} is not in the WAN edge list after the upload: the file does not carry it",
                    )
                edge = found_now
            if str(edge.get("validity")) != "valid":
                try:
                    res = await _push_validity(app, ctx, edge, "valid", wait)
                except UpstreamError as e:
                    return stop("validity", str(e)[:300])
                if bad := _failed(res):
                    return stop("validity", bad)
                done.append({"step": "validity", "status": "done", **res})
            if group_ctx:
                gid, gname = group_ctx["id"], group_ctx["name"]
                if c not in {str(a.get("chassis")) for a in await _associated(app, gid)}:
                    try:
                        await app.api.post(path(ASSOCIATE_PATH, id=gid), {"devices": [{"id": c}]})
                    except UpstreamError as e:
                        return stop("associate", str(e)[:300])
                    done.append({"step": "associate", "status": "done", "group": gname})
                try:
                    body = await app.api.get(path(VARIABLES_PATH, id=gid), {"device-id": c})
                    current = device_variable_lists(body).get(c, [])
                except UpstreamError as e:
                    return stop("variables", f"device variables not read: {str(e)[:300]}")
                if not current:
                    return stop("variables", f"the Manager returned no variables for {c} in {gname}")
                merged, changes, unknown = merge_variables(current, values)
                if unknown:
                    have = ", ".join(sorted(str(x["name"]) for x in current))
                    return stop(
                        "variables", f"group {gname} has no variable {', '.join(map(repr, unknown))} ({have})"
                    )
                if changes:
                    try:
                        await app.api.put(
                            path(VARIABLES_PATH, id=gid),
                            {
                                "solution": group_ctx["solution"],
                                "devices": [{"device-id": c, "variables": merged}],
                            },
                        )
                    except UpstreamError as e:
                        return stop("variables", str(e)[:300])
                done.append({"step": "variables", "status": "done", "stored": shown_changes(changes)})
                nxt = (
                    f"Once {hostname} has joined: catsdwan_deploy_config_group(group={gname!r}, "
                    f"devices=[{hostname!r}]) pushes the group (preview first)."
                )
            else:
                attach = ATTACH_CLI_PATH if tpl_ctx["cli"] else ATTACH_FEATURE_PATH
                row = tpl_ctx["row"]
                if row is None:  # the edge was only just uploaded: its template input exists now
                    try:
                        row, _, problems = await _template_row(
                            app, tpl_ctx["id"], tpl_ctx["name"], c, tpl_ctx["values"], variables
                        )
                    except UpstreamError as e:
                        return stop("attach template", str(e)[:300])
                    if row is None or problems:
                        return stop("attach template", "; ".join(problems))
                push = {
                    "deviceTemplateList": [
                        {
                            "templateId": tpl_ctx["id"],
                            "device": [{**row, "selected": "true"}],
                            "isEdited": False,
                            "isMasterEdited": False,
                            "isDraftDisabled": False,
                        }
                    ]
                }
                try:
                    started = await app.api.post(attach, push)
                    res = await _started(app, ctx, started, wait, f"attach of {tpl_ctx['name']}")
                except UpstreamError as e:
                    return stop("attach template", str(e)[:300])
                if bad := _failed(res):
                    return stop("attach template", bad)
                done.append({"step": "attach template", "status": "done", **res})
                nxt = f"The Manager pushes template {tpl_ctx['name']} when {hostname} joins."
            return {
                "outcome": "done",
                "steps": done,
                "next": [nxt, *boot_routes(c)],
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_onboard_edge",
            args={
                "chassis": chassis,
                "hostname": hostname,
                "system_ip": system_ip,
                "site_id": site_id,
                "config_group": config_group,
                "template": template,
                "variables": variables,
                "serial": serial,
                "serial_file": serial_file,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set SD-WAN WAN edge validity", destructive=True, task=True)
    async def catsdwan_set_edge_validity(
        ctx: Context,
        chassis: Chassis,
        validity: Annotated[
            Validity,
            Field(
                description="valid (may join), invalid (refused; a joined edge drops its control "
                "connections) or staging (joins the controllers, no data plane)"
            ),
        ],
        wait: Annotated[
            bool, Field(description="Wait for the controllers to take the list (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a WAN edge's validity in the Manager's WAN edge list and send the list to the controllers
        (POST /certificate/save/vedge/list, then /certificate/vedge/list?action=push, followed to the end).
        valid lets it join; invalid makes the validator refuse it and drops a joined edge's control
        connections and tunnels; staging lets it join the controllers without a data plane. Preview-first,
        with the edge's site. invalid, staging on a joined edge, and any change to a hub or a protected-site
        edge are dangerous (MCP_ENABLE_DANGEROUS); valid is write tier. Undo: the same call with the previous
        validity."""
        app: SdwanApp = get_client(ctx)
        v = edge_or_not_found(await _wan_edges(app), chassis)
        c = chassis_of(v)
        joined = is_joined(v)
        old = str(v.get("validity") or "")
        blockers: list[str] = []
        if old == validity:
            blockers.append(f"{c} is {validity} already: nothing to change")
        reasons: list[str] = []
        if validity == "invalid":
            reasons.append(
                f"invalid refuses {_site_note(v)}"
                + (": its control connections and tunnels drop" if joined else " when it tries to join")
            )
        elif validity == "staging" and joined:
            reasons.append(f"staging drops the data plane of {_site_note(v)}")
        reasons += tier_reasons([protected_row(v)], app.settings.hub_devices, app.settings.protected_sites)
        blockers += dangerous_blockers(ctx, app, reasons)
        plan = Plan(
            f"Set {c} ({v.get('host-name') or 'not joined'}) {old or '?'} -> {validity} and send the WAN "
            "edge list to the controllers",
            details={
                "edge": edge_row(v),
                "site": v.get("site-id"),
                "tier": "dangerous" if reasons else "write",
                **({"tier_reasons": reasons} if reasons else {}),
                "effect": VALIDITY_EFFECT[validity],
                "requests": [
                    f"POST {SAVE_VALIDITY_PATH} [{{chasisNumber, serialNumber, validity: {validity}}}]",
                    f"POST {PUSH_VEDGES_PATH}?action=push (send to controllers; an action, followed)",
                ],
                "undo": f"catsdwan_set_edge_validity(chassis={c!r}, validity={old!r})",
            },
            side_effects=[VALIDITY_EFFECT[validity]],
            fingerprint={k: v.get(k) for k in ("validity", "vedgeCertificateState", "system-ip")},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            res = await _push_validity(app, ctx, v, validity, wait)
            res["validity"] = {"from": old, "to": validity}
            if validity == "invalid" and joined:
                res["check"] = f"catsdwan_control_connections(device={c!r}): its connections go down"
            elif validity == "valid":
                res["check"] = f"catsdwan_control_connections(device={c!r}): its connections come (back) up"
            return res

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_edge_validity",
            args={"chassis": chassis, "validity": validity, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
