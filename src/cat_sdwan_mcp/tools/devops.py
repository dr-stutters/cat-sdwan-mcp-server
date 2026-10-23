"""W12 device operations: catsdwan_list_software, catsdwan_list_device_actions (reads),
catsdwan_reboot_devices and catsdwan_upgrade_software (always dangerous).

The two actions are the Manager's most disruptive operations: dangerous tier with MCP_ENABLE_DANGEROUS; with
writes on but dangerous changes off they are listed and their previews refuse with the reason. Every preview
names each device's site and role (hub per CATSDWAN_HUB_DEVICES), reports `blast_radius` = the devices (so
MCP_MAX_BLAST_RADIUS, change windows and two-person approval apply), and refuses two edges of one site in a
single run. Confirm starts the action and follows /device/action/status/{id} to success or failure per device.
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
from cat_sdwan_mcp.changes import (
    ACTION_STATUS_PATH,
    RUNNING_TASKS_PATH,
    action_outcome,
    action_progress,
    protection,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.devops import (
    ACTION_LIST_PATH,
    CHANGE_PARTITION_PATH,
    INSTALL_PATH,
    MIN_FREE_MB,
    REBOOT_ACTION_PATH,
    SOFTWARE_IMAGES_PATH,
    SOFTWARE_REPO_PATH,
    WARN_FREE_MB,
    action_type_row,
    change_partition_body,
    disk_mb,
    dual_edge_blockers,
    family_of,
    find_version,
    install_body,
    installed,
    newer_than,
    reboot_body,
    repo_row,
    rows,
    same_version,
    started_ms,
    task_row,
    train,
    train_text,
)
from cat_sdwan_mcp.fabric import fan_out, is_reachable, safely
from cat_sdwan_mcp.inventory import (
    REBOOT_PATH,
    SOFTWARE_PATH,
    STATUS_PATH,
    Inventory,
    load_inventory,
    matches_site,
    reboots,
    resolve,
)
from cat_sdwan_mcp.tools.changes import (
    _pending_blockers,
    _reachability_blockers,
    _started,
    dangerous_blockers,
    dangerous_tool,
)

MAX_TASK_DETAILS = 10
DeviceList = Annotated[
    list[str],
    Field(min_length=1, max_length=50, description="Devices by host name, system IP or chassis number"),
]
Wait = Annotated[bool, Field(description="Wait for every device to report success or failure (default true)")]
TASK_COLUMNS = ["action", "status", "started", "user", "progress", "process_id"]


def _resolve_targets(inv: Inventory, refs: list[str]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for ref in refs:
        row = resolve(inv, ref)
        if not row.get("system_ip") or not row.get("chassis"):
            raise InvalidRequest(
                f"{ref!r} has not joined the fabric (no system IP): the Manager can't act on it."
            )
        out[str(row["chassis"])] = row
    return list(out.values())


def _role(row: dict[str, Any], hubs: str | None, sites: str | None) -> str:
    why = protection(row, hubs, sites)
    if any("hub" in w for w in why):
        return "hub"
    return str(row.get("role") or "device")


def _brief(row: dict[str, Any], hubs: str | None, sites: str | None) -> dict[str, Any]:
    out = {
        "host": row.get("host"),
        "system_ip": row.get("system_ip"),
        "site": row.get("site_id"),
        "role": _role(row, hubs, sites),
        "model": row.get("model"),
        "version": row.get("version"),
        "up_since": row.get("up_since"),
    }
    prot = [w for w in protection(row, hubs, sites) if "hub" not in w]
    if prot:
        out["protected"] = prot
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _manager_version(inv: Inventory) -> str | None:
    found = sorted({str(r["version"]) for r in inv.rows if r.get("role") == "manager" and r.get("version")})
    return found[0] if found else None


def _ceiling(inv: Inventory) -> str | None:
    """The oldest Manager or controller version: no edge may run a newer release train."""
    versions = [
        str(r["version"]) for r in inv.rows if r.get("role") in ("manager", "controller") and r.get("version")
    ]
    known = [v for v in versions if train(v) is not None]
    return min(known, key=lambda v: train(v) or (0, 0)) if known else None


async def _realtime(app: SdwanApp, rows_: list[dict[str, Any]], what: str) -> dict[str, Any]:
    """{system_ip: rows or UpstreamError} for one real-time read on each reachable device."""
    reachable = [r for r in rows_ if is_reachable(r)]

    async def one(r: dict[str, Any]) -> list[dict[str, Any]]:
        return rows(await app.get_data(what, {"deviceId": r["system_ip"]}))

    got = await fan_out(reachable, one)
    return {str(r["system_ip"]): g for r, g in zip(reachable, got, strict=True)}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List SD-WAN software")
    async def catsdwan_list_software(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Only this device (host name, system IP or chassis)")
        ] = None,
        site: Annotated[str | None, Field(description="Only the edges of this site (id or name)")] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="Edges per page")] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Software: the Manager's image repository (GET /device/action/software: version, the controller
        release it needs, files; and /software/images), and per edge what it runs and has installed (read live
        from each reachable edge: active, default, other installed versions), plus the release ceiling (edges
        never run a newer release train than the Manager and controllers: IOS XE 17.18 with Manager 20.18).
        An empty repository is said plainly: catsdwan_upgrade_software needs the image there first."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        repo_body, images_body = await asyncio.gather(
            safely(app.api.get(SOFTWARE_REPO_PATH), f"GET {SOFTWARE_REPO_PATH}"),
            safely(app.api.get(SOFTWARE_IMAGES_PATH), f"GET {SOFTWARE_IMAGES_PATH}"),
        )
        out: dict[str, Any] = {
            "manager": _manager_version(inv),
            "ceiling": (
                f"edges may run up to release {train_text(train(_ceiling(inv)))} (the oldest Manager or "
                f"controller: {_ceiling(inv)}); never newer"
            ),
        }
        warnings: list[str] = list(inv.warnings)
        for key, body, what in (
            ("repository", repo_body, "versions"),
            ("images", images_body, "image files"),
        ):
            if isinstance(body, dict) and "error" in body and len(body) == 1:
                warnings.append(str(body["error"]))
                continue
            listed = [repo_row(r) for r in rows(body)]
            out[key] = (
                listed or f"no {what}: the software repository is empty (Maintenance > Software Repository)"
            )
        edges = [r for r in inv.rows if r.get("role") == "edge"]
        if device:
            edges = [resolve(inv, device)]
        elif site:
            edges = [r for r in edges if matches_site(r, site)]
            if not edges:
                raise InvalidRequest(f"No edge is at site {site!r}.")
        all_edges = edges
        edges = edges[offset : offset + limit]
        live = await _realtime(app, edges, SOFTWARE_PATH)
        devices = []
        for r in edges:
            row: dict[str, Any] = {
                "host": r.get("host"),
                "site": r.get("site_id"),
                "running": r.get("version"),
            }
            got = live.get(str(r.get("system_ip")))
            if got is None:
                row["installed"] = f"not read: {r.get('host')} is {r.get('reachability') or 'not joined'}"
            elif isinstance(got, UpstreamError):
                row["installed"] = f"not read: {str(got)[:200]}"
            else:
                versions = installed(got)
                row["installed"] = [v["version"] for v in versions]
                row["default"] = next((v["version"] for v in versions if v["default"]), None)
                row["active"] = next((v["version"] for v in versions if v["active"]), None)
            devices.append({k: v for k, v in row.items() if v not in (None, "")})
        out["devices"] = devices
        if len(all_edges) > len(edges):
            out["devices_shown"] = f"{offset + 1}-{offset + len(edges)} of {len(all_edges)} (limit, offset)"
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt=response_format)

    @reg.read(title="List SD-WAN device actions")
    async def catsdwan_list_device_actions(
        ctx: Context,
        since_hours: Annotated[
            int | None, Field(ge=1, le=720, description="Only actions started in the last N hours")
        ] = None,
        name: Annotated[
            str | None, Field(description="Action name contains, e.g. 'install', 'reboot'")
        ] = None,
        detail: Annotated[
            bool, Field(description="Read each action's per-device progress (up to 10 actions; default true)")
        ] = True,
        show_types: Annotated[
            bool, Field(description="Also list the action types the Manager knows (GET /device/action/list)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's running actions (GET /device/action/status/tasks: upgrades, reboots, template pushes,
        policy activations ... started by anyone, here or in the GUI), each with its per-device progress
        (GET /device/action/status/{id}: succeeded, failed, running, and the failing device's reason).
        Finished actions leave this list: catsdwan_audit_log shows them. `show_types` adds the action types
        (name, cancellable, runs in parallel)."""
        app: SdwanApp = get_client(ctx)
        body = await app.api.get(RUNNING_TASKS_PATH)
        tasks = rows(body.get("runningTasks") if isinstance(body, dict) and "runningTasks" in body else body)
        if since_hours:
            cutoff = (time.time() - since_hours * 3600) * 1000
            tasks = [t for t in tasks if started_ms(t) >= cutoff or not started_ms(t)]
        if name:
            tasks = [t for t in tasks if name.lower() in str(t.get("name") or t.get("action") or "").lower()]
        tasks.sort(key=started_ms, reverse=True)
        out = [task_row(t) for t in tasks]
        extra: dict[str, Any] = {"source": f"GET {RUNNING_TASKS_PATH}"}
        if detail and out:
            ids = [str(r["process_id"]) for r in out[:MAX_TASK_DETAILS] if r.get("process_id")]
            got = await asyncio.gather(
                *(safely(app.api.get(path(ACTION_STATUS_PATH, id=i)), f"status {i}") for i in ids)
            )
            for r, status in zip(out, got, strict=False):
                if isinstance(status, dict) and "error" in status and len(status) == 1:
                    r["progress"] = status["error"]
                    continue
                r["progress"] = action_progress(status)
                r["devices"] = action_outcome(status, str(r.get("process_id")))["devices"]
        if not out:
            extra["note"] = (
                "No action is running on the Manager. Finished ones: catsdwan_audit_log(changes_only=true)."
            )
        if show_types:
            types = await safely(app.api.get(ACTION_LIST_PATH), f"GET {ACTION_LIST_PATH}")
            if isinstance(types, dict) and "error" in types and len(types) == 1:
                extra["action_types"] = types["error"]
            else:
                extra["action_types"] = [action_type_row(a) for a in rows(types)]
        return list_result(
            page_of(out, limit=limit, offset=offset), fmt=response_format, columns=TASK_COLUMNS, extra=extra
        )

    @dangerous_tool(reg, title="Reboot SD-WAN devices", task=True)
    async def catsdwan_reboot_devices(
        ctx: Context, devices: DeviceList, wait: Wait = True, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Reboot edges or controllers (POST /device/action/reboot {action: reboot, deviceType, devices:
        [{deviceIP, deviceId}]}), then follow the action to success or failure per device. Always dangerous:
        every tunnel, control connection and service on the device drops for several minutes. Preview-first:
        each device's site, role (hub per CATSDWAN_HUB_DEVICES), version, uptime and last reboots;
        `blast_radius` = the devices. Blocked for the Manager itself, an unreachable device, a device with an
        action still running, and two edges of the same site in one run. Edges and controllers go in separate
        calls. Afterwards: catsdwan_control_connections(device) shows the connections come back."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        targets = _resolve_targets(inv, devices)
        hubs, sites = app.settings.hub_devices, app.settings.protected_sites
        if any(r.get("role") == "manager" for r in targets):
            raise InvalidRequest("This tool doesn't reboot the Manager (the API goes down with it).")
        kinds = {r.get("role") == "edge" for r in targets}
        if len(kinds) > 1:
            raise InvalidRequest(
                "Reboot edges and controllers in separate calls (the Manager takes one device type)."
            )
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        blockers += _reachability_blockers(targets)
        blockers += dual_edge_blockers(targets, inv.rows, "reboot")
        busy, busy_warn = await _pending_blockers(app, targets)
        blockers += busy
        warnings += busy_warn
        reasons = [
            f"a reboot takes {len(targets)} device(s) off the fabric for several minutes: every tunnel and "
            "control connection on them drops"
        ]
        reasons += [f"{r.get('host')} is {w}" for r in targets for w in protection(r, hubs, sites)]
        blockers += dangerous_blockers(ctx, app, reasons)
        history = await _realtime(app, targets, REBOOT_PATH)
        views = []
        for r in targets:
            view = _brief(r, hubs, sites)
            got = history.get(str(r.get("system_ip")))
            if isinstance(got, list):
                view["last_reboots"] = reboots(got, keep=2)
            views.append(view)
        body = reboot_body(targets)
        plan = Plan(
            f"Reboot {len(targets)} device(s): " + ", ".join(str(r.get("host")) for r in targets),
            details={
                "tier": "dangerous",
                "tier_reasons": reasons,
                "devices": views,
                "request": f"POST {REBOOT_ACTION_PATH} {{action: reboot, deviceType: {body['deviceType']}, "
                "devices: [{deviceIP, deviceId}]}",
                "after": "catsdwan_control_connections(device) until the connections are up again; "
                "catsdwan_bfd_sessions(device) for the tunnels",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Each device reloads: its tunnels, control connections and every service behind it are down "
                "until it is back (several minutes on a C8000V).",
                *(
                    ["A hub reboot cuts every branch that reaches the others through it."]
                    if any(v["role"] == "hub" for v in views)
                    else []
                ),
            ],
            fingerprint={str(r["chassis"]): [r.get("up_since"), r.get("reachability")] for r in targets},
            blockers=blockers,
            blast_radius=len(targets),
        )

        async def apply() -> Any:
            answer = await app.api.post(REBOOT_ACTION_PATH, body)
            res = await _started(app, ctx, answer, wait, f"reboot of {len(targets)} device(s)")
            res["check"] = [f"catsdwan_control_connections(device={str(r.get('host'))!r})" for r in targets]
            return res

        return await preview_or_apply(
            ctx,
            tool="catsdwan_reboot_devices",
            args={"devices": devices, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @dangerous_tool(reg, title="Upgrade SD-WAN software", task=True)
    async def catsdwan_upgrade_software(
        ctx: Context,
        devices: DeviceList,
        version: Annotated[
            str, Field(description="Version from the repository (catsdwan_list_software), e.g. '17.18.03'")
        ],
        activate: Annotated[
            bool,
            Field(
                description="Activate the new version after the install: the edge reboots into it (default "
                "false: install only, activate later with activate=true)"
            ),
        ] = False,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Install a software version on edges from the Manager's repository (POST /device/action/install
        {action: install, input: {data: [{family, version, versionId}], versionType, reboot, sync}, devices}),
        optionally activating it (the edge reboots into it); a version already installed is only activated
        (POST /device/action/changepartition). Followed per device to success or failure with the failing
        device's reason. Always dangerous. Preview-first, blocked when: the version isn't in the repository
        (an empty repository says so), it belongs to a newer release train than the Manager and controllers
        (edges never run newer than the Manager), the image needs newer controllers, an edge runs it already,
        has under 1 GB free on bootflash, is unreachable or busy, or two edges of the same site are in one
        run. Controllers are upgraded from the Manager's GUI, not here."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        targets = _resolve_targets(inv, devices)
        hubs, sites = app.settings.hub_devices, app.settings.protected_sites
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        not_edges = [str(r.get("host")) for r in targets if r.get("role") != "edge"]
        if not_edges:
            blockers.append(
                f"{', '.join(not_edges)}: only WAN edges are upgraded with this tool (controllers and the "
                "Manager are upgraded from the Manager's GUI, in their own order)"
            )
        repo_body, images_body = await asyncio.gather(
            safely(app.api.get(SOFTWARE_REPO_PATH), f"GET {SOFTWARE_REPO_PATH}"),
            safely(app.api.get(SOFTWARE_IMAGES_PATH), f"GET {SOFTWARE_IMAGES_PATH}"),
        )
        repo: list[dict[str, Any]] = []
        for body in (repo_body, images_body):
            if isinstance(body, dict) and "error" in body and len(body) == 1:
                warnings.append(str(body["error"]))
            else:
                repo += rows(body)
        entry, names = find_version(repo, version)
        if not repo:
            blockers.append(
                "the Manager's software repository is empty (GET /device/action/software and "
                "/software/images list no images): add the image under Maintenance > Software Repository "
                "first"
            )
        elif entry is None:
            blockers.append(
                f"{version} is not in the software repository (it has: "
                f"{', '.join(sorted(set(names))) or 'none'})"
            )
        target_version = str(entry.get("versionName")) if entry else version
        ceiling = _ceiling(inv)
        if newer_than(target_version, ceiling):
            blockers.append(
                f"{target_version} is release {train_text(train(target_version))}, newer than the Manager "
                f"and controllers ({ceiling}, release {train_text(train(ceiling))}): edges never run newer "
                "than the Manager; upgrade the controllers first"
            )
        needs = entry.get("controllerVersionName") if entry else None
        if needs and newer_than(needs, ceiling):
            blockers.append(f"the image needs controllers at {needs} or later; they run {ceiling}")
        blockers += _reachability_blockers(targets)
        blockers += dual_edge_blockers(targets, inv.rows, "upgrade")
        busy, busy_warn = await _pending_blockers(app, targets)
        blockers += busy
        warnings += busy_warn
        edge_rows = [r for r in targets if r.get("role") == "edge"]
        software, status = await asyncio.gather(
            _realtime(app, edge_rows, SOFTWARE_PATH), _realtime(app, edge_rows, STATUS_PATH)
        )
        views = []
        installed_everywhere = True
        for r in targets:
            ip = str(r.get("system_ip"))
            view = _brief(r, hubs, sites)
            if r.get("version") and same_version(r["version"], target_version):
                blockers.append(f"{r.get('host')} runs {r['version']} already")
            sw = software.get(ip)
            if isinstance(sw, list):
                have = [v["version"] for v in installed(sw)]
                view["installed"] = have
                if not any(same_version(v, target_version) for v in have):
                    installed_everywhere = False
            else:
                installed_everywhere = False
                if isinstance(sw, UpstreamError):
                    warnings.append(f"{r.get('host')}: installed software not read: {str(sw)[:150]}")
            st = status.get(ip)
            free = disk_mb(st[0].get("disk_avail")) if isinstance(st, list) and st else None
            if free is None:
                warnings.append(
                    f"{r.get('host')}: free disk not read; the install fails if bootflash is full"
                )
            else:
                view["bootflash_free_mb"] = round(free)
                if free < MIN_FREE_MB:
                    blockers.append(
                        f"{r.get('host')} has {round(free)} MB free on bootflash (under {MIN_FREE_MB} MB): "
                        "clean up old images first (request platform software package clean)"
                    )
                elif free < WARN_FREE_MB:
                    warnings.append(f"{r.get('host')} has only {round(free)} MB free on bootflash")
            views.append(view)
        only_activate = bool(entry) and activate and installed_everywhere
        family = (
            (entry or {}).get("platformFamily")
            or (entry or {}).get("family")
            or (family_of(targets[0]) or "")
        )
        if entry and not ((entry or {}).get("platformFamily") or (entry or {}).get("family")):
            warnings.append(
                f"the repository row names no platform family; using {family!r} from the device model"
            )
        if only_activate:
            body = change_partition_body(targets, target_version)
            request = f"POST {CHANGE_PARTITION_PATH} (the version is installed already: activate only)"
        else:
            body = install_body(targets, entry or {"versionName": target_version}, family, activate)
            request = f"POST {INSTALL_PATH} (install{', activate and reboot' if activate else ' only'})"
        reasons = [
            f"a software {'activation reboots' if activate else 'install loads'} {len(targets)} edge(s)"
            + (": each reboots into the new version" if activate else "")
        ]
        reasons += [f"{r.get('host')} is {w}" for r in targets for w in protection(r, hubs, sites)]
        blockers += dangerous_blockers(ctx, app, reasons)
        verb = "Activate" if only_activate else "Install and activate" if activate else "Install"
        plan = Plan(
            f"{verb} {target_version} on {len(targets)} edge(s): "
            + ", ".join(str(r.get("host")) for r in targets),
            details={
                "tier": "dangerous",
                "tier_reasons": reasons,
                "version": repo_row(entry) if entry else target_version,
                "ceiling": f"{ceiling} (release {train_text(train(ceiling))})",
                "devices": views,
                "request": request,
                "body": body,
                "rollback": "Activate the previous version again (catsdwan_upgrade_software with that "
                "version and activate=true: it is still installed) - the edge reboots back into it.",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Each edge reboots into the new version (several minutes down)."
                if activate
                else "Copies the image to each edge (bandwidth on the WAN); nothing reboots until "
                "activation.",
            ],
            fingerprint={
                "version": (entry or {}).get("versionId") or target_version,
                "devices": {str(r["chassis"]): [r.get("version"), r.get("reachability")] for r in targets},
            },
            blockers=blockers,
            blast_radius=len(targets),
        )

        async def apply() -> Any:
            answer = await app.api.post(CHANGE_PARTITION_PATH if only_activate else INSTALL_PATH, body)
            res = await _started(
                app, ctx, answer, wait, f"software {'activation' if only_activate else 'install'}"
            )
            res["check"] = "catsdwan_list_software(device=...) for the installed and active versions"
            return res

        return await preview_or_apply(
            ctx,
            tool="catsdwan_upgrade_software",
            args={"devices": devices, "version": version, "activate": activate, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
