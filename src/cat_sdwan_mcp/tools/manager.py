"""W25 Manager operations: catsdwan_manager_health, catsdwan_list_backups, catsdwan_create_backup."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import time
import uuid
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
    poll_until,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.manager import (
    BACKUP_DONE,
    BACKUP_EXPORT_PATH,
    BACKUP_FAILED,
    BACKUP_INFO_PATH,
    BACKUP_LIST_PATH,
    BACKUP_RUNNING,
    CLUSTER_LIST_PATH,
    DR_HISTORY_PATH,
    DR_STATUS_PATH,
    HEALTH_DETAILS_PATH,
    HEALTH_STATUS_PATH,
    HEALTH_SUMMARY_PATH,
    RESOURCES_PATH,
    SCHEDULE_CREATE_PATH,
    SCHEDULE_LIST_PATH,
    SERVER_INFO_PATH,
    STATS_SETTINGS_PATH,
    TASK_NAME_RE,
    active_schedule,
    backup_addresses,
    backup_destination,
    backup_row,
    backup_rows,
    backup_state,
    cluster_ip_configured,
    cluster_nodes,
    detail_rows,
    dr_state,
    export_error,
    export_id,
    resources,
    schedule_rows,
    server_info,
    services,
    statistics_processing,
    summary_rows,
    vm_version,
)

POLL_INTERVAL = 10.0  # seconds between backup-state reads (tests set it to 0)
# The Manager writes the LocalBackupInfo record to its config DB a few seconds after /backup/export returns:
# until then GET /backup/backupinfo/{id} answers 404 LOCALBK_ID_NOT_FOUND (recorded on 20.18.3.1, #165).
RECORD_GRACE = 60.0  # seconds after the export call that a 404 on the record still means "pending"
MEMORY_WARN = 90.0  # JVM memory % named in the verdict
BACKUP_COLUMNS = ["created", "task", "type", "state", "file", "id"]
BUSY_WARNING = (
    "The Manager exports its configuration database and statistics while the backup runs: the GUI and API "
    "are slower, and statistics collection may lag. Run it outside busy hours on a large fabric."
)


async def _get(app: SdwanApp, path: str) -> Any:
    try:
        return await app.api.get(path)
    except UpstreamError as e:
        return {"error": f"GET {path} failed: {str(e)[:300]}"}


def _err(body: Any) -> str | None:
    return body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else None


async def _release(app: SdwanApp) -> str:
    try:
        return await app.version()
    except UpstreamError:
        return "unknown"


async def _backups(app: SdwanApp) -> list[dict[str, Any]]:
    return backup_rows(await app.api.get(BACKUP_LIST_PATH))


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN Manager health")
    async def catsdwan_manager_health(ctx: Context, response_format: ResponseFormat = "json") -> ToolResult:
        """Is the Manager itself healthy (before any fabric answer)? Cluster nodes with their state and
        persona, the services per node (application server, configuration and OLAP databases, messaging,
        coordination, container manager, SD-AVC) up or down, the cluster health summary and details, JVM and
        third-party memory use with %, CPU count, the statistics indexes and which are not enabled, and
        disaster recovery (configured or not; its switchover history when it is). `verdict` names what is
        down or short. A read that fails is listed in `errors`; the rest still answers."""
        app: SdwanApp = get_client(ctx)
        paths = [
            HEALTH_STATUS_PATH,
            HEALTH_SUMMARY_PATH,
            HEALTH_DETAILS_PATH,
            CLUSTER_LIST_PATH,
            RESOURCES_PATH,
            SERVER_INFO_PATH,
            STATS_SETTINGS_PATH,
            DR_STATUS_PATH,
        ]
        status, summary, details, cluster, res, info, stats, dr = await asyncio.gather(
            *(_get(app, p) for p in paths)
        )
        errors = [
            e for e in (_err(b) for b in (status, summary, details, cluster, res, info, stats, dr)) if e
        ]
        out: dict[str, Any] = {}
        nodes = [] if _err(cluster) else cluster_nodes(cluster)
        svc = [] if _err(status) else services(status)
        out["nodes"] = nodes
        cluster_ip = None if _err(cluster) else cluster_ip_configured(cluster)
        if cluster_ip is not None:
            out["cluster_ip_configured"] = cluster_ip
        out["services"] = svc
        if not _err(summary):
            out["summary"] = summary_rows(summary)
        if not _err(details):
            out["details"] = detail_rows(details)
        if not _err(res):
            out["resources"] = {**resources(res), **({} if _err(info) else server_info(info))}
        if not _err(stats):
            out["statistics_processing"] = statistics_processing(stats)
        dr_info = {"configured": "unknown"} if _err(dr) else dr_state(dr)
        if dr_info.get("configured") is True:
            history = await _get(app, DR_HISTORY_PATH)
            dr_info["history"] = _err(history) or history.get("history", history)
        out["disaster_recovery"] = dr_info
        problems: list[str] = []
        for s in svc:
            if s.get("services_down"):
                problems.append(f"{s['node']}: {', '.join(s['services_down'])} down")
        for n in nodes:
            if n.get("state") and str(n["state"]).lower() != "ready":
                problems.append(f"node {n.get('host') or n.get('address')} is {n['state']}")
        for r in out.get("summary", []):
            problems += r.get("problems", [])
        jvm = out.get("resources", {}).get("jvm_memory", {})
        if jvm.get("used_percent", 0) >= MEMORY_WARN:
            problems.append(f"JVM memory {jvm['used_percent']}% used")
        if cluster_ip is False:
            out["cluster_ip_note"] = (
                "no cluster IP is configured (Administration > Cluster Management): catsdwan_create_backup "
                "needs one"
            )
        if problems:
            out["verdict"] = "attention: " + "; ".join(problems)
        elif svc:
            up = sum(len(s["services_up"]) for s in svc)
            out["verdict"] = (
                f"healthy: {len(nodes) or len(svc)} node(s), {up} service(s) up, none down"
                + (f", JVM memory {jvm['used_percent']}% used" if jvm else "")
                + ("; disaster recovery not configured" if dr_info.get("configured") is False else "")
            )
        else:
            out["verdict"] = "unknown: the service status could not be read"
        if (
            any(d.get("status") == "error" and not d.get("reporters") for d in out.get("details", []))
            and not problems
        ):
            out["note"] = (
                "health/details reports 'error' with no reporter, as a healthy single-node 20.18.3 Manager "
                "does; the services and the summary are what the verdict uses"
            )
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)

    @reg.read(title="List SD-WAN Manager backups")
    async def catsdwan_list_backups(
        ctx: Context,
        limit: Annotated[int, Field(ge=1, le=500)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The Manager's database backups (GET /backup/list), newest first: when, task name, on demand or
        scheduled, state (ALL_SUCCESS, IN_PROGRESS, FAILURE, ...), the file to download and the id, plus the
        backup schedules (GET /schedule/list). With none it says so; catsdwan_create_backup makes one."""
        app: SdwanApp = get_client(ctx)
        rows, sched = await asyncio.gather(_backups(app), _get(app, SCHEDULE_LIST_PATH))
        extra: dict[str, Any] = {}
        schedules = [] if _err(sched) else schedule_rows(sched)
        extra["schedules"] = schedules or "none"
        if _err(sched):
            extra["errors"] = [_err(sched)]
        if not rows:
            extra["note"] = (
                "No backup on the Manager yet. catsdwan_create_backup makes one (preview first); take one "
                "before a change window or an upgrade."
            )
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=BACKUP_COLUMNS,
            extra=extra,
        )

    @reg.write(title="Create SD-WAN Manager backup", task=True)
    async def catsdwan_create_backup(
        ctx: Context,
        task_name: Annotated[
            str, Field(description="A name for the backup task (letters, digits, space, _ - / \\)")
        ] = "catsdwan-mcp backup",
        wait: Annotated[
            bool, Field(description="Follow the backup to ALL_SUCCESS or a failure (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Back up the Manager's configuration database and statistics (POST /backup/export, an on-demand
        backup stored on the Manager's disk), then follow it (GET /backup/backupinfo/{id}) to ALL_SUCCESS or
        a failure with the file to download. The request is the full LocalBackupInfo the Manager needs
        (fresh ids, LOCAL /backup destination with the Manager's release, the nodes' cluster IPs) and names
        the active backup schedule when /schedule/list has one. Preview-first: the preview names the newest
        existing backup and the schedule (or that there is none), warns that the Manager is busy while it
        runs, and blocks while another backup is still running or when no cluster IP is configured. The
        Manager writes the record a few seconds after the export call: a 404 on it counts as pending for the
        first minute (the backup list is checked too). The
        first step of a change window and of controller or edge upgrades. Restores stay in the GUI."""
        if not TASK_NAME_RE.fullmatch(task_name):
            raise InvalidRequest(
                "task_name may hold letters, digits, spaces and _ - / \\ only (the Manager's own rule)."
            )
        app: SdwanApp = get_client(ctx)
        rows, cluster, sched, release = await asyncio.gather(
            _backups(app), app.api.get(CLUSTER_LIST_PATH), _get(app, SCHEDULE_LIST_PATH), _release(app)
        )
        schedule = None if _err(sched) else active_schedule(schedule_rows(sched))
        schedule_id = str(schedule["scheduleId"]) if schedule else None
        version = vm_version(release)
        nodes = cluster_nodes(cluster)
        configured = cluster_ip_configured(cluster)
        src, followers = backup_addresses(nodes)
        running = [r for r in rows if backup_state(r) in BACKUP_RUNNING]
        blockers = [
            f"backup {r.get('task') or r.get('id')} is still {r.get('state')} (started {r.get('created')}): "
            "wait for it (catsdwan_list_backups)"
            for r in running
        ]
        if configured is False or src is None:
            blockers.append(
                "the Manager has no cluster IP configured (Administration > Cluster Management): a backup "
                "needs it (the request names the nodes' cluster IPs; 'localhost' is refused)"
                + (f"; GET {CLUSTER_LIST_PATH} says isIPConfigured false" if configured is False else "")
            )
        newest = next((r for r in rows if backup_state(r) in BACKUP_DONE), None)
        destination = backup_destination(schedule, version)

        def request_body() -> dict[str, Any]:
            # Fresh ids per request: the Manager echoes localBackupInfoId as the answer's backupInfoId.
            body: dict[str, Any] = {
                "backupType": "ON_DEMAND",
                "backupState": "SCHEDULED",
                "taskName": task_name,
                "taskId": str(uuid.uuid4()),
                "localBackupInfoId": str(uuid.uuid4()),
                "createTime": int(time.time() * 1000),
                "srcIpAddress": src,
                "followerIpAddressList": followers,
                "destination": destination,
            }
            if schedule_id:
                body["scheduleId"] = schedule_id
            return body

        shown = {
            **request_body(),
            "taskId": "<new uuid>",
            "localBackupInfoId": "<new uuid>",
            "createTime": "<now, epoch ms>",
        }
        notes: list[str] = []
        if _err(sched):
            notes.append(f"the backup schedules could not be read ({_err(sched)}); the request names none")
        elif schedule is None:
            notes.append(
                "no active backup schedule on the Manager: the request names none, which the Manager accepts "
                "(proven on 20.18.3.1). Only if it refuses: create a local schedule "
                f"(Administration > Backup, or POST {SCHEDULE_CREATE_PATH} with destination.backupDest "
                "LOCAL) and try again"
            )
        if version is None:
            notes.append(f"the Manager's release is {release!r}: destination.vmVersion is left out")
        plan = Plan(
            f"Back up the Manager's configuration database and statistics (task {task_name!r})",
            details={
                "request": f"POST {BACKUP_EXPORT_PATH} {shown}",
                "then": f"GET {BACKUP_INFO_PATH} until ALL_SUCCESS or a failure" if wait else "not followed",
                "newest_backup": newest or "none",
                "existing_backups": len(rows),
                "schedule": (
                    {"id": schedule_id, "name": schedule.get("scheduleName")} if schedule else "none active"
                ),
                "cluster": {"ip_configured": configured, "nodes": nodes},
                "warning": BUSY_WARNING,
                **({"notes": notes} if notes else {}),
            },
            side_effects=[BUSY_WARNING, "The backup file stays on the Manager's disk until it is deleted."],
            fingerprint=[[(r.get("id"), r.get("state")) for r in running], src, followers, schedule_id],
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            started = time.time() * 1000
            body = request_body()
            try:
                answer = await app.api.post(BACKUP_EXPORT_PATH, body)
            except UpstreamError as e:
                reason = export_error(str(e), cluster_ip=configured, schedule=schedule_id)
                if reason is None:
                    raise
                raise UpstreamError(f"Backup not started: {reason}", e.status_code) from e
            # The Manager echoes the localBackupInfoId sent as backupInfoId: that is the record to follow
            # (its taskId is a different id, so it is not used here).
            echoed = {k: v for k, v in (answer if isinstance(answer, dict) else {}).items() if k != "taskId"}
            bid = export_id(echoed) or str(body["localBackupInfoId"])
            out: dict[str, Any] = {"outcome": "started", "task": task_name, "answer": answer}
            out["id"] = bid
            if not wait:
                out["check_with"] = "catsdwan_list_backups"
                return out
            info_path = BACKUP_INFO_PATH.format(id=bid)
            grace_until = time.monotonic() + RECORD_GRACE

            async def fetch() -> dict[str, Any]:
                # The backup's record as a backup row; {} while the Manager has not written it yet.
                try:
                    b = await app.api.get(info_path)
                except UpstreamError as e:
                    if e.status_code != 404:
                        raise
                    # Not in the config DB yet (LOCALBK_ID_NOT_FOUND): look for it in the backup list
                    # (the one catsdwan_list_backups reads), and keep waiting inside the grace window.
                    try:
                        listed = await _backups(app)
                    except UpstreamError:
                        listed = []
                    hit = next((r for r in listed if str(r.get("id")) == bid), None)
                    if hit is not None:
                        return hit
                    if time.monotonic() < grace_until:
                        return {}
                    raise UpstreamError(
                        f"The backup was started (id {bid}) but the Manager still has no record of it "
                        f"{int(RECORD_GRACE)}s later (GET {info_path} and {BACKUP_LIST_PATH}): "
                        f"{str(e)[:300]}. Check catsdwan_list_backups.",
                        404,
                    ) from e
                rec = b.get("data", b) if isinstance(b, dict) else {}
                rec = rec[0] if isinstance(rec, list) and rec else rec
                return backup_row(rec) if isinstance(rec, dict) else {}

            row = await poll_until(
                fetch,
                done=lambda r: backup_state(r) in BACKUP_DONE | BACKUP_FAILED,
                describe=lambda r: f"backup {backup_state(r) or 'pending'}",
                timeout=app.settings.mcp_task_timeout,
                interval=POLL_INTERVAL,
                ctx=ctx,
                what="the backup",
            )
            out.update(row)
            out["outcome"] = "success" if backup_state(row) in BACKUP_DONE else "failed"
            out["seconds"] = round((time.time() * 1000 - started) / 1000)
            out.pop("answer", None)
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_create_backup",
            args={"task_name": task_name, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
