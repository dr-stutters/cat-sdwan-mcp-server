"""W25 Manager operations: catsdwan_manager_health, catsdwan_list_backups, catsdwan_create_backup."""

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
    SCHEDULE_LIST_PATH,
    SERVER_INFO_PATH,
    STATS_SETTINGS_PATH,
    TASK_NAME_RE,
    backup_addresses,
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
)

POLL_INTERVAL = 10.0  # seconds between backup-state reads (tests set it to 0)
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
        backup stored on the Manager), then follow it (GET /backup/backupinfo/{id}) to ALL_SUCCESS or a
        failure with the file to download. Preview-first: the preview names the newest existing backup,
        warns that the Manager is busy while it runs, and blocks while another backup is still running or
        when no cluster IP is configured (the request names the nodes' cluster IPs). The
        first step of a change window and of controller or edge upgrades. Restores stay in the GUI."""
        if not TASK_NAME_RE.fullmatch(task_name):
            raise InvalidRequest(
                "task_name may hold letters, digits, spaces and _ - / \\ only (the Manager's own rule)."
            )
        app: SdwanApp = get_client(ctx)
        rows, cluster = await asyncio.gather(_backups(app), app.api.get(CLUSTER_LIST_PATH))
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
        body: dict[str, Any] = {
            "backupType": "ON_DEMAND",
            "taskName": task_name,
            "srcIpAddress": src,
            "followerIpAddressList": followers,
        }
        plan = Plan(
            f"Back up the Manager's configuration database and statistics (task {task_name!r})",
            details={
                "request": f"POST {BACKUP_EXPORT_PATH} {body}",
                "then": f"GET {BACKUP_INFO_PATH} until ALL_SUCCESS or a failure" if wait else "not followed",
                "newest_backup": newest or "none",
                "existing_backups": len(rows),
                "cluster": {"ip_configured": configured, "nodes": nodes},
                "warning": BUSY_WARNING,
            },
            side_effects=[BUSY_WARNING, "The backup file stays on the Manager's disk until it is deleted."],
            fingerprint=[[(r.get("id"), r.get("state")) for r in running], src, followers],
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            started = time.time() * 1000
            try:
                answer = await app.api.post(BACKUP_EXPORT_PATH, body)
            except UpstreamError as e:
                reason = export_error(str(e))
                if reason is None:
                    raise
                raise UpstreamError(f"Backup not started: {reason}", e.status_code) from e
            bid = export_id(answer)
            if bid is None:
                # No id in the answer: the new backup is the newest one created since the request.
                fresh = [r for r in await _backups(app) if r.get("task") == task_name]
                bid = next((str(r["id"]) for r in fresh if r.get("id")), None)
            out: dict[str, Any] = {"outcome": "started", "task": task_name, "answer": answer}
            if bid is None:
                out["note"] = "the Manager returned no backup id; check catsdwan_list_backups"
                return out
            out["id"] = bid
            if not wait:
                out["check_with"] = "catsdwan_list_backups"
                return out
            info_path = BACKUP_INFO_PATH.format(id=bid)

            def state(b: Any) -> str:
                rec = b.get("data", b) if isinstance(b, dict) else {}
                rec = rec[0] if isinstance(rec, list) and rec else rec
                return backup_state(backup_row(rec)) if isinstance(rec, dict) else ""

            final = await poll_until(
                lambda: app.api.get(info_path),
                done=lambda b: state(b) in BACKUP_DONE | BACKUP_FAILED,
                describe=lambda b: f"backup {state(b) or 'pending'}",
                timeout=app.settings.mcp_task_timeout,
                interval=POLL_INTERVAL,
                ctx=ctx,
                what="the backup",
            )
            rec = final.get("data", final) if isinstance(final, dict) else {}
            rec = rec[0] if isinstance(rec, list) and rec else rec
            row = backup_row(rec) if isinstance(rec, dict) else {}
            out.update(row)
            out["outcome"] = "success" if state(final) in BACKUP_DONE else "failed"
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
