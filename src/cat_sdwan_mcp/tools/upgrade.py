"""W27 controller upgrades: catsdwan_upgrade_controllers (preview-first; confirm is dangerous tier)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    FromResult,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    Undo,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp.client import ROLE, SdwanApp
from cat_sdwan_mcp.manager import BACKUP_DONE, BACKUP_LIST_PATH, backup_rows, backup_state
from cat_sdwan_mcp.tools.changes import dangerous_blockers
from cat_sdwan_mcp.upgrade import (
    ACTIONS,
    BACKUP_MAX_HOURS,
    CANCEL_PATH,
    COMPLIANCE_PATH,
    ORDER,
    ROLE_TYPE,
    STATUS_PATH,
    UPGRADE_PATH,
    VERSIONS_PATH,
    compliance,
    compliance_problems,
    process_id,
    schedule_body,
    versions,
)

# dangerous_blockers' advice is for deploys; it doesn't apply to a whole-control-plane change.
DEPLOY_HINT = " Deploy to one non-hub device at a time, or have the operator enable dangerous changes."


async def _get(app: SdwanApp, path: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return await app.api.get(path, params)
    except UpstreamError as e:
        return {"error": f"GET {path} failed: {str(e)[:300]}"}


def _err(body: Any) -> str | None:
    return body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else None


def _age_hours(created: Any) -> float | None:
    try:
        when = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(UTC) - when).total_seconds() / 3600


def _controllers(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for d in rows:
        role = ROLE.get(str(d.get("personality") or d.get("deviceType")))
        if role in ROLE_TYPE:
            out.append({"type": ROLE_TYPE[role], "host": d.get("host-name"), "version": d.get("version")})
    out.sort(key=lambda r: (ORDER.index(r["type"]), str(r.get("host"))))
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Upgrade SD-WAN controllers", destructive=True)
    async def catsdwan_upgrade_controllers(
        ctx: Context,
        version: Annotated[
            str | None, Field(description="Target release from the Manager's repository; omit to list them")
        ] = None,
        image_type: Annotated[
            Literal["upgrade", "patch"], Field(description="upgrade (a release) or patch")
        ] = "upgrade",
        start: Annotated[
            str | None,
            Field(
                description="Schedule for later: local time 'YYYY-MM-DDTHH:MM' in `timezone`; omit for now"
            ),
        ] = None,
        timezone: Annotated[str, Field(description="IANA time zone of `start`, e.g. 'UTC'")] = "UTC",
        cancel: Annotated[
            str | None,
            Field(description="Cancel this scheduled upgrade (its processId) instead of scheduling one"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Upgrade the control plane through the Manager's controllers-upgrade workflow (20.18+): validators,
        then controllers, then the Manager, to one version from the Manager's software repository. Preview:
        the versions available, the controllers in upgrade order with their current version, the compliance
        check of the target against every edge and controller (version-compliance-info) and the schedule.
        BLOCKS when the repository has no image (with that reason), the version isn't available, an edge or
        controller is too old for it, or there is no successful backup from the last 24 h
        (catsdwan_create_backup). Scheduling is dangerous (MCP_ENABLE_DANGEROUS). `cancel=<processId>`
        cancels a scheduled one. Edge upgrades are separate."""
        app: SdwanApp = get_client(ctx)
        if cancel:
            status = await _get(app, STATUS_PATH, {"processId": cancel})
            plan = Plan(
                f"Cancel controllers upgrade {cancel}",
                details={"status": _err(status) or status, "request": f"PUT {CANCEL_PATH} {{processId}}"},
                fingerprint=cancel,
                blockers=[f"no such upgrade: {_err(status)}"] if _err(status) else [],
                blast_radius=1,
                undo="schedule the upgrade again: catsdwan_upgrade_controllers(version=..., start=...)",
            )

            async def do_cancel() -> Any:
                return {"answer": await app.api.put(CANCEL_PATH, {"processId": cancel})}

            return await preview_or_apply(
                ctx,
                tool="catsdwan_upgrade_controllers",
                args={"cancel": cancel},
                confirm=confirm,
                plan=plan,
                apply=do_cancel,
            )
        when: datetime | None = None
        if start:
            try:
                zone = ZoneInfo(timezone)
                when = datetime.fromisoformat(start)
            except (ZoneInfoNotFoundError, ValueError) as e:
                raise InvalidRequest(
                    f"start/timezone not understood ({e}); use 'YYYY-MM-DDTHH:MM' and an IANA zone."
                ) from e
            if when.replace(tzinfo=zone) < datetime.now(zone) - timedelta(minutes=1):
                raise InvalidRequest(f"start {start} {timezone} is in the past.")
        avail_body, controllers, backups = await asyncio.gather(
            _get(app, VERSIONS_PATH, {"imageType": image_type}),
            app.controllers(),
            _get(app, BACKUP_LIST_PATH),
        )
        available = [] if _err(avail_body) else versions(avail_body)
        order = _controllers(controllers)
        blockers: list[str] = []
        if _err(avail_body):
            blockers.append(f"the available versions could not be read: {_err(avail_body)}")
        elif not available:
            blockers.append(
                f"the Manager's software repository has no controller image for an {image_type} (GET "
                f"{VERSIONS_PATH}?imageType={image_type} lists none): upload the Manager, Controller and "
                "Validator images in Maintenance > Software Repository first"
            )
        chosen = next((v for v in available if v["version"] == version), None)
        if available and version is None:
            blockers.append(f"name a version: {', '.join(v['version'] for v in available)}")
        elif version and available and chosen is None:
            blockers.append(
                f"{version} is not available for an {image_type}; available: "
                + ", ".join(v["version"] for v in available)
            )
        comp: dict[str, Any] = {}
        warnings: list[str] = []
        if version:
            cbody = await _get(app, COMPLIANCE_PATH, {"version": version})
            comp = {"error": _err(cbody)} if _err(cbody) else compliance(cbody)
            comp_blockers, comp_warnings = compliance_problems(comp, version)
            blockers += comp_blockers
            warnings += comp_warnings
        if version and order and all(c.get("version") == version for c in order):
            blockers.append(f"every controller runs {version} already")
        done = [] if _err(backups) else [r for r in backup_rows(backups) if backup_state(r) in BACKUP_DONE]
        newest = done[0] if done else None
        age = _age_hours(newest.get("created")) if newest else None
        if age is None or age > BACKUP_MAX_HOURS:
            blockers.append(
                f"no successful Manager backup from the last {BACKUP_MAX_HOURS} h"
                + (f" (newest: {newest.get('created')})" if newest else "")
                + ": run catsdwan_create_backup first"
            )
        reasons = [
            "it upgrades and reloads every validator, controller and the Manager: control connections drop "
            "while each one reloads, and a wrong order or unsupported edge release takes the fabric down"
        ]
        blockers += [b.replace(DEPLOY_HINT, "") for b in dangerous_blockers(ctx, app, reasons)]
        body: dict[str, Any] = {
            "action": ACTIONS[image_type],
            "targetVersion": version,
            "imageLocation": (chosen or {}).get("location") or "vmanage",
            "isScheduleNow": when is None,
        }
        if image_type == "patch":
            body["applicableControllerTypes"] = list(ORDER)
        if when is not None:
            body["schedule"] = schedule_body(when, timezone)
        plan = Plan(
            f"{'Schedule' if when else 'Start'} the controllers {image_type} to {version or '?'}"
            + (f" at {start} {timezone}" if when else " now"),
            details={
                "available_versions": available or "none in the repository",
                "upgrade_order": order,
                "compliance": comp or "not checked (no version)",
                "newest_backup": newest or "none",
                "request": f"POST {UPGRADE_PATH} {body}",
                **({"warnings": warnings} if warnings else {}),
                "tier": "dangerous",
                "tier_reasons": reasons,
                "after": f"GET {STATUS_PATH}?processId=<id>; cancel with cancel=<id> while scheduled",
            },
            side_effects=reasons,
            fingerprint=[available, [(c["host"], c["version"]) for c in order], comp],
            blockers=blockers,
            blast_radius=len(order) or None,
            # a scheduled upgrade can be cancelled until it starts; a started one has no API rollback
            undo=Undo("catsdwan_upgrade_controllers", {"cancel": FromResult("process_id")})
            if when
            else "not reversible: a started controller upgrade has no rollback in the API; restore the "
            "Manager from its backup (catsdwan_create_backup before the upgrade)",
        )

        async def apply() -> Any:
            answer = await app.api.post(UPGRADE_PATH, body)
            pid = process_id(answer)
            out: dict[str, Any] = {"outcome": "scheduled" if when else "started", "answer": answer}
            if pid:
                out["process_id"] = pid
                out["check_with"] = f"catsdwan_api_call('{STATUS_PATH}?processId={pid}')"
                out["cancel_with"] = f"catsdwan_upgrade_controllers(cancel={pid!r})"
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_upgrade_controllers",
            args={"version": version, "image_type": image_type, "start": start, "timezone": timezone},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
