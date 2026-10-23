"""Configuration changes (W8): device variables, configuration-group deploys and device-template attaches.

Pure helpers; the tools are in tools/changes.py. Sources (20.18.3.1; the OpenAPI document gives the paths
but its request/response schemas for configuration groups are external files it doesn't carry):
- GET /dataservice/v1/config-group/{id}/device/variables?device-id=<chassis>: {family, groups, devices:
  [{device-id, variables: [{name, value}]}]}, native value types, no "value" key when a variable has none
  (recorded). 400 CFGRP0012 while the group has no system profile.
- PUT /dataservice/v1/config-group/{id}/device/variables {solution, devices: [{device-id, variables}]}: must
  carry EVERY variable of the device ("Required But Missing Attributes" otherwise) with its native type
  ("Invalid Format Attributes: site_id" for "200"); recorded. So a change is read, merged and written back.
- POST /dataservice/v1/config-group/{id}/device/{deviceId}/preview: "Get a preview of the configuration for
  a device" (spec; body and answer not documented in the document, not recorded yet). Read here as the
  device's CLI text, or a JSON object carrying it.
- POST /dataservice/v1/config-group/{id}/device/deploy {devices: [{id: <chassis>}]} -> {parentTaskId}
  (Cisco's documented shape; not recorded yet).
- POST /dataservice/template/device/config/input {templateId, deviceIds, isEdited, isMasterEdited} ->
  {header: {columns: [{property, title}]}, data: [{csv-status, csv-deviceId, csv-deviceIP, csv-host-name,
  <variable>: value, ...}]} (spec example).
- POST /dataservice/template/device/config/config {templateId, device: <input row + csv-templateId>,
  isEdited, isMasterEdited} -> the device's CLI as text/plain (spec).
- POST /dataservice/template/device/config/attachfeature (feature-based templates) and
  /dataservice/template/device/config/attachcli (CLI templates, configType "file": "Attach CLI device
  template") {deviceTemplateList: [{templateId, device: [rows + selected], isEdited, isMasterEdited,
  isDraftDisabled}]} -> {id: push_..._configuration-<uuid>} (spec).
- GET /dataservice/device/action/status/{id}: {data: [per device: host-name, system-ip, uuid, status
  Success|Failure|In progress|Scheduled, statusId, currentActivity, activity: [...]], validation: {...},
  summary: {status: done|in_progress, count: {...}}} (Cisco's documented shape; not recorded yet).
- GET /dataservice/device/action/status/tasks: {runningTasks: [{processId, name, status, ...}]}.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.configuration import CONFIG_GROUP_PATH, blocks

DEPLOY_PATH = CONFIG_GROUP_PATH + "/device/deploy"
GROUP_PREVIEW_PATH = CONFIG_GROUP_PATH + "/device/{device}/preview"
ACTION_STATUS_PATH = "/dataservice/device/action/status/{id}"
RUNNING_TASKS_PATH = "/dataservice/device/action/status/tasks"
TEMPLATE_INPUT_PATH = "/dataservice/template/device/config/input"
TEMPLATE_CONFIG_PATH = "/dataservice/template/device/config/config"
ATTACH_FEATURE_PATH = "/dataservice/template/device/config/attachfeature"
ATTACH_CLI_PATH = "/dataservice/template/device/config/attachcli"

MASK = "********"


def split_list(value: str | None) -> list[str]:
    return [x.strip() for x in re.split(r"[,\n]", value or "") if x.strip()]


def masked(name: str, value: Any) -> Any:
    """`value` masked when `name` names a secret (password, key, community, ...)."""
    return mask_secrets({name: value})[name]


def text_hash(text: str | None) -> str | None:
    """A digest of configuration text that ignores block order, '!' lines and spacing (as the diff does)."""
    if text is None:
        return None
    return hashlib.sha256(json.dumps(blocks(text), sort_keys=True).encode()).hexdigest()


def device_brief(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: row.get(k) for k in ("host", "system_ip", "chassis", "site_id", "model")}
    return {k: v for k, v in out.items() if v not in (None, "")}


# --- tiers ---------------------------------------------------------------------------------------


def protection(row: dict[str, Any], hubs: str | None, sites: str | None) -> list[str]:
    """Why a device is protected: a hub (CATSDWAN_HUB_DEVICES) or at a protected site."""
    out = []
    hub_keys = {h.lower() for h in split_list(hubs)}
    if hub_keys & {str(row.get(k, "")).lower() for k in ("host", "system_ip", "chassis") if row.get(k)}:
        out.append("a hub (CATSDWAN_HUB_DEVICES)")
    site_keys = {s.lower() for s in split_list(sites)}
    at = {str(row.get(k, "")).lower() for k in ("site_id", "site_name") if row.get(k) not in (None, "")}
    if site_keys & at:
        out.append(f"at protected site {row.get('site_id')} (CATSDWAN_PROTECTED_SITES)")
    return out


def tier_reasons(rows: list[dict[str, Any]], hubs: str | None, sites: str | None) -> list[str]:
    """Why a change is dangerous tier: more than one device, or a hub / protected-site device."""
    out = [f"{len(rows)} devices"] if len(rows) > 1 else []
    for r in rows:
        out += [f"{r.get('host') or r.get('chassis')} is {why}" for why in protection(r, hubs, sites)]
    return out


# --- device variables ----------------------------------------------------------------------------


def coerce_like(old: Any, new: Any) -> Any:
    """`new` in the type of `old` when it came as text (the Manager refuses "200" for an integer)."""
    if not isinstance(new, str):
        return new
    text = new.strip()
    if isinstance(old, bool):
        return {"true": True, "false": False}.get(text.lower(), new)
    if isinstance(old, int):
        try:
            return int(text)
        except ValueError:
            return new
    if isinstance(old, float):
        try:
            return float(text)
        except ValueError:
            return new
    return new


def merge_variables(
    current: list[dict[str, Any]], values: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    """(the device's full variable list with `values` merged in, {name: {from, to}} for the changed names,
    names in `values` the device doesn't have). Original order and types are kept; None clears a value."""
    known = {str(v["name"]) for v in current}
    unknown = [n for n in values if n not in known]
    merged: list[dict[str, Any]] = []
    changes: dict[str, dict[str, Any]] = {}
    for v in current:
        name = str(v["name"])
        row = dict(v)
        if name in values:
            old = v.get("value")
            new = coerce_like(old, values[name])
            if new is None:
                row.pop("value", None)
            else:
                row["value"] = new
            if ("value" in v) != ("value" in row) or old != new:
                changes[name] = {"from": old, "to": new}
        merged.append(row)
    return merged, changes, unknown


def shown_changes(changes: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {n: {"from": masked(n, c["from"]), "to": masked(n, c["to"])} for n, c in changes.items()}


# --- previews ------------------------------------------------------------------------------------

_PREVIEW_KEYS = ("config", "cli", "cliConfig", "newConfig", "intendedConfig", "configuration", "preview")


def preview_text(body: Any) -> str | None:
    """The CLI text in a preview answer: the text itself, or the first configuration-like string field."""
    if isinstance(body, str):
        return body if body.strip() else None
    if isinstance(body, dict):
        for k in _PREVIEW_KEYS:
            if isinstance(body.get(k), str) and body[k].strip():
                return str(body[k])
        if "data" in body:
            return preview_text(body["data"])
        for v in body.values():
            if isinstance(v, str) and "\n" in v:
                return v
    if isinstance(body, list) and len(body) == 1:
        return preview_text(body[0])
    return None


# --- device templates ----------------------------------------------------------------------------


def _short(key: str) -> str:
    """'//system/host-name' -> 'host-name'; '{{banner_motd}}' -> 'banner_motd'."""
    k = key.strip().strip("/").rsplit("/", 1)[-1]
    return k.removeprefix("{{").removesuffix("}}").strip().lower()


def template_columns(body: Any) -> dict[str, str]:
    """{property: title} of the input answer's variable columns (csv-* bookkeeping left out)."""
    header = body.get("header") if isinstance(body, dict) else None
    cols = header.get("columns") if isinstance(header, dict) else None
    out: dict[str, str] = {}
    for c in _as_list(cols):
        if isinstance(c, dict) and c.get("property") and not str(c["property"]).startswith("csv-"):
            out[str(c["property"])] = str(c.get("title") or "")
    return out


def input_rows(body: Any) -> list[dict[str, Any]]:
    rows = body.get("data") if isinstance(body, dict) else body
    return [dict(r) for r in _as_list(rows) if isinstance(r, dict)]


def match_variable(name: str, keys: list[str], titles: dict[str, str]) -> str | list[str] | None:
    """The input key a variable name means: exact key, '{{name}}', the key's last path segment, or the
    column title (case-insensitive). A list when ambiguous, None when nothing matches."""
    if name in keys:
        return name
    want = _short(name)
    found = [k for k in keys if _short(k) == want]
    if not found:
        found = [k for k in keys if titles.get(k, "").strip().lower() == name.strip().lower()]
    if len(found) == 1:
        return found[0]
    return found or None


def variable_keys(row: dict[str, Any], titles: dict[str, str]) -> list[str]:
    return sorted({*(k for k in row if not k.startswith("csv-")), *titles})


# --- action status -------------------------------------------------------------------------------

_RUNNING = ("in progress", "in_progress", "scheduled", "new", "pending", "started", "")


def _state(row: dict[str, Any]) -> str:
    """success | failure | running for one device row of an action status."""
    sid = str(row.get("statusId") or "").lower()
    status = str(row.get("status") or "").lower()
    text = f"{sid} {status}"
    if "success" in text or sid == "done":
        return "success"
    if "fail" in text or "error" in text or "skipped" in text or "cancel" in text:
        return "failure"
    return "running"


def action_rows(body: Any) -> list[dict[str, Any]]:
    rows = body.get("data") if isinstance(body, dict) else body
    return [r for r in _as_list(rows) if isinstance(r, dict)]


def validation_failed(body: Any) -> str | None:
    v = body.get("validation") if isinstance(body, dict) else None
    if not isinstance(v, dict):
        return None
    text = f"{v.get('statusId') or ''} {v.get('status') or ''}".lower()
    if "fail" in text:
        return _reason(v) or "validation failed"
    return None


def action_done(body: Any) -> bool:
    if validation_failed(body):
        return True
    summary = body.get("summary") if isinstance(body, dict) else None
    rows = action_rows(body)
    if rows and all(_state(r) != "running" for r in rows):
        return True
    return isinstance(summary, dict) and str(summary.get("status", "")).lower() == "done" and bool(rows)


def _reason(row: dict[str, Any]) -> str | None:
    lines = [str(x).strip() for x in _as_list(row.get("activity")) if str(x).strip()]
    current = str(row.get("currentActivity") or "").strip()
    picked = [ln for ln in lines if re.search(r"fail|error|invalid|reject|unreachable", ln, re.I)]
    out = (picked or lines)[-3:]
    if current and current not in out:
        out.insert(0, current)
    return " | ".join(out) or None


def action_progress(body: Any) -> str:
    rows = action_rows(body)
    states = [_state(r) for r in rows]
    return (
        f"{states.count('success')} succeeded, {states.count('failure')} failed, "
        f"{states.count('running')} running of {len(rows)}"
    )


def action_outcome(body: Any, process_id: str) -> dict[str, Any]:
    """Per device: success or failure with the failing device's reason; overall success | partial | failed."""
    devices = []
    for r in action_rows(body):
        state = _state(r)
        row = {
            "host": r.get("host-name"),
            "system_ip": r.get("system-ip") or r.get("deviceIP"),
            "chassis": r.get("uuid"),
            "status": state,
            "detail": r.get("currentActivity") or r.get("status"),
        }
        if state == "failure":
            row["reason"] = _reason(r)
        devices.append({k: v for k, v in row.items() if v not in (None, "")})
    ok = sum(1 for d in devices if d["status"] == "success")
    failed = sum(1 for d in devices if d["status"] == "failure")
    if bad := validation_failed(body):
        outcome = "failed"
    elif failed and ok:
        outcome = "partial"
    elif failed or not devices:
        outcome = "failed"
    else:
        outcome = "success"
    out: dict[str, Any] = {"process_id": process_id, "outcome": outcome, "devices": devices}
    if bad:
        out["validation"] = bad
    out["summary"] = f"{ok} device(s) succeeded, {failed} failed"
    return out


def process_id(body: Any) -> str | None:
    """The action id a deploy or attach answers with: parentTaskId (config groups) or id (templates)."""
    if isinstance(body, dict):
        for k in ("parentTaskId", "id", "processId", "taskId"):
            if isinstance(body.get(k), str) and body[k]:
                return str(body[k])
    return None


def running_process_ids(body: Any) -> list[str]:
    rows = body.get("runningTasks") if isinstance(body, dict) else body
    if rows is None and isinstance(body, dict):
        rows = body.get("data")
    out = []
    for r in _as_list(rows):
        if isinstance(r, dict) and (pid := r.get("processId") or r.get("id")):
            out.append(str(pid))
    return out


def busy_devices(body: Any, keys: dict[str, str]) -> dict[str, str]:
    """{host: action} for the devices in `keys` ({chassis or system IP: host}) still running in an action."""
    out: dict[str, str] = {}
    summary = body.get("summary") if isinstance(body, dict) else None
    action = str((summary or {}).get("name") or (summary or {}).get("action") or "an action")
    for r in action_rows(body):
        if _state(r) != "running":
            continue
        for k in (r.get("uuid"), r.get("system-ip"), r.get("deviceID")):
            if k and str(k) in keys:
                out[keys[str(k)]] = action
    return out
