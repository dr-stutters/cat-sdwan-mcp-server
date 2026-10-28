"""W40 / W26 catsdwan_set_external_authentication on a single-tenant Manager: RADIUS or TACACS+ for the
Manager's own logins through its system AAA (a CLI device template on the Manager). See
cat_sdwan_mcp.manageraaa."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Any

from fastmcp import Context

from cat_sdwan_mcp._core import Plan, UpstreamError, preview_or_apply
from cat_sdwan_mcp.access import order_problems
from cat_sdwan_mcp.changes import ATTACH_CLI_PATH, TEMPLATE_INPUT_PATH, input_rows, text_hash
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import DEVICE_TEMPLATES_PATH, path
from cat_sdwan_mcp.inventory import load_inventory
from cat_sdwan_mcp.manageraaa import (
    CLI_TEMPLATE_PATH,
    DEFAULT_SYSTEM_ORDER,
    MASK,
    TEMPLATE_NAME,
    TEMPLATE_PATH,
    edit_system_aaa,
    find_template,
    system_aaa,
    template_body,
)
from cat_sdwan_mcp.tools.changes import (
    _device_view,
    _pending_blockers,
    _reachability_blockers,
    _running,
    _started,
    dangerous_blockers,
)

PROVIDER_ONLY = (
    "this Manager is single-tenant: /dataservice/admin/aaa, /admin/radius and /admin/tacacs (the GUI's "
    "Remote AAA) exist only for a multi-tenant provider (the 20.18 GUI shows no Remote AAA tab here, and "
    "the API answers a bare 400), so the Manager's own logins are set in its system AAA configuration instead"
)
DEFAULT_TIMEOUT, DEFAULT_RETRANSMIT = 5, 3


NAMES = {"radius": "RADIUS", "tacacs": "TACACS+"}
DEFAULT_PORTS = {"radius": 1812, "tacacs": 49}


def undo_order(before: dict[str, Any], protocol: str = "radius") -> list[str]:
    """The order that puts `before` back and passes this tool's own lockout guard (#120): the old order, but
    without `protocol` when none of its servers was configured, unless it is the Manager's factory order
    (which the guard allows)."""
    order = list(before["order"])
    unset = before.get(protocol, "not configured") == "not configured"
    if unset and protocol in order and order != DEFAULT_SYSTEM_ORDER:
        order = [m for m in order if m != protocol]
    return order


def shown_server(protocol: str, s: dict[str, Any]) -> dict[str, Any]:
    """One server as the preview shows it (secret masked, the CLI's defaults filled in)."""
    if protocol == "tacacs":
        return {
            "address": s["address"],
            "vpn": s.get("vpn", 0),
            "secret-key": MASK,
            "auth-port": s.get("auth_port") or 49,
            "priority": s.get("priority", 0),
        }
    return {
        "address": s["address"],
        "vpn": s.get("vpn", 0),
        "secret-key": MASK,
        "auth-port": s.get("auth_port") or 1812,
        "acct-port": s.get("acct_port") or 1813,
        "priority": s.get("priority", 0),
        **({"tag": s["tag"]} if s.get("tag") else {}),
    }


async def system_path(
    ctx: Context,
    app: SdwanApp,
    *,
    protocol: str,
    order: list[str],
    servers: list[dict[str, Any]] | None,
    fallback: bool | None,
    server_timeout: int | None,
    args: dict[str, Any],
    confirm: str | None,
    login_check: Any,
    authentication: str | None = None,
) -> dict[str, Any]:
    """Plan and apply the system-AAA change for the Manager (preview-first, dangerous)."""
    inv = await load_inventory(app)
    mgr = next((r for r in inv.rows if r.get("role") == "manager" and r.get("chassis")), None)
    blockers: list[str] = []
    warnings: list[str] = list(inv.warnings)
    reasons = [
        "it changes how every user, admin included, logs in to the Manager (lockout risk)",
        "it attaches a device template to the Manager: the template owns the Manager's configuration",
    ]
    if mgr is None:
        blockers.append("the inventory lists no Manager (personality vmanage) with a uuid")
    host = str((mgr or {}).get("host") or "manager")
    chassis = str((mgr or {}).get("chassis") or "")
    running: str | None = None
    name = NAMES[protocol]
    other = "tacacs" if protocol == "radius" else "radius"
    if mgr is not None:
        mode, cfg = mgr.get("config_mode"), mgr.get("config")
        if mode == "configuration group":
            blockers.append(f"{host} is in configuration group {cfg}: change its AAA there")
        elif mode == "template" and cfg and cfg != TEMPLATE_NAME:
            blockers.append(
                f"{host} is on device template {cfg}: set the {name} servers and auth-order in that "
                "template's AAA feature template (catsdwan_list_templates type='feature'), not here"
            )
        blockers += _reachability_blockers([mgr])
        busy, busy_warn = await _pending_blockers(app, [mgr])
        blockers += busy
        warnings += busy_warn
        running, note = await _running(app, chassis)
        if note:
            blockers.append(note)
        elif running is None:
            blockers.append(f"{host} returned no running configuration")
    blockers += [
        b.replace(
            " Deploy to one non-hub device at a time, or have the operator enable dangerous changes.",
            " Have the operator enable dangerous changes.",
        )
        for b in dangerous_blockers(ctx, app, reasons)
    ]
    before = system_aaa(running or "")
    cur = before[protocol] if isinstance(before[protocol], dict) else {}
    timeout = server_timeout or cur.get("timeout") or DEFAULT_TIMEOUT
    retransmit = (cur.get("retransmit") or DEFAULT_RETRANSMIT) if protocol == "radius" else None
    auth = (authentication or cur.get("authentication")) if protocol == "tacacs" else None
    has = {m: before[m] != "not configured" for m in ("radius", "tacacs")}
    if servers is not None:
        has[protocol] = bool(servers)
    blockers = order_problems(list(order), has) + blockers
    if other in order and not has[other]:
        blockers = [b for b in blockers if f"no {other.upper()} server" not in b]
        warnings.append(f"{other} stays in the order with no {NAMES[other]} server: it is skipped")
    if not has[protocol] and list(order) == DEFAULT_SYSTEM_ORDER:
        # The Manager's factory order (what the running configuration has before RADIUS or TACACS+ is set,
        # and so the preview's own undo, #120): a method without a server is skipped, local stays first.
        blockers = [b for b in blockers if f"no {protocol.upper()} server" not in b]
        warnings.append(
            f"{protocol} stays in the Manager's factory order with no {name} server: it is skipped, local "
            "accounts log in as before"
        )
    if protocol == "tacacs":
        for s in servers or []:
            dropped = [k for k in ("tag", "acct_port") if s.get(k)]
            if dropped:
                warnings.append(
                    f"{s['address']}: {' and '.join(dropped)} left out (a TACACS+ server in the system AAA "
                    "has neither)"
                )
    new: str | None = None
    if running is not None and not any("system" in b and "block" in b for b in blockers):
        try:
            new = edit_system_aaa(
                running,
                order=list(order),
                fallback=fallback,
                servers=servers,
                timeout=timeout if servers else None,
                retransmit=retransmit if servers else None,
                protocol=protocol,
                authentication=auth if servers else None,
            )
        except ValueError as e:
            blockers.append(f"{host}: {e}")
    if new is not None and text_hash(new) == text_hash(running):
        blockers.append("nothing to change: the Manager's system AAA is as asked")
    if list(order)[:1] != ["local"]:
        warnings.append(
            f"{order[0]} is tried first: a {NAMES.get(order[0], order[0])} reject ends the login and never "
            "falls back, so local users (admin and this server's API user) log in only while ISE is "
            "unreachable. Put 'local' first."
        )
    tpl_body = await app.api.get(DEVICE_TEMPLATES_PATH, {"feature": "all"})
    existing = find_template(tpl_body, TEMPLATE_NAME)
    model = str((mgr or {}).get("model") or "vmanage")
    view = _device_view(new, running, show_cli=False) if new is not None else {}
    settings: dict[str, Any] = {"timeout": timeout}
    if protocol == "radius":
        settings["retransmit"] = retransmit
    elif auth:
        settings["authentication"] = auth
    after_proto: Any = (
        before[protocol]
        if servers is None
        else ({"servers": [shown_server(protocol, s) for s in servers], **settings} if servers else "removed")
    )
    tpl_step = (
        f"PUT {path(TEMPLATE_PATH, id=str(existing.get('templateId')))} (template {TEMPLATE_NAME})"
        if existing
        else f"POST {CLI_TEMPLATE_PATH} (CLI device template {TEMPLATE_NAME}, deviceType {model})"
    )
    user = app.settings.username or "the API user"
    plan = Plan(
        f"Set {host}'s own login order {before['order']} -> {list(order)}"
        + (f" with {name} servers " + ", ".join(s["address"] for s in servers) if servers else "")
        + " (system AAA, single-tenant Manager)",
        details={
            "path": "system AAA (single-tenant Manager)",
            "why": PROVIDER_ONLY,
            "before": {
                "order": before["order"],
                "fallback": before["fallback"],
                protocol: before[protocol],
            },
            "after": {
                "order": list(order),
                "fallback": before["fallback"] if fallback is None else fallback,
                protocol: after_proto,
            },
            **({"unchanged": {other: before[other]}} if has[other] else {}),
            "local_fallback": "local" in order,
            "manager": {"host": host, "chassis": chassis, "config_mode": (mgr or {}).get("config_mode")},
            **view,
            "requests": [
                f"POST /j_security_check (test login as {user}, before: stop if it fails)",
                tpl_step,
                f"POST {TEMPLATE_INPUT_PATH} then POST {ATTACH_CLI_PATH} ({host}), followed to the end",
                f"POST /j_security_check (test login as {user}, after: re-attach the old configuration if "
                "it fails)",
            ],
            "tier": "dangerous",
            "tier_reasons": reasons,
            **({"warnings": warnings} if warnings else {}),
            "undo": (
                f"catsdwan_set_external_authentication(protocol={protocol!r}, "
                f"order={undo_order(before, protocol)!r}, "
                + ("servers=[])" if before[protocol] == "not configured" else "servers=<the old servers>)")
            ),
            "then": f"catsdwan_test_login with the local admin, then with an ISE {name} user; {host} stays "
            f"on template {TEMPLATE_NAME} (detach it to return to CLI mode; the configuration stays)",
        },
        side_effects=[
            f"Every login to {host} is checked in the order {list(order)}"
            + (f" against the {name} servers" if has[protocol] else ""),
            f"{host} leaves CLI mode: template {TEMPLATE_NAME} (its running configuration with the AAA lines "
            "changed, nothing else) owns its configuration from now on",
        ],
        fingerprint={"running": text_hash(running), "template": (existing or {}).get("lastUpdatedOn")},
        blockers=blockers,
        blast_radius=1,
    )

    async def attach(config: str, tid_known: str | None) -> tuple[str, dict[str, Any]]:
        body = template_body(TEMPLATE_NAME, model, config, host)
        if tid_known:
            await app.api.put(path(TEMPLATE_PATH, id=tid_known), {**body, "templateId": tid_known})
            tid = tid_known
        else:
            made = await app.api.post(CLI_TEMPLATE_PATH, body)
            tid = str((made or {}).get("templateId") if isinstance(made, dict) else "")
            if not tid:
                raise UpstreamError(f"POST {CLI_TEMPLATE_PATH} returned no templateId")
        answer = await app.api.post(
            TEMPLATE_INPUT_PATH,
            {"templateId": tid, "deviceIds": [chassis], "isEdited": False, "isMasterEdited": False},
        )
        rows = [r for r in input_rows(answer) if str(r.get("csv-deviceId")) == chassis] or [
            {"csv-deviceId": chassis, "csv-deviceIP": (mgr or {}).get("system_ip"), "csv-host-name": host}
        ]
        row = {**rows[0], "csv-status": "complete", "csv-templateId": tid, "selected": "true"}
        push = {
            "deviceTemplateList": [
                {
                    "templateId": tid,
                    "device": [row],
                    "isEdited": False,
                    "isMasterEdited": False,
                    "isDraftDisabled": False,
                }
            ]
        }
        started = await app.api.post(ATTACH_CLI_PATH, push)
        return tid, await _started(app, ctx, started, True, f"attach of {TEMPLATE_NAME} to {host}")

    async def apply() -> Any:
        assert new is not None and running is not None
        first = await login_check(app)
        out: dict[str, Any] = {"test_login_before": first}
        if not first["ok"]:
            out["outcome"] = "not started"
            out["reason"] = "the test login failed before the change, so nothing was sent"
            return out
        tid, action = await attach(new, str(existing["templateId"]) if existing else None)
        out["template"] = {"name": TEMPLATE_NAME, "id": tid}
        out["attach"] = action
        if action.get("outcome") in ("failed", "partial"):
            out["outcome"] = "attach failed"
            return out
        login = await login_check(app)
        out["test_login"] = login
        if not login["ok"]:
            _, back = await attach(running, tid)
            out["outcome"] = "rolled back"
            out["rolled_back"] = (
                f"the test login failed, so {host}'s previous configuration is attached again"
            )
            out["rollback_attach"] = back
        else:
            out["outcome"] = "done"
            out["check"] = (
                "catsdwan_get_device_config(device='manager', section='system'); catsdwan_test_login with "
                f"the local admin and with an ISE {name} user"
            )
        return out

    return await preview_or_apply(
        ctx,
        tool="catsdwan_set_external_authentication",
        args=args,
        confirm=confirm,
        plan=plan,
        apply=apply,
    )
