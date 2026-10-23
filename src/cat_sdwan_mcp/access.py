"""W26 access and AAA: the Manager's users, user groups and sessions, and how logins are authenticated (local,
RADIUS, TACACS+).

Recorded on 20.18.3.1: `/admin/user` lists admin (no group: the built-in netadmin), mcp-ro (operator) and
mcp-rw (netadmin); `/admin/usergroup` the five default groups, each with all 360 features flagged read/write;
`/admin/user/activeSessions` one row per GUI/API session; `/admin/user/userAuthType` {"userAuthType": "OTHER"}
for the API login; `/admin/aaa`, `/admin/radius` and `/admin/tacacs` answer `"data": {}` when nothing was ever
set (local authentication only, the Manager's default). The write bodies follow the 20.18 OpenAPI document:
`/admin/aaa` {authOrder [local|radius|tacacs], authFallback, adminAuthOrder, accounting, auditDisable},
`/admin/tacacs` {authentication pap|ascii, timeout, servers [{address, secretKey, authPort, acctPort, vpn,
priority}]}, `/admin/radius` {timeout, retransmit, server [{address, secretKey, authPort, acctPort, vpn,
priority, tag}]}.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.client import _as_list

USERS_PATH = "/dataservice/admin/user"
AUTH_TYPE_PATH = "/dataservice/admin/user/userAuthType"
GROUPS_PATH = "/dataservice/admin/usergroup"
SESSIONS_PATH = "/dataservice/admin/user/activeSessions"
VPN_GROUPS_PATH = "/dataservice/admin/vpngroup"
AAA_PATH = "/dataservice/admin/aaa"
RADIUS_PATH = "/dataservice/admin/radius"
TACACS_PATH = "/dataservice/admin/tacacs"
SESSION_LOGIN_PATH = "/j_security_check"
LOGOUT_PATH = "/logout"

DEFAULT_ORDER = ["local"]
MASK = "********"


def data_of(body: Any) -> Any:
    return body.get("data", body) if isinstance(body, dict) else body


def user_row(u: dict[str, Any], sessions: Counter[str]) -> dict[str, Any]:
    name = str(u.get("userName") or "")
    groups = [str(g) for g in _as_list(u.get("group")) if g]
    if not groups and name == "admin":
        groups = ["netadmin (built-in admin)"]
    row = {
        "user": name,
        "groups": groups,
        "status": u.get("status"),
        "locked": u.get("locked") if "locked" in u else None,
        "description": u.get("description"),
        "resource_group": u.get("resGroupName"),
        "sessions": sessions.get(name) or None,
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def group_row(g: dict[str, Any]) -> dict[str, Any]:
    tasks = [t for t in _as_list(g.get("tasks")) if isinstance(t, dict)]
    read = [str(t.get("feature")) for t in tasks if t.get("read")]
    write = [str(t.get("feature")) for t in tasks if t.get("write")]
    row: dict[str, Any] = {
        "group": g.get("groupName"),
        "type": g.get("type"),
        "features": len(tasks),
        "read": len(read),
        "write": len(write),
    }
    if 0 < len(write) <= 25:
        row["write_features"] = write
    elif write and len(write) == len(tasks):
        row["write_features"] = "all"
    return row


def session_summary(rows: Any) -> tuple[Counter[str], list[dict[str, Any]]]:
    """Sessions per user, and per user the source addresses and modes (webui, api, ...)."""
    per: Counter[str] = Counter()
    detail: dict[str, dict[str, set[str]]] = {}
    for s in _as_list(rows):
        if not isinstance(s, dict):
            continue
        user = str(s.get("rawUserName") or s.get("userName") or "?")
        per[user] += 1
        d = detail.setdefault(user, {"sources": set(), "modes": set()})
        if s.get("sourceIp"):
            d["sources"].add(str(s["sourceIp"]))
        if s.get("userMode"):
            d["modes"].add(str(s["userMode"]))
    out = [
        {
            "user": u,
            "sessions": n,
            "sources": sorted(detail[u]["sources"]),
            "modes": sorted(detail[u]["modes"]),
        }
        for u, n in per.most_common()
    ]
    return per, out


# --- AAA -------------------------------------------------------------------------------------------------


def aaa_view(aaa: Any, radius: Any, tacacs: Any) -> dict[str, Any]:
    """The login order and the servers, secrets masked; an empty /admin/aaa is the default (local only)."""
    a = data_of(aaa) if isinstance(data_of(aaa), dict) else {}
    order = [str(x) for x in _as_list(a.get("authOrder"))] or None
    out: dict[str, Any] = {
        "order": order or DEFAULT_ORDER,
        "order_source": "set" if order else "not set: the Manager's default, local users only",
        "fallback": a.get("authFallback"),
        "admin_auth_order": a.get("adminAuthOrder"),
        "accounting": a.get("accounting"),
        "audit_disabled": a.get("auditDisable"),
    }
    r = data_of(radius) if isinstance(data_of(radius), dict) else {}
    t = data_of(tacacs) if isinstance(data_of(tacacs), dict) else {}
    rs = [mask_server(s) for s in _as_list(r.get("server")) if isinstance(s, dict)]
    ts = [mask_server(s) for s in _as_list(t.get("servers") or t.get("server")) if isinstance(s, dict)]
    out["radius"] = (
        {"servers": rs, "timeout": r.get("timeout"), "retransmit": r.get("retransmit")}
        if rs
        else "not configured"
    )
    out["tacacs"] = (
        {"servers": ts, "timeout": t.get("timeout"), "authentication": t.get("authentication")}
        if ts
        else "not configured"
    )
    out["local_fallback"] = "local" in out["order"]
    return {k: v for k, v in out.items() if v is not None}


def mask_server(s: dict[str, Any]) -> dict[str, Any]:
    masked: dict[str, Any] = dict(mask_secrets(s))
    if s.get("secretKey"):
        masked["secretKey"] = MASK
    return masked


def server_body(protocol: str, s: dict[str, Any]) -> dict[str, Any]:
    default_port = 1812 if protocol == "radius" else 49
    default_acct = 1813 if protocol == "radius" else 49
    body: dict[str, Any] = {
        "address": s["address"],
        "secretKey": s["secret"],
        "authPort": s.get("auth_port") or default_port,
        "acctPort": s.get("acct_port") or default_acct,
        "vpn": s.get("vpn", 0),
        "priority": s.get("priority", 0),
    }
    if protocol == "radius" and s.get("tag"):
        body["tag"] = s["tag"]
    return body


def order_problems(order: list[str], has_servers: dict[str, bool]) -> list[str]:
    """Why an authentication order can't be applied safely (the lockout guard)."""
    problems = []
    if "local" not in order:
        problems.append(
            f"order {order} has no 'local': when the servers are unreachable or reject the login, no one can "
            "log in to the Manager (not even admin). Keep 'local' in the order, e.g. ['tacacs', 'local']."
        )
    if len(set(order)) != len(order):
        problems.append(f"order {order} names a method twice")
    for method in ("radius", "tacacs"):
        if method in order and not has_servers[method]:
            problems.append(f"order {order} uses {method}, but no {method.upper()} server is configured")
    return problems
