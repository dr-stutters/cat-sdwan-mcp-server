"""W40 / W26 RADIUS and TACACS+ for a single-tenant Manager's own logins: its system AAA, through a CLI
device template.

Why (Wave 8 GUI capture, 20.18.3.1, single-tenant): Administration > Users and Access has no Remote AAA tab
there; the GUI adds it (and with it /dataservice/admin/aaa, /admin/radius, /admin/tacacs) only for a
multi-tenant provider (isProviderOrProviderAsTenant), and the OpenAPI document says the same ("In a
multitenant vManage system, this API is only available in the Provider and Provider-As-Tenant view"). That is
the likely cause of the bare 400 on POST /admin/radius (#100, #66). The tenancy comes from GET
/dataservice/client/server (`tenancyMode`: "SingleTenant" recorded on 20.18.3.1).

On a single-tenant Manager, its own logins follow its system configuration, like any Viptela controller:
`system aaa auth-order ...`, `auth-fallback`, and a `system radius` block with `server <ip>` entries (vpn,
tag, secret-key, auth-port, acct-port, priority) plus `retransmit` / `timeout`. Recorded on 20.18.3.1: the
Manager is in CLI mode (no device template), its running configuration (GET
/dataservice/template/config/running/{uuid}) has `system / aaa / auth-order local radius tacacs` and no
radius block, and the factory AAA feature template lists vmanage among its device types. The change is
made the way the Manager configures controllers: a CLI device template (POST /dataservice/template/device/cli
{templateName, templateDescription, deviceType, templateConfiguration, factoryDefault, configType "file"}
-> {templateId}; spec example for a vsmart) holding the Manager's running configuration with the AAA lines
edited, attached to the Manager (POST /template/device/config/attachcli). Everything else in the
configuration stays as it is (the diff shows only the AAA lines). The Manager then leaves CLI mode and
the template owns its configuration.

TACACS+ (W26, #158) takes the same path: a `system tacacs` block with `server <ip>` entries (vpn,
secret-key, auth-port, priority) plus `timeout` and `authentication pap|ascii` (Viptela's system tacacs; no
accounting port and no retransmit), next to the radius block, and `tacacs` in the auth-order.

Not taken: 20.18's Control Component Settings (/dataservice/v1/control-component/network-settings with
`aaa` {authOrder, user [...], radius, ...} for ALL control components, then .../devices/settings/deploy):
its AAA requires the full local user list with passwords (which the API can't read back) and an NTP list,
and GET answers 404 until it is first created, so it would replace every controller's users. Not recorded.
"""

from __future__ import annotations

from typing import Any

from cat_sdwan_mcp.client import _as_list

CLIENT_SERVER_PATH = "/dataservice/client/server"
CLI_TEMPLATE_PATH = "/dataservice/template/device/cli"
TEMPLATE_PATH = "/dataservice/template/device/{id}"
TEMPLATE_NAME = "mcp-manager-system-aaa"
# Viptela's auth-order when the line is absent (the running config recorded on 20.18.3.1 shows it).
DEFAULT_SYSTEM_ORDER = ["local", "radius", "tacacs"]
MASK = "********"
# Block-level settings of `system radius` / `system tacacs` (the rest of the indent-2 lines are servers).
BLOCK_SETTINGS = ("timeout", "retransmit", "authentication")


def tenancy(body: Any) -> str | None:
    """'single' / 'multi' from /client/server's tenancyMode (None when it doesn't say)."""
    data = body.get("data", body) if isinstance(body, dict) else {}
    mode = str((data or {}).get("tenancyMode") or "").strip().lower() if isinstance(data, dict) else ""
    if not mode:
        return None
    return "single" if "single" in mode else "multi"


# --- Viptela CLI text -------------------------------------------------------------------------------------


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_closer(line: str) -> bool:
    return line.strip() in ("", "!")


def _system_span(lines: list[str]) -> tuple[int, int] | None:
    """[start, end) of the top-level `system` block."""
    # The Manager's running configuration starts with " system" (one space, recorded on 20.18.3.1) while
    # vpn 0 / vpn 512 start in column 0; system's own lines are one space in either way.
    start = next((i for i, ln in enumerate(lines) if ln.strip() == "system" and _indent(ln) <= 1), None)
    if start is None:
        return None
    end = start + 1
    while end < len(lines) and (_indent(lines[end]) > 0 or lines[end].strip() == ""):
        end += 1
    return start, end


def _sub_span(lines: list[str], lo: int, hi: int, name: str, depth: int) -> tuple[int, int] | None:
    """[start, end) of the block whose first line is `name` at indent `depth` inside lines[lo:hi]; its
    closing '!' / 'exit' lines included."""
    for i in range(lo, hi):
        if _indent(lines[i]) == depth and lines[i].strip() == name:
            end = i + 1
            while end < hi and (_indent(lines[end]) > depth or _is_closer(lines[end])):
                end += 1
            return i, end
    return None


def system_aaa(text: str) -> dict[str, Any]:
    """The Manager's own AAA from its running configuration: order, fallback, RADIUS servers (secrets masked),
    timeout and retransmit."""
    lines = text.splitlines()
    span = _system_span(lines)
    out: dict[str, Any] = {"order": list(DEFAULT_SYSTEM_ORDER), "order_source": "default", "fallback": False}
    if not span:
        out["radius"] = "not configured"
        return out
    aaa = _sub_span(lines, span[0] + 1, span[1], "aaa", 1)
    if aaa:
        for ln in lines[aaa[0] + 1 : aaa[1]]:
            words = ln.split()
            if _indent(ln) == 2 and words[:1] == ["auth-order"]:
                out["order"], out["order_source"] = words[1:], "set"
            if _indent(ln) == 2 and words == ["auth-fallback"]:
                out["fallback"] = True
            if _indent(ln) == 2 and words == ["admin-auth-order"]:
                out["admin_auth_order"] = True
    out["radius"] = _server_block(lines, span, "radius")
    out["tacacs"] = _server_block(lines, span, "tacacs")
    out["local_fallback"] = "local" in out["order"]
    return out


def _server_block(lines: list[str], span: tuple[int, int], name: str) -> Any:
    """`system radius` or `system tacacs`: {servers: [...], timeout, retransmit | authentication} with the
    secret keys masked, or 'not configured'."""
    blk = _sub_span(lines, span[0] + 1, span[1], name, 1)
    servers: list[dict[str, Any]] = []
    settings: dict[str, Any] = {}
    if blk:
        cur: dict[str, Any] | None = None
        for ln in lines[blk[0] + 1 : blk[1]]:
            words = ln.split()
            if not words or words[0] in ("!", "exit"):
                continue
            if _indent(ln) == 2 and words[0] == "server" and len(words) > 1:
                cur = {"address": words[1]}
                servers.append(cur)
            elif _indent(ln) == 2 and words[0] in BLOCK_SETTINGS and len(words) > 1:
                settings[words[0]] = _int(words[1])
                cur = None
            elif _indent(ln) >= 3 and cur is not None and len(words) > 1:
                key = words[0]
                cur[key] = MASK if key == "secret-key" else _int(words[1])
    return {"servers": servers, **settings} if servers else "not configured"


def _int(v: str) -> Any:
    return int(v) if v.isdigit() else v


def radius_lines(servers: list[dict[str, Any]], timeout: int | None, retransmit: int | None) -> list[str]:
    """The `system radius` block (one-space system indent, as the running configuration has it)."""
    out = [" radius"]
    if retransmit is not None:
        out.append(f"  retransmit {retransmit}")
    if timeout is not None:
        out.append(f"  timeout {timeout}")
    for s in servers:
        out.append(f"  server {s['address']}")
        out.append(f"   vpn {s.get('vpn', 0)}")
        if s.get("tag"):
            out.append(f"   tag {s['tag']}")
        out.append(f"   secret-key {s['secret']}")
        out.append(f"   auth-port {s.get('auth_port') or 1812}")
        out.append(f"   acct-port {s.get('acct_port') or 1813}")
        out.append(f"   priority {s.get('priority', 0)}")
        out.append("  exit")
    out.append(" !")
    return out


def tacacs_lines(servers: list[dict[str, Any]], timeout: int | None, authentication: str | None) -> list[str]:
    """The `system tacacs` block (Viptela: server <ip> with vpn, secret-key, auth-port, priority; block-level
    timeout and authentication pap|ascii; TACACS+ has no accounting port and no retransmit)."""
    out = [" tacacs"]
    if timeout is not None:
        out.append(f"  timeout {timeout}")
    if authentication:
        out.append(f"  authentication {authentication}")
    for s in servers:
        out.append(f"  server {s['address']}")
        out.append(f"   vpn {s.get('vpn', 0)}")
        out.append(f"   secret-key {s['secret']}")
        out.append(f"   auth-port {s.get('auth_port') or 49}")
        out.append(f"   priority {s.get('priority', 0)}")
        out.append("  exit")
    out.append(" !")
    return out


def edit_system_aaa(
    text: str,
    *,
    order: list[str],
    fallback: bool | None,
    servers: list[dict[str, Any]] | None,
    timeout: int | None,
    retransmit: int | None,
    protocol: str = "radius",
    authentication: str | None = None,
) -> str:
    """The running configuration with only the AAA lines changed: `aaa / auth-order`, `auth-fallback` (when
    `fallback` is given), and the `protocol` block (`radius` or `tacacs`) replaced (servers given; []
    removes it) or kept (None), in place. The other protocol's block and everything else stay as they are;
    a new block goes after `radius` (TACACS+, when there is one) or right after `aaa`."""
    lines = text.splitlines()
    span = _system_span(lines)
    if span is None:
        raise ValueError("the running configuration has no `system` block")
    lo, hi = span
    aaa = _sub_span(lines, lo + 1, hi, "aaa", 1)
    if aaa is None:
        lines[lo + 1 : lo + 1] = [" aaa"]
        hi += 1
        aaa = (lo + 1, lo + 2)
    a0, a1 = aaa
    body = lines[a0 + 1 : a1]
    body = [ln for ln in body if not (_indent(ln) == 2 and ln.split()[:1] == ["auth-order"])]
    has_fallback = any(_indent(ln) == 2 and ln.split() == ["auth-fallback"] for ln in body)
    if fallback is False:
        body = [ln for ln in body if not (_indent(ln) == 2 and ln.split() == ["auth-fallback"])]
    head = [f"  auth-order {' '.join(order)}"]
    if fallback and not has_fallback:
        head.append("  auth-fallback")
    lines[a0 + 1 : a1] = head + body
    hi += len(head) + len(body) - (a1 - a0 - 1)
    a1 = a0 + 1 + len(head) + len(body)
    if servers is None:
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    if not servers:
        block: list[str] = []
    elif protocol == "tacacs":
        block = tacacs_lines(servers, timeout, authentication)
    else:
        block = radius_lines(servers, timeout, retransmit)
    blk = _sub_span(lines, lo + 1, hi, protocol, 1)
    if blk:  # replaced where it is
        lines[blk[0] : blk[1]] = block
    else:  # new: after the radius block for TACACS+ when there is one, else right after aaa
        rad = _sub_span(lines, lo + 1, hi, "radius", 1) if protocol == "tacacs" else None
        at = rad[1] if rad else a1
        lines[at:at] = block
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def template_body(name: str, device_type: str, config: str, host: str) -> dict[str, Any]:
    """POST /template/device/cli (and the PUT that edits it): a CLI device template for the Manager."""
    return {
        "templateName": name,
        "templateDescription": f"{host}: the Manager's running configuration with its own AAA (RADIUS, "
        "TACACS+) set by catsdwan_set_external_authentication",
        "deviceType": device_type,
        "templateConfiguration": config,
        "factoryDefault": False,
        "configType": "file",
    }


def find_template(body: Any, name: str) -> dict[str, Any] | None:
    rows = body.get("data") if isinstance(body, dict) else body
    return next(
        (t for t in _as_list(rows) if isinstance(t, dict) and t.get("templateName") == name),
        None,
    )
