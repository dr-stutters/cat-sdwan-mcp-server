"""W41 ISE and pxGrid integration writes: catsdwan_set_ise_integration (dangerous, preview-first)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp._core.secrets import register_secret
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.inventory import load_inventory
from cat_sdwan_mcp.iseintegration import (
    CREDENTIALS_PATH,
    DISCONNECT_PATH,
    PXGRID_ACTIVATE_PATH,
    PXGRID_APPROVE_PATH,
    PXGRID_CREATE_PATH,
    PXGRID_PATH,
    SYNC_PATH,
    cert_check,
    connectivity_hints,
    differences,
    first_value,
    is_host,
    is_ip,
    keep_stored_certs,
    masked,
    node_name_of,
    pxgrid_state,
    server_body,
    stored,
)
from cat_sdwan_mcp.tools.changes import dangerous_blockers, dangerous_tool

Action = Literal["connect", "disconnect"]


async def _read(app: SdwanApp, path: str) -> tuple[dict[str, Any], str | None]:
    """The stored record ({} = none) and an error text when the Manager refused the read."""
    try:
        return stored(await app.api.get(path)), None
    except UpstreamError as e:
        return {}, f"GET {path} failed: {str(e)[:300]}"


def _node_default(inv_rows: list[dict[str, Any]]) -> str:
    mgr = next((r for r in inv_rows if r.get("role") == "manager" and r.get("host")), None)
    return f"vmanage-{mgr['host']}" if mgr else "vmanage"


def register(reg: ToolRegistrar) -> None:
    @dangerous_tool(reg, title="Set the SD-WAN Manager's ISE and pxGrid integration")
    async def catsdwan_set_ise_integration(
        ctx: Context,
        action: Annotated[
            Action,
            Field(description="connect (add or finish the integration) or disconnect (remove it: the undo)"),
        ] = "connect",
        ise_host: Annotated[
            str | None,
            Field(
                description="connect: ISE (the PAN with ERS and pxGrid): its FQDN as ISE's admin certificate "
                "names it (the Manager must resolve it), or its IP address"
            ),
        ] = None,
        vpn: Annotated[
            int, Field(ge=0, le=65530, description="VPN the Manager reaches ISE in (0 or 512)")
        ] = 0,
        subscribe_sgt: Annotated[bool, Field(description="Learn the SGT list from ISE")] = True,
        subscribe_users: Annotated[
            bool, Field(description="Learn users and user groups (needs ad_domain and join_point)")
        ] = False,
        ad_domain: Annotated[
            str | None, Field(description="Active Directory domain, e.g. corp.example")
        ] = None,
        join_point: Annotated[
            str | None, Field(description="ISE's AD join point for that domain (ise_get_ad_join_point)")
        ] = None,
        ise_root_cert: Annotated[
            str | None,
            Field(
                description="PEM of the root CA that signed ISE's admin certificate (443/9060; ISE's own "
                "self-signed one when it has no CA-signed one), optional; also used for pxGrid unless "
                "pxgrid_root_cert is given. Omitted on an update: the stored one is kept"
            ),
        ] = None,
        pxgrid_root_cert: Annotated[
            str | None,
            Field(
                description="PEM of the root CA that signed ISE's pxGrid certificate (8910), when it differs "
                "from ise_root_cert (ise_pxgrid_status shows the chain); default ise_root_cert"
            ),
        ] = None,
        pxgrid: Annotated[bool, Field(description="Also create and activate the pxGrid client")] = True,
        pxgrid_node_name: Annotated[
            str | None,
            Field(description="The pxGrid client name ISE lists (default vmanage-<Manager host name>)"),
        ] = None,
        approve_on_manager: Annotated[
            bool,
            Field(
                description="Let the Manager approve its own pxGrid client with the ISE login (PUT "
                "/ise/pxgrid/approve) instead of ise_approve_pxgrid_client on ISE"
            ),
        ] = False,
        sync_controllers: Annotated[
            bool, Field(description="Send the settings to the controllers once pxGrid is enabled")
        ] = True,
        rotate_password: Annotated[
            bool, Field(description="Rewrite the stored ISE login even when nothing else differs")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Connect the Manager to ISE (Administration > Integration Management): the ISE server and its ERS
        admin login (from CATSDWAN_ISE_USERNAME / CATSDWAN_ISE_PASSWORD, never an argument), the
        subscriptions (SGTs, users and groups), then the pxGrid client: created and activated on ISE, where it
        waits as pending for ise_approve_pxgrid_client (or approve_on_manager=true), then the settings sent to
        the controllers. Run it again after the approval: the preview plans only what is still missing (the
        controller sync). Name ISE by the FQDN its admin certificate carries where the Manager resolves it
        (an IP draws a warning: 'TestConnectivity failed' errors list the suspects); give pxgrid_root_cert
        when pxGrid's chain differs from the admin one; an update keeps the stored root certificates. The
        preview shows the ISE host, VPN, subscriptions, the root-certificate checks, the
        pxGrid client name ISE will list, every request in order, and what the controllers and edges receive
        (identity lists for identity-based policy). action='disconnect' removes both on the Manager and the
        pxGrid client on ISE. Dangerous tier: identity-based policy on every edge depends on it. Check with
        catsdwan_integrations."""
        app: SdwanApp = get_client(ctx)
        (creds, creds_err), (px, px_err) = await asyncio.gather(
            _read(app, CREDENTIALS_PATH), _read(app, PXGRID_PATH)
        )
        inv = await load_inventory(app)
        controllers = sorted(
            str(r.get("host") or r.get("system_ip")) for r in inv.rows if r.get("role") == "controller"
        )
        edges = [r for r in inv.rows if r.get("role") == "edge"]
        state = pxgrid_state(px)
        node = (pxgrid_node_name or "").strip() or node_name_of(px) or _node_default(inv.rows)
        reasons = [
            "identity-based policy and the SGT and user lists on every edge depend on the ISE connection"
        ]
        blockers: list[str] = [e for e in (creds_err,) if e]
        blockers += dangerous_blockers(ctx, app, reasons)
        warnings: list[str] = []
        steps: list[str] = []
        side_effects: list[str] = []
        details: dict[str, Any] = {}
        px_before: dict[str, Any] = {"state": state}
        if node_name_of(px):
            px_before["node"] = node_name_of(px)
        if px_err:
            px_before["read_error"] = px_err
        before = {"ise": masked(creds) if creds else "not configured", "pxgrid": px_before}
        wanted: dict[str, Any] | None = None
        write: str | None = None

        if action == "disconnect":
            if not creds and state == "none":
                blockers.append("nothing to disconnect: no ISE or pxGrid integration is configured")
            steps = [
                f"DELETE {DISCONNECT_PATH} (ISE and pxGrid on the Manager, and the pxGrid client on ISE)"
            ]
            if controllers:
                steps.append(f"POST {SYNC_PATH} (tell the controllers the integration is gone)")
            side_effects = [
                "Identity lists (users, user groups, SGTs from ISE) lose their source; identity-based "
                "firewall "
                "rules on the edges stop matching users",
                f"ISE no longer lists the pxGrid client {node_name_of(px) or node} "
                "(check ise_list_pxgrid_clients)",
            ]
            summary = f"Disconnect the Manager from ISE {creds.get('iseServerIP', '')}".rstrip()
            undo = "catsdwan_set_ise_integration(action='connect', ise_host=..., ...) with the old settings"
        else:
            user = app.settings.ise_username
            secret = app.settings.ise_password.get_secret_value() if app.settings.ise_password else ""
            if secret:
                register_secret(secret)
            host = (ise_host or "").strip() or str(creds.get("iseServerIP") or "")
            if not host:
                raise InvalidRequest("ise_host is required to connect (ISE's FQDN or IP address).")
            if not is_host(host):
                raise InvalidRequest(f"ise_host {host!r} is neither an IP address nor a host name.")
            if subscribe_users and not (ad_domain and join_point):
                raise InvalidRequest(
                    "subscribe_users needs ad_domain and join_point (ise_get_ad_join_point)."
                )
            wanted = server_body(
                ise_host=host,
                username=user or "",
                password=secret,
                vpn=vpn,
                subscribe_sgt=subscribe_sgt,
                subscribe_users=subscribe_users,
                ad_domain=ad_domain,
                join_point=join_point,
                root_cert=ise_root_cert,
                pxgrid_root_cert=pxgrid_root_cert,
            )
            diff = differences(creds, wanted) if creds else {}
            if not creds:
                write = "POST"
            elif diff or rotate_password or ise_root_cert or pxgrid_root_cert:
                write = "PUT"
            if write == "PUT":
                kept = keep_stored_certs(wanted, creds)
                if kept:
                    details["certificates_kept"] = kept
                elif not (ise_root_cert or pxgrid_root_cert):
                    warnings.append(
                        "the stored record shows no root certificate and none is given: if the Manager holds "
                        "one, a PUT without it may clear it (give ise_root_cert again to be sure)"
                    )
            if write and not (user and secret):
                blockers.append(
                    "no ISE login configured on this server: set CATSDWAN_ISE_USERNAME and "
                    "CATSDWAN_ISE_PASSWORD "
                    "(or _FILE / _REF) to an ISE ERS admin; the password is never a tool argument"
                )
            if write:
                steps.append(f"{write} {CREDENTIALS_PATH} (ISE {host}, VPN {vpn})")
            if creds and diff:
                details["changes"] = diff
            if pxgrid:
                if state in ("none", "created"):
                    steps.append(
                        f"POST {PXGRID_CREATE_PATH} {{nodeName: {node!r}}} (the client account on ISE)"
                    )
                    steps.append(f"POST {PXGRID_ACTIVATE_PATH} (ISE lists {node!r} as pending)")
                    state_after = "pending"
                else:
                    state_after = state
                if state_after == "pending" and approve_on_manager:
                    steps.append(
                        f"PUT {PXGRID_APPROVE_PATH} (the Manager approves {node!r} with the ISE login)"
                    )
                    state_after = "enabled"
                if state == "disabled":
                    blockers.append(
                        f"the pxGrid client {node!r} is disabled on ISE: enable it there, or disconnect and "
                        "connect again"
                    )
                if state_after == "enabled" and sync_controllers and controllers:
                    steps.append(
                        f"POST {SYNC_PATH} (send ISE and pxGrid settings to {', '.join(controllers)})"
                    )
                if state_after == "pending":
                    details["then"] = (
                        f"approve the client on ISE: ise_approve_pxgrid_client(name={node!r}) "
                        "(ise_list_pxgrid_clients "
                        "shows it pending), then run this tool again: its preview plans the controller sync"
                    )
            elif sync_controllers and write and controllers:
                steps.append(f"POST {SYNC_PATH} (send the ISE settings to {', '.join(controllers)})")
            if not steps and pxgrid and state == "pending":
                blockers.append(
                    f"nothing to change yet: the pxGrid client {node!r} is pending on ISE. Approve it with "
                    f"ise_approve_pxgrid_client(name={node!r}) (or approve_on_manager=true), then run this "
                    "tool again: it plans the controller sync"
                )
            elif not steps:
                blockers.append(
                    "nothing to change: ISE is configured as asked"
                    + (f" and pxGrid is {state}" if pxgrid else "")
                    + " (catsdwan_integrations shows it)"
                )
            for arg, pem, key in (
                ("ise_root_cert", ise_root_cert, "certificate_check"),
                ("pxgrid_root_cert", pxgrid_root_cert, "pxgrid_certificate_check"),
            ):
                if key == "pxgrid_certificate_check" and not pem:
                    continue
                cert = cert_check(pem)
                if cert.get("given") and not cert.get("ok"):
                    blockers += [f"{arg}: {p}" for p in cert.get("problems", [cert.get("problem")]) if p]
                warnings += [f"{arg}: {w}" for w in cert.get("warnings", [])]
                details[key] = cert
            if ise_root_cert and not pxgrid_root_cert:
                details["pxgrid_certificate_check"] = "same as ise_root_cert"
            if is_ip(host):
                warnings.append(
                    f"ISE is named by IP ({host}): if the Manager answers 'TestConnectivity failed', try the "
                    "FQDN ISE's admin certificate names (the Manager must resolve it)"
                )
            details["after"] = {
                "ise": masked(wanted),
                "pxgrid": {"node": node, "state": state_after} if pxgrid else "not requested",
            }
            if vpn not in (0, 512):
                warnings.append(f"VPN {vpn}: the Manager reaches ISE in VPN 0 or 512 on most deployments")
            if subscribe_users:
                warnings.append(
                    "users and groups come from ISE's AD join point: the user list can be large on a big "
                    "domain"
                )
            side_effects = [
                f"The controllers ({', '.join(controllers) or 'none'}) receive the ISE and pxGrid settings "
                "once "
                "pxGrid is enabled and the sync runs",
                f"{len(edges)} edge(s) can then match identity lists (SGTs"
                + (", users and user groups" if subscribe_users else "")
                + ") in identity-based firewall policy; nothing changes on an edge until such a policy is "
                "deployed",
            ]
            summary = f"Connect the Manager to ISE {host}" + (
                f" with pxGrid client {node!r}" if pxgrid else ""
            )
            undo = "catsdwan_set_ise_integration(action='disconnect')"

        if warnings:
            details["warnings"] = warnings
        plan = Plan(
            summary,
            details={
                "action": action,
                "before": before,
                **details,
                "requests": steps,
                "tier": "dangerous",
                "tier_reasons": reasons,
                "undo": undo,
            },
            side_effects=side_effects,
            fingerprint=[str(masked(creds)), state, node_name_of(px)],
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            done: list[str] = []
            out: dict[str, Any] = {"steps": done}
            if action == "disconnect":
                await app.api.delete(DISCONNECT_PATH)
                done.append("ISE and pxGrid removed on the Manager (and the pxGrid client on ISE)")
                if controllers:
                    try:
                        await app.api.post(SYNC_PATH, None)
                        done.append("controllers told")
                    except UpstreamError as e:
                        out["sync_error"] = f"POST {SYNC_PATH} failed: {str(e)[:200]}"
                out["outcome"] = "done"
                out["check"] = "catsdwan_integrations (not configured); ise_list_pxgrid_clients (client gone)"
                return out
            assert wanted is not None
            if write in ("POST", "PUT"):
                try:
                    if write == "POST":
                        await app.api.post(CREDENTIALS_PATH, wanted)
                    else:
                        await app.api.put(CREDENTIALS_PATH, wanted)
                except UpstreamError as e:
                    if "testconnectivity" not in str(e).lower().replace(" ", ""):
                        raise
                    hints = connectivity_hints(vpn, str(wanted["iseServerIP"]))
                    raise type(e)(
                        f"{e} Nothing was stored. Check, in this order: " + "; ".join(hints) + ".",
                        e.status_code,
                    ) from e
                done.append(f"ISE {wanted['iseServerIP']} {'added' if write == 'POST' else 'updated'}")
            now = state
            if pxgrid and now in ("none", "created"):
                created = await app.api.post(PXGRID_CREATE_PATH, {"nodeName": node})
                px_user = first_value(created, "userName", "nodeName") or node
                px_pass = first_value(created, "password")
                if isinstance(px_pass, str) and px_pass:
                    register_secret(px_pass)
                done.append(f"pxGrid client {px_user!r} created on ISE")
                activated = await app.api.post(
                    PXGRID_ACTIVATE_PATH,
                    {
                        "pxGridUserName": px_user,
                        "pxGridPassword": px_pass or "",
                        "description": "Catalyst SD-WAN Manager (catsdwan_set_ise_integration)",
                    },
                )
                now = str(first_value(activated, "accountState") or "PENDING").lower()
                done.append(f"pxGrid client activated: {now}")
            if pxgrid and "pending" in now and approve_on_manager:
                await app.api.put(PXGRID_APPROVE_PATH, None)
                now = "enabled"
                done.append("pxGrid client approved by the Manager")
            if sync_controllers and controllers and ("enabled" in now or (not pxgrid and write)):
                task = await app.api.post(SYNC_PATH, None)
                out["sync_task"] = first_value(task, "id")
                done.append(f"settings sent to {', '.join(controllers)}")
            out["pxgrid_state"] = now if pxgrid else "not requested"
            if pxgrid and "pending" in now:
                out["outcome"] = "waiting for approval"
                out["next"] = (
                    f"ise_approve_pxgrid_client(name={node!r}), then catsdwan_set_ise_integration again "
                    "(same "
                    "arguments) to send the settings to the controllers"
                )
            else:
                out["outcome"] = "done"
                out["check"] = "catsdwan_integrations (ISE and pxGrid configured, connection ok, SGT list)"
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_ise_integration",
            args={
                "action": action,
                "ise_host": ise_host,
                "vpn": vpn,
                "subscribe_sgt": subscribe_sgt,
                "subscribe_users": subscribe_users,
                "ad_domain": ad_domain,
                "join_point": join_point,
                "ise_root_cert": ise_root_cert,
                "pxgrid_root_cert": pxgrid_root_cert,
                "pxgrid": pxgrid,
                "pxgrid_node_name": pxgrid_node_name,
                "approve_on_manager": approve_on_manager,
                "sync_controllers": sync_controllers,
                "rotate_password": rotate_password,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
