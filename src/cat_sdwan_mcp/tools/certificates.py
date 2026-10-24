"""W16 certificates and trust: catsdwan_certificates, catsdwan_renew_controller_certificate,
catsdwan_sync_root_cert.

Tiers: catsdwan_certificates is a read. catsdwan_sync_root_cert is write tier (preview-first).
catsdwan_renew_controller_certificate is registered with the writes but is always dangerous: without
MCP_ENABLE_DANGEROUS its preview is shown with a blocker, and nothing can be confirmed. It runs in two
previewed steps, because the signature comes from the operator's Enterprise CA, outside the Manager:
1. no `signed_certificate`: preview (the controller, its current certificate, the CSR fields, the signing
   mode); confirm = POST /certificate/generate/csr, which returns the CSR to sign.
2. `signed_certificate` = the signed PEM: preview (the certificate checked against the controller's CSR);
   confirm = POST /certificate/install/signedCert (an action, followed), then POST /certificate/vsmart/list
   (send the controller list to the validators, followed).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from cat_sdwan_mcp._core.http import page_of
from cat_sdwan_mcp.certificates import (
    BREAKS,
    CONTROLLER_LIST_PATH,
    DETAIL_PATH,
    EDGE_CA_PATH,
    EDGE_LIST_PATH,
    ENTERPRISE_ROOT_PATH,
    FORCE_SYNC_ROOT_PATH,
    GENERATE_CSR_PATH,
    INSTALL_PATH,
    LIST_STATUS_PATH,
    ROOT_CHAIN_PATH,
    SEND_TO_VALIDATORS_PATH,
    SIGNING_PATH,
    SUMMARY_PATH,
    TRUSTPOINT_PATH,
    WARN_DAYS,
    WEBSERVER_PATH,
    controller_cert_row,
    controller_names,
    csr_of,
    describe_pem,
    edge_cert_row,
    first,
    is_pem_certificate,
    pem_digest,
    resolve_controller,
    root_rows,
    signing_row,
    sort_certs,
    trustpoint_row,
    webserver_row,
)
from cat_sdwan_mcp.client import ROLE, SdwanApp, _as_list
from cat_sdwan_mcp.fabric import find_device, require_reachable
from cat_sdwan_mcp.tools.changes import _started, dangerous_blockers

CERT_COLUMNS = ["kind", "host", "role", "system_ip", "status", "expires", "days_left", "state", "validity"]
Kind = Literal["all", "controller", "edge"]


async def _rows(app: SdwanApp, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    data = await app.get_data(path, params)
    return [r for r in _as_list(data) if isinstance(r, dict)]


async def _optional(coro: Any, what: str, errors: list[str]) -> Any:
    try:
        return await coro
    except UpstreamError as e:
        errors.append(f"{what} failed: {str(e)[:200]}")
        return None


async def _signing(app: SdwanApp, errors: list[str]) -> tuple[str | None, str | None]:
    """(controller certificate signing mode, edge certificate authority)."""
    c, e = await asyncio.gather(
        _optional(app.api.get(SIGNING_PATH), f"GET {SIGNING_PATH}", errors),
        _optional(app.api.get(EDGE_CA_PATH), f"GET {EDGE_CA_PATH}", errors),
    )
    mode = first(c).get("certificateSigning") if c is not None else None
    edge = first(e).get("certificateauthority") if e is not None else None
    return (str(mode) if mode else None), (str(edge) if edge else None)


def _attention(rows: list[dict[str, Any]]) -> list[str]:
    out = []
    for r in rows:
        if r.get("status") in ("invalid", "expired", "expiring", "not installed"):
            when = f", {r['days_left']} days left" if isinstance(r.get("days_left"), int) else ""
            out.append(f"{r.get('host') or r.get('name') or r.get('subject')}: {r['status']}{when}")
    return out


def _controller_brief(c: dict[str, Any]) -> dict[str, Any]:
    role = ROLE.get(str(c.get("personality") or c.get("deviceType")), c.get("personality"))
    out = {
        "host": c.get("host-name"),
        "role": role,
        "system_ip": c.get("system-ip") or c.get("deviceIP"),
        "state": c.get("state"),
        "install_status": c.get("certInstallStatus"),
        "validity": c.get("validity"),
        "expires": c.get("expirationDate"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", "NA")}


async def _reachability(app: SdwanApp, c: dict[str, Any]) -> str | None:
    """The controller's reachability from /system/device/controllers (None when it can't be read)."""
    try:
        rows = await app.controllers()
    except UpstreamError:
        return None
    ip = c.get("deviceIP") or c.get("system-ip")
    for r in rows:
        if ip and ip in (r.get("deviceIP"), r.get("system-ip")):
            return str(r.get("reachability") or "") or None
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN certificates and trust")
    async def catsdwan_certificates(
        ctx: Context,
        kind: Annotated[
            Kind, Field(description="controller (Manager, controllers, validators), edge, or all")
        ] = "all",
        expiring_days: Annotated[
            int | None,
            Field(
                ge=0,
                le=3650,
                description="Only certificates that are invalid, expired or expire within this many days "
                "(also the 'expiring' threshold; default 30)",
            ),
        ] = None,
        device: Annotated[
            str | None,
            Field(description="Also read this edge's trustpoints (host name, system IP, chassis or serial)"),
        ] = None,
        include_trust: Annotated[
            bool,
            Field(
                description="Add the root chain the fabric trusts, the Manager's HTTPS certificate and the "
                "signing settings (default true)"
            ),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Certificate expiry and trust across the fabric, the invalid, expired and expiring ones first.
        Each certificate has a status (invalid, expired, expiring, not installed, ok), its expiry, days left,
        state and `breaks_when_expired`: what stops when it lapses (a controller's takes every control
        connection to it down; a validator's stops every join). Controllers (Manager, controllers,
        validators) from the controller certificate list, edges from the WAN edge certificate list (empty
        slots left out), the Manager's own counts (`summary`). With include_trust: `signing` (Enterprise CA
        or Cisco for controllers, the Manager's CA or Enterprise for edges), `root_chain` (the CAs the
        fabric trusts, expiring first) and `webserver` (the Manager's HTTPS certificate). `device` adds that
        edge's trustpoints."""
        app: SdwanApp = get_client(ctx)
        warn = expiring_days if expiring_days is not None else WARN_DAYS
        errors: list[str] = []
        want_c, want_e = kind in ("all", "controller"), kind in ("all", "edge")

        async def nothing() -> None:
            return None

        got = await asyncio.gather(
            _optional(app.api.get(SUMMARY_PATH), f"GET {SUMMARY_PATH}", errors),
            _optional(_rows(app, CONTROLLER_LIST_PATH), f"GET {CONTROLLER_LIST_PATH}", errors)
            if want_c
            else nothing(),
            _optional(_rows(app, DETAIL_PATH), f"GET {DETAIL_PATH}", errors) if want_c else nothing(),
            _optional(_rows(app, EDGE_LIST_PATH), f"GET {EDGE_LIST_PATH}", errors) if want_e else nothing(),
        )
        summary_body, controllers, detail, edges = got
        status = {
            str(d.get("local-system-ip") or d.get("system-ip")): str(d["expirationStatus"])
            for d in detail or []
            if d.get("expirationStatus")
        }
        rows = [controller_cert_row(c, status, warn_days=warn) for c in controllers or []]
        rows += [r for v in edges or [] if (r := edge_cert_row(v, warn_days=warn)) is not None]
        if expiring_days is not None:
            rows = [r for r in rows if r.get("status") != "ok"]
        rows = sort_certs(rows)
        extra: dict[str, Any] = {}
        if summary_body is not None:
            extra["summary"] = first(summary_body)
        if attention := _attention(rows):
            extra["attention"] = attention
        if include_trust:
            mode, edge_ca = await _signing(app, errors)
            extra["signing"] = signing_row(mode, edge_ca)
            chain, web, list_status = await asyncio.gather(
                _optional(_rows(app, ROOT_CHAIN_PATH, {"action": "get"}), f"GET {ROOT_CHAIN_PATH}", errors),
                _optional(app.api.get(WEBSERVER_PATH), f"GET {WEBSERVER_PATH}", errors),
                _optional(app.api.get(LIST_STATUS_PATH, expect="text"), f"GET {LIST_STATUS_PATH}", errors),
            )
            if chain is not None:
                roots = root_rows(chain, warn_days=warn)
                extra["root_chain"] = (
                    [r for r in roots if r.get("status") != "ok"] if expiring_days else roots
                )
                extra["root_chain_note"] = f"{len(roots)} CA certificates; {BREAKS['root']} when one expires"
            if isinstance(web, dict) and (w := webserver_row(web.get("certificateDetails"), warn_days=warn)):
                extra["webserver"] = w
            if isinstance(list_status, str) and list_status.strip():
                extra["list_status"] = list_status.strip()[:500]
        if device:
            row, _ = await find_device(app, device)
            ip = require_reachable(row)
            tps = await _optional(
                _rows(app, TRUSTPOINT_PATH, {"deviceId": ip}), f"GET {TRUSTPOINT_PATH}", errors
            )
            if tps is not None:
                extra["trustpoints"] = {
                    "device": row.get("host") or ip,
                    "rows": sorted(
                        (trustpoint_row(t, warn_days=warn) for t in tps),
                        key=lambda t: t.get("days_left") if isinstance(t.get("days_left"), int) else 10**9,
                    )
                    or "none (a controller reports no trustpoints)",
                }
        if errors:
            extra["errors"] = errors
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            columns=CERT_COLUMNS,
            extra=extra,
        )

    @reg.write(title="Renew an SD-WAN controller certificate", destructive=True, task=True)
    async def catsdwan_renew_controller_certificate(
        ctx: Context,
        controller: Annotated[
            str,
            Field(
                description="Host name, system IP or role ('validator', 'controller', 'manager') of the "
                "Manager, controller or validator"
            ),
        ],
        signed_certificate: Annotated[
            str | None,
            Field(
                description="Step 2: the certificate the Enterprise CA signed from this tool's CSR (PEM). "
                "Leave empty for step 1 (generate the CSR)"
            ),
        ] = None,
        wait: Annotated[
            bool,
            Field(description="Step 2: follow the install and the send to the validators (default true)"),
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Renew a controller's (Manager, controller or validator) certificate with the Enterprise CA, in
        two previewed steps. Step 1 (no signed_certificate): the preview shows the controller, its current
        certificate (issuer, serial, expiry), the CSR fields and the signing mode; confirm generates a new
        CSR on it (POST /certificate/generate/csr) and returns the PEM to sign. Sign it with the Enterprise CA
        (in the lab: Windows_Server win_sign_csr), then step 2 (signed_certificate=<PEM>): the preview checks
        the certificate against the controller's CSR (common name, validity, issuer); confirm installs it
        (POST /certificate/install/signedCert, followed) and sends the controller list to the validators
        (POST /certificate/vsmart/list). Always dangerous (MCP_ENABLE_DANGEROUS): a wrong certificate drops
        every control connection to that controller. Refused when controller certificates are not signed by
        an Enterprise CA. Check afterwards with catsdwan_control_connections and catsdwan_certificates."""
        app: SdwanApp = get_client(ctx)
        errors: list[str] = []
        rows = await _rows(app, CONTROLLER_LIST_PATH)
        c = resolve_controller(rows, controller)
        if c is None:
            raise NotFound(
                f"No Manager, controller or validator matches {controller!r}. Controllers: "
                f"{', '.join(controller_names(rows)) or 'none'}."
            )
        mode, _ = await _signing(app, errors)
        brief = _controller_brief(c)
        name = str(brief.get("host") or brief.get("system_ip"))
        role = str(brief.get("role"))
        current = describe_pem(c.get("deviceEnterpriseCertificate"))
        last_csr = describe_pem(c.get("deviceCSR"))
        blockers: list[str] = []
        warnings: list[str] = []
        if mode is None:
            blockers.append(
                f"The controller certificate signing mode could not be read ({'; '.join(errors)}), so the "
                "Enterprise CA requirement can't be checked."
            )
        elif mode.lower() != "enterprise":
            blockers.append(
                f"Controller certificates on this Manager are signed by {mode!r}, not an Enterprise CA "
                "(Administration > Settings > Controller Certificate Authorization). This tool only renews "
                "with an Enterprise CA; with Cisco signing the Manager renews them itself."
            )
        reasons = [
            f"renewing {name}'s certificate: {BREAKS.get(role, 'its control connections drop')} if "
            "the new certificate is wrong"
        ]
        blockers += dangerous_blockers(ctx, app, reasons)
        fingerprint = {
            "state": c.get("state"),
            "serial": c.get("serialNumber"),
            "certificate": pem_digest(c.get("deviceEnterpriseCertificate")),
            "csr": pem_digest(c.get("deviceCSR")),
        }
        ip = str(c.get("deviceIP") or c.get("system-ip") or "")
        details: dict[str, Any] = {
            "controller": brief,
            "tier": "dangerous",
            "tier_reasons": reasons,
            "signing": signing_row(mode, None).get("controllers_meaning") or mode,
            "current_certificate": current
            or {"expires": c.get("expirationDate"), "serial": c.get("serialNumber")},
            "breaks_when_wrong_or_expired": BREAKS.get(role),
        }

        if signed_certificate is None:
            reach = await _reachability(app, c)
            if reach is not None and reach.lower() != "reachable":
                blockers.append(f"{name} is {reach}: the Manager can't generate a CSR on it")
            details["csr_fields"] = (
                {
                    "subject": last_csr.get("subject"),
                    "common_name": last_csr.get("common_name"),
                    "note": "from the controller's last CSR: the Manager builds the new one the same way "
                    "(organisation unit = the overlay's org name)",
                }
                if last_csr
                else {"common_name": c.get("deviceCSRCommonName"), "key_length": c.get("keyLength")}
            )
            details["steps"] = [
                f"1. (this confirm) POST {GENERATE_CSR_PATH} {{deviceIP: {ip}}}: a new key pair and CSR on "
                f"{name}; the installed certificate stays in place until step 2",
                "2. sign the CSR with the Enterprise CA (in the lab: Windows_Server win_sign_csr with "
                "the template mcpPxGrid, as the W0 build); the certificate needs server and client "
                "authentication",
                f"3. catsdwan_renew_controller_certificate(controller={name!r}, signed_certificate=<PEM>): "
                f"preview, then POST {INSTALL_PATH} and POST {SEND_TO_VALIDATORS_PATH}",
            ]
            plan = Plan(
                f"Generate a new certificate signing request on {role} {name} ({ip})",
                details=details,
                side_effects=[
                    f"{name} makes a new key pair for the CSR; until the signed certificate is installed its "
                    "certificate state reads 'CSR Generated'. Finish step 3 soon: the CSR's key is what the "
                    "new certificate must match"
                ],
                fingerprint=fingerprint,
                blockers=blockers,
                blast_radius=1,
            )

            async def apply_csr() -> Any:
                answer = await app.api.post(GENERATE_CSR_PATH, {"deviceIP": ip})
                pem = csr_of(answer)
                if pem is None:  # an async Manager: read the CSR back from the controller list
                    for r in await _rows(app, CONTROLLER_LIST_PATH):
                        if (
                            r.get("deviceIP") == c.get("deviceIP")
                            and pem_digest(r.get("deviceCSR")) != fingerprint["csr"]
                        ):
                            pem = csr_of({"data": [r]})
                out: dict[str, Any] = {"controller": name}
                if pem is None:
                    out["note"] = "the Manager returned no CSR; read it with catsdwan_api_call(" + (
                        f"'{CONTROLLER_LIST_PATH}') (deviceCSR)"
                    )
                    out["answer"] = answer
                    return out
                out["csr"] = pem
                out["csr_subject"] = (describe_pem(pem) or {}).get("subject")
                out["next"] = (
                    "Sign this CSR with the Enterprise CA (lab: Windows_Server win_sign_csr), then call "
                    f"catsdwan_renew_controller_certificate(controller={name!r}, signed_certificate=<the "
                    "signed PEM>) to preview the install."
                )
                return out

            return await preview_or_apply(
                ctx,
                tool="catsdwan_renew_controller_certificate",
                args={"controller": controller, "signed_certificate": None, "wait": wait},
                confirm=confirm,
                plan=plan,
                apply=apply_csr,
            )

        pem = signed_certificate.strip()
        new = describe_pem(pem) if is_pem_certificate(pem) else None
        if new is None:
            blockers.append(
                "signed_certificate is not a PEM certificate ('-----BEGIN CERTIFICATE-----' ... '-----END "
                "CERTIFICATE-----'); paste the certificate the CA returned, not the CSR."
            )
        else:
            want_cn = (last_csr or {}).get("common_name") or c.get("deviceCSRCommonName")
            if want_cn and new.get("common_name") != want_cn:
                blockers.append(
                    f"The certificate's common name {new.get('common_name')!r} is not {name}'s CSR's "
                    f"{want_cn!r}: it was signed from another CSR (or the controller has a newer CSR)."
                )
            if isinstance(new.get("days_left"), int) and new["days_left"] < 0:
                blockers.append(f"The certificate expired on {new.get('expires')}.")
            if pem_digest(pem) == fingerprint["certificate"]:
                blockers.append(f"This is the certificate {name} already has installed: nothing to change.")
            root = await _optional(app.api.get(ENTERPRISE_ROOT_PATH), f"GET {ENTERPRISE_ROOT_PATH}", errors)
            root_pem = first(root).get("enterpriseRootCA") if root is not None else None
            ca = describe_pem(root_pem)
            if ca and new.get("issuer") != ca.get("subject"):
                warnings.append(
                    f"The issuer {new.get('issuer')!r} is not the Enterprise root CA {ca.get('subject')!r}: "
                    "fine for an intermediate CA whose chain the controllers trust; otherwise the install "
                    "fails."
                )
        details["new_certificate"] = new
        if warnings:
            details["warnings"] = warnings
        if errors:
            details["errors"] = errors
        details["requests"] = [
            f"POST {INSTALL_PATH} (the PEM as the body; an action, followed)",
            f"POST {SEND_TO_VALIDATORS_PATH} (send the controller list to the validators; followed)",
        ]
        details["check"] = [
            f"catsdwan_control_connections(device={name!r}): its connections stay or come back up",
            "catsdwan_certificates(kind='controller'): the new expiry",
        ]
        plan = Plan(
            f"Install the signed certificate on {role} {name} ({ip}) and send the controller list to the "
            "validators",
            details=details,
            side_effects=[
                f"{name} uses the new certificate for its control connections; the old one is replaced",
            ],
            fingerprint=fingerprint,
            blockers=blockers,
            blast_radius=1,
        )

        async def apply_install() -> Any:
            answer = await app.api.request("POST", INSTALL_PATH, content=pem)
            out: dict[str, Any] = {"controller": name}
            out["install"] = await _started(app, ctx, answer, wait, f"install certificate on {name}")
            if isinstance(out["install"], dict) and out["install"].get("outcome") == "failed":
                out["sent_to_validators"] = "skipped: the install failed"
                return out
            sent = await app.api.post(SEND_TO_VALIDATORS_PATH, None)
            out["sent_to_validators"] = await _started(
                app, ctx, sent, wait, "send controller list to validators"
            )
            out["check"] = details["check"]
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_renew_controller_certificate",
            args={"controller": controller, "signed_certificate": pem, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply_install,
        )

    @reg.write(title="Sync the SD-WAN root certificate", task=True)
    async def catsdwan_sync_root_cert(
        ctx: Context,
        wait: Annotated[bool, Field(description="Follow the sync to the end (default true)")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push the Manager's root certificate chain to every device (POST /certificate/forcesync/rootCert),
        after a root or Enterprise CA change. Preview-first: the chain that would be sent (expiring first)
        and the devices that receive it. Write tier. Devices keep their own certificates; only their trust
        store is refreshed."""
        app: SdwanApp = get_client(ctx)
        errors: list[str] = []
        chain, devices = await asyncio.gather(
            _optional(_rows(app, ROOT_CHAIN_PATH, {"action": "get"}), f"GET {ROOT_CHAIN_PATH}", errors),
            app.devices(),
        )
        mode, edge_ca = await _signing(app, errors)
        reachable = [d for d in devices if str(d.get("reachability", "")).lower() == "reachable"]
        unreachable = [str(d.get("host-name") or d.get("system-ip")) for d in devices if d not in reachable]
        roots = root_rows(chain or [])
        details: dict[str, Any] = {
            "root_chain": [{k: r.get(k) for k in ("name", "expires", "status")} for r in roots],
            "signing": signing_row(mode, edge_ca),
            "devices": len(reachable),
            "request": f"POST {FORCE_SYNC_ROOT_PATH} (an action, followed)",
        }
        if unreachable:
            details["not_reached"] = unreachable[:25]
        if errors:
            details["errors"] = errors
        plan = Plan(
            f"Send the root certificate chain ({len(roots)} CAs) to {len(reachable)} reachable devices",
            details=details,
            side_effects=["each device's trust store is replaced with the Manager's chain"],
            fingerprint=[r.get("fingerprint") or r.get("name") for r in roots],
            blast_radius=len(reachable),
        )

        async def apply() -> Any:
            answer = await app.api.post(FORCE_SYNC_ROOT_PATH, None)
            # The force-sync's action status never lists device rows (live 20.18.3): follow it until it
            # leaves the running tasks, and point at the audit log for the per-device installs.
            sync = await _started(app, ctx, answer, wait, "root certificate sync", rowless=True)
            if sync.get("outcome") == "done" and not sync.get("devices"):
                sync["note"] = (
                    "the Manager lists no devices for this action; each device's install shows in "
                    "catsdwan_audit_log(module='vmanage-root-ca') as 'Installed root cert chain on ...'"
                )
            return {"sync": sync}

        return await preview_or_apply(
            ctx,
            tool="catsdwan_sync_root_cert",
            args={"wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
