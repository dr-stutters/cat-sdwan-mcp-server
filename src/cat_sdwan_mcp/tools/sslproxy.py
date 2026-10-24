"""W49 TLS/SSL proxy: catsdwan_ssl_proxy_ca (read), catsdwan_set_ssl_proxy_ca (the CA, two steps),
catsdwan_set_ssl_decryption and catsdwan_set_ssl_decryption_profile (the decryption parcels)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

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
    object_result,
    poll_until,
    preview_or_apply,
)
from cat_sdwan_mcp.certificates import pem_digest
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.securityprofiles import check_categories
from cat_sdwan_mcp.sslproxy import (
    EDGE_LIST_PATH,
    ENTERPRISE_ROOT_PATH,
    GENERATE_CSR_PATH,
    MANAGER_CERT_PATH,
    MANAGER_CSR_PATH,
    MANAGER_ROOT_PATH,
    SETTINGS_PATH,
    cert_view,
    csr_body,
    csr_pem_of,
    decryption_data,
    decryption_profile_data,
    edge_row,
    first_pem,
    install_body,
    mode_of,
    records,
    root_check,
    signed_check,
)
from cat_sdwan_mcp.tools.changes import dangerous_blockers
from cat_sdwan_mcp.tools.securityprofiles import plan_unified

Reputation = Literal["high-risk", "suspicious", "moderate-risk", "low-risk", "trustworthy"]
CSR_WAIT = 60.0


async def _get(app: SdwanApp, p: str) -> tuple[Any, str | None]:
    try:
        return await app.api.get(p), None
    except UpstreamError as e:
        return None, f"GET {p} failed: {str(e)[:200]}"


async def ca_state(app: SdwanApp) -> dict[str, Any]:
    """Everything the Manager says about the proxy CA (each read optional)."""
    paths = (SETTINGS_PATH, ENTERPRISE_ROOT_PATH, MANAGER_ROOT_PATH, MANAGER_CERT_PATH, MANAGER_CSR_PATH)
    got = await asyncio.gather(*(_get(app, p) for p in paths))
    (settings, _), (ent, _), (mroot, _), (mcert, _), (csr, _) = got
    errors = [e for _, e in got if e]
    ent_pem = next((p for r in records(ent) if (p := first_pem(r, "enterpriseRootCA"))), None)
    mcert_rec = next((r for r in records(mcert) if first_pem(r, "vManageRootCA")), None)
    mroot_rec = next((r for r in records(mroot) if first_pem(r, "publickey", "vManageRootCA")), None)
    csr_pem, csr_rec = csr_pem_of(csr)
    return {
        "settings": settings if isinstance(settings, dict) else {},
        "enterprise_root": ent_pem,
        "manager_cert": mcert_rec,
        "manager_root": mroot_rec,
        "csr": csr_pem,
        "csr_record": csr_rec,
        "errors": errors,
    }


def _view(st: dict[str, Any]) -> dict[str, Any]:
    mcert = st["manager_cert"]
    out: dict[str, Any] = {
        "mode": mode_of(st["settings"], mcert, st["enterprise_root"]),
        "flags": st["settings"] or "not read",
        "enterprise_root": cert_view(st["enterprise_root"]) or "none",
        "manager_ca": cert_view(first_pem(mcert, "vManageRootCA")) if mcert else "none",
    }
    if st["manager_root"]:
        out["manager_root_ca"] = cert_view(first_pem(st["manager_root"], "publickey", "vManageRootCA"))
    if st["csr"]:
        out["pending_csr"] = {
            "common_name": st["csr_record"].get("commonName"),
            "digest": pem_digest(st["csr"]),
            "pem": st["csr"],
        }
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN SSL proxy CA")
    async def catsdwan_ssl_proxy_ca(
        ctx: Context,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """The TLS/SSL proxy's certificate authority on the Manager (Administration > Settings > TLS/SSL
        Proxy): the mode (none, the Manager as root CA, the Manager as intermediate CA under the enterprise
        CA, the enterprise CA), the enterprise root, the Manager's CA certificate (subject, issuer, expiry),
        a pending CSR waiting to be signed (with its PEM, for win_sign_csr), and the edges' proxy certificates
        (state, expiry). Set it with catsdwan_set_ssl_proxy_ca."""
        app: SdwanApp = get_client(ctx)
        st, (edges, edge_err) = await asyncio.gather(ca_state(app), _get(app, EDGE_LIST_PATH))
        out = _view(st)
        rows = [edge_row(r) for r in records(edges, "sslproxylist")]
        out["edge_certificates"] = rows or "none (issued when a policy with SSL decryption is deployed)"
        mode = out["mode"]
        if mode == "none":
            out["next"] = (
                "catsdwan_set_ssl_proxy_ca(root_certificate=<enterprise root PEM>, common_name=...) "
                "generates the Manager's CA key and CSR; sign it with win_sign_csr(template='SubCA'); then "
                "catsdwan_set_ssl_proxy_ca(signed_certificate=<PEM>)"
            )
        elif st["csr"] and mode != "manager-intermediate-ca":
            out["next"] = (
                "sign pending_csr.pem with the enterprise CA (win_sign_csr, template 'SubCA'), then "
                "catsdwan_set_ssl_proxy_ca(signed_certificate=<PEM>)"
            )
        errors = st["errors"] + ([edge_err] if edge_err else [])
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)

    @reg.write(title="Set the SD-WAN SSL proxy CA")
    async def catsdwan_set_ssl_proxy_ca(
        ctx: Context,
        signed_certificate: Annotated[
            str | None,
            Field(
                description="Step 2: the certificate the enterprise CA signed from the Manager's CSR (PEM). "
                "Leave empty for step 1 (the root and the CSR)"
            ),
        ] = None,
        root_certificate: Annotated[
            str | None,
            Field(
                description="Step 1: the enterprise root CA certificate (PEM; lab: win_get_ca_certificate); "
                "not needed when the Manager already has it"
            ),
        ] = None,
        common_name: Annotated[
            str, Field(description="Step 1: the Manager CA's common name (also step 2's record name)")
        ] = "sdwan-ssl-proxy-ca",
        org: Annotated[str, Field(description="Step 1: organization")] = "Lab",
        org_unit: Annotated[str, Field(description="Step 1: organizational unit")] = "Network",
        locality: Annotated[str, Field(description="Step 1: city")] = "Lab",
        state: Annotated[str, Field(description="Step 1: state or province")] = "Lab",
        country: Annotated[str, Field(description="Step 1: two-letter country code")] = "CA",
        email: Annotated[str, Field(description="Step 1: contact email")] = "netops@example.com",
        replace: Annotated[
            bool,
            Field(
                description="Replace a CA the Manager already has (dangerous: the edges' proxy certificates)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set up the SSL proxy's CA with the Manager as an intermediate CA under the enterprise CA, so the
        CA's private key is generated on the Manager and never leaves it. Step 1 (no signed_certificate):
        the preview checks the enterprise root (self-signed, a CA, in date) and shows the CSR subject; confirm
        stores the root (POST /sslproxy/settings/enterprise/rootca), generates the key and CSR on the Manager
        (POST /sslproxy/generate/vmanage/csr) and returns the CSR PEM. Sign it as a subordinate CA (lab:
        Windows_Server win_sign_csr(csr, template='SubCA')). Step 2 (signed_certificate=<PEM>): the preview
        checks it is a CA, carries the CSR's key and was issued by the root; confirm installs it (POST
        /sslproxy/settings/vmanage/certificate). The edges get proxy certificates from this CA when a policy
        with SSL decryption is deployed (catsdwan_set_ssl_decryption -> catsdwan_set_security_policy -> the
        policy group). Replacing an existing CA (replace=true) is dangerous tier. Check with
        catsdwan_ssl_proxy_ca."""
        app: SdwanApp = get_client(ctx)
        st = await ca_state(app)
        view = _view(st)
        mode = view["mode"]
        blockers: list[str] = []
        has_ca = mode in ("manager-intermediate-ca", "manager-root-ca", "enterprise-ca")
        if has_ca:
            if not replace:
                blockers.append(
                    f"the Manager already has an SSL proxy CA ({mode}): pass replace=true to replace it "
                    "(catsdwan_ssl_proxy_ca shows it)"
                )
            else:
                blockers += dangerous_blockers(
                    ctx, app, ["replacing the proxy CA invalidates the edges' proxy certificates"]
                )
        details: dict[str, Any] = {"before": {k: view[k] for k in ("mode", "enterprise_root", "manager_ca")}}
        if signed_certificate:
            pem = signed_certificate.strip()
            check = signed_check(pem, st["csr"], st["enterprise_root"])
            details["certificate_check"] = check
            blockers += [f"signed_certificate: {p}" for p in check.get("problems", [])]
            cn = str(st["csr_record"].get("commonName") or common_name)
            body = install_body(cn, pem)
            details["request"] = (
                f"POST {MANAGER_CERT_PATH} {{data: [{{commonName: {cn!r}, intermediateCA}}]}}"
            )
            details["after"] = "the Manager signs the edges' proxy certificates with this CA"
            summary = f"Install the SSL proxy CA certificate {check.get('subject') or ''}".rstrip()
            fingerprint: Any = [pem_digest(st["csr"]), pem_digest(st["enterprise_root"]), mode]

            async def apply() -> Any:
                answer = await app.api.post(MANAGER_CERT_PATH, body)
                after = await ca_state(app)
                return {
                    "outcome": "installed",
                    "answer": _brief(answer),
                    "mode": mode_of(after["settings"], after["manager_cert"], after["enterprise_root"]),
                    "next": "catsdwan_set_ssl_decryption -> catsdwan_set_ssl_decryption_profile -> "
                    "catsdwan_set_inspection_profile(tls_action='decrypt') -> catsdwan_set_security_policy",
                }

        else:
            root = (root_certificate or "").strip() or st["enterprise_root"]
            rc = root_check(root)
            details["root_check"] = rc
            blockers += [f"root_certificate: {p}" for p in rc.get("problems", [])]
            send_root = bool(root_certificate) and pem_digest(root) != pem_digest(st["enterprise_root"])
            csr = csr_body(
                common_name=common_name,
                org=org,
                org_unit=org_unit,
                locality=locality,
                state=state,
                country=country,
                email=email,
            )
            requests = []
            if send_root:
                requests.append(f"POST {ENTERPRISE_ROOT_PATH} {{enterpriseRootCA, intermediateCA: 'true'}}")
            requests.append(f"POST {GENERATE_CSR_PATH} (the key stays on the Manager)")
            requests.append(f"GET {MANAGER_CSR_PATH} (the CSR to sign)")
            details["csr_subject"] = {k: v for k, v in csr.items() if k != "intermediateCA"}
            details["requests"] = requests
            if st["csr"]:
                details["notes"] = ["a CSR is already pending: generating a new one replaces it"]
            details["then"] = (
                "win_sign_csr(csr=<the PEM in the result>, template='SubCA') on the lab CA, then "
                "catsdwan_set_ssl_proxy_ca(signed_certificate=<PEM>)"
            )
            summary = f"Generate the SSL proxy CA key and CSR ({common_name}) on the Manager"
            fingerprint = [pem_digest(st["enterprise_root"]), mode, pem_digest(st["csr"])]
            old_csr = st["csr"]

            async def apply() -> Any:
                out: dict[str, Any] = {}
                if send_root:
                    await app.api.post(
                        ENTERPRISE_ROOT_PATH, {"enterpriseRootCA": root, "intermediateCA": "true"}
                    )
                    out["root"] = "stored"
                task = await app.api.post(GENERATE_CSR_PATH, csr)
                out["task"] = _brief(task)

                async def fetch() -> Any:
                    return await app.api.get(MANAGER_CSR_PATH)

                def ready(body: Any) -> bool:
                    pem, _ = csr_pem_of(body)
                    return bool(pem) and pem != old_csr

                body = await poll_until(fetch, done=ready, timeout=CSR_WAIT, interval=2.0, what="CSR")
                pem, rec = csr_pem_of(body)
                out.update(
                    {
                        "outcome": "csr generated",
                        "csr": pem,
                        "common_name": rec.get("commonName"),
                        "next": "win_sign_csr(csr=<csr>, template='SubCA'), then "
                        "catsdwan_set_ssl_proxy_ca(signed_certificate=<PEM>)",
                    }
                )
                return out

        details["tier"] = "dangerous" if has_ca else "write"
        if st["errors"]:
            details["read_errors"] = st["errors"]
        plan = Plan(
            summary,
            details=details,
            side_effects=[
                "The CA's private key is generated and kept on the Manager (never exported)",
                "Edges get proxy certificates from this CA at the next deploy of a policy with SSL "
                "decryption",
            ],
            fingerprint=fingerprint,
            blockers=blockers,
            blast_radius=1,
        )
        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_ssl_proxy_ca",
            args={
                "signed_certificate": signed_certificate,
                "root_certificate": root_certificate,
                "common_name": common_name,
                "org": org,
                "org_unit": org_unit,
                "locality": locality,
                "state": state,
                "country": country,
                "email": email,
                "replace": replace,
            },  # fmt: skip
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set an SD-WAN SSL decryption policy")
    async def catsdwan_set_ssl_decryption(
        ctx: Context,
        name: Annotated[str, Field(description="Policy name (1-32 characters, no spaces)")],
        enabled: Annotated[
            bool, Field(description="false: SSL decryption off (no other field is sent)")
        ] = True,
        expired_certificate: Annotated[
            Literal["drop", "decrypt"], Field(description="Server certificate expired")
        ] = "drop",
        untrusted_certificate: Annotated[
            Literal["drop", "decrypt"], Field(description="Server certificate not trusted")
        ] = "drop",
        revocation: Annotated[
            Literal["none", "ocsp"], Field(description="Certificate revocation check")
        ] = "none",
        unknown_status: Annotated[
            Literal["drop", "decrypt"], Field(description="OCSP status unknown (revocation='ocsp')")
        ] = "drop",
        unsupported_protocols: Annotated[
            Literal["no-decrypt", "drop"], Field(description="TLS versions the proxy can't decrypt")
        ] = "no-decrypt",
        unsupported_ciphers: Annotated[
            Literal["no-decrypt", "drop"], Field(description="Cipher suites the proxy can't decrypt")
        ] = "no-decrypt",
        failure_mode: Annotated[
            Literal["close", "open"], Field(description="When the proxy fails: close (drop) or open (pass)")
        ] = "close",
        key_modulus: Annotated[
            Literal["1024", "2048", "4096"], Field(description="RSA key size of the resigned certificates")
        ] = "2048",
        ec_key: Annotated[Literal["P256", "P384", "P521"], Field(description="EC key type")] = "P256",
        certificate_lifetime_days: Annotated[
            int,
            Field(
                ge=1,
                le=365,
                description="Lifetime of the proxy's certificate: 1 when the Manager is the CA (the Manager "
                "ignores other values then)",
            ),
        ] = 1,
        min_tls: Annotated[
            Literal["TLSv1", "TLSv1.1", "TLSv1.2"], Field(description="Lowest TLS version decrypted")
        ] = "TLSv1.2",
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update the SSL decryption policy (the proxy's behaviour: what to do with expired or
        untrusted server certificates, revocation checks, unsupported TLS versions and ciphers, failure mode,
        key sizes, minimum TLS), an ssl-decryption parcel of the policy-object profile, signed by the proxy CA
        (catsdwan_set_ssl_proxy_ca, catsdwan_ssl_proxy_ca). Which traffic is decrypted is the SSL decryption
        profile (catsdwan_set_ssl_decryption_profile). Stores only; applied by catsdwan_set_security_policy
        (ssl_decryption=<name>) and a deployed policy group."""
        app: SdwanApp = get_client(ctx)
        st = await ca_state(app)
        mode = mode_of(st["settings"], st["manager_cert"], st["enterprise_root"])
        notes = []
        if enabled and mode in ("none", "enterprise-root-only"):
            notes.append(
                "the Manager has no SSL proxy CA yet: the edges can't resign server certificates until "
                "catsdwan_set_ssl_proxy_ca finishes (catsdwan_ssl_proxy_ca)"
            )
        data = decryption_data(
            enabled=enabled,
            expired_certificate=expired_certificate,
            untrusted_certificate=untrusted_certificate,
            revocation=revocation,
            unknown_status=unknown_status,
            unsupported_protocols=unsupported_protocols,
            unsupported_ciphers=unsupported_ciphers,
            failure_mode=failure_mode,
            key_modulus=key_modulus,
            ec_key=ec_key,
            certificate_lifetime_days=certificate_lifetime_days,
            min_tls=min_tls,
        )
        return await plan_unified(
            ctx,
            tool="catsdwan_set_ssl_decryption",
            args={
                "name": name,
                "enabled": enabled,
                "expired_certificate": expired_certificate,
                "untrusted_certificate": untrusted_certificate,
                "revocation": revocation,
                "unknown_status": unknown_status,
                "unsupported_protocols": unsupported_protocols,
                "unsupported_ciphers": unsupported_ciphers,
                "failure_mode": failure_mode,
                "key_modulus": key_modulus,
                "ec_key": ec_key,
                "certificate_lifetime_days": certificate_lifetime_days,
                "min_tls": min_tls,
                "description": description,
            },  # fmt: skip
            kind="ssl-decryption",
            name=name,
            description=description or "TLS/SSL Proxy Policy Definition",
            build=lambda _p: data,
            confirm=confirm,
            notes=notes,
        )

    @reg.write(title="Set an SD-WAN SSL decryption profile")
    async def catsdwan_set_ssl_decryption_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (1-32 characters, no spaces)")],
        decrypt_categories: Annotated[
            list[str] | None, Field(description="Web categories to decrypt, e.g. ['gambling', 'games']")
        ] = None,
        never_decrypt_categories: Annotated[
            list[str] | None,
            Field(
                description="Categories never decrypted (bypass), e.g. ['financial-services', "
                "'health-and-medicine']"
            ),
        ] = None,
        skip_decrypt_categories: Annotated[
            list[str] | None, Field(description="Categories skipped (not decrypted, still inspected by name)")
        ] = None,
        reputation: Annotated[
            bool, Field(description="Also decrypt by web reputation (decrypt_threshold)")
        ] = False,
        decrypt_threshold: Annotated[
            Reputation, Field(description="Decrypt sites at this reputation or worse (reputation=true)")
        ] = "suspicious",
        skip_threshold: Annotated[
            Reputation | None, Field(description="Skip decryption at this reputation (reputation=true)")
        ] = None,
        fail_decrypt: Annotated[bool, Field(description="Decrypt when the category lookup fails")] = True,
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update an SSL decryption profile: which web categories are decrypted, never decrypted
        (a bypass, e.g. banking and health) or skipped, optionally by reputation. An advanced inspection
        profile uses it with tls_action='decrypt' (catsdwan_set_inspection_profile). Categories are checked
        against the Manager's list and may appear in one list only. Stores only."""
        dec = check_categories(decrypt_categories, "decrypt_categories")
        never = check_categories(never_decrypt_categories, "never_decrypt_categories")
        skip = check_categories(skip_decrypt_categories, "skip_decrypt_categories")
        if not (dec or reputation):
            raise InvalidRequest(
                "Give decrypt_categories or reputation=true: otherwise nothing is decrypted."
            )
        data = decryption_profile_data(
            decrypt=dec,
            never=never,
            skip=skip,
            reputation=reputation,
            decrypt_threshold=decrypt_threshold,
            skip_threshold=skip_threshold,
            fail_decrypt=fail_decrypt,
        )
        return await plan_unified(
            ctx,
            tool="catsdwan_set_ssl_decryption_profile",
            args={
                "name": name,
                "decrypt_categories": dec,
                "never_decrypt_categories": never,
                "skip_decrypt_categories": skip,
                "reputation": reputation,
                "decrypt_threshold": decrypt_threshold,
                "skip_threshold": skip_threshold,
                "fail_decrypt": fail_decrypt,
                "description": description,
            },  # fmt: skip
            kind="ssl-decryption-profile",
            name=name,
            description=description,
            build=lambda _p: data,
            confirm=confirm,
        )


def _brief(answer: Any) -> Any:
    """An answer without certificate or CSR text (public, but long)."""
    if isinstance(answer, dict):
        return {k: ("<PEM>" if isinstance(v, str) and "-----BEGIN" in v else v) for k, v in answer.items()}
    return answer
