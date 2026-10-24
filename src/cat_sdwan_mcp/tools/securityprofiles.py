"""W48 edge security profiles (preview-first writes): IPS, URL filtering, AMP, the advanced inspection profile
that bundles them, the embedded-security policy that applies it, and their removal."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.inventory import load_inventory, resolve
from cat_sdwan_mcp.securityprofiles import (
    AIP_REFS,
    EMBEDDED_LIST_PATH,
    KIND_LABEL,
    KINDS,
    POLICY_OBJECT_LIST_PATH,
    POLICY_OBJECT_PATH,
    SECURITY_POLICY_LIST_PATH,
    SECURITY_POLICY_PATH,
    UNIFIED_LIST_PATH,
    UNIFIED_PATH,
    aip_data,
    amp_data,
    changes,
    check_categories,
    check_name,
    data_of,
    find,
    ips_data,
    names_of,
    parcels_in,
    plain,
    policy_data,
    profiles_of,
    referencing,
    url_data,
)
from cat_sdwan_mcp.tools.utd import edge_state, repository

Reputation = Literal["high-risk", "suspicious", "moderate-risk", "low-risk", "trustworthy"]
Region = Literal["nam", "eur", "apjc"]
Alert = Literal["critical", "warning", "info"]
GROUP_STEP = (
    "catsdwan_set_security_policy (applies the advanced inspection profile) -> "
    "catsdwan_create_policy_group / "
    "catsdwan_associate_policy_group (the embedded-security profile and the edges) -> "
    "catsdwan_deploy_policy_group"
)
STORES_ONLY = (
    "Stored on the Manager only: no edge changes until a policy group with this security policy is deployed"
)


# --- lookups -------------------------------------------------------------------------------------


async def policy_object(app: SdwanApp) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(the policy-object profile {id, name}, its parcels): one per Manager, Default_Policy_Object_Profile."""
    body = await app.api.get(POLICY_OBJECT_LIST_PATH)
    profiles = profiles_of(body)
    if not profiles:
        raise NotFound(
            "The Manager has no policy-object feature profile (Configuration > Policy Objects creates "
            "Default_Policy_Object_Profile on first use)."
        )
    prof = next((p for p in profiles if p.get("name") == "Default_Policy_Object_Profile"), profiles[0])
    detail = await app.api.get(path(POLICY_OBJECT_PATH, profile=prof["id"]))
    return prof, parcels_in(detail)


async def read_unified(app: SdwanApp, profile_id: str, parcel: dict[str, Any]) -> Any:
    return await app.api.get(path(UNIFIED_PATH, profile=profile_id, kind=parcel["kind"], parcel=parcel["id"]))


def need(parcels: list[dict[str, Any]], kind: str, ref_: str, tool: str) -> dict[str, Any]:
    found = find(parcels, kind, ref_)
    if not found:
        have = names_of(parcels, kind)
        raise NotFound(
            f"No {KIND_LABEL[kind]} {ref_!r}. Existing: {', '.join(have) or 'none'} ({tool} creates one)."
        )
    return found


def _new_id(answer: Any) -> str | None:
    if isinstance(answer, dict):
        v = answer.get("parcelId") or answer.get("id") or answer.get("profileId")
        return str(v) if v else None
    return None


async def plan_unified(
    ctx: Context,
    *,
    tool: str,
    args: dict[str, Any],
    kind: str,
    name: str,
    description: str | None,
    build: Callable[[list[dict[str, Any]]], dict[str, Any]],
    confirm: str | None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """Create or update one security parcel of the policy-object profile (POST or PUT), preview-first."""
    app: SdwanApp = get_client(ctx)
    name = check_name(name)
    prof, parcels = await policy_object(app)
    data = build(parcels)
    existing = find(parcels, kind, name)
    current: dict[str, Any] = {}
    if existing:
        current = data_of(await read_unified(app, prof["id"], existing))
    diff = changes(current, data) if existing else {}
    blockers = []
    if existing and not diff:
        blockers.append(f"nothing to change: {KIND_LABEL[kind]} {name} already has these values")
    desc = description or f"{KIND_LABEL[kind]} {name} (catsdwan MCP)"
    body = {"name": name, "description": desc, "data": data}
    if existing:
        url = path(UNIFIED_PATH, profile=prof["id"], kind=kind, parcel=existing["id"])
        request = f"PUT {url}"
        undo = "this tool again with the old values (`before`)"
    else:
        url = path(UNIFIED_LIST_PATH, profile=prof["id"], kind=kind)
        request = f"POST {url}"
        undo = f"catsdwan_delete_security_profile(kind={kind!r}, name={name!r})"
    details: dict[str, Any] = {
        "kind": kind,
        "profile": prof.get("name"),
        "action": "update" if existing else "create",
        "values": plain(data),
        "request": request,
        "next": GROUP_STEP,
        "undo": undo,
    }
    if existing:
        details["before"] = plain(current)
        details["changes"] = diff
    if notes:
        details["notes"] = notes
    plan = Plan(
        f"{'Update' if existing else 'Create'} the {KIND_LABEL[kind]} {name}",
        details=details,
        side_effects=[STORES_ONLY],
        fingerprint=[existing["id"] if existing else None, current],
        blockers=blockers,
        blast_radius=1,
    )

    async def apply() -> Any:
        if existing:
            answer = await app.api.put(url, body)
            pid = _new_id(answer) or existing["id"]
        else:
            answer = await app.api.post(url, body)
            pid = _new_id(answer)
        return {
            "outcome": "updated" if existing else "created",
            "parcel_id": pid,
            "name": name,
            "next": GROUP_STEP,
        }

    return await preview_or_apply(ctx, tool=tool, args=args, confirm=confirm, plan=plan, apply=apply)


async def _embedded(app: SdwanApp, ref_: str) -> dict[str, Any] | None:
    want = ref_.strip().lower()
    body = await app.api.get(EMBEDDED_LIST_PATH)
    return next(
        (p for p in profiles_of(body) if want in (p["id"].lower(), str(p.get("name") or "").lower())), None
    )


async def _policy_parcels(app: SdwanApp, profile_id: str) -> list[dict[str, Any]]:
    body = await app.api.get(path(SECURITY_POLICY_LIST_PATH, profile=profile_id))
    rows = body.get("data", body) if isinstance(body, dict) else body
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get("parcelId"):
            payload = r["payload"] if isinstance(r.get("payload"), dict) else {}
            out.append({"id": str(r["parcelId"]), "name": payload.get("name"), "body": r})
    return out


def _kept(data: dict[str, Any], key: str) -> str | None:
    """'kept (ref <id>)' when the policy keeps its stored `key` assembly entry, else None."""
    for e in data.get("assembly") or []:
        if isinstance(e, dict) and isinstance(e.get(key), dict):
            return f"kept ({plain(e)[key]})"
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Set an SD-WAN IPS profile")
    async def catsdwan_set_ips_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (1-32 characters, no spaces)")],
        signature_set: Annotated[
            Literal["balanced", "connectivity", "security", "max-detect", "no-rules-active"],
            Field(description="Talos signature set: connectivity (fewest), balanced, security, max-detect"),
        ] = "balanced",
        mode: Annotated[
            Literal["detection", "protection"],
            Field(description="detection (alert only, IDS) or protection (drop, IPS)"),
        ] = "protection",
        log_level: Annotated[
            Literal["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"],
            Field(description="Alerts at this severity and above are logged"),
        ] = "error",
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update an intrusion prevention (Snort IPS/IDS) profile: the signature set and
        detection (IDS) or protection (IPS) mode, as a security parcel of the policy-object profile.
        Preview: the values, the change against the stored profile, the request. Stores only: it reaches an
        edge through catsdwan_set_inspection_profile -> catsdwan_set_security_policy -> a deployed policy
        group, and needs the UTD engine there (catsdwan_utd_status)."""
        return await plan_unified(
            ctx,
            tool="catsdwan_set_ips_profile",
            args={
                "name": name,
                "signature_set": signature_set,
                "mode": mode,
                "log_level": log_level,
                "description": description,
            },  # fmt: skip
            kind="intrusion-prevention",
            name=name,
            description=description,
            build=lambda _p: ips_data(signature_set=signature_set, mode=mode, log_level=log_level),
            confirm=confirm,
        )

    @reg.write(title="Set an SD-WAN URL-filtering profile")
    async def catsdwan_set_url_filtering_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (1-32 characters, no spaces)")],
        categories: Annotated[
            list[str] | None,
            Field(description="Web categories the action applies to, e.g. ['gambling', 'malware-sites']"),
        ] = None,
        action: Annotated[
            Literal["block", "allow"], Field(description="block or allow the listed categories")
        ] = "block",
        reputation: Annotated[
            Reputation,
            Field(description="Block sites at this web reputation or worse (high-risk is the worst)"),
        ] = "moderate-risk",
        block_page_text: Annotated[
            str | None, Field(description="Text of the block page (default: the Manager's usual text)")
        ] = None,
        redirect_url: Annotated[
            str | None, Field(description="Redirect blocked requests here instead of a block page")
        ] = None,
        alerts: Annotated[
            list[Literal["blacklist", "whitelist", "categories-reputation"]] | None,
            Field(description="Send alerts for these matches (none: alerts off)"),
        ] = None,
        allowed_list: Annotated[
            str | None, Field(description="An existing URL allow-list policy object (name or id)")
        ] = None,
        blocked_list: Annotated[
            str | None, Field(description="An existing URL block-list policy object (name or id)")
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update a URL-filtering profile: web categories to block (or allow), the web reputation
        threshold, the block page (text or a redirect URL), alerts and optional allow/block URL lists. The
        categories are checked against the Manager's list ('did you mean'). Stores only; reaches an edge
        through catsdwan_set_inspection_profile -> catsdwan_set_security_policy -> a deployed policy group.
        HTTPS sites are matched by name (SNI) unless the SSL proxy decrypts them."""
        cats = check_categories(categories, "categories")
        if action == "allow" and not cats:
            raise InvalidRequest("action='allow' needs categories.")
        if block_page_text and redirect_url:
            raise InvalidRequest("Give block_page_text or redirect_url, not both.")

        def build(parcels: list[dict[str, Any]]) -> dict[str, Any]:
            lists = {}
            for k, v in (("allowed", allowed_list), ("blocked", blocked_list)):
                if v:
                    hit = next(
                        (
                            p
                            for p in parcels
                            if "url" in p["kind"]
                            and p["kind"] not in KINDS
                            and v.strip().lower() in (p["id"].lower(), str(p.get("name") or "").lower())
                        ),
                        None,
                    )
                    if not hit:
                        raise NotFound(f"No URL list policy object {v!r} ({k}_list).")
                    lists[k] = hit["id"]
            return url_data(
                action=action,
                categories=cats,
                reputation=reputation,
                block_page_text=block_page_text,
                redirect_url=redirect_url,
                alerts=list(alerts or []),
                allowed_list=lists.get("allowed"),
                blocked_list=lists.get("blocked"),
            )

        return await plan_unified(
            ctx,
            tool="catsdwan_set_url_filtering_profile",
            args={
                "name": name,
                "categories": cats,
                "action": action,
                "reputation": reputation,
                "block_page_text": block_page_text,
                "redirect_url": redirect_url,
                "alerts": alerts,
                "allowed_list": allowed_list,
                "blocked_list": blocked_list,
                "description": description,
            },  # fmt: skip
            kind="url-filtering",
            name=name,
            description=description,
            build=build,
            confirm=confirm,
        )

    @reg.write(title="Set an SD-WAN AMP (file) profile")
    async def catsdwan_set_amp_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (1-32 characters, no spaces)")],
        region: Annotated[Region, Field(description="AMP file-reputation cloud region")] = "nam",
        alert: Annotated[Alert, Field(description="File-reputation alert level")] = "critical",
        file_analysis: Annotated[
            bool, Field(description="Also send unknown files to Threat Grid for sandbox analysis")
        ] = False,
        analysis_region: Annotated[
            Literal["nam", "eur"], Field(description="Threat Grid region (file_analysis)")
        ] = "nam",
        file_types: Annotated[
            list[str] | None,
            Field(description="File types to analyse (file_analysis), e.g. ['pdf', 'ms-exe', 'new-office']"),
        ] = None,
        analysis_alert: Annotated[Alert, Field(description="File-analysis alert level")] = "critical",
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update an Advanced Malware Protection (file policy) profile: file reputation lookups in
        the AMP cloud region (blocks known-malicious files such as the EICAR test file), optionally file
        analysis (Threat Grid) for chosen file types. AMP needs the edge to reach the AMP cloud over the
        internet. Stores only; reaches an edge through catsdwan_set_inspection_profile ->
        catsdwan_set_security_policy -> a deployed policy group."""
        data = amp_data(
            region=region,
            alert=alert,
            file_analysis=file_analysis,
            analysis_region=analysis_region,
            file_types=list(file_types or []),
            analysis_alert=analysis_alert,
        )
        return await plan_unified(
            ctx,
            tool="catsdwan_set_amp_profile",
            args={
                "name": name,
                "region": region,
                "alert": alert,
                "file_analysis": file_analysis,
                "analysis_region": analysis_region,
                "file_types": file_types,
                "analysis_alert": analysis_alert,
                "description": description,
            },  # fmt: skip
            kind="advanced-malware-protection",
            name=name,
            description=description,
            build=lambda _p: data,
            confirm=confirm,
        )

    @reg.write(title="Set an SD-WAN advanced inspection profile")
    async def catsdwan_set_inspection_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Profile name (1-32 characters, no spaces)")],
        ips: Annotated[str | None, Field(description="IPS profile (catsdwan_set_ips_profile)")] = None,
        url_filtering: Annotated[
            str | None, Field(description="URL-filtering profile (catsdwan_set_url_filtering_profile)")
        ] = None,
        amp: Annotated[str | None, Field(description="AMP profile (catsdwan_set_amp_profile)")] = None,
        tls_action: Annotated[
            Literal["decrypt", "neverDecrypt", "skipDecrypt"],
            Field(
                description="TLS traffic: decrypt (needs ssl_decryption_profile and the SSL proxy CA), "
                "neverDecrypt, skipDecrypt"
            ),
        ] = "neverDecrypt",
        ssl_decryption_profile: Annotated[
            str | None,
            Field(description="SSL decryption profile for tls_action='decrypt' (categories to decrypt)"),
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update an advanced inspection profile: the bundle of IPS, URL-filtering and AMP profiles
        (at least one, by name) and the TLS action (decrypt with an SSL decryption profile, or not). This is
        what a security policy applies (catsdwan_set_security_policy) and what makes the Manager install the
        UTD engine on the edges at the policy-group deploy. Stores only."""
        picks = {
            "intrusionPrevention": ips,
            "urlFiltering": url_filtering,
            "advancedMalwareProtection": amp,
            "sslDecryptionProfile": ssl_decryption_profile,
        }
        tools = {
            "intrusionPrevention": "catsdwan_set_ips_profile",
            "urlFiltering": "catsdwan_set_url_filtering_profile",
            "advancedMalwareProtection": "catsdwan_set_amp_profile",
            "sslDecryptionProfile": "catsdwan_set_ssl_decryption_profile",
        }
        notes = []
        if tls_action != "decrypt" and ssl_decryption_profile:
            notes.append("ssl_decryption_profile is only used with tls_action='decrypt'")

        def build(parcels: list[dict[str, Any]]) -> dict[str, Any]:
            refs = {}
            for f, v in picks.items():
                if v and (f != "sslDecryptionProfile" or tls_action == "decrypt"):
                    refs[f] = need(parcels, AIP_REFS[f], v, tools[f])["id"]
            return aip_data(tls_action=tls_action, refs=refs)

        return await plan_unified(
            ctx,
            tool="catsdwan_set_inspection_profile",
            args={
                "name": name,
                "ips": ips,
                "url_filtering": url_filtering,
                "amp": amp,
                "tls_action": tls_action,
                "ssl_decryption_profile": ssl_decryption_profile,
                "description": description,
            },  # fmt: skip
            kind="advanced-inspection-profile",
            name=name,
            description=description,
            build=build,
            confirm=confirm,
            notes=notes,
        )

    @reg.write(title="Set an SD-WAN embedded security policy (UTD)")
    async def catsdwan_set_security_policy(
        ctx: Context,
        name: Annotated[
            str,
            Field(description="Security policy name; also the embedded-security profile's (1-32 characters)"),
        ],
        inspection_profile: Annotated[
            str | None,
            Field(
                description="Advanced inspection profile to apply (catsdwan_set_inspection_profile); "
                "default: keep the one the policy has"
            ),
        ] = None,
        ssl_decryption: Annotated[
            str | None,
            Field(
                description="SSL decryption policy (catsdwan_set_ssl_decryption): the proxy settings; "
                "default: keep the one the policy has"
            ),
        ] = None,
        failure_mode: Annotated[
            Literal["open", "close"],
            Field(description="When the UTD engine is down: open (pass uninspected) or close (drop)"),
        ] = "open",
        resource_profile: Annotated[
            Literal["low", "medium", "high"],
            Field(description="UTD container resources (more Snort instances need more RAM and vCPU)"),
        ] = "low",
        url_database: Annotated[
            bool, Field(description="Download the URL category database to the edge (needs more memory)")
        ] = False,
        profile: Annotated[
            str | None,
            Field(description="Embedded-security feature profile (name or id); default: `name`, created"),
        ] = None,
        check_devices: Annotated[
            list[str] | None,
            Field(
                description="Edges you will deploy it to: the preview adds their UTD readiness (RAM, image)"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create or update the embedded-security policy that applies an advanced inspection profile (IPS,
        URL filtering, AMP) and the SSL decryption policy to the edges, with the UTD settings (failure mode,
        resource profile, URL database). Creates the embedded-security feature profile when it doesn't exist.
        Zone-based firewall rules already in the policy (ngfirewall, W47) are kept. The preview shows the
        policy, the change, the requests, and the UTD readiness: an image in the repository
        (catsdwan_upload_utd_image) and, for `check_devices`, each edge's RAM (UTD on a C8000V needs 8 GB)
        and matching image. Stores only: the group step installs and starts UTD on the edges:
        catsdwan_create_policy_group(profiles=[<this profile>]) / catsdwan_associate_policy_group(edges) ->
        catsdwan_deploy_policy_group -> catsdwan_utd_status."""
        app: SdwanApp = get_client(ctx)
        name = check_name(name)
        if not (inspection_profile or ssl_decryption):
            raise InvalidRequest("Give inspection_profile and/or ssl_decryption: the policy applies them.")
        prof_ref = (profile or name).strip()
        (po, parcels), emb = await asyncio.gather(policy_object(app), _embedded(app, prof_ref))
        aip = (
            need(
                parcels, "advanced-inspection-profile", inspection_profile, "catsdwan_set_inspection_profile"
            )
            if inspection_profile
            else None
        )
        ssl = (
            need(parcels, "ssl-decryption", ssl_decryption, "catsdwan_set_ssl_decryption")
            if ssl_decryption
            else None
        )
        existing: dict[str, Any] | None = None
        current: dict[str, Any] = {}
        if emb:
            pols = await _policy_parcels(app, emb["id"])
            existing = next((p for p in pols if str(p.get("name") or "").lower() == name.lower()), None)
            existing = existing or (pols[0] if len(pols) == 1 else None)
            if existing:
                body = existing["body"]
                if not data_of(body):
                    body = await app.api.get(
                        path(SECURITY_POLICY_PATH, profile=emb["id"], parcel=existing["id"])
                    )
                current = data_of(body)
        data = policy_data(
            current,
            inspection_id=aip["id"] if aip else None,
            ssl_decryption_id=ssl["id"] if ssl else None,
            failure_mode=failure_mode,
            resource_profile=resource_profile,
            url_database=url_database,
        )
        diff = changes(current, data) if existing else {}
        requests = []
        if not emb:
            requests.append(f"POST {EMBEDDED_LIST_PATH} {{name: {prof_ref!r}}} (embedded-security profile)")
        if existing and emb:
            requests.append(f"PUT {path(SECURITY_POLICY_PATH, profile=emb['id'], parcel=existing['id'])}")
        else:
            target = emb["id"] if emb else "<new profile>"
            requests.append("POST " + SECURITY_POLICY_LIST_PATH.replace("{profile}", target))
        blockers = []
        if existing and not diff:
            blockers.append(f"nothing to change: security policy {name} already applies these")
        images, repo_errors = await repository(app)
        readiness: dict[str, Any] = {
            "repository": [i.get("file") for i in images] or "no UTD image (catsdwan_upload_utd_image first)",
            "ram_needed_gb": 8,
        }
        warnings = list(repo_errors)
        if aip and not images:
            warnings.append(
                "the Manager's repository has no UTD image: the policy-group deploy cannot install UTD "
                "(catsdwan_upload_utd_image)"
            )
        if check_devices:
            inv = await load_inventory(app)
            states = await asyncio.gather(*(edge_state(app, resolve(inv, d), images) for d in check_devices))
            readiness["edges"] = [
                {
                    k: s[k]
                    for k in ("device", "memory_gb", "repository_image", "problems", "verdict")
                    if k in s
                }
                for s in states
            ]
            for s in states:
                for p in s.get("problems") or []:
                    warnings.append(f"{s['device']}: {p}")
        else:
            readiness["edges"] = "pass check_devices to check the edges (catsdwan_utd_status)"
        details: dict[str, Any] = {
            "profile": prof_ref,
            "action": "update" if existing else "create",
            "values": {
                "inspection_profile": aip.get("name") if aip else _kept(data, "advancedInspectionProfile"),
                "ssl_decryption": ssl.get("name") if ssl else _kept(data, "sslDecryption"),
                **plain({"settings": data["settings"], "appHosting": data["appHosting"]}),
                "other_assembly_entries_kept": len(data["assembly"]) - int(bool(aip)) - int(bool(ssl)),
            },
            "requests": requests,
            "utd_readiness": readiness,
            "next": "catsdwan_create_policy_group(profiles=[" + repr(prof_ref) + "]) / "
            "catsdwan_associate_policy_group(edges) -> catsdwan_deploy_policy_group (installs UTD) -> "
            "catsdwan_utd_status",
            "undo": f"catsdwan_delete_security_profile(kind='security-policy', name={name!r}, "
            f"profile={prof_ref!r})",
        }
        if existing:
            details["before"] = plain(current)
            details["changes"] = diff
        if warnings:
            details["warnings"] = warnings
        plan = Plan(
            f"{'Update' if existing else 'Create'} security policy {name} in embedded-security profile "
            f"{prof_ref}",
            details=details,
            side_effects=[
                STORES_ONLY,
                "At the deploy the Manager installs the UTD container from the repository on each edge that "
                "lacks it (C8000V: 8 GB RAM) and starts Snort; traffic is inspected from then on",
            ],
            fingerprint=[emb, existing["id"] if existing else None, current, aip, ssl],
            blockers=blockers,
            blast_radius=1,
        )
        policy_body = {"name": name, "description": f"Security policy {name} (catsdwan MCP)", "data": data}

        async def apply() -> Any:
            out: dict[str, Any] = {}
            pid = emb["id"] if emb else None
            if not pid:
                created = await app.api.post(
                    EMBEDDED_LIST_PATH,
                    {"name": prof_ref, "description": f"Embedded security {prof_ref} (catsdwan MCP)"},
                )
                pid = _new_id(created)
                if not pid:
                    found = await _embedded(app, prof_ref)
                    pid = found["id"] if found else None
                if not pid:
                    raise UpstreamError(f"POST {EMBEDDED_LIST_PATH} answered no profile id: {created!r}")
                out["profile_created"] = pid
            if existing and emb:
                await app.api.put(path(SECURITY_POLICY_PATH, profile=pid, parcel=existing["id"]), policy_body)
                out["outcome"] = "updated"
                out["parcel_id"] = existing["id"]
            else:
                answer = await app.api.post(path(SECURITY_POLICY_LIST_PATH, profile=pid), policy_body)
                out["outcome"] = "created"
                out["parcel_id"] = _new_id(answer)
            out["profile_id"] = pid
            out["next"] = details["next"]
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_security_policy",
            args={
                "name": name,
                "inspection_profile": inspection_profile,
                "ssl_decryption": ssl_decryption,
                "failure_mode": failure_mode,
                "resource_profile": resource_profile,
                "url_database": url_database,
                "profile": profile,
                "check_devices": check_devices,
            },  # fmt: skip
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete an SD-WAN security profile", destructive=True)
    async def catsdwan_delete_security_profile(
        ctx: Context,
        kind: Annotated[
            Literal[
                "intrusion-prevention",
                "url-filtering",
                "advanced-malware-protection",
                "advanced-inspection-profile",
                "ssl-decryption",
                "ssl-decryption-profile",
                "security-policy",
            ],
            Field(description="What to delete; security-policy is the embedded-security policy parcel"),
        ],
        name: Annotated[str, Field(description="Its name or id")],
        profile: Annotated[
            str | None,
            Field(description="security-policy: the embedded-security profile (default: `name`)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a security profile parcel (the undo of the catsdwan_set_* security tools). The preview names
        the advanced inspection profiles that still reference an IPS, URL-filtering, AMP or SSL decryption
        profile (the Manager refuses to delete a referenced parcel: remove the reference first). Deleting a
        security policy that a deployed policy group uses takes effect on the edges at the next deploy."""
        app: SdwanApp = get_client(ctx)
        blockers: list[str] = []
        details: dict[str, Any] = {"kind": kind}
        if kind == "security-policy":
            emb = await _embedded(app, (profile or name).strip())
            if not emb:
                raise NotFound(f"No embedded-security profile {(profile or name)!r}.")
            pols = await _policy_parcels(app, emb["id"])
            want = name.strip().lower()
            hit = next((p for p in pols if want in (p["id"].lower(), str(p.get("name") or "").lower())), None)
            if not hit:
                raise NotFound(f"No security policy {name!r} in profile {emb.get('name')}.")
            url = path(SECURITY_POLICY_PATH, profile=emb["id"], parcel=hit["id"])
            details.update({"profile": emb.get("name"), "name": hit.get("name"), "request": f"DELETE {url}"})
            fingerprint: Any = [emb["id"], hit["id"]]
            summary = f"Delete security policy {hit.get('name')} from {emb.get('name')}"
        else:
            prof, parcels = await policy_object(app)
            hit = find(parcels, kind, name)
            if not hit:
                have = ", ".join(names_of(parcels, kind)) or "none"
                raise NotFound(f"No {KIND_LABEL[kind]} {name!r}. Existing: {have}.")
            url = path(UNIFIED_PATH, profile=prof["id"], kind=kind, parcel=hit["id"])
            details.update({"name": hit.get("name"), "request": f"DELETE {url}"})
            if kind in AIP_REFS.values():
                aips = [p for p in parcels if p["kind"] == "advanced-inspection-profile"]
                bodies = await asyncio.gather(*(read_unified(app, prof["id"], p) for p in aips))
                users = referencing(list(zip(aips, bodies, strict=True)), hit["id"])
                if users:
                    blockers.append(
                        f"still referenced by advanced inspection profile(s) {', '.join(users)}: change or "
                        "delete those first (catsdwan_set_inspection_profile)"
                    )
                details["referenced_by"] = users
            fingerprint = [hit["id"]]
            summary = f"Delete the {KIND_LABEL[kind]} {hit.get('name')}"
        plan = Plan(
            summary,
            details=details,
            side_effects=["Policy groups using it change on the edges at their next deploy"],
            fingerprint=fingerprint,
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            await app.api.delete(url)
            return {"outcome": "deleted", "name": details.get("name")}

        return await preview_or_apply(
            ctx,
            tool="catsdwan_delete_security_profile",
            args={"kind": kind, "name": name, "profile": profile},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
