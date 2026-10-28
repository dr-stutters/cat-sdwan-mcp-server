"""W58 Enterprise CA renewal prompt (core `@reg.prompt`): catsdwan_renew_with_enterprise_ca.

Renews the controller certificates (validators, controllers, the Manager) with the organisation's Enterprise
CA, one controller at a time: what is due (catsdwan_certificates, catsdwan_list_controllers), a snapshot and a
backup, the CA's root against the chain the fabric trusts (catsdwan_sync_root_cert, W16, when it changed),
then per controller the CSR (catsdwan_renew_controller_certificate step 1) -> win_sign_csr on the Windows CA
with a template that issues server + client authentication -> the install (step 2) ->
catsdwan_control_connections verified before the next one. Dangerous tier, like the renew tool itself: a wrong
certificate drops every control connection to that controller. Every write stays preview-first; the prompt
tells the model to show each preview and wait.

Order (Cisco's controller certificate guidance): validators first (every join goes through them), then the
controllers, then the Manager last, so the session that runs the renewal is the last to see a new certificate.
The root comes before the first install: a controller only accepts a certificate whose issuer chain it already
trusts.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from cat_sdwan_mcp._core import Tier, ToolRegistrar, tool_ref

ORDER = "validators first, then controllers, then the Manager last"


def _clean(*texts: str) -> None:
    if any(not ch.isprintable() or ch in '"`' for t in texts for ch in t):
        raise ValueError("Arguments must be printable text without quotes or backticks.")


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Renew SD-WAN controller certificates with the Enterprise CA",
        uses=["catsdwan", "win"],
        tier=Tier.DANGEROUS,
        example={
            "controllers": "validator, controller",
            "ca_template": "SDWANController",
            "expiring_days": "60",
        },
    )
    def catsdwan_renew_with_enterprise_ca(
        controllers: Annotated[
            str,
            Field(
                description="Controllers to renew, comma separated (host names, system IPs or roles "
                "'validator', 'controller', 'manager'); blank = every one that is due"
            ),
        ] = "",
        ca_template: Annotated[
            str,
            Field(
                description="Certificate template on the Windows CA that issues server + client "
                "authentication (blank = pick one from win_list_ca_templates and ask the user)"
            ),
        ] = "",
        expiring_days: Annotated[
            str, Field(description="Due = invalid, expired or expiring within this many days")
        ] = "60",
    ) -> str:
        """Renew the Manager's, controllers' and validators' certificates with the organisation's Enterprise
        CA, one controller at a time: what is due (catsdwan_certificates), a snapshot and a backup, the CA's
        root against the fabric's chain (catsdwan_sync_root_cert when it changed), then per controller the CSR
        (catsdwan_renew_controller_certificate) -> win_sign_csr -> the install -> control connections back up
        and the serial changed before the next one. Dangerous tier; every write is preview-first."""
        _clean(controllers, ca_template, expiring_days)
        days = expiring_days.strip() or "60"
        if not days.isdigit() or int(days) > 3650:
            raise ValueError(f"expiring_days must be a whole number of days (0-3650), not {expiring_days!r}.")
        names = [c.strip() for c in controllers.split(",") if c.strip()]
        which = (
            "the controllers the user named: " + ", ".join(names) + f" (renew them in this order: {ORDER})"
            if names
            else f"every controller in the due list, in this order: {ORDER}"
        )
        template = (
            f'template="{ca_template.strip()}"'
            if ca_template.strip()
            else "template=<the template from step 4>"
        )
        pick = (
            f'Check "{ca_template.strip()}" is listed.'
            if ca_template.strip()
            else "Pick the one that issues BOTH server and client authentication (a Web Server template "
            "has server authentication only: a controller with it fails its DTLS/TLS peering); name it and "
            "wait for the user's go-ahead."
        )
        return f"""Renew SD-WAN controller certificates with the Enterprise CA: {which}.
Every write below is PREVIEW-FIRST: show the preview (the controller it names, its current serial and expiry,
the blockers), wait for the user's approval, then repeat the identical call with the confirm token. Never
confirm on your own, and never two controllers at once: a wrong certificate drops every control connection
to that controller (a validator's stops every join). Stop at the first failure and report it with its reason.
This needs MCP_ENABLE_DANGEROUS on this server. The CA is the Windows Server (win_) tools; when they are
not connected, say so, generate the CSR (step 5), hand it to whoever runs the CA, and go on with step 6 when
they return the signed PEM.

1. What is due: {tool_ref("catsdwan_certificates")} with kind="controller" and expiring_days={days}
   (status, expiry, days left, `breaks_when_expired`; `signing.controllers` must be 'enterprise': with Cisco
   signing the Manager renews controllers itself, so stop and say so). {tool_ref("catsdwan_list_controllers")}
   for each controller's role, system IP and reachability: every controller to renew must be reachable.
   Nothing due and none named: report the next expiry and stop. Then {tool_ref("catsdwan_certificates")} with
   kind="controller" and no expiring_days: the full list and the full `root_chain` (with expiring_days both
   leave out what is healthy, so a controller named but not due and a healthy root are missing). Write down
   each controller's current serial and expiry from it: step 7 proves they changed.
2. Before the change: {tool_ref("catsdwan_snapshot")} for the whole fabric (keep the blob for step 8) and
   {tool_ref("catsdwan_control_connections")} with no device (the fabric's baseline: every edge's
   connections to the controllers). Then a configuration-database backup with
   {tool_ref("catsdwan_create_backup")} (preview, approval; wait for it to finish).
3. The root: {tool_ref("win_get_ca_certificate")} (the CA's own certificate) against the
   full `root_chain` from step 1 (the list without expiring_days; match by subject or fingerprint).
   Listed: go on. Not listed, or a new root or intermediate: the Manager's Enterprise root CA must be updated
   first (Administration > Settings > Controller Certificate Authorization, or the settings endpoint
   {tool_ref("catsdwan_search_spec")} finds, through {tool_ref("catsdwan_api_call")}; preview-first), then
   {tool_ref("catsdwan_sync_root_cert")} (preview: the chain and the devices that receive it; approval) so
   every device trusts the new chain BEFORE any controller gets a certificate it signed.
4. The CA template: {tool_ref("win_list_ca_templates")}. {pick}

Then for each controller, one at a time, in the order above ({ORDER}):

5. CSR: {tool_ref("catsdwan_renew_controller_certificate")} with controller=<the controller> and no
   signed_certificate (step 1 of the tool). The preview shows the current certificate, the CSR fields and
   the signing mode; on approval it returns the CSR (PEM).
6. Sign and install: {tool_ref("win_sign_csr")} with csr_pem=<that CSR> and {template}; it returns the signed
   certificate (PEM). Then {tool_ref("catsdwan_renew_controller_certificate")} again with the same controller
   and signed_certificate=<the signed PEM> (step 2 of the tool): the preview checks the common name, validity
   and issuer against the controller's CSR (a blocker or an issuer warning: stop, don't install); on approval
   it installs the certificate and sends the controller list to the validators, both followed to the end.
7. Verify before the next controller: {tool_ref("catsdwan_certificates")} with kind="controller": this
   controller's serial is NOT the one from step 1, its expiry moved out and its state is installed. Then
   {tool_ref("catsdwan_control_connections")} with device=<this controller> (and no device for the fabric):
   every connection it had in step 2 is up again (allow a few minutes; failed attempts give the reason, e.g.
   certificate or serial not in the list). Not back: stop here, report, and renew no other controller;
   roll back by installing a certificate signed from a fresh CSR, or restore trust with
   catsdwan_sync_root_cert.
   If the root changed after step 3 for any reason, {tool_ref("catsdwan_sync_root_cert")} again (preview,
   approval) before the next controller.

8. After the last controller: {tool_ref("catsdwan_compare_snapshot")} with before=<the step 2 blob> (what got
   unhealthy: control connections, BFD, alarms), and {tool_ref("catsdwan_certificates")} once more with
   kind="controller" and expiring_days={days}: the renewed controllers are no longer due.

End with a table: controller, role, old serial and expiry, new serial and expiry, control connections
before and after, and anything left for the user (a root update, a controller not renewed)."""
