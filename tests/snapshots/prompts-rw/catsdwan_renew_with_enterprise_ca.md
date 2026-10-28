# catsdwan_renew_with_enterprise_ca

title: Renew SD-WAN controller certificates with the Enterprise CA
arguments: {"ca_template": "SDWANController", "controllers": "validator, controller", "expiring_days": "60"}

Renew the Manager's, controllers' and validators' certificates with the organisation's Enterprise
CA, one controller at a time: what is due (catsdwan_certificates), a snapshot and a backup, the CA's
root against the fabric's chain (catsdwan_sync_root_cert when it changed), then per controller the CSR
(catsdwan_renew_controller_certificate) -> win_sign_csr -> the install -> control connections back up
and the serial changed before the next one. Dangerous tier; every write is preview-first.

## user

Renew SD-WAN controller certificates with the Enterprise CA: the controllers the user named: validator, controller (renew them in this order: validators first, then controllers, then the Manager last).
Every write below is PREVIEW-FIRST: show the preview (the controller it names, its current serial and expiry,
the blockers), wait for the user's approval, then repeat the identical call with the confirm token. Never
confirm on your own, and never two controllers at once: a wrong certificate drops every control connection
to that controller (a validator's stops every join). Stop at the first failure and report it with its reason.
This needs MCP_ENABLE_DANGEROUS on this server. The CA is the Windows Server (win_) tools; when they are
not connected, say so, generate the CSR (step 5), hand it to whoever runs the CA, and go on with step 6 when
they return the signed PEM.

1. What is due: `catsdwan_certificates` with kind="controller" and expiring_days=60
   (status, expiry, days left, `breaks_when_expired`; `signing.controllers` must be 'enterprise': with Cisco
   signing the Manager renews controllers itself, so stop and say so). `catsdwan_list_controllers`
   for each controller's role, system IP and reachability: every controller to renew must be reachable.
   Nothing due and none named: report the next expiry and stop. Then `catsdwan_certificates` with
   kind="controller" and no expiring_days: the full list and the full `root_chain` (with expiring_days both
   leave out what is healthy, so a controller named but not due and a healthy root are missing). Write down
   each controller's current serial and expiry from it: step 7 proves they changed.
2. Before the change: `catsdwan_snapshot` for the whole fabric (keep the blob for step 8) and
   `catsdwan_control_connections` with no device (the fabric's baseline: every edge's
   connections to the controllers). Then a configuration-database backup with
   `catsdwan_create_backup` (preview, approval; wait for it to finish).
3. The root: `win_get_ca_certificate` (the CA's own certificate) against the
   full `root_chain` from step 1 (the list without expiring_days; match by subject or fingerprint).
   Listed: go on. Not listed, or a new root or intermediate: the Manager's Enterprise root CA must be updated
   first (Administration > Settings > Controller Certificate Authorization, or the settings endpoint
   `catsdwan_search_spec` finds, through `catsdwan_api_call`; preview-first), then
   `catsdwan_sync_root_cert` (preview: the chain and the devices that receive it; approval) so
   every device trusts the new chain BEFORE any controller gets a certificate it signed.
4. The CA template: `win_list_ca_templates`. Check "SDWANController" is listed.

Then for each controller, one at a time, in the order above (validators first, then controllers, then the Manager last):

5. CSR: `catsdwan_renew_controller_certificate` with controller=<the controller> and no
   signed_certificate (step 1 of the tool). The preview shows the current certificate, the CSR fields and
   the signing mode; on approval it returns the CSR (PEM).
6. Sign and install: `win_sign_csr` with csr_pem=<that CSR> and template="SDWANController"; it returns the signed
   certificate (PEM). Then `catsdwan_renew_controller_certificate` again with the same controller
   and signed_certificate=<the signed PEM> (step 2 of the tool): the preview checks the common name, validity
   and issuer against the controller's CSR (a blocker or an issuer warning: stop, don't install); on approval
   it installs the certificate and sends the controller list to the validators, both followed to the end.
7. Verify before the next controller: `catsdwan_certificates` with kind="controller": this
   controller's serial is NOT the one from step 1, its expiry moved out and its state is installed. Then
   `catsdwan_control_connections` with device=<this controller> (and no device for the fabric):
   every connection it had in step 2 is up again (allow a few minutes; failed attempts give the reason, e.g.
   certificate or serial not in the list). Not back: stop here, report, and renew no other controller;
   roll back by installing a certificate signed from a fresh CSR, or restore trust with
   catsdwan_sync_root_cert.
   If the root changed after step 3 for any reason, `catsdwan_sync_root_cert` again (preview,
   approval) before the next controller.

8. After the last controller: `catsdwan_compare_snapshot` with before=<the step 2 blob> (what got
   unhealthy: control connections, BFD, alarms), and `catsdwan_certificates` once more with
   kind="controller" and expiring_days=60: the renewed controllers are no longer due.

End with a table: controller, role, old serial and expiry, new serial and expiry, control connections
before and after, and anything left for the user (a root update, a controller not renewed).
