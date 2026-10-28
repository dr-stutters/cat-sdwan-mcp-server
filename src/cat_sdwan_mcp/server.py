"""cat-sdwan-mcp-server: server spec and factory."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from cat_sdwan_mcp._core import ServerSpec, ToolRegistrar, build_server, suite
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.config import Settings
from cat_sdwan_mcp.spec import spec_sources
from cat_sdwan_mcp.tools import (
    access,
    adminlogin,
    api,
    certificates,
    changes,
    confighistory,
    configuration,
    containment,
    control,
    dataplane,
    devicestate,
    devops,
    edgefirewall,
    events,
    features,
    findhost,
    health,
    history,
    inventory,
    iseintegration,
    licensing,
    manager,
    onboarding,
    pathinsight,
    policy,
    policygroups,
    prompts,
    security,
    securityprofiles,
    serviceinsertion,
    sgtpath,
    sitexport,
    snapshot,
    sslproxy,
    triage,
    troubleshooting,
    trustsec,
    upgrade,
    utd,
)

INSTRUCTIONS = """
Tools for Catalyst SD-WAN Manager (formerly vManage): fabric inventory and health, tunnels, BFD and
app-route state, configuration groups and policies. Personalities: vmanage = Manager, vsmart = Controller,
vbond = Validator, vedge = WAN edge. Devices are named by host name, system IP, chassis or serial.
Start with catsdwan_status (release, login, controllers, edge counts); call it if anything fails.
Inventory: catsdwan_list_devices (site, kind, reachability, model, version; certificate state and
configuration mode), catsdwan_get_device (one device plus live CPU, memory, interfaces, software, reboots),
catsdwan_list_controllers (control plane and certificate expiry). "What is unhealthy?":
catsdwan_device_health(health='poor'). Control plane: "why didn't this edge join?" ->
catsdwan_control_connections(device) (failed attempts with the reason in plain words; no device = the
fabric); "why can't branch A reach B?" -> catsdwan_omp_routes(A, vpn, prefix) then catsdwan_list_tlocs and
catsdwan_omp_peers. "Where is this host?" -> catsdwan_find_host(ip or mac) (edge, site, VPN, interface,
the OMP route advertising it). Data plane: "which tunnels are down?" -> catsdwan_bfd_sessions(state='not_up');
"which are lossy / is the voice SLA met?" -> catsdwan_app_route_stats(sla_class=...) (statistics every
10 minutes; source='realtime' for now), catsdwan_list_sla_classes, catsdwan_tunnel_stats. The Manager's own
health model: catsdwan_site_health(health='not_good'), catsdwan_tunnel_health(site, history=true: when was it
bad?), catsdwan_interface_stats(device) ("is a WAN link full?"), catsdwan_topology(site).
Logs: "what changed and who did it?" -> catsdwan_audit_log(changes_only=true); "what has been breaking at
this site?" -> catsdwan_recent_activity(site) (alarms, events and audit lines on one timeline);
catsdwan_list_alarms (active by default), catsdwan_list_events (busy: keep since_hours short).
Real-time reads go over the Manager's control connection, so an unreachable edge has none.
Configuration: "how is this edge configured, and did it drift?" -> catsdwan_get_device_config(device,
diff=true) (running vs intended, secrets masked; says configuration group, template or CLI mode);
catsdwan_list_config_groups -> catsdwan_get_config_group(group) (feature profiles, values, devices and their
variables); catsdwan_list_templates(type='device'|'feature'); catsdwan_list_policy_groups. A device is in a
configuration group or on a device template, never both. "What was it before last night's deploy?" ->
catsdwan_config_history(device, at=<time> | version='previous' | diff=true).
Changes (with MCP_ENABLE_WRITES; preview-first): catsdwan_set_device_variables (stores values only) ->
catsdwan_deploy_config_group(group, devices) (preview = CLI and diff per device; confirm follows the action to
success or failure per device) -> catsdwan_get_device_config(diff=true). Legacy templates:
catsdwan_attach_device_template(template, devices, variables). Change the group itself:
catsdwan_get_feature_parcel(profile or group, parcel, fields=true) -> catsdwan_set_feature_parcel(profile,
parcel, values | cli_replace) (schema-checked, stores only) -> deploy; catsdwan_associate_config_group(group,
add, remove);
catsdwan_deploy_policy_group(group, devices). One device is write tier; several devices, a
hub or a protected-site device need MCP_ENABLE_DANGEROUS. Name the preview's devices before confirming.
Onboarding: catsdwan_list_wan_edges(state='not_joined') -> catsdwan_onboard_edge(chassis, hostname, system_ip,
site_id, config_group or template) (validity, association, variables; stops at the failing step) -> boot the
edge with catsdwan_bootstrap_config(chassis) as its day-0, or the activate command it gives on a running
C8000V -> catsdwan_control_connections(device). catsdwan_set_edge_validity: invalid drops a joined edge
(dangerous). The one-time token is a secret: only catsdwan_bootstrap_config(reveal_otp=true) shows it.
Policy: catsdwan_list_policies (centralised, localised, policy groups; which is activated) ->
catsdwan_get_policy (sequences in plain words, lists resolved). "Why does voice take the internet link at this
branch?" -> catsdwan_explain_path(source_site, destination site or prefix, app or dscp) (offline walk of the
policy joined with each tunnel's SLA now). catsdwan_activate_policy(policy, action) is always dangerous
(fabric-wide).
Device operations (dangerous): catsdwan_list_software (repository, per edge installed and active, the release
ceiling) -> catsdwan_upgrade_software(devices, version, activate) / catsdwan_reboot_devices(devices); the
previews name each device's site and role and refuse both edges of one site in one run.
catsdwan_list_device_actions shows the Manager's running actions (upgrades started in the GUI too).
History: "is this site getting worse?" -> catsdwan_site_report(site, days) (availability and SLA misses per
transport, control drops, top alarms and applications) or catsdwan_sla_history(site or tunnel, sla_class or
app, days) (hourly/daily buckets, the periods each tunnel missed its SLA); "what is using the link?" ->
catsdwan_top_applications(site) (needs application visibility (DPI) on the edges; says so when it is off).
Change checks: catsdwan_snapshot(site) before a change (a blob to keep in the conversation), then
catsdwan_compare_snapshot(before) after it names what changed by severity (control, BFD, OMP, app-route SLA,
alarms, devices); the suite prompt suite_change_check runs the same on every connected server.
Digital twin: catsdwan_export_site(site) gives the site as a twin spec (configuration group or template,
variables with secrets as refs, policy, transports, service VPNs) for the cml recipe cat-sdwan-twin.
SGTs across the overlay: catsdwan_trustsec_path(source_edge, destination_edge, source_ip, destination_ip)
(inline tagging per tunnel, SXP, the destination edge's SGACL); the prompt catsdwan_sgt_path adds ISE.
Edge security (UTD: IPS, URL filtering, AMP): catsdwan_upload_utd_image(file in CATSDWAN_IMAGE_DIR) ->
catsdwan_set_ips_profile / catsdwan_set_url_filtering_profile / catsdwan_set_amp_profile ->
catsdwan_set_inspection_profile -> catsdwan_set_security_policy (stores only) -> the policy group
(catsdwan_create_policy_group / catsdwan_associate_policy_group -> catsdwan_deploy_policy_group installs UTD)
-> catsdwan_utd_status (UTD on a C8000V needs 8 GB RAM); undo: catsdwan_delete_security_profile.
TLS/SSL proxy: catsdwan_ssl_proxy_ca -> catsdwan_set_ssl_proxy_ca(root_certificate) (CSR generated on the
Manager, key never leaves it) -> win_sign_csr(template='SubCA') ->
catsdwan_set_ssl_proxy_ca(signed_certificate) -> catsdwan_set_ssl_decryption +
catsdwan_set_ssl_decryption_profile (decrypt / never-decrypt categories) ->
catsdwan_set_inspection_profile(tls_action='decrypt') -> catsdwan_set_security_policy(ssl_decryption).
Service insertion (FTD in a service chain): catsdwan_service_chains(vpn, device) (firewall services per VPN,
the steering rules, what an edge knows in OMP) -> catsdwan_set_service_chain(profile, vpn, addresses) (the LAN
VPN's FW service, tracking) -> catsdwan_set_service_steering(group, name, vpns, rules) (traffic policy setting
service FW; dangerous) -> deploy; the prompt catsdwan_trace_through_firewall(source, destination, app) adds
fmc_packet_tracer on the hub or branch FTD.
Contain a host (prompt catsdwan_contain_host; dangerous): once per policy group, the standing baseline
catsdwan_set_containment_baseline(group, quarantine_sgt, remediation) (mcp-quarantine-* rules on the
Quarantine SGT; deploy it in a change window). Main path: ISE ise_apply_anc assigns the Quarantine SGT, no
Manager change per incident (needs TrustSec on the edges: catsdwan_containment_status(trustsec=true)). No ISE
session: once per configuration group catsdwan_set_containment_acl(group, interfaces) (CLI add-on ACL
mcp-contain with per-device slots, neutral everywhere; deploy in a change window), then per incident
catsdwan_contain_at_edge(ip, reason, hours) writes one slot of the host's edge (deny + a note with the expiry)
and deploys that edge only -> catsdwan_release_at_edge(ip).
Identity: catsdwan_integrations (ISE, pxGrid, partners) and catsdwan_trustsec(device) read it;
catsdwan_set_ise_integration(ise_host) connects ISE and pxGrid (dangerous) -> ise_approve_pxgrid_client on
ISE -> run it again to sync the controllers; action='disconnect' undoes it.
Admin login through ISE: catsdwan_get_aaa -> ISE NAD + authorization profile returning Viptela-Group-Name ->
catsdwan_set_external_authentication(radius, order ['local', 'radius']) -> catsdwan_test_login (local admin
first: a RADIUS reject never falls back to local). Prompt catsdwan_admin_access_via_ise.
Prompts: catsdwan_branch_health(site) (a verdict per transport), catsdwan_onboard_branch(site) (NetBox ->
onboard -> boot -> deploy -> prove), catsdwan_why_is_app_slow(host, app) (ISE, app-route SLA, FMC, CML).
Branch triage: catsdwan_wifi_lan_or_wan(host), catsdwan_network_or_ise(site), catsdwan_site_down(site),
catsdwan_brownout_drill(site) (CML scenarios per transport, preview-first).
Anything without a tool: catsdwan_search_spec('bfd') -> catsdwan_get_definition(path) -> catsdwan_api_call
(paths as /dataservice/..., checked against the Manager's own OpenAPI document; GET and the statistics, alarm,
event and audit query POSTs are reads, other writes are preview-first, /device/action/* is dangerous).
Other planned tools are in the server's ROADMAP.md; until they exist, say so instead of guessing.
"""

SPEC = ServerSpec(
    name="cat-sdwan-mcp-server",
    prefix="catsdwan",
    product="Cisco Catalyst SD-WAN Manager",
    env_prefix="CATSDWAN_",
    instructions=INSTRUCTIONS,
    spec_search_example="bfd sessions",
    spec_path_example="/dataservice/device/bfd/sessions",
)


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    mcp = build_server(
        SPEC,
        settings,
        client_factory=lambda s: SdwanApp(s, transport=transport),
        register=[
            inventory.register,
            control.register,
            dataplane.register,
            events.register,
            configuration.register,
            changes.register,
            onboarding.register,
            policy.register,
            devops.register,
            history.register,
            confighistory.register,
            features.register,
            policygroups.register,
            edgefirewall.register,
            containment.register,
            health.register,
            prompts.register,
            triage.register,
            certificates.register,
            troubleshooting.register,
            devicestate.register,
            findhost.register,
            pathinsight.register,
            security.register,
            utd.register,
            securityprofiles.register,
            sslproxy.register,
            serviceinsertion.register,
            trustsec.register,
            sgtpath.register,
            iseintegration.register,
            manager.register,
            access.register,
            adminlogin.register,
            upgrade.register,
            licensing.register,
            snapshot.register,
            sitexport.register,
            suite.register,
        ],
        status=SdwanApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )
    # Core's generic api_call is GET-only or dangerous for every write; the Manager's is tiered per path.
    api.register_api_call(mcp, ToolRegistrar(mcp, settings, SPEC.prefix))
    return mcp
