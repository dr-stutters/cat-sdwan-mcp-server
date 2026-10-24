# catsdwan_admin_access_via_ise

title: SD-WAN Manager admin login through ISE
arguments: {"ad_group": "mcp-sdwan-admins", "ad_user": "mcp-sdwan-op1", "ise_ip": "192.0.2.20", "keep_enabled": "false", "manager_ip": "192.0.2.10", "sdwan_group": "operator", "vpn": "0"}

Move SD-WAN Manager administrator logins onto Active Directory through ISE over RADIUS: an AD
group and user, ISE's NAD for the Manager, an authorization profile returning
Viptela-Group-Name=<group>, a policy set for the Manager's logins, then RADIUS external
authentication with local first, local and AD test logins, a group change, and an undo list.
Every write is preview-first; uses the ise and Windows_Server (win_) servers; dangerous tier.

## user

Move SD-WAN Manager admin logins onto AD through ISE (RADIUS): members of AD group
"mcp-sdwan-admins" get the Manager user group operator; prove it with AD user mcp-sdwan-op1. The Manager sends RADIUS
(PAP) from 192.0.2.10 to ISE at 192.0.2.20 in VPN 0. Every write is preview-first: show the preview, wait for
the user's approval, then repeat the call with the confirm token. Stop and report on any failure.
Passwords and shared secrets: the user types them where a tool asks; never repeat one in the chat.
catsdwan_test_login takes no password argument: it uses the server's settings or prompts the user.

Lockout rules (read them to the user before step 8):
- authFallback only falls back when the RADIUS server is unreachable or times out. A RADIUS REJECT
  (ISE answering "no", e.g. for admin, who is not in AD) ends the login: it never falls back to local.
- So RADIUS first (order ['radius', 'local']) locks out every local account ISE doesn't know, admin
  and this server's own API user included. Use order ['local', 'radius']: local accounts are checked
  first, a name that isn't a local user goes on to ISE. Never remove 'local' from the order.
- Keep this server's session open until step 9 passes: it is the undo path.

1. Preconditions: `catsdwan_get_aaa`: note the order, fallback and any RADIUS server
   (local_fallback must stay true). `catsdwan_list_users`: the local accounts and the
   user groups; operator must be among `user_groups` (a custom group must exist on the Manager first,
   or the RADIUS user gets no rights). ISE: `ise_status`, then
   `ise_list_dictionary_attributes` with dictionary="Viptela" and scope="policyset":
   Viptela-Group-Name (STRING) must be listed (the default authorization scope leaves this OUT-only
   attribute out). If the Viptela dictionary is missing, stop: the user adds it in the ISE GUI
   (Policy > Policy Elements > Dictionaries > System > Radius > RADIUS Vendors: Viptela, vendor id
   41916, attribute Viptela-Group-Name, id 1, string).
2. Active Directory: `win_list_ad_groups` for "mcp-sdwan-admins"; create it with
   `win_create_ad_group` if missing. `win_get_ad_user` for mcp-sdwan-op1; create
   it with `win_create_ad_user` if missing (the user sets the password) and add it with
   `win_add_group_member`. On ISE: `ise_get_ad_join_point` (joined, its
   name and domain), `ise_list_ad_groups`; if "mcp-sdwan-admins" isn't selectable yet, add it with
   `ise_add_ad_groups`. `ise_test_ad_user` for mcp-sdwan-op1 must list the group.
3. ISE NAD for the Manager: `ise_get_nad` "192.0.2.10". If none, preview
   `ise_create_nad` name "sdwan-manager", ips ["192.0.2.10"], with a RADIUS shared secret the
   user chooses (the same secret goes on the Manager in step 8). If one exists without RADIUS
   settings (e.g. a TACACS+-only NAD), add the RADIUS secret with `ise_update_nad`; if it
   has one, the user must know it for step 8.
4. Authorization profiles: `ise_create_authz_profile` name "mcp-sdwan-operator", access accept,
   sdwan_group="operator" (the preview must show Viptela:Viptela-Group-Name=operator); and the same for
   "mcp-sdwan-netadmin" with sdwan_group="netadmin" (used by step 10).
5. Policy: create policy set "mcp-sdwan-admin-login" with `ise_create_policy_set`, condition
   "Network Access:Device IP Address equals 192.0.2.10", rank 0, allowed protocols that permit PAP
   (Default Network Access). Authentication: an identity source sequence mcp_sdwan_admins with the
   AD join point (`ise_set_identity_sequence`), used by an authentication rule in the set
   (`ise_create_authn_rule`, condition "Network Access:Device IP Address equals 192.0.2.10").
   Authorization (`ise_create_authz_rule`): rule mcp-sdwan-ad with condition
   "<join point>:ExternalGroups equals <domain>/<path>/mcp-sdwan-admins" (the exact value from step 2) ->
   mcp-sdwan-operator. The set's Default rule stays DenyAccess. Review it with `ise_get_policy_set`.
6. Baseline: `catsdwan_test_login` with the local admin the user names (blank username =
   this server's API user): it must pass with roles [netadmin] and auth_source "local account".
7. A second break-glass check: ask the user to keep a GUI session to the Manager open as a local
   admin until step 9 passes.
8. External authentication: `catsdwan_set_external_authentication` protocol='radius',
   order=['local', 'radius'], servers=[{address: "192.0.2.20", secret: <the step 3 secret, typed by the
   user>, vpn: 0}], fallback=true. Show the preview (before/after, local_fallback true, the
   warnings) and the lockout rules above; apply only after approval (it needs MCP_ENABLE_DANGEROUS).
   The confirm logs in afresh as the API user and puts the old order back if that fails.
9. Right after: `catsdwan_test_login` with the local admin again (must still pass, auth
   source local). If it fails, at once `catsdwan_set_external_authentication`
   protocol='radius', order=['local'] (preview, approval) from this server's session and stop.
10. The AD login: `catsdwan_test_login` with username="mcp-sdwan-op1" (the client prompts the user
    for the password, or it comes from the server's settings): it must pass with roles [operator],
    external_user true and local_account false. ISE: `ise_get_policy_set` "mcp-sdwan-admin-login": the
    set, the authentication rule and mcp-sdwan-ad must have counted the login (a hit on Default means
    the group or condition didn't match: `ise_test_ad_user`);
    `ise_get_auth_list` for the NAD or user when ISE logged a session. A failed login:
    `ise_recent_auth_failures` for the reason; passed but roles not [operator]: the profile
    didn't return Viptela-Group-Name, or the group doesn't exist on the Manager (step 1).
    Then the group change: point mcp-sdwan-ad at mcp-sdwan-netadmin with
    `ise_update_policy_rule` (preview, approval), test mcp-sdwan-op1 again: roles [netadmin].
    Point the rule back at mcp-sdwan-operator the same way.
11. Summary: what was created where (AD, ISE NAD, profiles, sequence, policy set, the Manager's
    RADIUS server and order), the login results with the groups granted, and the undo list.
12. Switch off (keep_enabled=false): `catsdwan_set_external_authentication`
    protocol='radius', order=['local'] (preview, approval), then `catsdwan_test_login`
    with the local admin once more and `catsdwan_get_aaa` (order ['local']). The RADIUS
    server entry may stay on the Manager (unused while the order is local); remove it only if the user
    asks (`catsdwan_api_call` DELETE /dataservice/admin/radius, preview-first). Then the
    ISE undo, each preview-first: policy set mcp-sdwan-admin-login (`ise_delete_object`), profiles
    mcp-sdwan-operator and mcp-sdwan-netadmin, the NAD's RADIUS secret or the NAD itself if step 3 created it
    (`ise_delete_nad`), and the AD user/group if step 2 created them for this proof (ask
    first).
