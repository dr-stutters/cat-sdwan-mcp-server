# Site twin spec (`catsdwan_export_site`)

`catsdwan_export_site(site)` describes one SD-WAN site as JSON that the cml recipe `cat-sdwan-twin` (cml-mcp-server
L64) builds an isolated twin from: the digital-twin scenario C59 is export -> build the twin -> apply the change on
the twin -> compare -> only then production. The tool is read tier and changes nothing on the Manager.

## Versioning

`kind` is always `cat-sdwan-twin-site`. `spec_version` is an integer, now `1`. A consumer refuses a `kind` it does
not know and a `spec_version` higher than it supports. Within one version, fields are only ever added; a field
removed or changing meaning bumps the version.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `cat-sdwan-twin-site` |
| `spec_version` | int | `1` |
| `exported_at` | string | UTC ISO 8601 time of the export |
| `source` | object | `manager_release` (the source Manager's release), `tool` |
| `site` | object | `id` (string, the SD-WAN site id), `name` when the Manager has one |
| `mode` | string | `configuration group`, `template`, `cli`, or `mixed: a, b` when the edges differ |
| `devices` | list | One entry per WAN edge at the site (below) |
| `config_groups` | list | The configuration groups the edges are in (below) |
| `device_templates` | list | The device templates the edges are attached to: `name`, `id`, `kind` (`feature` or `CLI`), `device_type`, `description` |
| `policy_groups` | list | Policy groups with an edge of the site associated: `name`, `id`, `solution`, `deploy_state`, `profiles` [`{name, type, id}`], `devices` (host names at the site) |
| `centralised_policy` | object or null | The activated centralised policy, cut to the parts that touch the site (below); null when none is activated |
| `colours` | list of strings | Every transport colour at the site (intended configuration and TLOCs) |
| `service_vpns` | list | `[{vpn: int, devices: [host]}]` across the site |
| `secrets` | list | Every secret the twin must supply: `{ref, name, where}` (below) |
| `twin_notes` | list of strings | What the twin keeps, rewrites and never gets |
| `warnings` | list of strings | Reads that failed; the rest of the spec is still valid. Absent when none |

## `devices[]`

| Field | Meaning |
|---|---|
| `host`, `system_ip`, `chassis`, `model`, `version`, `reachability` | From the Manager's inventory |
| `config_mode` | `configuration group`, `template` or `cli` |
| `config_group` / `device_template` | The group or template name, by mode |
| `variables` | `{name: value}`: configuration-group variables in their native types (`site_id` an integer), or the template's input keyed as the Manager keys it (`//system/host-name`, `{{name}}`). A secret is `{"secret_ref": "<host>/<name>"}`; a variable with no value is null |
| `transports` | `[{interface, colour, restrict?, encap, address?}]`: each `sdwan / interface` with a tunnel interface in the intended configuration; `encap` is `ipsec`, `gre` or `gre, ipsec`; `address` is the interface's first `ip address` as a prefix |
| `service_vpns` | `[{vpn: int, interfaces: [{interface, address?, description?}]}]`: each numbered `vrf definition` (Mgmt-intf and the platform's 65528-65530 left out) and the interfaces forwarding in it |
| `cli_addon_not_in_intended` | How many lines of the group's CLI add-on (rendered with the device's variables) the Manager's intended configuration lacks; absent when none. `transports` and `service_vpns` are parsed from the intended configuration **plus** the rendered add-on, which the device applies last (its primary `ip address`, `vrf forwarding` and `description` win) |
| `tlocs` | With `live_tlocs` (default): the TLOCs a controller holds for the edge, one per TLOC: `colour`, `encap`, `public`, `private` (`address:port`), `preference`, `weight`, `encryption`, `bfd_status` |
| `intended_config` | With `include_config`: the intended configuration text, secrets masked as `********` |

## `config_groups[]`

`name`, `id`, `solution`, `description`, `version`, `deploy_state`, and `feature_profiles`: each profile as
`catsdwan_get_config_group` gives it (`name`, `type`, `id`, `parcels` with `values` flattened to dotted keys,
variables shown as `{{name}}`, defaults left out, `subparcels`), except that a secret value is a ref
(`config-group/<group>/<profile>/<path>`, list indexes as path segments: `user/0/password`). On 20.18 the profile
read can leave out a parcel's data; the parcel is still listed by type and name.

A CLI add-on profile (`type` `cli`) has each parcel read on its own (`GET /v1/feature-profile/sdwan/cli/{profile}/
config/{parcel}`) and its text under `parcels[].cli`: secrets masked as `********`, `{{variables}}` kept as they
are (a `{{variable}}` after `secret` or `community` is a name, not a value, and stays). The Manager's intended
configuration can leave the add-on's lines out (seen on 20.18.3.1); the export then warns, names a few of the
missing lines, and adds a twin note: the twin applies the add-on after the rest, its variables filled from the
device's `variables`.

## `centralised_policy`

`name`, `id`, `type` (`policy builder` or `CLI`), `parts` (each part's `definition`, `type` in words, `sites`,
`vpns`, `direction`, `regions`: only the entries whose site list names the site, or that name no site list) and
`parts_not_touching_site` (how many parts were left out).

## Secrets

No secret value is ever in the spec. A value is a secret when its name is one by the suite's rules (password,
secret, psk, pre-shared, community, private key, token, ...) or ends in `key` (`ipsec_key`, `ike-key`). Its place
holds `{"secret_ref": "<ref>"}` and `secrets` lists each ref once:

```json
{"ref": "br1/ipsec_pre_shared_key", "name": "ipsec_pre_shared_key", "where": "variables of br1"}
```

The twin resolves a ref from its own secret store (the recipe's `${LAB_*}` templates); an unresolved ref is a build
error, never an empty value. Certificates, the serial file, one-time tokens and the controllers' own configuration
are not exported: the twin has its own controllers, CA and serial file.

## What the twin keeps and rewrites

Kept as exported: site id, system IPs, host names, colours, VPN numbers, configuration group / template names and
the policy that touches the site. Rewritten by the recipe: transport and service-VPN interface addresses and the
Validator address (the twin runs on a lab-internal network with a distinct Manager address). A diff between the
twin's and the source's configurations is therefore expected to show only addresses and certificates.

## Example (shortened)

```json
{
  "kind": "cat-sdwan-twin-site",
  "spec_version": 1,
  "exported_at": "2026-10-28T09:00:00Z",
  "source": {"manager_release": "20.18.3.1", "tool": "catsdwan_export_site"},
  "site": {"id": "200", "name": "SITE_200"},
  "mode": "configuration group",
  "devices": [
    {
      "host": "br1", "system_ip": "192.0.2.2", "chassis": "C8K-...", "config_mode": "configuration group",
      "config_group": "branch",
      "variables": {"host_name": "br1", "site_id": 200, "ipsec_pre_shared_key": {"secret_ref": "br1/ipsec_pre_shared_key"}},
      "transports": [{"interface": "GigabitEthernet1", "colour": "mpls", "restrict": true, "encap": "ipsec", "address": "198.51.100.14/24"}],
      "service_vpns": [{"vpn": 10, "interfaces": [{"interface": "GigabitEthernet3", "address": "203.0.113.1/24"}]}],
      "tlocs": [{"colour": "mpls", "encap": "ipsec", "public": "198.51.100.14:12426", "private": "198.51.100.14:12426"}]
    }
  ],
  "config_groups": [{"name": "branch", "id": "...", "feature_profiles": ["..."]}],
  "device_templates": [],
  "policy_groups": [{"name": "branch-pg", "devices": ["br1"], "profiles": [{"name": "Default_Policy_Object_Profile", "type": "policy-object"}]}],
  "centralised_policy": {"name": "fabric-policy", "parts": [{"definition": "app-route", "type": "application-aware routing", "sites": ["branches: 200-210"]}]},
  "colours": ["biz-internet", "mpls"],
  "service_vpns": [{"vpn": 10, "devices": ["br1"]}],
  "secrets": [{"ref": "br1/ipsec_pre_shared_key", "name": "ipsec_pre_shared_key", "where": "variables of br1"}],
  "twin_notes": ["..."]
}
```
