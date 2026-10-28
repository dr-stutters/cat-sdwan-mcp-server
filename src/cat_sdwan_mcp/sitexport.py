"""Site export (W55, #77): one site as a versioned twin spec that the cml recipe `cat-sdwan-twin` (L64)
consumes. Pure helpers; the tool is tools/sitexport.py and the schema is docs/twin-spec.md.

What goes in (every read is one the other tools already make; 20.18.3.1 shapes):
- the site's edges from the inventory (GET /dataservice/device + /system/device/vedges): host, system IP,
  chassis, model, version and configuration mode. `managed-by` reads "Config-Group <name>, Policy-Group
  <name>" once a policy group is associated (recorded 2026-10-28, br1).
- configuration-group mode: the group (GET /v1/config-group/{id}), its feature profiles with parcels
  (GET /v1/feature-profile/sdwan/<type>/{id}) and the devices' variables (GET /v1/config-group/{id}/device/
  variables?device-id=...: native types, unmasked, so secrets become refs here).
- template mode: the device template (GET /template/device?feature=all) and the devices' variables (POST
  /template/device/config/input {templateId, deviceIds, isEdited: false, isMasterEdited: false}: a read
  that changes nothing; rows keyed by csv-deviceId, variables keyed by their template path or {{name}}).
- policy groups whose associated devices (GET /v1/policy-group/{id}/device/associate) are at the site.
- the activated centralised policy (GET /template/policy/vsmart, .../vsmart/definition/{id}) with only the
  parts whose site lists include the site, or that name no site list (every site).
- transports and service VPNs from each edge's intended configuration (GET /template/config/attached/
  {chassis}: the Manager's rendering in every mode): `sdwan / interface X / tunnel-interface / encapsulation
  / color` per transport, the interface's `ip address`, `vrf definition <n>` and `vrf forwarding <n>` per
  service VPN; plus the TLOCs the controllers hold for the site's edges (GET /device/omp/tlocs/received,
  live; public and private address, preference, weight).

Secrets never leave as values: a variable or parcel value whose name is a secret becomes
{"secret_ref": "<scope>/<name>"} and is listed once under `secrets`; the twin supplies its own values.
Certificates, the serial file and one-time tokens are not exported (the twin has its own).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cat_sdwan_mcp._core.formatting import MASK, is_secret_key
from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.configuration import _normalise, blocks
from cat_sdwan_mcp.policy import _refs, assembly_view, in_site_list

KIND = "cat-sdwan-twin-site"
SPEC_VERSION = 1
# VRFs the platform owns, not service VPNs.
_PLATFORM_VRFS = frozenset({"Mgmt-intf", "65528", "65529", "65530"})
_KEY_SUFFIX = re.compile(r"(?:^|[_\-./])(?:key|secret|pass)$", re.IGNORECASE)


# --- secrets as refs ---------------------------------------------------------------------------------


def secret_name(name: str) -> bool:
    """Whether a variable or field name holds a secret: the core secret names (password, psk, community,
    ...) plus SD-WAN's '*_key' / '*-key' variables (IPsec and IKE keys)."""
    short = short_name(name)
    return is_secret_key(short) or bool(_KEY_SUFFIX.search(short))


def short_name(key: str) -> str:
    """'//system/host-name' -> 'host-name'; '{{banner_motd}}' -> 'banner_motd'; 'site_id' as it is."""
    k = key.strip()
    if k.startswith("{{") and k.endswith("}}"):
        k = k[2:-2].strip()
    return k.rstrip("/").rsplit("/", 1)[-1]


class Secrets:
    """The refs handed out while building one spec, so `secrets` lists each once."""

    def __init__(self) -> None:
        self.refs: dict[str, dict[str, str]] = {}

    def ref(self, scope: str, name: str, where: str) -> dict[str, str]:
        ref = f"{scope}/{name}"
        self.refs.setdefault(ref, {"ref": ref, "name": name, "where": where})
        return {"secret_ref": ref}

    def listed(self) -> list[dict[str, str]]:
        return [self.refs[k] for k in sorted(self.refs)]


def variables_with_refs(pairs: dict[str, Any], scope: str, where: str, secrets: Secrets) -> dict[str, Any]:
    """{variable: value} with every secret value replaced by a ref (an empty secret stays empty)."""
    out: dict[str, Any] = {}
    for name in sorted(pairs):
        value = pairs[name]
        if secret_name(name) and value not in (None, ""):
            out[name] = secrets.ref(scope, short_name(name), where)
        else:
            out[name] = value
    return out


def refs_for_masked(v: Any, scope: str, where: str, secrets: Secrets, key: str = "") -> Any:
    """`v` (a parcel's flattened values, already masked) with each masked value replaced by a ref."""
    if isinstance(v, dict):
        return {k: refs_for_masked(x, scope, where, secrets, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [refs_for_masked(x, scope, where, secrets, key) for x in v]
    if v == MASK:
        name = re.sub(r"\[(\d+)\]", r"/\1", key).replace(".", "/") or "value"
        return secrets.ref(scope, name, where)
    return v


def scrub(v: Any, key: str = "") -> Any:
    """A last pass over the finished spec: any scalar still sitting under a secret name is masked (refs are
    dicts and stay). The spec is returned unshaped, so this replaces the core's mask-by-key pass, which
    would also mask the refs."""
    if isinstance(v, dict):
        if set(v) == {"secret_ref"}:
            return v
        return {k: scrub(x, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x, key) for x in v]
    if key and secret_name(key) and isinstance(v, str | int | float) and not isinstance(v, bool):
        return v if v in ("", MASK) else MASK
    return v


# --- variables -----------------------------------------------------------------------------------


def group_variables(body: Any) -> dict[str, dict[str, Any]]:
    """{chassis: {variable: value}} from GET /v1/config-group/{id}/device/variables (native types,
    unmasked; a variable with no value is None)."""
    rows = body.get("devices") if isinstance(body, dict) else body
    out: dict[str, dict[str, Any]] = {}
    for d in _as_list(rows):
        if not isinstance(d, dict):
            continue
        dev = str(d.get("device-id") or d.get("deviceId") or d.get("id") or "")
        out[dev] = {
            str(v["name"]): v.get("value")
            for v in _as_list(d.get("variables"))
            if isinstance(v, dict) and v.get("name")
        }
    return out


def template_variables(body: Any) -> dict[str, dict[str, Any]]:
    """{chassis: {variable key: value}} from POST /template/device/config/input (csv-* columns are the
    Manager's own bookkeeping and stay out)."""
    rows = body.get("data") if isinstance(body, dict) else body
    out: dict[str, dict[str, Any]] = {}
    for r in _as_list(rows):
        if isinstance(r, dict) and r.get("csv-deviceId"):
            out[str(r["csv-deviceId"])] = {str(k): v for k, v in r.items() if not str(k).startswith("csv-")}
    return out


# --- intended configuration: transports and service VPNs -----------------------------------------


def _address(line: str) -> str | None:
    """'ip address 192.0.2.1 255.255.255.0' -> '192.0.2.1/24'; 'ipv6 address 2001:db8::1/64' as it is."""
    parts = line.split()
    if parts[:2] == ["ip", "address"] and len(parts) >= 4:
        try:
            return str(ipaddress.ip_interface(f"{parts[2]}/{parts[3]}"))
        except ValueError:
            return f"{parts[2]} {parts[3]}"
    if parts[:2] == ["ipv6", "address"] and len(parts) >= 3:
        return parts[2]
    return None


def _parse_part(
    lines: list[str],
    tunnels: dict[str, dict[str, Any]],
    interfaces: dict[str, dict[str, Any]],
    vrfs: list[str],
    *,
    addon: bool,
) -> None:
    in_sdwan = False
    sdwan_if: str | None = None
    current_if: str | None = None
    for ln in lines:
        indent = len(ln) - len(ln.lstrip())
        s = ln.strip()
        if indent == 0:
            in_sdwan, sdwan_if, current_if = s == "sdwan", None, None
            if s.startswith("interface "):
                current_if = s.split(None, 1)[1]
                interfaces.setdefault(current_if, {})
            elif s.startswith("vrf definition ") and (vrf := s.split(None, 2)[2]) not in vrfs:
                vrfs.append(vrf)
            continue
        if in_sdwan:
            if indent == 1:
                sdwan_if = s.split(None, 1)[1] if s.startswith("interface ") else None
            elif sdwan_if:
                t = tunnels.setdefault(sdwan_if, {"interface": sdwan_if})
                words = s.split()
                if words[0] == "tunnel-interface":
                    t["tunnel"] = True
                elif words[0] == "color" and len(words) > 1:
                    t["colour"] = words[1]
                    if "restrict" in words[2:]:
                        t["restrict"] = True
                elif words[0] == "encapsulation" and len(words) > 1 and words[1] not in t.get("encap", []):
                    t.setdefault("encap", []).append(words[1])
            continue
        if current_if is not None:
            if addr := _address(s):
                have = interfaces[current_if].setdefault("addresses", [])
                if addr in have:
                    continue
                if addon and "secondary" not in s.split():
                    have.insert(0, addr)
                else:
                    have.append(addr)
            elif s.startswith("vrf forwarding "):
                interfaces[current_if]["vrf"] = s.split(None, 2)[2]
            elif s.startswith("description "):
                interfaces[current_if]["description"] = s.split(None, 1)[1]


def parse_intended(text: str, *addons: str) -> dict[str, Any]:
    """{transports: [{interface, colour, restrict, encap, address}], service_vpns: [{vpn, interfaces:
    [{interface, address}]}]} from a device's intended configuration (the Manager's rendering, any mode)
    plus any rendered CLI add-on texts (#166). An add-on is applied after the rest on the device, so its
    primary `ip address`, `vrf forwarding` and `description` win over the intended text's."""
    tunnels: dict[str, dict[str, Any]] = {}
    interfaces: dict[str, dict[str, Any]] = {}
    vrfs: list[str] = []
    for n, part in enumerate((text, *addons)):
        _parse_part(_normalise(part), tunnels, interfaces, vrfs, addon=n > 0)
    transports = []
    for name, t in tunnels.items():
        if not t.get("tunnel") and "colour" not in t:
            continue
        row: dict[str, Any] = {"interface": name, "colour": t.get("colour", "default")}
        if t.get("restrict"):
            row["restrict"] = True
        row["encap"] = ", ".join(t.get("encap", [])) or None
        addrs = interfaces.get(name, {}).get("addresses")
        if addrs:
            row["address"] = addrs[0]
        transports.append({k: v for k, v in row.items() if v is not None})
    vpns = []
    for vrf in vrfs:
        if vrf in _PLATFORM_VRFS or not vrf.isdigit():
            continue
        members = [
            {
                k: v
                for k, v in {
                    "interface": n,
                    "address": (i.get("addresses") or [None])[0],
                    "description": i.get("description"),
                }.items()
                if v is not None
            }
            for n, i in interfaces.items()
            if i.get("vrf") == vrf
        ]
        vpns.append({"vpn": int(vrf), "interfaces": members})
    return {"transports": transports, "service_vpns": sorted(vpns, key=lambda v: v["vpn"])}


# --- CLI add-on profile (#166) -------------------------------------------------------------------

_VARIABLE = re.compile(r"\{\{\s*([\w.-]+)\s*\}\}")


def render_cli(text: str, variables: dict[str, Any]) -> str:
    """The add-on CLI with each {{variable}} that has a plain value in `variables` filled in; a secret
    (a ref) or a variable with no value stays as {{name}}."""

    def one(m: re.Match[str]) -> str:
        v = variables.get(m.group(1))
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str | int | float) and v != "":
            return str(v)
        return m.group(0)

    return _VARIABLE.sub(one, text)


def _pairs(text: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for key, children in blocks(text).items():
        out.append((key, None))
        out += [(key, c.strip()) for c in children]
    return out


def missing_from(addon: str, intended: str) -> list[str]:
    """The rendered add-on's lines ('block' or 'block / line') that are not in the intended configuration;
    lines still holding a {{variable}} are left out (their value is unknown here)."""
    have = set(_pairs(intended))
    return [
        key if line is None else f"{key} / {line}"
        for key, line in _pairs(addon)
        if "{{" not in key and "{{" not in (line or "") and (key, line) not in have
    ]


def tloc_view(t: dict[str, Any]) -> dict[str, Any]:
    """A received TLOC (control.tloc_row) as the spec carries it."""
    keep = ("colour", "encap", "public", "private", "preference", "weight", "encryption", "bfd_status")
    return {k: t[k] for k in keep if t.get(k) not in (None, "")}


# --- centralised policy --------------------------------------------------------------------------


def parts_for_site(parts: list[dict[str, Any]], site: str, lists: dict[str, Any]) -> list[dict[str, Any]]:
    """The assembly parts with only the entries that touch `site` (its site list names it, or the entry
    names no site list); parts with no such entry are dropped."""
    out = []
    for a in parts:
        entries = [e for e in _as_list(a.get("entries")) if isinstance(e, dict)]
        if not entries:
            out.append(a)
            continue
        keep = [
            e
            for e in entries
            if not _refs(e.get("siteLists"))
            or any(in_site_list(site, lists.get(r)) for r in _refs(e.get("siteLists")))
        ]
        if keep:
            out.append({**a, "entries": keep})
    return out


def policy_view(
    policy: dict[str, Any],
    parts: list[dict[str, Any]],
    site: str,
    defs: dict[str, dict[str, Any]],
    lists: dict[str, Any],
) -> dict[str, Any]:
    mine = parts_for_site(parts, site, lists)
    return {
        "name": policy.get("policyName"),
        "id": policy.get("policyId"),
        "type": {"feature": "policy builder", "cli": "CLI"}.get(
            str(policy.get("policyType")), policy.get("policyType")
        ),
        "parts": assembly_view(mine, defs, lists),
        "parts_not_touching_site": len(parts) - len(mine),
    }


# --- the spec ------------------------------------------------------------------------------------


def spec_mode(devices: list[dict[str, Any]]) -> str:
    modes = sorted({str(d.get("config_mode") or "unknown") for d in devices})
    return modes[0] if len(modes) == 1 else "mixed: " + ", ".join(modes)


def colours(devices: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(t["colour"])
            for d in devices
            for t in [*d.get("transports", []), *d.get("tlocs", [])]
            if t.get("colour")
        }
    )


def service_vpns(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """[{vpn, devices}] across the site's edges."""
    by: dict[int, list[str]] = {}
    for d in devices:
        for v in d.get("service_vpns", []):
            by.setdefault(int(v["vpn"]), []).append(str(d.get("host") or d.get("chassis")))
    return [{"vpn": k, "devices": sorted(v)} for k, v in sorted(by.items())]


TWIN_NOTES = [
    "Keep: site id, system IPs, host names, colours, VPN numbers, configuration group / template names and "
    "the policy that touches the site; the twin rebuilds these as they are.",
    "Rewrite: transport and service-VPN interface addresses and the Validator address (the twin has its own "
    "lab-internal network); the diff between twin and source configurations should be only these.",
    "Not exported: certificates, the serial file, one-time tokens and secret values (each secret is a "
    "secret_ref under `secrets`: the twin supplies its own).",
]

CLI_ADDON_NOTE = (
    "CLI add-on: the group's CLI profile is under config_groups[].feature_profiles[].parcels[].cli "
    "({{variables}} as they are, filled from each device's variables). The Manager's intended configuration "
    "can leave its lines out (devices[].cli_addon_not_in_intended counts them); the twin applies the add-on "
    "after the rest."
)
