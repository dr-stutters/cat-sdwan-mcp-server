"""Configuration reads (W7): configuration groups and their feature profiles, policy groups, device and
feature templates, and a device's running and intended configuration.

Sources (recorded on 20.18.3.1 unless marked; paths checked against the Manager's OpenAPI document):
- GET /dataservice/v1/config-group: [{id, name, description, solution, profiles: [{id, name, type, ...}],
  numberOfDevices, numberOfDevicesUpToDate, state (null until deployed), lastUpdatedBy/On, origin, ...}]
  (`devices` comes back empty: the associated devices are a separate read).
- GET /dataservice/v1/config-group/{id}: the same record for one group.
- GET /dataservice/v1/config-group/{id}/device/associate: {devices: [{id (chassis), host-name, site-id,
  deviceIP, configStatusMessage, configGroupUpToDate "True"|"False", isDeployable, ...}]}.
- GET /dataservice/v1/config-group/{id}/device/variables?device-id=<chassis,...>: answers 400 without
  `device-id` (the spec lists it as optional), and 400 CFGRP0012 while the group has no system profile.
  {family: "sdwan", groups: [{name, group-variables}], devices: [{device-id, variables: [{name, value}]}]}:
  native value types (site_id an integer, booleans); a variable with no value has no "value" key.
- GET /dataservice/v1/feature-profile/sdwan/<type>/{id} (type system, transport, service, cli, other, ...):
  {profileName, profileType, associatedProfileParcels: [{parcelId, parcelType, payload: {name, description,
  data}, subparcels}]}, each value {optionType: global|variable|default, value} (spec; not recorded yet).
- GET /dataservice/v1/policy-group: the same shape as configuration groups ([] on the lab).
- GET /dataservice/template/device?feature=all: {data: [{templateId, templateName, templateDescription,
  deviceType, configType file (CLI) | template (feature-based), factoryDefault, devicesAttached, draftMode,
  lastUpdatedBy, lastUpdatedOn}]}; GET /dataservice/template/device/config/attached/{templateId} names the
  attached devices (spec; not recorded yet).
- GET /dataservice/template/feature: {data: [{templateId, templateName, templateType, deviceType: [...],
  factoryDefault, devicesAttached, attachedMastersCount, lastUpdatedBy, lastUpdatedOn, templateDefinition}]}.
- GET /dataservice/template/config/running/{chassis} and /template/config/attached/{chassis}: {config: text},
  the device's running configuration (IOS XE CLI) and what the Manager intends for it (its own rendering:
  "no config / config" header, everything indented two spaces, blocks in another order).
"""

from __future__ import annotations

import difflib
import re
from typing import Any
from urllib.parse import quote

from cat_sdwan_mcp._core import InvalidRequest, NotFound
from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.inventory import iso

CONFIG_GROUPS_PATH = "/dataservice/v1/config-group"
CONFIG_GROUP_PATH = CONFIG_GROUPS_PATH + "/{id}"
ASSOCIATE_PATH = CONFIG_GROUP_PATH + "/device/associate"
VARIABLES_PATH = CONFIG_GROUP_PATH + "/device/variables"
POLICY_GROUPS_PATH = "/dataservice/v1/policy-group"
PROFILE_PATH = "/dataservice/v1/feature-profile/sdwan/{type}/{id}"
DEVICE_TEMPLATES_PATH = "/dataservice/template/device"
FEATURE_TEMPLATES_PATH = "/dataservice/template/feature"
TEMPLATE_DEVICES_PATH = "/dataservice/template/device/config/attached/{id}"
RUNNING_PATH = "/dataservice/template/config/running/{id}"
INTENDED_PATH = "/dataservice/template/config/attached/{id}"

# Feature profile types with a GET /v1/feature-profile/sdwan/<type>/{id} in the 20.18 spec.
PROFILE_TYPES = frozenset(
    {"system", "transport", "service", "cli", "other", "dns-security", "sig-security", "sse-spa"}
)
CONFIG_TYPE = {"file": "CLI", "template": "feature"}


def path(template: str, **ids: str) -> str:
    return template.format(**{k: quote(str(v), safe="") for k, v in ids.items()})


def _clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v not in (None, "", [], {})}


# --- configuration and policy groups ---------------------------------------------------------------


def _profiles(g: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in _as_list(g.get("profiles")) if isinstance(p, dict)]


def deploy_state(g: dict[str, Any]) -> str:
    """The group's deploy state in words: the Manager's `state` when it has one, else from the counts."""
    if isinstance(g.get("state"), str) and g["state"].strip():
        return " ".join(g["state"].split())
    total, current = g.get("numberOfDevices"), g.get("numberOfDevicesUpToDate")
    if not total:
        return "no devices associated"
    if isinstance(current, int) and current >= total:
        return "deployed, every device up to date"
    if not current:
        return "not deployed (no device has the group's current version)"
    return f"partly deployed ({current} of {total} devices up to date)"


def group_row(g: dict[str, Any]) -> dict[str, Any]:
    profiles = _profiles(g)
    total, current = g.get("numberOfDevices"), g.get("numberOfDevicesUpToDate")
    return _clean(
        {
            "name": g.get("name"),
            "id": g.get("id"),
            "solution": g.get("solution"),
            "description": g.get("description"),
            "profiles": ", ".join(f"{p.get('name')} ({p.get('type')})" for p in profiles) or "none",
            "devices": total,
            "up_to_date": f"{current}/{total}"
            if isinstance(total, int) and isinstance(current, int)
            else None,
            "deploy_state": deploy_state(g),
            "version": g.get("version"),
            "origin": g.get("origin"),
            "last_updated": iso(g.get("lastUpdatedOn")),
            "last_updated_by": g.get("lastUpdatedBy"),
        }
    )


def resolve_group(
    groups: list[dict[str, Any]], ref: str, kind: str = "configuration group"
) -> dict[str, Any]:
    """A group by id or name (exact, case-insensitive), then a unique name prefix; NotFound with the closest
    names otherwise."""
    want = ref.strip().lower()
    if not want:
        raise InvalidRequest(f"Give a {kind} name or id.")
    found = [g for g in groups if want in (str(g.get("id", "")).lower(), str(g.get("name", "")).lower())]
    if not found:
        found = [g for g in groups if str(g.get("name", "")).lower().startswith(want)]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        listed = ", ".join(str(g.get("name")) for g in found[:10])
        raise InvalidRequest(f"{ref!r} matches {len(found)} {kind}s: {listed}. Give the full name or the id.")
    names = [str(g["name"]) for g in groups if g.get("name")]
    close = difflib.get_close_matches(ref.strip(), names, n=5, cutoff=0.5)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    known = f" Known: {', '.join(names[:20])}." if names and not close else ""
    raise NotFound(f"No {kind} matches {ref!r}.{hint}{known}")


def associated_row(d: dict[str, Any]) -> dict[str, Any]:
    up = str(d.get("configGroupUpToDate", "")).lower()
    return _clean(
        {
            "host": d.get("host-name"),
            "chassis": d.get("id"),
            "system_ip": d.get("deviceIP"),
            "site_id": d.get("site-id"),
            "site_name": d.get("site-name"),
            "model": d.get("deviceModel"),
            "config_status": d.get("configStatusMessage"),
            "group_up_to_date": {"true": True, "false": False}.get(up),
            "deployable": d.get("isDeployable"),
            "tags": d.get("tags"),
            "unsupported_features": d.get("unsupportedFeatures"),
        }
    )


def associated(body: Any) -> list[dict[str, Any]]:
    rows = body.get("devices") if isinstance(body, dict) else body
    return [associated_row(d) for d in _as_list(rows) if isinstance(d, dict)]


def device_variable_lists(body: Any) -> dict[str, list[dict[str, Any]]]:
    """{device id: [{name, value?}, ...]} as the Manager returned them (unmasked, native types; a variable
    with no value has no "value" key). Accepts {devices: [{device-id, variables: [...]}]} and a bare list."""
    rows = body.get("devices") if isinstance(body, dict) else body
    out: dict[str, list[dict[str, Any]]] = {}
    for d in _as_list(rows):
        if not isinstance(d, dict):
            continue
        dev = str(d.get("device-id") or d.get("deviceId") or d.get("id") or "")
        out[dev] = [v for v in _as_list(d.get("variables")) if isinstance(v, dict) and v.get("name")]
    return out


def variables_by_device(body: Any) -> dict[str, dict[str, Any]]:
    """{device id: {variable: value}} from the variables answer, secrets masked. Accepts the recorded
    {family, groups, devices: [{device-id, variables: [{name, value}]}]} and a bare list of those devices."""
    return {
        dev: mask_secrets({str(v["name"]): v.get("value") for v in rows})
        for dev, rows in device_variable_lists(body).items()
    }


# --- feature profiles ------------------------------------------------------------------------------


def _values(data: Any, prefix: str, values: dict[str, Any], variables: list[str]) -> None:
    """Flatten a parcel's `data` into dotted keys: global values as they are, variables as '{{name}}'
    (and listed), defaults left out."""
    if isinstance(data, dict) and "optionType" in data:
        kind = data.get("optionType")
        if kind == "variable":
            variables.append(str(data.get("value")))
            values[prefix] = "{{" + str(data.get("value")) + "}}"
        elif kind == "global":
            v = data.get("value")
            if isinstance(v, dict | list):
                _values(v, prefix, values, variables)
            else:
                values[prefix] = v
        return
    if isinstance(data, dict):
        for k, v in data.items():
            _values(v, f"{prefix}.{k}" if prefix else str(k), values, variables)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            _values(v, f"{prefix}[{i}]", values, variables)
    elif data is not None:
        values[prefix] = data


def _mask_flat(values: dict[str, Any]) -> dict[str, Any]:
    """Mask a flattened value whose last key names a secret (password, key, community...)."""
    out = {}
    for k, v in values.items():
        last = re.sub(r"\[\d+\]$", "", k.rsplit(".", 1)[-1])
        out[k] = mask_secrets({last: v})[last] if not str(v).startswith("{{") else v
    return out


def parcel_row(p: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = p["payload"] if isinstance(p.get("payload"), dict) else {}
    values: dict[str, Any] = {}
    variables: list[str] = []
    _values(payload.get("data"), "", values, variables)
    subs = [parcel_row(s) for s in _as_list(p.get("subparcels")) if isinstance(s, dict)]
    return _clean(
        {
            "type": p.get("parcelType"),
            "name": payload.get("name"),
            "description": payload.get("description"),
            "id": p.get("parcelId"),
            "values": _mask_flat(values),
            "variables": sorted(set(variables)),
            "subparcels": subs,
        }
    )


def profile_detail(body: Any) -> dict[str, Any]:
    b = body if isinstance(body, dict) else {}
    parcels = [parcel_row(p) for p in _as_list(b.get("associatedProfileParcels")) if isinstance(p, dict)]
    return _clean(
        {
            "name": b.get("profileName"),
            "type": b.get("profileType"),
            "id": b.get("profileId"),
            "description": b.get("description"),
            "last_updated": iso(b.get("lastUpdatedOn")),
            "last_updated_by": b.get("lastUpdatedBy"),
            "parcels": parcels,
            "variables": sorted({v for p in parcels for v in _all_vars(p)}),
        }
    )


def _all_vars(p: dict[str, Any]) -> list[str]:
    return [*p.get("variables", []), *(v for s in p.get("subparcels", []) for v in _all_vars(s))]


# --- templates -------------------------------------------------------------------------------------


def device_template_row(t: dict[str, Any]) -> dict[str, Any]:
    return _clean(
        {
            "name": t.get("templateName"),
            "id": t.get("templateId"),
            "kind": CONFIG_TYPE.get(str(t.get("configType")), t.get("configType")),
            "device_type": t.get("deviceType"),
            "description": t.get("templateDescription"),
            "devices_attached": t.get("devicesAttached"),
            "factory_default": t.get("factoryDefault"),
            "draft_mode": t.get("draftMode"),
            "last_updated": iso(t.get("lastUpdatedOn")),
            "last_updated_by": t.get("lastUpdatedBy"),
        }
    )


def feature_template_row(t: dict[str, Any]) -> dict[str, Any]:
    types = [str(x) for x in _as_list(t.get("deviceType"))]
    return _clean(
        {
            "name": t.get("templateName"),
            "id": t.get("templateId"),
            "type": t.get("templateType"),
            "device_types": ", ".join(types[:5]) + (f" (+{len(types) - 5} more)" if len(types) > 5 else ""),
            "description": t.get("templateDescription"),
            "devices_attached": t.get("devicesAttached"),
            "device_templates": t.get("attachedMastersCount"),
            "factory_default": t.get("factoryDefault"),
            "min_version": t.get("templateMinVersion"),
            "last_updated": iso(t.get("lastUpdatedOn")),
            "last_updated_by": t.get("lastUpdatedBy"),
        }
    )


def template_devices(body: Any) -> list[str]:
    rows = body.get("data") if isinstance(body, dict) else body
    out = []
    for d in _as_list(rows):
        if isinstance(d, dict):
            name = d.get("host-name") or d.get("deviceIP") or d.get("system-ip") or d.get("uuid")
            if name:
                out.append(str(name))
    return out


# --- configuration text: secrets and diff ----------------------------------------------------------

MASK = "********"
# The IOS encryption type before a secret (0 clear, 5 MD5, 6 AES, 7, 8/9 hashes); possessive, so "secret 9
# <redacted>" never takes the 9 for the secret.
_TYPE = r"(?:[05-9]\s+)?+"
_NOT_SECRET = (
    r"(?!(?:chain|generate|config-key|zeroize|import|export|storage|label|pubkey|address|hostname|"
    r"encryption|exchange|pair|rotation|hash|ascii|modulus)\b)"
)
_SECRET = re.compile(
    r"(?P<kw>(?<![\w-])(?:secret-key|password|secret|key-string|key|community|psk|pre-shared-key|"
    r"pre-shared-secret|passphrase|server-key|authentication-key|auth-password|priv-password|shared-secret|"
    r"ascii))"
    rf"(?P<sep>\s+){_TYPE}{_NOT_SECRET}(?P<secret>[^\s*<]\S*)",
    re.IGNORECASE,
)
_SNMP_USER = re.compile(r"^\s*snmp-server\s+user\b", re.IGNORECASE)
_SNMP_SECRETS = re.compile(
    r"\b(?P<kw>auth\s+(?:md5|sha\S*)|priv\s+(?:des\S*|3des|aes(?:\s+\d{3})?))\s+(?P<secret>\S+)",
    re.IGNORECASE,
)


def _mask(m: re.Match[str]) -> str:
    whole = m.group(0)
    if m.group("kw").lower() == "key" and m.group("secret").isdigit() and not m.string[m.end() :].strip():
        return whole  # 'key 1' under a key chain: the key's number, not a secret
    start, end = m.start("secret") - m.start(0), m.end("secret") - m.start(0)
    return whole[:start] + MASK + whole[end:]


def mask_config(text: str) -> tuple[str, int]:
    """Configuration text with passwords, secrets, keys, pre-shared keys and SNMP communities and user keys
    masked (the keyword and encryption type stay), and how many lines were masked."""
    out, masked = [], 0
    for line in text.splitlines():
        new = _SNMP_SECRETS.sub(_mask, line) if _SNMP_USER.match(line) else _SECRET.sub(_mask, line)
        masked += new != line
        out.append(new)
    return "\n".join(out), masked


def mask_config_leaves(v: Any) -> Any:
    """`v` with every multi-line string (a configuration in an API answer) passed through mask_config."""
    if isinstance(v, str):
        return mask_config(v)[0] if "\n" in v else v
    if isinstance(v, dict):
        return {k: mask_config_leaves(x) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_config_leaves(x) for x in v]
    return v


# Lines only the Manager's rendering carries (its own bookkeeping in `system`), left out of the diff.
_MANAGER_ONLY = re.compile(r"^(personality|device-model|chassis-number)\s")


def _normalise(text: str) -> list[str]:
    """Lines with the Manager's 'no config / config' header and '!' closers dropped, dedented to the
    configuration's own indent (the Manager's rendering is two spaces in), inner runs of spaces collapsed."""
    lines = [ln.rstrip() for ln in text.splitlines()]
    while lines and lines[0].strip() in ("", "no config", "config"):
        lines.pop(0)
    lines = [ln for ln in lines if ln.strip() and ln.strip() != "!"]
    base = min((len(ln) - len(ln.lstrip()) for ln in lines), default=0)
    out = []
    for ln in lines:
        body = ln[base:]
        indent = len(body) - len(body.lstrip())
        out.append(" " * indent + " ".join(body.split()))
    return out


def blocks(text: str) -> dict[str, list[str]]:
    """{top-level line: its child lines} (child lines keep their indent relative to the block). A leading run
    of indented lines (the device's ' system' block) is one block keyed by its first line; top-level 'exit'
    lines only close blocks."""
    out: dict[str, list[str]] = {}
    key: str | None = None
    for ln in _normalise(text):
        stripped = ln.strip()
        top = not ln.startswith(" ")
        if key is None and not top:
            key, top = stripped, True
            out.setdefault(key, [])
            continue
        if top:
            if stripped == "exit":
                key = None
                continue
            key = stripped
            n = 2
            while key in out:  # a repeated top-level line (rare): keep both
                key = f"{stripped} #{n}"
                n += 1
            out[key] = []
        elif key is not None:
            if not _MANAGER_ONLY.match(stripped):
                out[key].append(stripped if len(ln) - len(stripped) <= 1 else ln[1:])
    return out


def config_diff(running: str, intended: str) -> dict[str, Any]:
    """Running vs intended by top-level block (order-independent: the Manager renders blocks in another
    order): blocks only on the device, only intended, and per changed block a unified diff of its lines
    ('-' running, '+' intended)."""
    run, want = blocks(running), blocks(intended)
    only_device = [k for k in run if k not in want]
    only_intended = [k for k in want if k not in run]
    changed: dict[str, list[str]] = {}
    for k in run:
        if k in want and run[k] != want[k]:
            lines = [
                ln
                for ln in difflib.unified_diff(run[k], want[k], lineterm="", n=0)
                if ln[:1] in "+-" and not ln.startswith(("---", "+++"))
            ]
            if lines:
                changed[k] = lines
    out: dict[str, Any] = {
        "in_sync": not (only_device or only_intended or changed),
        "summary": f"{len(only_device)} block(s) only on the device, {len(only_intended)} only intended, "
        f"{len(changed)} changed",
    }
    if only_device:
        out["only_on_device"] = only_device
    if only_intended:
        out["only_intended"] = only_intended
    if changed:
        out["changed"] = changed
    return out


def sections(text: str, wanted: str) -> str:
    """The top-level blocks of `text` whose first line contains `wanted` (case-insensitive), with their
    child lines (normalised as for the diff)."""
    want = wanted.strip().lower()
    out: list[str] = []
    for key, children in blocks(text).items():
        if want in key.lower():
            out += [key, *(" " + c for c in children)]
    return "\n".join(out)
