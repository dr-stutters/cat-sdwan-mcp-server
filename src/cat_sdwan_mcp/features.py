"""Feature profiles and configuration-group authoring (W21): parcel values, the Manager's parcel schemas, and
the change a set_feature_parcel makes.

Pure helpers; the tools are in tools/features.py. Sources (recorded on 20.18.3.1 unless marked):
- GET /dataservice/v1/feature-profile/sdwan/<type> (system, transport, service, cli, ...): [{profileId,
  profileName, profileType, solution, description, lastUpdatedBy/On, ...}].
- GET /dataservice/v1/feature-profile/sdwan/<type>/{profileId}: {profileName, profileType, profileId,
  associatedProfileParcels: [{parcelId, parcelType ("basic", "wan/vpn", "config", ...), payload: {name,
  description} (NO data here), subparcels, lastUpdatedBy/On}]}.
- GET /dataservice/v1/feature-profile/sdwan/<type>/{profileId}/<parcelType>/{parcelId}: {parcelId, parcelType,
  origin, createdBy/On, lastUpdatedBy/On, payload: {name, description, data}}; each leaf of `data` is
  {optionType: global|variable|default, value} (a default may carry no value); the CLI profile's `config`
  parcel is data.config = a PLAIN STRING of CLI with {{variables}}.
- GET /dataservice/v1/feature-profile/sdwan/<type>/<parcelType>/schema?schemaType=post|put: {request: a JSON
  Schema (2019-09) for {name, description, data, metadata}}; each leaf is {oneOf: [branch per optionType]}, a
  branch's `value` with type, enum, minimum/maximum, min/maxLength, pattern; a `default` branch's value is
  often pinned by a one-item enum (consoleBaudRate default "9600"), and `data.required` names the leaves.
- PUT .../<parcelType>/{parcelId} and POST .../<parcelType> {name, description, data}: the Manager reports
  missing required fields one round at a time ("Validation Errors": "Required But Missing Attributes",
  "Invalid Format Attributes"), so every field is checked here first, all at once. Answer {parcelId}
  (spec; not recorded). Nothing reaches a device until the configuration group is deployed (W8).
- POST / DELETE /dataservice/v1/config-group/{id}/device/associate {devices: [{id: <chassis>}]} (Cisco's
  documented shape; not recorded).
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest
from cat_sdwan_mcp._core.formatting import mask_secrets
from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.configuration import mask_config, path

PROFILE_LIST_PATH = "/dataservice/v1/feature-profile/sdwan/{type}"
PARCEL_LIST_PATH = "/dataservice/v1/feature-profile/sdwan/{type}/{profile}/{parcel_type}"
PARCEL_PATH = PARCEL_LIST_PATH + "/{parcel}"
SCHEMA_PATH = "/dataservice/v1/feature-profile/sdwan/{type}/{parcel_type}/schema"
POLICY_GROUP_PATH = "/dataservice/v1/policy-group/{id}"
POLICY_ASSOCIATE_PATH = POLICY_GROUP_PATH + "/device/associate"
POLICY_PREVIEW_PATH = POLICY_GROUP_PATH + "/device/{device}/preview"
POLICY_DEPLOY_PATH = POLICY_GROUP_PATH + "/device/deploy"

# Profile types with a list read (GET /v1/feature-profile/sdwan/<type>) in the 20.18 spec.
LISTABLE_TYPES = (
    "system",
    "transport",
    "service",
    "cli",
    "other",
    "policy-object",
    "application-priority",
    "embedded-security",
    "dns-security",
    "sig-security",
    "sse-spa",
)
OPTION_TYPES = ("global", "variable", "default")
_PARCEL_TYPE = re.compile(r"^[a-z0-9][a-z0-9-]*(?:/[a-z0-9][a-z0-9-]*)*$")
_VARIABLE = re.compile(r"^\{\{[.\/\[\]a-zA-Z0-9_-]+\}\}$")
_SEGMENT = re.compile(r"^(?P<key>[^\[\]]+)(?:\[(?P<index>\d+)\])?$")
MISSING = object()


def as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def parcel_url(template: str, *, ptype: str, parcel_type: str, **ids: str) -> str:
    """A feature-profile path. The parcel type keeps its '/' (wan/vpn is two path segments); ids are
    quoted."""
    if not _PARCEL_TYPE.match(parcel_type):
        raise InvalidRequest(
            f"{parcel_type!r} is not a parcel type (e.g. 'basic', 'ntp', 'wan/vpn', 'config')."
        )
    return path(template.replace("{parcel_type}", parcel_type), type=ptype, **ids)


# --- reading a parcel ----------------------------------------------------------------------------


def is_leaf(v: Any) -> bool:
    return isinstance(v, dict) and "optionType" in v


def flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    """{dotted path: leaf} for every option leaf ({optionType, value}) and plain value in a parcel's data.
    A global value that is itself a list of objects (VPN routes, NTP servers) is walked with [i] indexes."""
    out: dict[str, Any] = {}
    if is_leaf(data):
        v = data.get("value")
        if (
            data.get("optionType") == "global"
            and isinstance(v, list)
            and v
            and all(isinstance(x, dict) for x in v)
        ):
            for i, x in enumerate(v):
                out.update(flatten(x, f"{prefix}[{i}]"))
        else:
            out[prefix] = data
    elif isinstance(data, dict):
        for k, v in data.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            out.update(flatten(v, f"{prefix}[{i}]"))
    elif prefix:
        out[prefix] = data
    return out


def _secret_key(path: str) -> str:
    return re.sub(r"\[\d+\]$", "", path.rsplit(".", 1)[-1])


def shown(path: str, leaf: Any) -> Any:
    """A leaf for people: '{{name}}' for a variable, the value for global, 'default (<value>)' for a default;
    secrets masked; CLI text masked line by line."""
    if not is_leaf(leaf):
        if isinstance(leaf, str) and "\n" in leaf:
            return mask_config(leaf)[0]
        return mask_secrets({_secret_key(path): leaf})[_secret_key(path)]
    kind, value = leaf.get("optionType"), leaf.get("value", MISSING)
    if kind == "variable":
        return value
    if kind == "default":
        return "default" if value is MISSING or value is None else f"default ({value})"
    key = _secret_key(path)
    return mask_secrets({key: None if value is MISSING else value})[key]


def parcel_view(body: Any) -> dict[str, Any]:
    """A parcel as people read it: values by source (global, variable, default), the variables, CLI text."""
    b = body if isinstance(body, dict) else {}
    payload = as_dict(b.get("payload"))
    data = as_dict(payload.get("data"))
    flat = flatten(data)
    configured: dict[str, Any] = {}
    defaults: dict[str, Any] = {}
    variables: list[str] = []
    cli: str | None = None
    for p, leaf in flat.items():
        if not is_leaf(leaf):
            if isinstance(leaf, str) and "\n" in leaf:
                cli = leaf
                continue
            configured[p] = shown(p, leaf)
        elif leaf.get("optionType") == "default":
            v = leaf.get("value")
            defaults[p] = "(no value)" if v is None else v
        else:
            configured[p] = shown(p, leaf)
            if leaf.get("optionType") == "variable":
                variables.append(str(leaf.get("value")).strip("{}"))
    out: dict[str, Any] = {
        "name": payload.get("name"),
        "type": b.get("parcelType"),
        "id": b.get("parcelId"),
        "description": payload.get("description"),
        "last_updated_by": b.get("lastUpdatedBy"),
        "configured": configured,
        "variables": sorted(set(variables)),
        "defaults": defaults,
    }
    if cli is not None:
        masked, n = mask_config(cli)
        out["cli"] = masked
        out["cli_lines"] = len(cli.splitlines())
        out["variables"] = sorted(set(variables) | set(re.findall(r"\{\{\s*([\w.-]+)\s*\}\}", cli)))
        if n:
            out["cli_masked_lines"] = n
    return {k: v for k, v in out.items() if v not in (None, "", [], {}) or k in ("configured",)}


def parcels_of(profile_body: Any) -> list[dict[str, Any]]:
    """[{id, type, name}] of a profile detail's parcels (subparcels are not walked)."""
    b = profile_body if isinstance(profile_body, dict) else {}
    out = []
    for p in _as_list(b.get("associatedProfileParcels")):
        if isinstance(p, dict) and p.get("parcelId"):
            payload = as_dict(p.get("payload"))
            out.append(
                {
                    "id": str(p["parcelId"]),
                    "type": str(p.get("parcelType") or ""),
                    "name": payload.get("name"),
                    "subparcels": len(_as_list(p.get("subparcels"))),
                }
            )
    return out


def pick_parcel(parcels: list[dict[str, Any]], ref: str, where: str) -> dict[str, Any]:
    """A parcel by id, name or type (exact, case-insensitive); a type that matches several asks for the
    name."""
    want = ref.strip().lower()
    for key in ("id", "name", "type"):
        found = [p for p in parcels if str(p.get(key) or "").lower() == want]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = ", ".join(f"{p['name']} ({p['type']})" for p in found)
            raise InvalidRequest(f"{ref!r} matches {len(found)} parcels in {where}: {names}. Give the name.")
    have = ", ".join(f"{p['name']} ({p['type']})" for p in parcels) or "none"
    raise InvalidRequest(f"{where} has no parcel {ref!r} (its parcels: {have}).")


# --- the schema ----------------------------------------------------------------------------------


def request_schema(body: Any) -> dict[str, Any]:
    b = body.get("request") if isinstance(body, dict) and isinstance(body.get("request"), dict) else body
    return b if isinstance(b, dict) else {}


def data_schema(schema: dict[str, Any]) -> dict[str, Any]:
    props = as_dict(schema.get("properties"))
    return as_dict(props.get("data"))


def _segments(path: str) -> list[tuple[str, int | None]]:
    out = []
    for seg in path.split("."):
        m = _SEGMENT.match(seg)
        if not m:
            raise InvalidRequest(f"{path!r} is not a field path (e.g. 'consoleBaudRate', 'clock.timezone').")
        out.append((m.group("key"), int(m.group("index")) if m.group("index") else None))
    return out


def field_schema(dschema: dict[str, Any], path: str) -> dict[str, Any] | None:
    """The schema of the leaf at `path` under data (None when the schema has no such field). An indexed
    segment walks into the list held by the global branch's value (or `items`)."""
    node: Any = dschema
    for key, index in _segments(path):
        props = node.get("properties") if isinstance(node, dict) else None
        if not isinstance(props, dict) or key not in props:
            return None
        node = props[key]
        if index is not None:
            node = _list_items(node)
            if node is None:
                return None
    return node if isinstance(node, dict) else None


def _list_items(node: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(node.get("items"), dict):
        return dict(node["items"])
    for br in _as_list(node.get("oneOf")):
        value = (br.get("properties") or {}).get("value") if isinstance(br, dict) else None
        if isinstance(value, dict) and isinstance(value.get("items"), dict):
            return dict(value["items"])
    return None


def is_required(dschema: dict[str, Any], name: str) -> bool:
    """Whether every level of a dotted field path is required by its parent object."""
    node: Any = dschema
    for seg in name.split("."):
        key = seg.removesuffix("[i]")
        if not isinstance(node, dict) or key not in _as_list(node.get("required")):
            return False
        node = as_dict(node.get("properties")).get(key)
        if seg.endswith("[i]") and isinstance(node, dict):
            node = _list_items(node)
    return True


def field_names(dschema: dict[str, Any], prefix: str = "", depth: int = 3) -> list[str]:
    """The leaf paths the schema knows (nested objects walked a few levels; lists shown as name[i])."""
    out: list[str] = []
    props = as_dict(dschema.get("properties"))
    for k, v in props.items():
        p = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and "oneOf" not in v and isinstance(v.get("properties"), dict) and depth > 0:
            out += field_names(v, p, depth - 1)
        else:
            out.append(p + ("[i]" if isinstance(v, dict) and _list_items(v) else ""))
    return out


def _branches(fs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{optionType: branch} of a leaf schema's oneOf."""
    out: dict[str, dict[str, Any]] = {}
    for br in _as_list(fs.get("oneOf")):
        props = br.get("properties") if isinstance(br, dict) else None
        opt = props.get("optionType") if isinstance(props, dict) else None
        for kind in _as_list(opt.get("enum") if isinstance(opt, dict) else None):
            out[str(kind)] = br
    return out


def _type_ok(want: Any, v: Any) -> bool:
    kinds = want if isinstance(want, list) else [want]
    for k in kinds:
        if k == "string" and isinstance(v, str):
            return True
        if k == "integer" and isinstance(v, int) and not isinstance(v, bool):
            return True
        if k == "number" and isinstance(v, int | float) and not isinstance(v, bool):
            return True
        if k == "boolean" and isinstance(v, bool):
            return True
        if k == "array" and isinstance(v, list):
            return True
        if k == "object" and isinstance(v, dict):
            return True
        if k == "null" and v is None:
            return True
    return False


def check_value(vs: dict[str, Any], v: Any) -> str | None:
    """Why `v` breaks the value schema `vs` (type, enum, range, length, pattern), or None."""
    if not vs:
        return None
    if "type" in vs and not _type_ok(vs["type"], v):
        return f"must be {vs['type']}, got {type(v).__name__} {v!r}"
    if isinstance(vs.get("enum"), list) and v not in vs["enum"]:
        shown_enum = ", ".join(map(repr, vs["enum"][:12])) + (" ..." if len(vs["enum"]) > 12 else "")
        return f"{v!r} is not one of {shown_enum}"
    if isinstance(v, int | float) and not isinstance(v, bool):
        if isinstance(vs.get("minimum"), int | float) and v < vs["minimum"]:
            return f"{v} is below the minimum {vs['minimum']}"
        if isinstance(vs.get("maximum"), int | float) and v > vs["maximum"]:
            return f"{v} is above the maximum {vs['maximum']}"
    if isinstance(v, str):
        if isinstance(vs.get("minLength"), int) and len(v) < vs["minLength"]:
            return f"is shorter than {vs['minLength']} characters"
        if isinstance(vs.get("maxLength"), int) and len(v) > vs["maxLength"]:
            return f"is longer than {vs['maxLength']} characters"
        if isinstance(vs.get("pattern"), str):
            try:
                if not re.search(vs["pattern"], v):
                    return f"{v!r} does not match the pattern {vs['pattern']}"
            except re.error:
                pass
    if isinstance(v, list):
        if isinstance(vs.get("minItems"), int) and len(v) < vs["minItems"]:
            return f"needs at least {vs['minItems']} items"
        if isinstance(vs.get("maxItems"), int) and len(v) > vs["maxItems"]:
            return f"takes at most {vs['maxItems']} items"
    return None


def default_leaf(fs: dict[str, Any]) -> dict[str, Any] | None:
    """The {optionType: default, value?} the schema allows for a leaf: the default branch's pinned value (a
    one-item enum, or its `default`), or no value when the branch has none. None: no default branch."""
    br = _branches(fs).get("default")
    if br is None:
        return None
    vs = (br.get("properties") or {}).get("value")
    if not isinstance(vs, dict):
        return {"optionType": "default"}
    if isinstance(vs.get("enum"), list) and len(vs["enum"]) == 1:
        return {"optionType": "default", "value": vs["enum"][0]}
    if "default" in vs:
        return {"optionType": "default", "value": vs["default"]}
    if isinstance(vs.get("minimum"), int | float) and vs.get("minimum") == vs.get("maximum"):
        return {"optionType": "default", "value": vs["minimum"]}
    return None


def check_leaf(fs: dict[str, Any], leaf: Any) -> str | None:
    """Why a leaf breaks its field schema, or None. A plain (non-option) field is checked as a value."""
    if not is_leaf(leaf):
        return check_value(fs, leaf)
    kind = str(leaf.get("optionType"))
    branches = _branches(fs)
    if not branches:
        return None  # not an option field in this schema (left to the Manager)
    br = branches.get(kind)
    if br is None:
        return f"can't be {kind} (allowed: {', '.join(branches)})"
    props = br.get("properties") or {}
    required = _as_list(br.get("required"))
    if "value" not in leaf:
        return "needs a value" if "value" in required else None
    vs = props.get("value")
    if kind == "variable" and not _VARIABLE.match(str(leaf.get("value"))):
        return f"{leaf.get('value')!r} is not a variable name in {{{{...}}}}"
    return check_value(vs if isinstance(vs, dict) else {}, leaf.get("value"))


def missing_required(dschema: dict[str, Any], data: Any, prefix: str = "") -> list[str]:
    """Required fields absent from `data` (nested objects walked), all at once: the Manager reports them one
    round at a time."""
    out: list[str] = []
    props = as_dict(dschema.get("properties"))
    have = data if isinstance(data, dict) else {}
    for k in _as_list(dschema.get("required")):
        if k not in have:
            out.append(f"{prefix}{k}")
    for k, v in props.items():
        if k in have and isinstance(v, dict) and "oneOf" not in v and isinstance(v.get("properties"), dict):
            out += missing_required(v, have[k], f"{prefix}{k}.")
    return out


def defaults_for(dschema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """(data with every required field the schema can default, the required fields it can't) for a new
    parcel."""
    data: dict[str, Any] = {}
    unresolved: list[str] = []
    props = as_dict(dschema.get("properties"))
    for k in _as_list(dschema.get("required")):
        fs = props.get(k)
        if not isinstance(fs, dict):
            unresolved.append(str(k))
        elif "oneOf" in fs:
            leaf = default_leaf(fs)
            if leaf is None:
                unresolved.append(str(k))
            else:
                data[k] = leaf
        elif isinstance(fs.get("properties"), dict):
            sub, missing = defaults_for(fs)
            data[k] = sub
            unresolved += [f"{k}.{m}" for m in missing]
        elif fs.get("type") == "array":
            data[k] = []
        else:
            unresolved.append(str(k))
    return data, unresolved


# --- changing a parcel ---------------------------------------------------------------------------


def to_leaf(fs: dict[str, Any] | None, current: Any, value: Any) -> Any:
    """What a given value becomes: None = the schema's default, '{{name}}' = a variable, an explicit
    {optionType, value} as given, anything else global. A plain field (the CLI parcel's config) is set as
    given."""
    if isinstance(value, dict) and "optionType" in value:
        return dict(value)
    plain = current is not MISSING and not is_leaf(current)
    if (fs is not None and not _branches(fs)) or (fs is None and plain):
        return value
    if value is None:
        leaf = default_leaf(fs) if fs is not None else None
        if leaf is None:
            raise InvalidRequest("has no default in the schema: give a value")
        return leaf
    if isinstance(value, str) and _VARIABLE.match(value.strip()):
        return {"optionType": "variable", "value": value.strip()}
    return {"optionType": "global", "value": value}


def get_at(data: Any, path: str) -> Any:
    node = data
    for key, index in _segments(path):
        if not isinstance(node, dict) or key not in node:
            return MISSING
        node = node[key]
        if index is not None:
            items = node.get("value") if is_leaf(node) else node
            if not isinstance(items, list) or index >= len(items):
                return MISSING
            node = items[index]
    return node


def set_at(data: dict[str, Any], path: str, leaf: Any) -> None:
    """Set the leaf at `path`, creating plain objects on the way; an index must exist already."""
    segs = _segments(path)
    node: Any = data
    for i, (key, index) in enumerate(segs):
        last = i == len(segs) - 1
        if index is None:
            if last:
                node[key] = leaf
                return
            node = node.setdefault(key, {})
            if not isinstance(node, dict):
                raise InvalidRequest(f"{path!r}: {key} is not an object")
            continue
        holder = node.get(key)
        items = holder.get("value") if is_leaf(holder) else holder
        if not isinstance(items, list) or index >= len(items):
            raise InvalidRequest(f"{path!r}: {key} has no item {index}")
        if last:
            items[index] = leaf
            return
        node = items[index]


def describe(leaf: Any) -> Any:
    """old/new for the preview: ('global', value) style text."""
    if leaf is MISSING:
        return "(not set)"
    if not is_leaf(leaf):
        return leaf
    kind, value = leaf.get("optionType"), leaf.get("value", MISSING)
    if kind == "variable":
        return f"variable {value}"
    if value is MISSING:
        return str(kind)
    return f"{kind}: {value!r}"


def masked_change(path: str, old: Any, new: Any) -> dict[str, Any]:
    key = _secret_key(path)
    if mask_secrets({key: "x"})[key] != "x":
        return {"from": "********" if old is not MISSING else "(not set)", "to": "********"}
    return {"from": describe(old), "to": describe(new)}


def cli_replace(text: str, edits: dict[str, str]) -> tuple[str, list[str]]:
    """`text` with each old -> new replacement made (each old must occur exactly once), and the problems."""
    out, problems = text, []
    for old, new in edits.items():
        n = out.count(old)
        if n != 1:
            problems.append(
                f"cli_replace {old!r} occurs {n} times in the CLI parcel (it must occur exactly once)"
            )
            continue
        out = out.replace(old, new)
    return out, problems


def cli_diff(old: str, new: str) -> list[str]:
    """Changed CLI lines ('-' old, '+' new), secrets masked."""
    a, b = mask_config(old)[0].splitlines(), mask_config(new)[0].splitlines()
    return [
        ln
        for ln in difflib.unified_diff(a, b, lineterm="", n=0)
        if ln[:1] in "+-" and ln[:3] not in ("---", "+++")
    ]
