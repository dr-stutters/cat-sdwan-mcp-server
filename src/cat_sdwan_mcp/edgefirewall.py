"""W47 edge firewall writes: security objects (zones, identity lists, SGT lists, IPv4 prefix lists) in the
policy-object profile, and the zone-based / identity firewall (NGFW) in a policy group's embedded-security
profile. Pure helpers; the tools are in tools/edgefirewall.py. Reads extend W23 (catsdwan_security_status).

On 20.18 the edge firewall is policy-group content: lists live in the Manager's policy-object profile
(Default_Policy_Object_Profile), the rules in an embedded-security profile, and a device gets them with
catsdwan_deploy_policy_group. Sources:
- Recorded (20.18.3.1, read only): GET
  /v1/feature-profile/sdwan/policy-object/<listType>/schema?schemaType=post for security-zone (entries: VPNs
  or interfaces, never both; name not untrusted/self/default/service), security-identity (users and user
  groups, at most 16), security-scalablegrouptag (sgtName + tag, at most 8) and security-data-ip-prefix;
  GET .../policy-object/{id}/security-zone = {header, data: []}; a system data-prefix parcel {parcelId,
  parcelType, origin, payload: {name, data: {entries}}}.
- Not recorded (the 20.18 OpenAPI document carries no body schema for them and the lab has no security
  profile): the embedded-security profile create (POST /v1/feature-profile/sdwan/embedded-security {name,
  description} -> {id}), the NGFW parcel (POST .../embedded-security/{id}/unified/ngfirewall: data
  {defaultActionType, sequences: [{sequenceId, sequenceName, baseAction drop|pass|inspect, sequenceType
  ngfirewall, match: {entries: [one match per entry]}, actions, disableSequence}]}) and the security policy
  parcel that binds it to zone pairs (POST .../embedded-security/{id}/policy: data {assembly: [{ngfirewall:
  {refId, entries: [{srcZone: {refId}, dstZone: {refId}}]}}], settings}). These follow Cisco's published
  parcel models; the preview checks them against the Manager's own schema when it answers one, and the
  Manager validates them on confirm.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cat_sdwan_mcp.client import _as_list

PO_LIST_PATH = "/dataservice/v1/feature-profile/sdwan/policy-object/{profile}/{list_type}"
PO_ITEM_PATH = PO_LIST_PATH + "/{parcel}"
PO_SCHEMA_PATH = "/dataservice/v1/feature-profile/sdwan/policy-object/{list_type}/schema"
SEC_PROFILES_PATH = "/dataservice/v1/feature-profile/sdwan/embedded-security"
SEC_PROFILE_PATH = SEC_PROFILES_PATH + "/{id}"
NGFW_LIST_PATH = SEC_PROFILE_PATH + "/unified/ngfirewall"
NGFW_PATH = NGFW_LIST_PATH + "/{parcel}"
SEC_POLICY_LIST_PATH = SEC_PROFILE_PATH + "/policy"
SEC_POLICY_PATH = SEC_POLICY_LIST_PATH + "/{parcel}"
SEC_SCHEMA_PATH = "/dataservice/v1/feature-profile/sdwan/embedded-security/{parcel_type}/schema"

# kind -> the policy-object list type.
OBJECT_TYPES = {
    "zone": "security-zone",
    "identity": "security-identity",
    "sgt": "security-scalablegrouptag",
    "prefix": "security-data-ip-prefix",
}
ACTIONS = ("drop", "pass", "inspect")
LOG_ACTION = {"type": {"optionType": "global", "value": "log"}, "parameter": {"optionType": "default"}}
RESERVED_ZONES = ("untrusted", "self", "default", "service")
_VPN = re.compile(r"^\d{1,5}$")


def g(value: Any) -> dict[str, Any]:
    """A global option leaf."""
    return {"optionType": "global", "value": value}


def ref(ids: list[str] | str) -> dict[str, Any]:
    return {"refId": g(ids)}


def leaf_value(v: Any) -> Any:
    return v.get("value") if isinstance(v, dict) and "optionType" in v else v


def parcels(body: Any) -> list[dict[str, Any]]:
    """[{id, name, data, raw}] from a parcel list ({header, data: [...]} or a bare list)."""
    rows = body.get("data") if isinstance(body, dict) and "data" in body else body
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        payload: dict[str, Any] = r["payload"] if isinstance(r.get("payload"), dict) else {}
        pid = r.get("parcelId") or r.get("id")
        if pid:
            out.append(
                {
                    "id": str(pid),
                    "name": payload.get("name") or r.get("name"),
                    "data": payload.get("data") if isinstance(payload.get("data"), dict) else {},
                    "raw": r,
                }
            )
    return out


def by_name(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    want = name.strip().lower()
    for r in rows:
        if str(r.get("name") or "").lower() == want or r["id"].lower() == want:
            return r
    return None


# --- security objects -----------------------------------------------------------------------------


def object_entries(
    kind: str, values: list[str], sgt_names: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """(the parcel's data.entries, problems) for a kind and its values:
    zone: VPN numbers or interface names (not both); identity: 'user:<name>' or 'group:<name>' (a bare value
    is a user); sgt: '<name>:<tag>', a tag number or an ISE SGT name; prefix: IPv4 prefixes."""
    problems: list[str] = []
    entries: list[dict[str, Any]] = []
    clean = [v.strip() for v in values if v and v.strip()]
    if not clean:
        return [], ["no values"]
    if len(set(clean)) != len(clean):
        problems.append("a value is given twice")
    if kind == "zone":
        vpns = [v for v in clean if _VPN.match(v)]
        if vpns and len(vpns) != len(clean):
            problems.append("a zone holds VPNs or interfaces, not both")
        for v in clean:
            entries.append({"vpn": g(v)} if _VPN.match(v) else {"interface": g(v)})
    elif kind == "identity":
        for v in clean:
            head, _, rest = v.partition(":")
            if head.lower() in ("group", "usergroup", "user_group") and rest.strip():
                entries.append({"userGroup": g(rest.strip())})
            elif head.lower() == "user" and rest.strip():
                entries.append({"user": g(rest.strip())})
            else:
                entries.append({"user": g(v)})
        if len(entries) > 16:
            problems.append(f"an identity list holds at most 16 users and groups ({len(entries)} given)")
    elif kind == "sgt":
        names = {k.lower(): (k, t) for k, t in (sgt_names or {}).items()}
        by_tag = {t: k for k, t in (sgt_names or {}).items()}
        for v in clean:
            name, _, tag = v.rpartition(":")
            if name and tag.strip().isdigit():
                entries.append({"sgtName": g(name.strip()), "tag": g(tag.strip())})
            elif v.isdigit():
                entries.append({"sgtName": g(by_tag.get(v, f"SGT_{v}")), "tag": g(v)})
            elif v.lower() in names:
                n, t = names[v.lower()]
                entries.append({"sgtName": g(n), "tag": g(t)})
            else:
                problems.append(f"SGT {v!r}: give '<name>:<tag>' or a tag number (ISE does not list it)")
        if len(clean) > 8:
            problems.append(f"an SGT list holds at most 8 tags ({len(clean)} given)")
    elif kind == "prefix":
        for v in clean:
            try:
                net = ipaddress.IPv4Network(v, strict=True)
            except ValueError as e:
                problems.append(f"{v!r} is not an IPv4 prefix ({e})")
                continue
            entries.append({"ipPrefix": g(str(net))})
    else:
        problems.append(f"unknown kind {kind!r} (one of {', '.join(OBJECT_TYPES)})")
    return entries, problems


def object_body(name: str, description: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": name, "description": description, "data": {"entries": entries}}


def object_values(kind: str, data: dict[str, Any]) -> list[str]:
    """An object's values in the same words object_entries takes."""
    out = []
    for e in _as_list(data.get("entries")):
        if not isinstance(e, dict):
            continue
        if kind == "zone":
            out.append(str(leaf_value(e.get("vpn")) or leaf_value(e.get("interface")) or "?"))
        elif kind == "identity":
            if "userGroup" in e:
                out.append(f"group:{leaf_value(e['userGroup'])}")
            else:
                out.append(f"user:{leaf_value(e.get('user'))}")
        elif kind == "sgt":
            out.append(f"{leaf_value(e.get('sgtName'))}:{leaf_value(e.get('tag'))}")
        elif kind == "prefix":
            out.append(str(leaf_value(e.get("ipPrefix"))))
        else:
            out.append(str({k: leaf_value(v) for k, v in e.items()}))
    return out


def sgt_table(body: Any) -> dict[str, str]:
    """{SGT name: tag} from GET /template/policy/ise/identity/sgt (an error body when ISE is not
    configured, recorded; row keys taken loosely as the shape with ISE is not recorded)."""
    rows = body.get("data", body) if isinstance(body, dict) else body
    out = {}
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        name = r.get("name") or r.get("sgtName")
        tag = r.get("tag") or r.get("value") or r.get("sgt")
        if name and tag is not None:
            out[str(name)] = str(tag)
    return out


# --- firewall rules ------------------------------------------------------------------------------

# rule field -> (match key, policy-object kind for names, or None for literal values)
REF_MATCHES = {
    "source_objects": ("sourceDataPrefixList", "prefix"),
    "destination_objects": ("destinationDataPrefixList", "prefix"),
    "identities": ("sourceIdentityList", "identity"),
    "source_sgts": ("sourceSecurityGroup", "sgt"),
    "destination_sgts": ("destinationSecurityGroup", "sgt"),
    "apps": ("appList", "app"),
}
LITERAL_MATCHES = {
    "source_prefixes": "sourceIp",
    "destination_prefixes": "destinationIp",
}


def literal_prefix_problems(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            ipaddress.IPv4Network(v, strict=True)
        except ValueError as e:
            out.append(f"{v!r} is not an IPv4 prefix ({e})")
    return out


def match_entries(rule: dict[str, Any], refs: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """The NGFW sequence's match.entries: one entry per match, list names resolved to parcel ids by
    refs[kind][name]."""
    out: list[dict[str, Any]] = []
    for field_name, key in LITERAL_MATCHES.items():
        if rule.get(field_name):
            out.append({key: {"ipv4Value": g(list(rule[field_name]))}})
    for field_name, (key, kind) in REF_MATCHES.items():
        names = rule.get(field_name) or []
        if names:
            out.append({key: ref([refs[kind][n] for n in names])})
    if rule.get("protocols"):
        out.append({"protocolName": g([str(p).lower() for p in rule["protocols"]])})
    return out


def ngfw_body(
    name: str,
    description: str,
    default_action: str,
    rules: list[dict[str, Any]],
    refs: dict[str, dict[str, str]],
) -> dict[str, Any]:
    seqs = []
    for i, r in enumerate(rules, start=1):
        seqs.append(
            {
                "sequenceId": g(str(i)),
                "sequenceName": g(str(r["name"])),
                "baseAction": g(str(r["action"])),
                "sequenceType": g("ngfirewall"),
                "match": {"entries": match_entries(r, refs)},
                "actions": [LOG_ACTION] if r.get("log") else [],
                "disableSequence": g(False),
            }
        )
    return {
        "name": name,
        "description": description,
        "data": {"defaultActionType": g(default_action), "sequences": seqs},
    }


def assembly_item(ngfw_id: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "ngfirewall": {
            "refId": g(ngfw_id),
            "entries": [{"srcZone": ref(s), "dstZone": ref(d)} for s, d in pairs],
        }
    }


def assembly_ref(item: Any) -> str | None:
    if isinstance(item, dict) and isinstance(item.get("ngfirewall"), dict):
        rid = leaf_value(item["ngfirewall"].get("refId"))
        return str(rid) if rid else None
    return None


def merge_assembly(data: dict[str, Any], ngfw_id: str, item: dict[str, Any] | None) -> dict[str, Any]:
    """The security policy parcel's data with this NGFW's assembly item replaced (None removes it); the
    other items and the settings are kept."""
    others = [a for a in _as_list(data.get("assembly")) if assembly_ref(a) != ngfw_id]
    out = {k: v for k, v in data.items() if k != "assembly"}
    out["assembly"] = others + ([item] if item else [])
    return out


def policy_body(name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "description": "Security policy (zone pairs to NGFW)", "data": data}


def describe_rules(data: dict[str, Any], names: dict[str, str]) -> list[str]:
    """NGFW sequences in plain words ('1 allow-alice: identity alice-list, apps webex -> pass, log'), ids
    shown as the object names in `names` ({parcel id: name})."""
    words = {
        "sourceIp": "source",
        "destinationIp": "destination",
        "sourceDataPrefixList": "source list",
        "destinationDataPrefixList": "destination list",
        "sourceIdentityList": "identity",
        "sourceSecurityGroup": "source SGT",
        "destinationSecurityGroup": "destination SGT",
        "appList": "apps",
        "protocolName": "protocol",
    }
    out = []
    for s in _as_list(data.get("sequences")):
        if not isinstance(s, dict):
            continue
        parts = []
        for e in _as_list((s.get("match") or {}).get("entries")):
            if not isinstance(e, dict):
                continue
            for k, v in e.items():
                val = leaf_value(v)
                if isinstance(v, dict) and "refId" in v:
                    val = leaf_value(v["refId"])
                elif isinstance(v, dict) and "ipv4Value" in v:
                    val = leaf_value(v["ipv4Value"])
                vals = [names.get(str(x), str(x)) for x in _as_list(val)] if val is not None else []
                parts.append(f"{words.get(k, k)} {', '.join(vals)}")
        logged = any(
            isinstance(a, dict) and leaf_value(a.get("type")) == "log" for a in _as_list(s.get("actions"))
        )
        off = leaf_value(s.get("disableSequence")) is True
        out.append(
            f"{leaf_value(s.get('sequenceId'))} {leaf_value(s.get('sequenceName'))}: "
            f"{'; '.join(parts) or 'any'} -> {leaf_value(s.get('baseAction'))}"
            + (", log" if logged else "")
            + (" (disabled)" if off else "")
        )
    out.append(f"default -> {leaf_value(data.get('defaultActionType'))}")
    return out


def zone_pairs_of(policy_data: dict[str, Any], ngfw_id: str | None = None) -> list[tuple[str, str, str]]:
    """[(ngfw id, source zone id, destination zone id)] from the security policy parcel."""
    out = []
    for a in _as_list(policy_data.get("assembly")):
        rid = assembly_ref(a)
        if not rid or (ngfw_id and rid != ngfw_id):
            continue
        for e in _as_list(a["ngfirewall"].get("entries")):
            if isinstance(e, dict):
                s = leaf_value((e.get("srcZone") or {}).get("refId"))
                d = leaf_value((e.get("dstZone") or {}).get("refId"))
                out.append((rid, str(s), str(d)))
    return out


# --- a small JSON Schema check (the Manager's parcel schemas, 2019-09 subset) ----------------------


def schema_problems(schema: Any, value: Any, at: str = "") -> list[str]:
    """Problems of `value` against a JSON Schema: type, enum, properties, required, additionalProperties,
    items, min/maxItems, min/maxLength, pattern, oneOf. Enough for the parcel schemas; [] when it fits."""
    if not isinstance(schema, dict):
        return []
    where = at or "body"
    if "oneOf" in schema:
        branches = [b for b in _as_list(schema["oneOf"]) if isinstance(b, dict)]
        base = {k: v for k, v in schema.items() if k != "oneOf"}
        results = [schema_problems({**base, **b}, value, at) for b in branches]
        if any(not r for r in results):
            return []
        if results:
            return min(results, key=len)
    t = schema.get("type")
    types = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
    }
    if t in types and not isinstance(value, types[t]):
        return [f"{where}: must be {t}"]
    if t in ("integer", "number") and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return [f"{where}: must be {t}"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: {value!r} is not one of {schema['enum']}"]
    out: list[str] = []
    if isinstance(value, dict):
        props: dict[str, Any] = schema["properties"] if isinstance(schema.get("properties"), dict) else {}
        for r in _as_list(schema.get("required")):
            if r not in value:
                out.append(f"{where}: {r} is required")
        if schema.get("additionalProperties") is False:
            out += [f"{where}: {k} is not allowed" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                out += schema_problems(props[k], v, f"{at}.{k}" if at else k)
    elif isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(f"{where}: at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(f"{where}: at most {schema['maxItems']} item(s)")
        if isinstance(schema.get("items"), dict):
            for i, v in enumerate(value):
                out += schema_problems(schema["items"], v, f"{where}[{i}]")
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(f"{where}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(f"{where}: longer than {schema['maxLength']}")
        if isinstance(schema.get("pattern"), str):
            try:
                if not re.search(schema["pattern"], value):
                    out.append(f"{where}: {value!r} does not match the Manager's pattern")
            except re.error:
                pass
    return out


def request_schema(body: Any) -> dict[str, Any]:
    return body["request"] if isinstance(body, dict) and isinstance(body.get("request"), dict) else {}
