"""Policy (W11): centralised and localised policies and policy groups in plain words, the offline path
explanation, and the activation preview.

Pure helpers; the tools are in tools/policy.py. Sources (20.18.3.1):
- GET /dataservice/template/policy/vsmart: centralised policies {policyId, policyName, policyDescription,
  policyType feature|cli, isPolicyActivated, policyVersion, lastUpdatedOn/By, policyDefinition: the assembly
  as a JSON string} (recorded).
- GET /dataservice/template/policy/vsmart/definition/{policyId}: {policyName, policyType, isPolicyActivated,
  policyDefinition: {assembly: [{definitionId, type, entries: [{siteLists, vpnLists, direction?}]}]}}
  (recorded).
- GET /dataservice/template/policy/vedge: localised policies {policyId, policyName, devicesAttached,
  mastersAttached, ...} (recorded, empty in the lab).
- GET /dataservice/v1/policy-group: policy groups (recorded, empty in the lab; W7).
- GET /dataservice/template/policy/definition/<type>: the definitions of one type without their sequences
  (recorded for approute, control and data); GET .../<type>/{id}: one definition with `sequences` (each
  {sequenceId, sequenceName, sequenceType, match: {entries: [{field, value | ref}]}, actions: [{type,
  parameter}], baseAction}) and `defaultAction` (Cisco's documented shape; not recorded yet).
- GET /dataservice/template/policy/list: every policy list (spec: "Get all policy lists"; not recorded), or
  /template/policy/list/<type> (recorded for site, vpn, app, sla): {listId, name, type, entries: [...]}.
- POST /dataservice/template/policy/vsmart/activate/{policyId} {"isEdited": false} and
  POST .../deactivate/{policyId} (no body in the spec; the activate operation's own example for deactivation
  is {}) -> {"id": "vsmart_policy_config-<id>"}, an action followed with /device/action/status/{id} (spec).
  Cisco: a centralised policy can only be activated while the controllers are in vManage mode (a device
  template attached to each controller); in CLI mode the Manager refuses it.
- GET /dataservice/template/policy/vsmart/connectivity/status: the Manager's own pre-activation check of its
  controllers ("Check VSmart Connectivity Status"; shape not recorded).
"""

from __future__ import annotations

import json
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.configuration import path
from cat_sdwan_mcp.dataplane import _num, sla_verdict
from cat_sdwan_mcp.inventory import iso

VSMART_PATH = "/dataservice/template/policy/vsmart"
VSMART_DEFINITION_PATH = "/dataservice/template/policy/vsmart/definition/{id}"
VEDGE_PATH = "/dataservice/template/policy/vedge"
VEDGE_DEFINITION_PATH = "/dataservice/template/policy/vedge/definition/{id}"
DEFINITION_PATH = "/dataservice/template/policy/definition/{type}/{id}"
LISTS_PATH = "/dataservice/template/policy/list"
LIST_TYPE_PATH = "/dataservice/template/policy/list/{type}"
ACTIVATE_PATH = "/dataservice/template/policy/vsmart/activate/{id}"
DEACTIVATE_PATH = "/dataservice/template/policy/vsmart/deactivate/{id}"
CONNECTIVITY_PATH = "/dataservice/template/policy/vsmart/connectivity/status"

# The list types read one by one when /template/policy/list (all lists) is not available.
LIST_TYPES = ("site", "vpn", "app", "sla", "color", "tloc", "prefix", "dataprefix", "class", "region")

# Assembly type -> the path segment of its definition API.
DEFINITION_TYPES = {
    "appRoute": "approute",
    "control": "control",
    "data": "data",
    "hubAndSpoke": "hubandspoke",
    "mesh": "mesh",
    "cflowd": "cflowd",
    "vpnMembershipGroup": "vpnmembershipgroup",
}
TYPE_WORDS = {
    "appRoute": "application-aware routing",
    "control": "control policy",
    "data": "data policy",
    "hubAndSpoke": "hub-and-spoke topology",
    "mesh": "mesh topology",
    "cflowd": "cflowd",
    "vpnMembershipGroup": "VPN membership",
}

FIELD_WORDS = {
    "appList": "application list",
    "dnsAppList": "DNS application list",
    "app": "application",
    "dscp": "DSCP",
    "plp": "packet loss priority",
    "protocol": "IP protocol",
    "sourcePort": "source port",
    "destinationPort": "destination port",
    "sourceIp": "source IP",
    "destinationIp": "destination IP",
    "sourceDataPrefixList": "source prefix list",
    "destinationDataPrefixList": "destination prefix list",
    "destinationRegion": "destination region",
    "trafficTo": "traffic to",
    "color": "colour",
    "colorList": "colour list",
    "siteList": "site list",
    "siteId": "site",
    "tlocList": "TLOC list",
    "tloc": "TLOC",
    "vpnList": "VPN list",
    "vpn": "VPN",
    "prefixList": "prefix list",
    "ompTag": "OMP tag",
    "origin": "origin protocol",
    "originator": "originator",
    "preference": "preference",
    "carrier": "carrier",
    "domainId": "domain id",
    "groupId": "group id",
    "packetLength": "packet length",
    "tcp": "TCP flags",
}

ACTION_WORDS = {
    "count": "count packets in",
    "log": "log",
    "cflowd": "export cflowd",
    "nat": "NAT (direct internet access)",
    "redirectDns": "redirect DNS",
    "tcpOptimization": "TCP optimisation",
    "lossProtect": "loss protection (FEC / packet duplication)",
    "lossProtectFec": "forward error correction",
    "lossProtectPktDup": "packet duplication",
    "appqoeOptimization": "AppQoE optimisation",
    "exportTo": "export to",
    "affinity": "affinity",
}


def parse_definition(raw: Any) -> dict[str, Any]:
    """The policy's definition as a dict (the list API carries it as a JSON string)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def assembly(policy: dict[str, Any]) -> list[dict[str, Any]]:
    body = parse_definition(policy.get("policyDefinition"))
    return [a for a in _as_list(body.get("assembly")) if isinstance(a, dict)]


def is_active(policy: dict[str, Any]) -> bool:
    v = policy.get("isPolicyActivated")
    return v is True or str(v).lower() == "true"


def rows(data: Any) -> list[dict[str, Any]]:
    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    return [r for r in _as_list(body) if isinstance(r, dict)]


# --- lists -----------------------------------------------------------------------------------------


def entry_values(lst: dict[str, Any]) -> list[str]:
    """A list's entries as text: '100', 'webex', 'loss 2% latency 150 ms jitter 50 ms', '10.0.0.1 mpls'."""
    out = []
    for e in _as_list(lst.get("entries")):
        if not isinstance(e, dict):
            continue
        if str(lst.get("type")) == "sla":
            out.append(sla_text(e))
        elif len(e) == 1:
            out.append(str(next(iter(e.values()))))
        else:
            out.append(" ".join(f"{k}={v}" for k, v in e.items() if v not in (None, "")))
    return out


def sla_text(e: dict[str, Any]) -> str:
    parts = []
    for key, label, unit in (
        ("loss", "loss", "%"),
        ("latency", "latency", " ms"),
        ("jitter", "jitter", " ms"),
    ):
        if e.get(key) not in (None, ""):
            parts.append(f"{label} <= {e[key]}{unit}")
    return ", ".join(parts) or "no limits"


def sla_limits(lst: dict[str, Any]) -> dict[str, Any]:
    """{name, loss_max, latency_max, jitter_max} of an SLA list, as catsdwan_list_sla_classes gives them."""
    e = next((x for x in _as_list(lst.get("entries")) if isinstance(x, dict)), {})
    return {
        "name": lst.get("name"),
        "loss_max": _num(e.get("loss")),
        "latency_max": _num(e.get("latency")),
        "jitter_max": _num(e.get("jitter")),
    }


def limits_text(limits: dict[str, Any]) -> str:
    parts = []
    for key, label, unit in (
        ("loss_max", "loss", "%"),
        ("latency_max", "latency", " ms"),
        ("jitter_max", "jitter", " ms"),
    ):
        if isinstance(limits.get(key), int | float):
            parts.append(f"{label} <= {limits[key]:g}{unit}")
    return ", ".join(parts) or "no limits"


def list_text(lst: dict[str, Any] | None, ref: Any = None) -> str:
    if lst is None:
        return f"list {ref} (not found)"
    values = entry_values(lst)
    shown = ", ".join(values[:12]) + (f", ... ({len(values)} entries)" if len(values) > 12 else "")
    return f"{lst.get('type')} list {lst.get('name')} ({shown or 'empty'})"


def by_id(lists: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(x.get("listId")): x for x in lists if x.get("listId")}


def _refs(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, "")]
    if isinstance(v, str) and v:
        return [x.strip() for x in v.split(" ") if x.strip()] if " " in v else [v]
    return []


# --- sequences in words ----------------------------------------------------------------------------


def _value(e: dict[str, Any], lists: dict[str, dict[str, Any]]) -> str:
    if e.get("ref") not in (None, ""):
        return " + ".join(list_text(lists.get(r), r) for r in _refs(e["ref"]))
    v = e.get("value")
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return " ".join(f"{k} {x}" for k, x in v.items())
    return str(v)


def match_words(match: Any, lists: dict[str, dict[str, Any]]) -> list[str]:
    entries = match.get("entries") if isinstance(match, dict) else match
    out = []
    for e in _as_list(entries):
        if isinstance(e, dict) and e.get("field"):
            field = str(e["field"])
            out.append(f"{FIELD_WORDS.get(field, field)} {_value(e, lists)}")
    return out


def _params(p: Any) -> list[dict[str, Any]]:
    return [x for x in _as_list(p) if isinstance(x, dict)]


def sla_action(actions: Any, lists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """The app-route steering of a sequence: {sla_class, sla, preferred_colours, preferred_colour_group,
    strict, fallback_to_best_path, backup_colours}."""
    out: dict[str, Any] = {}
    for a in _as_list(actions):
        if not isinstance(a, dict):
            continue
        kind = str(a.get("type"))
        if kind == "slaClass":
            for p in _params(a.get("parameter")):
                field = str(p.get("field"))
                if field == "name":
                    ref = next(iter(_refs(p.get("ref"))), None)
                    lst = lists.get(str(ref)) if ref else None
                    out["sla_class"] = lst.get("name") if lst else (ref or p.get("value"))
                    if lst:
                        out["sla"] = sla_limits(lst)
                elif field == "preferredColor":
                    out["preferred_colours"] = str(p.get("value") or "").split()
                elif field == "preferredColorGroup":
                    ref = next(iter(_refs(p.get("ref"))), None)
                    lst = lists.get(str(ref)) if ref else None
                    out["preferred_colour_group"] = list_text(lst, ref)
                elif field == "strict":
                    out["strict"] = True
                elif field == "fallbackToBestPath":
                    out["fallback_to_best_path"] = True
        elif kind == "backupSlaPreferredColor":
            out["backup_colours"] = str(a.get("parameter") or "").split()
    return out or None


def _set_words(params: Any, lists: dict[str, dict[str, Any]]) -> list[str]:
    out = []
    for p in _params(params):
        field = str(p.get("field"))
        out.append(f"set {FIELD_WORDS.get(field, field)} {_value(p, lists)}")
    return out


def action_words(seq: dict[str, Any], lists: dict[str, dict[str, Any]]) -> list[str]:
    out = []
    base = seq.get("baseAction")
    if base:
        out.append(str(base))
    for a in _as_list(seq.get("actions")):
        if not isinstance(a, dict):
            continue
        kind = str(a.get("type"))
        if kind == "slaClass":
            sla = sla_action([a], lists) or {}
            words = f"SLA class {sla.get('sla_class')}"
            if sla.get("sla"):
                limits = sla["sla"]
                words += f" ({limits_text(limits)})"
            if sla.get("preferred_colours"):
                words += f", preferring {' '.join(sla['preferred_colours'])}"
            if sla.get("preferred_colour_group"):
                words += f", preferring {sla['preferred_colour_group']}"
            if sla.get("strict"):
                words += ", strict (dropped when no tunnel meets it)"
            if sla.get("fallback_to_best_path"):
                words += ", else the best tunnel"
            out.append(words)
        elif kind == "backupSlaPreferredColor":
            out.append(f"when no tunnel meets the SLA: {a.get('parameter')}")
        elif kind == "set":
            out += _set_words(a.get("parameter"), lists)
        elif kind in ACTION_WORDS:
            param = a.get("parameter")
            out.append(ACTION_WORDS[kind] + (f" {_value({'value': param}, lists)}" if param else ""))
        else:
            param = a.get("parameter")
            out.append(
                f"{kind}{' ' + _value({'value': param}, lists) if param not in (None, '', []) else ''}"
            )
    return out


def sequence_row(seq: dict[str, Any], lists: dict[str, dict[str, Any]]) -> dict[str, Any]:
    match = match_words(seq.get("match"), lists)
    actions = action_words(seq, lists)
    words = f"if {' and '.join(match) if match else 'any traffic'} -> {'; '.join(actions) or 'no action'}"
    row: dict[str, Any] = {
        "sequence": seq.get("sequenceId"),
        "name": seq.get("sequenceName"),
        "type": seq.get("sequenceType"),
        "ip": seq.get("sequenceIpType"),
        "match": match or ["any traffic"],
        "action": actions,
        "in_words": words,
    }
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def ordered(seqs: Any) -> list[dict[str, Any]]:
    out = [s for s in _as_list(seqs) if isinstance(s, dict)]
    return sorted(out, key=lambda s: _num(s.get("sequenceId")) or 0)


def default_action_words(d: dict[str, Any], lists: dict[str, dict[str, Any]]) -> str | None:
    da = d.get("defaultAction")
    if not isinstance(da, dict):
        return None
    kind = str(da.get("type") or "")
    if kind == "slaClass" and da.get("ref"):
        lst = lists.get(str(da["ref"]))
        return f"SLA class {lst.get('name') if lst else da['ref']}"
    return kind or None


def definition_view(d: dict[str, Any], lists: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """One definition with its sequences (or its topology) in plain words."""
    kind = str(d.get("type") or "")
    out: dict[str, Any] = {
        "name": d.get("name"),
        "type": TYPE_WORDS.get(kind, kind),
        "description": d.get("description"),
    }
    if seqs := ordered(d.get("sequences")):
        out["sequences"] = [sequence_row(s, lists) for s in seqs]
    if (default := default_action_words(d, lists)) is not None:
        out["default_action"] = default
    raw = d.get("definition")
    defn: dict[str, Any] = raw if isinstance(raw, dict) else {}
    if kind == "hubAndSpoke":
        out["topology"] = hub_spoke_words(defn, lists)
    elif kind == "mesh":
        regions = [r for r in _as_list(defn.get("regions")) if isinstance(r, dict)]
        out["topology"] = [
            f"mesh region {r.get('name')}: "
            + "; ".join(list_text(lists.get(x), x) for x in _refs(r.get("siteLists")))
            for r in regions
        ] or None
        if defn.get("vpnList"):
            out["vpn"] = list_text(lists.get(str(defn["vpnList"])), defn["vpnList"])
    elif kind == "vpnMembershipGroup":
        out["memberships"] = [
            f"{list_text(lists.get(str(s.get('siteList'))), s.get('siteList'))}: "
            + ", ".join(list_text(lists.get(v), v) for v in _refs(s.get("vpnList")))
            for s in _as_list(defn.get("sites"))
            if isinstance(s, dict)
        ] or None
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def hub_spoke_words(defn: dict[str, Any], lists: dict[str, dict[str, Any]]) -> list[str]:
    out = []
    vpn = list_text(lists.get(str(defn.get("vpnList"))), defn.get("vpnList")) if defn.get("vpnList") else None
    for sub in _as_list(defn.get("subDefinitions")):
        if not isinstance(sub, dict):
            continue
        for spoke in _as_list(sub.get("spokes")):
            if not isinstance(spoke, dict):
                continue
            hubs = [
                list_text(lists.get(str(h.get("siteList"))), h.get("siteList"))
                for h in _as_list(spoke.get("hubs"))
                if isinstance(h, dict)
            ]
            line = (
                f"{sub.get('name') or 'hub-and-spoke'}: spokes "
                f"{list_text(lists.get(str(spoke.get('siteList'))), spoke.get('siteList'))} reach each other "
                f"only through hubs {', '.join(hubs) or '?'}"
            )
            out.append(line + (f" in {vpn}" if vpn else ""))
    return out


# --- the assembly ----------------------------------------------------------------------------------


def assembly_view(
    parts: list[dict[str, Any]], defs: dict[str, dict[str, Any]], lists: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Each part of a centralised policy: the definition it applies and where (sites, VPNs, direction)."""
    out = []
    for a in parts:
        d = defs.get(str(a.get("definitionId")), {})
        kind = str(a.get("type") or d.get("type") or "")
        for e in _as_list(a.get("entries")) or [{}]:
            if not isinstance(e, dict):
                continue
            row = {
                "definition": d.get("name") or a.get("definitionId"),
                "type": TYPE_WORDS.get(kind, kind),
                "sites": [list_text(lists.get(x), x) for x in _refs(e.get("siteLists"))]
                or ("every site" if kind in ("appRoute", "data", "control") else None),
                "vpns": [list_text(lists.get(x), x) for x in _refs(e.get("vpnLists"))] or None,
                "direction": e.get("direction"),
                "regions": e.get("regionIds") or e.get("regionLists"),
            }
            out.append({k: v for k, v in row.items() if v not in (None, "", [])})
    return out


def site_ids(parts: list[dict[str, Any]], lists: dict[str, dict[str, Any]]) -> set[str] | None:
    """Every site id a centralised policy's parts name; None when one part applies everywhere."""
    out: set[str] = set()
    for a in parts:
        for e in _as_list(a.get("entries")) or [{}]:
            refs = _refs(e.get("siteLists")) if isinstance(e, dict) else []
            if not refs:
                return None
            for r in refs:
                out |= set(entry_values(lists.get(r) or {}))
    return out


def _expand(site: str) -> set[str]:
    """'100' -> {'100'}; '200-210' -> every id in the range (site lists allow ranges)."""
    if "-" in site:
        lo, _, hi = site.partition("-")
        if lo.isdigit() and hi.isdigit() and int(hi) - int(lo) <= 10000:
            return {str(i) for i in range(int(lo), int(hi) + 1)}
    return {site}


def in_site_list(site: str, lst: dict[str, Any] | None) -> bool:
    return any(site in _expand(v) for v in entry_values(lst or {}))


def entry_applies(
    entry: dict[str, Any], site: str, vpn: int | None, lists: dict[str, dict[str, Any]]
) -> tuple[bool, str]:
    """(applies, why) for one assembly entry and a source site and VPN."""
    sites = _refs(entry.get("siteLists"))
    if sites and not any(in_site_list(site, lists.get(s)) for s in sites):
        return False, f"site {site} is not in " + ", ".join(list_text(lists.get(s), s) for s in sites)
    vpns = _refs(entry.get("vpnLists"))
    if vpns and vpn is not None and not any(str(vpn) in entry_values(lists.get(v) or {}) for v in vpns):
        return False, f"VPN {vpn} is not in " + ", ".join(list_text(lists.get(v), v) for v in vpns)
    where = [list_text(lists.get(s), s) for s in sites] or ["every site"]
    what = [list_text(lists.get(v), v) for v in vpns] or ["every VPN"]
    return True, f"applies to {', '.join(where)} in {', '.join(what)}"


# --- the offline path walk -------------------------------------------------------------------------

_APP_FIELDS = ("appList", "dnsAppList", "app")


def sequence_matches(
    seq: dict[str, Any], app: str | None, dscp: int | None, lists: dict[str, dict[str, Any]]
) -> tuple[str, str]:
    """('yes' | 'no' | 'maybe', why) for one sequence and the traffic: the application (by name, or the
    name of an application list) and the DSCP. Conditions this tool can't evaluate (prefixes, ports) make
    'maybe'."""
    entries = [e for e in _as_list((seq.get("match") or {}).get("entries")) if isinstance(e, dict)]
    if not entries:
        return "yes", "it matches any traffic"
    unknown = []
    why = []
    for e in entries:
        field = str(e.get("field"))
        if field in _APP_FIELDS:
            names = (
                [lists.get(r, {}) for r in _refs(e.get("ref"))]
                if e.get("ref")
                else [{"name": e.get("value"), "entries": [{"app": x} for x in str(e.get("value")).split()]}]
            )
            apps = {str(v).lower() for lst in names for v in entry_values(lst)}
            list_names = {str(lst.get("name", "")).lower() for lst in names}
            if app is None:
                unknown.append("application")
            elif app.lower() in apps or app.lower() in list_names:
                why.append(f"{app} is in {_value(e, lists)}")
            else:
                return "no", f"{app} is not in {_value(e, lists)}"
        elif field == "dscp":
            want = {x for x in str(e.get("value", "")).split()}
            if dscp is None:
                unknown.append("DSCP")
            elif str(dscp) in want:
                why.append(f"DSCP {dscp} matches")
            else:
                return "no", f"DSCP {dscp} is not {' '.join(sorted(want))}"
        else:
            unknown.append(FIELD_WORDS.get(field, field))
    if unknown:
        return "maybe", "depends on " + ", ".join(dict.fromkeys(unknown)) + (
            f" ({'; '.join(why)})" if why else ""
        )
    return "yes", "; ".join(why)


def tunnel_choice(
    steering: dict[str, Any] | None, tunnels: list[dict[str, Any]], sla: dict[str, Any] | None
) -> dict[str, Any]:
    """Which tunnels the traffic takes now, from the sequence's SLA action and the tunnels' current
    loss/latency/jitter (aggregated app-route statistics rows). Follows Cisco's app-route logic: the
    SLA-meeting tunnels on the preferred colours, else any SLA-meeting tunnel, else the backup colour, else
    the best tunnel (fallback), else dropped (strict), else every tunnel (load-balanced)."""
    up = [t for t in tunnels if str(t.get("state", "up")).lower() == "up"]
    for t in up:
        if sla:
            t["sla"] = sla_verdict(t, sla)
    if not up:
        return {
            "verdict": "no tunnel is up between the sites: the traffic has no overlay path",
            "tunnels": [],
        }
    if steering is None or sla is None:
        return {
            "verdict": "no SLA steering: the traffic is load-balanced across every up tunnel (ECMP)",
            "tunnels": up,
        }
    meeting = [t for t in up if t.get("sla") == "meets"]
    preferred = [c.lower() for c in steering.get("preferred_colours") or []]
    backup = [c.lower() for c in steering.get("backup_colours") or []]
    colours = sorted({str(t.get("local_colour")) for t in meeting})
    if meeting:
        if preferred:
            pref = [t for t in meeting if str(t.get("local_colour", "")).lower() in preferred]
            if pref:
                return {
                    "verdict": f"the preferred colour {' '.join(preferred)} meets {sla['name']}: "
                    "traffic takes " + _names(pref),
                    "tunnels": pref,
                    "colours_meeting_sla": colours,
                }
            return {
                "verdict": f"the preferred colour {' '.join(preferred)} misses {sla['name']}; "
                f"{', '.join(colours)} meets it, so traffic moves there: " + _names(meeting),
                "tunnels": meeting,
                "colours_meeting_sla": colours,
            }
        return {
            "verdict": f"{', '.join(colours)} meets {sla['name']}: traffic is shared across "
            + _names(meeting),
            "tunnels": meeting,
            "colours_meeting_sla": colours,
        }
    if backup:
        bk = [t for t in up if str(t.get("local_colour", "")).lower() in backup]
        if bk:
            return {
                "verdict": f"no tunnel meets {sla['name']}: traffic falls back to the backup colour "
                f"{' '.join(backup)}: " + _names(bk),
                "tunnels": bk,
                "colours_meeting_sla": [],
            }
    if steering.get("fallback_to_best_path"):
        best = sorted(up, key=lambda t: (t.get("loss_percent") or 0, t.get("latency_ms") or 0))[:1]
        return {
            "verdict": f"no tunnel meets {sla['name']}: traffic falls back to the best tunnel "
            + _names(best),
            "tunnels": best,
            "colours_meeting_sla": [],
        }
    if steering.get("strict"):
        return {
            "verdict": f"no tunnel meets {sla['name']} and the class is strict: the traffic is DROPPED",
            "tunnels": [],
            "colours_meeting_sla": [],
        }
    return {
        "verdict": f"no tunnel meets {sla['name']}: traffic is load-balanced across every up tunnel",
        "tunnels": up,
        "colours_meeting_sla": [],
    }


def _names(rows: list[dict[str, Any]]) -> str:
    return ", ".join(
        f"{t.get('host') or t.get('system_ip')} {t.get('local_colour')} -> "
        f"{t.get('remote') or t.get('remote_system_ip')} {t.get('remote_colour')}"
        for t in rows
    )


# --- rows ------------------------------------------------------------------------------------------


def centralised_row(p: dict[str, Any], defs: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    parts = assembly(p)
    kinds = [TYPE_WORDS.get(str(a.get("type")), str(a.get("type"))) for a in parts]
    names = [str((defs or {}).get(str(a.get("definitionId")), {}).get("name") or "") for a in parts]
    row = {
        "name": p.get("policyName"),
        "kind": "centralised",
        "type": {"feature": "policy builder", "cli": "CLI"}.get(
            str(p.get("policyType")), p.get("policyType")
        ),
        "activated": is_active(p),
        "parts": ", ".join(f"{n} ({k})" if n else k for n, k in zip(names, kinds, strict=True)) or None,
        "description": p.get("policyDescription"),
        "updated": iso(p.get("lastUpdatedOn")),
        "updated_by": p.get("lastUpdatedBy"),
        "id": p.get("policyId"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def localised_row(p: dict[str, Any]) -> dict[str, Any]:
    row = {
        "name": p.get("policyName"),
        "kind": "localised",
        "type": {"feature": "policy builder", "cli": "CLI"}.get(
            str(p.get("policyType")), p.get("policyType")
        ),
        "devices": p.get("devicesAttached"),
        "device_templates": p.get("mastersAttached"),
        "description": p.get("policyDescription"),
        "updated": iso(p.get("lastUpdatedOn")),
        "updated_by": p.get("lastUpdatedBy"),
        "id": p.get("policyId"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def group_policy_row(g: dict[str, Any]) -> dict[str, Any]:
    profiles = [p for p in _as_list(g.get("profiles")) if isinstance(p, dict)]
    row = {
        "name": g.get("name"),
        "kind": "policy group",
        "type": g.get("solution"),
        "parts": ", ".join(f"{p.get('name')} ({p.get('type')})" for p in profiles) or None,
        "devices": g.get("numberOfDevices"),
        "description": g.get("description"),
        "updated": iso(g.get("lastUpdatedOn")),
        "updated_by": g.get("lastUpdatedBy"),
        "id": g.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def definition_path(kind: str, def_id: str) -> str:
    return path(DEFINITION_PATH, type=DEFINITION_TYPES.get(kind, kind.lower()), id=def_id)


def controller_mode_blockers(controllers: list[dict[str, Any]]) -> list[str]:
    """Controllers the Manager can't push a centralised policy to: unreachable, or in CLI mode (Cisco: the
    controllers must be in vManage mode, i.e. have a device template attached)."""
    out = []
    for c in controllers:
        name = c.get("host") or c.get("system_ip") or c.get("chassis")
        if str(c.get("reachability", "")).lower() != "reachable":
            out.append(
                f"controller {name} is {c.get('reachability') or 'unreachable'}: the policy can't reach it"
            )
        if c.get("config_mode") == "cli":
            out.append(
                f"controller {name} is in CLI mode: the Manager activates a centralised policy only on "
                "controllers in vManage mode, i.e. with a device template attached to each controller "
                "(Configuration > Templates; catsdwan_attach_device_template). Attach a controller template "
                "first, or keep the policy in CLI on the controller"
            )
    return out


def connectivity_rows(body: Any) -> list[dict[str, Any]]:
    """The Manager's own pre-activation check (shape not recorded): per controller what it reports."""
    out = []
    for r in rows(body):
        row = {
            "controller": r.get("host-name") or r.get("deviceIP") or r.get("deviceId") or r.get("system-ip"),
            "mode": r.get("operationMode") or r.get("configOperationMode") or r.get("mode"),
            "online": r.get("isOnline") if "isOnline" in r else r.get("reachability"),
            "status": r.get("status") or r.get("message"),
        }
        out.append({k: v for k, v in row.items() if v not in (None, "")})
    return out
