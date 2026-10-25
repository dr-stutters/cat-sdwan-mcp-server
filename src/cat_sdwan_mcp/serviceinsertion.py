"""W50 service insertion: firewall (and other) services in a service VPN, the traffic-policy rules that steer
traffic into them, and what an edge advertises. Pure helpers; the tools are in tools/serviceinsertion.py.

A service chain on Catalyst SD-WAN has two halves: (1) an edge in the service VPN advertises a service (FW,
IDS, IDP, netsvc1-4, appqoe) at the address of the firewall's interface, optionally tracked so it is
withdrawn when the firewall stops answering; (2) a data policy (20.12+: a traffic-policy parcel in a policy
group's application-priority profile; template world: a centralised data policy) sets `service FW` (or a
service chain SC1-SC16) on the matching traffic. Sources:
- Recorded (20.18.3.1, read only): GET /v1/feature-profile/sdwan/service = [] and
  /v1/service-insertion/service-chain-mapping = [] on the lab (no service profile; VPN 10 is CLI-profile
  configuration); GET /device/omp/services?deviceId=<hub1> (OMP services: {vpn-id, service: "VPN", originator,
  from-peer | to-peer, label, path-id, status, address-family}); GET
  /v1/feature-profile/sdwan/service/lan/vpn/schema?schemaType=post (the LAN VPN parcel's JSON Schema; the
  tool's answer is larger than the capture tool shows, so the `service` subtree below is from Cisco's
  published parcel model and checked against the Manager's schema in every preview).
- Not recorded (no instance on the lab; Cisco's published parcel models): the LAN VPN parcel's
  data.service = [{serviceType: {global FW|IDS|IDP|netsvc1-4|TE|appqoe}, ipv4Addresses: {global [ip, ...]},
  tracking: {global|default bool}}]; the application-priority profile create (POST
  /v1/feature-profile/sdwan/application-priority {name, description} -> {id}) and the traffic-policy parcel
  (POST .../application-priority/{id}/traffic-policy: data {dataDefaultAction, target: {vpn: [..],
  direction: service|tunnel|all}, sequences: [{sequenceId, sequenceName, baseAction, sequenceIpType, match:
  {entries}, actions: [{set: [{service: {type, vpn, local, restrict}} | {serviceChain: {serviceChainType,
  vpn, local, restrict}}]}]}]}).
- Recorded (20.18.3.1, the W50 live run 2026-10-24): the traffic-policy POST schema
  (GET .../application-priority/traffic-policy/schema?schemaType=post): a match entry has exactly one key
  (`sourceIp` / `destinationIp` {global "a.b.c.d/n"}, `sourceDataPrefixList` / `destinationDataPrefixList`
  {refId}, `protocol`, `destinationPort`, ...); `service` requires `type` and `vpn`; `serviceChain` names
  its chain in `type` and needs `vpn` unless `local`. The IOS XE CLI form of a firewall service is
  `sdwan` / ` service firewall vrf 10` / `  ipv4 address <ip>` (the Manager refuses `service FW vrf 10`:
  `"FW" is an invalid`); hub1 then advertises FW in VPN 10 into OMP. Used when the VPN is CLI-profile
  configuration.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.edgefirewall import g, leaf_value

SERVICE_PROFILES_PATH = "/dataservice/v1/feature-profile/sdwan/service"
LAN_VPN_LIST_PATH = SERVICE_PROFILES_PATH + "/{profile}/lan/vpn"
LAN_VPN_PATH = LAN_VPN_LIST_PATH + "/{parcel}"
LAN_VPN_SCHEMA_PATH = SERVICE_PROFILES_PATH + "/lan/vpn/schema"
APP_PRIORITY_PATH = "/dataservice/v1/feature-profile/sdwan/application-priority"
APP_PRIORITY_PROFILE_PATH = APP_PRIORITY_PATH + "/{id}"
TRAFFIC_POLICY_LIST_PATH = APP_PRIORITY_PROFILE_PATH + "/traffic-policy"
TRAFFIC_POLICY_PATH = TRAFFIC_POLICY_LIST_PATH + "/{parcel}"
TRAFFIC_POLICY_SCHEMA_PATH = APP_PRIORITY_PATH + "/traffic-policy/schema"
CHAIN_MAPPING_PATH = "/dataservice/v1/service-insertion/service-chain-mapping"
OMP_SERVICES_PATH = "/dataservice/device/omp/services"

SERVICE_TYPES = ("FW", "IDS", "IDP", "netsvc1", "netsvc2", "netsvc3", "netsvc4", "appqoe")
CHAINS = tuple(f"SC{i}" for i in range(1, 17))
DIRECTIONS = ("service", "tunnel", "all")
# A service VPN: 1-511 and 513-65527 (the LAN VPN parcel's vpnId range); 0 and 512 are transport/management.
_RESERVED_VPNS = (0, 512)


def vpn_problem(vpn: int) -> str | None:
    if vpn in _RESERVED_VPNS or not (1 <= vpn <= 65527):
        return f"VPN {vpn} is not a service VPN (1-511, 513-65527)"
    return None


def address_problems(addresses: list[str]) -> list[str]:
    out = []
    if not addresses:
        out.append("give the firewall's address in the service VPN (its interface facing the edge)")
    if len(set(addresses)) != len(addresses):
        out.append("an address is given twice")
    for a in addresses:
        try:
            ipaddress.IPv4Address(a)
        except ValueError:
            out.append(f"{a!r} is not an IPv4 address")
    if len(addresses) > 4:
        out.append(f"a service takes at most 4 addresses ({len(addresses)} given)")
    return out


# --- LAN VPN parcels (configuration groups) --------------------------------------------------------


def vpn_parcels(body: Any) -> list[dict[str, Any]]:
    """[{id, name, vpn, vpn_name, data, raw}] from GET .../service/{id}/lan/vpn ({data: [...]} or a list)."""
    rows = body.get("data") if isinstance(body, dict) and "data" in body else body
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        payload: dict[str, Any] = r["payload"] if isinstance(r.get("payload"), dict) else {}
        data: dict[str, Any] = payload["data"] if isinstance(payload.get("data"), dict) else {}
        pid = r.get("parcelId") or r.get("id")
        if not pid:
            continue
        vpn = leaf_value(data.get("vpnId"))
        out.append(
            {
                "id": str(pid),
                "name": payload.get("name"),
                "description": payload.get("description"),
                "vpn": vpn,
                "vpn_name": leaf_value(data.get("name")),
                "data": data,
                "raw": r,
            }
        )
    return out


def service_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """A LAN VPN parcel's services in plain words: [{type, addresses, tracking}]. A {{variable}} stays as
    written (filled per device)."""
    out = []
    for s in _as_list(data.get("service")):
        if not isinstance(s, dict):
            continue
        addrs = leaf_value(s.get("ipv4Addresses"))
        track = s.get("tracking")
        tracking = leaf_value(track)
        if isinstance(track, dict) and track.get("optionType") == "default" and tracking is None:
            tracking = True
        out.append(
            {
                "type": leaf_value(s.get("serviceType")),
                "addresses": addrs if isinstance(addrs, list) else [addrs] if addrs else [],
                "tracking": tracking,
            }
        )
    return out


def service_entry(stype: str, addresses: list[str], tracking: bool) -> dict[str, Any]:
    return {"serviceType": g(stype), "ipv4Addresses": g(list(addresses)), "tracking": g(tracking)}


def with_service(data: dict[str, Any], stype: str, entry: dict[str, Any] | None) -> dict[str, Any]:
    """The LAN VPN parcel's data with the `stype` service replaced (None removes it); other services and
    every other field kept."""
    others = [
        s
        for s in _as_list(data.get("service"))
        if not (isinstance(s, dict) and str(leaf_value(s.get("serviceType"))) == stype)
    ]
    out = {k: v for k, v in data.items() if k != "service"}
    services = others + ([entry] if entry else [])
    if services:
        out["service"] = services
    return out


# --- the CLI form (CLI-profile configuration groups) ------------------------------------------------

# The parcel's service type -> the IOS XE keyword under `sdwan`. Only `firewall` is proven (17.18, the Manager
# refuses `FW`); the others are written as the parcel names them until an edge shows otherwise.
CLI_KEYWORDS = {"FW": "firewall"}
# Read generously: the IOS XE keywords and the parcel's names, both mapped back to the parcel's type.
_CLI_TYPES = {
    "firewall": "FW",
    "fw": "FW",
    "intrusion-detection": "IDS",
    "ids": "IDS",
    "intrusion-prevention": "IDP",
    "intrusion-detection-prevention": "IDP",
    "idp": "IDP",
    "appqoe": "appqoe",
    **{f"netsvc{i}": f"netsvc{i}" for i in range(1, 5)},
}
_CLI_SERVICE = re.compile(
    r"^\s*service\s+(?P<type>firewall|intrusion-detection-prevention|intrusion-detection|"
    r"intrusion-prevention|FW|IDS|IDP|netsvc[1-4]|appqoe)\s+(?:vrf|vpn)\s+(?P<vpn>\d+)\b",
    re.IGNORECASE,
)
_CLI_ADDRESS = re.compile(r"^\s*(?:ipv4\s+)?address\s+(?P<addrs>[\d.\s]+?)\s*$")
_CLI_TRACK_OFF = re.compile(r"^\s*no\s+track-enable\b")


def cli_services(text: str) -> list[dict[str, Any]]:
    """Services in a CLI-profile text: [{type, vpn, addresses, tracking}], `type` as the parcel names it (FW
    for IOS XE `sdwan` / `service firewall vrf 10` / `ipv4 address ...`; the parcel-style `service FW vrf
    10` and the vEdge-style `service FW address ...` are matched too when they name the VPN). Unrecognised
    lines are ignored."""
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    indent = 0
    for line in text.splitlines():
        m = _CLI_SERVICE.match(line)
        if m:
            stype = _CLI_TYPES.get(m.group("type").lower(), m.group("type"))
            cur = {"type": stype, "vpn": int(m.group("vpn")), "addresses": [], "tracking": True}
            indent = len(line) - len(line.lstrip())
            out.append(cur)
            rest = line[m.end() :]
            a = re.search(r"address\s+([\d.\s]+)$", rest)
            if a:
                cur["addresses"] = a.group(1).split()
            continue
        if cur is None:
            continue
        stripped = line.strip()
        if not stripped or stripped == "!":
            continue
        if len(line) - len(line.lstrip()) <= indent:
            cur = None
            continue
        a2 = _CLI_ADDRESS.match(line)
        if a2:
            cur["addresses"] += a2.group("addrs").split()
        elif _CLI_TRACK_OFF.match(line):
            cur["tracking"] = False
    return out


def cli_lines(stype: str, vpn: int, addresses: list[str], tracking: bool) -> list[str]:
    """The IOS XE lines for a service (for a CLI-profile group). `service firewall vrf <n>` is proven on
    17.18; for the other types check the edge's running config after the deploy."""
    keyword = CLI_KEYWORDS.get(stype, stype)
    lines = ["sdwan", f" service {keyword} vrf {vpn}", f"  ipv4 address {' '.join(addresses)}"]
    if not tracking:
        lines.append("  no track-enable")
    return lines


# --- OMP services on an edge -----------------------------------------------------------------------


def omp_service_rows(rows: list[dict[str, Any]], vpn: int | None = None) -> list[dict[str, Any]]:
    """GET /device/omp/services rows in plain words, optionally for one VPN: [{vpn, service, originator,
    direction (sent | received), peer, status, label}]."""
    out = []
    for r in rows:
        if vpn is not None and str(r.get("vpn-id")) != str(vpn):
            continue
        sent = bool(r.get("to-peer"))
        out.append(
            {
                "vpn": r.get("vpn-id"),
                "service": r.get("service"),
                "originator": r.get("originator"),
                "direction": "sent"
                if sent
                else "received"
                if r.get("from-peer") not in (None, "0.0.0.0")
                else "local",
                "peer": r.get("to-peer") or r.get("from-peer"),
                "status": r.get("status"),
                "label": r.get("label"),
            }
        )
    return out


# --- traffic policies (policy groups) --------------------------------------------------------------


def _prefix_match(side: str, lists: list[str], prefixes: list[str]) -> list[dict[str, Any]]:
    """Match entries for one side, one key each (20.18 schema): `<side>DataPrefixList` {refId} for a
    data-prefix list, `<side>Ip` for a literal prefix."""
    out: list[dict[str, Any]] = []
    for pid in lists:
        out.append({f"{side}DataPrefixList": {"refId": g(pid)}})
    for p in prefixes:
        out.append({f"{side}Ip": g(p)})
    return out


def steering_sequence(
    seq_id: int, rule: dict[str, Any], refs: dict[str, str], default_vpn: int | None = None
) -> dict[str, Any]:
    """One sequence. The service's VPN is `service_vpn`, else `default_vpn` (the policy's one target VPN):
    20.18 requires it on `service`, and on `serviceChain` unless the chain is local."""
    entries = _prefix_match(
        "source", [refs[n] for n in rule.get("source_lists") or []], rule.get("source_prefixes") or []
    )
    entries += _prefix_match(
        "destination",
        [refs[n] for n in rule.get("destination_lists") or []],
        rule.get("destination_prefixes") or [],
    )
    if rule.get("protocols"):
        entries.append({"protocol": g([str(p) for p in rule["protocols"]])})
    if rule.get("destination_ports"):
        entries.append({"destinationPort": g([str(p) for p in rule["destination_ports"]])})
    target: dict[str, Any] = {"local": g(bool(rule.get("local"))), "restrict": g(bool(rule.get("restrict")))}
    svc_vpn = rule.get("service_vpn") if rule.get("service_vpn") is not None else default_vpn
    if svc_vpn is not None:
        target["vpn"] = g(int(svc_vpn))
    if rule.get("chain"):
        action = {"serviceChain": {"type": g(rule["chain"]), **target}}
    else:
        action = {"service": {"type": g(rule.get("service") or "FW"), **target}}
    return {
        "sequenceId": g(seq_id),
        "sequenceName": g(str(rule["name"])),
        "baseAction": g("accept"),
        "sequenceIpType": g("ipv4"),
        "match": {"entries": entries},
        "actions": [{"set": [action]}],
    }


def traffic_policy_body(
    name: str,
    description: str,
    vpns: list[int],
    direction: str,
    default_action: str,
    rules: list[dict[str, Any]],
    refs: dict[str, str],
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """`targets`: the LAN VPN parcel names the controller matches (#118; servicevpns.resolve_vpns); the VPN
    ids are only the fallback when none is given. A service's own `vpn` stays the VPN id."""
    default_vpn = vpns[0] if len(vpns) == 1 else None
    return {
        "name": name,
        "description": description,
        "data": {
            "dataDefaultAction": g(default_action),
            "target": {
                "vpn": g(list(targets) if targets else [str(v) for v in vpns]),
                "direction": g(direction),
            },
            "sequences": [steering_sequence(i, r, refs, default_vpn) for i, r in enumerate(rules, start=1)],
        },
    }


def _ref_or_value(v: Any, names: dict[str, str]) -> str | None:
    if isinstance(v, dict) and "refId" in v:
        rid = str(leaf_value(v["refId"]))
        return f"list {names.get(rid, rid)}"
    val = leaf_value(v)
    return None if val is None else str(val)


def _match_words(entries: list[Any], names: dict[str, str]) -> list[str]:
    words = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        for k, v in e.items():
            if k in ("sourceIp", "destinationIp", "sourceDataPrefixList", "destinationDataPrefixList"):
                side = "from" if k.startswith("source") else "to"
                w = _ref_or_value(v, names)
                if w:
                    words.append(f"{side} {w}")
            elif k in ("sourceDataPrefix", "destinationDataPrefix") and isinstance(v, dict):
                # The pre-20.18 nested form, still read so older parcels show in plain words.
                side = "from" if k.startswith("source") else "to"
                for sub in v.values():
                    w = _ref_or_value(sub, names)
                    if w:
                        words.append(f"{side} {w}")
            else:
                val = leaf_value(v)
                if isinstance(v, dict) and "refId" in v:
                    words.append(f"{k} {_ref_or_value(v, names)}")
                else:
                    words.append(f"{k} {', '.join(map(str, val)) if isinstance(val, list) else val}")
    return words


def steering_rows(data: dict[str, Any], names: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """The sequences of a traffic policy that send traffic to a service or a service chain, in plain words:
    [{sequence, name, match, to, service | chain, vpn, local, restrict, fallback}]."""
    names = names or {}
    out = []
    for s in _as_list(data.get("sequences")):
        if not isinstance(s, dict):
            continue
        match: dict[str, Any] = s["match"] if isinstance(s.get("match"), dict) else {}
        for a in _as_list(s.get("actions")):
            if not isinstance(a, dict):
                continue
            for st in _as_list(a.get("set")):
                if not isinstance(st, dict):
                    continue
                svc = st.get("service") if isinstance(st.get("service"), dict) else None
                chain = st.get("serviceChain") if isinstance(st.get("serviceChain"), dict) else None
                body = svc or chain
                if body is None:
                    continue
                row: dict[str, Any] = {
                    "sequence": leaf_value(s.get("sequenceId")),
                    "name": leaf_value(s.get("sequenceName")),
                    "match": _match_words(_as_list(match.get("entries")), names) or ["any"],
                }
                if svc is not None:
                    row["service"] = leaf_value(svc.get("type"))
                else:
                    row["chain"] = leaf_value(body.get("type") or body.get("serviceChainType"))
                for k in ("vpn", "local", "restrict"):
                    if k in body:
                        row[k] = leaf_value(body[k])
                row["if_down"] = (
                    "dropped (restrict)" if row.get("restrict") else "routed normally, bypassing the firewall"
                )
                out.append(row)
    return out


def target_of(data: dict[str, Any]) -> dict[str, Any]:
    t: dict[str, Any] = data["target"] if isinstance(data.get("target"), dict) else {}
    vpns = leaf_value(t.get("vpn"))
    return {
        "vpns": [str(v) for v in vpns] if isinstance(vpns, list) else [str(vpns)] if vpns else [],
        "direction": leaf_value(t.get("direction")),
        "default_action": leaf_value(data.get("dataDefaultAction")),
    }


def chain_mapping(body: Any) -> dict[str, str]:
    """{SC number: chain name} from GET /v1/service-insertion/service-chain-mapping ([] on the lab)."""
    out = {}
    for r in _as_list(body.get("data") if isinstance(body, dict) else body):
        if isinstance(r, dict) and r.get("serviceChainNumber"):
            out[str(r["serviceChainNumber"])] = str(r.get("serviceChainName") or "")
    return out
