"""W45 WAN-edge containment, in two paths like a real deployment. Pure helpers; the tools are in
tools/containment.py.

1. Main path: ISE quarantine SGT. A standing baseline on the edges (set once, previewed, deployed in a change
   window): sequences mcp-quarantine-* at the top of the group's NGFW policies (W47) drop traffic from and to
   the Quarantine SGT, apart from the remediation prefixes. Containing a host is then an ISE ANC action
   (ise_apply_anc; the ANC policy's authorization result assigns the Quarantine SGT; CoA), with no Manager
   change per incident. It works only where the edge knows the host's SGT: TrustSec propagation (inline
   tagging from the access switch, SXP from ISE, or pxGrid) and the edge's environment data (W42).
2. Fallback: a host with no ISE session. The same baseline carries an edge slot: sequences mcp-contain-slots-*
   matching the prefix list mcp-contain-slots, whose entries are per-device variables {{mcp_contain_1}} ..
   {{mcp_contain_4}} (the recorded security-data-ip-prefix schema takes a variable per entry). Every device
   holds inert documentation addresses there (192.0.2.241-244/32). Containing a host writes ONE device's
   variable (the edge where the host sits) and deploys that device only: no parcel of the group changes, no
   other device's variables change, so no other edge's intended config changes. The containment record is a
   prefix-list object named mcp-contain-<ip> (referenced by no rule, so it renders on no device) whose
   description holds the edge, slot, expiry and reason; release puts the inert value back, deletes exactly
   that record and deploys the edge again.

Nothing here touches a sequence it did not create: every write strips only its own names (exact names, listed
below), puts its own block at the top and renumbers the rest in their order.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.edgefirewall import LOG_ACTION, g, leaf_value, match_entries

QUARANTINE_OBJECT = "mcp-quarantine-sgt"  # SGT list (security-scalablegrouptag): the Quarantine SGT
SLOT_OBJECT = "mcp-contain-slots"  # prefix list (security-data-ip-prefix) of per-device variables
RECORD_PREFIX = "mcp-contain-"
SLOTS = 4
SLOT_VARS = [f"mcp_contain_{i}" for i in range(1, SLOTS + 1)]
# Inert per-device values: TEST-NET-1 (RFC 5737) /32s, never a real host; distinct so the list has no
# duplicate entries.
INERT = {v: f"192.0.2.{240 + i}/32" for i, v in enumerate(SLOT_VARS, start=1)}
MAX_REMEDIATION = 16
MAX_HOURS = 168
REASON_CHARS = 120

# The baseline's sequences, in the order they sit at the top of an NGFW policy.
SLOT_RULES = (
    "mcp-contain-slots-allow-out",
    "mcp-contain-slots-allow-in",
    "mcp-contain-slots-out",
    "mcp-contain-slots-in",
)
QUARANTINE_RULES = (
    "mcp-quarantine-allow-out",
    "mcp-quarantine-allow-in",
    "mcp-quarantine-out",
    "mcp-quarantine-in",
)
BASELINE_RULES = SLOT_RULES + QUARANTINE_RULES


def host_ip(value: str) -> str:
    """The host's IPv4 address, normalised; ValueError for anything else (a prefix, IPv6, a name)."""
    s = value.strip()
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        raise ValueError(f"{value!r} is not an IP address") from None
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"{value!r} is IPv6: the edge firewall rules match IPv4 only")
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        raise ValueError(f"{value!r} is not a host address")
    if addr in ipaddress.IPv4Network("192.0.2.240/29"):
        raise ValueError(f"{value!r} is one of the inert slot addresses (192.0.2.241-244)")
    return str(addr)


def slug(ip: str) -> str:
    return ip.replace(".", "-")


def record_name(ip: str) -> str:
    """mcp-contain-<ip with dashes> (at most 27 characters: the object name limit is 32)."""
    return f"{RECORD_PREFIX}{slug(ip)}"


_RECORD = re.compile(rf"{re.escape(RECORD_PREFIX)}(\d{{1,3}}(?:-\d{{1,3}}){{3}})")


def record_ip(name: Any) -> str | None:
    """The host a record object names (mcp-contain-10-61-100-10 -> 10.61.100.10), else None."""
    m = _RECORD.fullmatch(str(name or ""))
    return m.group(1).replace("-", ".") if m else None


# Reserved TrustSec tags (Cisco TrustSec / ISE): 0 Unknown (every untagged packet: on an edge without TrustSec
# that is ALL traffic), 2 TrustSec_Devices (the network devices themselves), 65520-65535 reserved (65535
# ANY). So a quarantine tag must be a user SGT, 3..65519 (ISE's default Quarantined_Systems is 255).
QUARANTINE_TAG_MIN, QUARANTINE_TAG_MAX = 3, 65519


def quarantine_tag_problems(entries: list[dict[str, Any]]) -> list[str]:
    """Why an SGT list entry can't be the Quarantine SGT: a drop rule on a reserved tag drops far more than
    the quarantined hosts (tag 0 is every untagged flow, fleet-wide)."""
    out = []
    for e in entries:
        tag = str(leaf_value(e.get("tag")) or "").strip()
        if not tag.isdigit() or not QUARANTINE_TAG_MIN <= int(tag) <= QUARANTINE_TAG_MAX:
            out.append(
                f"SGT tag {tag or '?'} can't be the Quarantine SGT: tags 0 (Unknown: every untagged flow, "
                "all traffic where TrustSec is not running), 2 (TrustSec_Devices: the network devices) and "
                f"65520-65535 (reserved, ANY) would drop far more than quarantined hosts; use a user SGT "
                f"{QUARANTINE_TAG_MIN}-{QUARANTINE_TAG_MAX} (ISE's Quarantined_Systems is 255)"
            )
    return out


def moved_devices(before: dict[str, dict[str, Any]], after: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Chassis whose variables ({name: value} before) differ in `after` (a device-variables read): the
    safety stop after a policy-group variables PUT that must leave these devices alone."""
    return [
        c
        for c, vals in before.items()
        if {str(v.get("name")): v.get("value") for v in after.get(c, [])} != vals
    ]


def remediation_problems(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            net = ipaddress.IPv4Network(v, strict=True)
        except ValueError as e:
            out.append(f"remediation {v!r} is not an IPv4 prefix ({e})")
            continue
        if net.prefixlen == 0:
            out.append(f"remediation {v!r} is everything: it would let quarantined hosts reach any address")
    if len(values) > MAX_REMEDIATION:
        out.append(f"at most {MAX_REMEDIATION} remediation prefixes ({len(values)} given)")
    if len(set(values)) != len(values):
        out.append("a remediation prefix is given twice")
    return out


# --- the baseline's sequences --------------------------------------------------------------------


def baseline_rules(*, slots: bool, quarantine: bool, remediation: list[str]) -> list[dict[str, Any]]:
    """The baseline rules in order (W47 FirewallRule fields, objects by name): for the edge slot and the
    Quarantine SGT each, pass to and from the remediation prefixes first, then drop from and to, logged."""
    rules: list[dict[str, Any]] = []
    if slots:
        if remediation:
            rules += [
                {
                    "name": SLOT_RULES[0],
                    "action": "pass",
                    "source_objects": [SLOT_OBJECT],
                    "destination_prefixes": list(remediation),
                },
                {
                    "name": SLOT_RULES[1],
                    "action": "pass",
                    "source_prefixes": list(remediation),
                    "destination_objects": [SLOT_OBJECT],
                },
            ]
        rules += [
            {"name": SLOT_RULES[2], "action": "drop", "source_objects": [SLOT_OBJECT], "log": True},
            {"name": SLOT_RULES[3], "action": "drop", "destination_objects": [SLOT_OBJECT], "log": True},
        ]
    if quarantine:
        if remediation:
            rules += [
                {
                    "name": QUARANTINE_RULES[0],
                    "action": "pass",
                    "source_sgts": [QUARANTINE_OBJECT],
                    "destination_prefixes": list(remediation),
                },
                {
                    "name": QUARANTINE_RULES[1],
                    "action": "pass",
                    "source_prefixes": list(remediation),
                    "destination_sgts": [QUARANTINE_OBJECT],
                },
            ]
        rules += [
            {"name": QUARANTINE_RULES[2], "action": "drop", "source_sgts": [QUARANTINE_OBJECT], "log": True},
            {
                "name": QUARANTINE_RULES[3],
                "action": "drop",
                "destination_sgts": [QUARANTINE_OBJECT],
                "log": True,
            },
        ]
    return rules


def sequence(rule: dict[str, Any], refs: dict[str, dict[str, str]]) -> dict[str, Any]:
    """One NGFW sequence in W47's shape (ngfw_body); the id is set by renumber()."""
    return {
        "sequenceId": g("0"),
        "sequenceName": g(str(rule["name"])),
        "baseAction": g(str(rule["action"])),
        "sequenceType": g("ngfirewall"),
        "match": {"entries": match_entries(rule, refs)},
        "actions": [LOG_ACTION] if rule.get("log") else [],
        "disableSequence": g(False),
    }


def sequences_of(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in _as_list(data.get("sequences")) if isinstance(s, dict)]


def seq_name(s: dict[str, Any]) -> str:
    return str(leaf_value(s.get("sequenceName")) or "")


def renumber(seqs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The sequences in order with ids 1..n (the first match decides, so order is what matters)."""
    out = []
    for i, s in enumerate(seqs, start=1):
        row = copy.deepcopy(s)
        old = row.get("sequenceId")
        row["sequenceId"] = (
            {**old, "value": str(i)} if isinstance(old, dict) and "optionType" in old else g(str(i))
        )
        out.append(row)
    return out


def _strip(data: dict[str, Any], names: tuple[str, ...]) -> tuple[list[dict[str, Any]], list[str]]:
    kept, removed = [], []
    for s in sequences_of(data):
        if seq_name(s) in names:
            removed.append(seq_name(s))
        else:
            kept.append(s)
    return kept, removed


def with_baseline(
    data: dict[str, Any], seqs: list[dict[str, Any]], names: tuple[str, ...] = BASELINE_RULES
) -> tuple[dict[str, Any], list[str]]:
    """(the NGFW policy's data with `seqs` at the top, the names of the earlier `names` sequences it
    replaces). Every other key and sequence is kept in its order."""
    kept, replaced = _strip(data, names)
    out = {k: copy.deepcopy(v) for k, v in data.items() if k != "sequences"}
    out["sequences"] = renumber(list(seqs) + kept)
    return out, replaced


def without_baseline(
    data: dict[str, Any], names: tuple[str, ...] = BASELINE_RULES
) -> tuple[dict[str, Any], list[str]]:
    """(the NGFW policy's data without the `names` sequences, their names)."""
    kept, removed = _strip(data, names)
    out = {k: copy.deepcopy(v) for k, v in data.items() if k != "sequences"}
    out["sequences"] = renumber(kept)
    return out, removed


def baseline_state(data: dict[str, Any]) -> dict[str, bool]:
    """Which parts of the baseline an NGFW policy holds: the edge slot's drops and the quarantine drops."""
    names = {seq_name(s) for s in sequences_of(data) if leaf_value(s.get("disableSequence")) is not True}
    return {
        "edge_slots": {SLOT_RULES[2], SLOT_RULES[3]} <= names,
        "quarantine": {QUARANTINE_RULES[2], QUARANTINE_RULES[3]} <= names,
    }


def slot_entries() -> list[dict[str, Any]]:
    """The mcp-contain-slots prefix list's entries: one per-device variable each."""
    return [{"ipPrefix": {"optionType": "variable", "value": "{{" + v + "}}"}} for v in SLOT_VARS]


def is_slot_object(data: dict[str, Any]) -> bool:
    """Whether a prefix-list object holds exactly the slot variables (so it is ours)."""
    got = [leaf_value(e.get("ipPrefix")) for e in _as_list(data.get("entries")) if isinstance(e, dict)]
    return got == ["{{" + v + "}}" for v in SLOT_VARS]


# --- per-device slots ----------------------------------------------------------------------------


def slot_values(variables: list[dict[str, Any]]) -> dict[str, Any]:
    """{slot variable: value or None} for the slot variables a device has."""
    by_name = {str(v.get("name")): v for v in variables}
    return {s: by_name[s].get("value") for s in SLOT_VARS if s in by_name}


def host_of(value: Any) -> str | None:
    """The contained host in a slot value ('10.61.100.10/32'), None when inert or empty."""
    text = str(value or "").strip()
    if not text or text in INERT.values():
        return None
    return text.removesuffix("/32")


def pick_slot(values: dict[str, Any], ip: str) -> tuple[str | None, bool]:
    """(the slot for this host, whether it already holds it): its own slot, else the first inert/empty."""
    for s, v in values.items():
        if host_of(v) == ip:
            return s, True
    for s, v in values.items():
        if host_of(v) is None:
            return s, False
    return None, False


def contained_at(values: dict[str, Any]) -> dict[str, str]:
    """{slot: host} of the hosts a device's slots hold."""
    return {s: h for s, v in values.items() if (h := host_of(v))}


# --- containment records -------------------------------------------------------------------------


def expiry(hours: int, now: datetime | None = None) -> str:
    t = (now or datetime.now(UTC)) + timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%MZ")


def record_description(
    *, edge: str, chassis: str, group: str, slot: str, vpn: str | None, expires: str, reason: str
) -> str:
    clean = " ".join(reason.replace(";", ",").split())[:REASON_CHARS]
    return (
        f"mcp-contain; edge={edge}; chassis={chassis}; group={group}; slot={slot}; vpn={vpn or '?'}; "
        f"expires={expires}; reason={clean}"
    )


def parse_record(description: Any) -> dict[str, str]:
    """The fields of a record's description (reason last: it is everything after 'reason=')."""
    text = str(description or "")
    if not text.startswith("mcp-contain;"):
        return {}
    head, _, reason = text.partition("; reason=")
    out: dict[str, str] = {}
    for part in head.split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    if reason:
        out["reason"] = reason
    return out


def is_expired(expires: str | None, now: datetime | None = None) -> bool | None:
    if not expires:
        return None
    try:
        t = datetime.strptime(expires, "%Y-%m-%dT%H:%MZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return (now or datetime.now(UTC)) >= t


# --- zones ---------------------------------------------------------------------------------------


def zone_holds(data: dict[str, Any], vpn: str | None, interface: str | None) -> bool:
    """Whether a security-zone object holds the host's VPN or the interface it sits on."""
    for e in _as_list(data.get("entries")):
        if not isinstance(e, dict):
            continue
        z_vpn = leaf_value(e.get("vpn"))
        z_if = leaf_value(e.get("interface"))
        if vpn is not None and z_vpn is not None and str(z_vpn) == str(vpn):
            return True
        if interface and z_if and str(z_if).lower() == interface.lower():
            return True
    return False


def host_zones(zones: list[dict[str, Any]], vpn: str | None, interface: str | None) -> dict[str, str]:
    """{zone id: name} of the security zones holding the host."""
    return {z["id"]: str(z.get("name")) for z in zones if zone_holds(z["data"], vpn, interface)}


def payload_of(raw: dict[str, Any]) -> dict[str, Any]:
    return raw["payload"] if isinstance(raw.get("payload"), dict) else {}


def ngfw_put_body(row: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """The PUT body for an NGFW parcel: its own name and description, the new data."""
    payload = payload_of(row["raw"])
    return {
        "name": row.get("name") or payload.get("name"),
        "description": payload.get("description") or "",
        "data": data,
    }
