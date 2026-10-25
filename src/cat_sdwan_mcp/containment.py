"""W45 WAN-edge containment, in two paths like a real deployment. Pure helpers; the tools are in
tools/containment.py.

1. Main path: ISE quarantine SGT. A standing baseline on the edges (set once, previewed, deployed in a change
   window): sequences mcp-quarantine-* at the top of the policy group's NGFW policies (W47) drop traffic from
   and to the Quarantine SGT, apart from the remediation prefixes. Containing a host is then an ISE ANC action
   (ise_apply_anc; the ANC policy's authorization result assigns the Quarantine SGT; CoA), with no Manager
   change per incident. It works only where the edge knows the host's SGT: TrustSec propagation (inline
   tagging from the access switch, SXP from ISE, or pxGrid) and the edge's environment data (W42).
2. Fallback: a host with no ISE session, contained by a per-edge CLI ACL (owner decision 2026-10-25, after
   20.18 refused device variables in a policy-object prefix list: PPARC0012, #126). The configuration group's
   CLI add-on holds a standing extended ACL `mcp-contain` (IOS XE 17.18 syntax), applied inbound on the
   service-side (VPN 10) interfaces where the edge's LAN traffic enters:

       ip access-list extended mcp-contain
        10 permit ip any host 198.51.100.53          <- remediation, before the slots
        110 remark {{mcp_contain_1_note}}
        111 deny ip host {{mcp_contain_1}} any        <- slot 1 (.. 4)
        ...
        1000 permit ip any any
       interface GigabitEthernet3
        ip access-group mcp-contain in
       exit

   Every device holds neutral slot values (the documentation addresses 192.0.2.241-244 and the note
   "mcp-contain slot free"), as br1's FTD leg in mcp-test has real values and br2 a neutral one. Containing a
   host writes ONE device's slot (address + note: the time-boxed record, expiry and reason) and deploys that
   device only: no parcel changes and no other device's variables change, so no other edge's intended config
   changes. Release puts the neutral values back. Explicit sequence numbers keep a re-rendered entry in its
   place (an entry without one is appended after `permit ip any any` and would match nothing).

Nothing here touches a sequence or CLI line it did not create: the NGFW writes strip only their own sequence
names; the ACL block is found by its exact shape (the ACL stanza and the `interface X / ip access-group
mcp-contain in / exit` triples) and replaced or removed as a whole.
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
ACL_NAME = "mcp-contain"
SLOTS = 4
SLOT_VARS = [f"mcp_contain_{i}" for i in range(1, SLOTS + 1)]
NOTE_VARS = {v: f"{v}_note" for v in SLOT_VARS}
# Neutral per-device values: TEST-NET-1 (RFC 5737) addresses, never a real host; distinct so the ACL has no
# duplicate entries.
INERT = {v: f"192.0.2.{240 + i}" for i, v in enumerate(SLOT_VARS, start=1)}
NOTE_FREE = "mcp-contain slot free"
NOTE_PREFIX = "mcp-contain until "
REMARK_CHARS = 100  # IOS XE ACL remark limit
MAX_REMEDIATION = 16
MAX_INTERFACES = 8
MAX_HOURS = 168
REMEDIATION_SEQ = 10  # 10..25
SLOT_SEQ = 100  # slot i: remark 100+10i, deny 101+10i
PERMIT_SEQ = 1000

QUARANTINE_RULES = (
    "mcp-quarantine-allow-out",
    "mcp-quarantine-allow-in",
    "mcp-quarantine-out",
    "mcp-quarantine-in",
)
BASELINE_RULES = QUARANTINE_RULES


def host_ip(value: str) -> str:
    """The host's IPv4 address, normalised; ValueError for anything else (a prefix, IPv6, a name)."""
    s = value.strip()
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        raise ValueError(f"{value!r} is not an IP address") from None
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"{value!r} is IPv6: the edge ACL matches IPv4 only")
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        raise ValueError(f"{value!r} is not a host address")
    if addr in ipaddress.IPv4Network("192.0.2.240/29"):
        raise ValueError(f"{value!r} is one of the neutral slot addresses (192.0.2.241-244)")
    return str(addr)


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
    safety stop after a configuration-group variables PUT that must leave these devices alone."""
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


# --- the quarantine baseline's sequences (policy group NGFW) -------------------------------------


def baseline_rules(*, remediation: list[str]) -> list[dict[str, Any]]:
    """The quarantine rules in order (W47 FirewallRule fields, objects by name): pass to and from the
    remediation prefixes first, then drop from and to the Quarantine SGT, logged."""
    rules: list[dict[str, Any]] = []
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
        {"name": QUARANTINE_RULES[3], "action": "drop", "destination_sgts": [QUARANTINE_OBJECT], "log": True},
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
    """Whether an NGFW policy holds the quarantine drops (enabled)."""
    names = {seq_name(s) for s in sequences_of(data) if leaf_value(s.get("disableSequence")) is not True}
    return {"quarantine": {QUARANTINE_RULES[2], QUARANTINE_RULES[3]} <= names}


# --- the per-edge CLI ACL (configuration group CLI add-on) ---------------------------------------

_IFNAME = re.compile(r"[A-Za-z][A-Za-z-]*\d+(?:[/.:]\d+)*")
_VAR = re.compile(r"\{\{([A-Za-z][A-Za-z0-9_]*)\}\}")
_ACL_HEAD = f"ip access-list extended {ACL_NAME}"
_APPLY = f" ip access-group {ACL_NAME} in"


def _wildcard(prefix: str) -> str:
    net = ipaddress.IPv4Network(prefix)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def acl_block(remediation: list[str], interfaces: list[str]) -> str:
    """The CLI add-on lines of the containment ACL and where it is applied (no trailing newline)."""
    lines = [_ACL_HEAD]
    lines += [f" {REMEDIATION_SEQ + i} permit ip any {_wildcard(p)}" for i, p in enumerate(remediation)]
    for i, v in enumerate(SLOT_VARS, start=1):
        lines.append(f" {SLOT_SEQ + 10 * i} remark {{{{{NOTE_VARS[v]}}}}}")
        lines.append(f" {SLOT_SEQ + 10 * i + 1} deny ip host {{{{{v}}}}} any")
    lines.append(f" {PERMIT_SEQ} permit ip any any")
    lines.append("!")
    for name in interfaces:
        lines += [f"interface {name}", _APPLY, "exit"]
    return "\n".join(lines)


def _split_block(text: str) -> tuple[list[str], list[str], list[str]]:
    """(the lines without the block, the ACL stanza's lines, the interfaces the block applies it on)."""
    lines = text.splitlines()
    kept: list[str] = []
    acl: list[str] = []
    interfaces: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.rstrip() == _ACL_HEAD:
            acl.append(ln.rstrip())
            i += 1
            while i < len(lines) and lines[i].startswith(" "):
                acl.append(lines[i].rstrip())
                i += 1
            if i < len(lines) and lines[i].strip() == "!":
                i += 1
            continue
        if (
            ln.startswith("interface ")
            and i + 2 < len(lines)
            and lines[i + 1].rstrip() == _APPLY
            and lines[i + 2].strip() == "exit"
        ):
            interfaces.append(ln[len("interface ") :].strip())
            i += 3
            continue
        kept.append(ln)
        i += 1
    while kept and not kept[-1].strip():
        kept.pop()
    return kept, acl, interfaces


def acl_state(text: str) -> dict[str, Any] | None:
    """The containment ACL a CLI add-on holds: {interfaces, remediation, slots (variables), intact}, or None.
    `intact` is False when the ACL is not exactly what acl_block writes (edited by hand)."""
    _, acl, interfaces = _split_block(text)
    if not acl:
        return None
    remediation = []
    for ln in acl[1:]:
        m = re.fullmatch(r" (\d+) permit ip any (host (\S+)|(\S+) (\S+))", ln)
        if m and REMEDIATION_SEQ <= int(m.group(1)) < SLOT_SEQ:
            if m.group(3):
                remediation.append(f"{m.group(3)}/32")
            else:
                mask = ipaddress.IPv4Address(int(ipaddress.IPv4Address(m.group(5))) ^ 0xFFFFFFFF)
                remediation.append(str(ipaddress.IPv4Network(f"{m.group(4)}/{mask}", strict=False)))
    expected = acl_block(remediation, interfaces).splitlines()
    got = [*acl, "!"] + [ln for name in interfaces for ln in (f"interface {name}", _APPLY, "exit")]
    return {
        "interfaces": interfaces,
        "remediation": remediation,
        "slots": [v for v in SLOT_VARS if f"host {{{{{v}}}}} any" in "\n".join(acl)],
        "intact": got == expected and bool(interfaces),
    }


def with_acl(text: str, block: str) -> str:
    """The CLI text with the containment block (re)placed at its end; everything else kept in order."""
    kept, _, _ = _split_block(text)
    return "\n".join([*kept, block]) + ("\n" if text.endswith("\n") else "")


def without_acl(text: str) -> str:
    kept, _, _ = _split_block(text)
    return "\n".join(kept) + ("\n" if text.endswith("\n") and kept else "")


def interface_problems(interfaces: list[str], text: str) -> list[str]:
    """Why the ACL can't be applied on these interfaces: a bad name, a variable the CLI does not have yet
    (devices would have no value), or an interface whose stanza already applies another inbound ACL."""
    out = []
    if len(interfaces) > MAX_INTERFACES:
        out.append(f"at most {MAX_INTERFACES} interfaces ({len(interfaces)} given)")
    if len(set(interfaces)) != len(interfaces):
        out.append("an interface is given twice")
    kept, _, _ = _split_block(text)
    body = "\n".join(kept)
    for name in interfaces:
        var = _VAR.fullmatch(name)
        if var:
            if name not in body:
                out.append(
                    f"interface {name}: the CLI add-on has no variable {var.group(1)} yet, so devices have "
                    "no "
                    "value for it; give an interface name or a variable the CLI already uses (e.g. {{fw_if}})"
                )
            continue
        if not _IFNAME.fullmatch(name):
            out.append(f"{name!r} is not an interface name (e.g. GigabitEthernet3) or a {{{{variable}}}}")
            continue
        current = None
        for ln in kept:
            if ln.startswith("interface "):
                current = ln[len("interface ") :].strip()
            elif not ln.startswith(" "):
                current = None
            elif current == name and re.fullmatch(r" ip access-group \S+ in", ln.rstrip()):
                out.append(
                    f"{name} already applies an inbound ACL in the CLI ({ln.strip()}): one per direction"
                )
    return out


def resolve_interfaces(interfaces: list[str], variables: list[dict[str, Any]]) -> list[str]:
    """The interface names on one device: {{variables}} replaced by the device's values."""
    by_name = {str(v.get("name")): v.get("value") for v in variables}

    def one(name: str) -> str:
        m = _VAR.fullmatch(name)
        return str(by_name.get(m.group(1)) or name) if m else name

    return [one(n) for n in interfaces]


# --- per-device slots ----------------------------------------------------------------------------


def slot_values(variables: list[dict[str, Any]]) -> dict[str, Any]:
    """{slot variable: value or None} for the slot variables a device has."""
    by_name = {str(v.get("name")): v for v in variables}
    return {s: by_name[s].get("value") for s in SLOT_VARS if s in by_name}


def note_values(variables: list[dict[str, Any]]) -> dict[str, Any]:
    """{slot variable: its note's value} for the slots a device has."""
    by_name = {str(v.get("name")): v.get("value") for v in variables}
    return {s: by_name.get(NOTE_VARS[s]) for s in SLOT_VARS if s in by_name}


def host_of(value: Any) -> str | None:
    """The contained host in a slot value ('10.61.100.10'), None when neutral or empty."""
    text = str(value or "").strip().removesuffix("/32")
    if not text or text in INERT.values():
        return None
    return text


def pick_slot(values: dict[str, Any], ip: str) -> tuple[str | None, bool]:
    """(the slot for this host, whether it already holds it): its own slot, else the first neutral/empty."""
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


def neutral(slots: list[str] | None = None) -> dict[str, str]:
    """The neutral values of these slots (default all): address and note."""
    out: dict[str, str] = {}
    for s in slots if slots is not None else SLOT_VARS:
        out[s] = INERT[s]
        out[NOTE_VARS[s]] = NOTE_FREE
    return out


# --- the record (each slot's note) ---------------------------------------------------------------


def expiry(hours: int, now: datetime | None = None) -> str:
    t = (now or datetime.now(UTC)) + timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%MZ")


def note(expires: str, reason: str) -> str:
    """The slot's record, rendered as the ACL remark: 'mcp-contain until <expiry> <reason>' (IOS XE remarks
    hold 100 characters; the reason is cut to fit and keeps only plain characters)."""
    clean = " ".join(re.sub(r"[^A-Za-z0-9 ._,:/#()=+-]", " ", reason).split())
    head = f"{NOTE_PREFIX}{expires} "
    return (head + clean)[:REMARK_CHARS].rstrip()


def parse_note(value: Any) -> dict[str, str]:
    """{expires, reason} from a slot's note; {} for a free slot or another text."""
    text = str(value or "")
    if not text.startswith(NOTE_PREFIX):
        return {}
    expires, _, reason = text[len(NOTE_PREFIX) :].partition(" ")
    return {"expires": expires, "reason": reason}


def is_expired(expires: str | None, now: datetime | None = None) -> bool | None:
    if not expires:
        return None
    try:
        t = datetime.strptime(expires, "%Y-%m-%dT%H:%MZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return (now or datetime.now(UTC)) >= t


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
