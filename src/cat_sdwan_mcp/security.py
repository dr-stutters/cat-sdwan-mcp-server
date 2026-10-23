"""W23 edge security reads: the UTD container (Snort IPS, URL filtering), the zone-based firewall, the SSL
proxy and the Secure Internet Gateway tunnels on one edge, and the security event indexes.

Reads only: security policy is written in FMC (firewalling in this suite) or the Manager's GUI. Recorded on
20.18.3.1 (a lab without any security policy): every real-time table answers 200 with no rows (the zone-based
firewall statistics with one empty record, the drop counters with every counter at "0"), the four statistics
indexes answer with no rows, and `utd/version-status` reports whether the edge's IOS XE supports the UTD image
and which one is recommended.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from cat_sdwan_mcp.client import _as_list

LEGACY_POLICIES_PATH = "/dataservice/template/policy/security"
# Not in the 20.18 OpenAPI document as a GET, but answered (a list of embedded-security feature profiles).
EMBEDDED_PROFILES_PATH = "/dataservice/v1/feature-profile/sdwan/embedded-security"

# Real-time tables of one edge (GET <path>?deviceId=<system-ip>), by section.
STATUS_PATHS: dict[str, str] = {
    "utd_engine": "/dataservice/device/utd/engine-status",
    "utd_version": "/dataservice/device/utd/version-status",
    "ips_signatures": "/dataservice/device/utd/signature/version/details",
    "ips_updates": "/dataservice/device/utd/ips-update-status",
    "url_filtering_cloud": "/dataservice/device/utd/urlf-con-status",
    "zbfw_statistics": "/dataservice/device/policy/zbfwstatistics",
    "zbfw_drops": "/dataservice/device/policy/zbfwdropstatistics",
    "zone_pairs": "/dataservice/device/policy/zonepairstatistics",
    "zone_pair_sessions": "/dataservice/device/policy/zonepairsessions",
    "ssl_proxy": "/dataservice/device/sslproxy/status",
    "sig_tunnels": "/dataservice/device/sig/getSigTunnelList",
    "umbrella_tunnels": "/dataservice/device/sig/umbrella/tunnels",
}

# kind -> the statistics index of the security events.
EVENT_PATHS = {
    "ips": "/dataservice/statistics/ipsalert",
    "url": "/dataservice/statistics/urlf",
    "connection": "/dataservice/statistics/sul/connections",
    "dns": "/dataservice/statistics/umbrella",
}

_NOISE = ("vdevice-name", "vdevice-host-name", "vdevice-dataKey", "lastupdated")
URLF_COUNTERS = (
    "whitelist_hit_cnt",
    "blacklist_hit_cnt",
    "reputation_action_block",
    "category_action_block",
    "category_action_pass",
    "reputation_action_pass",
    "amp_file_malicious",
)


def records(rows: Any) -> list[dict[str, Any]]:
    """Real-time rows without the Manager's bookkeeping keys; records with nothing left (the zone-based
    firewall statistics answer one empty record when no firewall is configured) are dropped."""
    out = []
    for r in _as_list(rows):
        if not isinstance(r, dict):
            continue
        rec = {k: v for k, v in r.items() if k not in _NOISE and v not in (None, "")}
        if rec:
            out.append(rec)
    return out


def _int(v: Any) -> int:
    try:
        return int(str(v).strip() or 0)
    except ValueError:
        return 0


def nonzero_drops(rows: list[dict[str, Any]]) -> dict[str, int]:
    """The zone-based firewall drop counters that are not zero, biggest first."""
    total: Counter[str] = Counter()
    for r in rows:
        for k, v in r.items():
            if (n := _int(v)) > 0:
                total[k] += n
    return dict(total.most_common())


def utd_version(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    r = rows[0]
    supported = str(r.get("utd-version-status-supported", "")).lower()
    out = {
        "image_supported": supported == "true" if supported in ("true", "false") else None,
        "recommended_image": r.get("utd-version-status-recommended-version"),
        "installed_image": r.get("utd-version-status-version") or r.get("utd-version-status-current-version"),
    }
    return {k: v for k, v in out.items() if v is not None}


def engine_row(r: dict[str, Any]) -> dict[str, Any]:
    out = {
        "version": r.get("utd-engine-status-version"),
        "profile": r.get("utd-engine-status-profile"),
        "status": str(r.get("utd-engine-status-status") or "").removeprefix("utd-oper-status-") or None,
        "reason": r.get("utd-engine-status-reason"),
        "memory_usage": r.get("utd-engine-status-memory-usage"),
        "memory_status": r.get("utd-engine-status-memory-status"),
    }
    return {k: v for k, v in out.items() if v is not None}


def zone_pair_row(r: dict[str, Any]) -> dict[str, Any]:
    out = {
        "zone_pair": r.get("zonepair-name"),
        "source_zone": r.get("src-zone-name"),
        "destination_zone": r.get("dst-zone-name"),
        "policy": r.get("policy-name"),
        "class": r.get("class-name"),
        "action": r.get("class-action"),
        "packets": _int(r.get("pkts-counter") or r.get("pkt-counters")),
        "bytes": _int(r.get("bytes-counter") or r.get("byte-counters")),
        "active_sessions": _int(r.get("current-active-conn")),
        "attempted": _int(r.get("attempted-conn")),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def sig_row(r: dict[str, Any]) -> dict[str, Any]:
    out = {
        "tunnel": r.get("tunnel-name") or r.get("tunnel-if-name"),
        "provider": r.get("provider"),
        "data_centre": r.get("destination-data-center"),
        "state": r.get("sig-state") or r.get("tunnel-state") or r.get("device-state"),
        "tracker": r.get("tracker-state"),
        "ha_pair": r.get("ha-pair"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def ssl_proxy_row(r: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "sslproxy-oper-state",
        "tcpproxy-oper-state",
        "failure-mode",
        "minimum-tls-version",
        "ca-tp-label",
    )
    return {k.replace("-", "_"): r[k] for k in keys if r.get(k) not in (None, "")}


def policy_names(legacy: Any, embedded: Any) -> list[str]:
    """Security policies on the Manager: legacy (localized security) policies and embedded-security feature
    profiles (configuration groups)."""
    names = []
    for p in _as_list(legacy):
        if isinstance(p, dict) and p.get("policyName"):
            used = f", on {p['devicesAttached']} device(s)" if p.get("devicesAttached") else ""
            names.append(f"{p['policyName']} (security policy{used})")
    names += [
        f"{p.get('profileName') or p.get('name')} (embedded-security profile)"
        for p in _as_list(embedded)
        if isinstance(p, dict) and (p.get("profileName") or p.get("name"))
    ]
    return names


# --- events -----------------------------------------------------------------------------------------


def _top(counter: Counter[Any], keep: int) -> list[tuple[Any, int]]:
    return counter.most_common(keep)


def aggregate(
    kind: str, rows: list[dict[str, Any]], hosts: dict[str, str], keep: int
) -> list[dict[str, Any]]:
    """Rows of one statistics index grouped the way an operator asks: IPS by signature, URL filtering per
    edge (the index carries counters), connections by firewall policy / action / drop reason, DNS (Umbrella)
    per edge."""

    def host(r: dict[str, Any]) -> str:
        ip = str(r.get("vdevice_name") or "")
        return str(r.get("host_name") or hosts.get(ip) or ip)

    out: list[dict[str, Any]] = []
    if kind == "ips":
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        for r in rows:
            key = (r.get("gid"), r.get("sid"), r.get("message"))
            g = groups.setdefault(
                key,
                {
                    "signature": f"{r.get('gid')}:{r.get('sid')}",
                    "message": r.get("message"),
                    "classification": r.get("classification"),
                    "priority": r.get("priority"),
                    "hits": 0,
                    "actions": Counter(),
                    "edges": Counter(),
                    "sources": Counter(),
                    "destinations": Counter(),
                },
            )
            g["hits"] += 1
            g["actions"][str(r.get("action") or "?")] += 1
            g["edges"][host(r)] += 1
            g["sources"][str(r.get("src_ip"))] += 1
            g["destinations"][str(r.get("dst_ip"))] += 1
        for g in groups.values():
            for k in ("actions", "edges"):
                g[k] = dict(g[k].most_common())
            g["top_sources"] = [ip for ip, _ in _top(g.pop("sources"), 3)]
            g["top_destinations"] = [ip for ip, _ in _top(g.pop("destinations"), 3)]
            out.append(g)
        out.sort(key=lambda g: -int(g["hits"]))
    elif kind == "connection":
        conn: dict[tuple[Any, ...], dict[str, Any]] = {}
        for r in rows:
            reason = r.get("fw_drop_reason") or r.get("utd_drop_reason_name") or r.get("drop_cause")
            ckey = (
                r.get("fw_policy"),
                r.get("fw_zone_pair"),
                r.get("fw_action"),
                reason,
                r.get("utd_urlf_action"),
            )
            g = conn.setdefault(
                ckey,
                {
                    "policy": r.get("fw_policy"),
                    "zone_pair": r.get("fw_zone_pair"),
                    "action": r.get("fw_action"),
                    "drop_reason": reason,
                    "url_action": r.get("utd_urlf_action"),
                    "connections": 0,
                    "edges": Counter(),
                    "applications": Counter(),
                },
            )
            g["connections"] += 1
            g["edges"][host(r)] += 1
            if r.get("application"):
                g["applications"][str(r["application"])] += 1
        for g in conn.values():
            g["edges"] = dict(g["edges"].most_common())
            g["applications"] = [a for a, _ in _top(g["applications"], 5)]
            out.append({k: v for k, v in g.items() if v not in (None, "", [])})
        out.sort(key=lambda g: -int(g["connections"]))
    else:
        counters = URLF_COUNTERS if kind == "url" else ("redirect_pkts", "local_domain_bypass_total_pkts")
        per: dict[str, Counter[str]] = {}
        for r in rows:
            c = per.setdefault(host(r), Counter())
            for k in counters:
                c[k] += _int(r.get(k))
            if kind == "url" and r.get("action"):
                c[f"action_{r['action']}"] += 1
        for name, c in per.items():
            out.append({"edge": name, "records": None, **{k: v for k, v in c.items() if v}})
        counts = Counter(host(r) for r in rows)
        for g in out:
            g["records"] = counts[g["edge"]]
        out.sort(key=lambda g: -int(g["records"]))
    return out[:keep]
