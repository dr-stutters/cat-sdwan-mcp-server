# ruff: noqa: E501  (the rule table keeps one regex per line so a tag is easy to find)
"""Map every tag in the Manager's OpenAPI document to a roadmap item and write docs/spec-coverage.md.

Usage: python scripts/spec_coverage.py <vmanageapi.json> [release]

The spec comes from a running Manager (GET /apidocs/vmanageapi.json after a login). Rules are matched in
order against the tag name; the first match wins. A tag that matches nothing is reported and fails the run,
so a new release's tags are never silently left out.
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

METHODS = ("get", "post", "put", "delete", "patch")

# (tag regex, item, note). Items: W-ids, "api_call" (reachable through catsdwan_api_call, no tool planned)
# or "not planned" (see ROADMAP.md "Not planned" for the reason).
RULES: list[tuple[str, str, str]] = [
    # Done (v0.1.0, v0.2.0)
    (r"^Client - ", "W1", "login and XSRF token"),
    (r"^Monitoring - Device Details$", "W2", "device list, counters, status"),
    (r"^Monitoring - Health$", "W2", "device health"),
    (r"^Real-Time Monitoring - (System|Software|Reboot History)$", "W2", "per-device detail"),
    (r"^Real-Time Monitoring - Interface$", "W2", "interfaces in get_device; error and queue counters W18"),
    (r"^Real-Time Monitoring - (Device Control|OMP)$", "W3", ""),
    (r"^Real-Time Monitoring - (BFD|Tunnel|IPsec|Application-Aware Route)$", "W4", ""),
    (r"^Monitoring - (Application Aware Routing|BFD)$", "W4", "statistics"),
    (r"^Monitoring - (Alarms Details|Events)$", "W5", ""),
    (r"^Administration - Audit Log$", "W5", ""),
    (
        r"^Configuration - (Configuration Group|Device Template|General Template|Template Master|Template Configuration)$",
        "W7/W8",
        "reads W7, deploy and attach W8",
    ),
    (r"^Policy - Policy Group$", "W7/W21", "list W7, deploy W21"),
    (r"^Configuration - Device Inventory$", "W9", "WAN edge list, serial file, bootstrap"),
    (r"^Manual Onboard Device$", "W9", ""),
    # Planned (W11-W15)
    (
        r"^Configuration - (vSmart|vEdge|Security|Voice) Template Policy$",
        "W11",
        "centralised and localised policy",
    ),
    (r"^Configuration - Policy (vSmart|vEdge|Security|Voice) Assembler$", "W11", ""),
    (r"^Real-Time Monitoring - Policy$", "W11/W23", "policy filters W11, zone-based firewall counters W23"),
    (
        r"^Configuration - (Device Actions|Software Actions|Device Software Update|Dashboard Status|Downloaded Images|Maintenance window flag)$",
        "W12",
        "reboot, install, activate, action status",
    ),
    (r"^Monitoring - DPI$", "W13", "top applications"),
    (r"^Real-Time Monitoring - DPI$", "W13", ""),
    (
        r"^Monitoring - (Device Statistics|Device Statistics Details|Device Statistics Details V2|System Status Stats|Device Health)$",
        "W13",
        "history",
    ),
    (r"^Real-Time Monitoring - Device System Stats$", "W13", ""),
    (r"^Tenant Management$", "W1/W14", "VSessionId and tenant pinning"),
    # New (W16-W28)
    (r"^Certificate Management - ", "W16", ""),
    (r"^Real-Time Monitoring - Pki Trustpoint$", "W16", ""),
    (
        r"^Troubleshooting Tools - (Device Connectivity|Device Group)$",
        "W17",
        "ping, traceroute, tunnel path, bring-up, admin-tech",
    ),
    (r"^Real-Time Monitoring - (Tools|Show On Demand Local|Show On Demand Remote)$", "W17", ""),
    (
        r"^Real-Time Monitoring - (BGP|OSPF|EIGRP|IP|IPv4 FIB|IPv6 FIB|PIM|IGMP|Multicast|VRRP|ARP|IPv6 Neighbours|DHCP|NTP|Hardware|Crash Log|Lacp|Bridge|Transport|VPN|Device|Device Feature List|Static Route Tracker Service|Dual Static Route Tracker Service|Endpoint Tracker Service|Endpoint Tracker Group Service|CFM|PPPoE|QoS|QFP|Policer|SDWAN Statistics|AAA|Commit List|License Info|NMS|Lpshield)$",
        "W18",
        "catsdwan_routes / catsdwan_device_state catalogue",
    ),
    (r"^Monitoring - (CDP|LLDP|BootUp Time|Underlay Alarms)$", "W18", ""),
    (r"^Troubleshooting Tools - Network Wide Path Insight$", "W19", ""),
    (r"^Configuration - Device Config History$", "W20", ""),
    (
        r"^Configuration - Feature Profile \((SDWAN|SD-Routing)\)$",
        "W21",
        "parcel reads and preview-first parcel changes",
    ),
    (r"^Topology - Topology Group$", "W21", ""),
    (
        r"^Monitoring - (SiteHealth Monitor|Tunnel Health|Interface Statistics|QoS|Network Availability|Qfp|Qfp Drop Statistics|ART|Performance Monitor)$",
        "W22",
        "",
    ),
    (r"^Device - Network$", "W22", ""),
    (r"^Configuration - Topology$", "W22", ""),
    (r"^Real-Time Monitoring - (UTD|Security|Sslproxy|SIG|Umbrella|SSE)$", "W23", ""),
    (
        r"^Monitoring - (IPsAlert|URL Filtering|Umbrella|Umbrella Patterns|Security Unified Logging Connection Events|Security Policy|Flowlog)$",
        "W23",
        "",
    ),
    (r"^Real-Time Monitoring - (Trustsec|DOT1x)$", "W24", ""),
    (r"^Configuration - Ise Server$", "W24", "reads only; pxGrid setup stays in the GUI"),
    (
        r"^Partner - (Registration|DNAC SDA API)$",
        "W24",
        "partner list and the Catalyst Center SD-Access integration, reads",
    ),
    (r"^Cluster Management$", "W25", "health reads; cluster changes not planned"),
    (r"^Configuration - Disaster Recovery$", "W25", "status and history reads; DR changes not planned"),
    (r"^Scheduled Backup Restore$", "W25", "list and create backups; restores not planned"),
    (r"^(Management|Monitoring - Server Info|Monitoring - Stats Processing|Monitoring - Status)$", "W25", ""),
    (r"^Administration - User and Group$", "W26", "users, groups, sessions, AAA; W14 user-group script"),
    (r"^Workflows - Controllers Upgrade$", "W27", ""),
    (r"^(Licensing - Next Generation|MSLA|Smart License|SmartLicensing - .*)$", "W28", "reads"),
    # Reachable through catsdwan_api_call, no tool planned
    (
        r"^Configuration - (Policy .*|.* List Builder|.* Definition Builder|.* Definition|Rule Set Definition|Security Group Definition|Advanced Inspection Profile Definition|FQDN List Builder|Preferred Color Group List Builder|SSL Decryption .*)$",
        "api_call",
        "legacy policy objects: read in W11, written through api_call",
    ),
    (
        r"^Configuration - (Settings|Segments|Circuits|Network Design|Network Design Templates|Template Lock|Quick Connect|Control Component Setting|Feature Certificate)$",
        "api_call",
        "",
    ),
    (r"^Network Settings$", "api_call", ""),
    (
        r"^Monitoring - (Alarms Notification|Stats Download|Search|Endpoint Tracker Status|Temperature Statistics|Power Consumption Statistics)$",
        "api_call",
        "",
    ),
    (r"^Scheduled Report Management$", "api_call", "the Manager's own report templates"),
    (r"^Resource - Pool$", "api_call", ""),
    (r"^Compliance - Device Details$", "api_call", ""),
    (r"^Jobs - Batch$", "api_call", ""),
    (r"^Locale$", "api_call", ""),
    (r"^Utility - (Logging|Configuration DB|OLAP DB|Security)$", "api_call", "Manager internals"),
    (
        r"^(IPS Signature - .*|Configuration - Device SSL Proxy Certificate Management)$",
        "api_call",
        "edge security objects (security writes belong to FMC)",
    ),
    (
        r"^(Troubleshooting Tools - Diagnostics|Troubleshooting MRE - Workflow|Setting - Dynamic Scheduler|Real Time Monitoring - Raw Socket|File based RealTime Data Collection - .*|Monitoring - DPI - On-demand troubleshooting)$",
        "api_call",
        "packet capture, speed test and log streaming need a browser session",
    ),
    # Not planned (ROADMAP.md "Not planned")
    (
        r"^(Configuration - (Cloud On Ramp|Cloud On Ramp SaaS|CloudExpress|Multi Cloud|Azure Connect|Secure Internet Gateway|Secure Internet Gateway Tunnels)|MultiCloud - .*|Multicloud Interconnect - .*|Monitoring - CloudExpress|Real-Time Monitoring - CloudExpress|Monitoring - SecureX Integration|System - Cloud Service.*|Umbrella|Kubernetes Services)$",
        "not planned",
        "cloud accounts",
    ),
    (
        r"^(Configuration - Feature Profile \((NFVirtual|Mobility)\)|Colocation|Real-Time Monitoring - (Container Lifecycle|NetworkHub Resources|RBAC|VM|App Hosting|Ucse|Orchestrator|App Logs)|Monitoring - (App Hosting|VNF Interface Statistics|Bridge)|Service Chain Mapping)$",
        "not planned",
        "NFV, colocation and app hosting hardware",
    ),
    (
        r"^(Real-Time Monitoring -LTE450 Cellular|Real-Time Monitoring - (Cellular.*|Voice|WLAN|Wireless|VDSL Service|SFP|Power Consumption|Geo-fencing|Ignition Status|Appqoe|DRE|TCP Optimization|Tcpproxy)|Overview - Cellular|Monitoring - (Cellular-EIOLTE|Wlan Client Info|SDRA|Cflowd|Cedge Cflowd|Crypto VPN)|Troubleshooting Tools - UMTS|Configuration - Device Firmware Update|Secure Device O[nN]Boarding - .*|Secure Device Onboarding - .*)$",
        "not planned",
        "hardware modules, voice, wireless, AppQoE and cellular the CML edges cannot run",
    ),
    (
        r"^(Multitenant APIs - Provider|Tenant Backup Restore|Tenant Migration)$",
        "not planned",
        "provider-mode Manager",
    ),
    (
        r"^(SD AVC.*|Protocol Pack .*|Cloud Sourced Application .*|Configuration - App Registry|Configuration - Policy App Registry|System - Container|Wani Recommendations|url monitor)$",
        "not planned",
        "SD-AVC, protocol packs and analytics recommendations",
    ),
    (
        r"^(Data Collection Agent|Deployment Mode|HSEC|Hsec|Tools - TAC Cases|CCI Authorization Service.*|Cisco Software|Partner - (ACI Policy Builder|WCM Configs)|Configuration - Multidomain Policy|developers|Rules|Device - Messaging|System - Reverse Proxy)$",
        "not planned",
        "Cisco cloud, FedRAMP, ACI and other partner plumbing",
    ),
]


def main() -> int:
    spec_path = Path(sys.argv[1])
    release = sys.argv[2] if len(sys.argv) > 2 else "20.18.3.1"
    spec = json.loads(spec_path.read_text())
    counts: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    for item in spec["paths"].values():
        for method, op in item.items():
            if method in METHODS:
                for tag in op.get("tags") or ["(untagged)"]:
                    counts[tag][0 if method == "get" else 1] += 1

    rows, unmatched = [], []
    for tag in sorted(counts):
        rule = next((r for r in RULES if re.search(r[0], tag)), None)
        if rule is None:
            unmatched.append(tag)
            continue
        rows.append((rule[1], tag, *counts[tag], rule[2]))
    if unmatched:
        print("unmatched tags:", *unmatched, sep="\n  ", file=sys.stderr)
        return 1

    def order(item: str) -> tuple[int, int]:
        m = re.match(r"W(\d+)", item)
        return (0, int(m.group(1))) if m else ((1, 0) if item == "api_call" else (2, 0))

    by_item: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0, 0])
    for item, _tag, r, w, _note in rows:
        by_item[item][0] += 1
        by_item[item][1] += r
        by_item[item][2] += w

    ops = sum(r + w for _i, _t, r, w, _n in rows)
    out = [
        "# Manager API coverage",
        "",
        f"Every tag in the Manager's OpenAPI document (release {release}, OpenAPI {spec.get('openapi')}, "
        f"{len(spec['paths'])} paths, {len(counts)} tags; operations counted once per tag, {ops} in all) mapped to a "
        "roadmap item. Generated by `scripts/spec_coverage.py` from `GET /apidocs/vmanageapi.json`; rerun it on "
        "each new release (W15) and treat an unmatched tag as a roadmap question. Reads are GET; writes are every "
        "other method, including the statistics and alarm query POSTs that change nothing. `api_call` means "
        "reachable through `catsdwan_api_call` with no tool planned; `not planned` is explained in "
        "[ROADMAP.md](../ROADMAP.md#not-planned).",
        "",
        "## By item",
        "| Item | Tags | Reads | Writes |",
        "|---|---|---|---|",
    ]
    for item in sorted(by_item, key=order):
        t, r, w = by_item[item]
        out.append(f"| {item} | {t} | {r} | {w} |")
    out += ["", "## By tag", "| Item | Tag | Reads | Writes | Note |", "|---|---|---|---|---|"]
    for item, tag, r, w, note in sorted(rows, key=lambda x: (order(x[0]), x[1])):
        out.append(f"| {item} | {tag} | {r} | {w} | {note} |")
    target = Path(__file__).resolve().parent.parent / "docs" / "spec-coverage.md"
    target.parent.mkdir(exist_ok=True)
    target.write_text("\n".join(out) + "\n")
    print(f"{len(rows)} tags -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
