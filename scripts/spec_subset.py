#!/usr/bin/env python3
"""Cut a small test fixture out of the Manager's OpenAPI document (GET /apidocs/vmanageapi.json).

The full 20.18 document is 13 MB (2811 paths), too big to commit. This keeps the named paths with every
operation, the `info`/`servers` blocks, and the local `#/components/...` entries they reference
(transitively), so the fixture has the real structure:

    python scripts/spec_subset.py vmanageapi.json tests/fixtures/20.18/spec_subset.json

Stdlib only. External `$ref`s (`schema/...json#/...`) are kept as they are: the Manager's own document
has them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PATHS = [
    "/device",
    "/device/bfd/sessions",
    "/device/bfd/summary",
    "/device/bfd/state/device",
    "/device/tunnel/bfd_statistics",
    "/device/control/connections",
    "/device/action/reboot",
    "/device/action/status/{processId}",
    "/data/device/state/{state_data_type}",
    "/statistics/bfd",
    "/statistics/bfd/page",
    "/statistics/approute",
    "/statistics/approute/page",
    "/statistics/approute/aggregation",
    "/statistics/dynamic/collect",
    "/alarms",
    "/alarms/clear",
    "/alarms/markviewed",
    "/event",
    "/auditlog",
    "/template/device",
    "/template/feature",
    "/template/config/running/{deviceId}",
    "/template/config/attached/{deviceId}",
    "/template/device/config/attachfeature",
    "/template/device/config/attached/{masterTemplateId}",
    "/template/config/diff/{deviceId}",
    "/v1/config-group",
    "/v1/config-group/{configGroupId}",
    "/v1/config-group/{configGroupId}/device/associate",
    "/v1/config-group/{configGroupId}/device/variables",
    "/v1/config-group/{configGroupId}/device/deploy",
    "/v1/config-group/{configGroupId}/device/{deviceId}/preview",
    "/device/action/status/tasks",
    "/template/device/config/input",
    "/template/device/config/config",
    "/template/device/config/attachcli",
    "/v1/policy-group",
    "/v1/policy-group/{policyGroupId}",
    "/v1/feature-profile/sdwan",
    "/v1/feature-profile/sdwan/system",
    "/v1/feature-profile/sdwan/system/{systemId}",
    "/v1/feature-profile/sdwan/transport/{transportId}",
    "/admin/user",
    "/certificate/save/vedge/list",
    "/certificate/vedge/list",
    "/system/device/bootstrap/device/{uuid}",
    "/system/device/fileupload",
    "/system/device/smartaccount/sync",
    # W11 policy
    "/template/policy/vsmart",
    "/template/policy/vsmart/definition/{policyId}",
    "/template/policy/vsmart/activate/{policyId}",
    "/template/policy/vsmart/deactivate/{policyId}",
    "/template/policy/vsmart/connectivity/status",
    "/template/policy/vedge",
    "/template/policy/vedge/definition/{policyId}",
    "/template/policy/definition/approute",
    "/template/policy/definition/approute/{id}",
    "/template/policy/definition/control/{id}",
    "/template/policy/definition/data/{id}",
    "/template/policy/definition/hubandspoke/{id}",
    "/template/policy/list",
    "/template/policy/list/site",
    "/template/policy/list/sla",
    # W12 device operations
    "/device/action/software",
    "/device/action/software/images",
    "/device/action/install",
    "/device/action/changepartition",
    "/device/action/list",
    "/device/software",
    "/device/reboothistory",
    "/device/system/status",
    # W13 history
    "/statistics/dpi",
    "/statistics/dpi/aggregation",
    "/device/control/connectionshistory",
    # W20 configuration history
    "/device/history/config",
    "/device/history/config/{config_id}",
    "/device/history/config/diff/list",
    # W21 feature profiles and policy groups
    "/v1/feature-profile/sdwan/system/{systemId}/basic/{basicId}",
    "/v1/feature-profile/sdwan/system/{systemId}/ntp",
    "/v1/feature-profile/sdwan/system/basic/schema",
    "/v1/feature-profile/sdwan/cli/{cliId}/config/{configId}",
    "/v1/feature-profile/sdwan/cli/config/schema",
    "/v1/policy-group/{policyGroupId}/device/associate",
    "/v1/policy-group/{policyGroupId}/device/{deviceId}/preview",
    "/v1/policy-group/{policyGroupId}/device/deploy",
    # W22 site, tunnel and interface health
    "/statistics/sitehealth/common",
    "/statistics/sitehealth/topology",
    "/health/devices/overview",
    "/network/status",
    "/statistics/tunnelhealth/overview/{type}",
    "/statistics/tunnelhealth/history",
    "/statistics/interface/aggregation",
    "/statistics/interface/ccapacity/distribution",
    "/statistics/qos",
    "/topology/device/site/{siteId}",
    # W16 certificates
    "/certificate/stats/summary",
    "/certificate/data/controller/list",
    "/certificate/data/vedge/list",
    "/certificate/rootcertchains",
    "/certificate/generate/csr",
    "/certificate/install/signedCert",
    "/certificate/vsmart/list",
    "/certificate/forcesync/rootCert",
    "/device/pki/trustpoint",
    # W17 troubleshooting
    "/device/tools/ping/{deviceIP}",
    "/device/tools/nping/{deviceIP}",
    "/device/tools/traceroute/{deviceIP}",
    "/device/tools/servicepath/{deviceIP}",
    "/device/tools/tunnelpath/{deviceIP}",
    "/troubleshooting/devicebringup",
    "/troubleshooting/control/{uuid}",
    "/device/tools/admintech",
    "/device/tools/admintechs",
    "/device/tools/admintechs/inprogress",
    "/device/tools/admintech/download/{filename}",
    # W18 device state
    "/device/ip/ipRoutes",
    "/device/ip/routetable",
    "/device/ip/fib",
    "/device/bgp/neighbors",
    "/device/bgp/routes",
    "/device/ospf/neighbor",
    "/device/ospf/routes",
    "/device/eigrp/interface",
    "/device/eigrp/route",
    "/device/arp",
    "/device/dhcp/client",
    "/device/dhcp/server",
    "/device/dhcp/interface",
    "/device/vrrp",
    "/device/ip/nat/translation",
    "/device/ip/nat/interfacestatistics",
    "/device/interface/error_stats",
    "/device/interface/queue_stats",
    "/device/interface/port_stats",
    "/device/hardware/environment",
    "/device/hardware/alarms",
    "/device/hardware/inventory",
    "/device/crashlog",
    "/device/ntp/associations",
    "/device/ntp/status",
    "/device/lacp/info",
    "/device/lacp/members",
    "/device/cdp/neighbors",
    "/device/lldp/neighbors",
    "/device/staticRouteTracker",
    "/device/endpointTracker",
    "/device/license/usage",
    "/device/license/registration",
    "/device/aaa/users",
    "/device/aaa/servers",
    "/device/users",
    "/device/logging",
    "/device/sdwan-global-drop-statistics",
    "/device/qos/session/summary",
    "/device/policer",
    # W19 path insight
    "/stream/device/nwpi/trace/start",
    "/stream/device/nwpi/trace/stop/{traceId}",
    "/stream/device/nwpi/traceHistory",
    "/stream/device/nwpi/tasks/taskHistory",
]


def _refs(node: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/"):
            out.add(ref)
        for v in node.values():
            out |= _refs(v)
    elif isinstance(node, list):
        for v in node:
            out |= _refs(v)
    return out


def subset(doc: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    missing = [p for p in paths if p not in doc["paths"]]
    if missing:
        raise SystemExit(f"not in the document: {', '.join(missing)}")
    out: dict[str, Any] = {
        "openapi": doc["openapi"],
        "info": doc["info"],
        "servers": doc.get("servers", []),
        "paths": {p: doc["paths"][p] for p in paths},
        "components": {},
    }
    todo = _refs(out["paths"])
    seen: set[str] = set()
    while todo:
        ref = todo.pop()
        if ref in seen:
            continue
        seen.add(ref)
        _, _, kind, name = ref.split("/", 3)
        node = doc.get("components", {}).get(kind, {}).get(name)
        if node is None:
            continue
        out["components"].setdefault(kind, {})[name] = node
        todo |= _refs(node) - seen
    return out


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    doc = json.loads(Path(sys.argv[1]).read_text())
    Path(sys.argv[2]).write_text(json.dumps(subset(doc, PATHS), indent=1) + "\n")


if __name__ == "__main__":
    main()
