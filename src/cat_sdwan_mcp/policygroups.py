"""Policy-group lifecycle (#94): create, associate / dissociate devices, delete. Pure helpers; the tools are
in tools/policygroups.py. Deploying a policy group is catsdwan_deploy_policy_group (W21).

On 20.18 a policy group holds the policy-side feature profiles of configuration-group devices: one
policy-object profile (the Manager's Default_Policy_Object_Profile holds the shared lists: app lists, data
prefixes, security zones, identity and SGT lists), application priority, embedded security (NGFW, IPS, URL
filtering, AMP, SSL proxy: W47-W49), DNS security and SIG security. Sources (20.18.3.1):
- GET /dataservice/v1/policy-group: a bare list ([] recorded on the lab; the W7 group mcp-w7-pg was listed
  like a configuration group: {id, name, description, solution, profiles: [{id, name, type}],
  numberOfDevices, ...}).
- POST /dataservice/v1/policy-group {name, description, solution: "sdwan", profiles: [{id}]} -> {id}
  (W7 #35: created with only Default_Policy_Object_Profile; answer shape from Cisco's documentation).
- POST / DELETE /dataservice/v1/policy-group/{id}/device/associate {devices: [{id: <chassis>}]} (W7 #35: the
  POST recorded; the DELETE needs its body, sent by catsdwan_api_call since 0.4.0).
- DELETE /dataservice/v1/policy-group/{id}[?deleteProfiles=true]: refused with PLGRP0003 while a device is
  associated (W7 #35), so dissociate first.
"""

from __future__ import annotations

import re
from typing import Any

from cat_sdwan_mcp.client import _as_list

POLICY_GROUP_TYPES = (
    "policy-object",
    "application-priority",
    "embedded-security",
    "dns-security",
    "sig-security",
)
# The Manager's group-name rule for configuration and policy groups (the parcel schemas use the same class).
_NAME = re.compile(r'^[^&<>! "]+$')
NAME_MAX = 128


def name_problem(name: str) -> str | None:
    """Why a policy-group name would be refused, or None."""
    if not name.strip():
        return "the name is empty"
    if len(name) > NAME_MAX:
        return f"the name is longer than {NAME_MAX} characters"
    if not _NAME.match(name):
        return 'the name contains a space or one of & < > ! "'
    return None


def group_profiles(group: dict[str, Any]) -> list[dict[str, Any]]:
    """[{id, name, type}] of a policy group record."""
    return [
        {"id": str(p.get("id")), "name": p.get("name"), "type": p.get("type")}
        for p in _as_list(group.get("profiles"))
        if isinstance(p, dict) and p.get("id")
    ]


def create_body(name: str, description: str, profile_ids: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "solution": "sdwan",
        "profiles": [{"id": i} for i in profile_ids],
    }


def update_body(group: dict[str, Any], profile_ids: list[str]) -> dict[str, Any]:
    """PUT /v1/policy-group/{id}: the group as it is with another profile list."""
    return create_body(str(group.get("name")), str(group.get("description") or ""), profile_ids)


def devices_body(chassis: list[str]) -> dict[str, Any]:
    return {"devices": [{"id": c} for c in chassis]}


def created_id(answer: Any) -> str | None:
    if isinstance(answer, dict):
        for k in ("id", "policyGroupId", "profileId", "parcelId"):
            if answer.get(k):
                return str(answer[k])
    return None


def duplicate_types(profiles: list[dict[str, Any]]) -> list[str]:
    """Profile types given more than once (a policy group holds one profile per type)."""
    seen: dict[str, int] = {}
    for p in profiles:
        seen[str(p.get("type"))] = seen.get(str(p.get("type")), 0) + 1
    return sorted(t for t, n in seen.items() if n > 1)
