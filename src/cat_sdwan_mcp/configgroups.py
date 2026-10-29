"""Configuration-group lifecycle (W62 #134): create a group from new or existing feature profiles (or a clone
of another group), delete one. Pure helpers; the tools are in tools/configgroups.py. Associating devices is
catsdwan_associate_config_group and pushing is catsdwan_deploy_config_group.

On 20.18 a configuration group for IOS XE WAN edges holds one feature profile per type: system (basic, AAA,
banner, NTP, logging, ...), transport (WAN VPN, its interfaces, the management VPN), service (LAN VPNs) and
CLI (an add-on CLI parcel). A device's own values stay variables, set per device. Sources (20.18.3.1 spec,
operationIds CreateConfigGroup, DeleteConfigGroup, CreateSdwanSystemFeatureProfile and its transport,
service and cli siblings; bodies are Cisco's documented shapes, not recorded on the lab yet):
- POST /dataservice/v1/feature-profile/sdwan/<type> {name, description} -> {id}.
- DELETE /dataservice/v1/feature-profile/sdwan/<type>/{id}: used here only to take back a profile this tool
  created when a later step of the same create fails.
- POST /dataservice/v1/config-group {name, description, solution: "sdwan", profiles: [{id}]} -> {id}.
- DELETE /dataservice/v1/config-group/{id}[?deleteProfiles=true].
- A deep clone copies each parcel: GET .../<type>/{profile}/<parcelType>/{parcel} -> {payload: {name,
  description, data}}, POST .../<type>/{new profile}/<parcelType> with that payload; a subparcel (a WAN VPN's
  interface) is read and posted under its parent: .../<parcelType>/{parent}/<subType>[/{id}].
"""

from __future__ import annotations

from typing import Any

from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.features import as_dict

# The profile types a configuration group for WAN edges holds, in the order the GUI shows them.
GROUP_PROFILE_TYPES = ("system", "transport", "service", "cli")
NEW_PREFIX = "new:"


def parse_profile_ref(value: str) -> tuple[str, str]:
    """('new', name) for 'new:<name>', else ('existing', the name or id)."""
    v = value.strip()
    if v.lower().startswith(NEW_PREFIX):
        return "new", v[len(NEW_PREFIX) :].strip()
    return "existing", v


def profile_body(name: str, description: str) -> dict[str, Any]:
    return {"name": name, "description": description}


def group_body(name: str, description: str, profile_ids: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "solution": "sdwan",
        "profiles": [{"id": i} for i in profile_ids],
    }


def group_profiles(group: dict[str, Any]) -> list[dict[str, Any]]:
    """[{id, name, type}] of a configuration group record."""
    return [
        {"id": str(p.get("id")), "name": p.get("name"), "type": p.get("type")}
        for p in _as_list(group.get("profiles"))
        if isinstance(p, dict) and p.get("id")
    ]


def parcel_tree(profile_body: Any) -> list[dict[str, Any]]:
    """[{id, type, name, subparcels: [{id, type, name}]}] of a profile detail (one level of subparcels: a
    WAN or LAN VPN's interfaces)."""

    def row(p: dict[str, Any]) -> dict[str, Any]:
        payload = as_dict(p.get("payload"))
        return {"id": str(p["parcelId"]), "type": str(p.get("parcelType") or ""), "name": payload.get("name")}

    b = profile_body if isinstance(profile_body, dict) else {}
    out = []
    for p in _as_list(b.get("associatedProfileParcels")):
        if isinstance(p, dict) and p.get("parcelId"):
            subs = [
                row(s) for s in _as_list(p.get("subparcels")) if isinstance(s, dict) and s.get("parcelId")
            ]
            out.append({**row(p), "subparcels": subs})
    return out


def copy_payload(parcel: Any) -> dict[str, Any]:
    """The {name, description, data} to POST for a copy of a parcel read with GET .../{parcelId}."""
    b = as_dict(parcel)
    payload = as_dict(b.get("payload")) or b
    return {k: payload[k] for k in ("name", "description", "data") if k in payload}


def deploy_pending(group: dict[str, Any]) -> str | None:
    """The Manager's deploy state when it says a deploy is still running, else None."""
    state = group.get("state")
    if isinstance(state, str) and any(w in state.lower() for w in ("progress", "pending", "deploying")):
        return " ".join(state.split())
    return None
