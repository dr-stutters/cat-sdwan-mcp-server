"""W21 feature profiles and configuration-group authoring: catsdwan_get_feature_parcel,
catsdwan_set_feature_parcel, catsdwan_associate_config_group, catsdwan_deploy_policy_group.

Tiers: set_feature_parcel and associate_config_group store on the Manager only (write): nothing reaches a
device until a deploy, and the preview's `blast_radius` counts the devices the next deploy of the groups would
reach. deploy_policy_group pushes like W8's deploy: one device is write tier; several devices, a hub or a
protected-site device are dangerous.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import copy
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
    preview_or_apply,
)
from cat_sdwan_mcp.changes import device_brief, preview_text, text_hash
from cat_sdwan_mcp.client import SdwanApp, _as_list
from cat_sdwan_mcp.configuration import (
    ASSOCIATE_PATH,
    CONFIG_GROUPS_PATH,
    POLICY_GROUPS_PATH,
    PROFILE_PATH,
    associated,
    path,
    resolve_group,
)
from cat_sdwan_mcp.features import (
    LISTABLE_TYPES,
    MISSING,
    PARCEL_LIST_PATH,
    PARCEL_PATH,
    POLICY_ASSOCIATE_PATH,
    POLICY_DEPLOY_PATH,
    POLICY_GROUP_PATH,
    POLICY_PREVIEW_PATH,
    PROFILE_LIST_PATH,
    SCHEMA_PATH,
    as_dict,
    check_leaf,
    cli_diff,
    cli_undo,
    data_schema,
    default_leaf,
    defaults_for,
    field_names,
    field_schema,
    get_at,
    is_leaf,
    is_required,
    masked_change,
    missing_required,
    parcel_url,
    parcel_view,
    parcels_of,
    pick_parcel,
    request_schema,
    set_at,
    to_leaf,
)
from cat_sdwan_mcp.features import cli_replace as replace_cli
from cat_sdwan_mcp.hubs import change_tier
from cat_sdwan_mcp.inventory import load_inventory
from cat_sdwan_mcp.servicevpns import vpn_context
from cat_sdwan_mcp.tools.changes import (
    AllowPendingCertificate,
    _certificate_problems,
    _device_view,
    _pending_blockers,
    _reachability_blockers,
    _resolve_devices,
    _running,
    _started,
    dangerous_blockers,
)
from cat_sdwan_mcp.tools.configuration import _associated, _groups

ProfileRef = Annotated[
    str,
    Field(
        description="Feature profile name or id (e.g. 'mcp-test-system'), or a configuration group name to "
        "search all of its profiles"
    ),
]
ParcelRef = Annotated[
    str,
    Field(
        description="Parcel name, id or type within the profile (e.g. 'basic', 'ntp', 'wan/vpn', 'config')"
    ),
]
NOTHING_PUSHED = (
    "Stores the parcel on the Manager only: no device changes until each configuration group using the "
    "profile is deployed (catsdwan_deploy_config_group); until then those groups show their devices out "
    "of date."
)


# --- profile and parcel lookup -------------------------------------------------------------------


def _group_profiles(groups: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """{profile id: {id, name, type, groups: [group names]}} from the configuration groups."""
    out: dict[str, dict[str, Any]] = {}
    for g in groups:
        for p in _as_list(g.get("profiles")):
            if isinstance(p, dict) and p.get("id"):
                row = out.setdefault(
                    str(p["id"]),
                    {"id": str(p["id"]), "name": p.get("name"), "type": p.get("type"), "groups": []},
                )
                row["groups"].append(str(g.get("name")))
    return out


async def _listed_profiles(app: SdwanApp) -> list[dict[str, Any]]:
    """Every profile the Manager lists, type by type (profiles in no configuration group too)."""

    async def one(t: str) -> list[dict[str, Any]]:
        try:
            body = await app.api.get(path(PROFILE_LIST_PATH, type=t))
        except UpstreamError:
            return []
        return [
            {"id": str(r["profileId"]), "name": r.get("profileName"), "type": r.get("profileType") or t}
            for r in _as_list(body.get("data") if isinstance(body, dict) else body)
            if isinstance(r, dict) and r.get("profileId")
        ]

    got = await asyncio.gather(*(one(t) for t in LISTABLE_TYPES))
    return [p for rows in got for p in rows]


async def _find_profiles(app: SdwanApp, ref: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """(candidate profiles, configuration groups, where): a configuration group's profiles when `ref` names
    a group, else the one profile `ref` names."""
    groups = await _groups(app, CONFIG_GROUPS_PATH)
    known = _group_profiles(groups)
    want = ref.strip().lower()
    for g in groups:
        if want in (str(g.get("id", "")).lower(), str(g.get("name", "")).lower()):
            profiles = [known[str(p["id"])] for p in _as_list(g.get("profiles")) if str(p.get("id")) in known]
            if not profiles:
                raise InvalidRequest(f"Configuration group {g.get('name')} has no feature profiles.")
            return profiles, groups, f"configuration group {g.get('name')}"
    pool = list(known.values())
    found = [p for p in pool if want in (p["id"].lower(), str(p.get("name") or "").lower())]
    if not found:
        listed = await _listed_profiles(app)
        pool += [p for p in listed if p["id"] not in known]
        found = [p for p in pool if want in (p["id"].lower(), str(p.get("name") or "").lower())]
    if len(found) == 1:
        return found, groups, f"profile {found[0]['name']} ({found[0]['type']})"
    if len(found) > 1:
        names = ", ".join(f"{p['name']} ({p['type']}, {p['id']})" for p in found)
        raise InvalidRequest(f"{ref!r} matches several profiles: {names}. Give the id.")
    known_names = sorted({str(p.get("name")) for p in pool if p.get("name")})
    raise NotFound(
        f"No feature profile or configuration group matches {ref!r}. "
        f"Profiles: {', '.join(known_names[:30]) or 'none'}."
    )


async def _profile_parcels(app: SdwanApp, profile: dict[str, Any]) -> list[dict[str, Any]]:
    body = await app.api.get(path(PROFILE_PATH, type=str(profile["type"]), id=profile["id"]))
    return [{**p, "profile": profile} for p in parcels_of(body)]


async def _locate(
    app: SdwanApp, profile_ref: str, parcel_ref: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(the parcel {id, type, name, profile}, the configuration groups)."""
    profiles, groups, where = await _find_profiles(app, profile_ref)
    parcels = [
        p for rows in await asyncio.gather(*(_profile_parcels(app, p) for p in profiles)) for p in rows
    ]
    return pick_parcel(parcels, parcel_ref, where), groups


async def _read_parcel(app: SdwanApp, parcel: dict[str, Any]) -> dict[str, Any]:
    prof = parcel["profile"]
    url = parcel_url(
        PARCEL_PATH,
        ptype=str(prof["type"]),
        parcel_type=parcel["type"],
        profile=prof["id"],
        parcel=parcel["id"],
    )
    body = await app.api.get(url)
    return body if isinstance(body, dict) else {}


async def _schema(
    app: SdwanApp, ptype: str, parcel_type: str, kind: str
) -> tuple[dict[str, Any], str | None]:
    """(the data schema, why it couldn't be read)."""
    try:
        url = parcel_url(SCHEMA_PATH, ptype=ptype, parcel_type=parcel_type)
        body = await app.api.get(url, {"schemaType": kind})
    except UpstreamError as e:
        return {}, f"the parcel schema was not read: {str(e)[:200]}"
    d = data_schema(request_schema(body))
    return d, None if d else "the Manager returned no schema for this parcel type"


async def _reach(
    app: SdwanApp, groups: list[dict[str, Any]], profile_id: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """The configuration groups using a profile, each with its devices, and read problems."""
    using = [
        g
        for g in groups
        if any(str(p.get("id")) == profile_id for p in _as_list(g.get("profiles")) if isinstance(p, dict))
    ]
    got = await asyncio.gather(*(_associated(app, str(g["id"])) for g in using), return_exceptions=True)
    out, warnings = [], []
    for g, devs in zip(using, got, strict=True):
        if isinstance(devs, UpstreamError):
            warnings.append(f"{g.get('name')}: devices not read: {str(devs)[:200]}")
            devs = []
        elif isinstance(devs, BaseException):
            raise devs
        out.append(
            {
                "group": g.get("name"),
                "devices": [str(d.get("host") or d.get("chassis")) for d in devs],
            }
        )
    return out, warnings


def controller_outcome(result: dict[str, Any], chassis: list[str]) -> dict[str, Any]:
    """A policy-group deploy whose edges succeeded but whose controller row failed did not apply the policy
    (#118): report it as failed with the controller's reason, not partial."""
    if not isinstance(result, dict) or result.get("outcome") != "partial":
        return result
    devs = [d for d in result.get("devices") or [] if isinstance(d, dict)]
    failed = [d for d in devs if d.get("status") == "failure"]
    if not failed or any(str(d.get("chassis")) in chassis for d in failed):
        return result
    return {
        **result,
        "outcome": "failed",
        "controller_failure": [d.get("reason") or d.get("detail") for d in failed],
        "note": "the edges took the configuration but the controller refused the policy group, so it is not "
        "in effect; fix the reason and deploy again",
    }


def _names(rows: list[dict[str, Any]]) -> list[str]:
    return [str(r.get("host") or r.get("chassis")) for r in rows]


def _field_summary(dschema: dict[str, Any]) -> dict[str, Any]:
    """{field: allowed option types, value type, enum (first few), range, the schema default}, for
    authoring."""
    out: dict[str, Any] = {}
    for name in field_names(dschema):
        fs = field_schema(dschema, name.replace("[i]", "[0]"))
        if fs is None:
            continue
        row: dict[str, Any] = {}
        branches = [br for br in _as_list(fs.get("oneOf")) if isinstance(br, dict)]
        kinds = []
        for br in branches:
            kinds += _as_list(((br.get("properties") or {}).get("optionType") or {}).get("enum"))
            if "global" in _as_list(((br.get("properties") or {}).get("optionType") or {}).get("enum")):
                vs = (br.get("properties") or {}).get("value") or {}
                row["type"] = vs.get("type")
                if isinstance(vs.get("enum"), list):
                    row["enum"] = vs["enum"][:10] + (["..."] if len(vs["enum"]) > 10 else [])
                if "minimum" in vs or "maximum" in vs:
                    row["range"] = [vs.get("minimum"), vs.get("maximum")]
        if kinds:
            row["option_types"] = kinds
        elif fs.get("type"):
            row["type"] = fs.get("type")
        if (d := default_leaf(fs)) is not None:
            row["default"] = d.get("value", "(none)")
        if is_required(dschema, name):
            row["required"] = True
        out[name] = {k: v for k, v in row.items() if v is not None}
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get SD-WAN feature parcel")
    async def catsdwan_get_feature_parcel(
        ctx: Context,
        profile: ProfileRef,
        parcel: Annotated[
            str | None,
            Field(description="Parcel name, id or type; omit to list the profile's (or group's) parcels"),
        ] = None,
        fields: Annotated[
            bool,
            Field(
                description="Add the parcel type's fields from the Manager's schema (option types, value "
                "type, enum, range, default, required): what catsdwan_set_feature_parcel accepts"
            ),
        ] = False,
    ) -> ToolResult:
        """A feature-profile parcel (configuration groups, 20.12+) with its values by source: `configured`
        (global values, and variables as {{name}} filled per device by catsdwan_set_device_variables),
        `defaults` (left at the schema's default), the variables, and for the CLI profile's config parcel the
        CLI text (secrets masked). Also the configuration groups using the profile and their devices, i.e.
        what a change would reach once deployed. Without `parcel`: the profile's parcels (name, type, id).
        `profile` can be a configuration group name to search all its profiles."""
        app: SdwanApp = get_client(ctx)
        if parcel is None:
            profiles, _, where = await _find_profiles(app, profile)
            rows = [p for r in await asyncio.gather(*(_profile_parcels(app, p) for p in profiles)) for p in r]
            return object_result(
                {
                    "where": where,
                    "parcels": [
                        {
                            "profile": p["profile"]["name"],
                            "profile_type": p["profile"]["type"],
                            "name": p["name"],
                            "type": p["type"],
                            "id": p["id"],
                            **({"subparcels": p["subparcels"]} if p["subparcels"] else {}),
                        }
                        for p in rows
                    ],
                },
                fmt="json",
            )
        found, groups = await _locate(app, profile, parcel)
        prof = found["profile"]
        body = await _read_parcel(app, found)
        out: dict[str, Any] = {
            "profile": {"name": prof["name"], "type": prof["type"], "id": prof["id"]},
            **parcel_view(body),
        }
        reach, warnings = await _reach(app, groups, prof["id"])
        out["used_by"] = reach or "no configuration group uses this profile"
        if found["subparcels"]:
            out["subparcels"] = f"{found['subparcels']} (not shown: read them with catsdwan_api_call)"
        if fields:
            dschema, why = await _schema(app, str(prof["type"]), found["type"], "put")
            if why:
                warnings.append(why)
            else:
                out["fields"] = _field_summary(dschema)
        if warnings:
            out["warnings"] = warnings
        return object_result(out, fmt="json")

    @reg.write(title="Set SD-WAN feature parcel", idempotent=True)
    async def catsdwan_set_feature_parcel(
        ctx: Context,
        profile: ProfileRef,
        parcel: ParcelRef,
        values: Annotated[
            dict[str, Any] | None,
            Field(
                description="Field path -> new value, e.g. {'consoleBaudRate': '115200', 'clock.timezone': "
                "'Europe/London'}. A value is global; '{{name}}' makes it a device variable; null resets it "
                "to the schema's default; {'optionType': global|variable|default, 'value': ...} is taken as "
                "given and schema-checked like any value. Paths as "
                "catsdwan_get_feature_parcel(fields=true) lists them; list items as name[0].field"
            ),
        ] = None,
        cli_replace: Annotated[
            dict[str, str] | None,
            Field(
                description="CLI parcel only: old text -> new text in its CLI (each old text must occur "
                "exactly once), e.g. {'banner motd #{{banner_motd}}#': 'banner motd #Authorised use only#'}"
            ),
        ] = None,
        new_parcel_name: Annotated[
            str | None,
            Field(
                description="Create a parcel instead: `parcel` is then its type (e.g. 'ntp') and every "
                "required field the schema can default is filled in"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="New parcel only: its description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a feature-profile parcel's values (or create a parcel) in a configuration group's profile.
        Preview-first: old -> new per field (secrets masked; changed CLI lines for the CLI parcel), every
        value checked against the Manager's own schema for the parcel type before anything is sent (wrong
        type, not in the enum, out of range, a required field missing: all reported at once, where the Manager
        reports one round at a time), and the configuration groups using the profile with the devices they
        reach (`blast_radius`). Confirm PUTs the parcel (POST for a new one). It only STORES the change: no
        device changes until catsdwan_deploy_config_group, which shows the CLI per device first."""
        app: SdwanApp = get_client(ctx)
        values = values or {}
        edits = cli_replace or {}
        if not values and not edits and new_parcel_name is None:
            raise InvalidRequest("Give `values` or `cli_replace`.")
        blockers: list[str] = []
        warnings: list[str] = []
        creating = new_parcel_name is not None
        if creating:
            profiles, groups, where = await _find_profiles(app, profile)
            if len(profiles) != 1:
                types = ", ".join(f"{p['name']} ({p['type']})" for p in profiles)
                raise InvalidRequest(
                    f"{where} has several profiles ({types}): name the profile to create in."
                )
            prof = profiles[0]
            ptype = parcel.strip().lower()
            existing = await _profile_parcels(app, prof)
            if any(
                str(p.get("name") or "").lower() == str(new_parcel_name).strip().lower() for p in existing
            ):
                blockers.append(f"profile {prof['name']} already has a parcel named {new_parcel_name!r}")
            body: dict[str, Any] = {}
            dschema, why = await _schema(app, str(prof["type"]), ptype, "post")
            if why:
                blockers.append(f"{why}: a new parcel can't be checked, so it isn't created")
            current_data, unresolved = defaults_for(dschema)
            found: dict[str, Any] = {"type": ptype, "name": new_parcel_name, "profile": prof, "id": None}
        else:
            found, groups = await _locate(app, profile, parcel)
            prof = found["profile"]
            ptype = found["type"]
            body = await _read_parcel(app, found)
            dschema, why = await _schema(app, str(prof["type"]), ptype, "put")
            if why:
                warnings.append(
                    f"{why}: only fields the parcel already has can be changed, and values aren't checked"
                )
            payload = as_dict(body.get("payload"))
            current_data = copy.deepcopy(as_dict(payload.get("data")))
            unresolved = []
        new_data = copy.deepcopy(current_data)
        changes: dict[str, dict[str, Any]] = {}
        for p, value in values.items():
            fs = field_schema(dschema, p) if dschema else None
            old = get_at(current_data, p)
            if dschema and fs is None:
                known = ", ".join(field_names(dschema)[:40])
                blockers.append(f"{ptype} has no field {p!r} (its fields: {known})")
                continue
            if not dschema and old is MISSING:
                blockers.append(f"{ptype} parcel has no field {p!r} set (and the schema isn't available)")
                continue
            try:
                leaf = to_leaf(fs, old, value)
                if fs is not None and (bad := check_leaf(fs, leaf)):
                    blockers.append(f"{p}: {bad}")
                    continue
                set_at(new_data, p, leaf)
            except InvalidRequest as e:
                blockers.append(f"{p}: {e}")
                continue
            if old != leaf:
                changes[p] = masked_change(p, old, leaf)
        cli_lines: list[str] = []
        if edits:
            text = get_at(new_data, "config")
            if not isinstance(text, str) or is_leaf(text):
                blockers.append(
                    f"cli_replace is for the CLI profile's config parcel; {ptype} has no CLI text"
                )
            else:
                new_text, problems = replace_cli(text, edits)
                blockers += problems
                if new_text != text:
                    new_data["config"] = new_text
                    cli_lines = cli_diff(text, new_text)
        if dschema:
            still = sorted(set(missing_required(dschema, new_data)) | set(unresolved))
            given = set(values)
            still = [m for m in still if m not in given]
            if still:
                blockers.append(
                    "required fields with no value (the schema has no default for them): " + ", ".join(still)
                )
        if not creating and not changes and not cli_lines and not blockers:
            blockers.append("nothing to change: every value is already as given")
        reach, reach_warn = await _reach(app, groups, str(prof["id"]))
        warnings += reach_warn
        devices = sorted({d for g in reach for d in g["devices"]})
        if creating:
            req = (
                f"POST {PARCEL_LIST_PATH.format(type=prof['type'], profile='{profileId}', parcel_type=ptype)}"
            )
            summary = f"Create {ptype} parcel {new_parcel_name} in feature profile {prof['name']}"
        else:
            shape = PARCEL_PATH.format(
                type=prof["type"], profile="{profileId}", parcel_type=ptype, parcel="{parcelId}"
            )
            req = f"PUT {shape}"
            n = len(changes) + (1 if cli_lines else 0)
            summary = f"Change {n} field(s) of {ptype} parcel {found['name']} in {prof['name']}"
        details: dict[str, Any] = {
            "profile": {"name": prof["name"], "type": prof["type"]},
            "parcel": {"name": found["name"], "type": ptype, **({"id": found["id"]} if found["id"] else {})},
            "changes": changes,
            **({"cli_changes": cli_lines} if cli_lines else {}),
            **({"new_parcel_fields": {k: str(v) for k, v in new_data.items()}} if creating else {}),
            "reaches": reach or "no configuration group uses this profile: no device is affected",
            "schema_check": "passed"
            if dschema and not blockers
            else ("not available" if not dschema else "failed"),
            "request": req,
            **({"warnings": warnings} if warnings else {}),
        }
        if creating:
            details["undo"] = "delete the new parcel (catsdwan_api_call DELETE on its path, preview-first)"
        elif cli_lines and not changes:
            text = get_at(current_data, "config")
            undo = cli_undo(text, edits) if isinstance(text, str) else None
            details["undo"] = (
                {"cli_replace": undo}
                if undo
                else "re-PUT the parcel read before the change (catsdwan_get_feature_parcel shows its CLI)"
            )
        else:
            details["undo"] = (
                "catsdwan_set_feature_parcel with the 'from' values (null for a field that was default), or "
                "re-PUT the parcel read before the change (catsdwan_get_feature_parcel shows it)"
            )
        plan = Plan(
            summary,
            details=details,
            side_effects=[NOTHING_PUSHED],
            fingerprint={
                "parcel": [body.get("lastUpdatedOn"), (body.get("payload") or {}).get("data")]
                if body
                else None,
                "groups": reach,
            },
            blockers=blockers,
            blast_radius=len(devices),
        )

        async def apply() -> Any:
            if creating:
                url = parcel_url(
                    PARCEL_LIST_PATH, ptype=str(prof["type"]), parcel_type=ptype, profile=prof["id"]
                )
                out_body = {"name": new_parcel_name, "description": description or "", "data": new_data}
                answer = await app.api.post(url, out_body)
            else:
                payload = as_dict(body.get("payload"))
                url = parcel_url(
                    PARCEL_PATH,
                    ptype=str(prof["type"]),
                    parcel_type=ptype,
                    profile=prof["id"],
                    parcel=found["id"],
                )
                out_body = {
                    "name": payload.get("name"),
                    "description": payload.get("description") or "",
                    "data": new_data,
                }
                answer = await app.api.put(url, out_body)
            names = [str(g["group"]) for g in reach]
            return {
                "stored": changes or ("new parcel" if creating else "CLI text"),
                **({"cli_changes": cli_lines} if cli_lines else {}),
                "parcel_id": (answer or {}).get("parcelId") if isinstance(answer, dict) else None,
                "next": (
                    f"catsdwan_deploy_config_group(group={names[0]!r}, devices=[...]) pushes it "
                    "(preview first)"
                    if names
                    else "no configuration group uses this profile yet"
                ),
            }

        return await preview_or_apply(
            ctx,
            tool="catsdwan_set_feature_parcel",
            args={
                "profile": profile,
                "parcel": parcel,
                "values": values,
                "cli_replace": edits,
                "new_parcel_name": new_parcel_name,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Associate devices with SD-WAN configuration group")
    async def catsdwan_associate_config_group(
        ctx: Context,
        group: Annotated[str, Field(description="Configuration group name or id")],
        add: Annotated[
            list[str] | None, Field(description="Devices to associate (host name, system IP or chassis)")
        ] = None,
        remove: Annotated[list[str] | None, Field(description="Devices to remove from the group")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add devices to or remove them from a configuration group (POST / DELETE .../device/associate).
        Preview-first: the group's devices before and after. Blocked for a device on a device template (a
        device is in a configuration group or on a template, never both: detach it first), a device in another
        configuration group, a device already in (add) or not in (remove) this group. Nothing is pushed: an
        added device needs its variables (catsdwan_set_device_variables) and a deploy; a removed device
        keeps its running configuration; the Manager stops managing it until it joins a group or template."""
        if not add and not remove:
            raise InvalidRequest("Give devices to `add` or `remove`.")
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, CONFIG_GROUPS_PATH), group)
        gid, gname = str(found.get("id")), str(found.get("name"))
        inv = await load_inventory(app)
        adds = _resolve_devices(inv, add or [])
        removes = _resolve_devices(inv, remove or [])
        current = await _associated(app, gid)
        in_group = {str(a.get("chassis")) for a in current}
        blockers: list[str] = []
        both = {str(r["chassis"]) for r in adds} & {str(r["chassis"]) for r in removes}
        if both:
            blockers.append("a device can't be both added and removed")
        for r in adds:
            host = r.get("host") or r.get("chassis")
            if str(r["chassis"]) in in_group:
                blockers.append(f"{host} is already in configuration group {gname}")
            elif r.get("config_mode") == "template":
                blockers.append(
                    f"{host} is attached to device template {r.get('config') or '?'}: a device is in a "
                    "configuration group or on a template, never both (detach it first)"
                )
            elif r.get("config_mode") == "configuration group" and str(r.get("config") or "") not in (
                "",
                gname,
            ):
                blockers.append(
                    f"{host} is in configuration group {r.get('config')}: remove it from there first"
                )
        for r in removes:
            if str(r["chassis"]) not in in_group:
                blockers.append(f"{r.get('host') or r.get('chassis')} is not in configuration group {gname}")
        before = [str(a.get("host") or a.get("chassis")) for a in current]
        after = sorted((set(before) - set(_names(removes))) | set(_names(adds)))
        plan = Plan(
            f"Configuration group {gname}: add {len(adds)}, remove {len(removes)} device(s)",
            details={
                "group": gname,
                "add": [device_brief(r) for r in adds],
                "remove": [device_brief(r) for r in removes],
                "devices_before": before,
                "devices_after": after,
                "requests": [
                    *([f"POST {ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"] if adds else []),
                    *([f"DELETE {ASSOCIATE_PATH} {{devices: [{{id: <chassis>}}]}}"] if removes else []),
                ],
                "undo": "the same call with add and remove swapped",
            },
            side_effects=[
                "Nothing is pushed to a device. An added device needs its variables "
                "(catsdwan_set_device_variables) and a deploy (catsdwan_deploy_config_group).",
                *(
                    [
                        "A removed device keeps its running configuration but is no longer managed by "
                        "the group."
                    ]
                    if removes
                    else []
                ),
            ],
            fingerprint={"group": found.get("lastUpdatedOn"), "devices": sorted(in_group)},
            blockers=blockers,
            blast_radius=len(adds) + len(removes),
        )

        async def apply() -> Any:
            url = path(ASSOCIATE_PATH, id=gid)
            done: dict[str, Any] = {}
            if adds:
                await app.api.post(url, {"devices": [{"id": str(r["chassis"])} for r in adds]})
                done["added"] = _names(adds)
            if removes:
                await app.api.delete(url, json={"devices": [{"id": str(r["chassis"])} for r in removes]})
                done["removed"] = _names(removes)
            now = await _associated(app, gid)
            done["devices_now"] = [str(a.get("host") or a.get("chassis")) for a in now]
            if adds:
                done["next"] = (
                    "catsdwan_set_device_variables for each added device, then catsdwan_deploy_config_group"
                )
            return done

        return await preview_or_apply(
            ctx,
            tool="catsdwan_associate_config_group",
            args={"group": group, "add": add, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Deploy SD-WAN policy group", task=True)
    async def catsdwan_deploy_policy_group(
        ctx: Context,
        group: Annotated[str, Field(description="Policy group name or id (catsdwan_list_policy_groups)")],
        devices: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Devices by host name, system IP or chassis. One device is write tier; more than "
                "one, or a hub / protected-site device, is dangerous",
            ),
        ],
        show_cli: Annotated[bool, Field(description="Include the full intended CLI per device")] = True,
        wait: Annotated[bool, Field(description="Wait for every device to report success or failure")] = True,
        allow_pending_certificate: AllowPendingCertificate = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push a policy group (application priority, NGFW, SIG / DNS security profiles; the 20.12+ policy
        counterpart of configuration groups) to some of its devices. Preview-first: per device the Manager's
        own preview (POST /v1/policy-group/{id}/device/{deviceId}/preview) and its diff against the running
        configuration, secrets masked. Blocked for a device not associated with the group, on a device
        template, unreachable, with an action still running or with its certificate not installed (the
        Manager would only queue the deploy and report success; allow_pending_certificate=true makes that a
        warning). Confirm deploys (POST .../device/deploy) and
        follows the action status per device. The controller step is prechecked too (#118): every traffic
        policy target must be a LAN VPN parcel name, and every VPN of a zone the security policy binds a LAN
        VPN parcel, in each device's configuration group; otherwise the controller refuses the group after
        the edges took it ("Please configure the VPN's ..."), so the preview is blocked with the fix. A
        controller failure is reported as failed, not partial. One device is write tier; several, a hub or a
        protected-site device need MCP_ENABLE_DANGEROUS (hubs: CATSDWAN_HUB_DEVICES, else found from
        hub-and-spoke topologies and BFD; `hub_status` in the preview)."""
        app: SdwanApp = get_client(ctx)
        found = resolve_group(await _groups(app, POLICY_GROUPS_PATH), group, "policy group")
        gid, gname = str(found.get("id")), str(found.get("name"))
        inv = await load_inventory(app)
        rows = _resolve_devices(inv, devices)
        blockers: list[str] = []
        warnings: list[str] = list(inv.warnings)
        try:
            assoc = {
                str(a.get("chassis")): a
                for a in associated(await app.api.get(path(POLICY_ASSOCIATE_PATH, id=gid)))
            }
        except UpstreamError as e:
            assoc = {}
            blockers.append(f"the policy group's devices were not read: {str(e)[:200]}")
        for r in rows:
            host = r.get("host") or r.get("chassis")
            if r.get("config_mode") == "template":
                blockers.append(
                    f"{host} is on device template {r.get('config') or '?'}: policy groups are for "
                    "configuration-group devices"
                )
            elif assoc and str(r["chassis"]) not in assoc:
                blockers.append(f"{host} is not associated with policy group {gname}")
        blockers += _reachability_blockers(rows)
        (warnings if allow_pending_certificate else blockers).extend(_certificate_problems(rows))
        busy, busy_warn = await _pending_blockers(app, rows)
        blockers += busy
        warnings += busy_warn
        reasons, hubs = await change_tier(app, inv, rows)
        warnings += hubs.warnings
        blockers += dangerous_blockers(ctx, app, reasons)
        # The controller's half (#118): VPN references must name the devices' LAN VPN parcels.
        from cat_sdwan_mcp.tools.policyvpns import group_vpn_problems

        controller: dict[str, Any] = {}
        try:
            detail = await app.api.get(path(POLICY_GROUP_PATH, id=gid))
            detail = detail if isinstance(detail, dict) and detail.get("profiles") is not None else found
            vctx = await vpn_context(app, [str(r["chassis"]) for r in rows])
            vpn_block, controller, vpn_warn = await group_vpn_problems(app, detail, vctx)
            blockers += vpn_block
            warnings += vpn_warn + list(vctx.get("warnings") or [])
        except UpstreamError as e:
            warnings.append(f"controller precheck (policy VPNs) not run: {str(e)[:200]}")

        async def one(r: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
            c = str(r["chassis"])
            view: dict[str, Any] = device_brief(r)
            new: str | None = None
            try:
                new = preview_text(await app.api.post(path(POLICY_PREVIEW_PATH, id=gid, device=c), {}))
                if new is None:
                    view["preview_unavailable"] = "the Manager's preview returned no configuration text"
            except UpstreamError as e:
                view["preview_unavailable"] = str(e)[:300]
            running, note = await _running(app, c)
            if note:
                view["note"] = note
            view.update(_device_view(new, running, show_cli))
            return view, text_hash(new)

        got = await asyncio.gather(*(one(r) for r in rows))
        blockers += [
            f"{v.get('host') or v.get('chassis')}: no preview from the Manager ({v['preview_unavailable']})"
            for v, _ in got
            if v.get("preview_unavailable")
        ]
        chassis = [str(r["chassis"]) for r in rows]
        plan = Plan(
            f"Deploy policy group {gname} to {len(rows)} device(s): "
            + ", ".join(str(r.get("host") or r.get("chassis")) for r in rows),
            details={
                "group": gname,
                "tier": "dangerous" if reasons else "write",
                **({"tier_reasons": reasons} if reasons else {}),
                **({"hub_status": hubs.status} if hubs.status else {}),
                "devices": [v for v, _ in got],
                "request": f"POST {POLICY_DEPLOY_PATH} {{devices: [{{id: <chassis>}}]}}",
                "controller_step": {
                    "what": "after the edges, the Manager generates the group's policy for the controller; "
                    "it refuses VPN references that are not the devices' LAN VPN parcels",
                    **controller,
                },
                "rollback": "The Manager has no undo: change the policy group's profiles back and deploy "
                "again.",
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                "Pushes the policy group's configuration to each device (QoS, firewall, security)."
            ],
            fingerprint={
                "group": [found.get("lastUpdatedOn"), found.get("version")],
                "devices": dict(zip(chassis, (h for _, h in got), strict=True)),
                "controller": controller,
            },
            blockers=blockers,
            blast_radius=len(rows),
        )

        async def apply() -> Any:
            answer = await app.api.post(
                path(POLICY_DEPLOY_PATH, id=gid), {"devices": [{"id": c} for c in chassis]}
            )
            return controller_outcome(
                await _started(app, ctx, answer, wait, f"deploy of policy group {gname}"), chassis
            )

        return await preview_or_apply(
            ctx,
            tool="catsdwan_deploy_policy_group",
            args={
                "group": group,
                "devices": devices,
                "show_cli": show_cli,
                "wait": wait,
                "allow_pending_certificate": allow_pending_certificate,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
