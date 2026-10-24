"""W48 edge security profiles (20.18 unified security): the IPS, URL-filtering, AMP and advanced-inspection
parcels of the policy-object profile, and the embedded-security policy that applies them.

Pure helpers; the tools are in tools/securityprofiles.py. Sources (recorded on 20.18.3.1 unless marked):
- GET /v1/feature-profile/sdwan/policy-object (not in the OpenAPI document as a GET, but answered): one
  profile per Manager, `Default_Policy_Object_Profile`; GET .../policy-object/{id} lists its parcels
  (associatedProfileParcels: parcelId, parcelType, payload.name).
- GET /v1/feature-profile/sdwan/policy-object/unified/<type>/schema?schemaType=post: the JSON Schema of each
  security parcel (recorded for the six types below). Every leaf is {optionType: "global", value} (no
  variables, no defaults); references to other parcels are {refId: {optionType: "global", value: <uuid>}}.
- POST /v1/feature-profile/sdwan/policy-object/{id}/unified/<type> {name, description, data} answers
  {parcelId}; PUT/DELETE .../unified/<type>/{parcelId} (spec; not recorded).
- GET /v1/feature-profile/sdwan/embedded-security (answered, not in the spec as a GET; [] on the lab):
  embedded-security feature profiles; POST on the same path {name, description} creates one (the GUI's
  request; not in the spec, not recorded). GET/POST /v1/feature-profile/sdwan/embedded-security/{id}/policy
  and PUT/DELETE .../policy/{parcelId}: the security policy parcel (spec). Its data, from the spec's example:
  assembly [{advancedInspectionProfile: {refId}}, {sslDecryption: {refId}}, {ngfirewall: {refId, entries}}],
  settings {failureMode, ...}, appHosting {nat, databaseUrl, resourceProfile}: the UTD container's resource
  profile and URL database download.
Nothing reaches an edge until the embedded-security profile is in a policy group that is deployed to it
(catsdwan_create_policy_group / catsdwan_associate_policy_group from #94, then catsdwan_deploy_policy_group).
"""

from __future__ import annotations

import re
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest
from cat_sdwan_mcp.client import _as_list
from cat_sdwan_mcp.features import flatten

POLICY_OBJECT_LIST_PATH = "/dataservice/v1/feature-profile/sdwan/policy-object"
POLICY_OBJECT_PATH = POLICY_OBJECT_LIST_PATH + "/{profile}"
UNIFIED_LIST_PATH = POLICY_OBJECT_PATH + "/unified/{kind}"
UNIFIED_PATH = UNIFIED_LIST_PATH + "/{parcel}"
EMBEDDED_LIST_PATH = "/dataservice/v1/feature-profile/sdwan/embedded-security"
EMBEDDED_PATH = EMBEDDED_LIST_PATH + "/{profile}"
SECURITY_POLICY_LIST_PATH = EMBEDDED_PATH + "/policy"
SECURITY_POLICY_PATH = SECURITY_POLICY_LIST_PATH + "/{parcel}"

# The security parcel types of the policy-object profile (the spec's securityProfileParcelType enum).
KINDS = (
    "intrusion-prevention",
    "url-filtering",
    "advanced-malware-protection",
    "advanced-inspection-profile",
    "ssl-decryption",
    "ssl-decryption-profile",
)
KIND_LABEL = {
    "intrusion-prevention": "IPS profile",
    "url-filtering": "URL-filtering profile",
    "advanced-malware-protection": "AMP profile",
    "advanced-inspection-profile": "advanced inspection profile",
    "ssl-decryption": "SSL decryption policy",
    "ssl-decryption-profile": "SSL decryption profile",
}
# Which advanced-inspection field references which kind.
AIP_REFS = {
    "intrusionPrevention": "intrusion-prevention",
    "urlFiltering": "url-filtering",
    "advancedMalwareProtection": "advanced-malware-protection",
    "sslDecryptionProfile": "ssl-decryption-profile",
}

# Web categories (the url-filtering and ssl-decryption-profile schemas share this enum, 20.18.3).
CATEGORIES = (
    "abortion", "abused-drugs", "adult-and-pornography", "alcohol-and-tobacco", "auctions", "bot-nets",
    "business-and-economy", "cdns", "cheating", "computer-and-internet-info",
    "computer-and-internet-security",
    "confirmed-spam-sources", "cult-and-occult", "dating", "dead-sites", "dynamic-content",
    "educational-institutions", "entertainment-and-arts", "fashion-and-beauty", "financial-services",
    "gambling", "games", "government", "gross", "hacking", "hate-and-racism", "health-and-medicine", "home",
    "hunting-and-fishing", "illegal", "image-and-video-search", "individual-stock-advice-and-tools",
    "internet-communications", "internet-portals", "job-search", "keyloggers-and-monitoring", "kids", "legal",
    "local-information", "malware-sites", "marijuana", "military", "motor-vehicles", "music",
    "news-and-media", "nudity", "online-greeting-cards", "online-personal-storage", "open-http-proxies",
    "p2p",
    "parked-sites", "pay-to-surf", "personal-sites-and-blogs", "philosophy-and-political-advocacy",
    "phishing-and-other-frauds", "private-ip-addresses", "proxy-avoid-and-anonymizers", "questionable",
    "real-estate", "recreation-and-hobbies", "reference-and-research", "religion", "search-engines",
    "sex-education", "shareware-and-freeware", "shopping", "social-network", "society", "spam-urls", "sports",
    "spyware-and-adware", "streaming-media", "swimsuits-and-intimate-apparel", "training-and-tools",
    "translation", "travel", "uncategorized", "unconfirmed-spam-sources", "violence", "weapons",
    "web-advertisements", "web-based-email", "web-hosting", "unused-food-and-dining", "unused-reputation",
    "self-harm", "dns-over-https", "low-thc-cannabis-products", "generative-ai",
)  # fmt: skip
REPUTATIONS = ("high-risk", "suspicious", "moderate-risk", "low-risk", "trustworthy")
_NAME = re.compile(r'^[^&<>! "]{1,32}$')
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def g(value: Any) -> dict[str, Any]:
    """A global option leaf."""
    return {"optionType": "global", "value": value}


def ref(parcel_id: str) -> dict[str, Any]:
    return {"refId": g(parcel_id)}


def check_name(name: str, what: str = "name") -> str:
    n = (name or "").strip()
    if not _NAME.match(n):
        raise InvalidRequest(
            f"{what} {name!r}: 1-32 characters, no spaces and none of & < > ! \" (the Manager's rule)."
        )
    return n


def check_categories(values: list[str] | None, what: str) -> list[str]:
    out = []
    for v in values or []:
        c = v.strip().lower().replace(" ", "-").replace("_", "-")
        if c not in CATEGORIES:
            import difflib

            close = difflib.get_close_matches(c, CATEGORIES, n=3, cutoff=0.6)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise InvalidRequest(f"{what}: {v!r} is not a web category.{hint}")
        if c not in out:
            out.append(c)
    return out


def is_uuid(v: str) -> bool:
    return bool(_UUID.match(v.strip()))


# --- profiles and parcels ------------------------------------------------------------------------


def profiles_of(body: Any) -> list[dict[str, Any]]:
    """[{id, name}] from a feature-profile list answer."""
    rows = body.get("data", body) if isinstance(body, dict) else body
    return [
        {"id": str(r["profileId"]), "name": r.get("profileName")}
        for r in _as_list(rows)
        if isinstance(r, dict) and r.get("profileId")
    ]


def parcel_kind(parcel_type: Any) -> str:
    """'unified/intrusion-prevention' (or 'intrusion-prevention') -> 'intrusion-prevention'."""
    return str(parcel_type or "").rsplit("/", 1)[-1]


def parcels_in(profile_body: Any) -> list[dict[str, Any]]:
    """[{id, type, kind, name}] of a profile detail's associatedProfileParcels."""
    body = profile_body if isinstance(profile_body, dict) else {}
    out = []
    for p in _as_list(body.get("associatedProfileParcels")):
        if not isinstance(p, dict) or not p.get("parcelId"):
            continue
        payload = p["payload"] if isinstance(p.get("payload"), dict) else {}
        out.append(
            {
                "id": str(p["parcelId"]),
                "type": str(p.get("parcelType") or ""),
                "kind": parcel_kind(p.get("parcelType")),
                "name": payload.get("name") or p.get("name"),
            }
        )
    return out


def find(parcels: list[dict[str, Any]], kind: str | tuple[str, ...], ref_: str) -> dict[str, Any] | None:
    """The parcel of `kind` whose name or id is `ref_` (case-insensitive), None when there is none."""
    kinds = (kind,) if isinstance(kind, str) else kind
    want = ref_.strip().lower()
    for p in parcels:
        if p["kind"] in kinds and want in (p["id"].lower(), str(p.get("name") or "").lower()):
            return p
    return None


def names_of(parcels: list[dict[str, Any]], kind: str) -> list[str]:
    return sorted(str(p.get("name")) for p in parcels if p["kind"] == kind and p.get("name"))


def data_of(parcel_body: Any) -> dict[str, Any]:
    body = parcel_body if isinstance(parcel_body, dict) else {}
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else body
    data = payload.get("data") if isinstance(payload, dict) else None
    return data if isinstance(data, dict) else {}


def value_of(leaf: Any) -> Any:
    return leaf.get("value") if isinstance(leaf, dict) else leaf


def changes(old: dict[str, Any], new: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{dotted field: {from, to}} between two parcel data blocks (option leaves compared by value)."""
    a = {k: value_of(v) for k, v in flatten(old).items()}
    b = {k: value_of(v) for k, v in flatten(new).items()}
    out = {}
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out[k] = {"from": a.get(k), "to": b.get(k)}
    return out


def plain(data: dict[str, Any]) -> dict[str, Any]:
    """A parcel's data for people: {field: value} (references as 'ref <uuid>')."""
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict) and "refId" in v:
            out[k] = f"ref {value_of(v['refId'])}"
        elif isinstance(v, dict) and "optionType" in v:
            out[k] = v.get("value")
        elif isinstance(v, dict):
            out[k] = plain(v)
        else:
            out[k] = v
    return out


def referencing(aip_bodies: list[tuple[dict[str, Any], Any]], parcel_id: str) -> list[str]:
    """Names of the advanced inspection profiles (parcel row, body) that reference `parcel_id`."""
    out = []
    for row, body in aip_bodies:
        data = data_of(body)
        for f in AIP_REFS:
            leaf = data.get(f)
            if isinstance(leaf, dict) and value_of(leaf.get("refId")) == parcel_id:
                out.append(str(row.get("name")))
                break
    return out


# --- parcel bodies -------------------------------------------------------------------------------


def ips_data(*, signature_set: str, mode: str, log_level: str) -> dict[str, Any]:
    return {
        "signatureSet": g(signature_set),
        "inspectionMode": g(mode),
        "logLevel": g(log_level),
        "customSignature": g(False),
    }


def url_data(
    *,
    action: str,
    categories: list[str],
    reputation: str,
    block_page_text: str | None,
    redirect_url: str | None,
    alerts: list[str],
    allowed_list: str | None,
    blocked_list: str | None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"webCategoriesAction": g(action), "webReputation": g(reputation)}
    if categories:
        data["webCategories"] = g(categories)
    if redirect_url:
        data["blockPageAction"] = g("redirect-url")
        data["redirectUrl"] = g(redirect_url)
    else:
        data["blockPageAction"] = g("text")
        data["blockPageContents"] = g(
            block_page_text
            or "Access to the requested page has been denied. Please contact your Network Administrator"
        )
    data["enableAlerts"] = g(bool(alerts))
    if alerts:
        data["alerts"] = g(alerts)
    if allowed_list:
        data["urlAllowedList"] = ref(allowed_list)
    if blocked_list:
        data["urlBlockedList"] = ref(blocked_list)
    return data


def amp_data(
    *,
    region: str,
    alert: str,
    file_analysis: bool,
    analysis_region: str,
    file_types: list[str],
    analysis_alert: str,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "matchAllVpn": g(True),
        "fileReputationCloudServer": g(region),
        "fileReputationEstServer": g(region),
        "fileReputationAlert": g(alert),
        "fileAnalysisEnabled": g(file_analysis),
    }
    if file_analysis:
        if not file_types:
            raise InvalidRequest("file_analysis needs file_types (e.g. ['pdf', 'ms-exe']).")
        data["fileAnalysisCloudServer"] = g(analysis_region)
        data["fileAnalysisFileTypes"] = g(sorted(set(file_types)))
        data["fileAnalysisAlert"] = g(analysis_alert)
    return data


def aip_data(*, tls_action: str, refs: dict[str, str]) -> dict[str, Any]:
    """refs: {aip field: parcel id} (intrusionPrevention, urlFiltering, advancedMalwareProtection,
    sslDecryptionProfile)."""
    if not any(refs.get(f) for f in ("intrusionPrevention", "urlFiltering", "advancedMalwareProtection")):
        raise InvalidRequest(
            "An advanced inspection profile needs at least one of ips, url_filtering or amp."
        )
    if tls_action == "decrypt" and not refs.get("sslDecryptionProfile"):
        raise InvalidRequest(
            "tls_action='decrypt' needs ssl_decryption_profile (catsdwan_set_ssl_decryption_profile)."
        )
    data: dict[str, Any] = {"tlsDecryptionAction": g(tls_action)}
    for f in AIP_REFS:
        if refs.get(f):
            data[f] = ref(refs[f])
    return data


def policy_data(
    current: dict[str, Any],
    *,
    inspection_id: str | None,
    ssl_decryption_id: str | None,
    failure_mode: str,
    resource_profile: str,
    url_database: bool,
) -> dict[str, Any]:
    """The embedded-security policy parcel's data: the assembly entries given here (advanced inspection, SSL
    decryption) replaced, every other entry kept: one not given (None keeps the stored advanced inspection
    profile or SSL decryption policy), ngfirewall rules from W47, and the settings."""
    given = {
        k
        for k, v in (("advancedInspectionProfile", inspection_id), ("sslDecryption", ssl_decryption_id))
        if v
    }
    keep = [
        e for e in _as_list(current.get("assembly")) if isinstance(e, dict) and not any(k in e for k in given)
    ]
    assembly: list[dict[str, Any]] = []
    if inspection_id:
        assembly.append({"advancedInspectionProfile": ref(inspection_id)})
    if ssl_decryption_id:
        assembly.append({"sslDecryption": ref(ssl_decryption_id)})
    settings = dict(current.get("settings") or {}) if isinstance(current.get("settings"), dict) else {}
    settings["failureMode"] = g(failure_mode)
    app_hosting = dict(current.get("appHosting") or {}) if isinstance(current.get("appHosting"), dict) else {}
    app_hosting.update(
        {"nat": g(True), "databaseUrl": g(url_database), "resourceProfile": g(resource_profile)}
    )
    return {"assembly": [*assembly, *keep], "settings": settings, "appHosting": app_hosting}
