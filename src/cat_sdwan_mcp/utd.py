"""W48 the UTD engine (Snort IPS, URL filtering, AMP in an IOx container on the edge): the image in the
Manager's virtual-image repository, and per edge whether it can run, is installed and is up.

Pure helpers; the tools are in tools/utd.py. Sources (recorded on 20.18.3.1, a lab with no UTD anywhere):
- GET /device/action/software/images?imageType=<type> (imageType required): the repository grid, keys
  software, container, lxc, virtualmachine, ...; rows {versionId, availableFiles, versionName, versionType,
  imageType, fileSizeStr, ...}; [] on the lab. The UTD image is listed under the virtual images.
- POST /device/action/software/package/{imageType} (multipart/form-data, one part `file`): the upload (spec;
  not recorded, the type the Manager files it under is read back from the repository afterwards).
- GET /device/utd/version-status?deviceId=<system-ip>: {utd-version-status-recommended-version
  '1.1.0_SV3.3.5.0_XE17.18', -supported-regex '^1\\.1\\.([0-9]+)_SV(.*)_XE17.18$', -supported 'false'}.
- GET /device/virtualApplication/utd?deviceId=: installed UTD (version, active, previous); [] when none.
- GET /device/app-hosting/details?deviceId=: IOx apps (name, state, package-info-name,
  application-installed-version, resource-reservation-memory, resource-admission-*); [] when none.
- GET /device/utd/engine-status?deviceId=: the Snort engines (W23 reads them too); [] when none.
- GET /device/system/status?deviceId=: mem_total in KB (4987936 on a 5 GB C8000V).
There is no separate install call: the Manager installs the image from the repository on every edge a policy
group with UTD features (IPS, URL filtering, AMP) is deployed to. UTD on a C8000V needs 8 GB of RAM.
"""

from __future__ import annotations

import re
from typing import Any

IMAGES_PATH = "/dataservice/device/action/software/images"
UPLOAD_PATH = "/dataservice/device/action/software/package/{image_type}"
VERSION_STATUS_PATH = "/dataservice/device/utd/version-status"
INSTALLED_PATH = "/dataservice/device/virtualApplication/utd"
APP_HOSTING_PATH = "/dataservice/device/app-hosting/details"
ENGINE_PATH = "/dataservice/device/utd/engine-status"
SYSTEM_STATUS_PATH = "/dataservice/device/system/status"

# Repository types the UTD image can be filed under (the grid's keys for container images).
IMAGE_TYPES = ("lxc", "container", "virtualmachine")
# UTD on a C8000V (and a CSR1000v) needs an 8 GB VM; IOS XE reports a little less as mem_total.
RAM_NEEDED_GB = 8
RAM_MIN_KB = 7_000_000
VIRTUAL_MODELS = ("c8000v", "csr1000v")
MAX_IMAGE_BYTES = 1024**3

# secapp-utd.17.18.02.1.1.0_SV3.3.5.0_XE17.18.x86_64.tar
_IMAGE = re.compile(
    r"^secapp-utd\.(?P<xe>\d+\.\d+\.\d+[a-z]?)\.(?P<utd>\d+\.\d+\.\d+_SV[0-9.]+_XE\d+\.\d+)"
    r"\.(?P<arch>x86_64|aarch64)\.tar$",
    re.IGNORECASE,
)
_NOISE = ("vdevice-name", "vdevice-host-name", "vdevice-dataKey", "lastupdated")


def parse_image_name(name: str) -> dict[str, str] | None:
    """{ios_xe, utd_version, arch} from a UTD image file name, None when it isn't one."""
    m = _IMAGE.match(name.rsplit("/", 1)[-1])
    if not m:
        return None
    return {"ios_xe": m.group("xe"), "utd_version": m.group("utd"), "arch": m.group("arch").lower()}


def _rows(body: Any) -> list[dict[str, Any]]:
    data = body.get("data", body) if isinstance(body, dict) else body
    return [r for r in (data if isinstance(data, list) else []) if isinstance(r, dict)]


def clean(rows: Any) -> list[dict[str, Any]]:
    out = []
    for r in _rows(rows):
        rec = {k: v for k, v in r.items() if k not in _NOISE and v not in (None, "", [])}
        if rec:
            out.append(rec)
    return out


def image_row(r: dict[str, Any]) -> dict[str, Any]:
    files = r.get("availableFiles")
    row = {
        "file": files if isinstance(files, str) else ", ".join(str(f) for f in files or []),
        "version": r.get("versionName"),
        "type": r.get("imageType"),
        "version_type": r.get("versionType"),
        "size": r.get("fileSizeStr"),
        "checksum": r.get("checksumValidity"),
        "version_id": r.get("versionId"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def is_utd_image(row: dict[str, Any]) -> bool:
    text = f"{row.get('file', '')} {row.get('version', '')} {row.get('version_type', '')}".lower()
    return "utd" in text


def utd_images(bodies: list[Any]) -> list[dict[str, Any]]:
    """The UTD rows of several repository answers, one row per file."""
    seen: dict[str, dict[str, Any]] = {}
    for body in bodies:
        for r in _rows(body):
            row = image_row(r)
            if is_utd_image(row):
                seen.setdefault(str(row.get("file") or row.get("version_id")), row)
    return list(seen.values())


def image_version(row: dict[str, Any]) -> str | None:
    """The UTD version of a repository row (its version name, or parsed from the file name)."""
    parsed = parse_image_name(str(row.get("file") or ""))
    if parsed:
        return parsed["utd_version"]
    v = row.get("version")
    return str(v) if v else None


def version_status(rows: Any) -> dict[str, Any]:
    """{recommended, supported_regex, installed_supported} from utd/version-status."""
    recs = clean(rows)
    if not recs:
        return {}
    r = recs[0]
    out = {
        "recommended": r.get("utd-version-status-recommended-version"),
        "supported_regex": r.get("utd-version-status-supported-regex"),
        "installed_supported": str(r.get("utd-version-status-supported", "")).lower() == "true"
        if r.get("utd-version-status-supported") is not None
        else None,
    }
    return {k: v for k, v in out.items() if v is not None}


def version_matches(regex: str | None, version: str | None) -> bool | None:
    """Does a UTD version fit the edge's supported pattern? None when either is unknown."""
    if not regex or not version:
        return None
    try:
        return re.match(regex, version) is not None
    except re.error:
        return None


def memory_kb(rows: Any) -> float | None:
    recs = clean(rows)
    try:
        return float(recs[0]["mem_total"]) if recs and recs[0].get("mem_total") else None
    except (TypeError, ValueError):
        return None


def is_virtual(model: Any) -> bool:
    m = str(model or "").lower()
    return any(v in m for v in VIRTUAL_MODELS)


def ram_problem(model: Any, mem_kb: float | None) -> str | None:
    if mem_kb is None or mem_kb >= RAM_MIN_KB:
        return None
    gb = round(mem_kb / 1024 / 1024, 1)
    what = "this C8000V" if is_virtual(model) else "this edge"
    return (
        f"{what} has {gb} GB of RAM; UTD needs {RAM_NEEDED_GB} GB (C8000V: give the VM 8 GB and restart it "
        "before deploying UTD)"
    )


def installed(rows: Any) -> list[dict[str, Any]]:
    return [
        {k: v for k, v in r.items() if k in ("version", "active", "previous", "timestamp")}
        for r in clean(rows)
    ]


def app_rows(rows: Any) -> list[dict[str, Any]]:
    keys = {
        "name": "name",
        "state": "state",
        "package-info-name": "package",
        "application-installed-version": "version",
        "activated-profile-name": "profile",
        "resource-reservation-memory": "memory_reserved",
        "resource-admission-state": "admission",
    }
    out = []
    for r in clean(rows):
        rec = {new: r[old] for old, new in keys.items() if r.get(old) not in (None, "")}
        if rec:
            out.append(rec)
    return out


def utd_app(apps: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((a for a in apps if "utd" in f"{a.get('name', '')} {a.get('package', '')}".lower()), None)


def edge_verdict(row: dict[str, Any]) -> str:
    """One line: running / installed but not running / ready / not ready (why)."""
    problems = row.get("problems") or []
    app = row.get("app") or {}
    engines = row.get("engines") or []
    if engines and app:
        return f"UTD running ({app.get('version') or 'version unknown'}, {app.get('state', 'state unknown')})"
    if app or row.get("installed"):
        state = app.get("state") if app else "no app-hosting record"
        return f"UTD installed but not running ({state}): check catsdwan_security_status(device)"
    if problems:
        return "not ready for UTD: " + "; ".join(problems)
    return (
        "ready: UTD installs when a policy group with IPS, URL filtering or AMP is deployed to this edge "
        "(catsdwan_deploy_policy_group)"
    )
