"""W48 UTD engine: catsdwan_utd_status (read), catsdwan_upload_utd_image (write, preview-first)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from cat_sdwan_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
    preview_or_apply,
)
from cat_sdwan_mcp.client import SdwanApp
from cat_sdwan_mcp.fabric import device_rows, is_reachable, unreachable_reason
from cat_sdwan_mcp.inventory import load_inventory, matches_site, resolve
from cat_sdwan_mcp.utd import (
    APP_HOSTING_PATH,
    ENGINE_PATH,
    IMAGE_TYPES,
    IMAGES_PATH,
    INSTALLED_PATH,
    MAX_IMAGE_BYTES,
    RAM_NEEDED_GB,
    SYSTEM_STATUS_PATH,
    UPLOAD_PATH,
    VERSION_STATUS_PATH,
    app_rows,
    clean,
    edge_verdict,
    image_version,
    installed,
    memory_kb,
    parse_image_name,
    ram_problem,
    utd_app,
    utd_images,
    version_matches,
    version_status,
)

DIR_OFF = (
    "UTD image upload is off: set CATSDWAN_IMAGE_DIR to a directory on the MCP server host that holds the "
    "image (secapp-utd.<IOS XE>.<UTD version>.x86_64.tar from software.cisco.com); the file is read there "
    "and sent to the Manager only, never through MCP."
)
UPLOAD_TIMEOUT = 900.0


def image_path(image_dir: Path | None, name: str) -> tuple[Path, os.stat_result]:
    """A regular file inside CATSDWAN_IMAGE_DIR (no paths outside it, also not through symlinks)."""
    if not image_dir:
        raise InvalidRequest(DIR_OFF)
    try:
        root = Path(os.path.expanduser(str(image_dir))).resolve()
        if not root.is_dir():
            raise InvalidRequest(f"CATSDWAN_IMAGE_DIR {str(root)!r} is not a directory")
        candidate = (root / name).resolve()
        inside = candidate != root and root in candidate.parents
        st = candidate.stat() if inside and candidate.is_file() else None
    except (OSError, ValueError) as e:
        raise InvalidRequest(f"Bad image file name {name!r}: {e}") from None
    if not inside:
        raise InvalidRequest(f"{name!r} is outside CATSDWAN_IMAGE_DIR: give a file name in that directory")
    if st is None or not stat.S_ISREG(st.st_mode):
        files = sorted(p.name for p in root.iterdir() if p.is_file() and p.suffix == ".tar")[:20]
        raise InvalidRequest(
            f"No file {name!r} in CATSDWAN_IMAGE_DIR. Image files there: {', '.join(files) or 'none'}."
        )
    if st.st_size > MAX_IMAGE_BYTES:
        raise InvalidRequest(f"{name!r} is {st.st_size} bytes; a UTD image is well under 1 GB")
    return candidate, st


def sha256_of(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def multipart(p: Path) -> tuple[bytes, str]:
    """(body, content type) of a multipart/form-data upload with one part `file`."""
    with p.open("rb") as f:
        req = httpx.Request(
            "POST", "https://upload.invalid/", files={"file": (p.name, f, "application/x-tar")}
        )
        body = req.read()
    return body, req.headers["Content-Type"]


async def repository(app: SdwanApp) -> tuple[list[dict[str, Any]], list[str]]:
    """(the UTD images in the virtual-image repository, read problems)."""
    got = await asyncio.gather(
        *(app.api.get(IMAGES_PATH, {"imageType": t}) for t in IMAGE_TYPES), return_exceptions=True
    )
    bodies, errors = [], []
    for t, res in zip(IMAGE_TYPES, got, strict=True):
        if isinstance(res, UpstreamError):
            errors.append(f"GET {IMAGES_PATH}?imageType={t} failed: {str(res)[:200]}")
        elif isinstance(res, BaseException):
            raise res
        else:
            bodies.append(res)
    return utd_images(bodies), errors


async def _table(app: SdwanApp, path: str, ip: str) -> list[dict[str, Any]] | str:
    try:
        return await device_rows(app, path, ip)
    except UpstreamError as e:
        return f"GET {path} failed: {str(e)[:200]}"


async def edge_state(app: SdwanApp, row: dict[str, Any], images: list[dict[str, Any]]) -> dict[str, Any]:
    """One edge's UTD readiness and state (five real-time reads)."""
    out: dict[str, Any] = {
        "device": row.get("host") or row.get("chassis"),
        "system_ip": row.get("system_ip"),
        "site_id": row.get("site_id"),
        "model": row.get("model"),
        "version": row.get("version"),
    }
    if not is_reachable(row):
        out["problems"] = [str(unreachable_reason(row))]
        out["verdict"] = "not read: " + out["problems"][0]
        return out
    ip = str(row["system_ip"])
    paths = (VERSION_STATUS_PATH, SYSTEM_STATUS_PATH, INSTALLED_PATH, APP_HOSTING_PATH, ENGINE_PATH)
    vs, sysrows, inst, apps, engines = await asyncio.gather(*(_table(app, p, ip) for p in paths))
    errors = [t for t in (vs, sysrows, inst, apps, engines) if isinstance(t, str)]
    problems: list[str] = []
    status = version_status(vs if not isinstance(vs, str) else [])
    if status:
        out["utd_image"] = status
    mem = memory_kb(sysrows if not isinstance(sysrows, str) else [])
    if mem is not None:
        out["memory_gb"] = round(mem / 1024 / 1024, 1)
        if why := ram_problem(row.get("model"), mem):
            problems.append(why)
    matching = [
        str(i.get("file")) for i in images if version_matches(status.get("supported_regex"), image_version(i))
    ]
    out["repository_image"] = matching[0] if matching else None
    if not matching:
        rec = status.get("recommended")
        problems.append(
            "no UTD image for this edge in the Manager's repository"
            + (f" (it wants {rec}: catsdwan_upload_utd_image)" if rec else " (catsdwan_upload_utd_image)")
        )
    inst_rows = installed(inst if not isinstance(inst, str) else [])
    if inst_rows:
        out["installed"] = inst_rows
    app_list = app_rows(apps if not isinstance(apps, str) else [])
    if a := utd_app(app_list):
        out["app"] = a
    eng = clean(engines if not isinstance(engines, str) else [])
    if eng:
        out["engines"] = eng
    if problems:
        out["problems"] = problems
    if errors:
        out["errors"] = errors
    out["verdict"] = edge_verdict(out)
    return out


def _edges(inv_rows: list[dict[str, Any]], site: str | None) -> list[dict[str, Any]]:
    return [r for r in inv_rows if r.get("role") == "edge" and matches_site(r, site)]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN UTD engine status")
    async def catsdwan_utd_status(
        ctx: Context,
        devices: Annotated[
            list[str] | None,
            Field(description="Edges (host name, system IP or chassis); default every edge (of `site`)"),
        ] = None,
        site: Annotated[str | None, Field(description="Only the edges of this site (id or name)")] = None,
        response_format: ResponseFormat = "json",
    ) -> ToolResult:
        """Can these edges run the UTD engine (Snort IPS, URL filtering, AMP), and do they? The Manager's
        virtual-image repository (the UTD images uploaded), then per edge: the UTD version its IOS XE wants
        (recommended, supported pattern), whether the repository has a matching image, its RAM (UTD on a
        C8000V needs 8 GB), the installed UTD, the IOx app state and the Snort engines, with a verdict:
        running, installed but not running, ready, or not ready and why. There is no separate install: the
        Manager installs UTD from the repository on each edge a policy group with IPS, URL filtering or AMP is
        deployed to (catsdwan_set_security_policy -> catsdwan_create_policy_group /
        catsdwan_associate_policy_group -> catsdwan_deploy_policy_group); run this after the deploy to see it
        come up, and catsdwan_security_status(device) for the engine's detail."""
        app: SdwanApp = get_client(ctx)
        inv = await load_inventory(app)
        if devices:
            rows = [resolve(inv, d) for d in devices]
            not_edges = [str(r.get("host")) for r in rows if r.get("role") != "edge"]
            if not_edges:
                raise InvalidRequest(f"Not WAN edges (UTD runs on edges only): {', '.join(not_edges)}")
        else:
            rows = _edges(inv.rows, site)
            if not rows:
                raise InvalidRequest(f"No edges{f' at site {site}' if site else ''} in the inventory.")
        images, errors = await repository(app)
        edges = await asyncio.gather(*(edge_state(app, r, images) for r in rows))
        ready = [e["device"] for e in edges if str(e.get("verdict", "")).startswith("ready")]
        running = [e["device"] for e in edges if str(e.get("verdict", "")).startswith("UTD running")]
        out: dict[str, Any] = {
            "repository": images or "no UTD image in the Manager's virtual-image repository",
            "edges": edges,
            "summary": {
                "edges": len(edges),
                "running": running,
                "ready": ready,
                "not_ready": [
                    e["device"] for e in edges if e["device"] not in ready and e["device"] not in running
                ],
            },
            "ram_needed_gb": RAM_NEEDED_GB,
        }
        if errors:
            out["errors"] = errors
        return object_result(out, fmt=response_format)

    @reg.write(title="Upload a UTD engine image to the SD-WAN Manager")
    async def catsdwan_upload_utd_image(
        ctx: Context,
        file_name: Annotated[
            str,
            Field(
                description="The image's file name in CATSDWAN_IMAGE_DIR on the MCP server host, e.g. "
                "secapp-utd.17.18.02.1.1.0_SV3.3.5.0_XE17.18.x86_64.tar (never the file's bytes)"
            ),
        ],
        image_type: Annotated[
            str,
            Field(
                description="The repository type in the upload path (POST /device/action/software/package/"
                "<type>); default lxc, the repository's type for IOx containers (the result shows the row "
                "the Manager filed)"
            ),
        ] = "lxc",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Upload the UTD engine image (Snort IPS, URL filtering, AMP container) to the Manager's
        virtual-image repository (Maintenance > Software Repository > Virtual Images), from a file in
        CATSDWAN_IMAGE_DIR: only its name travels here, the server reads and sends the file. The preview shows
        the file (size, SHA-256, the IOS XE and UTD versions in its name), whether the repository already has
        it, which edges it fits (each edge's supported UTD pattern) and which not, and the RAM check: UTD on a
        C8000V needs 8 GB (edges with less are named). Nothing changes on an edge: UTD installs when a policy
        group with IPS, URL filtering or AMP is deployed (catsdwan_set_security_policy ->
        catsdwan_create_policy_group / catsdwan_associate_policy_group -> catsdwan_deploy_policy_group); check
        with catsdwan_utd_status. The confirm sends the file (57 MB for 17.18), then reads the repository
        back."""
        app: SdwanApp = get_client(ctx)
        name = file_name.strip()
        if "/" in name or "\\" in name:
            raise InvalidRequest("file_name is a name inside CATSDWAN_IMAGE_DIR, not a path.")
        if not re.match(r"^[a-z][a-z0-9-]{0,31}$", image_type.strip()):
            raise InvalidRequest(f"image_type {image_type!r} is not a repository type (e.g. 'lxc').")
        p, st = image_path(app.settings.image_dir, name)
        digest = await asyncio.to_thread(sha256_of, p)
        parsed = parse_image_name(name)
        inv = await load_inventory(app)
        edges = [r for r in inv.rows if r.get("role") == "edge"]
        (images, repo_errors), states = await asyncio.gather(
            repository(app),
            asyncio.gather(*(_edge_fit(app, r) for r in edges)),
        )
        blockers: list[str] = []
        warnings: list[str] = list(repo_errors)
        if not name.lower().endswith(".tar"):
            blockers.append(f"{name!r} is not a .tar: UTD images are secapp-utd.<IOS XE>.<UTD>.x86_64.tar")
        elif not parsed:
            warnings.append(
                f"{name!r} does not look like a UTD image name (secapp-utd.<IOS XE>.<UTD version>.x86_64.tar)"
            )
        present = [i for i in images if str(i.get("file", "")).lower() == name.lower()]
        if present:
            blockers.append(f"the repository already has {name} (catsdwan_utd_status lists it)")
        fits, misfits, ram = [], [], []
        for row, state in zip(edges, states, strict=True):
            dev = str(row.get("host") or row.get("chassis"))
            ok = version_matches(state.get("supported_regex"), parsed["utd_version"] if parsed else None)
            if ok:
                fits.append(dev)
            elif ok is False:
                misfits.append(f"{dev} (wants {state.get('recommended') or state.get('supported_regex')})")
            if state.get("ram_problem"):
                ram.append(f"{dev}: {state['ram_problem']}")
        if edges and not fits:
            warnings.append(
                "no edge's supported UTD pattern matches this image: check the IOS XE release (UTD images "
                "are per release train)"
            )
        if ram:
            warnings.append(f"UTD on a C8000V needs {RAM_NEEDED_GB} GB of RAM: " + "; ".join(ram))
        upload = UPLOAD_PATH.format(image_type=image_type.strip())
        plan = Plan(
            f"Upload {name} ({round(st.st_size / 1024 / 1024, 1)} MB) to the Manager's virtual-image "
            "repository",
            details={
                "file": {
                    "name": name,
                    "bytes": st.st_size,
                    "sha256": digest,
                    **({"ios_xe": parsed["ios_xe"], "utd_version": parsed["utd_version"]} if parsed else {}),
                },
                "request": f"POST {upload} (multipart/form-data, part 'file')",
                "repository_now": images or "no UTD image",
                "fits_edges": fits,
                "other_edges": misfits,
                "ram_needed_gb": RAM_NEEDED_GB,
                **({"warnings": warnings} if warnings else {}),
                "then": "catsdwan_set_security_policy -> catsdwan_create_policy_group / "
                "catsdwan_associate_policy_group -> catsdwan_deploy_policy_group installs UTD on the edges; "
                "catsdwan_utd_status shows it",
                "undo": "delete the image in the GUI (Maintenance > Software Repository > Virtual Images)",
            },
            side_effects=[
                "The image is stored on the Manager (its data disk); nothing changes on an edge until a "
                "policy group with UTD features is deployed"
            ],
            fingerprint=[st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, digest, sorted(map(str, images))],
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            body, ctype = await asyncio.to_thread(multipart, p)
            answer = await app.api.request(
                "POST", upload, content=body, headers={"Content-Type": ctype}, timeout=UPLOAD_TIMEOUT
            )
            after, errors = await repository(app)
            row = next((i for i in after if str(i.get("file", "")).lower() == name.lower()), None)
            out: dict[str, Any] = {
                "outcome": "uploaded" if row else "sent; not yet listed in the repository",
                "answer": answer,
            }
            if row:
                out["repository_row"] = row
            else:
                out["check"] = "catsdwan_utd_status (the repository) in a minute"
            if errors:
                out["errors"] = errors
            return out

        return await preview_or_apply(
            ctx,
            tool="catsdwan_upload_utd_image",
            args={"file_name": name, "image_type": image_type},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )


async def _edge_fit(app: SdwanApp, row: dict[str, Any]) -> dict[str, Any]:
    """{recommended, supported_regex, ram_problem} of one reachable edge ({} when unreachable)."""
    if not is_reachable(row):
        return {}
    ip = str(row["system_ip"])
    vs, sysrows = await asyncio.gather(
        _table(app, VERSION_STATUS_PATH, ip), _table(app, SYSTEM_STATUS_PATH, ip)
    )
    out = version_status(vs if not isinstance(vs, str) else [])
    mem = memory_kb(sysrows if not isinstance(sysrows, str) else [])
    if why := ram_problem(row.get("model"), mem):
        out["ram_problem"] = why
    return out
