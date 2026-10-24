"""W48: catsdwan_utd_status and catsdwan_upload_utd_image.

Recorded on 20.18.3.1 (no UTD anywhere): the image repository (device_action_software_images, empty), br1's
utd/version-status (recommended 1.1.0_SV3.3.5.0_XE17.18), virtualApplication/utd and app-hosting/details
(both empty), utd/engine-status (empty) and system/status (a 5 GB C8000V). A repository row with the UTD
image and an 8 GB edge are hand-built from the recorded grid headers, and marked so. The upload
answer is not recorded (the Stage 2 live run records it).
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from cat_sdwan_mcp.utd import (
    edge_verdict,
    parse_image_name,
    ram_problem,
    utd_images,
    version_matches,
    version_status,
)

from .conftest import fixture, make_server
from .test_inventory import EDGES, mock_inventory

IMAGE = "secapp-utd.17.18.02.1.1.0_SV3.3.5.0_XE17.18.x86_64.tar"
IMAGES = "/dataservice/device/action/software/images"
UPLOAD = "/dataservice/device/action/software/package/lxc"
REPO_ROW = {  # hand-built from the recorded grid's fields
    "versionId": "5f1c2d3e-0000-4000-8000-000000000001", "availableFiles": IMAGE,
    "versionName": "1.1.0_SV3.3.5.0_XE17.18", "versionType": "utd", "imageType": "lxc",
    "fileSizeStr": "57 MB", "checksumValidity": "valid",
}  # fmt: skip
BIG_RAM = {"mem_total": "8023456"}  # hand-built: an 8 GB C8000V


def repo_body(*rows: dict[str, Any]) -> dict[str, Any]:
    body = fixture("device_action_software_images")
    body["data"] = list(rows)
    return body


def sysstatus(**edit: str) -> dict[str, Any]:
    body = fixture("device_system_status_br1")
    body["data"][0].update(edit)
    return body


def mock_edges(api: respx.MockRouter, *, repo: Any = None, ram: dict[str, str] | None = None) -> None:
    mock_inventory(api)
    api.get(IMAGES).respond(json=repo if repo is not None else repo_body())
    for ip in EDGES.values():
        p = {"deviceId": ip}
        api.get("/dataservice/device/utd/version-status", params=p).respond(
            json=fixture("device_utd_version_status_br1")
        )
        api.get("/dataservice/device/system/status", params=p).respond(json=sysstatus(**(ram or {})))
        api.get("/dataservice/device/virtualApplication/utd", params=p).respond(
            json=fixture("device_virtualapplication_utd_br1")
        )
        api.get("/dataservice/device/app-hosting/details", params=p).respond(
            json=fixture("device_app_hosting_details_br1")
        )
        api.get("/dataservice/device/utd/engine-status", params=p).respond(
            json=fixture("device_utd_engine_status_br1")
        )


def server(tmp: Path | None = None, **kw: Any) -> Any:
    return make_server(mcp_enable_writes=True, image_dir=str(tmp) if tmp else None, **kw)


async def run(srv: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    async with Client(srv) as c:
        out = (await c.call_tool(name, args)).structured_content
    assert out is not None
    return out


def test_image_name_and_recorded_pattern() -> None:
    parsed = parse_image_name(IMAGE)
    assert parsed == {"ios_xe": "17.18.02", "utd_version": "1.1.0_SV3.3.5.0_XE17.18", "arch": "x86_64"}
    assert parse_image_name("c8000v-universalk9.17.18.02.SPA.bin") is None
    status = version_status(fixture("device_utd_version_status_br1"))
    assert status == {
        "recommended": "1.1.0_SV3.3.5.0_XE17.18",
        "supported_regex": "^1\\.1\\.([0-9]+)_SV(.*)_XE17.18$",
        "installed_supported": False,
    }
    assert version_matches(status["supported_regex"], parsed["utd_version"]) is True
    assert version_matches(status["supported_regex"], "1.0.9_SV3.1.0.0_XE17.12") is False
    assert version_matches(None, "x") is None


def test_ram_rule() -> None:
    assert "5 GB" not in (ram_problem("vedge-C8000V", 4987936) or "")
    assert "4.8 GB of RAM; UTD needs 8 GB" in (ram_problem("vedge-C8000V", 4987936) or "")
    assert ram_problem("vedge-C8000V", 8023456) is None
    assert ram_problem("vedge-C8000V", None) is None


def test_repository_rows_and_verdicts() -> None:
    other = {**REPO_ROW, "availableFiles": "c8000v.17.18.02.SPA.bin", "versionName": "17.18.02",
             "versionType": "software"}  # fmt: skip
    rows = utd_images([repo_body(REPO_ROW, other), repo_body(REPO_ROW)])
    assert [r["file"] for r in rows] == [IMAGE]
    assert edge_verdict({"problems": ["x"]}) == "not ready for UTD: x"
    assert edge_verdict({}).startswith("ready")
    assert edge_verdict({"app": {"state": "RUNNING", "version": "1.1.0"}, "engines": [{"a": 1}]}).startswith(
        "UTD running (1.1.0, RUNNING)"
    )
    assert "installed but not running (DEPLOYED)" in edge_verdict({"app": {"state": "DEPLOYED"}})


async def test_status_on_the_recorded_lab(api: respx.MockRouter) -> None:
    mock_edges(api)
    out = await run(make_server(), "catsdwan_utd_status", {})
    assert out["repository"] == "no UTD image in the Manager's virtual-image repository"
    br1 = next(e for e in out["edges"] if e["device"] == "br1")
    assert br1["memory_gb"] == 4.8 and br1.get("repository_image") is None
    assert br1["utd_image"]["recommended"] == "1.1.0_SV3.3.5.0_XE17.18"
    assert any("UTD needs 8 GB" in p for p in br1["problems"])
    assert any("it wants 1.1.0_SV3.3.5.0_XE17.18: catsdwan_upload_utd_image" in p for p in br1["problems"])
    assert br1["verdict"].startswith("not ready for UTD")
    assert out["summary"] == {"edges": 3, "not_ready": ["hub1", "br1", "br2"]}


async def test_status_ready_with_image_and_ram(api: respx.MockRouter) -> None:
    mock_edges(api, repo=repo_body(REPO_ROW), ram=BIG_RAM)
    out = await run(make_server(), "catsdwan_utd_status", {"devices": ["br1"]})
    (br1,) = out["edges"]
    assert br1["repository_image"] == IMAGE and "problems" not in br1
    assert br1["verdict"].startswith("ready: UTD installs when a policy group")
    assert out["repository"][0]["version_id"] == REPO_ROW["versionId"]


async def test_status_refuses_controllers(api: respx.MockRouter) -> None:
    mock_edges(api)
    async with Client(make_server()) as c:
        with pytest.raises(ToolError, match="Not WAN edges"):
            await c.call_tool("catsdwan_utd_status", {"devices": ["controller"]})


async def test_upload_is_off_without_the_directory(api: respx.MockRouter) -> None:
    mock_edges(api)
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="CATSDWAN_IMAGE_DIR"):
            await c.call_tool("catsdwan_upload_utd_image", {"file_name": IMAGE})


async def test_upload_refuses_paths_and_missing_files(api: respx.MockRouter, tmp_path: Path) -> None:
    mock_edges(api)
    outside = tmp_path.parent / "outside.tar"
    outside.write_bytes(b"x")
    (tmp_path / "link.tar").symlink_to(outside)
    async with Client(server(tmp_path)) as c:
        with pytest.raises(ToolError, match="not a path"):
            await c.call_tool("catsdwan_upload_utd_image", {"file_name": "../outside.tar"})
        with pytest.raises(ToolError, match="outside CATSDWAN_IMAGE_DIR"):
            await c.call_tool("catsdwan_upload_utd_image", {"file_name": "link.tar"})
        with pytest.raises(ToolError, match="No file 'nope.tar'"):
            await c.call_tool("catsdwan_upload_utd_image", {"file_name": "nope.tar"})


async def test_upload_preview_then_confirm(api: respx.MockRouter, tmp_path: Path) -> None:
    (tmp_path / IMAGE).write_bytes(b"UTD-IMAGE-BYTES" * 100)
    mock_edges(api)
    api.get(IMAGES).mock(
        # preview (3 image types), the confirm's re-check (3), then the read-back after the upload
        side_effect=[httpx.Response(200, json=repo_body())] * 6
        + [httpx.Response(200, json=repo_body(REPO_ROW))] * 3
    )
    post = api.post(UPLOAD).respond(200)
    srv = server(tmp_path)
    async with Client(srv) as c:
        prev = (await c.call_tool("catsdwan_upload_utd_image", {"file_name": IMAGE})).structured_content
        assert prev is not None and prev["status"] == "preview" and not post.called
        p = prev["preview"]
        assert p["file"]["bytes"] == 1500 and p["file"]["utd_version"] == "1.1.0_SV3.3.5.0_XE17.18"
        assert len(p["file"]["sha256"]) == 64
        assert p["request"] == f"POST {UPLOAD} (multipart/form-data, part 'file')"
        assert p["fits_edges"] == ["hub1", "br1", "br2"]
        assert any("UTD on a C8000V needs 8 GB of RAM" in w for w in p["warnings"])
        assert "catsdwan_deploy_policy_group" in p["then"]
        done = (
            await c.call_tool("catsdwan_upload_utd_image", {"file_name": IMAGE, "confirm": prev["confirm"]})
        ).structured_content
    assert done is not None
    assert done["result"]["outcome"] == "uploaded"
    assert done["result"]["repository_row"]["version_id"] == REPO_ROW["versionId"]
    req = post.calls.last.request
    assert req.headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert f'name="file"; filename="{IMAGE}"'.encode() in req.content
    assert b"UTD-IMAGE-BYTES" in req.content


async def test_upload_blocked_when_already_there(api: respx.MockRouter, tmp_path: Path) -> None:
    (tmp_path / IMAGE).write_bytes(b"x")
    mock_edges(api, repo=repo_body(REPO_ROW), ram=BIG_RAM)
    prev = await run(server(tmp_path), "catsdwan_upload_utd_image", {"file_name": IMAGE})
    assert prev["status"] == "blocked"
    assert any("already has" in b for b in json.loads(json.dumps(prev))["blockers"])
    assert "warnings" not in prev["preview"]


async def test_upload_warns_on_a_foreign_name(api: respx.MockRouter, tmp_path: Path) -> None:
    (tmp_path / "odd.tar").write_bytes(b"x")
    mock_edges(api, ram=BIG_RAM)
    prev = await run(server(tmp_path), "catsdwan_upload_utd_image", {"file_name": "odd.tar"})
    assert prev["status"] == "preview"
    assert any("does not look like a UTD image" in w for w in prev["preview"]["warnings"])
