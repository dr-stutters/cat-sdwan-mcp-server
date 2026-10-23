"""API discovery (W6): the Manager's own OpenAPI document, and what a raw call may do.

Recorded on 20.18.3.1: the Swagger UI at /apidocs/ loads GET /apidocs/vmanageapi.json, an OpenAPI 3.0.1
document (info.version 2.0.0, 2811 paths, 13.4 MB, 0.2 s) behind the same login as the API. Its paths are
relative to `servers: [{"url": "/dataservice"}]` ("/device/bfd/sessions"), so the index prefixes them with
/dataservice to give the paths every other tool uses. The index (about 4100 operations, 3.8 MB) is cached per
Manager release in MCP_CACHE_DIR.

Tiers of a raw call (`classify`):
- read: every GET, and the POSTs that only run a query: /statistics/<index>[/page|/aggregation|/doccount|...],
  /alarms, /event and /auditlog with their page, count and aggregation forms.
- write: every other POST, PUT and DELETE (preview first, needs MCP_ENABLE_WRITES).
- dangerous: POST/PUT/DELETE under /device/action/ (reboot, software install and activate, reset, ...).
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from cat_sdwan_mcp._core import InvalidRequest, UpstreamError
from cat_sdwan_mcp._core.spec import SpecIndex, SpecSource
from cat_sdwan_mcp._core.spec.tools import validate_path
from cat_sdwan_mcp.client import SdwanApp

SPEC_PATH = "/apidocs/vmanageapi.json"
API_PREFIX = "/dataservice"
SOURCE = "dataservice"

# Query POSTs under these roots that change nothing (alarms and event and auditlog: the query itself and its
# page, count and aggregation forms).
_QUERY_ROOTS = ("alarms", "event", "auditlog")
_QUERY_SUFFIXES = frozenset({"", "page", "aggregation", "doccount", "count", "topn", "byuuids"})
# Under /statistics every POST is a query except these (collection switches, on-demand queues, downloads,
# settings).
_STATISTICS_WRITES = frozenset({"dynamic", "on-demand", "download", "settings"})
_DANGEROUS = "device/action/"


async def load_spec(app: SdwanApp) -> dict[str, Any]:
    doc = await app.api.get(SPEC_PATH)
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        raise UpstreamError(f"GET {SPEC_PATH} did not return an OpenAPI document")
    return doc


def spec_sources(app: SdwanApp) -> list[SpecSource]:
    async def version(a: SdwanApp) -> str:
        return await a.version()

    return [
        SpecSource(
            SOURCE,
            load=load_spec,
            client=lambda a: a.api,
            version=version,
            path_prefix=API_PREFIX,
            description=f"The Manager's own OpenAPI document (GET {SPEC_PATH}), paths under {API_PREFIX}",
        )
    ]


def api_path(path: str) -> str:
    """A raw-call path as /dataservice/...: checked (no scheme, host, query string, '..' or placeholder) and
    prefixed when given relative to /dataservice ('/device' and 'device' are /dataservice/device)."""
    p = validate_path(path)
    if p == API_PREFIX or p.startswith(API_PREFIX + "/"):
        return p
    return API_PREFIX + p


def _rel(path: str) -> str:
    return path.removeprefix(API_PREFIX).strip("/")


def classify(method: str, path: str) -> str:
    """read, write or dangerous for METHOD /dataservice/... (see the module docstring)."""
    method = method.upper()
    rel = _rel(path)
    if method == "GET":
        return "read"
    if rel.startswith(_DANGEROUS):
        return "dangerous"
    if method != "POST":
        return "write"
    parts = rel.split("/")
    if parts[0] == "statistics":
        return "write" if len(parts) > 1 and parts[1] in _STATISTICS_WRITES else "read"
    if parts[0] in _QUERY_ROOTS and "/".join(parts[1:]) in _QUERY_SUFFIXES:
        return "read"
    return "write"


def _template_re(template: str) -> re.Pattern[str]:
    parts = [
        "[^/]+" if re.fullmatch(r"\{[^}]+\}", seg) else re.escape(seg)
        for seg in template.strip("/").split("/")
    ]
    return re.compile("^/" + "/".join(parts) + "/?$", re.IGNORECASE)


def match_operation(idx: SpecIndex, method: str, path: str) -> tuple[str, list[str]]:
    """The spec path template a concrete path matches (the most literal one when several do) and the methods
    it allows. Unknown paths raise InvalidRequest with the closest spec paths ('did you mean')."""
    by_template: dict[str, set[str]] = {}
    for op in idx.operations:
        by_template.setdefault(op.path, set()).add(op.method)
    hits = [t for t in by_template if _template_re(t).match(path)]
    if not hits:
        raise InvalidRequest(
            f"{path} is not in the Manager's API spec.{_did_you_mean(idx, path, by_template)}"
        )
    best = max(hits, key=lambda t: sum(1 for s in t.split("/") if s and not s.startswith("{")))
    methods = sorted(by_template[best])
    if method.upper() not in methods:
        raise InvalidRequest(
            f"{method.upper()} is not an operation on {best} (the spec has {', '.join(methods)} there)."
        )
    return best, methods


def _did_you_mean(idx: SpecIndex, path: str, templates: dict[str, set[str]]) -> str:
    close = difflib.get_close_matches(path, list(templates), n=5, cutoff=0.6)
    if not close:
        words = " ".join(s for s in _rel(path).split("/") if s and not s.isdigit())
        close = [
            str(h["name"]).split(" ", 1)[1] for h in idx.search(words, limit=5) if h["kind"] == "operation"
        ]
    seen = list(dict.fromkeys(close))
    hint = f" Did you mean: {', '.join(seen)}?" if seen else ""
    return f"{hint} catsdwan_search_spec finds paths by keyword."
