#!/usr/bin/env python3
"""Bounded authenticated read-only GitHub REST inventories for banner admission.

The caller supplies an independent read-scoped token and must reverify exact
main/head references around the complete collection. This module can neither
approve nor merge PRs. It never manufactures native checks or authorizations.
"""
from __future__ import annotations

import io
import json
import re
import urllib.parse
import urllib.request
from typing import Any, Callable

ORIGIN = "https://api.github.com"
PREFIX = "/repos/portyu9/portyu9/"
VERSION = "2022-11-28"
PAGE_SIZE = 100
MAX_PAGES = 20
MAX_BYTES = 2_000_000
LINK = re.compile(r'^<([^<>]+)>;\s*rel="(next|prev|first|last)"$')


class ObservationError(ValueError):
    """An authenticated inventory cannot be proven complete or well-formed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ObservationError(message)


def query_pairs(query: str) -> dict[str, str]:
    try:
        pairs = urllib.parse.parse_qsl(
            query, keep_blank_values=True, strict_parsing=True, max_num_fields=25
        )
    except ValueError as exc:
        raise ObservationError("invalid native GitHub query") from exc
    require(all(k and v for k, v in pairs)
            and len(set(k for k, _ in pairs)) == len(pairs),
            "duplicate or empty native GitHub query")
    return dict(pairs)


def path_parts(path: str) -> tuple[str, dict[str, str]]:
    require(type(path) is str and path.startswith(PREFIX)
            and len(path) <= 1400
            and all(32 < ord(c) < 127 for c in path)
            and "\\" not in path, "GitHub path escaped approved repository")
    value = urllib.parse.urlsplit(path)
    require(not value.scheme and not value.netloc and not value.fragment
            and value.path.startswith(PREFIX)
            and "%" not in value.path
            and all(p not in {"", ".", ".."} for p in value.path.split("/")[1:]),
            "GitHub path is escaped, ambiguous or malformed")
    return value.path, query_pairs(value.query) if value.query else {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a bearer token to a redirect destination."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


class ReadOnlyGitHub:
    def __init__(self, token: str, *, opener: Callable[..., Any] | None = None):
        require(type(token) is str and bool(token.strip())
                and not any(c.isspace() for c in token),
                "nonempty caller-scoped GitHub read token required")
        self.__token = token
        self.__opener = (
            opener if opener is not None
            else urllib.request.build_opener(NoRedirect()).open
        )

    def get(self, path: str) -> tuple[Any, str | None]:
        path_parts(path)
        url = ORIGIN + path
        request = urllib.request.Request(
            url, method="GET",
            headers={
                "Authorization": f"Bearer {self.__token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": VERSION,
                "User-Agent": "portyu9-banner-readonly-observer",
            },
        )
        with self.__opener(request, timeout=20) as response:
            require(response.geturl() == url and response.status == 200,
                    "GitHub response redirected or returned non-200")
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, "GitHub inventory page too large")
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ObservationError("GitHub response is not UTF-8 JSON") from exc
            link = response.headers.get("Link")
            require(link is None or type(link) is str,
                    "GitHub Link header type invalid")
            return data, link


def verified_next(link: str | None, requested: str, page: int) -> bool:
    """Validate HTTPS origin, query continuity, links, and page progression."""
    if link is None:
        return False
    require(bool(link) and len(link) <= 6000, "pagination Link malformed")
    endpoint, params = path_parts(requested)
    seen: set[str] = set()
    has_next = False
    for section in link.split(","):
        matched = LINK.fullmatch(section.strip())
        require(matched is not None, "unrecognized pagination Link")
        url, relation = matched.groups()
        require(relation not in seen, "duplicate pagination relation")
        seen.add(relation)
        parts = urllib.parse.urlsplit(url)
        require(parts.scheme == "https" and parts.netloc == "api.github.com"
                and not parts.fragment and parts.path == endpoint,
                "pagination Link escaped pinned GitHub HTTPS endpoint")
        linked = query_pairs(parts.query)
        require(set(linked) == set(params)
                and all(linked[key] == value for key, value in params.items()
                        if key != "page"),
                "pagination Link changed immutable filters")
        number = linked.get("page", "")
        require(number.isascii() and number.isdecimal()
                and str(int(number)) == number and int(number) > 0,
                "pagination Link page number invalid")
        target = int(number)
        if relation == "next":
            require(target == page + 1, "pagination skipped or replayed a page")
            has_next = True
        elif relation == "prev":
            require(page > 1 and target == page - 1,
                    "pagination previous page inconsistent")
        elif relation == "first":
            require(target == 1, "pagination first page inconsistent")
        else:
            require(target >= page, "pagination last page inconsistent")
    return has_next


def inventory(
    client: ReadOnlyGitHub, endpoint: str, *,
    field: str | None = None, limit: int = 100, uniqueness: str = "id",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return fully exhausted, unique REST rows plus an observed count witness.

    field=None reads array endpoints (e.g., open PRs, reviews, files).
    field='check_runs' reads a count-bearing check-run endpoint.
    Exhaust every native page; never assert completeness from a caller-provided
    JSON envelope. Bound both rows and bytes before passing data to admission.
    """
    path, filters = path_parts(endpoint)
    require("page" not in filters and "per_page" not in filters
            and type(limit) is int and 0 < limit <= MAX_PAGES * PAGE_SIZE
            and (field is None or (type(field) is str and field.isidentifier()))
            and uniqueness in {"id", "filename"},
            "inventory selection/limit malformed")
    result: list[dict[str, Any]] = []
    seen: set[Any] = set()
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        q = urllib.parse.urlencode({
            **filters, "per_page": str(PAGE_SIZE), "page": str(page),
        })
        request_path = f"{path}?{q}"
        payload, links = client.get(request_path)
        if field is None:
            require(type(payload) is list, "native endpoint not a JSON array")
            batch = payload
        else:
            require(type(payload) is dict
                    and type(payload.get("total_count")) is int
                    and payload["total_count"] >= 0
                    and type(payload.get(field)) is list,
                    "count-bearing native inventory malformed")
            observed = payload["total_count"]
            require(total is None or total == observed,
                    "native total changed between pages")
            total = observed
            batch = payload[field]
        require(len(batch) <= PAGE_SIZE and len(result) + len(batch) <= limit,
                "native inventory exceeded reviewed bounds")
        for row in batch:
            require(type(row) is dict, "native inventory includes a non-object")
            identity = row.get(uniqueness)
            require((type(identity) is int and identity > 0)
                    if uniqueness == "id"
                    else (type(identity) is str and bool(identity)),
                    "native inventory identity absent or malformed")
            require(identity not in seen, "duplicate native inventory identity")
            seen.add(identity)
            result.append(row)
        more = verified_next(links, request_path, page)
        require(not more or len(batch) == PAGE_SIZE,
                "native pagination advertises next after short page")
        if total is not None:
            require(len(result) <= total, "rows exceed native total")
            if len(result) == total:
                require(not more, "native Link extends beyond total")
                return result, {"totalCount": len(result), "hasNextPage": False}
            require(more or len(batch) == PAGE_SIZE,
                    "native inventory truncated before total")
        if not more and len(batch) < PAGE_SIZE:
            require(total is None or len(result) == total,
                    "native total differs from exhausted inventory")
            return result, {"totalCount": len(result), "hasNextPage": False}
        # A full page with no Link still requires another GET; do not infer EOF.
    raise ObservationError("native pagination exceeded bounded page budget")


def self_test() -> None:
    class Response:
        def __init__(self, url: str, body: Any, link: str | None):
            self.url = url
            self.data = io.BytesIO(json.dumps(body).encode())
            self.headers = {"Link": link} if link else {}
            self.status = 200
        def __enter__(self) -> "Response":
            return self
        def __exit__(self, *_: Any) -> None:
            self.data.close()
        def geturl(self) -> str:
            return self.url
        def read(self, n: int) -> bytes:
            return self.data.read(n)

    endpoint = PREFIX + "commits/" + "a" * 40 + "/check-runs"
    def source(request: Any, *, timeout: int) -> Response:
        require(request.get_method() == "GET" and timeout == 20
                and request.get_header("Authorization") == "Bearer local-test",
                "read-only token/method binding changed")
        page = int(query_pairs(urllib.parse.urlsplit(request.full_url).query)["page"])
        if page == 1:
            next_url = request.full_url.replace("&page=1", "&page=2")
            return Response(request.full_url, {
                "total_count": 101, "check_runs": [{"id": i} for i in range(1, 101)],
            }, f'<{next_url}>; rel="next"')
        return Response(request.full_url, {
            "total_count": 101, "check_runs": [{"id": 101}],
        }, None)

    rows, witness = inventory(
        ReadOnlyGitHub("local-test", opener=source), endpoint,
        field="check_runs", limit=150,
    )
    require(len(rows) == 101
            and witness == {"totalCount": 101, "hasNextPage": False},
            "valid complete native two-page inventory rejected")
    def must_reject(label: str, action: Callable[[], Any]) -> None:
        try:
            action()
        except ObservationError:
            return
        raise AssertionError(f"unsafe native GitHub transport accepted: {label}")

    requested = PREFIX + "pulls?state=open&per_page=100&page=1"
    valid = f'<{ORIGIN}{PREFIX}pulls?state=open&per_page=100&page=2>; rel="next"'
    require(verified_next(valid, requested, 1), "valid next Link rejected")
    must_reject("outside host", lambda: verified_next(
        valid.replace("api.github.com", "attacker.example"), requested, 1))
    must_reject("skipped page", lambda: verified_next(
        valid.replace("page=2", "page=3"), requested, 1))
    must_reject("query mutation", lambda: verified_next(
        valid.replace("state=open", "state=closed"), requested, 1))
    must_reject("duplicate Link", lambda: verified_next(valid + ", " + valid, requested, 1))
    must_reject("path escape", lambda: path_parts(PREFIX + "../users"))
    must_reject("foreign repo", lambda: path_parts("/repos/foreign/repo/pulls"))
    must_reject("missing token", lambda: ReadOnlyGitHub(""))
    def truncated(request: Any, *, timeout: int) -> Response:
        response = source(request, timeout=timeout)
        if "page=2" in request.full_url:
            response.data = io.BytesIO(json.dumps({
                "total_count": 101, "check_runs": [],
            }).encode())
        return response
    must_reject("truncated total", lambda: inventory(
        ReadOnlyGitHub("local-test", opener=truncated),
        endpoint, field="check_runs", limit=150))
    def duplicate(request: Any, *, timeout: int) -> Response:
        response = source(request, timeout=timeout)
        if "page=2" in request.full_url:
            response.data = io.BytesIO(json.dumps({
                "total_count": 101, "check_runs": [{"id": 1}],
            }).encode())
        return response
    must_reject("duplicate across pages", lambda: inventory(
        ReadOnlyGitHub("local-test", opener=duplicate),
        endpoint, field="check_runs", limit=150))
    def redirected(request: Any, *, timeout: int) -> Response:
        response = source(request, timeout=timeout)
        response.url = "https://attacker.example/"
        return response
    must_reject("response redirect", lambda: inventory(
        ReadOnlyGitHub("local-test", opener=redirected),
        endpoint, field="check_runs", limit=150))
    print("banner REST transport: authenticated GET and complete pagination PASS")


if __name__ == "__main__":
    self_test()
