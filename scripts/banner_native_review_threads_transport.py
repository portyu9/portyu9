#!/usr/bin/env python3
"""Read-only, authenticated, exact-identity GraphQL review-thread inventory for banners.

A query-only POST is required by GitHub GraphQL. There is no authored mutation,
review, status publication or merge. Partial/oversized review-thread connections
are never treated as complete, and unresolved threads never grant admission.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.request

import automation_github_read
import independent_banner_candidate_contract as contract

GRAPHQL_URL = "https://api.github.com/graphql"
REPOSITORY = "portyu9/portyu9"
QUERY = (
    "query($owner:String!,$name:String!,$number:Int!){"
    "repository(owner:$owner,name:$name){nameWithOwner "
    "pullRequest(number:$number){number "
    "reviewThreads(first:100){totalCount nodes{id isResolved}"
    "pageInfo{hasNextPage endCursor}}}}}"
)
MAX_RESPONSE_BYTES = 1_000_000


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str,
        headers: Any, newurl: str,
    ) -> None:
        return None


def request_payload(repository: str, pr_number: int) -> bytes:
    require(type(repository) is str and repository == REPOSITORY,
            "banner review-thread repository is not the exact accepted repository")
    require(type(pr_number) is int and 0 < pr_number < 2**31,
            "banner review-thread PR identity must be a positive GraphQL Int")
    require(QUERY.startswith("query(") and "mutation" not in QUERY.lower()
            and QUERY.count("reviewThreads(first:100)") == 1,
            "banner GraphQL request must be one reviewed read-only query")
    return json.dumps({
        "query": QUERY,
        "variables": {"owner": "portyu9", "name": "portyu9", "number": pr_number},
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_connection(body: bytes, repository: str, pr_number: int) -> dict[str, Any]:
    request_payload(repository, pr_number)
    require(type(body) is bytes and 0 < len(body) <= MAX_RESPONSE_BYTES,
            "banner GraphQL response is empty, oversized or not bytes")
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("banner GraphQL response is not UTF-8") from exc
    try:
        result = automation_github_read.strict_json(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("banner GraphQL response has duplicate members or malformed JSON") from exc
    # Reject GraphQL's HTTP-200 partial-data-with-errors convention. Refuse
    # extensions and unfamiliar envelopes instead of silently ignoring them.
    require(type(result) is dict and set(result) == {"data"},
            "banner GraphQL errors or unexpected envelope prohibit native admission")
    data = result["data"]
    require(type(data) is dict and set(data) == {"repository"},
            "banner GraphQL repository envelope is incomplete")
    repo = data["repository"]
    require(type(repo) is dict and set(repo) == {"nameWithOwner", "pullRequest"}
            and repo["nameWithOwner"] == repository,
            "banner GraphQL response did not bind the exact repository")
    pr = repo["pullRequest"]
    require(type(pr) is dict and set(pr) == {"number", "reviewThreads"}
            and type(pr["number"]) is int and pr["number"] == pr_number,
            "banner GraphQL response did not bind the exact PR number")
    threads = pr["reviewThreads"]
    contract.verified_review_thread_connection(threads)
    return threads


def fetch_connection(
    repository: str, pr_number: int, *,
    token: str | None = None,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    payload = request_payload(repository, pr_number)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(credential is not None,
            "banner GraphQL transport requires independently scoped GH_TOKEN")
    headers = automation_github_read.token_headers(credential)
    headers["Content-Type"] = "application/json"
    headers["User-Agent"] = "portyu9-banner-readonly-graphql-v1"
    for attempt in range(automation_github_read.ATTEMPTS):
        request = urllib.request.Request(
            GRAPHQL_URL, data=payload, method="POST", headers=headers,
        )
        try:
            # NoRedirect refuses 30x BEFORE urllib can forward bearer credentials.
            if opener is None:
                response_context = urllib.request.build_opener(NoRedirect()).open(
                    request, timeout=automation_github_read.TIMEOUT_SECONDS,
                )
            else:
                response_context = opener(
                    request, timeout=automation_github_read.TIMEOUT_SECONDS,
                )
            with response_context as response:
                require(response.status == 200 and response.geturl() == GRAPHQL_URL,
                        "banner GraphQL response is redirected or not HTTP 200")
                require(response.headers.get_content_type() == "application/json",
                        "banner GraphQL response must have JSON content type")
                body = response.read(MAX_RESPONSE_BYTES + 1)
            return parse_connection(body, repository, pr_number)
        except urllib.error.HTTPError as exc:
            if (attempt + 1 == automation_github_read.ATTEMPTS
                    or not automation_github_read.retryable_http_error(exc)):
                raise ValueError(f"banner GraphQL HTTP {exc.code} is terminal") from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: read-only banner GraphQL transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{automation_github_read.ATTEMPTS}",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 == automation_github_read.ATTEMPTS:
                raise ValueError("banner GraphQL transient transport retries exhausted") from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            sleeper(delay)
    raise ValueError("unreachable banner GraphQL transport retry state")


class _FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return self.get("Content-Type", "application/json").split(";", 1)[0]


class _FixtureResponse:
    def __init__(
        self, body: bytes, *,
        status: int = 200, final_url: str = GRAPHQL_URL,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self.final_url = final_url
        self.headers = _FixtureHeaders({"Content-Type": content_type})
        self.body = body

    def __enter__(self) -> "_FixtureResponse":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def _response(connection: dict[str, Any], *, number: int = 27,
              repository: str = REPOSITORY) -> bytes:
    return json.dumps({
        "data": {"repository": {
            "nameWithOwner": repository,
            "pullRequest": {"number": number, "reviewThreads": connection},
        }},
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def self_test() -> None:
    require(GRAPHQL_URL == "https://api.github.com/graphql"
            and REPOSITORY == contract.REPOSITORY
            and MAX_RESPONSE_BYTES == 1_000_000,
            "banner GraphQL scoped transport constants drifted")
    require(QUERY == (
        "query($owner:String!,$name:String!,$number:Int!){"
        "repository(owner:$owner,name:$name){nameWithOwner "
        "pullRequest(number:$number){number "
        "reviewThreads(first:100){totalCount nodes{id isResolved}"
        "pageInfo{hasNextPage endCursor}}}}}"
    ), "banner GraphQL document lost its exact read-only shape")
    require(automation_github_read.strict_json(
        request_payload(REPOSITORY, 27).decode("utf-8")
    ) == {"query": QUERY, "variables": {
        "owner": "portyu9", "name": "portyu9", "number": 27,
    }}, "banner GraphQL payload is no longer bound to its three variables")

    connection = {
        "nodes": [{"id": "THREAD:1", "isResolved": True}],
        "pageInfo": {"hasNextPage": False, "endCursor": "opaque-cursor"},
        "totalCount": 1,
    }
    require(parse_connection(_response(connection), REPOSITORY, 27) == connection,
            "resolved complete GraphQL review-thread evidence rejected")
    empty = {
        "nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None},
        "totalCount": 0,
    }
    require(parse_connection(_response(empty), REPOSITORY, 27) == empty,
            "complete empty GraphQL review-thread evidence rejected")

    invalid: list[tuple[str, bytes]] = []
    def mutate(label: str, change: Callable[[dict[str, Any]], None]) -> None:
        sample = copy.deepcopy(connection)
        change(sample)
        invalid.append((label, _response(sample)))
    mutate("unresolved", lambda x: x["nodes"][0].update(isResolved=False))
    mutate("next page", lambda x: x["pageInfo"].update(hasNextPage=True))
    mutate("wrong total count", lambda x: x.update(totalCount=2))
    mutate("boolean count", lambda x: x.update(totalCount=True))
    mutate("oversized", lambda x: x.update(totalCount=101))
    mutate("missing cursor", lambda x: x["pageInfo"].pop("endCursor"))
    mutate("wrong cursor type", lambda x: x["pageInfo"].update(endCursor=27))
    mutate("wrong node type", lambda x: x["nodes"][0].update(isResolved="true"))
    mutate("duplicate node", lambda x: x["nodes"].append(copy.deepcopy(x["nodes"][0])))
    mutate("unknown node key", lambda x: x["nodes"][0].update(author="untrusted"))
    mutate("missing nodes", lambda x: x.pop("nodes"))
    invalid.extend([
        ("wrong owner", _response(connection, repository="elsewhere/repo")),
        ("wrong PR", _response(connection, number=28)),
        ("partial data", _response(connection).replace(b'{"data":', b'{"errors":[],"data":')),
        ("missing repository", b'{"data":{"repository":null}}'),
        ("unknown root member", _response(connection).replace(b'{"data":', b'{"extra":1,"data":')),
        ("duplicate root member", b'{"data":null,"data":null}'),
        ("not JSON", b"<html>redirected</html>"),
        ("not UTF-8", b"\xff"),
        ("excessive bytes", b"x" * (MAX_RESPONSE_BYTES + 1)),
        ("empty response", b""),
    ])
    for label, body in invalid:
        try:
            parse_connection(body, REPOSITORY, 27)
        except (ValueError, TypeError, KeyError):
            continue
        raise AssertionError(f"banner GraphQL accepted unsafe evidence: {label}")

    for repository, number in (
        ("other/repo", 27), (REPOSITORY + "/extra", 27),
        (REPOSITORY, True), (REPOSITORY, 0),
        (REPOSITORY, -1), (REPOSITORY, 2**31),
    ):
        try:
            request_payload(repository, number)
        except ValueError:
            continue
        raise AssertionError("banner GraphQL accepted unreviewed query variables")

    calls: list[bytes] = []
    delays: list[float] = []
    sequence: list[Any] = [
        urllib.error.HTTPError(GRAPHQL_URL, 503, "fixture", {}, None),
        urllib.error.HTTPError(
            GRAPHQL_URL, 403, "fixture",
            {"X-RateLimit-Remaining": "0", "Retry-After": "1"}, None,
        ),
        _FixtureResponse(_response(connection)),
    ]

    def retry_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.full_url == GRAPHQL_URL
                and request.get_method() == "POST"
                and timeout == automation_github_read.TIMEOUT_SECONDS
                and request.get_header("Authorization") == "Bearer scoped-fixture-token"
                and request.get_header("Content-type") == "application/json"
                and request.data == request_payload(REPOSITORY, 27),
                "banner GraphQL retry fixture lost exact endpoint, bearer or query")
        calls.append(bytes(request.data))
        result = sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    require(fetch_connection(
        REPOSITORY, 27, token="scoped-fixture-token",
        opener=retry_open, sleeper=delays.append,
    ) == connection, "bounded transient GraphQL retries failed")
    require(len(calls) == 3 and calls[0] == calls[1] == calls[2]
            and delays == [1.0, 1.0],
            "GraphQL retries must replay only the identical fixed query")
    rejected: list[tuple[str, Callable[..., Any]]] = [
        ("redirect", lambda *_args, **_kwargs: _FixtureResponse(
            _response(connection), final_url="https://attacker.invalid/graphql")),
        ("non-200", lambda *_args, **_kwargs: _FixtureResponse(
            _response(connection), status=302)),
        ("bad content type", lambda *_args, **_kwargs: _FixtureResponse(
            _response(connection), content_type="text/html")),
        ("GraphQL errors", lambda *_args, **_kwargs: _FixtureResponse(
            b'{"errors":[{"message":"denied"}],"data":null}')),
        ("401", lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError(GRAPHQL_URL, 401, "fixture", {}, None))),
    ]
    for label, fake_open in rejected:
        attempts = [0]
        def observed_open(request: urllib.request.Request, *, timeout: int) -> Any:
            attempts[0] += 1
            return fake_open(request, timeout=timeout)
        try:
            fetch_connection(REPOSITORY, 27, token="scoped-fixture-token",
                             opener=observed_open, sleeper=lambda _: None)
        except ValueError:
            require(attempts == [1],
                    f"terminal banner GraphQL {label} was replayed")
        else:
            raise AssertionError(f"unsafe GraphQL transport accepted: {label}")
    print("banner GraphQL review threads: fixed query, exact identity, complete pages and fail-closed retries PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            require(args.repository is None and args.pr_number is None,
                    "--self-test cannot accept repository or PR")
            self_test()
            return 0
        require(args.repository is not None and args.pr_number is not None,
                "banner GraphQL requires --repository and --pr-number")
        connection = fetch_connection(args.repository, args.pr_number)
        sys.stdout.write(json.dumps(connection, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
