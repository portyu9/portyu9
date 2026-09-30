#!/usr/bin/env python3
"""Authenticated bounded transport for the fixed read-only PR review-thread GraphQL query."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.request

import automation_github_read

GRAPHQL_URL = "https://api.github.com/graphql"
EXPECTED_REPOSITORY = "portyu9/portyu9"
QUERY = (
    "query($owner:String!,$name:String!,$number:Int!){"
    "repository(owner:$owner,name:$name){pullRequest(number:$number){"
    "reviewThreads(first:100){nodes{isResolved}pageInfo{hasNextPage}}}}}"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def repository_parts(value: str) -> tuple[str, str]:
    require(isinstance(value, str) and value == value.strip() and bool(value),
            "review-thread repository must be one nonempty trimmed string")
    require(value == EXPECTED_REPOSITORY,
            "review-thread repository must be the exact governed repository")
    parts = value.split("/")
    require(
        len(parts) == 2
        and all(automation_github_read.REPOSITORY_SEGMENT.fullmatch(part) is not None for part in parts),
        "review-thread repository must be owner/name using GitHub repository-segment grammar",
    )
    return parts[0], parts[1]


def query_payload(repository: str, pr_number: int) -> bytes:
    owner, name = repository_parts(repository)
    require(type(pr_number) is int and pr_number > 0,
            "review-thread PR number must be a positive integer")
    require(QUERY.startswith("query(") and "mutation" not in QUERY.lower(),
            "review-thread GraphQL document must remain query-only")
    return json.dumps(
        {
            "query": QUERY,
            "variables": {"owner": owner, "name": name, "number": pr_number},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def query_json_text(
    repository: str,
    pr_number: int,
    *,
    token: str | None = None,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> str:
    payload = query_payload(repository, pr_number)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(credential is not None, "GH_TOKEN is required for governed review-thread reads")
    headers = automation_github_read.token_headers(credential)
    headers["Content-Type"] = "application/json"

    for attempt in range(automation_github_read.ATTEMPTS):
        request = urllib.request.Request(
            GRAPHQL_URL,
            data=payload,
            method="POST",
            headers=headers,
        )
        try:
            if opener is None:
                response_context = urllib.request.build_opener(
                    NoRedirect()
                ).open(request, timeout=automation_github_read.TIMEOUT_SECONDS)
            else:
                response_context = opener(
                    request, timeout=automation_github_read.TIMEOUT_SECONDS
                )
            with response_context as response:
                require(response.status == 200,
                        f"GitHub GraphQL query returned unexpected HTTP {response.status}")
                require(response.geturl() == GRAPHQL_URL,
                        "GitHub GraphQL query was redirected")
                raw = response.read(automation_github_read.MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= automation_github_read.MAX_RESPONSE_BYTES,
                    "GitHub GraphQL response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "GitHub GraphQL response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"GitHub GraphQL response is not UTF-8: {exc}") from exc
            automation_github_read.strict_json(text)
            return text
        except urllib.error.HTTPError as exc:
            if (
                attempt + 1 >= automation_github_read.ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(f"GitHub GraphQL query returned HTTP {exc.code}") from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: governed GitHub GraphQL query transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= automation_github_read.ATTEMPTS:
                raise ValueError(
                    f"GitHub GraphQL query exhausted transient transport retry budget: {exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed GitHub GraphQL query transient transport failure; "
                f"attempt {attempt + 1}/{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable governed GitHub GraphQL retry state")


class _FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return "application/json"


class _FixtureResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self._body = body
        self.headers = _FixtureHeaders()

    def __enter__(self) -> "_FixtureResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def geturl(self) -> str:
        return GRAPHQL_URL

    def read(self, _limit: int) -> bytes:
        return self._body


def self_test() -> None:
    require(GRAPHQL_URL == "https://api.github.com/graphql",
            "review-thread GraphQL endpoint changed")
    require(EXPECTED_REPOSITORY == "portyu9/portyu9",
            "review-thread governed repository changed")
    require(QUERY.startswith("query(") and "mutation" not in QUERY.lower(),
            "review-thread GraphQL document lost query-only identity")
    require("reviewThreads(first:100)" in QUERY and "nodes{isResolved}" in QUERY
            and "pageInfo{hasNextPage}" in QUERY,
            "review-thread GraphQL projection changed")
    require(
        query_payload("portyu9/portyu9", 123)
        == json.dumps(
            {
                "query": QUERY,
                "variables": {"owner": "portyu9", "name": "portyu9", "number": 123},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        "review-thread GraphQL request payload changed",
    )
    for forbidden in (
        "", "portyu9", "openai/openai", "portyu9/portyu9/extra",
        "../portyu9", "portyu9/../repo",
    ):
        try:
            repository_parts(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"review-thread reader accepted forbidden repository: {forbidden!r}")

    calls: list[bytes] = []
    sleeps: list[float] = []
    rate_limited = urllib.error.HTTPError(
        GRAPHQL_URL, 403, "fixture",
        {"X-RateLimit-Remaining": "0", "Retry-After": "1"}, None,
    )
    unavailable = urllib.error.HTTPError(GRAPHQL_URL, 503, "fixture", {}, None)
    sequence: list[Any] = [
        rate_limited,
        unavailable,
        _FixtureResponse(b'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}}\n'),
    ]

    def fixture_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.get_method() == "POST",
                "review-thread retry fixture observed non-POST transport")
        require(request.full_url == GRAPHQL_URL,
                "review-thread retry fixture endpoint changed")
        require(timeout == automation_github_read.TIMEOUT_SECONDS,
                "review-thread retry fixture timeout changed")
        require(request.data is not None,
                "review-thread retry fixture lost request payload")
        body = bytes(request.data)
        decoded = automation_github_read.strict_json(body.decode("utf-8"))
        require(decoded.get("query") == QUERY,
                "review-thread retry fixture query document changed")
        require(decoded.get("variables") == {
            "owner": "portyu9", "name": "portyu9", "number": 123
        }, "review-thread retry fixture variables changed")
        calls.append(body)
        result = sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    text = query_json_text(
        "portyu9/portyu9",
        123,
        token="fixture-token",
        opener=fixture_open,
        sleeper=sleeps.append,
    )
    require('"hasNextPage":false' in text,
            "review-thread retry fixture changed response bytes")
    require(len(calls) == 3 and calls[0] == calls[1] == calls[2],
            "each review-thread retry must replay only the identical fixed query")
    require(sleeps == [1.0, 2.0],
            "review-thread deterministic retry backoff changed")

    terminal_calls = 0

    def terminal_open(request: urllib.request.Request, *, timeout: int) -> Any:
        nonlocal terminal_calls
        terminal_calls += 1
        raise urllib.error.HTTPError(request.full_url, 401, "fixture", {}, None)

    try:
        query_json_text(
            "portyu9/portyu9",
            123,
            token="fixture-token",
            opener=terminal_open,
            sleeper=lambda _: None,
        )
    except ValueError as exc:
        require("HTTP 401" in str(exc),
                "review-thread terminal authorization fixture failed for wrong reason")
    else:
        raise ValueError("review-thread reader retried or accepted HTTP 401")
    require(terminal_calls == 1,
            "review-thread authorization failure must remain terminal")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--repository")
    value.add_argument("--pr-number", type=int)
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(args.repository is None and args.pr_number is None,
                    "--self-test does not accept repository/PR arguments")
            self_test()
            print(
                "Governed review-thread GraphQL reader self-test passed: fixed query-only "
                "document; authenticated no-redirect POST; 3 attempts/20s timeout; "
                "1s/2s backoff; capped Retry-After; transient-only replay."
            )
            return 0
        require(args.repository is not None, "--repository is required")
        require(args.pr_number is not None, "--pr-number is required")
        sys.stdout.write(query_json_text(args.repository, args.pr_number))
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
