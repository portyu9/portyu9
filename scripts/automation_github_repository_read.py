#!/usr/bin/env python3
"""Authenticated bounded GET transport for exact GitHub repository-root metadata."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

import automation_github_read

ATTEMPTS = automation_github_read.ATTEMPTS
TIMEOUT_SECONDS = automation_github_read.TIMEOUT_SECONDS
BACKOFF_SECONDS = automation_github_read.BACKOFF_SECONDS
MAX_RETRY_AFTER_SECONDS = automation_github_read.MAX_RETRY_AFTER_SECONDS
MAX_RESPONSE_BYTES = automation_github_read.MAX_RESPONSE_BYTES
RETRYABLE_HTTP_STATUS = automation_github_read.RETRYABLE_HTTP_STATUS


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_endpoint(value: str) -> str:
    """Accept exactly repos/{owner}/{repo}; reject all broader or deeper API authority."""
    require(
        isinstance(value, str) and value == value.strip() and bool(value),
        "GitHub repository-root endpoint must be one nonempty trimmed string",
    )
    require(
        "\\" not in value and not any(ord(character) < 0x20 for character in value),
        "GitHub repository-root endpoint contains forbidden characters",
    )
    parsed = urllib.parse.urlsplit(value)
    require(
        not parsed.scheme and not parsed.netloc and not parsed.query and not parsed.fragment,
        "GitHub repository-root endpoint must be an unqualified api.github.com path",
    )
    require(
        not parsed.path.startswith("/") and ".." not in parsed.path.split("/"),
        "GitHub repository-root endpoint must be a traversal-free relative path",
    )
    segments = parsed.path.split("/")
    require(
        len(segments) == 3
        and segments[0] == "repos"
        and automation_github_read.REPOSITORY_SEGMENT.fullmatch(segments[1]) is not None
        and automation_github_read.REPOSITORY_SEGMENT.fullmatch(segments[2]) is not None,
        "GitHub repository-root endpoint must be exactly repos/{owner}/{repo}",
    )
    return value


def get_json_text(
    endpoint: str,
    *,
    token: str | None = None,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> str:
    normalized = normalize_endpoint(endpoint)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(credential is not None, "GH_TOKEN is required for governed GitHub repository-root reads")
    url = urllib.parse.urljoin(automation_github_read.API_ROOT, normalized)

    for attempt in range(ATTEMPTS):
        request = urllib.request.Request(
            url,
            method="GET",
            headers=automation_github_read.token_headers(credential),
        )
        try:
            if opener is None:
                response_context = urllib.request.build_opener(
                    automation_github_read.NoRedirect()
                ).open(request, timeout=TIMEOUT_SECONDS)
            else:
                response_context = opener(request, timeout=TIMEOUT_SECONDS)
            with response_context as response:
                require(
                    response.status == 200,
                    f"GitHub repository-root GET returned unexpected HTTP {response.status}",
                )
                require(
                    response.geturl() == url,
                    "GitHub repository-root GET was redirected",
                )
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= MAX_RESPONSE_BYTES,
                    "GitHub repository-root response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "GitHub repository-root response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"GitHub repository-root response is not UTF-8: {exc}"
                ) from exc
            automation_github_read.strict_json(text)
            return text
        except urllib.error.HTTPError as exc:
            if (
                attempt + 1 >= ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(
                    f"GitHub repository-root GET returned HTTP {exc.code}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: governed GitHub repository-root GET transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= ATTEMPTS:
                raise ValueError(
                    "GitHub repository-root GET exhausted transient transport retry budget: "
                    f"{exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed GitHub repository-root GET transient transport failure; "
                f"attempt {attempt + 1}/{ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable governed GitHub repository-root retry state")


class _FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return "application/json"


class _FixtureResponse:
    def __init__(self, url: str, body: bytes) -> None:
        self.status = 200
        self._url = url
        self._body = body
        self.headers = _FixtureHeaders()

    def __enter__(self) -> "_FixtureResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._body


def self_test() -> None:
    require(
        ATTEMPTS == automation_github_read.ATTEMPTS == 3
        and TIMEOUT_SECONDS == automation_github_read.TIMEOUT_SECONDS == 20,
        "repository-root retry attempt/timeout budget diverged from canonical policy",
    )
    require(
        BACKOFF_SECONDS == automation_github_read.BACKOFF_SECONDS == (1.0, 2.0)
        and MAX_RETRY_AFTER_SECONDS
        == automation_github_read.MAX_RETRY_AFTER_SECONDS
        == 5.0,
        "repository-root retry backoff/Retry-After policy diverged from canonical policy",
    )
    require(
        RETRYABLE_HTTP_STATUS
        == automation_github_read.RETRYABLE_HTTP_STATUS
        == frozenset({408, 429, 500, 502, 503, 504}),
        "repository-root retryable HTTP allowlist diverged from canonical policy",
    )
    require(
        normalize_endpoint("repos/github/codeql-action") == "repos/github/codeql-action",
        "reviewed public Action repository-root endpoint was rejected",
    )
    require(
        normalize_endpoint("repos/portyu9/portyu9") == "repos/portyu9/portyu9",
        "repository-root normalization changed",
    )
    for forbidden in (
        "https://api.github.com/repos/github/codeql-action",
        "/repos/github/codeql-action",
        "repos/github/codeql-action/releases",
        "repos/github/codeql-action?x=1",
        "repos/github/codeql-action#fragment",
        "repos/github/../codeql-action",
        "repos/github/",
        "users/github",
    ):
        try:
            normalize_endpoint(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(
                f"repository-root reader accepted forbidden endpoint: {forbidden}"
            )

    endpoint = "repos/github/codeql-action"
    target = automation_github_read.API_ROOT + endpoint
    calls: list[urllib.request.Request] = []
    sleeps: list[float] = []
    sequence: list[Any] = [
        urllib.error.HTTPError(
            target,
            403,
            "fixture",
            {"X-RateLimit-Remaining": "0", "Retry-After": "1"},
            None,
        ),
        urllib.error.HTTPError(target, 503, "fixture", {}, None),
        _FixtureResponse(target, b'{"id":1,"full_name":"github/codeql-action"}\n'),
    ]

    def fixture_open(request: urllib.request.Request, *, timeout: int) -> Any:
        calls.append(request)
        require(timeout == TIMEOUT_SECONDS, "repository-root fixture timeout changed")
        result = sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    text = get_json_text(
        endpoint,
        token="fixture-token",
        opener=fixture_open,
        sleeper=sleeps.append,
    )
    require(
        text == '{"id":1,"full_name":"github/codeql-action"}\n',
        "repository-root retry fixture changed response bytes",
    )
    require(
        [request.full_url for request in calls] == [target, target, target]
        and [request.get_method() for request in calls] == ["GET", "GET", "GET"]
        and len({id(request) for request in calls}) == 3,
        "each repository-root retry must issue one fresh GET to the exact endpoint",
    )
    require(
        sleeps == [1.0, 2.0],
        "repository-root retry fixture backoff sequence changed",
    )

    terminal_calls: list[str] = []

    def terminal_open(request: urllib.request.Request, *, timeout: int) -> Any:
        terminal_calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 403, "fixture", {}, None)

    try:
        get_json_text(
            endpoint,
            token="fixture-token",
            opener=terminal_open,
            sleeper=lambda _: None,
        )
    except ValueError as exc:
        require(
            "HTTP 403" in str(exc),
            "repository-root terminal 403 self-test failed for wrong reason",
        )
    else:
        raise ValueError("repository-root reader retried or accepted ordinary HTTP 403")
    require(
        terminal_calls == [target],
        "ordinary repository-root HTTP 403 must terminate without retry",
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("endpoint", nargs="?")
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(args.endpoint is None, "--self-test does not accept an endpoint")
            self_test()
            print(
                "Governed GitHub repository-root reader self-test passed: exact "
                "repos/{owner}/{repo} GET only; canonical 3-attempt transient classifier; "
                "fresh requests; redirects and broader/deeper API authority rejected."
            )
            return 0
        require(args.endpoint is not None, "GitHub repository-root endpoint is required")
        sys.stdout.write(get_json_text(args.endpoint))
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
