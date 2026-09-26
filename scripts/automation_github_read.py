#!/usr/bin/env python3
"""Authenticated, bounded, read-only GitHub REST transport for governed automation."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com/"
ATTEMPTS = 3
TIMEOUT_SECONDS = 20
BACKOFF_SECONDS = (1.0, 2.0)
MAX_RETRY_AFTER_SECONDS = 5.0
MAX_RESPONSE_BYTES = 8_000_000
RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})
REPOSITORY_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"GitHub API JSON contains duplicate object key: {key}")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=unique)


def normalize_endpoint(value: str) -> str:
    require(isinstance(value, str) and value == value.strip() and bool(value),
            "GitHub API endpoint must be one nonempty trimmed string")
    require("\\" not in value and not any(ord(character) < 0x20 for character in value),
            "GitHub API endpoint contains forbidden characters")
    parsed = urllib.parse.urlsplit(value)
    require(not parsed.scheme and not parsed.netloc and not parsed.fragment,
            "GitHub API endpoint must be relative to api.github.com")
    require(not parsed.path.startswith("/") and ".." not in parsed.path.split("/"),
            "GitHub API endpoint must be a traversal-free relative path")
    segments = parsed.path.split("/")
    require(
        len(segments) >= 4
        and segments[0] == "repos"
        and REPOSITORY_SEGMENT.fullmatch(segments[1]) is not None
        and REPOSITORY_SEGMENT.fullmatch(segments[2]) is not None,
        "GitHub API endpoint must be repository-scoped under repos/{owner}/{repo}/...",
    )
    return value


def token_headers(token: str) -> dict[str, str]:
    require(token == token.strip() and bool(token),
            "GH_TOKEN must be nonempty and free of surrounding whitespace")
    require(len(token) <= 1024 and all(0x21 <= ord(character) <= 0x7E for character in token),
            "GH_TOKEN contains invalid characters")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "portyu9-governed-github-read-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }


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


def retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    if exc.code in RETRYABLE_HTTP_STATUS:
        return True
    if exc.code != 403:
        return False
    headers = exc.headers or {}
    return headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))


def retry_delay_seconds(exc: BaseException, failure_index: int) -> float:
    default = BACKOFF_SECONDS[min(failure_index, len(BACKOFF_SECONDS) - 1)]
    if not isinstance(exc, urllib.error.HTTPError) or not exc.headers:
        return default
    raw = str(exc.headers.get("Retry-After") or "").strip()
    try:
        requested = float(raw)
    except ValueError:
        return default
    return max(0.0, min(requested, MAX_RETRY_AFTER_SECONDS))


def get_json_text(
    endpoint: str,
    *,
    token: str | None = None,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> str:
    normalized = normalize_endpoint(endpoint)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(credential is not None, "GH_TOKEN is required for governed GitHub API reads")
    url = urllib.parse.urljoin(API_ROOT, normalized)

    for attempt in range(ATTEMPTS):
        request = urllib.request.Request(
            url,
            method="GET",
            headers=token_headers(credential),
        )
        try:
            if opener is None:
                response_context = urllib.request.build_opener(NoRedirect()).open(
                    request,
                    timeout=TIMEOUT_SECONDS,
                )
            else:
                response_context = opener(request, timeout=TIMEOUT_SECONDS)
            with response_context as response:
                require(response.status == 200, f"GitHub API GET returned unexpected HTTP {response.status}")
                require(response.geturl() == url, "GitHub API GET was redirected")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                require(len(raw) <= MAX_RESPONSE_BYTES, "GitHub API response exceeds size bound")
                require(
                    response.headers.get_content_type() == "application/json",
                    "GitHub API response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"GitHub API response is not UTF-8: {exc}") from exc
            strict_json(text)
            return text
        except urllib.error.HTTPError as exc:
            if attempt + 1 >= ATTEMPTS or not retryable_http_error(exc):
                raise ValueError(f"GitHub API GET returned HTTP {exc.code}") from exc
            delay = retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: governed GitHub API GET transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= ATTEMPTS:
                raise ValueError(
                    f"GitHub API GET exhausted transient transport retry budget: {exc}"
                ) from exc
            delay = retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed GitHub API GET transient transport failure; "
                f"attempt {attempt + 1}/{ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable governed GitHub API retry state")


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
    require(ATTEMPTS == 3 and TIMEOUT_SECONDS == 20,
            "governed GitHub read attempt/timeout budget changed")
    require(BACKOFF_SECONDS == (1.0, 2.0),
            "governed GitHub read deterministic backoff changed")
    require(MAX_RETRY_AFTER_SECONDS == 5.0,
            "governed GitHub read Retry-After cap changed")
    require(RETRYABLE_HTTP_STATUS == frozenset({408, 429, 500, 502, 503, 504}),
            "governed GitHub read HTTP transient allowlist changed")

    require(
        normalize_endpoint("repos/portyu9/portyu9/actions/runs/123?per_page=100")
        == "repos/portyu9/portyu9/actions/runs/123?per_page=100",
        "repository-scoped endpoint normalization changed",
    )
    for forbidden in (
        "https://api.github.com/repos/portyu9/portyu9/actions/runs/1",
        "/repos/portyu9/portyu9/actions/runs/1",
        "repos/portyu9/portyu9/../other",
        "users/portyu9",
    ):
        try:
            normalize_endpoint(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"governed GitHub read accepted forbidden endpoint: {forbidden}")

    rate_limited = urllib.error.HTTPError(
        API_ROOT, 403, "fixture",
        {"X-RateLimit-Remaining": "0", "Retry-After": "999"}, None,
    )
    ordinary_forbidden = urllib.error.HTTPError(API_ROOT, 403, "fixture", {}, None)
    unauthorized = urllib.error.HTTPError(API_ROOT, 401, "fixture", {}, None)
    unavailable = urllib.error.HTTPError(API_ROOT, 503, "fixture", {}, None)
    require(retryable_http_error(rate_limited),
            "rate-limit-evidenced HTTP 403 must be retryable")
    require(not retryable_http_error(ordinary_forbidden),
            "ordinary HTTP 403 must remain terminal")
    require(not retryable_http_error(unauthorized),
            "HTTP 401 must remain terminal")
    require(retryable_http_error(unavailable),
            "HTTP 503 must remain retryable")
    require(retry_delay_seconds(rate_limited, 0) == 5.0,
            "Retry-After cap changed")
    require(retry_delay_seconds(unavailable, 0) == 1.0
            and retry_delay_seconds(unavailable, 1) == 2.0,
            "deterministic backoff schedule changed")

    endpoint = "repos/portyu9/portyu9/actions/runs/123"
    target = API_ROOT + endpoint
    calls: list[str] = []
    sleeps: list[float] = []
    sequence: list[Any] = [
        urllib.error.HTTPError(
            target, 403, "fixture",
            {"X-RateLimit-Remaining": "0", "Retry-After": "1"}, None,
        ),
        urllib.error.HTTPError(target, 503, "fixture", {}, None),
        _FixtureResponse(target, b'{"id":123}\n'),
    ]

    def fixture_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.get_method() == "GET", "governed retry fixture observed non-GET method")
        require(timeout == TIMEOUT_SECONDS, "governed retry fixture timeout changed")
        calls.append(request.full_url)
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
    require(text == '{"id":123}\n', "governed retry fixture changed response bytes")
    require(calls == [target, target, target],
            "each governed retry must issue one fresh GET to the exact endpoint")
    require(sleeps == [1.0, 2.0],
            "governed retry fixture backoff sequence changed")

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
        require("HTTP 403" in str(exc), "terminal 403 self-test failed for wrong reason")
    else:
        raise ValueError("governed GitHub read retried or accepted ordinary HTTP 403")
    require(len(terminal_calls) == 1,
            "ordinary HTTP 403 must terminate without retry")

    try:
        strict_json('{"id":1,"id":2}')
    except ValueError as exc:
        require("duplicate object key" in str(exc),
                "duplicate JSON self-test failed for wrong reason")
    else:
        raise ValueError("governed GitHub read accepted duplicate JSON object keys")


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
                "Governed GitHub read client self-test passed: authenticated repository-scoped "
                "GET only; 3 attempts/20s timeout; 1s/2s backoff; capped Retry-After; "
                "408/429/5xx and rate-limit-evidenced 403 only; duplicate JSON rejected."
            )
            return 0
        require(args.endpoint is not None, "GitHub API endpoint is required")
        sys.stdout.write(get_json_text(args.endpoint))
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
