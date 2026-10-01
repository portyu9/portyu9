#!/usr/bin/env python3
"""Transient-safe GET-only GitHub transport for Ruleset Administration bootstrap reads."""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

import automation_github_read

APP_INSTALLATION_ENDPOINT = re.compile(r"^app/installations/([1-9][0-9]{0,18})$")
INSTALLATION_REPOSITORIES_ENDPOINT = "installation/repositories?per_page=100"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_endpoint(value: str) -> str:
    require(
        isinstance(value, str) and value == value.strip() and bool(value),
        "Ruleset admin GitHub API endpoint must be one nonempty trimmed string",
    )
    require(
        "\\" not in value and not any(ord(character) < 0x20 for character in value),
        "Ruleset admin GitHub API endpoint contains forbidden characters",
    )
    parsed = urllib.parse.urlsplit(value)
    require(
        not parsed.scheme and not parsed.netloc and not parsed.fragment,
        "Ruleset admin GitHub API endpoint must be relative to api.github.com",
    )
    require(
        not parsed.path.startswith("/") and ".." not in parsed.path.split("/"),
        "Ruleset admin GitHub API endpoint must be traversal-free",
    )
    if APP_INSTALLATION_ENDPOINT.fullmatch(value):
        return value
    require(
        value == INSTALLATION_REPOSITORIES_ENDPOINT,
        "Ruleset admin GitHub API endpoint is outside the reviewed bootstrap allowlist",
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
    require(
        credential is not None,
        "GH_TOKEN is required for governed Ruleset admin GitHub API reads",
    )
    url = urllib.parse.urljoin(automation_github_read.API_ROOT, normalized)

    for attempt in range(automation_github_read.ATTEMPTS):
        request = urllib.request.Request(
            url,
            method="GET",
            headers=automation_github_read.token_headers(credential),
        )
        try:
            if opener is None:
                response_context = urllib.request.build_opener(
                    automation_github_read.NoRedirect()
                ).open(
                    request,
                    timeout=automation_github_read.TIMEOUT_SECONDS,
                )
            else:
                response_context = opener(
                    request,
                    timeout=automation_github_read.TIMEOUT_SECONDS,
                )
            with response_context as response:
                require(
                    response.status == 200,
                    f"Ruleset admin GitHub API GET returned unexpected HTTP {response.status}",
                )
                require(
                    response.geturl() == url,
                    "Ruleset admin GitHub API GET was redirected",
                )
                raw = response.read(automation_github_read.MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= automation_github_read.MAX_RESPONSE_BYTES,
                    "Ruleset admin GitHub API response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "Ruleset admin GitHub API response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"Ruleset admin GitHub API response is not UTF-8: {exc}"
                ) from exc
            automation_github_read.strict_json(text)
            return text
        except urllib.error.HTTPError as exc:
            if (
                attempt + 1 >= automation_github_read.ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(
                    f"Ruleset admin GitHub API GET returned HTTP {exc.code}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed Ruleset admin GitHub API GET transient "
                f"HTTP {exc.code}; attempt {attempt + 1}/"
                f"{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= automation_github_read.ATTEMPTS:
                raise ValueError(
                    "Ruleset admin GitHub API GET exhausted transient transport "
                    f"retry budget: {exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed Ruleset admin GitHub API GET transient transport "
                f"failure; attempt {attempt + 1}/"
                f"{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable Ruleset admin GitHub API retry state")


class _FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return str(self.get("Content-Type", "application/json")).split(";", 1)[0]


class _FixtureResponse:
    def __init__(
        self,
        url: str,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self._url = url
        self._body = body
        self.headers = _FixtureHeaders({"Content-Type": content_type})

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
        normalize_endpoint("app/installations/123")
        == "app/installations/123",
        "Ruleset admin App installation endpoint normalization changed",
    )
    require(
        normalize_endpoint(INSTALLATION_REPOSITORIES_ENDPOINT)
        == INSTALLATION_REPOSITORIES_ENDPOINT,
        "Ruleset admin installation-repositories endpoint normalization changed",
    )

    for invalid in (
        "",
        " app/installations/123",
        "/app/installations/123",
        "https://api.github.com/app/installations/123",
        "app/installations/0",
        "app/installations/123/access_tokens",
        "installation/repositories",
        "installation/repositories?per_page=99",
        "repos/portyu9/portyu9/rulesets/22148161",
        "../app/installations/123",
    ):
        try:
            normalize_endpoint(invalid)
        except ValueError:
            pass
        else:
            raise ValueError(
                f"Ruleset admin endpoint allowlist accepted forbidden input: {invalid!r}"
            )

    endpoint = "app/installations/123"
    expected_url = urllib.parse.urljoin(automation_github_read.API_ROOT, endpoint)
    attempts: list[str] = []
    sleeps: list[float] = []

    def transient_then_success(
        request: urllib.request.Request,
        *,
        timeout: int,
    ) -> Any:
        require(
            timeout == automation_github_read.TIMEOUT_SECONDS,
            "Ruleset admin GET timeout changed",
        )
        require(
            request.full_url == expected_url,
            "Ruleset admin GET URL changed",
        )
        require(
            request.get_method() == "GET",
            "Ruleset admin helper acquired non-GET transport",
        )
        require(
            request.headers.get("Authorization") == "Bearer test-token",
            "Ruleset admin helper lost explicit Bearer authorization",
        )
        attempts.append(request.full_url)
        if len(attempts) == 1:
            raise urllib.error.HTTPError(
                expected_url,
                503,
                "Service Unavailable",
                _FixtureHeaders(),
                None,
            )
        return _FixtureResponse(expected_url, b'{"id":123}')

    text = get_json_text(
        endpoint,
        token="test-token",
        opener=transient_then_success,
        sleeper=sleeps.append,
    )
    require(text == '{"id":123}', "Ruleset admin GET altered response text")
    require(
        len(attempts) == 2 and sleeps == [1.0],
        "Ruleset admin transient retry budget/backoff changed",
    )

    terminal_attempts = 0

    def terminal_forbidden(
        _request: urllib.request.Request,
        *,
        timeout: int,
    ) -> Any:
        nonlocal terminal_attempts
        require(
            timeout == automation_github_read.TIMEOUT_SECONDS,
            "Ruleset admin terminal fixture timeout changed",
        )
        terminal_attempts += 1
        raise urllib.error.HTTPError(
            expected_url,
            403,
            "Forbidden",
            _FixtureHeaders({"X-RateLimit-Remaining": "1"}),
            None,
        )

    try:
        get_json_text(
            endpoint,
            token="test-token",
            opener=terminal_forbidden,
            sleeper=lambda _delay: None,
        )
    except ValueError as exc:
        require(
            "HTTP 403" in str(exc),
            "Ruleset admin ordinary 403 terminal error changed",
        )
    else:
        raise ValueError("Ruleset admin ordinary 403 unexpectedly retried/succeeded")
    require(
        terminal_attempts == 1,
        "Ruleset admin ordinary 403 was retried",
    )

    rate_attempts = 0
    rate_sleeps: list[float] = []

    def rate_limited_then_success(
        _request: urllib.request.Request,
        *,
        timeout: int,
    ) -> Any:
        nonlocal rate_attempts
        require(
            timeout == automation_github_read.TIMEOUT_SECONDS,
            "Ruleset admin rate-limit fixture timeout changed",
        )
        rate_attempts += 1
        if rate_attempts == 1:
            raise urllib.error.HTTPError(
                expected_url,
                403,
                "Rate limited",
                _FixtureHeaders(
                    {
                        "X-RateLimit-Remaining": "0",
                        "Retry-After": "99",
                    }
                ),
                None,
            )
        return _FixtureResponse(expected_url, b'{"id":123}')

    get_json_text(
        endpoint,
        token="test-token",
        opener=rate_limited_then_success,
        sleeper=rate_sleeps.append,
    )
    require(
        rate_attempts == 2
        and rate_sleeps == [automation_github_read.MAX_RETRY_AFTER_SECONDS],
        "Ruleset admin rate-limit retry/cap changed",
    )

    duplicate = b'{"id":123,"id":124}'

    def duplicate_json(
        _request: urllib.request.Request,
        *,
        timeout: int,
    ) -> Any:
        require(
            timeout == automation_github_read.TIMEOUT_SECONDS,
            "Ruleset admin duplicate fixture timeout changed",
        )
        return _FixtureResponse(expected_url, duplicate)

    try:
        get_json_text(
            endpoint,
            token="test-token",
            opener=duplicate_json,
            sleeper=lambda _delay: None,
        )
    except ValueError as exc:
        require(
            "duplicate object key" in str(exc),
            "Ruleset admin duplicate-key failure changed",
        )
    else:
        raise ValueError("Ruleset admin duplicate-key JSON unexpectedly passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch one reviewed Ruleset Administration bootstrap JSON endpoint "
            "with bounded transient retries."
        )
    )
    parser.add_argument("endpoint")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic transport contract fixtures and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("Ruleset admin governed read self-test passed")
        return 0
    text = get_json_text(args.endpoint)
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
