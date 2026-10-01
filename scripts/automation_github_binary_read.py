#!/usr/bin/env python3
"""Authenticated, bounded, transient-safe GitHub Actions artifact ZIP download."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

import automation_github_read

MAX_RESPONSE_BYTES = 8_000_000
ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ARTIFACT_ZIP_ENDPOINT = re.compile(
    r"^repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/artifacts/[1-9][0-9]*/zip$"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_artifact_endpoint(value: str) -> str:
    normalized = automation_github_read.normalize_endpoint(value)
    parsed = urllib.parse.urlsplit(normalized)
    require(
        not parsed.query and ARTIFACT_ZIP_ENDPOINT.fullmatch(parsed.path) is not None,
        "binary GitHub read is restricted to one repository artifact ZIP endpoint",
    )
    return normalized


def normalize_signed_location(value: str) -> str:
    require(
        isinstance(value, str) and value == value.strip() and bool(value),
        "artifact ZIP redirect must be one nonempty trimmed URL",
    )
    require(
        not any(ord(character) < 0x20 for character in value),
        "artifact ZIP redirect contains control characters",
    )
    parsed = urllib.parse.urlsplit(value)
    require(
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.port in (None, 443)
        and not parsed.fragment,
        "artifact ZIP redirect must be credential-free HTTPS on the default TLS port",
    )
    return value


def _default_open(request: urllib.request.Request, *, timeout: int) -> Any:
    return urllib.request.build_opener(automation_github_read.NoRedirect()).open(
        request,
        timeout=timeout,
    )


def _api_redirect(
    url: str,
    token: str,
    *,
    opener: Callable[..., Any],
) -> str:
    request = urllib.request.Request(
        url,
        method="GET",
        headers=automation_github_read.token_headers(token),
    )
    try:
        response_context = opener(
            request,
            timeout=automation_github_read.TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise
        location = str((exc.headers or {}).get("Location") or "")
        return normalize_signed_location(location)

    with response_context as response:
        raise ValueError(
            f"artifact ZIP GitHub endpoint returned unexpected HTTP {response.status}; expected 302"
        )


def _signed_bytes(
    location: str,
    *,
    opener: Callable[..., Any],
) -> bytes:
    request = urllib.request.Request(
        location,
        method="GET",
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "portyu9-governed-github-binary-read-v1",
        },
    )
    response_context = opener(
        request,
        timeout=automation_github_read.TIMEOUT_SECONDS,
    )
    with response_context as response:
        require(
            response.status == 200,
            f"artifact ZIP signed download returned unexpected HTTP {response.status}",
        )
        require(
            response.geturl() == location,
            "artifact ZIP signed download was redirected again",
        )
        raw_length = str(response.headers.get("Content-Length") or "").strip()
        if raw_length:
            require(
                raw_length.isdigit(),
                "artifact ZIP signed response Content-Length is malformed",
            )
            require(
                int(raw_length) <= MAX_RESPONSE_BYTES,
                "artifact ZIP signed response exceeds size bound",
            )
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        require(
            len(raw) <= MAX_RESPONSE_BYTES,
            "artifact ZIP signed response exceeds size bound",
        )
    require(raw.startswith(ZIP_PREFIXES), "artifact ZIP response does not have a ZIP signature")
    return raw


def _atomic_write(target: Path, raw: bytes) -> None:
    require(target.name not in {"", ".", ".."}, "artifact ZIP output path must name a file")
    parent = target.parent
    require(parent.exists() and parent.is_dir(), "artifact ZIP output parent must exist")
    require(not target.exists() or not target.is_dir(), "artifact ZIP output must not be a directory")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def download_artifact_zip(
    endpoint: str,
    output: str | Path,
    *,
    token: str | None = None,
    api_opener: Callable[..., Any] = _default_open,
    signed_opener: Callable[..., Any] = _default_open,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    normalized = normalize_artifact_endpoint(endpoint)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(credential is not None, "GH_TOKEN is required for governed GitHub binary reads")
    automation_github_read.token_headers(credential)
    target = Path(output)
    url = urllib.parse.urljoin(automation_github_read.API_ROOT, normalized)

    for attempt in range(automation_github_read.ATTEMPTS):
        try:
            location = _api_redirect(url, credential, opener=api_opener)
            raw = _signed_bytes(location, opener=signed_opener)
            _atomic_write(target, raw)
            return
        except urllib.error.HTTPError as exc:
            if (
                attempt + 1 >= automation_github_read.ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(
                    f"artifact ZIP download returned HTTP {exc.code}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed artifact ZIP GET transient HTTP "
                f"{exc.code}; attempt {attempt + 1}/{automation_github_read.ATTEMPTS}, "
                f"sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= automation_github_read.ATTEMPTS:
                raise ValueError(
                    f"artifact ZIP download exhausted transient transport retry budget: {exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed artifact ZIP GET transient transport failure; "
                f"attempt {attempt + 1}/{automation_github_read.ATTEMPTS}, "
                f"sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable governed artifact ZIP retry state")


class _FixtureHeaders(dict[str, str]):
    pass


class _FixtureResponse:
    def __init__(self, url: str, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = 200
        self._url = url
        self._body = body
        self.headers = _FixtureHeaders(headers or {})

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
        automation_github_read.ATTEMPTS == 3
        and automation_github_read.TIMEOUT_SECONDS == 20
        and automation_github_read.BACKOFF_SECONDS == (1.0, 2.0)
        and automation_github_read.MAX_RETRY_AFTER_SECONDS == 5.0,
        "artifact ZIP helper lost canonical governed retry budgets",
    )
    require(MAX_RESPONSE_BYTES == 8_000_000, "artifact ZIP response-size bound changed")

    endpoint = "repos/portyu9/portyu9/actions/artifacts/123/zip"
    require(normalize_artifact_endpoint(endpoint) == endpoint, "artifact ZIP endpoint normalization changed")
    for forbidden in (
        "repos/portyu9/portyu9/actions/artifacts/0/zip",
        "repos/portyu9/portyu9/actions/artifacts/123/zip?x=1",
        "repos/portyu9/portyu9/actions/runs/123/artifacts",
        "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/123/zip",
    ):
        try:
            normalize_artifact_endpoint(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"artifact ZIP helper accepted forbidden endpoint: {forbidden}")

    signed = "https://results.example.invalid/artifact.zip?signature=fixture"
    require(normalize_signed_location(signed) == signed, "signed redirect normalization changed")
    for forbidden in (
        "http://results.example.invalid/artifact.zip",
        "https://user:secret@results.example.invalid/artifact.zip",
        "https://results.example.invalid:8443/artifact.zip",
        "https://results.example.invalid/artifact.zip#fragment",
    ):
        try:
            normalize_signed_location(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"artifact ZIP helper accepted forbidden redirect: {forbidden}")

    api_url = automation_github_read.API_ROOT + endpoint
    api_calls: list[str] = []
    signed_calls: list[str] = []
    sleeps: list[float] = []
    api_sequence: list[Any] = [
        urllib.error.HTTPError(api_url, 503, "fixture", {}, None),
        urllib.error.HTTPError(api_url, 302, "fixture", {"Location": signed}, None),
        urllib.error.HTTPError(api_url, 302, "fixture", {"Location": signed}, None),
    ]
    signed_sequence: list[Any] = [
        urllib.error.HTTPError(signed, 503, "fixture", {}, None),
        _FixtureResponse(
            signed,
            b"PK\x03\x04fixture-artifact",
            {"Content-Length": "20"},
        ),
    ]

    def api_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.get_method() == "GET", "artifact ZIP fixture observed non-GET API method")
        require(timeout == automation_github_read.TIMEOUT_SECONDS, "artifact ZIP API timeout changed")
        require(
            request.get_header("Authorization") == "Bearer fixture-token",
            "artifact ZIP GitHub request lost bearer token",
        )
        api_calls.append(request.full_url)
        result = api_sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def signed_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.get_method() == "GET", "artifact ZIP fixture observed non-GET signed method")
        require(timeout == automation_github_read.TIMEOUT_SECONDS, "artifact ZIP signed timeout changed")
        require(
            request.get_header("Authorization") is None,
            "artifact ZIP bearer token was forwarded to signed redirect target",
        )
        signed_calls.append(request.full_url)
        result = signed_sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    with tempfile.TemporaryDirectory(prefix="artifact-zip-helper-self-test-") as temporary:
        target = Path(temporary) / "receipt.zip"
        download_artifact_zip(
            endpoint,
            target,
            token="fixture-token",
            api_opener=api_open,
            signed_opener=signed_open,
            sleeper=sleeps.append,
        )
        require(
            target.read_bytes() == b"PK\x03\x04fixture-artifact",
            "artifact ZIP helper changed complete output bytes",
        )
        require(
            api_calls == [api_url, api_url, api_url],
            "every artifact ZIP retry must restart with one fresh GitHub API GET",
        )
        require(
            signed_calls == [signed, signed],
            "artifact ZIP signed-target retry topology changed",
        )
        require(sleeps == [1.0, 2.0], "artifact ZIP deterministic retry delays changed")

        terminal = Path(temporary) / "terminal.zip"
        terminal_api_calls: list[str] = []
        terminal_signed_calls: list[str] = []

        def terminal_api_open(request: urllib.request.Request, *, timeout: int) -> Any:
            terminal_api_calls.append(request.full_url)
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "fixture",
                {"Location": signed},
                None,
            )

        def terminal_signed_open(request: urllib.request.Request, *, timeout: int) -> Any:
            terminal_signed_calls.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, 403, "fixture", {}, None)

        try:
            download_artifact_zip(
                endpoint,
                terminal,
                token="fixture-token",
                api_opener=terminal_api_open,
                signed_opener=terminal_signed_open,
                sleeper=lambda _: None,
            )
        except ValueError as exc:
            require("HTTP 403" in str(exc), "artifact ZIP terminal 403 failed for wrong reason")
        else:
            raise ValueError("artifact ZIP helper retried or accepted ordinary signed HTTP 403")
        require(
            terminal_api_calls == [api_url] and terminal_signed_calls == [signed],
            "artifact ZIP ordinary signed HTTP 403 must terminate without retry",
        )
        require(not terminal.exists(), "artifact ZIP terminal failure left partial output")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("endpoint", nargs="?")
    value.add_argument("output", nargs="?")
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(args.endpoint is None and args.output is None, "--self-test accepts no endpoint/output")
            self_test()
            print(
                "Governed artifact ZIP binary read self-test passed: artifact endpoint only; "
                "authenticated fresh API GET per retry; token-free one-hop HTTPS download; "
                "3 attempts/20s timeout; canonical transient classifier; 8 MB complete-byte bound; "
                "atomic output."
            )
            return 0
        require(args.endpoint is not None and args.output is not None, "endpoint and output are required")
        download_artifact_zip(args.endpoint, args.output)
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
