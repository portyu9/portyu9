#!/usr/bin/env python3
"""Authenticated, bounded GitHub Actions artifact ZIP download for governed automation."""
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

ARTIFACT_PATH = re.compile(
    r"^repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/artifacts/[1-9][0-9]*/zip$"
)
ALLOWED_STORAGE_HOST_SUFFIXES = (
    "actions.githubusercontent.com",
    "blob.core.windows.net",
    "githubusercontent.com",
)
REDIRECT_STATUS = 302
MAX_RESPONSE_BYTES = 8_000_000
ZIP_SIGNATURES = (b"PK\\x03\\x04", b"PK\\x05\\x06", b"PK\\x07\\x08")
USER_AGENT = "portyu9-governed-github-artifact-download-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_artifact_endpoint(value: str) -> str:
    normalized = automation_github_read.normalize_endpoint(value)
    parsed = urllib.parse.urlsplit(normalized)
    require(parsed.query == "", "artifact ZIP endpoint must not contain a query")
    require(
        ARTIFACT_PATH.fullmatch(parsed.path) is not None,
        "artifact ZIP endpoint must be repos/{owner}/{repo}/actions/artifacts/{positive-id}/zip",
    )
    return normalized


def validate_signed_storage_url(value: str) -> str:
    require(
        isinstance(value, str) and value == value.strip() and bool(value),
        "artifact ZIP redirect Location must be one nonempty trimmed string",
    )
    require(
        "\\" not in value and not any(ord(character) < 0x20 for character in value),
        "artifact ZIP redirect Location contains forbidden characters",
    )
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", "artifact ZIP redirect must use HTTPS")
    require(
        parsed.username is None and parsed.password is None,
        "artifact ZIP redirect must not contain URL credentials",
    )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("artifact ZIP redirect contains an invalid port") from exc
    require(port in (None, 443), "artifact ZIP redirect must use the default HTTPS port")
    hostname = (parsed.hostname or "").lower()
    require(bool(hostname), "artifact ZIP redirect is missing a hostname")
    require(
        any(
            hostname == suffix or hostname.endswith("." + suffix)
            for suffix in ALLOWED_STORAGE_HOST_SUFFIXES
        ),
        "artifact ZIP redirect hostname is outside reviewed GitHub Actions storage",
    )
    require(bool(parsed.path), "artifact ZIP redirect is missing a path")
    require(not parsed.fragment, "artifact ZIP redirect must not contain a fragment")
    return value


def api_request(endpoint: str, token: str) -> urllib.request.Request:
    url = urllib.parse.urljoin(automation_github_read.API_ROOT, endpoint)
    return urllib.request.Request(
        url,
        method="GET",
        headers=automation_github_read.token_headers(token),
    )


def storage_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": USER_AGENT,
        },
    )


def open_without_redirect(
    request: urllib.request.Request,
    *,
    opener: Callable[..., Any] | None,
) -> Any:
    if opener is not None:
        return opener(request, timeout=automation_github_read.TIMEOUT_SECONDS)
    return urllib.request.build_opener(automation_github_read.NoRedirect()).open(
        request,
        timeout=automation_github_read.TIMEOUT_SECONDS,
    )


def signed_storage_url(
    endpoint: str,
    token: str,
    *,
    opener: Callable[..., Any] | None = None,
) -> str:
    request = api_request(endpoint, token)
    expected_url = request.full_url
    try:
        response = open_without_redirect(request, opener=opener)
    except urllib.error.HTTPError as exc:
        if exc.code != REDIRECT_STATUS:
            raise
        location = (exc.headers or {}).get("Location")
        require(location is not None, "artifact ZIP redirect is missing Location")
        return validate_signed_storage_url(str(location))

    with response:
        require(
            response.status == REDIRECT_STATUS,
            f"artifact ZIP API GET returned unexpected HTTP {response.status}",
        )
        require(
            response.geturl() == expected_url,
            "artifact ZIP API request changed URL before reviewed redirect",
        )
        location = response.headers.get("Location")
        require(location is not None, "artifact ZIP redirect is missing Location")
        return validate_signed_storage_url(str(location))


def storage_zip_bytes(
    signed_url: str,
    *,
    opener: Callable[..., Any] | None = None,
) -> bytes:
    validated = validate_signed_storage_url(signed_url)
    request = storage_request(validated)
    require(
        request.get_header("Authorization") is None,
        "artifact ZIP storage request must never carry Authorization",
    )
    response = open_without_redirect(request, opener=opener)
    with response:
        require(
            response.status == 200,
            f"artifact ZIP storage GET returned unexpected HTTP {response.status}",
        )
        require(
            response.geturl() == validated,
            "artifact ZIP storage GET was redirected",
        )
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    require(
        len(raw) <= MAX_RESPONSE_BYTES,
        "artifact ZIP response exceeds size bound",
    )
    require(
        len(raw) >= 4 and raw[:4] in ZIP_SIGNATURES,
        "artifact ZIP response does not have a reviewed ZIP signature",
    )
    return raw


def get_artifact_zip(
    endpoint: str,
    *,
    token: str | None = None,
    api_opener: Callable[..., Any] | None = None,
    storage_opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> bytes:
    normalized = normalize_artifact_endpoint(endpoint)
    credential = os.environ.get("GH_TOKEN") if token is None else token
    require(
        credential is not None,
        "GH_TOKEN is required for governed GitHub artifact downloads",
    )
    # Reuse the canonical token validation without ever forwarding the token to storage.
    automation_github_read.token_headers(credential)

    for attempt in range(automation_github_read.ATTEMPTS):
        try:
            signed_url = signed_storage_url(
                normalized,
                credential,
                opener=api_opener,
            )
            return storage_zip_bytes(signed_url, opener=storage_opener)
        except urllib.error.HTTPError as exc:
            if (
                attempt + 1 >= automation_github_read.ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(
                    f"artifact ZIP GET returned terminal HTTP {exc.code}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed artifact ZIP whole transaction after transient "
                f"HTTP {exc.code}; attempt {attempt + 1}/"
                f"{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= automation_github_read.ATTEMPTS:
                raise ValueError(
                    "artifact ZIP GET exhausted transient transport retry budget: "
                    f"{exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: governed artifact ZIP whole transaction after transient "
                f"transport failure; attempt {attempt + 1}/"
                f"{automation_github_read.ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable governed artifact ZIP retry state")


def write_atomic(path: str, payload: bytes) -> None:
    require(
        isinstance(path, str) and path == path.strip() and bool(path),
        "artifact ZIP output path must be one nonempty trimmed string",
    )
    output = Path(path)
    require(output.name not in ("", ".", ".."), "artifact ZIP output path is invalid")
    parent = output.parent if str(output.parent) else Path(".")
    require(parent.is_dir(), "artifact ZIP output parent directory does not exist")

    temporary_name: str | None = None
    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=str(parent),
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


class _FixtureHeaders(dict[str, str]):
    pass


class _FixtureResponse:
    def __init__(
        self,
        url: str,
        *,
        status: int,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
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
        and automation_github_read.TIMEOUT_SECONDS == 20,
        "artifact ZIP retry attempt/timeout budget changed",
    )
    require(
        automation_github_read.BACKOFF_SECONDS == (1.0, 2.0)
        and automation_github_read.MAX_RETRY_AFTER_SECONDS == 5.0,
        "artifact ZIP deterministic retry timing changed",
    )
    require(MAX_RESPONSE_BYTES == 8_000_000, "artifact ZIP response-size bound changed")
    require(REDIRECT_STATUS == 302, "artifact ZIP reviewed redirect status changed")

    endpoint = "repos/portyu9/portyu9/actions/artifacts/123/zip"
    require(
        normalize_artifact_endpoint(endpoint) == endpoint,
        "artifact ZIP endpoint normalization changed",
    )
    for forbidden in (
        "repos/portyu9/portyu9/actions/artifacts/0/zip",
        "repos/portyu9/portyu9/actions/artifacts/123/zip?x=1",
        "repos/portyu9/portyu9/actions/runs/123",
        "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/123/zip",
    ):
        try:
            normalize_artifact_endpoint(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"artifact ZIP helper accepted forbidden endpoint: {forbidden}")

    signed = (
        "https://productionresults0.blob.core.windows.net/actions-results/"
        "fixture/receipt.zip?sig=fixture"
    )
    require(validate_signed_storage_url(signed) == signed, "signed storage URL changed")
    for forbidden in (
        "http://productionresults0.blob.core.windows.net/actions-results/a.zip",
        "https://user:pass@productionresults0.blob.core.windows.net/actions-results/a.zip",
        "https://example.com/actions-results/a.zip",
        "https://productionresults0.blob.core.windows.net:444/actions-results/a.zip",
        "https://productionresults0.blob.core.windows.net/actions-results/a.zip#fragment",
    ):
        try:
            validate_signed_storage_url(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"artifact ZIP helper accepted forbidden redirect: {forbidden}")

    api_url = automation_github_read.API_ROOT + endpoint
    api_calls: list[str] = []
    storage_calls: list[str] = []
    sleeps: list[float] = []
    api_sequence: list[Any] = [
        urllib.error.HTTPError(api_url, 503, "fixture", {}, None),
        urllib.error.HTTPError(api_url, 302, "fixture", {"Location": signed}, None),
        urllib.error.HTTPError(api_url, 302, "fixture", {"Location": signed}, None),
    ]
    storage_sequence: list[Any] = [
        urllib.error.HTTPError(signed, 503, "fixture", {}, None),
        _FixtureResponse(signed, status=200, body=b"PK\\x03\\x04fixture"),
    ]

    def api_fixture(request: urllib.request.Request, *, timeout: int) -> Any:
        require(timeout == 20, "artifact ZIP API fixture timeout changed")
        require(
            request.get_header("Authorization") == "Bearer fixture-token",
            "artifact ZIP API request lost bearer token",
        )
        api_calls.append(request.full_url)
        result = api_sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def storage_fixture(request: urllib.request.Request, *, timeout: int) -> Any:
        require(timeout == 20, "artifact ZIP storage fixture timeout changed")
        require(
            request.get_header("Authorization") is None,
            "artifact ZIP helper leaked Authorization to signed storage",
        )
        storage_calls.append(request.full_url)
        result = storage_sequence.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    payload = get_artifact_zip(
        endpoint,
        token="fixture-token",
        api_opener=api_fixture,
        storage_opener=storage_fixture,
        sleeper=sleeps.append,
    )
    require(payload == b"PK\\x03\\x04fixture", "artifact ZIP retry fixture payload changed")
    require(
        api_calls == [api_url, api_url, api_url],
        "each artifact ZIP retry must restart at the exact authenticated API endpoint",
    )
    require(
        storage_calls == [signed, signed],
        "artifact ZIP storage retry sequence changed",
    )
    require(
        sleeps == [1.0, 2.0],
        "artifact ZIP deterministic retry backoff changed",
    )

    terminal_calls: list[str] = []

    def terminal_api(request: urllib.request.Request, *, timeout: int) -> Any:
        terminal_calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 403, "fixture", {}, None)

    try:
        get_artifact_zip(
            endpoint,
            token="fixture-token",
            api_opener=terminal_api,
            storage_opener=storage_fixture,
            sleeper=lambda _: None,
        )
    except ValueError as exc:
        require("HTTP 403" in str(exc), "artifact ZIP terminal 403 failed for wrong reason")
    else:
        raise ValueError("artifact ZIP helper retried or accepted ordinary HTTP 403")
    require(
        terminal_calls == [api_url],
        "artifact ZIP ordinary HTTP 403 must terminate without retry",
    )

    with tempfile.TemporaryDirectory(prefix="artifact-zip-self-test-") as directory:
        output = Path(directory) / "receipt.zip"
        write_atomic(str(output), b"PK\\x03\\x04fixture")
        require(
            output.read_bytes() == b"PK\\x03\\x04fixture",
            "artifact ZIP atomic output changed bytes",
        )


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
            require(
                args.endpoint is None and args.output is None,
                "--self-test does not accept endpoint/output",
            )
            self_test()
            print(
                "Governed artifact ZIP self-test passed: exact repository artifact endpoint; "
                "authenticated no-redirect API GET; reviewed HTTPS storage redirect; no token "
                "forwarding; whole-transaction transient retry; bounded ZIP bytes; atomic output."
            )
            return 0
        require(args.endpoint is not None, "artifact ZIP endpoint is required")
        require(args.output is not None, "artifact ZIP output path is required")
        payload = get_artifact_zip(args.endpoint)
        write_atomic(args.output, payload)
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
