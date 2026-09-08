#!/usr/bin/env python3
"""Surface a definitively published successor to the exact pinned CPython patch.

This check is intentionally availability-friendly: a confirmed successor release fails,
while upstream/network uncertainty is emitted as an advisory warning so protected PRs do
not become dependent on python.org availability.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
RELEASE_ROOT = "https://www.python.org/downloads/release"
USER_AGENT = "portyu9-python-maintenance-freshness/1"
TIMEOUT_SECONDS = 8


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    require(match is not None, f"PYTHON_VERSION must be exact X.Y.Z; got {value!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def successor_version(value: str) -> str:
    major, minor, patch = parse_version(value)
    return f"{major}.{minor}.{patch + 1}"


def release_url(version: str) -> str:
    parse_version(version)
    return f"{RELEASE_ROOT}/python-{version.replace('.', '')}/"


def warn(message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=Python maintenance freshness::{message}")
    else:
        print(f"WARNING: {message}", file=sys.stderr)


def probe_release(
    version: str,
    *,
    opener: Callable[..., object] = urllib.request.urlopen,
    warning: Callable[[str], None] = warn,
) -> bool | None:
    """Return True if published, False if definitively absent, None if uncertain."""
    url = release_url(version)
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        response = opener(request, timeout=TIMEOUT_SECONDS)
        with response:  # type: ignore[attr-defined]
            status = int(getattr(response, "status", 0))
        if status == 200:
            return True
        warning(f"python.org returned unexpected HTTP {status} for {url}; freshness remains advisory")
        return None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        warning(f"python.org returned HTTP {exc.code} for {url}; freshness remains advisory")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        warning(f"could not verify {url}: {exc}; freshness remains advisory")
        return None


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def self_test() -> None:
    require(successor_version("3.13.15") == "3.13.16", "successor calculation drifted")
    require(
        release_url("3.13.16") == "https://www.python.org/downloads/release/python-31316/",
        "release URL construction drifted",
    )
    try:
        parse_version("3.13")
    except ValueError:
        pass
    else:
        raise ValueError("floating runtime was accepted by freshness checker")

    quiet = lambda _message: None
    published = probe_release(
        "3.13.16",
        opener=lambda *_args, **_kwargs: _FakeResponse(200),
        warning=quiet,
    )
    require(published is True, "self-test failed to detect a published successor")

    def missing(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError(release_url("3.13.16"), 404, "not found", None, None)

    require(
        probe_release("3.13.16", opener=missing, warning=quiet) is False,
        "self-test failed to accept absent successor",
    )

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("offline")

    require(
        probe_release("3.13.16", opener=unavailable, warning=quiet) is None,
        "self-test made network uncertainty blocking",
    )


def main() -> int:
    try:
        self_test()
        pinned = os.environ.get("PYTHON_VERSION", "")
        parse_version(pinned)
        successor = successor_version(pinned)
        state = probe_release(successor)
        if state is True:
            print(
                f"ERROR: pinned CPython {pinned} is stale: Python {successor} has a published release page; "
                "update the canonical exact runtime pin and its contract before merging.",
                file=sys.stderr,
            )
            return 1
        if state is False:
            print(f"Python maintenance freshness passed: CPython {pinned} has no published immediate successor ({successor}).")
        else:
            print(f"Python maintenance freshness advisory: CPython {pinned}; successor {successor} could not be verified.")
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
