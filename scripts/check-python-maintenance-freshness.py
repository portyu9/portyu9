#!/usr/bin/env python3
"""Surface a definitively published successor to the exact pinned CPython patch.

This check is intentionally availability-friendly: a confirmed successor release fails,
while upstream/network uncertainty is emitted as an advisory warning so protected PRs do
not become dependent on python.org availability.
"""
from __future__ import annotations

import json
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
SETUP_PYTHON_MANIFEST = "https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json"
MANIFEST_MAX_BYTES = 8 * 1024 * 1024
TARGET_PLATFORM = "linux"
TARGET_PLATFORM_VERSION = "24.04"
TARGET_ARCH = "x64"


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


def probe_setup_python_availability(
    version: str,
    *,
    opener: Callable[..., object] = urllib.request.urlopen,
    warning: Callable[[str], None] = warn,
) -> bool | None:
    """Return True only when setup-python can install the exact reviewed runtime platform."""
    parse_version(version)
    request = urllib.request.Request(
        SETUP_PYTHON_MANIFEST,
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        response = opener(request, timeout=TIMEOUT_SECONDS)
        with response:  # type: ignore[attr-defined]
            status = int(getattr(response, "status", 0))
            if status != 200:
                warning(
                    f"actions/python-versions returned unexpected HTTP {status}; "
                    "setup-python availability remains advisory"
                )
                return None
            body = response.read(MANIFEST_MAX_BYTES + 1)  # type: ignore[attr-defined]
        if not isinstance(body, (bytes, bytearray)):
            warning("actions/python-versions manifest returned a non-byte body; availability remains advisory")
            return None
        if len(body) > MANIFEST_MAX_BYTES:
            warning("actions/python-versions manifest exceeded the reviewed size bound; availability remains advisory")
            return None
        try:
            manifest = json.loads(bytes(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            warning(f"actions/python-versions manifest was malformed: {exc}; availability remains advisory")
            return None
        if not isinstance(manifest, list) or len(manifest) > 1000:
            warning("actions/python-versions manifest envelope changed; availability remains advisory")
            return None

        observed_versions: list[str] = []
        for entry in manifest:
            if not isinstance(entry, dict):
                warning("actions/python-versions manifest contains a non-object entry; availability remains advisory")
                return None
            entry_version = entry.get("version")
            if not isinstance(entry_version, str) or not entry_version or len(entry_version) > 64:
                warning("actions/python-versions manifest contains an invalid version identity; availability remains advisory")
                return None
            observed_versions.append(entry_version)
        if len(observed_versions) != len(set(observed_versions)):
            warning("actions/python-versions manifest contains duplicate version identities; availability remains advisory")
            return None

        matches = [entry for entry in manifest if entry["version"] == version]
        if not matches:
            return False
        if len(matches) != 1:
            warning(f"actions/python-versions manifest has ambiguous entries for {version}; availability remains advisory")
            return None

        entry = matches[0]
        if entry.get("stable") is not True:
            return False
        release_url_value = entry.get("release_url")
        if (
            not isinstance(release_url_value, str)
            or not release_url_value.startswith("https://github.com/actions/python-versions/releases/tag/")
        ):
            warning(f"actions/python-versions release provenance changed for {version}; availability remains advisory")
            return None
        files = entry.get("files")
        if not isinstance(files, list) or len(files) > 100:
            warning(f"actions/python-versions file inventory changed for {version}; availability remains advisory")
            return None

        platform_matches: list[dict[str, object]] = []
        for item in files:
            if not isinstance(item, dict):
                warning(f"actions/python-versions file inventory is malformed for {version}; availability remains advisory")
                return None
            if (
                item.get("platform") == TARGET_PLATFORM
                and item.get("platform_version") == TARGET_PLATFORM_VERSION
                and item.get("arch") == TARGET_ARCH
            ):
                platform_matches.append(item)
        if not platform_matches:
            return False
        if len(platform_matches) != 1:
            warning(
                f"actions/python-versions has ambiguous {TARGET_PLATFORM}/{TARGET_PLATFORM_VERSION}/{TARGET_ARCH} "
                f"artifacts for {version}; availability remains advisory"
            )
            return None

        artifact = platform_matches[0]
        expected_filename = f"python-{version}-{TARGET_PLATFORM}-{TARGET_PLATFORM_VERSION}-{TARGET_ARCH}.tar.gz"
        filename = artifact.get("filename")
        download_url = artifact.get("download_url")
        if filename != expected_filename:
            warning(f"actions/python-versions artifact filename changed for {version}; availability remains advisory")
            return None
        if (
            not isinstance(download_url, str)
            or not download_url.startswith("https://github.com/actions/python-versions/releases/download/")
            or not download_url.endswith(f"/{expected_filename}")
        ):
            warning(f"actions/python-versions artifact URL changed for {version}; availability remains advisory")
            return None
        return True
    except urllib.error.HTTPError as exc:
        warning(f"actions/python-versions returned HTTP {exc.code}; availability remains advisory")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        warning(f"could not verify setup-python availability: {exc}; availability remains advisory")
        return None


class _FakeResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def read(self, _size: int = -1) -> bytes:
        if _size < 0:
            return self._body
        return self._body[:_size]

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def self_test() -> None:
    require(successor_version("3.13.16") == "3.13.17", "successor calculation drifted")
    require(
        release_url("3.13.17") == "https://www.python.org/downloads/release/python-31317/",
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
        "3.13.17",
        opener=lambda *_args, **_kwargs: _FakeResponse(200),
        warning=quiet,
    )
    require(published is True, "self-test failed to detect a published successor")

    def manifest(entries: list[dict[str, object]]) -> bytes:
        return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")

    exact_artifact = {
        "filename": "python-3.13.17-linux-24.04-x64.tar.gz",
        "arch": "x64",
        "platform": "linux",
        "platform_version": "24.04",
        "download_url": (
            "https://github.com/actions/python-versions/releases/download/"
            "3.13.17-123/python-3.13.17-linux-24.04-x64.tar.gz"
        ),
    }
    available_entry = {
        "version": "3.13.17",
        "stable": True,
        "release_url": "https://github.com/actions/python-versions/releases/tag/3.13.17-123",
        "files": [exact_artifact],
    }
    unrelated_prerelease = {
        "version": "3.15.0-rc.2",
        "stable": False,
        "release_url": "https://github.com/actions/python-versions/releases/tag/3.15.0-rc.2-123",
        "files": [],
    }
    available = probe_setup_python_availability(
        "3.13.17",
        opener=lambda *_args, **_kwargs: _FakeResponse(
            200, manifest([unrelated_prerelease, available_entry])
        ),
        warning=quiet,
    )
    require(available is True, "self-test rejected an exact stable setup-python successor")

    absent = probe_setup_python_availability(
        "3.13.17",
        opener=lambda *_args, **_kwargs: _FakeResponse(
            200,
            manifest(
                [
                    {
                        "version": "3.13.16",
                        "stable": True,
                        "release_url": "https://github.com/actions/python-versions/releases/tag/3.13.16-123",
                        "files": [],
                    }
                ]
            ),
        ),
        warning=quiet,
    )
    require(absent is False, "self-test failed to accept a manifest without the successor")

    unstable_entry = dict(available_entry)
    unstable_entry["stable"] = False
    require(
        probe_setup_python_availability(
            "3.13.17",
            opener=lambda *_args, **_kwargs: _FakeResponse(200, manifest([unstable_entry])),
            warning=quiet,
        )
        is False,
        "self-test accepted an unstable setup-python successor",
    )

    wrong_platform_entry = dict(available_entry)
    wrong_platform_entry["files"] = [
        {
            **exact_artifact,
            "filename": "python-3.13.17-linux-22.04-x64.tar.gz",
            "platform_version": "22.04",
            "download_url": (
                "https://github.com/actions/python-versions/releases/download/"
                "3.13.17-123/python-3.13.17-linux-22.04-x64.tar.gz"
            ),
        }
    ]
    require(
        probe_setup_python_availability(
            "3.13.17",
            opener=lambda *_args, **_kwargs: _FakeResponse(200, manifest([wrong_platform_entry])),
            warning=quiet,
        )
        is False,
        "self-test accepted a successor unavailable on Ubuntu 24.04 x64",
    )

    require(
        probe_setup_python_availability(
            "3.13.17",
            opener=lambda *_args, **_kwargs: _FakeResponse(
                200, manifest([available_entry, available_entry])
            ),
            warning=quiet,
        )
        is None,
        "self-test accepted ambiguous duplicate setup-python version evidence",
    )
    require(
        probe_setup_python_availability(
            "3.13.17",
            opener=lambda *_args, **_kwargs: _FakeResponse(200, b"{"),
            warning=quiet,
        )
        is None,
        "self-test accepted malformed setup-python manifest evidence",
    )

    def missing(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError(release_url("3.13.17"), 404, "not found", None, None)

    require(
        probe_release("3.13.17", opener=missing, warning=quiet) is False,
        "self-test failed to accept absent successor",
    )

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("offline")

    require(
        probe_release("3.13.17", opener=unavailable, warning=quiet) is None,
        "self-test made python.org network uncertainty blocking",
    )
    require(
        probe_setup_python_availability("3.13.17", opener=unavailable, warning=quiet) is None,
        "self-test made setup-python manifest network uncertainty blocking",
    )


def main() -> int:
    try:
        self_test()
        pinned = os.environ.get("PYTHON_VERSION", "")
        parse_version(pinned)
        successor = successor_version(pinned)
        release_state = probe_release(successor)
        if release_state is True:
            setup_state = probe_setup_python_availability(successor)
            if setup_state is True:
                print(
                    f"ERROR: pinned CPython {pinned} is stale: Python {successor} is published and "
                    f"available to setup-python for {TARGET_PLATFORM}/{TARGET_PLATFORM_VERSION}/{TARGET_ARCH}; "
                    "update the canonical exact runtime pin and its contract before merging.",
                    file=sys.stderr,
                )
                return 1
            if setup_state is False:
                print(
                    f"Python maintenance freshness passed: Python {successor} is published but is not yet "
                    f"available to setup-python for {TARGET_PLATFORM}/{TARGET_PLATFORM_VERSION}/{TARGET_ARCH}; "
                    f"CPython {pinned} remains the latest actionable exact runtime."
                )
            else:
                print(
                    f"Python maintenance freshness advisory: Python {successor} is published, but exact "
                    "setup-python availability could not be verified."
                )
            return 0
        if release_state is False:
            print(
                f"Python maintenance freshness passed: CPython {pinned} has no published immediate successor "
                f"({successor})."
            )
        else:
            print(
                f"Python maintenance freshness advisory: CPython {pinned}; successor {successor} publication "
                "could not be verified."
            )
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
