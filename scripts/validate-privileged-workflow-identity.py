#!/usr/bin/env python3
"""Lock terminal write/Actions workflow source to exact reviewed Git blob identities.

Granular workflow validators remain responsible for useful structural diagnostics, but
raw shell text cannot prove that reviewed command-looking lines are actually executable.
These two workflows contain the repository's terminal contents/pull-request/Actions
mutation authority, so their complete bytes are part of the reviewed authority contract.
Any future workflow-byte change must deliberately advance this lock in the same review.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = "privileged-workflow-byte-identity-v1"
EXPECTED = {
    ".github/workflows/profile-stats.yml": "a01febb5174db50e977d7f580e02a9db7ebc2437",
    ".github/workflows/spotlight-link-sync.yml": "098d123dbd432ce9d34f095bdf2dc8138f22aa4c",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob_sha_bytes(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def git_blob_sha(path: Path) -> str:
    relative = path.relative_to(ROOT)
    require(path.exists() or path.is_symlink(), f"privileged workflow is missing: {relative}")
    require(path.absolute() == path.resolve(strict=True),
            f"privileged workflow resolves through an alias: {relative}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(),
            f"privileged workflow must be a real regular file: {relative}")
    return git_blob_sha_bytes(path.read_bytes())


def self_test() -> None:
    require(git_blob_sha_bytes(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "Git blob identity self-test failed for empty bytes")
    require(git_blob_sha_bytes(b"test\n") == "9daeafb9864cf43055ae93beb0afd6c7d144bfa4",
            "Git blob identity self-test failed for canonical text bytes")
    require(git_blob_sha_bytes(b"test") != git_blob_sha_bytes(b"test\n"),
            "Git blob identity self-test lost byte-level sensitivity")


def main() -> int:
    try:
        self_test()
        observed: dict[str, str] = {}
        for relative, expected in EXPECTED.items():
            actual = git_blob_sha(ROOT / relative)
            require(actual == expected,
                    f"{relative}: privileged workflow bytes changed; expected Git blob {expected}, got {actual}")
            observed[relative] = actual
        require(set(observed) == set(EXPECTED), "privileged workflow identity inventory changed")
        print(
            f"Privileged workflow byte identity passed: {VERSION} · "
            f"{len(observed)} exact reviewed workflow blobs · terminal mutation source is byte-locked"
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
