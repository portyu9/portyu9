#!/usr/bin/env python3
"""Lock mutation-authority and required-assurance workflows to exact reviewed Git blobs.

Granular workflow validators remain responsible for useful structural diagnostics, but
raw source scans cannot prove that reviewed command-looking lines are the exact bytes
GitHub Actions will execute. Profile stats and Spotlight sync contain terminal mutation
authority, while Profile Quality defines the required repository-authored validation
path. Their complete workflow bytes are therefore part of the reviewed authority and
assurance contract. Any future workflow-byte change must deliberately advance this lock
in the same review.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v4"
EXPECTED = {
    ".github/workflows/profile-quality.yml": "a7824194821155e22503093c43cad5cf023c6dc3",
    ".github/workflows/profile-stats.yml": "c8b9ad62b93477c69f13d637a4daea6023fe2b4c",
    ".github/workflows/spotlight-link-sync.yml": "79ebe8a87f8a118bb10aef53042a4db1d0b3ec4b",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob_sha_bytes(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def git_blob_sha(path: Path) -> str:
    relative = path.relative_to(ROOT)
    require(path.exists() or path.is_symlink(), f"governed workflow is missing: {relative}")
    require(path.absolute() == path.resolve(strict=True),
            f"governed workflow resolves through an alias: {relative}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(),
            f"governed workflow must be a real regular file: {relative}")
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
                    f"{relative}: governed workflow bytes changed; expected Git blob {expected}, got {actual}")
            observed[relative] = actual
        require(set(observed) == set(EXPECTED), "governed workflow identity inventory changed")
        print(
            f"Governed workflow byte identity passed: {VERSION} · "
            f"{len(observed)} exact reviewed workflow blobs · mutation/required-check source is byte-locked"
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
