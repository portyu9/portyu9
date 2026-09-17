#!/usr/bin/env python3
"""Diagnostic: emit hash-bound canonical Dependabot controller BOM bytes."""
from __future__ import annotations

import base64
import hashlib
import sys

import workflow_capability_bom as compiler


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()  # noqa: S324


def main() -> int:
    try:
        compiled = compiler.compile_bom()
        controller = [workflow for workflow in compiled["workflows"] if workflow["id"] == "dependabot-controller"]
        require(len(controller) == 1, "compiler lost exact Dependabot controller workflow")
        extension = {
            key: compiled[key]
            for key in ("automationPolicyId", "bomId", "repository", "schemaVersion")
        }
        extension["workflows"] = controller
        payload = compiler.canonical_json(extension).encode("utf-8")
        print(f"CANONICAL_CONTROLLER_BOM_BYTES={len(payload)}")
        print(f"CANONICAL_CONTROLLER_BOM_GIT_BLOB={git_blob_sha(payload)}")
        print("CANONICAL_CONTROLLER_BOM_BASE64=" + base64.b64encode(payload).decode("ascii"))
        raise ValueError("diagnostic canonical controller BOM payload emitted")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
