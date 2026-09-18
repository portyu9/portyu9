#!/usr/bin/env python3
"""Diagnostic: emit canonical event-driven Dependabot controller BOM extension."""
from __future__ import annotations

import base64
import hashlib
import sys

import workflow_capability_bom as compiler


def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def main() -> int:
    compiled = compiler.compile_bom()
    workflow = next((item for item in compiled["workflows"] if item["id"] == "dependabot-controller"), None)
    if workflow is None:
        raise ValueError("compiled BOM lost dependabot-controller")
    extension = {key: value for key, value in compiled.items() if key != "workflows"}
    extension["workflows"] = [workflow]
    raw = compiler.canonical_json(extension).encode("utf-8")
    print("DEPENDABOT_LIVENESS_LENGTH=" + str(len(raw)))
    print("DEPENDABOT_LIVENESS_GIT_BLOB_SHA=" + git_blob_sha(raw))
    print("DEPENDABOT_LIVENESS_BASE64=" + base64.b64encode(raw).decode("ascii"))
    print("ERROR: diagnostic intentionally stops after canonical liveness extension emission", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
