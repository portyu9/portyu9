#!/usr/bin/env python3
"""Diagnostic: emit canonical hardened workflow BOM extensions with Git blob identities."""
from __future__ import annotations

import base64
import hashlib
import sys

import workflow_capability_bom as compiler


def git_blob_sha(raw: bytes) -> str:
    framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    return hashlib.sha1(framed).hexdigest()


def main() -> int:
    compiled = compiler.compile_bom()
    metadata = {key: value for key, value in compiled.items() if key != "workflows"}
    wanted = {
        "CAPABILITY_ADMISSION": "capability-admission",
        "DEPENDABOT_CONTROLLER": "dependabot-controller",
    }
    by_id = {workflow["id"]: workflow for workflow in compiled["workflows"]}
    for label, identity in wanted.items():
        extension = dict(metadata)
        extension["workflows"] = [by_id[identity]]
        raw = compiler.canonical_json(extension).encode("utf-8")
        print(f"{label}_LENGTH={len(raw)}")
        print(f"{label}_GIT_BLOB_SHA={git_blob_sha(raw)}")
        print(f"{label}_BASE64={base64.b64encode(raw).decode('ascii')}")
    print("ERROR: diagnostic intentionally stops after emitting canonical extension bytes", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
