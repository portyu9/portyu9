#!/usr/bin/env python3
"""Temporary read-only diagnostic: emit canonical trusted workflow BOM extensions."""
from __future__ import annotations

import base64
import gzip
import sys

import workflow_capability_bom as compiler


def main() -> int:
    compiled = compiler.compile_bom()
    for workflow_id in ("capability-admission", "codeql-autofix"):
        matches = [workflow for workflow in compiled["workflows"] if workflow.get("id") == workflow_id]
        if len(matches) != 1:
            raise ValueError(f"expected one workflow: {workflow_id}")
        part = {key: compiled[key] for key in compiled if key != "workflows"}
        part["workflows"] = matches
        raw = compiler.canonical_json(part).encode("utf-8")
        packed = gzip.compress(raw, mtime=0)
        print(f"BOM_DIAG {workflow_id} {len(raw)} {base64.b64encode(packed).decode('ascii')}")
    print("ERROR: intentional diagnostic failure", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
