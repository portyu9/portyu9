#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip

import workflow_capability_bom as compiler

compiled = compiler.compile_bom()
matches = [workflow for workflow in compiled["workflows"] if workflow.get("id") == "codeql-autofix"]
if len(matches) != 1:
    raise SystemExit("expected exactly one codeql-autofix workflow")
payload = {key: compiled[key] for key in compiled if key != "workflows"}
payload["workflows"] = matches
raw = compiler.canonical_json(payload).encode("utf-8")
encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")
print(f"CODEQL_AUTOFIX_BOM_GZIP_BASE64={encoded}")
raise SystemExit(1)
