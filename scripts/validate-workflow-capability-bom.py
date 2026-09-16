#!/usr/bin/env python3
"""Temporary read-only diagnostic: emit the trusted compiler product compactly."""
from __future__ import annotations

import base64
import gzip

import workflow_capability_bom as compiler


def main() -> int:
    payload = compiler.canonical_json(compiler.compile_bom()).encode("utf-8")
    encoded = base64.b64encode(gzip.compress(payload, mtime=0)).decode("ascii")
    print(f"CAPABILITY_BOM_GZIP_BASE64={encoded}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
