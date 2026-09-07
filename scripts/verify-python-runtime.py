#!/usr/bin/env python3
"""Fail closed unless the active interpreter matches the exact workflow runtime pin."""
from __future__ import annotations

import os
import re
import sys

EXACT_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    try:
        expected_text = os.environ.get("PYTHON_VERSION", "")
        if not EXACT_VERSION.fullmatch(expected_text):
            fail(f"PYTHON_VERSION must be an exact X.Y.Z pin: {expected_text!r}")
        expected = tuple(int(part) for part in expected_text.split("."))
        observed = tuple(sys.version_info[:3])
        if sys.implementation.name != "cpython":
            fail(
                "Python implementation drifted: "
                f"observed={sys.implementation.name} expected=cpython"
            )
        if observed != expected:
            fail(
                "Python runtime drifted: "
                f"observed={'.'.join(map(str, observed))} expected={expected_text}"
            )
        print(f"Exact Python runtime verified: CPython {expected_text}")
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
