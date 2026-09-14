#!/usr/bin/env python3
"""Adapt the exact Python runtime proof to canonical compressed step spacing."""
from __future__ import annotations

import re

import python_runtime_contract_core as core


def runtime_probe_pair(command: str) -> re.Pattern[str]:
    """Require direct setup→probe adjacency while accepting zero or one spacer line."""
    return re.compile(
        r"(?m)^      - name: Set up Python\n"
        r"        uses: actions/setup-python@[0-9a-f]{40}\s+#\s+v[0-9]+\.[0-9]+\.[0-9]+\s*\n"
        r"        with:\n"
        r"          python-version: \$\{\{ env\.PYTHON_VERSION \}\}\n"
        r"(?:\n)?"
        r"      - name: Verify resolved Python runtime\n"
        rf"        run: {re.escape(command)}$"
    )


core.runtime_probe_pair = runtime_probe_pair


def main() -> int:
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
