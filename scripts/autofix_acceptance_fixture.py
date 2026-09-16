#!/usr/bin/env python3
"""Inert acceptance fixture for the trusted CodeQL Autofix controller.

The function below is deliberately never called. It contains no repository secret and exists
only long enough for CodeQL to report a deterministic clear-text logging finding on ordinary,
auto-merge-eligible Python source. The trusted controller must remediate this through its
normal protected PR path; this fixture must not be retained after that proof completes.
"""
from __future__ import annotations

import os


def codeql_autofix_acceptance_fixture() -> None:
    """Provide a static CodeQL finding without executing or exposing runtime data."""
    print(f"[INFO] Environment: {os.environ}")
