#!/usr/bin/env python3
"""Temporary production acceptance fixture for the trusted CodeQL Autofix controller.

This file intentionally mirrors GitHub CodeQL's documented bad example for
`py/clear-text-logging-sensitive-data`. Nothing in this repository imports, calls, or executes
this file. It contains no repository secret and must be removed by the Autofix acceptance flow.
"""
import os

# BAD by design for issue #414 acceptance: exact upstream CodeQL example pattern.
print(f"[INFO] Environment: {os.environ}")
