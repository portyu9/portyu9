#!/usr/bin/env python3
"""Temporary production acceptance fixture for the trusted CodeQL Autofix controller.

Nothing in this repository imports, calls, or executes this file. The function deliberately
models a Flask request value flowing into `eval` so the repository's pinned CodeQL default suite
has a deterministic `py/code-injection` target on ordinary auto-merge-eligible Python source.
The fixture must be removed by the Autofix acceptance flow.
"""
from flask import request


def codeql_autofix_acceptance_fixture() -> str:
    """Deliberately vulnerable static fixture; never invoked by repository code or workflows."""
    expression = request.args.get("expression", "")
    return str(eval(expression))
