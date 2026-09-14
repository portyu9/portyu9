#!/usr/bin/env python3
"""Extend the frozen workflow shell-safety scanner with item-11 ADR signers."""
from __future__ import annotations

import workflow_shell_safety_item10_core as core


ITEM11_PRIVILEGED_JOBS = {
    "profile-stats.yml": ("publish", "dispatch", "decision_receipt_attest"),
    "spotlight-link-sync.yml": (
        "reconcile", "propose", "approve", "authorize_attest", "merge", "decision_receipt_attest"
    ),
}


def main() -> int:
    original = core.PRIVILEGED_JOBS
    core.PRIVILEGED_JOBS = ITEM11_PRIVILEGED_JOBS
    try:
        return core.main()
    finally:
        core.PRIVILEGED_JOBS = original


if __name__ == "__main__":
    raise SystemExit(main())
