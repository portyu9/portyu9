#!/usr/bin/env python3
"""Validate append-only Automation Decision Receipt coverage against executable policy."""
from __future__ import annotations

import sys

import automation_decision_receipts
import automation_policy


def main() -> int:
    try:
        policy = automation_policy.load_policy()
        contract = automation_decision_receipts.strict_json(automation_decision_receipts.CONTRACT_PATH)
        automation_decision_receipts.validate(policy, contract)
        automation_decision_receipts.self_test(policy, contract)
        total = sum(len(workflow["jobs"]) for workflow in contract["workflows"].values())
        generic = sum(
            1
            for workflow in contract["workflows"].values()
            for job in workflow["jobs"].values()
            if job["mode"] == "generic-decision-receipt"
        )
        print(
            "Automation Decision Receipt contract passed: "
            f"{automation_decision_receipts.CONTRACT_ID} · {total} exact lease-bound privileged jobs · "
            f"{generic} generic receipt effect classes · complete self-attested/specialized receipt disposition"
        )
        return 0
    except (OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
