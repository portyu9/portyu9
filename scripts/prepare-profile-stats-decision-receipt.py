#!/usr/bin/env python3
"""Prepare read-only Profile Stats Automation Decision Receipt state."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

import profile_stats_decision_receipt as core


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            core.self_test()
            print("Profile Stats Automation Decision Receipt preparer self-test passed")
            return 0
        core.require(args.output is not None, "output path is required outside --self-test")
        state = core.build_state(dict(os.environ))
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Profile Stats Automation Decision Receipt state prepared: {args.output}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
