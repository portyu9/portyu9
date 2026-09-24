#!/usr/bin/env python3
"""Execute the canonical read-only validation boundary for candidate profile evidence."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

import profile_evidence_validation as contract


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal-field-dir", type=Path, required=True)
    parser.add_argument("--spotlight-dir", type=Path, required=True)
    parser.add_argument("--portfolio-ledger-dir", type=Path, required=True)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Validate deterministic local/synthetic Portfolio evidence without asserting live external subjects",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = contract.load_manifest()
        commands = contract.candidate_commands(
            signal_field_dir=args.signal_field_dir,
            spotlight_dir=args.spotlight_dir,
            portfolio_ledger_dir=args.portfolio_ledger_dir,
        )
        removed_live_flags = 0
        for index, (script, command_args) in enumerate(commands, start=1):
            stage = payload["stages"][index - 1]
            effective_args = command_args
            if args.offline:
                removed = command_args.count("--require-live")
                if removed:
                    if stage["id"] not in {"portfolio-ledger-live", "engineering-spotlight-live"}:
                        raise ValueError(
                            f"offline validation attempted to relax an unreviewed stage: {stage['id']}"
                        )
                    if removed != 1:
                        raise ValueError(
                            f"offline validation expected exactly one live flag for {stage['id']}"
                        )
                    effective_args = tuple(
                        value for value in command_args if value != "--require-live"
                    )
                    removed_live_flags += removed
            print(f"[profile-evidence-boundary {index:02d}/{len(commands):02d}] {stage['id']}: {script.name}", flush=True)
            subprocess.run([sys.executable, str(script), *effective_args], check=True)
        if args.offline and removed_live_flags != 2:
            raise ValueError(
                "offline validation must relax exactly the reviewed Portfolio and Spotlight live assertions"
            )
        if not args.offline and removed_live_flags != 0:
            raise ValueError("live validation unexpectedly altered canonical validator arguments")
        mode = "deterministic local/offline subject closure" if args.offline else "exact live subject closure"
        print(
            f"Profile evidence candidate boundary passed: {payload['version']} · "
            f"{len(commands)} ordered read-only stages · {mode}"
        )
        return 0
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: profile evidence validation boundary failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
