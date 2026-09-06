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
        for index, (script, command_args) in enumerate(commands, start=1):
            stage = payload["stages"][index - 1]
            print(f"[profile-evidence-boundary {index:02d}/{len(commands):02d}] {stage['id']}: {script.name}", flush=True)
            subprocess.run([sys.executable, str(script), *command_args], check=True)
        print(
            f"Profile evidence candidate boundary passed: {payload['version']} · "
            f"{len(commands)} ordered read-only stages · exact live subject closure"
        )
        return 0
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: profile evidence validation boundary failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
