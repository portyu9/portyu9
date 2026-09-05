#!/usr/bin/env python3
"""Compatibility entrypoint for registry-backed Portfolio Evidence Ledger v2."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys

from portfolio_evidence_ledger import *  # re-export retry/evidence contract for validators


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Generate deterministic synthetic evidence without GitHub API calls")
    return parser.parse_args()


def utc_date(raw: str | None) -> dt.date:
    return dt.date.fromisoformat(raw) if raw else dt.datetime.now(dt.timezone.utc).date()


def main() -> int:
    try:
        args = parse_args()
        day = utc_date(args.date)
        ledger = generate(args.output_dir, day, os.environ.get("GITHUB_TOKEN"), args.offline)
        print(
            f"Portfolio evidence ledger v2 generated: {ledger['evidence_id']} · {ledger['system_count']} systems · "
            f"registry {ledger['portfolio_registry']['version']} · result/binding/freshness separated"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
