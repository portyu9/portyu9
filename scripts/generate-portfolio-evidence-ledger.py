#!/usr/bin/env python3
"""Generate a machine-readable portfolio evidence ledger.

The ledger aggregates the reviewed QE portfolio into one deterministic evidence
surface. Each system records its current main revision, explicit evidence contract,
exact GitHub Actions run provenance, UTC freshness, and whether it is a permanent
profile system or a rotating Evidence Spotlight candidate.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import engineering_spotlight_v2 as evidence

OWNER = "portyu9"
VERSION = "portfolio-evidence-ledger-v1"
KIND = "portfolio-evidence-ledger"
OUTPUT = "portfolio-evidence-ledger.json"
SHA40_ZERO = "0" * 40

PERMANENT = (
    {
        "repo": "ai-qa-automation",
        "title": "AI QA CONTROL PLANE",
        "evidence": ({"label": "CI", "workflow": "ci.yml"},),
    },
    {
        "repo": "qa-automation-ai-agent-evals",
        "title": "AGENT EVALUATION + TEVV",
        "evidence": evidence.AGENT_EVIDENCE,
    },
    {
        "repo": "qa-automation-graphql",
        "title": "GRAPHQL QE",
        "evidence": evidence.DEFAULT_EVIDENCE,
    },
    {
        "repo": "qa-automation-visual-and-accessibility-playwright-axe",
        "title": "VISUAL + ACCESSIBILITY QE",
        "evidence": evidence.DEFAULT_EVIDENCE,
    },
)

PERMANENT_REPOS = {str(system["repo"]) for system in PERMANENT}
ROTATING = tuple(system for system in evidence.POOL if str(system["repo"]) not in PERMANENT_REPOS)
SYSTEMS = PERMANENT + tuple(
    {"repo": system["repo"], "title": system["title"], "evidence": system["evidence"]}
    for system in ROTATING
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Generate deterministic synthetic evidence without GitHub API calls")
    return parser.parse_args()


def utc_date(raw: str | None) -> dt.date:
    return dt.date.fromisoformat(raw) if raw else dt.datetime.now(dt.timezone.utc).date()


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def classify(repo: str) -> str:
    return "permanent" if repo in PERMANENT_REPOS else "rotating"


def collect_system(system: dict[str, Any], day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    subject, signals = evidence.collect_evidence(system, day, token, offline)
    contract = [
        {
            "label": spec["label"],
            "workflow": spec["workflow"],
            "scope": evidence.evidence_scope(spec),
        }
        for spec in system["evidence"]
    ]
    ages = [int(signal.get("age_days") or 0) for signal in signals]
    return {
        "repository": f"{OWNER}/{system['repo']}",
        "title": system["title"],
        "classification": classify(str(system["repo"])),
        "subject_revision": subject,
        "evidence_max_age_days": max(ages, default=0),
        "evidence_contract": contract,
        "signals": signals,
    }


def build_ledger(day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    if len(SYSTEMS) != 13 or len({str(system["repo"]) for system in SYSTEMS}) != 13:
        raise ValueError("portfolio ledger must contain exactly 13 distinct reviewed systems")
    if len(PERMANENT) != 4 or len(ROTATING) != 9:
        raise ValueError("portfolio classification must remain four permanent plus nine rotating systems")

    prior_version = evidence.VERSION
    if offline:
        evidence.VERSION = VERSION
    try:
        systems = [collect_system(system, day, token, offline) for system in SYSTEMS]
    finally:
        evidence.VERSION = prior_version

    signal_states: dict[str, int] = {}
    for system in systems:
        for signal in system["signals"]:
            state = str(signal.get("signal") or "UNKNOWN")
            signal_states[state] = signal_states.get(state, 0) + 1

    core: dict[str, Any] = {
        "version": VERSION,
        "kind": KIND,
        "owner": OWNER,
        "as_of_date_utc": day.isoformat(),
        "subject_policy": "current-main-revision-per-system",
        "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
        "classification_policy": "four permanent profile systems plus nine rotating Spotlight systems",
        "system_count": len(systems),
        "signal_summary": dict(sorted(signal_states.items())),
        "systems": systems,
    }
    digest = canonical_digest(core)
    return {
        **core,
        "evidence_id": f"PL1-{digest[:16].upper()}",
        "evidence_digest": f"sha256:{digest}",
    }


def main() -> int:
    try:
        args = parse_args()
        day = utc_date(args.date)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ledger = build_ledger(day, os.environ.get("GITHUB_TOKEN"), args.offline)
        path = args.output_dir / OUTPUT
        path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Portfolio evidence ledger generated: {ledger['evidence_id']} · {ledger['system_count']} systems")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
