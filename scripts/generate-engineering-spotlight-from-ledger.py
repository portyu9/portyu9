#!/usr/bin/env python3
"""Render Engineering Evidence Spotlight v2.1 from one Portfolio Evidence Ledger.

The Portfolio Evidence Ledger is the single live evidence collection surface. This
renderer performs no GitHub API calls: it deterministically selects the three rotating
systems for the ledger's UTC date and projects the exact ledger subject revision,
evidence contract, and signals into the reviewed Spotlight SVG/manifest presentation.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

import engineering_spotlight_v2 as base
import engineering_spotlight_v21 as v21

LEDGER_VERSION = "portfolio-evidence-ledger-v1"
LEDGER_KIND = "portfolio-evidence-ledger"
EVIDENCE_SOURCE = LEDGER_VERSION
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LEDGER_ID = re.compile(r"^PL1-[0-9A-F]{16}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--ledger", type=Path, required=True, help="Validated Portfolio Evidence Ledger JSON")
    parser.add_argument("--date", help="Optional UTC date; must equal the ledger as_of_date_utc")
    return parser.parse_args()


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def expected_contract(system: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "label": str(spec["label"]),
            "workflow": str(spec["workflow"]),
            "scope": base.evidence_scope(spec),
        }
        for spec in system["evidence"]
    ]


def load_ledger(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"Portfolio Evidence Ledger is missing: {path}")
    ledger = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(ledger, dict), "Portfolio Evidence Ledger must be a JSON object")
    require(ledger.get("version") == LEDGER_VERSION, "Portfolio Evidence Ledger version changed")
    require(ledger.get("kind") == LEDGER_KIND, "Portfolio Evidence Ledger kind changed")
    require(ledger.get("owner") == base.OWNER, "Portfolio Evidence Ledger owner changed")
    require(ledger.get("system_count") == 13, "Portfolio Evidence Ledger must contain 13 systems")
    evidence_id = ledger.get("evidence_id")
    evidence_digest = ledger.get("evidence_digest")
    require(isinstance(evidence_id, str) and LEDGER_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
    require(isinstance(evidence_digest, str) and DIGEST.fullmatch(evidence_digest) is not None, "Portfolio evidence digest is malformed")
    core = {key: value for key, value in ledger.items() if key not in {"evidence_id", "evidence_digest"}}
    digest = canonical_digest(core)
    require(evidence_digest == f"sha256:{digest}", "Portfolio evidence digest does not match canonical ledger semantics")
    require(evidence_id == f"PL1-{digest[:16].upper()}", "Portfolio Evidence ID does not match canonical ledger digest")
    systems = ledger.get("systems")
    require(isinstance(systems, list) and len(systems) == 13, "Portfolio Evidence Ledger systems array changed")
    return ledger


def ledger_systems(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in ledger["systems"]:
        require(isinstance(entry, dict), "Portfolio ledger system entry must be an object")
        repository = entry.get("repository")
        require(isinstance(repository, str) and repository.startswith(f"{base.OWNER}/"), "Portfolio ledger repository is invalid")
        require(repository not in result, f"Duplicate Portfolio ledger repository: {repository}")
        result[repository] = entry
    require(len(result) == 13, "Portfolio ledger repository inventory must contain 13 distinct systems")
    return result


def project_entry(system: dict[str, Any], entry: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, str]]]:
    repository = f"{base.OWNER}/{system['repo']}"
    require(entry.get("repository") == repository, f"{repository}: ledger repository mismatch")
    require(entry.get("classification") == "rotating", f"{repository}: Spotlight source must be classified rotating")
    require(entry.get("title") == system["title"], f"{repository}: ledger/display title mismatch")
    subject = entry.get("subject_revision")
    require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None, f"{repository}: subject revision is malformed")
    contract = entry.get("evidence_contract")
    signals = entry.get("signals")
    expected = expected_contract(system)
    require(contract == expected, f"{repository}: ledger evidence contract differs from reviewed Spotlight contract")
    require(isinstance(signals, list) and len(signals) == len(expected), f"{repository}: ledger signal count changed")
    signal_keys = [(item.get("label"), item.get("workflow"), item.get("scope")) for item in signals if isinstance(item, dict)]
    contract_keys = [(item["label"], item["workflow"], item["scope"]) for item in expected]
    require(signal_keys == contract_keys, f"{repository}: ledger signals do not match the reviewed contract")
    return subject, [dict(item) for item in signals], expected


def render(output_dir: Path, ledger_path: Path, requested_date: str | None) -> dict[str, Any]:
    ledger = load_ledger(ledger_path)
    raw_date = ledger.get("as_of_date_utc")
    require(isinstance(raw_date, str), "Portfolio ledger UTC date is missing")
    day = dt.date.fromisoformat(raw_date)
    if requested_date is not None:
        require(requested_date == raw_date, "Spotlight date must equal Portfolio ledger as_of_date_utc")

    by_repo = ledger_systems(ledger)
    selected = v21.select_systems(day)
    require(len(selected) == v21.SLOT_COUNT, "Spotlight selection count changed")
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "version": v21.VERSION,
        "selection_date_utc": raw_date,
        "selection_policy": "deterministic-daily-sha256-sample",
        "evidence_model": base.EVIDENCE_MODEL,
        "evidence_source": EVIDENCE_SOURCE,
        "portfolio_evidence_id": ledger["evidence_id"],
        "portfolio_evidence_digest": ledger["evidence_digest"],
        "portfolio_as_of_date_utc": raw_date,
        "freshness_basis": ledger.get("freshness_basis"),
        "live_policy": "signals are projected from the validated Portfolio Evidence Ledger for the same subject revisions",
        "slots": [],
    }

    prior_version = base.VERSION
    base.VERSION = v21.VERSION
    try:
        for slot, system in enumerate(selected, start=1):
            repository = f"{base.OWNER}/{system['repo']}"
            require(repository in by_repo, f"Selected Spotlight repository is absent from Portfolio ledger: {repository}")
            subject, signals, contract = project_entry(system, by_repo[repository])
            for theme in ("light", "dark"):
                (output_dir / f"spotlight-{slot}-{theme}.svg").write_text(
                    base.render_card(system, slot, day, subject, signals, theme),
                    encoding="utf-8",
                )
            manifest["slots"].append(
                {
                    "slot": slot,
                    "repository": repository,
                    "title": system["title"],
                    "glyph": system["glyph"],
                    "topology": system["topology"],
                    "subject_revision": subject,
                    "evidence_contract": contract,
                    "signals": signals,
                }
            )
    finally:
        base.VERSION = prior_version

    (output_dir / "spotlight-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    try:
        args = parse_args()
        base.validate_pool()
        render(args.output_dir, args.ledger, args.date)
        print(f"Engineering Spotlight rendered from Portfolio Evidence Ledger: {args.ledger}")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
