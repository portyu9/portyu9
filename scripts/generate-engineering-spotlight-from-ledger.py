#!/usr/bin/env python3
"""Render Engineering Evidence Spotlight v2.1 from Portfolio Evidence Ledger v2.

The Portfolio Evidence Ledger remains the single live evidence collection surface.
This renderer performs no GitHub API calls. It deterministically selects the three
rotating systems for the ledger UTC date and projects the exact ledger subject,
contract, execution result, subject binding, freshness, and run provenance.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import re
import sys
from typing import Any

import engineering_spotlight_v2 as base
import engineering_spotlight_v21 as v21

LEDGER_VERSION = "portfolio-evidence-ledger-v2"
LEDGER_KIND = "portfolio-evidence-ledger"
EVIDENCE_SOURCE = LEDGER_VERSION
EVIDENCE_MODEL = "per-system-evidence-contract-v3"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LEDGER_ID = re.compile(r"^PL2-[0-9A-F]{16}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--ledger", type=Path, required=True, help="Validated Portfolio Evidence Ledger v2 JSON")
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
    require(ledger.get("evidence_semantics") == EVIDENCE_SEMANTICS, "Portfolio evidence semantics changed")
    require("signal_summary" not in ledger, "Ledger v2 must not contain the legacy conflated signal summary")
    evidence_id = ledger.get("evidence_id")
    evidence_digest = ledger.get("evidence_digest")
    require(isinstance(evidence_id, str) and LEDGER_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
    require(isinstance(evidence_digest, str) and DIGEST.fullmatch(evidence_digest) is not None, "Portfolio evidence digest is malformed")
    core = {key: value for key, value in ledger.items() if key not in {"evidence_id", "evidence_digest"}}
    digest = canonical_digest(core)
    require(evidence_digest == f"sha256:{digest}", "Portfolio evidence digest does not match canonical ledger semantics")
    require(evidence_id == f"PL2-{digest[:16].upper()}", "Portfolio Evidence ID does not match canonical ledger digest")
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
    records = entry.get("signals")
    expected = expected_contract(system)
    require(contract == expected, f"{repository}: ledger evidence contract differs from reviewed Spotlight contract")
    require(isinstance(records, list) and len(records) == len(expected), f"{repository}: ledger evidence-record count changed")
    record_keys = [(item.get("label"), item.get("workflow"), item.get("scope")) for item in records if isinstance(item, dict)]
    contract_keys = [(item["label"], item["workflow"], item["scope"]) for item in expected]
    require(record_keys == contract_keys, f"{repository}: ledger evidence records do not match the reviewed contract")
    for record in records:
        require(isinstance(record, dict), f"{repository}: evidence record must be an object")
        require("signal" not in record, f"{repository}: legacy conflated signal field reached Ledger v2 projection")
        for field in ("result", "binding", "freshness"):
            require(isinstance(record.get(field), str) and record.get(field), f"{repository}: evidence {field} is missing")
    return str(subject), [dict(item) for item in records], expected


def dimension_attr(records: list[dict[str, Any]], field: str) -> str:
    return ";".join(f"{record['label']}:{record[field]}" for record in records)


def render_projection(
    system: dict[str, Any], slot: int, day: dt.date, subject: str, records: list[dict[str, Any]], theme: str
) -> str:
    # The v2 visual renderer still colors the primary pill by execution result. Feed it
    # a presentation-only compatibility field; the Ledger and manifest remain signal-free.
    present = [{**record, "signal": record["result"]} for record in records]
    svg = base.render_card(system, slot, day, subject, present, theme)
    result_attr = html.escape(dimension_attr(records, "result"), quote=True)
    binding_attr = html.escape(dimension_attr(records, "binding"), quote=True)
    freshness_attr = html.escape(dimension_attr(records, "freshness"), quote=True)
    insertion = (
        f' data-evidence-semantics="{EVIDENCE_SEMANTICS}"'
        f' data-evidence-results="{result_attr}"'
        f' data-evidence-bindings="{binding_attr}"'
        f' data-evidence-freshness="{freshness_attr}"'
    )
    svg = svg.replace(' data-glyph="', insertion + ' data-glyph="', 1)
    details = "; ".join(
        f"{record['label']} result {record['result']}, binding {record['binding']}, freshness {record['freshness']} ({record['age_days']}d)"
        for record in records
    )
    svg = svg.replace(
        "Freshness is UTC whole-day age from the named workflow evidence timestamp.</desc>",
        f"Evidence dimensions: {html.escape(details)}. Freshness is UTC whole-day age from the named workflow evidence timestamp.</desc>",
        1,
    )
    return svg


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
        "evidence_model": EVIDENCE_MODEL,
        "evidence_source": EVIDENCE_SOURCE,
        "evidence_semantics": EVIDENCE_SEMANTICS,
        "portfolio_evidence_id": ledger["evidence_id"],
        "portfolio_evidence_digest": ledger["evidence_digest"],
        "portfolio_as_of_date_utc": raw_date,
        "freshness_basis": ledger.get("freshness_basis"),
        "live_policy": "execution result, subject binding, and freshness are projected independently from the validated Portfolio Evidence Ledger",
        "slots": [],
    }

    prior_version = base.VERSION
    base.VERSION = v21.VERSION
    try:
        for slot, system in enumerate(selected, start=1):
            repository = f"{base.OWNER}/{system['repo']}"
            require(repository in by_repo, f"Selected Spotlight repository is absent from Portfolio ledger: {repository}")
            subject, records, contract = project_entry(system, by_repo[repository])
            for theme in ("light", "dark"):
                (output_dir / f"spotlight-{slot}-{theme}.svg").write_text(
                    render_projection(system, slot, day, subject, records, theme),
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
                    "signals": records,
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
        print(f"Engineering Spotlight rendered from Portfolio Evidence Ledger v2: {args.ledger}")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
