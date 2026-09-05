#!/usr/bin/env python3
"""Validate exact closure between the canonical subject contract, schema, workflow, and candidate files."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import profile_evidence_subjects as subjects

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"
WORKFLOW = ROOT / ".github/workflows/profile-stats.yml"
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"
STAGER = ROOT / "scripts/stage-profile-evidence.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal-field-dir", type=Path)
    parser.add_argument("--spotlight-dir", type=Path)
    parser.add_argument("--portfolio-ledger-dir", type=Path)
    parser.add_argument("--published-root", type=Path)
    return parser.parse_args()


def top_level_files(directory: Path) -> set[str]:
    require(directory.is_dir(), f"subject candidate directory is missing: {directory}")
    return {path.name for path in directory.iterdir() if path.is_file()}


def validate_candidate_group(group_name: str, directory: Path) -> None:
    expected = set(subjects.source_basenames(group_name))
    prefix = {
        "signal_field": "profile-stats/profile/",
        "engineering_spotlight": "engineering-spotlight/",
        "portfolio_evidence_ledger": "portfolio-evidence/",
    }[group_name]
    internal = {
        Path(path).name
        for path in subjects.internal_artifacts()
        if path.startswith(prefix)
    }
    actual = top_level_files(directory)
    require(expected <= actual, f"{group_name} candidate is missing subjects: {sorted(expected - actual)}")
    require(actual <= expected | internal, f"{group_name} candidate contains unreviewed files: {sorted(actual - expected - internal)}")
    if internal:
        require(internal <= actual, f"{group_name} candidate is missing reviewed internal artifacts: {sorted(internal - actual)}")


def validate_schema() -> None:
    payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
    published = (
        payload.get("properties", {})
        .get("subjectSet", {})
        .get("properties", {})
        .get("publishedPaths", {})
        .get("const")
    )
    require(published == list(subjects.published_paths()), "predicate v3 schema subject array differs from canonical subject contract")


def subject_path_block(workflow: str) -> str:
    match = re.search(r"(?ms)^\s+subject-path:\s*\|\s*\n(?P<body>(?:\s{12}.+\n)+)", workflow)
    require(match is not None, "actions/attest subject-path block is missing")
    return match.group("body")


def validate_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    block = subject_path_block(text)
    lines = tuple(line.strip() for line in block.splitlines() if line.strip())
    require(lines == subjects.attestation_patterns(), "actions/attest patterns differ from canonical subject contract")
    require("engineering-spotlight/*.svg" not in block, "broad Spotlight attestation glob can include internal artifacts")

    candidate_command = "python3 source/scripts/validate-profile-evidence-subjects.py"
    require(text.count(candidate_command) >= 3, "subject closure validator must run at attestation, publish-input, and staged-publication boundaries")
    require("python3 source/scripts/stage-profile-evidence.py artifacts" in text, "publication must stage through the canonical subject contract")
    require("cp publish-input/signal-field-*.svg" not in text, "publication still duplicates Signal Field subject selection in shell")
    require("cp spotlight-publish-input/spotlight-*.svg" not in text, "publication still duplicates Spotlight subject selection in shell")
    require("cp portfolio-ledger-publish-input/portfolio-evidence-ledger.json" not in text, "publication still duplicates Ledger subject selection in shell")
    require("find artifacts/profile-stats/profile artifacts/engineering-spotlight artifacts/portfolio-evidence -type f | wc -l" not in text, "publication still encodes an independent eleven-file count")

    for path in (
        "scripts/profile-evidence-subjects-v1.json",
        "scripts/profile_evidence_subjects.py",
        "scripts/stage-profile-evidence.py",
        "scripts/validate-profile-evidence-subjects.py",
    ):
        require(f'      - "{path}"' in text, f"production push trigger is missing canonical subject-contract source: {path}")


def validate_builder() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    require("import profile_evidence_subjects as subjects" in text, "attestation builder must load canonical subject contract")
    require("PUBLISHED_PATHS = subjects.published_paths()" in text, "attestation builder must derive published paths from canonical subject contract")
    require("SIGNAL_FIELD_FILENAMES = subjects.source_basenames(\"signal_field\")" in text, "attestation builder must derive Signal Field subjects from canonical contract")
    for path in subjects.published_paths():
        require(text.count(f'"{path}"') == 0, f"attestation builder still hardcodes canonical subject path: {path}")


def main() -> int:
    args = parse_args()
    try:
        subjects.load_manifest()
        for path in (SCHEMA, WORKFLOW, BUILDER, STAGER):
            require(path.is_file(), f"subject-closure contract input is missing: {path.relative_to(ROOT)}")
        validate_schema()
        validate_workflow()
        validate_builder()

        candidate_values = (args.signal_field_dir, args.spotlight_dir, args.portfolio_ledger_dir)
        if any(value is not None for value in candidate_values):
            require(all(value is not None for value in candidate_values), "all three candidate evidence directories must be supplied together")
            validate_candidate_group("signal_field", args.signal_field_dir)  # type: ignore[arg-type]
            validate_candidate_group("engineering_spotlight", args.spotlight_dir)  # type: ignore[arg-type]
            validate_candidate_group("portfolio_evidence_ledger", args.portfolio_ledger_dir)  # type: ignore[arg-type]
        if args.published_root is not None:
            subjects.validate_published_root(args.published_root)

        print(
            f"Profile evidence subject closure passed: {subjects.VERSION} · "
            f"11 exact published subjects · sha256:{subjects.manifest_digest()}"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
