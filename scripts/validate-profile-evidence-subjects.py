#!/usr/bin/env python3
"""Validate exact closure between the canonical subject contract, schema, workflow, and candidate files."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import profile_evidence_subjects as subjects
import profile_evidence_validation as validation_contract

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


def subject_path_patterns(workflow: str) -> tuple[str, ...]:
    """Read the literal scalar using YAML indentation without a YAML dependency."""
    lines = workflow.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "subject-path: |":
            continue
        parent_indent = len(line) - len(line.lstrip(" "))
        child_indent = parent_indent + 2
        collected: list[str] = []
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                break
            indent = len(candidate) - len(candidate.lstrip(" "))
            if indent != child_indent:
                break
            collected.append(candidate.strip())
        require(collected, "actions/attest subject-path block is empty")
        return tuple(collected)
    raise ValueError("actions/attest subject-path block is missing")


def validate_boundary_contract() -> None:
    payload = validation_contract.load_manifest()
    closure = [stage for stage in payload["stages"] if stage.get("id") == "exact-subject-closure"]
    require(len(closure) == 1, "canonical validation boundary must contain one exact-subject-closure stage")
    stage = closure[0]
    require(stage.get("script") == "validate-profile-evidence-subjects.py", "candidate closure stage must execute this validator")
    require(stage.get("predicateGroup") is None and stage.get("predicateIdentity") is None, "subject closure is a boundary control, not a predicate validator identity")
    args = stage.get("args")
    require(isinstance(args, list), "candidate closure stage args are missing")
    for fragment in (
        "--signal-field-dir",
        "{signal_field_dir}",
        "--spotlight-dir",
        "{spotlight_dir}",
        "--portfolio-ledger-dir",
        "{portfolio_ledger_dir}",
    ):
        require(fragment in args, f"candidate closure stage is missing: {fragment}")


def validate_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    patterns = subject_path_patterns(text)
    require(patterns == subjects.attestation_patterns(), "actions/attest patterns differ from canonical subject contract")
    require("engineering-spotlight/*.svg" not in patterns, "broad Spotlight attestation glob can include internal artifacts")

    require(text.count("python3 source/scripts/validate-profile-evidence-boundary.py") == 2, "attestation and publication must each execute the canonical candidate validation boundary")
    require("python3 source/scripts/validate-profile-evidence-subjects.py --published-root published" in text, "scheduled delta comparison must validate exact current generated subjects")
    require("python3 source/scripts/validate-profile-evidence-subjects.py --published-root artifacts" in text, "staged publication must validate exact generated subjects")
    require("python3 source/scripts/stage-profile-evidence.py artifacts" in text, "publication must stage through the canonical subject contract")
    require("cp publish-input/signal-field-*.svg" not in text, "publication still duplicates Signal Field subject selection in shell")
    require("cp spotlight-publish-input/spotlight-*.svg" not in text, "publication still duplicates Spotlight subject selection in shell")
    require("cp portfolio-ledger-publish-input/portfolio-evidence-ledger.json" not in text, "publication still duplicates Ledger subject selection in shell")
    require("find artifacts/profile-stats/profile artifacts/engineering-spotlight artifacts/portfolio-evidence -type f | wc -l" not in text, "publication still encodes an independent eleven-file count")
    require('      - "scripts/**"' in text, "production push trigger must cover the complete trusted scripts source surface")
    for path in (
        "scripts/profile-evidence-subjects-v1.json",
        "scripts/profile_evidence_subjects.py",
        "scripts/stage-profile-evidence.py",
        "scripts/validate-profile-evidence-subjects.py",
        "scripts/profile-evidence-validation-boundary-v1.json",
        "scripts/profile_evidence_validation.py",
        "scripts/validate-profile-evidence-boundary.py",
    ):
        require(path.startswith("scripts/"), f"subject/validation-contract source moved outside the closed scripts trigger surface: {path}")


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
        validate_boundary_contract()
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
            f"11 exact published subjects · candidate closure owned by {validation_contract.VERSION} · sha256:{subjects.manifest_digest()}"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
