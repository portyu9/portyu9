#!/usr/bin/env python3
"""Validate generated-surface cache identities and reviewer paths.

Signal Field remains a mutable generated-branch surface and therefore uses one reviewed
query-token identity. Engineering Spotlight is different: its profile hrefs rotate with
the selected systems, so all six theme images are pinned to one immutable generated
commit SHA. That makes the card bytes and direct navigation targets switch atomically in
one reviewed README change instead of allowing a mutable image to outrun a static href.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

SPOTLIGHT_TOKEN = "engineering-spotlight-v21-ledger-v2-result-binding-freshness-v1"
SIGNAL_FIELD_TOKEN = "signal-field-v218-wide-v219-compact-eid-bug-found-current-red-v1-profile-refresh-v2"

STALE_SPOTLIGHT_TOKENS = (
    "engineering-spotlight-v21-three-slots-20260905",
    "engineering-spotlight-v21-ledger-v1-20260905",
)
STALE_SIGNAL_FIELD_TOKENS = (
    "signal-field-v212-balance-20260903",
    "signal-field-v214-evidence-id-20260905",
    "signal-field-v216-profile-refresh-v1",
    "signal-field-v217-wide-alignment-profile-refresh-v1",
    "signal-field-v218-wide-alignment-profile-refresh-v1",
    "signal-field-v218-wide-alignment-current-red-v1-profile-refresh-v2",
    "signal-field-v218-wide-v219-compact-eid-current-red-v1-profile-refresh-v2",
)

LEDGER_REVIEW_URL = "https://github.com/portyu9/portyu9/blob/generated/portfolio-evidence/portfolio-evidence-ledger.json"
ATTESTATION_REVIEW_URL = "https://github.com/portyu9/portyu9/blob/main/.github/ATTESTATION.md"
REVIEW_NAVIGATION = (
    '<p align="center"><sub><strong>Evidence review</strong> · '
    f'<a href="{LEDGER_REVIEW_URL}">Portfolio Evidence Ledger</a> · '
    f'<a href="{ATTESTATION_REVIEW_URL}">Attestation Contract</a></sub></p>'
)
SELECTED_HEADING = '<h2 align="center">◇ Selected Engineering Systems</h2>'
FIRST_FLAGSHIP = '<a href="https://github.com/portyu9/ai-qa-automation"><picture>'

SPOTLIGHT_IMMUTABLE = re.compile(
    r"https://raw\.githubusercontent\.com/portyu9/portyu9/([0-9a-f]{40})/engineering-spotlight/"
    r"spotlight-[123]-(?:light|dark)\.svg"
)
MUTABLE_SPOTLIGHT = re.compile(
    r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/engineering-spotlight/"
    r"spotlight-[123]-(?:light|dark)\.svg"
)
SIGNAL_FIELD = re.compile(
    r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/profile-stats/profile/"
    r"signal-field-(?:wide|compact)-(?:light|dark)\.svg\?v=([^\"'> ]+)"
)
SVG_ROOT = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')

EXPECTED_SPOTLIGHT_FILES = tuple(
    f"spotlight-{slot}-{theme}.svg"
    for slot in (1, 2, 3)
    for theme in ("light", "dark")
)
EXPECTED_SIGNAL_FIELD_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def attrs_of_svg(path: Path) -> dict[str, str]:
    require(path.is_file() and path.stat().st_size > 0, f"candidate SVG is missing or empty: {path}")
    match = SVG_ROOT.search(path.read_text(encoding="utf-8"))
    require(match is not None, f"candidate SVG root is missing: {path}")
    return dict(ATTR.findall(match.group(0)))


def require_exact_files(directory: Path, expected: tuple[str, ...], pattern: str) -> list[Path]:
    require(directory.is_dir(), f"candidate directory is missing: {directory}")
    actual = sorted(path.name for path in directory.glob(pattern) if path.is_file())
    require(actual == sorted(expected), f"candidate file inventory changed in {directory}: {actual}")
    return [directory / name for name in expected]


def one_value(values: Iterable[str], label: str) -> str:
    unique = {value for value in values if value}
    require(len(unique) == 1, f"candidate {label} is missing or inconsistent: {sorted(unique)}")
    return next(iter(unique))


def compact_spotlight_version(version: str) -> str:
    require(re.fullmatch(r"engineering-spotlight-v\d+\.\d+", version) is not None,
            f"unexpected Spotlight version: {version}")
    return version.replace(".", "")


def compact_ledger_version(version: str) -> str:
    match = re.fullmatch(r"portfolio-evidence-ledger-(v\d+)", version)
    require(match is not None, f"unexpected Portfolio Ledger version: {version}")
    return f"ledger-{match.group(1)}"


def compact_evidence_semantics(semantics: str) -> str:
    match = re.fullmatch(r"execution-result-subject-binding-freshness-(v\d+)", semantics)
    require(match is not None, f"unexpected evidence-dimension semantics: {semantics}")
    return f"result-binding-freshness-{match.group(1)}"


def compact_signal_field_version(version: str) -> str:
    require(re.fullmatch(r"signal-field-v\d+\.\d+", version) is not None,
            f"unexpected final Signal Field version: {version}")
    return version.replace(".", "")


def compact_signal_field_component(version: str) -> str:
    compact = compact_signal_field_version(version)
    require(compact.startswith("signal-field-"), f"unexpected compact Signal Field version: {compact}")
    return compact.removeprefix("signal-field-")


def derive_spotlight_token(spotlight_dir: Path, ledger_dir: Path) -> str:
    paths = require_exact_files(spotlight_dir, EXPECTED_SPOTLIGHT_FILES, "spotlight-*.svg")
    attrs = [attrs_of_svg(path) for path in paths]
    spotlight_version = one_value((item.get("data-spotlight", "") for item in attrs), "Spotlight version")
    spotlight_semantics = one_value(
        (item.get("data-evidence-semantics", "") for item in attrs),
        "Spotlight evidence semantics",
    )
    ledger_path = ledger_dir / "portfolio-evidence-ledger.json"
    require(ledger_path.is_file() and ledger_path.stat().st_size > 0,
            "candidate Portfolio Ledger is missing")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    require(isinstance(ledger, dict), "candidate Portfolio Ledger root must be an object")
    ledger_version = str(ledger.get("version") or "")
    ledger_semantics = str(ledger.get("evidence_semantics") or "")
    require(ledger.get("system_count") == 13, "candidate Portfolio Ledger system count changed")
    require(ledger_semantics == spotlight_semantics,
            "Spotlight/Portfolio Ledger evidence semantics diverged")
    return "-".join((
        compact_spotlight_version(spotlight_version),
        compact_ledger_version(ledger_version),
        compact_evidence_semantics(ledger_semantics),
    ))


def derive_signal_field_token(signal_field_dir: Path) -> str:
    paths = require_exact_files(signal_field_dir, EXPECTED_SIGNAL_FIELD_FILES, "signal-field-*.svg")
    attrs_by_name = {path.name: attrs_of_svg(path) for path in paths}
    attrs = list(attrs_by_name.values())
    identity = one_value((item.get("data-evidence-identity", "") for item in attrs), "Signal Field evidence identity")
    presentation = one_value((item.get("data-evidence-presentation", "") for item in attrs), "Signal Field presentation")
    final_version = one_value((item.get("data-issues-label-balance", "") for item in attrs), "Signal Field v2.16 presentation")
    issue_alias = one_value((item.get("data-issues-display-alias", "") for item in attrs), "Signal Field issue display alias")
    issue_scale = one_value((item.get("data-issues-label-scale", "") for item in attrs), "Signal Field issue label scale")
    cadence = one_value((item.get("data-generation-cadence-contract", "") for item in attrs), "Signal Field refresh contract")
    schedule = one_value((item.get("data-generation-schedule", "") for item in attrs), "Signal Field generation schedule")
    current_day = one_value((item.get("data-current-day-highlight", "") for item in attrs), "Signal Field current-day highlight")

    require(identity == "signal-field-v2.14", f"candidate Signal Field evidence identity changed: {identity}")
    require(presentation == "signal-field-v2.15", f"candidate Signal Field evidence presentation changed: {presentation}")
    require(final_version == "signal-field-v2.16", f"candidate Signal Field v2.16 presentation changed: {final_version}")
    require(issue_alias == "bug-found", f"candidate Signal Field issue display alias changed: {issue_alias}")
    require(issue_scale == "peer-metric-label", f"candidate Signal Field issue label scale changed: {issue_scale}")
    require(schedule == "1-hour", f"candidate Signal Field generation schedule changed: {schedule}")
    require(cadence == "profile-refresh-v2", f"unexpected Signal Field refresh contract: {cadence}")
    require(current_day == "phosphorescent-red-v1", f"candidate current-day highlight changed: {current_day}")

    wide_attrs = [item for name, item in attrs_by_name.items() if "-wide-" in name]
    compact_attrs = [item for name, item in attrs_by_name.items() if "-compact-" in name]
    require(len(wide_attrs) == 2 and len(compact_attrs) == 2,
            "Signal Field responsive inventory changed")
    wide_alignment = one_value((item.get("data-wide-detail-alignment", "") for item in wide_attrs),
                               "Signal Field desktop alignment")
    compact_eid = one_value((item.get("data-compact-eid-layout", "") for item in compact_attrs),
                            "Signal Field compact EID layout")
    require(wide_alignment == "signal-field-v2.18",
            f"candidate desktop Signal Field alignment changed: {wide_alignment}")
    require(compact_eid == "signal-field-v2.19",
            f"candidate compact Signal Field EID layout changed: {compact_eid}")
    require(all("data-wide-detail-alignment" not in item for item in compact_attrs),
            "desktop-only Signal Field alignment provenance leaked into compact artifacts")
    require(all("data-compact-eid-layout" not in item for item in wide_attrs),
            "compact-only Signal Field EID provenance leaked into wide artifacts")
    return (
        f"{compact_signal_field_version(wide_alignment)}-wide-"
        f"{compact_signal_field_component(compact_eid)}-compact-eid-bug-found-current-red-v1-{cadence}"
    )


def readme_identities() -> tuple[list[str], list[str], str]:
    text = README.read_text(encoding="utf-8")
    return SPOTLIGHT_IMMUTABLE.findall(text), SIGNAL_FIELD.findall(text), text


def validate_reviewer_navigation(text: str) -> None:
    require(text.count(REVIEW_NAVIGATION) == 1,
            "README must contain exactly one reviewed evidence-navigation line")
    require(text.count(LEDGER_REVIEW_URL) == 1,
            "README Portfolio Evidence Ledger review link changed or duplicated")
    require(text.count(ATTESTATION_REVIEW_URL) == 1,
            "README attestation review link changed or duplicated")
    selected = text.find(SELECTED_HEADING)
    navigation = text.find(REVIEW_NAVIGATION)
    first_flagship = text.find(FIRST_FLAGSHIP, selected)
    require(selected >= 0 and navigation >= 0 and first_flagship >= 0,
            "Selected Engineering Systems review-navigation anchors are missing")
    require(selected < navigation < first_flagship,
            "evidence review links must remain adjacent to Selected Engineering Systems before flagship cards")


def validate_readme(expected_signal: str = SIGNAL_FIELD_TOKEN) -> None:
    spotlight_shas, signal, text = readme_identities()
    require(len(spotlight_shas) == 6,
            "README must reference exactly six immutable Spotlight theme assets")
    require(len(set(spotlight_shas)) == 1,
            "all six Spotlight theme assets must bind one immutable generated commit")
    require(MUTABLE_SPOTLIGHT.search(text) is None,
            "Spotlight README images must not regress to mutable generated-branch URLs")
    require(len(signal) == 4,
            "README must reference exactly four generated Signal Field assets")
    require(set(signal) == {expected_signal},
            "Signal Field cache token is stale or inconsistent across layouts/themes")

    for stale in STALE_SPOTLIGHT_TOKENS + STALE_SIGNAL_FIELD_TOKENS:
        require(stale not in text, f"stale generated-surface cache token remains in README: {stale}")

    mutable_urls = re.findall(
        r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/[^\"'> ]+",
        text,
    )
    require(len(mutable_urls) == 4,
            "mutable generated profile asset inventory must contain only four Signal Field URLs")
    require(all("?v=" in url for url in mutable_urls),
            "mutable generated profile asset lacks an explicit cache identity")
    validate_reviewer_navigation(text)


def validate_candidate(signal_field_dir: Path, spotlight_dir: Path, ledger_dir: Path) -> None:
    candidate_spotlight = derive_spotlight_token(spotlight_dir, ledger_dir)
    candidate_signal = derive_signal_field_token(signal_field_dir)
    require(candidate_spotlight == SPOTLIGHT_TOKEN,
            f"Spotlight renderer/ledger semantics advanced unexpectedly to {candidate_spotlight!r}; "
            "the direct-link snapshot contract must be reviewed before publication")
    require(candidate_signal == SIGNAL_FIELD_TOKEN,
            f"README Signal Field cache contract must advance to live candidate identity {candidate_signal!r}")
    validate_readme(candidate_signal)


def self_test() -> None:
    require("-".join((
        compact_spotlight_version("engineering-spotlight-v2.1"),
        compact_ledger_version("portfolio-evidence-ledger-v2"),
        compact_evidence_semantics("execution-result-subject-binding-freshness-v1"),
    )) == SPOTLIGHT_TOKEN, "Spotlight semantic-token derivation changed")
    require(
        f"{compact_signal_field_version('signal-field-v2.18')}-wide-"
        f"{compact_signal_field_component('signal-field-v2.19')}-compact-eid-bug-found-current-red-v1-profile-refresh-v2"
        == SIGNAL_FIELD_TOKEN,
        "Signal Field cache-token derivation changed",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal-field-dir", type=Path)
    parser.add_argument("--spotlight-dir", type=Path)
    parser.add_argument("--ledger-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        self_test()
        validate_readme()
        supplied = (args.signal_field_dir, args.spotlight_dir, args.ledger_dir)
        require(all(value is None for value in supplied) or all(value is not None for value in supplied),
                "candidate validation requires all three candidate directories")
        if all(value is not None for value in supplied):
            assert args.signal_field_dir is not None
            assert args.spotlight_dir is not None
            assert args.ledger_dir is not None
            validate_candidate(args.signal_field_dir, args.spotlight_dir, args.ledger_dir)
            print(
                "Profile cache/reviewer contract passed: immutable Spotlight snapshot semantics match the live "
                "candidate family, Signal Field cache identity matches the live candidate, and reviewer paths remain explicit."
            )
        else:
            print(
                "Profile cache/reviewer contract passed: six Spotlight assets share one immutable generated commit; "
                "four mutable Signal Field assets share the reviewed cache identity; reviewer paths remain explicit."
            )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
