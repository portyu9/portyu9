#!/usr/bin/env python3
"""Validate Engineering Evidence Spotlight v2.1 artifacts."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from validate_engineering_spotlight_v2 import require, require_signal

VERSION = "engineering-spotlight-v2.1"
EVIDENCE_MODEL = "per-system-evidence-contract-v2"
MANIFEST = "spotlight-manifest.json"
SLOT_COUNT = 3
EXPECTED = tuple(
    f"spotlight-{slot}-{theme}.svg"
    for slot in range(1, SLOT_COUNT + 1)
    for theme in ("light", "dark")
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
STATIC_REPOSITORIES = {
    "portyu9/ai-qa-automation",
    "portyu9/qa-automation-ai-agent-evals",
    "portyu9/qa-automation-graphql",
    "portyu9/qa-automation-visual-and-accessibility-playwright-axe",
}
ALLOWED_REPOS = {
    "portyu9/qa-automation-dotnet-selenium",
    "portyu9/qa-automation-api-postman-newman",
    "portyu9/qa-automation-mobile-appium",
    "portyu9/qa-automation-ui-cypress",
    "portyu9/qa-automation-python-pytest",
    "portyu9/qa-automation-node-supertest",
    "portyu9/qa-automation-java-restassured",
    "portyu9/qa-automation-node-playwright",
    "portyu9/qa-automation-load-k6",
}


def validate_manifest(root: Path, require_live: bool) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    manifest_path = root / MANIFEST
    require(manifest_path.is_file(), "Spotlight manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("version") == VERSION, "Spotlight manifest version changed")
    require(manifest.get("evidence_model") == EVIDENCE_MODEL, "Spotlight evidence model changed")
    require(
        manifest.get("freshness_basis") == "UTC whole-day age from workflow evidence timestamp",
        "Spotlight freshness basis changed",
    )
    require(
        manifest.get("live_policy")
        == "signals bind to current main revision; mismatched workflow head is STALE",
        "Spotlight live binding policy changed",
    )
    require(
        manifest.get("selection_policy") == "deterministic-daily-sha256-sample",
        "Spotlight selection policy changed",
    )
    require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(manifest.get("selection_date_utc")) or "") is not None,
        "Spotlight UTC date is invalid",
    )

    slots = manifest.get("slots")
    require(isinstance(slots, list) and len(slots) == SLOT_COUNT, "Exactly three spotlight slots are required")
    repos = [slot.get("repository") for slot in slots]
    require(len(set(repos)) == SLOT_COUNT, "Spotlight slots must select three distinct repositories")
    require(all(repo in ALLOWED_REPOS for repo in repos), "Spotlight repository pool changed")
    require(not (set(repos) & STATIC_REPOSITORIES), "Permanent flagship repository entered Spotlight rotation")

    glyphs = [slot.get("glyph") for slot in slots]
    topologies = [slot.get("topology") for slot in slots]
    require(all(glyphs) and len(set(glyphs)) == SLOT_COUNT, "Visible Spotlight systems must use distinct glyph identities")
    require(all(topologies) and len(set(topologies)) == SLOT_COUNT, "Visible Spotlight systems must use distinct topology identities")

    slot_by_number: dict[int, dict[str, Any]] = {}
    for slot in slots:
        number = slot.get("slot")
        require(number in (1, 2, 3), "Spotlight slot number is invalid")
        slot_by_number[int(number)] = slot
        repository = str(slot.get("repository"))
        subject = slot.get("subject_revision")
        require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None, f"{repository}: subject revision is malformed")

        contract = slot.get("evidence_contract")
        signals = slot.get("signals")
        require(isinstance(contract, list) and len(contract) == 2, f"{repository}: exactly two evidence contract entries are required")
        require(isinstance(signals, list) and len(signals) == 2, f"{repository}: exactly two evidence signals are required")
        contract_pairs = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in contract]
        signal_pairs = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in signals]
        require(contract_pairs == signal_pairs, f"{repository}: rendered evidence does not match the declared per-system contract")
        require(len({entry.get("label") for entry in signals}) == 2, f"{repository}: evidence labels must be distinct")
        for signal in signals:
            require_signal(repository, str(subject), signal, require_live)

    require(set(slot_by_number) == {1, 2, 3}, "Spotlight manifest must contain slots 1, 2, and 3 exactly once")
    return manifest, slot_by_number


def validate_svgs(root: Path, slot_by_number: dict[int, dict[str, Any]]) -> None:
    seen_by_slot: dict[str, tuple[str, str, str]] = {}
    for name in EXPECTED:
        path = root / name
        require(path.is_file(), f"Missing spotlight SVG: {name}")
        content = path.read_text(encoding="utf-8")
        require(len(content.encode()) <= 35000, f"Spotlight SVG exceeds 35 KB: {name}")
        require(f'data-spotlight="{VERSION}"' in content, f"Spotlight provenance missing: {name}")
        require('data-layout="evidence-v2"' in content, f"Spotlight layout provenance missing: {name}")
        require('width="620" height="198" viewBox="0 0 620 198"' in content, f"Spotlight reviewed geometry changed: {name}")
        for marker in (
            "EVIDENCE SPOTLIGHT",
            "SUBJECT · ",
            "FRESHNESS · ",
            "d UTC",
            "RUNS · ",
            'data-subject-revision="',
            'data-evidence-runs="',
            'data-evidence-workflows="',
            "repo · ",
        ):
            require(marker in content, f"Spotlight evidence marker missing from {name}: {marker}")
        require('fill="url(#edge)"' in content and 'fill="url(#wash)"' in content, f"Spotlight gradient visual system regressed: {name}")
        require(content.count("<linearGradient") >= 2, f"Spotlight gradient definitions missing: {name}")
        require(content.count("<circle") >= 7, f"Spotlight node/evidence markers regressed: {name}")

        glyph = re.search(r'data-glyph="([^"]+)"', content)
        topology = re.search(r'data-topology="([^"]+)"', content)
        slot_match = re.search(r'data-slot="([123])"', content)
        subject_match = re.search(r'data-subject-revision="([0-9a-f]{40})"', content)
        require(glyph is not None and topology is not None and slot_match is not None and subject_match is not None, f"Spotlight visual/evidence identity provenance missing: {name}")
        identity = (glyph.group(1), topology.group(1), subject_match.group(1))
        prior = seen_by_slot.setdefault(slot_match.group(1), identity)
        require(prior == identity, f"Light/dark Spotlight identity diverged for slot {slot_match.group(1)}")

        slot = slot_by_number[int(slot_match.group(1))]
        require(subject_match.group(1) == slot["subject_revision"], f"SVG/manifest subject revision diverged for slot {slot_match.group(1)}")
        require(f"SUBJECT · {slot['subject_revision']} · MAIN" in content, f"Full visible subject revision missing for slot {slot_match.group(1)}")
        require(str(slot["repository"]) not in STATIC_REPOSITORIES, f"Permanent flagship rendered in slot {slot_match.group(1)}")
        for signal in slot["signals"]:
            require(f"{signal['label']} · {signal['signal']}" in content, f"Named evidence signal missing from {name}: {signal['label']}")
            require(f"{signal['workflow']}#{signal['run_id']}" in content, f"Exact workflow/run provenance missing from {name}: {signal['label']}")

        lowered = content.lower()
        for forbidden in ("<image", "<foreignobject", "<script", "javascript:", "data:image", "<a "):
            require(forbidden not in lowered, f"Unsafe SVG content {forbidden!r}: {name}")

    require(len(seen_by_slot) == SLOT_COUNT, "Exactly three Spotlight visual identities are required")
    require(len({identity[0] for identity in seen_by_slot.values()}) == SLOT_COUNT, "Visible Spotlight glyphs must be unique")
    require(len({identity[1] for identity in seen_by_slot.values()}) == SLOT_COUNT, "Visible Spotlight topologies must be unique")
    require('fill="#FFFFFF"' in (root / "spotlight-1-light.svg").read_text(encoding="utf-8"), "Light spotlight surface changed")
    require('fill="#0D1117"' in (root / "spotlight-1-dark.svg").read_text(encoding="utf-8"), "Dark spotlight surface changed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-live", action="store_true")
    args = parser.parse_args()
    try:
        root = args.directory
        require(root.is_dir(), f"Spotlight directory is missing: {root}")
        _, slot_by_number = validate_manifest(root, args.require_live)
        validate_svgs(root, slot_by_number)
        print(
            "Engineering spotlight v2.1 validation passed: three distinct daily slots, permanent flagships excluded, "
            "per-system evidence contracts, current-main subject binding, UTC freshness, exact run/workflow provenance, "
            "explicit-theme visuals, and safe SVG contracts are intact."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
