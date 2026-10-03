#!/usr/bin/env python3
"""Render an atomic README link snapshot for the rotating Evidence Spotlight.

The validated Spotlight manifest is the only source of repository/workflow identity.
This module never writes repository state. It renders a proposed README whose three
Spotlight cards point directly to the selected repositories and whose external CI /
SECURITY controls point directly to the selected workflows. The card image URLs are
pinned to one immutable generated-branch commit so visual identity and navigation
switch atomically when the reviewed README change lands on main.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any

VERSION = "spotlight-profile-links-v1"
PUBLICATION_EPOCH_VERSION = "generated-publication-epoch-v1"
OWNER = "portyu9"
PROFILE_REPOSITORY = "portyu9/portyu9"
SPOTLIGHT_VERSION = "engineering-spotlight-v2.1"
LEDGER_VERSION = "portfolio-evidence-ledger-v2"
SEMANTICS = "execution-result-subject-binding-freshness-v1"
START = "<!-- spotlight-direct-links:start -->"
END = "<!-- spotlight-direct-links:end -->"
SLOT_COUNT = 3
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PUBLICATION_EPOCH_MARKER = re.compile(
    r"^<!-- generated-publication-epoch:v1 sequence=(0|[1-9][0-9]*) "
    r"generated=([0-9a-f]{40}) tree=([0-9a-f]{40}) -->$",
    re.MULTILINE,
)
REPOSITORY = re.compile(r"^portyu9/[A-Za-z0-9_.-]+$")
RUN_URL = re.compile(r"^https://github\.com/portyu9/([A-Za-z0-9_.-]+)/actions/runs/([0-9]+)$")
EXPECTED_LABELS = ("CI", "SECURITY")
EXPECTED_WORKFLOWS = {"CI": "ci.yml", "SECURITY": "security.yml"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def real_file(path: Path, label: str) -> None:
    require(path.exists() or path.is_symlink(), f"{label} is missing: {path}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), f"{label} must be a real regular file: {path}")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def slot_projection(slot: dict[str, Any], number: int) -> tuple[str, dict[str, dict[str, Any]]]:
    require(slot.get("slot") == number, f"slot order changed at {number}")
    repository = slot.get("repository")
    subject = slot.get("subject_revision")
    signals = slot.get("signals")
    require(isinstance(repository, str) and REPOSITORY.fullmatch(repository) is not None,
            f"slot {number}: repository is invalid")
    require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None,
            f"slot {number}: subject revision is invalid")
    require(isinstance(signals, list) and len(signals) == 2,
            f"slot {number}: exactly CI and SECURITY evidence are required")
    slug = repository.split("/", 1)[1]
    by_label: dict[str, dict[str, Any]] = {}
    for record in signals:
        require(isinstance(record, dict), f"slot {number}: evidence record is malformed")
        label = record.get("label")
        workflow = record.get("workflow")
        run_id = record.get("run_id")
        run_url = record.get("run_url")
        require(label in EXPECTED_LABELS and label not in by_label,
                f"slot {number}: evidence labels must be CI and SECURITY exactly once")
        require(workflow == EXPECTED_WORKFLOWS[str(label)], f"slot {number} {label}: workflow identity changed")
        require(record.get("binding") == "CURRENT_SUBJECT", f"slot {number} {label}: current-subject binding is required")
        require(record.get("freshness") in {"SAME_DAY", "AGED"}, f"slot {number} {label}: freshness is unavailable")
        require(isinstance(run_id, int) and run_id > 0 and isinstance(run_url, str),
                f"slot {number} {label}: run identity is invalid")
        match = RUN_URL.fullmatch(run_url)
        require(match is not None and match.group(1) == slug and int(match.group(2)) == run_id,
                f"slot {number} {label}: run URL is not bound to the selected repository/run")
        by_label[str(label)] = record
    require(tuple(by_label) == EXPECTED_LABELS, f"slot {number}: evidence order must remain CI then SECURITY")
    return repository, by_label


def validate_manifest(manifest: dict[str, Any]) -> list[tuple[str, dict[str, dict[str, Any]]]]:
    require(manifest.get("version") == SPOTLIGHT_VERSION, "Spotlight source version changed")
    require(manifest.get("evidence_source") == LEDGER_VERSION, "Spotlight evidence source changed")
    require(manifest.get("evidence_semantics") == SEMANTICS, "Spotlight evidence semantics changed")
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(manifest.get("selection_date_utc", ""))) is not None,
            "Spotlight selection date is invalid")
    slots = manifest.get("slots")
    require(isinstance(slots, list) and len(slots) == SLOT_COUNT, "Spotlight link snapshot requires exactly three slots")
    return [slot_projection(raw, i) for i, raw in enumerate(slots, start=1) if isinstance(raw, dict)]


def publication_high_water(readme: str) -> tuple[int, str, str] | None:
    matches = list(PUBLICATION_EPOCH_MARKER.finditer(readme))
    require(readme.count("<!-- generated-publication-epoch:") == len(matches),
            "README contains a malformed generated publication epoch marker")
    require(len(matches) <= 1, "README contains multiple generated publication epoch markers")
    if not matches:
        return None
    match = matches[0]
    start = readme.find(START)
    end = readme.find(END, start + len(START))
    require(start >= 0 and end > start and start < match.start() < end,
            "generated publication epoch marker must be inside the guarded Spotlight block")
    return int(match.group(1)), match.group(2), match.group(3)


def render_block(
    manifest: dict[str, Any],
    generated_sha: str,
    publication_sequence: int,
    generated_tree_sha: str,
) -> tuple[str, list[dict[str, str]]]:
    require(SHA40.fullmatch(generated_sha) is not None, "generated commit must be a lowercase 40-character SHA")
    require(type(publication_sequence) is int and publication_sequence >= 0,
            "publication sequence must be one non-negative integer")
    require(SHA40.fullmatch(generated_tree_sha) is not None,
            "generated tree must be a lowercase 40-character SHA")
    projections = validate_manifest(manifest)
    require(len(projections) == SLOT_COUNT, "Spotlight link projection lost a slot")
    lines = [
        START,
        f"<!-- generated-publication-epoch:v1 sequence={publication_sequence} "
        f"generated={generated_sha} tree={generated_tree_sha} -->",
    ]
    targets: list[dict[str, str]] = []
    for slot, (repository, signals) in enumerate(projections, start=1):
        repo_url = f"https://github.com/{repository}"
        ci_workflow = str(signals["CI"]["workflow"])
        security_workflow = str(signals["SECURITY"]["workflow"])
        ci_url = f"{repo_url}/actions/workflows/{ci_workflow}"
        security_url = f"{repo_url}/actions/workflows/{security_workflow}"
        ci_badge = f"https://img.shields.io/github/actions/workflow/status/{repository}/{ci_workflow}?branch=main&style=flat-square&label=CI"
        security_badge = f"https://img.shields.io/github/actions/workflow/status/{repository}/{security_workflow}?branch=main&style=flat-square&label=SECURITY"
        dark = f"https://raw.githubusercontent.com/{PROFILE_REPOSITORY}/{generated_sha}/engineering-spotlight/spotlight-{slot}-dark.svg"
        light = f"https://raw.githubusercontent.com/{PROFILE_REPOSITORY}/{generated_sha}/engineering-spotlight/spotlight-{slot}-light.svg"
        lines.extend([
            '<p align="center">',
            f'<a href="{repo_url}"><picture><source media="(prefers-color-scheme: dark)" srcset="{dark}"><img alt="Daily engineering Evidence Spotlight slot {slot}" src="{light}" width="620"></picture></a><br>',
            f'<a href="{ci_url}"><img alt="Spotlight slot {slot} CI" height="24" src="{ci_badge}"></a>&nbsp;<a href="{security_url}"><img alt="Spotlight slot {slot} security" height="24" src="{security_badge}"></a>',
            '</p>',
            '',
        ])
        targets.append({"slot": str(slot), "repository": repository, "card": repo_url, "ci": ci_url, "security": security_url})
    lines.append(END)
    return "\n".join(lines), targets


def replace_block(readme: str, block: str) -> str:
    require(readme.count(START) == 1 and readme.count(END) == 1, "README must contain exactly one guarded Spotlight direct-link block")
    start = readme.index(START)
    end = readme.index(END, start) + len(END)
    require(start < end, "README Spotlight direct-link markers are malformed")
    return readme[:start] + block + readme[end:]


def render_plan(
    manifest: dict[str, Any],
    readme: str,
    generated_sha: str,
    base_sha: str,
    publication_sequence: int,
    generated_tree_sha: str,
) -> tuple[str, dict[str, Any]]:
    require(SHA40.fullmatch(base_sha) is not None, "base main commit must be a lowercase 40-character SHA")
    high_water = publication_high_water(readme)
    if high_water is not None:
        previous_sequence, previous_generated, previous_tree = high_water
        require(publication_sequence >= previous_sequence,
                "generated publication epoch rollback is forbidden")
        if publication_sequence == previous_sequence:
            require(generated_sha == previous_generated and generated_tree_sha == previous_tree,
                    "same generated publication epoch must preserve exact commit and tree identity")
    block, targets = render_block(manifest, generated_sha, publication_sequence, generated_tree_sha)
    proposed = replace_block(readme, block)
    plan = {
        "version": VERSION,
        "publication_epoch_version": PUBLICATION_EPOCH_VERSION,
        "publication_sequence": publication_sequence,
        "previous_publication_sequence": high_water[0] if high_water is not None else None,
        "base_sha": base_sha,
        "generated_sha": generated_sha,
        "generated_tree_sha": generated_tree_sha,
        "selection_date_utc": manifest["selection_date_utc"],
        "readme_sha256_before": sha256_text(readme),
        "readme_sha256_after": sha256_text(proposed),
        "changed": proposed != readme,
        "targets": targets,
    }
    return proposed, plan


def write_outputs(directory: Path, proposed: str, plan: dict[str, Any]) -> None:
    require(not directory.exists() and not directory.is_symlink(), f"output directory already exists: {directory}")
    directory.mkdir(parents=False)
    (directory / "README.md").write_text(proposed, encoding="utf-8")
    (directory / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    real_file(directory / "README.md", "proposed README")
    real_file(directory / "plan.json", "Spotlight link plan")


def fixture_manifest() -> dict[str, Any]:
    slots = []
    for slot in range(1, 4):
        repo = f"portyu9/qa-automation-fixture-{slot}"
        slots.append({
            "slot": slot,
            "repository": repo,
            "subject_revision": str(slot) * 40,
            "signals": [
                {"label": "CI", "workflow": "ci.yml", "run_id": 1000 + slot,
                 "run_url": f"https://github.com/{repo}/actions/runs/{1000 + slot}",
                 "binding": "CURRENT_SUBJECT", "freshness": "SAME_DAY"},
                {"label": "SECURITY", "workflow": "security.yml", "run_id": 2000 + slot,
                 "run_url": f"https://github.com/{repo}/actions/runs/{2000 + slot}",
                 "binding": "CURRENT_SUBJECT", "freshness": "AGED"},
            ],
        })
    return {
        "version": SPOTLIGHT_VERSION,
        "evidence_source": LEDGER_VERSION,
        "evidence_semantics": SEMANTICS,
        "selection_date_utc": "2026-09-06",
        "slots": slots,
    }


def self_test() -> None:
    readme = f"before\n{START}\nold\n{END}\nafter\n"
    proposed, plan = render_plan(
        fixture_manifest(), readme, "a" * 40, "b" * 40, 7, "c" * 40
    )
    require(plan["changed"] is True and len(plan["targets"]) == 3, "self-test lost direct link targets")
    require("issues/122" not in proposed, "self-test retained the obsolete issue navigator")
    require("https://github.com/portyu9/qa-automation-fixture-2/actions/workflows/security.yml" in proposed,
            "self-test lost direct workflow navigation")
    require("img.shields.io/github/actions/workflow/status/portyu9/qa-automation-fixture-1/ci.yml" in proposed,
            "self-test lost live workflow-status badges")
    require("/" + "a" * 40 + "/engineering-spotlight/spotlight-3-dark.svg" in proposed,
            "self-test did not pin the visual snapshot to one generated commit")
    require(
        "<!-- generated-publication-epoch:v1 sequence=7 generated=" + "a" * 40
        + " tree=" + "c" * 40 + " -->" in proposed,
        "self-test lost the protected publication high-water marker",
    )
    again, second_plan = render_plan(
        fixture_manifest(), proposed, "a" * 40, "b" * 40, 7, "c" * 40
    )
    require(again == proposed and second_plan["changed"] is False, "direct-link rendering is not idempotent")
    try:
        render_plan(fixture_manifest(), proposed, "d" * 40, "b" * 40, 6, "e" * 40)
    except ValueError as exc:
        require("rollback" in str(exc), f"publication rollback self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("publication rollback self-test accepted a lower epoch")
    try:
        render_plan(fixture_manifest(), proposed, "d" * 40, "b" * 40, 7, "e" * 40)
    except ValueError as exc:
        require("same generated publication epoch" in str(exc),
                f"same-epoch identity self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("same-epoch identity self-test accepted different generated evidence")
    advanced, advanced_plan = render_plan(
        fixture_manifest(), proposed, "d" * 40, "b" * 40, 8, "e" * 40
    )
    require(advanced_plan["changed"] is True and "sequence=8" in advanced,
            "publication high-water self-test rejected a monotonic advance")
    print(f"Spotlight profile link self-test passed: {VERSION} · direct repo/workflow targets · immutable visual snapshot")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--readme", type=Path)
    parser.add_argument("--generated-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--publication-sequence", type=int)
    parser.add_argument("--generated-tree-sha")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            require(all(value is None for value in (
                        args.manifest, args.readme, args.generated_sha, args.base_sha,
                        args.publication_sequence, args.generated_tree_sha, args.output_dir,
                    )),
                    "--self-test cannot be combined with render arguments")
            self_test()
            return 0
        require(all(value is not None for value in (
                    args.manifest, args.readme, args.generated_sha, args.base_sha,
                    args.publication_sequence, args.generated_tree_sha, args.output_dir,
                )),
                "render mode requires manifest, README, generated/base SHAs, publication sequence/tree, and output directory")
        real_file(args.manifest, "Spotlight manifest")
        real_file(args.readme, "profile README")
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        require(isinstance(manifest, dict), "Spotlight manifest root must be an object")
        proposed, plan = render_plan(
            manifest,
            args.readme.read_text(encoding="utf-8"),
            str(args.generated_sha),
            str(args.base_sha),
            int(args.publication_sequence),
            str(args.generated_tree_sha),
        )
        write_outputs(args.output_dir, proposed, plan)
        print(f"Spotlight profile links rendered: {VERSION} · changed={str(plan['changed']).lower()} · generated={args.generated_sha}")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
