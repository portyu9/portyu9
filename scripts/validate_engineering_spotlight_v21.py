#!/usr/bin/env python3
"""Validate Engineering Evidence Spotlight v2.1 as a Ledger v2 projection."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import engineering_spotlight_v2 as base
import engineering_spotlight_v21 as v21

VERSION = "engineering-spotlight-v2.1"
EVIDENCE_MODEL = "per-system-evidence-contract-v3"
EVIDENCE_SOURCE = "portfolio-evidence-ledger-v2"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
MANIFEST = "spotlight-manifest.json"
SLOT_COUNT = 3
EXPECTED = tuple(
    f"spotlight-{slot}-{theme}.svg"
    for slot in range(1, SLOT_COUNT + 1)
    for theme in ("light", "dark")
)
SHA40_ZERO = "0" * 40
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LEDGER_ID = re.compile(r"^PL2-[0-9A-F]{16}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN_URL = re.compile(r"^https://github\.com/portyu9/([A-Za-z0-9_.-]+)/actions/runs/([0-9]+)$")
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
BAD_LIVE_RESULTS = {"UNAVAILABLE", "NO SIGNAL", "UNKNOWN"}
BINDINGS = {
    "CURRENT_SUBJECT",
    "DIFFERENT_SUBJECT",
    "SUBJECT_UNAVAILABLE",
    "RUN_HEAD_UNAVAILABLE",
    "UNAVAILABLE",
    "SYNTHETIC",
}
FRESHNESS = {"SAME_DAY", "AGED", "UNAVAILABLE", "SYNTHETIC"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_ledger(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    require(path.is_file(), f"Portfolio Evidence Ledger is missing: {path}")
    ledger = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(ledger, dict), "Portfolio Evidence Ledger must be an object")
    require(ledger.get("version") == EVIDENCE_SOURCE, "Portfolio Evidence Ledger version changed")
    require(ledger.get("kind") == "portfolio-evidence-ledger", "Portfolio Evidence Ledger kind changed")
    require(ledger.get("owner") == "portyu9", "Portfolio Evidence Ledger owner changed")
    require(ledger.get("evidence_semantics") == EVIDENCE_SEMANTICS, "Portfolio Evidence Ledger semantics changed")
    require(ledger.get("system_count") == 13, "Portfolio Evidence Ledger system count changed")
    require("signal_summary" not in ledger, "Ledger v2 must not contain legacy conflated signal summary")
    evidence_id = ledger.get("evidence_id")
    digest_value = ledger.get("evidence_digest")
    require(isinstance(evidence_id, str) and LEDGER_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
    require(isinstance(digest_value, str) and DIGEST.fullmatch(digest_value) is not None, "Portfolio evidence digest is malformed")
    core = {key: value for key, value in ledger.items() if key not in {"evidence_id", "evidence_digest"}}
    digest = canonical_digest(core)
    require(digest_value == f"sha256:{digest}", "Portfolio evidence digest does not match canonical semantics")
    require(evidence_id == f"PL2-{digest[:16].upper()}", "Portfolio Evidence ID does not match canonical digest")
    systems = ledger.get("systems")
    require(isinstance(systems, list) and len(systems) == 13, "Portfolio Evidence Ledger systems array changed")
    by_repo: dict[str, dict[str, Any]] = {}
    for system in systems:
        require(isinstance(system, dict), "Portfolio Evidence Ledger system entry must be an object")
        repository = system.get("repository")
        require(isinstance(repository, str), "Portfolio Evidence Ledger repository is missing")
        require(repository not in by_repo, f"Duplicate Portfolio Evidence Ledger repository: {repository}")
        by_repo[repository] = system
    require(len(by_repo) == 13, "Portfolio Evidence Ledger repositories must be distinct")
    return ledger, by_repo


def validate_record(repository: str, subject: str, record: dict[str, Any], require_live: bool) -> None:
    label = record.get("label")
    workflow = record.get("workflow")
    scope = record.get("scope")
    result = record.get("result")
    binding = record.get("binding")
    freshness = record.get("freshness")
    run_id = record.get("run_id")
    run_number = record.get("run_number")
    run_url = record.get("run_url")
    head_sha = record.get("head_sha")
    completed = record.get("completed_at_utc")
    age = record.get("age_days")
    offline = record.get("offline")

    require(isinstance(label, str) and label, f"{repository}: evidence label missing")
    require(isinstance(workflow, str) and workflow.endswith((".yml", ".yaml")), f"{repository} {label}: workflow filename is invalid")
    require(isinstance(scope, str) and scope, f"{repository} {label}: scope missing")
    require(isinstance(result, str) and result and result != "STALE", f"{repository} {label}: execution result is invalid")
    require(binding in BINDINGS, f"{repository} {label}: binding is invalid")
    require(freshness in FRESHNESS, f"{repository} {label}: freshness is invalid")
    require("signal" not in record, f"{repository} {label}: legacy conflated signal field is forbidden")
    require(isinstance(run_id, int) and run_id >= 0, f"{repository} {label}: run id is invalid")
    require(isinstance(run_number, int) and run_number >= 0, f"{repository} {label}: run number is invalid")
    require(isinstance(head_sha, str) and SHA40.fullmatch(head_sha) is not None, f"{repository} {label}: workflow head sha is invalid")
    require(isinstance(age, int) and age >= 0, f"{repository} {label}: freshness age is invalid")
    require(isinstance(completed, str), f"{repository} {label}: evidence timestamp is invalid")
    require(isinstance(offline, bool), f"{repository} {label}: offline marker is invalid")

    if run_id > 0:
        require(isinstance(run_url, str), f"{repository} {label}: run URL missing")
        match = RUN_URL.fullmatch(run_url)
        require(match is not None, f"{repository} {label}: exact run URL is invalid")
        require(match.group(1) == repository.split("/", 1)[1], f"{repository} {label}: run URL repository drifted")
        require(int(match.group(2)) == run_id, f"{repository} {label}: run URL/id mismatch")

    if binding == "CURRENT_SUBJECT":
        require(subject != SHA40_ZERO and head_sha == subject and run_id > 0, f"{repository} {label}: CURRENT_SUBJECT binding is false")
    elif binding == "DIFFERENT_SUBJECT":
        require(subject != SHA40_ZERO and head_sha not in {SHA40_ZERO, subject} and run_id > 0, f"{repository} {label}: DIFFERENT_SUBJECT binding is false")
    elif binding == "SUBJECT_UNAVAILABLE":
        require(subject == SHA40_ZERO and run_id > 0, f"{repository} {label}: SUBJECT_UNAVAILABLE binding is inconsistent")
    elif binding == "RUN_HEAD_UNAVAILABLE":
        require(subject != SHA40_ZERO and head_sha == SHA40_ZERO and run_id > 0, f"{repository} {label}: RUN_HEAD_UNAVAILABLE binding is inconsistent")
    elif binding == "UNAVAILABLE":
        require(run_id == 0 and head_sha == SHA40_ZERO, f"{repository} {label}: UNAVAILABLE binding is inconsistent")
    elif binding == "SYNTHETIC":
        require(offline is True, f"{repository} {label}: SYNTHETIC binding requires offline evidence")

    if freshness == "SAME_DAY":
        require(completed.endswith("Z") and age == 0, f"{repository} {label}: SAME_DAY freshness is inconsistent")
    elif freshness == "AGED":
        require(completed.endswith("Z") and age > 0, f"{repository} {label}: AGED freshness is inconsistent")
    elif freshness == "UNAVAILABLE":
        require(completed == "", f"{repository} {label}: unavailable freshness must not carry a timestamp")
    elif freshness == "SYNTHETIC":
        require(offline is True and completed.endswith("Z"), f"{repository} {label}: synthetic freshness is inconsistent")

    if require_live:
        require(offline is False, f"{repository} {label}: live Spotlight cannot use synthetic evidence")
        require(result not in BAD_LIVE_RESULTS, f"{repository} {label}: live execution result is unavailable: {result}")
        require(binding == "CURRENT_SUBJECT", f"{repository} {label}: live evidence is not bound to current main: {binding}")
        require(freshness in {"SAME_DAY", "AGED"}, f"{repository} {label}: live freshness is unavailable")
        require(run_id > 0 and run_number > 0, f"{repository} {label}: live run provenance missing")


def validate_manifest(
    root: Path,
    ledger: dict[str, Any],
    ledger_by_repo: dict[str, dict[str, Any]],
    require_live: bool,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    manifest_path = root / MANIFEST
    require(manifest_path.is_file(), "Spotlight manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("version") == VERSION, "Spotlight manifest version changed")
    require(manifest.get("evidence_model") == EVIDENCE_MODEL, "Spotlight evidence model changed")
    require(manifest.get("evidence_source") == EVIDENCE_SOURCE, "Spotlight must identify Ledger v2 as its evidence source")
    require(manifest.get("evidence_semantics") == EVIDENCE_SEMANTICS, "Spotlight evidence semantics changed")
    require(manifest.get("portfolio_evidence_id") == ledger.get("evidence_id"), "Spotlight/Portfolio Evidence ID diverged")
    require(manifest.get("portfolio_evidence_digest") == ledger.get("evidence_digest"), "Spotlight/Portfolio evidence digest diverged")
    require(manifest.get("portfolio_as_of_date_utc") == ledger.get("as_of_date_utc"), "Spotlight/Portfolio UTC date diverged")
    require(
        manifest.get("freshness_basis") == ledger.get("freshness_basis") == "UTC whole-day age from workflow evidence timestamp",
        "Spotlight freshness basis diverged from Portfolio Ledger",
    )
    require(
        manifest.get("live_policy")
        == "execution result, subject binding, and freshness are projected independently from the validated Portfolio Evidence Ledger",
        "Spotlight independent-dimension policy changed",
    )
    require(manifest.get("selection_policy") == "deterministic-daily-sha256-sample", "Spotlight selection policy changed")
    raw_date = str(manifest.get("selection_date_utc") or "")
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw_date) is not None, "Spotlight UTC date is invalid")
    require(raw_date == ledger.get("as_of_date_utc"), "Spotlight selection date must equal Portfolio Ledger date")

    expected_systems = v21.select_systems(dt.date.fromisoformat(raw_date))
    expected_repos = [f"{base.OWNER}/{system['repo']}" for system in expected_systems]
    slots = manifest.get("slots")
    require(isinstance(slots, list) and len(slots) == SLOT_COUNT, "Exactly three spotlight slots are required")
    repos = [slot.get("repository") for slot in slots]
    require(repos == expected_repos, "Spotlight slots do not match deterministic selection for the ledger date")
    require(len(set(repos)) == SLOT_COUNT, "Spotlight slots must select three distinct repositories")
    require(all(repo in ALLOWED_REPOS for repo in repos), "Spotlight repository pool changed")
    require(not (set(repos) & STATIC_REPOSITORIES), "Permanent flagship repository entered Spotlight rotation")

    glyphs = [slot.get("glyph") for slot in slots]
    topologies = [slot.get("topology") for slot in slots]
    require(all(glyphs) and len(set(glyphs)) == SLOT_COUNT, "Visible Spotlight systems must use distinct glyph identities")
    require(all(topologies) and len(set(topologies)) == SLOT_COUNT, "Visible Spotlight systems must use distinct topology identities")

    slot_by_number: dict[int, dict[str, Any]] = {}
    for slot, selected_system in zip(slots, expected_systems):
        require(isinstance(slot, dict), "Spotlight slot must be an object")
        number = slot.get("slot")
        require(number in (1, 2, 3), "Spotlight slot number is invalid")
        slot_by_number[int(number)] = slot
        repository = str(slot.get("repository"))
        require(repository in ledger_by_repo, f"{repository}: selected repository is missing from Portfolio Ledger")
        ledger_entry = ledger_by_repo[repository]
        require(ledger_entry.get("classification") == "rotating", f"{repository}: selected ledger entry must be rotating")
        require(slot.get("title") == selected_system["title"] == ledger_entry.get("title"), f"{repository}: selected title diverged")
        subject = slot.get("subject_revision")
        require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None, f"{repository}: subject revision is malformed")
        require(subject == ledger_entry.get("subject_revision"), f"{repository}: Spotlight subject differs from Portfolio Ledger")
        contract = slot.get("evidence_contract")
        records = slot.get("signals")
        require(contract == ledger_entry.get("evidence_contract"), f"{repository}: Spotlight contract differs from Portfolio Ledger")
        require(records == ledger_entry.get("signals"), f"{repository}: Spotlight evidence records differ from Portfolio Ledger")
        require(isinstance(contract, list) and len(contract) == 2, f"{repository}: exactly two evidence contract entries are required")
        require(isinstance(records, list) and len(records) == 2, f"{repository}: exactly two evidence records are required")
        contract_pairs = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in contract]
        record_pairs = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in records]
        require(contract_pairs == record_pairs, f"{repository}: rendered evidence does not match declared contract")
        require(len({entry.get("label") for entry in records}) == 2, f"{repository}: evidence labels must be distinct")
        for record in records:
            validate_record(repository, str(subject), record, require_live)

    require(set(slot_by_number) == {1, 2, 3}, "Spotlight manifest must contain slots 1, 2, and 3 exactly once")
    return manifest, slot_by_number


def attr_value(content: str, name: str) -> str:
    match = re.search(rf'{re.escape(name)}="([^"]*)"', content)
    require(match is not None, f"Spotlight SVG attribute is missing: {name}")
    return match.group(1)


def expected_dimension_attr(records: list[dict[str, Any]], field: str) -> str:
    return ";".join(f"{record['label']}:{record[field]}" for record in records)


def validate_svgs(root: Path, slot_by_number: dict[int, dict[str, Any]]) -> None:
    seen_by_slot: dict[str, tuple[str, str, str]] = {}
    for name in EXPECTED:
        path = root / name
        require(path.is_file(), f"Missing spotlight SVG: {name}")
        content = path.read_text(encoding="utf-8")
        require(len(content.encode()) <= 38000, f"Spotlight SVG exceeds 38 KB: {name}")
        require(f'data-spotlight="{VERSION}"' in content, f"Spotlight provenance missing: {name}")
        require('data-layout="evidence-v2"' in content, f"Spotlight layout provenance missing: {name}")
        require('data-status-presentation="external-clickable-only"' in content, f"Spotlight visible status presentation regressed: {name}")
        require(f'data-evidence-semantics="{EVIDENCE_SEMANTICS}"' in content, f"Spotlight evidence semantics missing: {name}")
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
            'data-evidence-results="',
            'data-evidence-bindings="',
            'data-evidence-freshness="',
            "repo · ",
        ):
            require(marker in content, f"Spotlight evidence marker missing from {name}: {marker}")
        require('fill="url(#edge)"' in content and 'fill="url(#wash)"' in content, f"Spotlight gradient visual system regressed: {name}")
        require(content.count("<linearGradient") >= 2, f"Spotlight gradient definitions missing: {name}")
        require(content.count("<circle") >= 5, f"Spotlight topology node markers regressed: {name}")

        glyph = re.search(r'data-glyph="([^"]+)"', content)
        topology = re.search(r'data-topology="([^"]+)"', content)
        slot_match = re.search(r'data-slot="([123])"', content)
        subject_match = re.search(r'data-subject-revision="([0-9a-f]{40})"', content)
        require(glyph is not None and topology is not None and slot_match is not None and subject_match is not None, f"Spotlight visual/evidence identity provenance missing: {name}")
        identity = (glyph.group(1), topology.group(1), subject_match.group(1))
        prior = seen_by_slot.setdefault(slot_match.group(1), identity)
        require(prior == identity, f"Light/dark Spotlight identity diverged for slot {slot_match.group(1)}")

        slot = slot_by_number[int(slot_match.group(1))]
        records = slot["signals"]
        require(subject_match.group(1) == slot["subject_revision"], f"SVG/manifest subject revision diverged for slot {slot_match.group(1)}")
        require(f"SUBJECT · {slot['subject_revision']} · MAIN" in content, f"Full visible subject revision missing for slot {slot_match.group(1)}")
        require(str(slot["repository"]) not in STATIC_REPOSITORIES, f"Permanent flagship rendered in slot {slot_match.group(1)}")
        require(attr_value(content, "data-evidence-results") == expected_dimension_attr(records, "result"), f"SVG execution-result projection diverged: {name}")
        require(attr_value(content, "data-evidence-bindings") == expected_dimension_attr(records, "binding"), f"SVG subject-binding projection diverged: {name}")
        require(attr_value(content, "data-evidence-freshness") == expected_dimension_attr(records, "freshness"), f"SVG freshness projection diverged: {name}")
        for record in records:
            require(f"{record['label']} result {record['result']}" in content, f"Execution result missing from accessible evidence description: {name}: {record['label']}")
            require(f"{record['workflow']}#{record['run_id']}" in content, f"Exact workflow/run provenance missing from {name}: {record['label']}")
            require(f"binding {record['binding']}" in content, f"Subject binding missing from SVG description: {name}")
            require(f"freshness {record['freshness']}" in content, f"Freshness state missing from SVG description: {name}")

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
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--require-live", action="store_true")
    args = parser.parse_args()
    try:
        root = args.directory
        require(root.is_dir(), f"Spotlight directory is missing: {root}")
        ledger, by_repo = load_ledger(args.ledger)
        _, slot_by_number = validate_manifest(root, ledger, by_repo, args.require_live)
        validate_svgs(root, slot_by_number)
        print(
            "Engineering spotlight v2.1 validation passed: three deterministic rotating slots are an exact Ledger v2 projection; "
            "execution result, current-subject binding, freshness, run provenance, explicit-theme visuals, and safe SVG contracts remain independent and fail-closed."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
