#!/usr/bin/env python3
"""Validate generated Engineering Evidence Spotlight v2 artifacts."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

EXPECTED = tuple(
    f"spotlight-{slot}-{theme}.svg"
    for slot in (1, 2)
    for theme in ("light", "dark")
)
MANIFEST = "spotlight-manifest.json"
VERSION = "engineering-spotlight-v2"
EVIDENCE_MODEL = "per-system-evidence-contract-v2"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
RUN_URL = re.compile(
    r"^https://github\.com/portyu9/([A-Za-z0-9_.-]+)/actions/runs/([0-9]+)$"
)
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
    "portyu9/qa-automation-ai-agent-evals",
}
BAD_LIVE_SIGNALS = {"UNAVAILABLE", "NO SIGNAL", "UNKNOWN", "STALE"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_signal(
    repository: str,
    subject: str,
    signal: dict[str, Any],
    require_live: bool,
) -> None:
    label = signal.get("label")
    workflow = signal.get("workflow")
    scope = signal.get("scope")
    state = signal.get("signal")
    run_id = signal.get("run_id")
    run_number = signal.get("run_number")
    run_url = signal.get("run_url")
    head_sha = signal.get("head_sha")
    completed = signal.get("completed_at_utc")
    age = signal.get("age_days")

    require(isinstance(label, str) and label, f"{repository}: evidence label missing")
    require(
        isinstance(workflow, str) and workflow.endswith((".yml", ".yaml")),
        f"{repository} {label}: workflow filename is invalid",
    )
    require(isinstance(scope, str) and scope, f"{repository} {label}: scope missing")
    require(isinstance(state, str) and state, f"{repository} {label}: signal missing")
    require(
        isinstance(run_id, int) and run_id >= 0,
        f"{repository} {label}: run id is invalid",
    )
    require(
        isinstance(run_number, int) and run_number >= 0,
        f"{repository} {label}: run number is invalid",
    )
    require(
        isinstance(head_sha, str) and SHA40.fullmatch(head_sha) is not None,
        f"{repository} {label}: workflow head sha is invalid",
    )
    require(
        isinstance(age, int) and age >= 0,
        f"{repository} {label}: freshness age is invalid",
    )
    require(
        isinstance(completed, str),
        f"{repository} {label}: evidence timestamp is invalid",
    )

    if run_id > 0:
        require(isinstance(run_url, str), f"{repository} {label}: run URL missing")
        match = RUN_URL.fullmatch(run_url)
        require(match is not None, f"{repository} {label}: exact run URL is invalid")
        repo_name = repository.split("/", 1)[1]
        require(match.group(1) == repo_name, f"{repository} {label}: run URL repository drifted")
        require(int(match.group(2)) == run_id, f"{repository} {label}: run URL/id mismatch")

    if require_live:
        require(
            state not in BAD_LIVE_SIGNALS,
            f"Live spotlight evidence unavailable for {repository} {label}: {state}",
        )
        require(run_id > 0 and run_number > 0, f"{repository} {label}: live run provenance missing")
        require(head_sha == subject, f"{repository} {label}: workflow evidence is not bound to current main")
        require(completed.endswith("Z"), f"{repository} {label}: live UTC evidence timestamp missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-live", action="store_true")
    args = parser.parse_args()

    try:
        root = args.directory
        require(root.is_dir(), f"Spotlight directory is missing: {root}")

        manifest_path = root / MANIFEST
        require(manifest_path.is_file(), "Spotlight manifest is missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        require(manifest.get("version") == VERSION, "Spotlight manifest version changed")
        require(manifest.get("evidence_model") == EVIDENCE_MODEL, "Spotlight evidence model changed")
        require(
            manifest.get("freshness_basis")
            == "UTC whole-day age from workflow evidence timestamp",
            "Spotlight freshness basis changed",
        )
        require(
            manifest.get("live_policy")
            == "signals bind to current main revision; mismatched workflow head is STALE",
            "Spotlight live binding policy changed",
        )

        slots = manifest.get("slots")
        require(isinstance(slots, list) and len(slots) == 2, "Exactly two spotlight slots are required")
        repos = [slot.get("repository") for slot in slots]
        require(len(set(repos)) == 2, "Spotlight slots must select distinct repositories")
        require(all(repo in ALLOWED_REPOS for repo in repos), "Spotlight repository pool changed")

        glyphs = [slot.get("glyph") for slot in slots]
        topologies = [slot.get("topology") for slot in slots]
        require(all(glyphs) and len(set(glyphs)) == 2, "Visible Spotlight systems must use distinct glyph identities")
        require(all(topologies) and len(set(topologies)) == 2, "Visible Spotlight systems must use distinct topology identities")
        require(
            re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(manifest.get("selection_date_utc")) or ""),
            "Spotlight UTC date is invalid",
        )

        slot_by_number: dict[int, dict[str, Any]] = {}
        for slot in slots:
            number = slot.get("slot")
            require(number in (1, 2), "Spotlight slot number is invalid")
            slot_by_number[int(number)] = slot
            repository = str(slot.get("repository"))
            subject = slot.get("subject_revision")
            require(
                isinstance(subject, str) and SHA40.fullmatch(subject) is not None,
                f"{repository}: subject revision is malformed",
            )
            contract = slot.get("evidence_contract")
            signals = slot.get("signals")
            require(
                isinstance(contract, list) and len(contract) == 2,
                f"{repository}: exactly two evidence contract entries are required",
            )
            require(
                isinstance(signals, list) and len(signals) == 2,
                f"{repository}: exactly two evidence signals are required",
            )
            contract_pairs = [
                (entry.get("label"), entry.get("workflow"), entry.get("scope"))
                for entry in contract
            ]
            signal_pairs = [
                (entry.get("label"), entry.get("workflow"), entry.get("scope"))
                for entry in signals
            ]
            require(
                contract_pairs == signal_pairs,
                f"{repository}: rendered evidence does not match the declared per-system contract",
            )
            require(
                len({entry.get("label") for entry in signals}) == 2,
                f"{repository}: evidence labels must be distinct",
            )
            for signal in signals:
                require_signal(repository, str(subject), signal, args.require_live)

            if repository == "portyu9/qa-automation-ai-agent-evals":
                labels = tuple(entry.get("label") for entry in contract)
                workflows = tuple(entry.get("workflow") for entry in contract)
                scopes = tuple(str(entry.get("scope") or "") for entry in contract)
                require(labels == ("QUALITY+SEC", "AGENT LABS"), "Agent Evaluation v2 evidence labels changed")
                require(workflows == ("ci.yml", "ci.yml"), "Agent Evaluation must remain bound to its single CI workflow")
                require("Bandit" in scopes[0] and "Dependency audit" in scopes[0], "Agent Evaluation security step scope changed")
                require("OpenAI adapter / deterministic SDK" in scopes[1], "Agent Evaluation lab scope changed")
                require("MCP OAuth flow / separated AS-RS" in scopes[1], "Agent Evaluation OAuth lab scope changed")

        seen_by_slot: dict[str, tuple[str, str, str]] = {}
        for name in EXPECTED:
            path = root / name
            require(path.is_file(), f"Missing spotlight SVG: {name}")
            content = path.read_text(encoding="utf-8")
            require(len(content.encode()) <= 35000, f"Spotlight SVG exceeds 35 KB: {name}")
            require(f'data-spotlight="{VERSION}"' in content, f"Spotlight provenance missing: {name}")
            require('data-layout="evidence-v2"' in content, f"Spotlight v2 layout provenance missing: {name}")
            require(
                'width="620" height="198" viewBox="0 0 620 198"' in content,
                f"Spotlight v2 reviewed geometry changed: {name}",
            )
            require("EVIDENCE SPOTLIGHT" in content, f"Spotlight slot identity missing: {name}")
            require("SUBJECT · " in content, f"Visible subject revision missing: {name}")
            require("FRESHNESS · " in content and "d UTC" in content, f"Visible evidence freshness missing: {name}")
            require("RUNS · " in content, f"Visible exact workflow/run provenance missing: {name}")
            require('data-subject-revision="' in content, f"Subject revision metadata missing: {name}")
            require('data-evidence-runs="' in content, f"Run provenance metadata missing: {name}")
            require('data-evidence-workflows="' in content, f"Workflow provenance metadata missing: {name}")
            require('fill="url(#edge)"' in content and 'fill="url(#wash)"' in content, f"Spotlight gradient visual system regressed: {name}")
            require(content.count("<linearGradient") >= 2, f"Spotlight gradient definitions missing: {name}")
            require(content.count("<circle") >= 7, f"Spotlight node/evidence markers regressed: {name}")
            require("repo · " in content, f"Spotlight repository provenance row missing: {name}")

            glyph = re.search(r'data-glyph="([^"]+)"', content)
            topology = re.search(r'data-topology="([^"]+)"', content)
            slot_match = re.search(r'data-slot="([12])"', content)
            subject_match = re.search(r'data-subject-revision="([0-9a-f]{40})"', content)
            require(
                glyph is not None and topology is not None and slot_match is not None and subject_match is not None,
                f"Spotlight visual/evidence identity provenance missing: {name}",
            )
            identity = (glyph.group(1), topology.group(1), subject_match.group(1))
            prior = seen_by_slot.setdefault(slot_match.group(1), identity)
            require(prior == identity, f"Light/dark Spotlight identity diverged for slot {slot_match.group(1)}")

            slot_manifest = slot_by_number[int(slot_match.group(1))]
            require(
                subject_match.group(1) == slot_manifest["subject_revision"],
                f"SVG/manifest subject revision diverged for slot {slot_match.group(1)}",
            )
            require(
                f"SUBJECT · {slot_manifest['subject_revision']} · MAIN" in content,
                f"Full visible subject revision missing for slot {slot_match.group(1)}",
            )

            for signal in slot_manifest["signals"]:
                require(
                    f"{signal['label']} · {signal['signal']}" in content,
                    f"Named evidence signal missing from {name}: {signal['label']}",
                )
                require(
                    f"{signal['workflow']}#{signal['run_id']}" in content,
                    f"Exact workflow/run provenance missing from {name}: {signal['label']}",
                )

            lowered = content.lower()
            for forbidden in ("<image", "<foreignobject", "<script", "javascript:", "data:image", "<a "):
                require(forbidden not in lowered, f"Unsafe SVG content {forbidden!r}: {name}")

        require(
            len({identity[0] for identity in seen_by_slot.values()}) == 2,
            "Visible Spotlight glyphs must be unique",
        )
        require(
            len({identity[1] for identity in seen_by_slot.values()}) == 2,
            "Visible Spotlight topologies must be unique",
        )
        require(
            'fill="#FFFFFF"' in (root / "spotlight-1-light.svg").read_text(encoding="utf-8"),
            "Light spotlight surface changed",
        )
        require(
            'fill="#0D1117"' in (root / "spotlight-1-dark.svg").read_text(encoding="utf-8"),
            "Dark spotlight surface changed",
        )
        print(
            "Engineering spotlight v2 validation passed: two distinct daily slots, "
            "per-system evidence contracts, current-main subject binding, UTC freshness, "
            "exact run/workflow provenance, explicit-theme visuals, and safe SVG contracts are intact."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
