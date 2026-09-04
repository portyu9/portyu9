#!/usr/bin/env python3
"""Validate the repository's Dependabot and action-pinning governance contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT = ROOT / ".github/dependabot.yml"
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_dependabot(text: str) -> None:
    require(text.startswith("version: 2\n"), "Dependabot config must use version 2")
    require(text.count('package-ecosystem: "github-actions"') == 1,
            "Dependabot must define exactly one GitHub Actions update ecosystem")
    require('directory: "/"' in text, "GitHub Actions updates must be scoped to repository root")
    require('interval: "weekly"' in text, "Dependabot cadence must remain weekly")
    require('day: "monday"' in text, "Dependabot weekly review day must remain Monday")
    require('time: "09:00"' in text, "Dependabot review time must remain 09:00")
    require('timezone: "America/New_York"' in text,
            "Dependabot review timezone must remain America/New_York")
    require('open-pull-requests-limit: 5' in text,
            "Dependabot open pull-request limit must remain bounded at five")
    require('prefix: "chore(deps)"' in text, "Dependabot commit prefix changed")
    require('first-party-actions:' in text, "First-party GitHub Actions group is missing")
    require(text.count('- "actions/*"') == 1,
            "Only actions/* should be grouped as first-party Actions updates")
    require('- "*"' not in text, "Broad dependency grouping would hide third-party review boundaries")
    require('target-branch:' not in text,
            "Dependabot must target the repository default branch rather than generated artifacts")
    require('ignore:' not in text, "Dependabot must not silently suppress reviewed dependency updates")
    require('shinpr/github-profile-stats' not in text,
            "Third-party Signal Field generator must not be grouped or specially bypassed")


def validate_action_pins(text: str, label: str) -> None:
    refs = re.findall(r'(?m)^\s*uses:\s+([^\s@]+)@([^\s#]+)', text)
    require(refs, f"No GitHub Actions dependencies found in {label}")
    for action, ref in refs:
        require(re.fullmatch(r"[0-9a-fA-F]{40}", ref) is not None,
                f"{label} action must be pinned to an exact 40-character commit SHA: {action}@{ref}")


def validate_quality_contract(text: str) -> None:
    require('- ".github/dependabot.yml"' in text,
            "Profile Quality push paths must include Dependabot governance changes")
    require('python3 scripts/validate-dependabot-contract.py' in text,
            "Profile Quality must execute the Dependabot governance validator")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Dependency update automation",
        ".github/dependabot.yml",
        "exact commit SHA",
        "actions/*",
        "shinpr/github-profile-stats",
        "never auto-merged",
        "Profile quality / validate-contracts",
        "Profile quality / integration-pinned-upstream",
    ):
        require(phrase in text, f"Dependabot governance documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (DEPENDABOT, QUALITY, STATS, GOVERNANCE):
            require(path.is_file(), f"Dependabot governance input is missing: {path.relative_to(ROOT)}")
        dependabot = DEPENDABOT.read_text(encoding="utf-8")
        quality = QUALITY.read_text(encoding="utf-8")
        stats = STATS.read_text(encoding="utf-8")
        governance = GOVERNANCE.read_text(encoding="utf-8")

        validate_dependabot(dependabot)
        validate_action_pins(quality, "Profile Quality")
        validate_action_pins(stats, "Profile Stats")
        validate_quality_contract(quality)
        validate_governance(governance)

        print(
            "Dependabot governance validation passed: GitHub Actions updates are weekly and bounded; "
            "first-party actions are grouped, the third-party Signal Field generator remains separately reviewable, "
            "and every workflow dependency remains pinned to an exact commit SHA."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
