#!/usr/bin/env python3
"""Validate Dependabot policy and immutable external-action references.

The repository intentionally keeps this validator dependency-free. The Dependabot
configuration is small enough to lock canonically, while workflow action references
are discovered across every current/future workflow and must use immutable Git SHAs.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEPENDABOT = ROOT / ".github/dependabot.yml"
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

EXPECTED_DEPENDABOT = """version: 2

updates:
  - package-ecosystem: \"github-actions\"
    directory: \"/\"
    schedule:
      interval: \"weekly\"
      day: \"monday\"
      time: \"09:00\"
      timezone: \"America/New_York\"
    open-pull-requests-limit: 10
    commit-message:
      prefix: \"chore(deps)\"
"""

REQUIRED_EXTERNAL_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/attest",
    "actions/dependency-review-action",
    "shinpr/github-profile-stats",
}
ACTION_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.\-/]+)?")
SHA40 = re.compile(r"[0-9a-fA-F]{40}")
USES_LINE = re.compile(r"^\s*(?:-\s*)?(?:['\"]?uses['\"]?)\s*:\s*(.+?)\s*$")


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def validate_dependabot(text: str) -> None:
    require(
        text == EXPECTED_DEPENDABOT,
        "Dependabot configuration drifted from the reviewed canonical GitHub-Actions-only policy",
    )


def validate_uses_text(text: str, label: str) -> set[str]:
    """Return external action names after rejecting mutable/unsupported references."""
    external: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue
        value = match.group(1).split("#", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()

        if value.startswith("./"):
            # Repository-local actions/reusable workflows are versioned with this PR.
            continue

        require(
            not value.startswith("docker://"),
            f"{label}:{line_number} uses an external Docker action that Dependabot cannot govern: {value}",
        )
        require(
            "@" in value,
            f"{label}:{line_number} external action must use repository@commit syntax: {value}",
        )
        action, ref = value.rsplit("@", 1)
        require(
            ACTION_NAME.fullmatch(action) is not None,
            f"{label}:{line_number} external action reference is not GitHub repository syntax: {value}",
        )
        require(
            SHA40.fullmatch(ref) is not None,
            f"{label}:{line_number} external action must be pinned to an exact 40-character commit SHA: {value}",
        )
        external.add(action)
    return external


def validate_all_workflow_pins() -> None:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    workflow_files = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(workflow_files, "No GitHub Actions workflow files found")

    observed: set[str] = set()
    for path in workflow_files:
        observed |= validate_uses_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))

    missing = sorted(REQUIRED_EXTERNAL_ACTIONS - observed)
    require(
        not missing,
        "Reviewed trust-boundary action dependency disappeared without governance review: " + ", ".join(missing),
    )


def validate_quality_contract(text: str) -> None:
    require(
        '- ".github/dependabot.yml"' in text,
        "Profile Quality push paths must include Dependabot governance changes",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover every current and future workflow",
    )
    require(
        "python3 scripts/validate-dependabot-contract.py" in text,
        "Profile Quality must execute the Dependabot governance validator",
    )


def validate_governance(text: str) -> None:
    for phrase in (
        "## Dependency update automation",
        ".github/dependabot.yml",
        "exact commit SHA",
        "separate pull request",
        "actions/attest",
        "actions/checkout",
        "shinpr/github-profile-stats",
        "Dependency review / dependency-review",
        "never auto-merged",
        "Dependabot alerts",
        "SHA-pinned GitHub Actions",
        "Profile quality / validate-contracts",
        "Profile quality / integration-pinned-upstream",
    ):
        require(phrase in text, f"Dependabot governance documentation is missing: {phrase}")


def self_test() -> None:
    good_sha = "a" * 40
    observed = validate_uses_text(
        f"steps:\n  - uses: actions/checkout@{good_sha} # v7\n  - uses : ./.github/actions/local\n  - 'uses' : actions/setup-python@{good_sha} # v6\n",
        "self-test-good.yml",
    )
    require(
        observed == {"actions/checkout", "actions/setup-python"},
        "Action-pin self-test failed to identify immutable external actions",
    )

    for bad, expected in (
        ("steps:\n  - uses: actions/checkout@v7\n", "exact 40-character commit SHA"),
        ("steps:\n  - uses : docker://alpine:3.22\n", "external Docker action"),
        ("steps:\n  - \"uses\" : owner/repo\n", "repository@commit syntax"),
    ):
        try:
            validate_uses_text(bad, "self-test-bad.yml")
        except ValueError as exc:
            require(expected in str(exc), f"Action-pin self-test rejected input for the wrong reason: {exc}")
        else:
            fail(f"Action-pin self-test accepted forbidden reference: {bad.strip()}")


def main() -> int:
    try:
        for path in (DEPENDABOT, QUALITY, GOVERNANCE):
            require(path.is_file(), f"Dependabot governance input is missing: {path.relative_to(ROOT)}")

        self_test()
        validate_dependabot(DEPENDABOT.read_text(encoding="utf-8"))
        validate_all_workflow_pins()
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        print(
            "Dependabot governance validation passed: the canonical GitHub Actions update policy is locked; "
            "dependency updates remain individually reviewable; and every external action in every workflow "
            "is pinned to an immutable 40-character commit SHA."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
