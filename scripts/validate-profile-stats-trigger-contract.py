#!/usr/bin/env python3
"""Fail closed when production profile refresh triggers or source refs exceed the reviewed boundary."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/profile-stats.yml"
CADENCE = ROOT / ".github/REFRESH_CADENCE.md"
MAIN_REF_GUARD = "if: github.ref == 'refs/heads/main'"
REVIEW_SENTINELS = (
    "scripts/set-signal-field-refresh-cadence.py",
    "scripts/signal_field_pipeline.py",
    "scripts/signal-field-pipeline-v1.json",
    "scripts/profile-evidence-subjects-v1.json",
    "scripts/profile_evidence_subjects.py",
    "scripts/stage-profile-evidence.py",
    "scripts/validate-profile-evidence-subjects.py",
)
EXPECTED_PATHS = (
    ".github/workflows/profile-stats.yml",
    ".github/ATTESTATION.md",
    ".github/attestation/**",
    "scripts/**",
    *REVIEW_SENTINELS,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def push_paths(workflow: str) -> tuple[str, ...]:
    lines = workflow.splitlines()
    push_index = next((i for i, line in enumerate(lines) if line == "  push:"), None)
    require(push_index is not None, "profile-stats push trigger is missing")
    paths_index = next(
        (i for i in range(push_index + 1, len(lines)) if lines[i] == "    paths:"),
        None,
    )
    require(paths_index is not None, "profile-stats push paths block is missing")
    collected: list[str] = []
    for line in lines[paths_index + 1 :]:
        if line.startswith("      - "):
            value = line[len("      - ") :].strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            collected.append(value)
            continue
        break
    require(collected, "profile-stats push paths block is empty")
    return tuple(collected)


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    require(start is not None, f"profile-stats job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", workflow[start.end():])
    require(end is not None, f"profile-stats job boundary is missing: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def main() -> int:
    try:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cadence = CADENCE.read_text(encoding="utf-8")
        paths = push_paths(workflow)
        require(paths == EXPECTED_PATHS, f"profile-stats push paths must be the exact closed trigger set: {EXPECTED_PATHS!r}; got {paths!r}")
        script_paths = tuple(path for path in paths if path.startswith("scripts/"))
        require(script_paths[0] == "scripts/**", "scripts/** must be the first and authoritative script trigger")
        require(script_paths[1:] == REVIEW_SENTINELS, "only reviewed legacy/subject contract sentinels may accompany the scripts/** umbrella")

        require("  workflow_dispatch:" in workflow, "manual main refresh path must remain available")
        require("  push:\n    branches:\n      - main\n" in workflow, "push-triggered production refresh must remain restricted to main")
        require("pull_request:" not in workflow, "production refresh workflow must never run from pull_request events")
        generate = job_block(workflow, "generate", "attest")
        require(MAIN_REF_GUARD in generate, "production generation must be guarded to refs/heads/main")
        require(workflow.count(MAIN_REF_GUARD) == 1, "main source-ref guard must exist exactly once at the generation authority boundary")
        require("needs: generate" in job_block(workflow, "attest", "publish"), "attestation must remain downstream of main-guarded generation")
        require("needs: [generate, attest]" in job_block(workflow, "publish", None), "publication must remain downstream of main-guarded generation and attestation")

        require("scripts/**" in cadence, "refresh cadence rationale must document the trusted scripts/** trigger surface")
        require(
            "new production source modules cannot silently fall outside the immediate push-triggered refresh path" in cadence,
            "refresh cadence rationale must state the source-closure property",
        )
        print(
            "Profile stats trigger contract passed: scripts/** closes the trusted production source surface; "
            "pushes are main-only, manual dispatch remains available but generation is gated to refs/heads/main, "
            "and attestation/publication stay downstream of that source-ref guard."
        )
        return 0
    except (OSError, ValueError, StopIteration, IndexError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
