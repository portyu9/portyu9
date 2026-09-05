#!/usr/bin/env python3
"""Fail closed when production profile refresh push triggers can miss trusted script changes."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/profile-stats.yml"
CADENCE = ROOT / ".github/REFRESH_CADENCE.md"
SUBJECT_SENTINELS = (
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
    *SUBJECT_SENTINELS,
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


def main() -> int:
    try:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cadence = CADENCE.read_text(encoding="utf-8")
        paths = push_paths(workflow)
        require(paths == EXPECTED_PATHS, f"profile-stats push paths must be the exact closed trigger set: {EXPECTED_PATHS!r}; got {paths!r}")
        script_paths = tuple(path for path in paths if path.startswith("scripts/"))
        require(script_paths[0] == "scripts/**", "scripts/** must be the first and authoritative script trigger")
        require(script_paths[1:] == SUBJECT_SENTINELS, "only reviewed subject-contract sentinels may accompany the scripts/** umbrella")
        require("scripts/**" in cadence, "refresh cadence rationale must document the trusted scripts/** trigger surface")
        require(
            "new production source modules cannot silently fall outside the immediate push-triggered refresh path" in cadence,
            "refresh cadence rationale must state the source-closure property",
        )
        print(
            "Profile stats trigger contract passed: scripts/** closes the trusted production source surface; "
            "four explicit subject-contract paths remain review sentinels, not coverage dependencies."
        )
        return 0
    except (OSError, ValueError, StopIteration, IndexError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
