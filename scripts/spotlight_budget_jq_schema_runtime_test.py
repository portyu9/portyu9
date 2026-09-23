#!/usr/bin/env python3
"""Execute the exact Spotlight mutation-budget jq schema against runtime fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/spotlight-link-sync.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    try:
        spotlight = WORKFLOW.read_text(encoding="utf-8")
        require(spotlight.count("  budget:\n") == 1, "Spotlight budget job anchor is missing or ambiguous")
        require(spotlight.count("  quarantine:\n") == 1, "Spotlight quarantine job anchor is missing or ambiguous")
        start = spotlight.index("  budget:\n")
        end = spotlight.index("  quarantine:\n", start)
        budget = spotlight[start:end]

        schema_marker = 'jq -e --arg name "$ARTIFACT_NAME" --arg base "$BASE_SHA" --argjson repo "$GITHUB_REPOSITORY_ID"'
        program_open = "\n            '\n"
        program_close = "\n          ' <<<\"$ARTIFACTS\" >/dev/null || {"
        require(budget.count(schema_marker) == 1, "Spotlight jq schema marker is missing or ambiguous")
        schema_start = budget.index(schema_marker)
        require(budget.count(program_close) == 1, "Spotlight jq schema close marker is missing or ambiguous")
        program_start = budget.index(program_open, schema_start) + len(program_open)
        program_end = budget.index(program_close, program_start)
        jq_program = budget[program_start:program_end]
        require(jq_program.strip(), "Spotlight jq schema program is empty")

        base = "a" * 40
        generated = "b" * 40
        artifact_name = f"spotlight-link-plan-{base}-{generated}"
        repo_id = 424242
        valid = {
            "total_count": 2,
            "artifacts": [
                {
                    "id": 101,
                    "name": artifact_name,
                    "expired": False,
                    "workflow_run": {
                        "id": 1001,
                        "repository_id": repo_id,
                        "head_repository_id": repo_id,
                        "head_branch": "main",
                        "head_sha": base,
                    },
                },
                {
                    "id": 102,
                    "name": artifact_name,
                    "expired": False,
                    "workflow_run": {
                        "id": 1002,
                        "repository_id": repo_id,
                        "head_repository_id": repo_id,
                        "head_branch": "main",
                        "head_sha": base,
                    },
                },
            ],
        }

        def execute(payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "jq", "-e",
                    "--arg", "name", artifact_name,
                    "--arg", "base", base,
                    "--argjson", "repo", str(repo_id),
                    jq_program,
                ],
                input=json.dumps(payload, separators=(",", ":")),
                text=True,
                capture_output=True,
                check=False,
            )

        accepted = execute(valid)
        require(
            accepted.returncode == 0 and accepted.stdout.strip() == "true",
            "Spotlight mutation-budget jq schema must compile and accept the valid fixture; "
            f"rc={accepted.returncode}, stdout={accepted.stdout.strip()!r}, stderr={accepted.stderr.strip()!r}",
        )

        invalid_fixtures: list[tuple[str, dict[str, object]]] = []

        mismatched_count = json.loads(json.dumps(valid))
        mismatched_count["total_count"] = 1
        invalid_fixtures.append(("mismatched total_count", mismatched_count))

        duplicate_id = json.loads(json.dumps(valid))
        duplicate_id["artifacts"][1]["id"] = duplicate_id["artifacts"][0]["id"]
        invalid_fixtures.append(("duplicate artifact id", duplicate_id))

        wrong_head = json.loads(json.dumps(valid))
        wrong_head["artifacts"][0]["workflow_run"]["head_sha"] = "c" * 40
        invalid_fixtures.append(("wrong nested head sha", wrong_head))

        for label, payload in invalid_fixtures:
            rejected = execute(payload)
            require(
                rejected.returncode == 1,
                f"Spotlight mutation-budget jq schema must reject {label} with predicate failure; "
                f"rc={rejected.returncode}, stdout={rejected.stdout.strip()!r}, stderr={rejected.stderr.strip()!r}",
            )

        print(
            "Spotlight mutation-budget jq runtime fixtures passed: "
            "exact embedded filter compiled; 1 valid fixture accepted; 3 adversarial fixtures rejected."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
