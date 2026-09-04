#!/usr/bin/env python3
"""Fail closed on GitHub expression interpolation inside workflow shell source.

GitHub evaluates ${{ ... }} expressions before a `run:` script reaches the shell. If
attacker-controlled event data is interpolated directly into shell source, characters in
that data can become shell syntax. This validator requires dynamic values to cross a
non-shell boundary such as `env:`, `with:`, or `if:` instead.

The scanner intentionally accepts only canonical plain single-line run scalars or
literal/folded block scalars. YAML aliases, anchors, tags, or quoted whole-command
scalars are rejected for `run:` because they can obscure the bytes that will become
shell source and make a dependency-free source validator ambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"

EXPRESSION = "${{"
RUN_KEY = re.compile(
    r"^(?P<indent>\s*)(?P<item>-\s+)?(?:run|'run'|\"run\")\s*:\s*(?P<value>.*)$"
)
BLOCK_HEADER = re.compile(r"^[|>](?:[+-]?[1-9]?|[1-9][+-]?)?\s*(?:#.*)?$")
FORBIDDEN_NODE_PREFIXES = ("&", "*", "!", "'", '"', "[", "{")


@dataclass(frozen=True)
class RunBlock:
    line: int
    source: str


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def extract_run_blocks(text: str, label: str) -> list[RunBlock]:
    """Extract canonical run scalars without evaluating YAML or GitHub expressions."""
    lines = text.splitlines()
    blocks: list[RunBlock] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = RUN_KEY.match(line)
        if not match:
            index += 1
            continue

        indent = len(match.group("indent")) + len(match.group("item") or "")
        value = match.group("value").strip()
        require(value, f"{label}:{index + 1}: empty run scalar is forbidden")
        require(
            not value.startswith(FORBIDDEN_NODE_PREFIXES),
            f"{label}:{index + 1}: run must not use YAML aliases, anchors, tags, or a quoted whole-command scalar",
        )

        if value.startswith(("|", ">")):
            require(
                BLOCK_HEADER.fullmatch(value) is not None,
                f"{label}:{index + 1}: non-canonical run block header is forbidden: {value}",
            )
            payload: list[str] = []
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if not candidate.strip():
                    payload.append(candidate)
                    cursor += 1
                    continue
                if indentation(candidate) <= indent:
                    break
                payload.append(candidate)
                cursor += 1
            require(payload, f"{label}:{index + 1}: run block has no shell body")
            blocks.append(RunBlock(index + 1, "\n".join(payload)))
            index = cursor
            continue

        blocks.append(RunBlock(index + 1, value))
        index += 1

    return blocks


def validate_text(text: str, label: str) -> int:
    blocks = extract_run_blocks(text, label)
    for block in blocks:
        require(
            EXPRESSION not in block.source,
            f"{label}:{block.line}: GitHub expression interpolation is forbidden inside run shell source; pass dynamic data through env:/with:/if: instead",
        )
    return len(blocks)


def validate_inventory() -> tuple[int, int]:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(paths, "No workflow files found")
    run_blocks = sum(validate_text(path.read_text(encoding="utf-8"), path.name) for path in paths)
    return len(paths), run_blocks


def validate_quality_binding(text: str) -> None:
    require(
        "python3 scripts/validate-workflow-shell-safety.py" in text,
        "Profile Quality must execute the workflow shell-safety validator",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover every workflow shell-safety change",
    )


def expect_failure(text: str, fragment: str) -> None:
    try:
        validate_text(text, "self-test.yml")
    except ValueError as exc:
        require(fragment in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden run syntax: {fragment}")


def self_test() -> None:
    safe = """name: Safe\non:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        if: ${{ github.event_name == 'pull_request' }}\n        run: |\n          set -euo pipefail\n          printf '%s\\n' \"$TITLE\"\n      - run: python3 scripts/check.py --self-test\n"""
    require(validate_text(safe, "self-test.yml") == 2, "safe env-boundary fixture was not fully scanned")

    cases = (
        (safe.replace('run: python3 scripts/check.py --self-test', 'run: echo "${{ github.event.pull_request.title }}"'), "expression interpolation"),
        (safe.replace('printf \'%s\\n\' \"$TITLE\"', 'printf \'%s\\n\' "${{ github.head_ref }}"'), "expression interpolation"),
        (safe.replace('run: |\n          set -euo pipefail', 'run: >-\n          echo "${{ matrix.command }}"'), "expression interpolation"),
        (safe.replace('run: python3 scripts/check.py --self-test', 'run : echo "${{ github.event.issue.title }}" # payload may contain $(id)'), "expression interpolation"),
        (safe.replace('run: python3 scripts/check.py --self-test', '\"run\": echo "${{ github.event.comment.body }}"'), "expression interpolation"),
        (safe.replace('run: python3 scripts/check.py --self-test', 'run: *shared_script'), "aliases, anchors"),
        (safe.replace('run: python3 scripts/check.py --self-test', 'run: &shared |\n          echo safe'), "aliases, anchors"),
        (safe.replace('run: python3 scripts/check.py --self-test', 'run: \"python3 scripts/check.py --self-test\"'), "quoted whole-command"),
    )
    for text, fragment in cases:
        expect_failure(text, fragment)

    shorthand_block = """jobs:\n  test:\n    steps:\n      - run: |\n          echo \"${{ github.event.pull_request.title }}\"\n        shell: bash\n"""
    expect_failure(shorthand_block, "expression interpolation")

    heredoc = """jobs:\n  test:\n    steps:\n      - run: |\n          cat <<'EOF'\n          ${{ github.event.pull_request.body }}\n          EOF\n"""
    expect_failure(heredoc, "expression interpolation")


def main() -> int:
    try:
        self_test()
        require(QUALITY.is_file(), "Profile Quality workflow is missing")
        workflow_count, run_count = validate_inventory()
        validate_quality_binding(QUALITY.read_text(encoding="utf-8"))
        print(
            f"Workflow shell-safety validation passed: scanned {run_count} run blocks across {workflow_count} workflows; "
            "GitHub expressions remain outside shell source and dynamic data crosses explicit non-shell boundaries."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
