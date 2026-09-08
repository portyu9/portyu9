#!/usr/bin/env python3
"""Fail closed on workflow YAML source forms outside the reviewed parser subset.

Several repository governance validators intentionally inspect workflow source without a
third-party YAML dependency. Their security argument therefore depends on workflows using
one canonical block-style YAML subset. This gate closes that precondition before the
specialized authority, shell-safety, and Action-identity scanners run.

Shell block-scalar bodies are opaque here because their contents are shell/program text,
not YAML structure. The only reviewed flow collection is a simple ``needs: [job, ...]``
sequence; flow mappings and every other flow sequence remain forbidden.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"

BLOCK_HEADER = re.compile(r":\s*[|>](?:[+-]?[1-9]?|[1-9][+-]?)?\s*$")
FLOW_NEEDS = re.compile(
    r"^\s*needs:\s*\[\s*[A-Za-z0-9_-]+(?:\s*,\s*[A-Za-z0-9_-]+)*\s*\]\s*$"
)
QUOTED_KEY = re.compile(r"^\s*(?:-\s*)?['\"][^'\"\n]+['\"]\s*:")
FORBIDDEN_TOKEN = re.compile(
    r"(?:^|[\s,:])(?:&[A-Za-z0-9_.-]+|\*[A-Za-z0-9_.-]+|!(?!=)[^\s]+|<<\s*:)"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def strip_expressions(line: str) -> str:
    """Blank same-line GitHub expressions so their braces are not YAML flow syntax."""
    chars = list(line)
    cursor = 0
    while True:
        start = line.find("${{", cursor)
        if start < 0:
            break
        end = line.find("}}", start + 3)
        require(end >= 0, "unterminated GitHub expression in workflow source")
        for index in range(start, end + 2):
            chars[index] = " "
        cursor = end + 2
    return "".join(chars)


def structural_skeleton(line: str) -> str:
    """Blank quoted scalar contents and comments while preserving YAML punctuation."""
    line = strip_expressions(line)
    result = list(line)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote == '"':
            result[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            result[index] = " "
            if char == "'":
                if index + 1 < len(line) and line[index + 1] == "'":
                    result[index + 1] = " "
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            result[index] = " "
            index += 1
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            for tail in range(index, len(line)):
                result[tail] = " "
            break
        index += 1
    require(quote is None, "unterminated quoted scalar in workflow source")
    return "".join(result).rstrip()


def validate_text(text: str, label: str) -> int:
    lines = text.splitlines()
    block_indent: int | None = None
    structural_lines = 0

    for line_number, line in enumerate(lines, start=1):
        if block_indent is not None:
            if not line.strip() or indentation(line) > block_indent:
                continue
            block_indent = None

        if not line.strip() or line.lstrip().startswith("#"):
            continue
        require("\t" not in line, f"{label}:{line_number}: tabs are forbidden in workflow YAML structure")
        require(
            QUOTED_KEY.match(line) is None,
            f"{label}:{line_number}: quoted mapping keys are outside the canonical workflow source subset",
        )

        skeleton = structural_skeleton(line)
        stripped = skeleton.strip()
        if not stripped:
            continue
        structural_lines += 1

        require(stripped not in {"---", "..."},
                f"{label}:{line_number}: YAML document markers are forbidden")
        require(not stripped.startswith("%"),
                f"{label}:{line_number}: YAML directives are forbidden")
        require(not stripped.startswith("? ") and stripped != "?",
                f"{label}:{line_number}: explicit complex mapping keys are forbidden")
        require(FORBIDDEN_TOKEN.search(skeleton) is None,
                f"{label}:{line_number}: YAML anchors, aliases, tags, or merge keys are forbidden")

        if "{" in skeleton or "}" in skeleton:
            raise ValueError(
                f"{label}:{line_number}: flow-style YAML mappings are forbidden; use canonical block mappings"
            )
        if "[" in skeleton or "]" in skeleton:
            require(
                FLOW_NEEDS.fullmatch(skeleton) is not None,
                f"{label}:{line_number}: flow-style YAML sequences are forbidden except simple needs: [job, ...]",
            )

        if BLOCK_HEADER.search(skeleton):
            block_indent = indentation(line)

    require(structural_lines > 0, f"{label}: workflow source contains no structural YAML")
    return structural_lines


def validate_inventory() -> tuple[int, int]:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(paths, "No workflow files found")
    count = sum(validate_text(path.read_text(encoding="utf-8"), path.name) for path in paths)
    return len(paths), count


def validate_quality_binding(text: str) -> None:
    require(
        "python3 scripts/validate-workflow-source-shape.py" in text,
        "Profile Quality must execute the workflow YAML source-shape gate",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover every workflow source-shape change",
    )


def expect_failure(text: str, fragment: str) -> None:
    try:
        validate_text(text, "self-test.yml")
    except ValueError as exc:
        require(fragment in str(exc), f"source-shape self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"source-shape self-test accepted forbidden YAML: {fragment}")


def self_test() -> None:
    safe = """name: Safe\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  plan:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Safe expression\n        env:\n          VALUE: ${{ github.ref }}\n        run: |\n          set -euo pipefail\n          data='{"k":[1,2]}'\n          [[ -n "$VALUE" ]]\n  merge:\n    needs: [plan, approve]\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n"""
    validate_text(safe, "self-test-safe.yml")

    cases = (
        (safe.replace("on:\n  pull_request:", "on: [pull_request, pull_request_target]"), "flow-style YAML sequences"),
        (safe.replace("jobs:\n  plan:", "jobs: {plan: {runs-on: ubuntu-24.04}}\nignored:"), "flow-style YAML mappings"),
        (safe.replace("    runs-on: ubuntu-24.04\n    steps:", "    permissions: {contents: write}\n    runs-on: ubuntu-24.04\n    steps:"), "flow-style YAML mappings"),
        (safe.replace("      - run: echo safe", "      - {run: echo unsafe}"), "flow-style YAML mappings"),
        (safe.replace("      - run: echo safe", "      - {uses: ./local-action}"), "flow-style YAML mappings"),
        (safe.replace("permissions:\n  contents: read", "permissions: &shared\n  contents: read"), "anchors, aliases"),
        (safe.replace("permissions:\n  contents: read", "permissions:\n  <<: *shared"), "anchors, aliases"),
        ("---\n" + safe, "document markers"),
        (safe.replace("jobs:", '"jobs":'), "quoted mapping keys"),
        (safe.replace("jobs:", "? jobs\n:"), "complex mapping keys"),
    )
    for mutated, fragment in cases:
        expect_failure(mutated, fragment)


def main() -> int:
    try:
        self_test()
        require(QUALITY.is_file(), "Profile Quality workflow is missing")
        workflow_count, structural_lines = validate_inventory()
        validate_quality_binding(QUALITY.read_text(encoding="utf-8"))
        print(
            f"Workflow source-shape validation passed: {workflow_count} workflows · {structural_lines} structural lines · "
            "block-style canonical YAML enforced, flow mappings/structural aliases rejected, and only reviewed simple needs sequences allowed."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
