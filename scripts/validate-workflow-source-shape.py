#!/usr/bin/env python3
"""Fail closed on workflow YAML source forms outside the reviewed parser subset.

Several repository governance validators intentionally inspect workflow source without a
third-party YAML dependency. Their security argument therefore depends on workflows using
one canonical block-style YAML subset. This gate closes that precondition before the
specialized authority, shell-safety, and Action-identity scanners run.

Shell block-scalar bodies are opaque here because their contents are shell/program text,
not YAML structure. The only reviewed flow collection is a simple ``needs: [job, ...]``
sequence; flow mappings and every other flow sequence remain forbidden. Every structural
mapping scope must also use unique keys so source scanners and GitHub's YAML loader can
never disagree through duplicate-key/last-value-wins semantics.

Interpreter and workflow-call semantics are part of the same source contract. Every job
must remain an ordinary GitHub-hosted ``ubuntu-24.04`` job using the reviewed implicit
Linux shell semantics. Workflow/job ``defaults`` shell substitution, step-level ``shell``
overrides, job containers, and job-level reusable-workflow ``uses``/``with``/``secrets``
authority are rejected unless a future policy explicitly models them.
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
AUTHORITY_IDENTITY_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):(?:\s*(?:#.*)?)$")
PLAIN_MAPPING_KEY = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.-]+)\s*:(?:\s.*)?$"
)
SEQUENCE_MAPPING_KEY = re.compile(
    r"^(?P<indent> *)-\s+(?P<key>[A-Za-z0-9_.-]+)\s*:(?:\s.*)?$"
)
SEQUENCE_ITEM = re.compile(r"^(?P<indent> *)-\s+.*$")

REVIEWED_RUNNER = "ubuntu-24.04"
JOB_CALL_AUTHORITY_KEYS = {"uses", "with", "secrets"}


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


def reject_duplicate_authority_identities(text: str, label: str, parent: str) -> None:
    """Reject duplicate trigger/job keys before set-based authority parsing can collapse them."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"{parent}:"]
    if len(starts) != 1:
        return
    seen: set[str] = set()
    for index in range(starts[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = indentation(line)
        if indent == 0:
            break
        if indent != 2:
            continue
        match = AUTHORITY_IDENTITY_KEY.fullmatch(line)
        if not match:
            continue
        identity = match.group(1)
        require(
            identity not in seen,
            f"{label}:{index + 1}: duplicate {parent} authority identity is forbidden: {identity}",
        )
        seen.add(identity)


def reject_duplicate_mapping_key(
    skeleton: str,
    label: str,
    line_number: int,
    stack: list[tuple[int, str]],
    seen: dict[tuple[tuple[str, ...], int], set[str]],
    sequence_serial: int,
) -> int:
    """Reject duplicate keys in every canonical mapping scope without evaluating YAML.

    Canonical source has no anchors, aliases, quoted keys, flow mappings, or structural
    block-scalar payload here. That lets indentation plus explicit sequence-item identity
    define an unambiguous lexical mapping scope. Sequence item IDs keep repeated keys such
    as ``name``/``uses`` in different steps independent while still detecting duplicate
    keys inside one step.
    """
    sequence_mapping = SEQUENCE_MAPPING_KEY.fullmatch(skeleton)
    sequence_item = SEQUENCE_ITEM.fullmatch(skeleton)
    if sequence_mapping is not None or sequence_item is not None:
        dash_indent = len((sequence_mapping or sequence_item).group("indent"))
        while stack and stack[-1][0] >= dash_indent:
            stack.pop()
        sequence_serial += 1
        stack.append((dash_indent, f"@sequence-item-{sequence_serial}"))

        if sequence_mapping is None:
            return sequence_serial

        logical_indent = dash_indent + 2
        key = sequence_mapping.group("key")
    else:
        mapping = PLAIN_MAPPING_KEY.fullmatch(skeleton)
        if mapping is None:
            return sequence_serial
        logical_indent = len(mapping.group("indent"))
        while stack and stack[-1][0] >= logical_indent:
            stack.pop()
        key = mapping.group("key")

    parent = tuple(component for _, component in stack)
    scope = (parent, logical_indent)
    keys = seen.setdefault(scope, set())
    require(
        key not in keys,
        f"{label}:{line_number}: duplicate mapping key is forbidden in canonical workflow source: {key}",
    )
    keys.add(key)
    stack.append((logical_indent, key))
    return sequence_serial


def validate_execution_semantics(text: str, label: str) -> int:
    """Lock the workflow interpreter and job-call model without evaluating YAML."""
    lines = text.splitlines()
    block_indent: int | None = None
    in_jobs = False
    current_job: str | None = None
    current_runner_count = 0
    jobs = 0

    def finish_job() -> None:
        if current_job is None:
            return
        require(
            current_runner_count == 1,
            f"{label}: job {current_job} must define exactly one literal runs-on: {REVIEWED_RUNNER}",
        )

    for line_number, line in enumerate(lines, start=1):
        if block_indent is not None:
            if not line.strip() or indentation(line) > block_indent:
                continue
            block_indent = None

        if not line.strip() or line.lstrip().startswith("#"):
            continue

        skeleton = structural_skeleton(line)
        stripped = skeleton.strip()
        if not stripped:
            continue

        mapping = PLAIN_MAPPING_KEY.fullmatch(skeleton)
        sequence_mapping = SEQUENCE_MAPPING_KEY.fullmatch(skeleton)
        if mapping is None and sequence_mapping is None:
            if BLOCK_HEADER.search(skeleton):
                block_indent = indentation(line)
            continue

        if sequence_mapping is not None:
            logical_indent = len(sequence_mapping.group("indent")) + 2
            key = sequence_mapping.group("key")
        else:
            logical_indent = len(mapping.group("indent"))
            key = mapping.group("key")

        if logical_indent == 0 and key == "defaults":
            raise ValueError(
                f"{label}:{line_number}: workflow-level defaults are forbidden; reviewed run-shell semantics are implicit"
            )

        if logical_indent == 0:
            if key == "jobs":
                finish_job()
                in_jobs = True
                current_job = None
                current_runner_count = 0
            elif in_jobs:
                finish_job()
                in_jobs = False
                current_job = None
                current_runner_count = 0

        if not in_jobs:
            if BLOCK_HEADER.search(skeleton):
                block_indent = indentation(line)
            continue

        if logical_indent == 2:
            finish_job()
            current_job = key
            current_runner_count = 0
            jobs += 1
        elif current_job is not None and logical_indent == 4:
            if key == "runs-on":
                current_runner_count += 1
                require(
                    line.strip() == f"runs-on: {REVIEWED_RUNNER}",
                    f"{label}:{line_number}: job {current_job} must use literal runs-on: {REVIEWED_RUNNER}",
                )
                require(
                    current_runner_count == 1,
                    f"{label}:{line_number}: job {current_job} defines multiple runner authorities",
                )
            elif key in JOB_CALL_AUTHORITY_KEYS:
                raise ValueError(
                    f"{label}:{line_number}: job-level {key}: reusable-workflow call authority is forbidden"
                )
            elif key == "defaults":
                raise ValueError(
                    f"{label}:{line_number}: job-level defaults are forbidden; reviewed run-shell semantics are implicit"
                )
            elif key == "container":
                raise ValueError(
                    f"{label}:{line_number}: job containers are forbidden because they substitute runner/interpreter semantics"
                )
        elif current_job is not None and logical_indent == 8 and key == "shell":
            raise ValueError(
                f"{label}:{line_number}: explicit step shell overrides are forbidden; use the reviewed implicit Linux shell"
            )

        if BLOCK_HEADER.search(skeleton):
            block_indent = indentation(line)

    finish_job()
    require(jobs > 0, f"{label}: workflow contains no ordinary jobs")
    return jobs


def validate_text(text: str, label: str) -> int:
    lines = text.splitlines()
    block_indent: int | None = None
    structural_lines = 0
    mapping_stack: list[tuple[int, str]] = []
    seen_mapping_keys: dict[tuple[tuple[str, ...], int], set[str]] = {}
    sequence_serial = 0

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

        sequence_serial = reject_duplicate_mapping_key(
            skeleton,
            label,
            line_number,
            mapping_stack,
            seen_mapping_keys,
            sequence_serial,
        )

        if BLOCK_HEADER.search(skeleton):
            block_indent = indentation(line)

    require(structural_lines > 0, f"{label}: workflow source contains no structural YAML")
    # Keep these focused diagnostics in addition to generalized mapping-key uniqueness.
    reject_duplicate_authority_identities(text, label, "on")
    reject_duplicate_authority_identities(text, label, "jobs")
    validate_execution_semantics(text, label)
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
    safe = """name: Safe
on:
  pull_request:
permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-24.04
    steps:
      - name: Safe expression
        env:
          VALUE: ${{ github.ref }}
        run: |
          set -euo pipefail
          data='{"k":[1,2]}'
          [[ -n "$VALUE" ]]
      - run: echo safe
  merge:
    needs: [plan, approve]
    runs-on: ubuntu-24.04
    steps:
      - run: echo safe
"""
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
        (safe.replace("jobs:", '\"jobs\":'), "quoted mapping keys"),
        (safe.replace("jobs:", "? jobs\n:"), "complex mapping keys"),
        (safe.replace("  pull_request:\n", "  pull_request:\n  pull_request:\n"), "duplicate mapping key"),
        (safe.replace("  plan:\n", "  plan:\n  plan:\n", 1), "duplicate mapping key"),
        (safe.replace("permissions:\n  contents: read", "permissions:\n  contents: read\n  contents: write"), "duplicate mapping key"),
        (safe.replace("    runs-on: ubuntu-24.04\n    steps:", "    runs-on: ubuntu-24.04\n    runs-on: ubuntu-24.04\n    steps:", 1), "duplicate mapping key"),
        (safe.replace("          VALUE: ${{ github.ref }}", "          VALUE: ${{ github.ref }}\n          VALUE: fixed"), "duplicate mapping key"),
        (safe.replace("      - name: Safe expression", "      - name: Safe expression\n        name: Shadowed expression"), "duplicate mapping key"),
        (safe.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1), "must use literal runs-on: ubuntu-24.04"),
        ("defaults:\n  run:\n    shell: bash\n" + safe, "workflow-level defaults are forbidden"),
        (safe.replace("  plan:\n    runs-on:", "  plan:\n    defaults:\n      run:\n        shell: bash\n    runs-on:", 1), "job-level defaults are forbidden"),
        (safe.replace("      - run: echo safe", "      - run: echo safe\n        shell: python", 1), "explicit step shell overrides are forbidden"),
        (safe.replace("      - run: echo safe", "      - shell: python\n        run: echo safe", 1), "explicit step shell overrides are forbidden"),
        (safe.replace("    runs-on: ubuntu-24.04", "    container: alpine:3.20\n    runs-on: ubuntu-24.04", 1), "job containers are forbidden"),
        (safe.replace("    runs-on: ubuntu-24.04", "    uses: octo/repo/.github/workflows/reuse.yml@0123456789012345678901234567890123456789\n    runs-on: ubuntu-24.04", 1), "job-level uses: reusable-workflow call authority is forbidden"),
        (safe.replace("    runs-on: ubuntu-24.04", "    with:\n      mode: unsafe\n    runs-on: ubuntu-24.04", 1), "job-level with: reusable-workflow call authority is forbidden"),
        (safe.replace("    runs-on: ubuntu-24.04", "    secrets: inherit\n    runs-on: ubuntu-24.04", 1), "job-level secrets: reusable-workflow call authority is forbidden"),
    )
    for mutated, fragment in cases:
        expect_failure(mutated, fragment)

    # Repeated step keys in distinct sequence items are valid mapping scopes.
    repeated_step_keys = safe.replace(
        "      - run: echo safe\n  merge:",
        "      - name: second step\n        run: echo safe\n      - name: third step\n        run: echo safe\n  merge:",
        1,
    )
    validate_text(repeated_step_keys, "self-test-distinct-sequence-items.yml")


def main() -> int:
    try:
        self_test()
        require(QUALITY.is_file(), "Profile Quality workflow is missing")
        workflow_count, structural_lines = validate_inventory()
        validate_quality_binding(QUALITY.read_text(encoding="utf-8"))
        print(
            f"Workflow source-shape validation passed: {workflow_count} workflows · {structural_lines} structural lines · "
            "block-style canonical YAML enforced, every structural mapping scope uses unique keys, trigger/job authority identities are unique, "
            "flow mappings/structural aliases rejected, only reviewed simple needs sequences allowed, and every job remains an ordinary "
            f"{REVIEWED_RUNNER} job with reviewed implicit shell semantics and no reusable-workflow/secret-inheritance call authority."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
