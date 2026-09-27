#!/usr/bin/env python3
"""Fail closed on workflow YAML source forms outside the reviewed parser subset.

Several repository governance validators intentionally inspect workflow source without a
third-party YAML dependency. Their security argument therefore depends on workflows using
one canonical block-style YAML subset. This gate closes that precondition before the
specialized authority, shell-safety, and Action-identity scanners run.

Shell block-scalar bodies remain opaque to the YAML structural parser because their
contents are program text, not YAML structure. After structural validation, every literal
``run: |`` body is independently parsed as Bash without execution and scanned for
reviewed shell-source invariants. The only reviewed flow collection is a simple
``needs: [job, ...]``
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
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"

BLOCK_HEADER = re.compile(r":\s*[|>](?:[+-]?[1-9]?|[1-9][+-]?)?\s*$")
RUN_BLOCK_HEADER = re.compile(
    r"^(?P<indent> *)(?:-\s+)?run:\s*(?P<style>[|>])(?:[+-]?[1-9]?|[1-9][+-]?)?\s*$"
)
SIMPLE_HEREDOC_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
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
RAW_PLAIN_MAPPING = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.-]+)\s*:(?P<value>.*)$"
)
RAW_SEQUENCE_MAPPING = re.compile(
    r"^(?P<indent> *)-\s+(?P<key>[A-Za-z0-9_.-]+)\s*:(?P<value>.*)$"
)
ACTION_VERSION_COMMENT = re.compile(
    r"#\s+v[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9_.-]+)?$"
)

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


def reject_ambiguous_inline_comment(line: str, label: str, line_number: int) -> None:
    """Forbid structural inline comments that can truncate plain YAML scalars.

    A quote character encountered inside a YAML plain scalar does not start a quoted YAML
    scalar. GitHub therefore treats whitespace-plus-# inside expressions such as
    ``if: startsWith(..., 'Merge pull request #123 ...')`` as a YAML comment even though a
    naive lexical scanner may think the single quote protects it. Canonical workflow source
    permits inline comments only for the reviewed immutable Action version annotation form.
    Quoted scalar values and block-scalar program bodies remain unaffected.
    """
    sequence_mapping = RAW_SEQUENCE_MAPPING.fullmatch(line)
    mapping = sequence_mapping or RAW_PLAIN_MAPPING.fullmatch(line)
    if mapping is None:
        return

    key = mapping.group("key")
    value = mapping.group("value")
    stripped = value.lstrip()
    if not stripped or stripped[0] in {"|", ">"}:
        return

    if stripped[0] in {"'", '"'}:
        quote = stripped[0]
        index = 1
        while index < len(stripped):
            char = stripped[index]
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                if quote == "'" and index + 1 < len(stripped) and stripped[index + 1] == "'":
                    index += 2
                    continue
                tail = stripped[index + 1 :].strip()
                require(
                    not tail.startswith("#"),
                    f"{label}:{line_number}: structural inline YAML comments are forbidden after quoted scalars",
                )
                return
            index += 1
        raise ValueError(f"{label}:{line_number}: unterminated quoted scalar in workflow source")

    for index, char in enumerate(value):
        if char != "#" or index == 0 or not value[index - 1].isspace():
            continue
        comment = value[index:].strip()
        if key == "uses" and ACTION_VERSION_COMMENT.fullmatch(comment):
            return
        raise ValueError(
            f"{label}:{line_number}: plain-scalar inline YAML comments are forbidden; quote the complete scalar when # is data"
        )


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



def parse_simple_heredoc(
    line: str,
    index: int,
    label: str,
    line_number: int,
) -> tuple[str, bool, int]:
    """Parse the repository's reviewed simple here-document delimiter forms."""
    require(
        line.startswith("<<", index) and not line.startswith("<<<", index),
        f"{label}:{line_number}: invalid heredoc parser position",
    )
    cursor = index + 2
    strip_tabs = False
    if cursor < len(line) and line[cursor] == "-":
        strip_tabs = True
        cursor += 1
    while cursor < len(line) and line[cursor] in " \t":
        cursor += 1
    require(cursor < len(line), f"{label}:{line_number}: heredoc delimiter is missing")

    if line[cursor] in {"'", '"'}:
        quote = line[cursor]
        end = line.find(quote, cursor + 1)
        require(end >= 0, f"{label}:{line_number}: unterminated quoted heredoc delimiter")
        delimiter = line[cursor + 1 : end]
        cursor = end + 1
    else:
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[cursor:])
        require(
            match is not None,
            f"{label}:{line_number}: heredoc delimiter is outside the reviewed simple identifier form",
        )
        delimiter = match.group(0)
        cursor += len(delimiter)

    require(
        SIMPLE_HEREDOC_WORD.fullmatch(delimiter) is not None,
        f"{label}:{line_number}: heredoc delimiter is outside the reviewed simple identifier form",
    )
    return delimiter, strip_tabs, cursor


def reject_unquoted_escaped_newlines(script: str, label: str, start_line: int) -> None:
    """Reject literal backslash-n tokens in shell code unless they are quoted data.

    This closes the exact #1226 serialization class: a generated literal backslash-n
    between commands is valid Bash syntax because backslash escapes n, but silently joins
    command arguments instead of creating a command boundary. Quoted format/data strings
    retain their normal meaning. Simple heredoc payloads are data and are skipped until
    their reviewed delimiter.
    """
    quote: str | None = None
    heredocs: list[tuple[str, bool]] = []

    for offset, line in enumerate(script.splitlines(), start=0):
        line_number = start_line + offset
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == delimiter:
                heredocs.pop(0)
            continue

        cursor = 0
        while cursor < len(line):
            char = line[cursor]

            if quote == "'":
                if char == "'":
                    quote = None
                cursor += 1
                continue

            if quote == '"':
                if char == "\\" and cursor + 1 < len(line):
                    cursor += 2
                    continue
                if char == '"':
                    quote = None
                cursor += 1
                continue

            if char in {"'", '"'}:
                quote = char
                cursor += 1
                continue

            if char == "#" and (cursor == 0 or line[cursor - 1].isspace()):
                break

            if line.startswith("<<<", cursor):
                cursor += 3
                continue

            if line.startswith("<<", cursor):
                delimiter, strip_tabs, cursor = parse_simple_heredoc(
                    line, cursor, label, line_number
                )
                heredocs.append((delimiter, strip_tabs))
                continue

            if char == "\\":
                if cursor + 1 < len(line) and line[cursor + 1] == "n":
                    raise ValueError(
                        f"{label}:{line_number}: unquoted escaped-newline token \\\\n is forbidden in run shell source; "
                        "use an actual YAML block newline for command separation or quote \\\\n when it is data"
                    )
                cursor += 2 if cursor + 1 < len(line) else 1
                continue

            cursor += 1


def validate_shell_program(script: str, label: str, start_line: int) -> None:
    """Parse a run block as Bash without executing candidate-controlled commands."""
    result = subprocess.run(
        ["bash", "-n"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"{label}:{start_line}: Bash syntax validation failed for run block: "
        f"{result.stderr.strip()[:400]}",
    )
    reject_unquoted_escaped_newlines(script, label, start_line + 1)


def validate_shell_run_blocks(text: str, label: str) -> int:
    """Validate each YAML run block as the reviewed implicit Bash program."""
    lines = text.splitlines()
    index = 0
    run_blocks = 0

    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue

        skeleton = structural_skeleton(line)
        if BLOCK_HEADER.search(skeleton) is None:
            index += 1
            continue

        header_indent = indentation(line)
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and indentation(candidate) <= header_indent:
                break
            end += 1

        run_header = RUN_BLOCK_HEADER.fullmatch(skeleton)
        if run_header is not None:
            require(
                run_header.group("style") == "|",
                f"{label}:{index + 1}: folded run blocks are forbidden; shell programs require literal run: | source",
            )
            payload = lines[index + 1 : end]
            body_indents = [indentation(item) for item in payload if item.strip()]
            require(body_indents, f"{label}:{index + 1}: run block must not be empty")
            body_indent = min(body_indents)
            require(
                body_indent > header_indent,
                f"{label}:{index + 1}: run block body must be indented beneath run: |",
            )
            body = "\n".join(
                "" if not item.strip() else item[body_indent:] for item in payload
            ) + "\n"
            validate_shell_program(body, label, index + 1)
            run_blocks += 1

        index = end

    return run_blocks


def validate_execution_semantics(text: str, label: str) -> int:
    """Lock the workflow interpreter and job-call model without evaluating YAML."""
    lines = text.splitlines()
    block_indent: int | None = None
    in_jobs = False
    current_job: str | None = None
    current_runner_count = 0
    jobs = 0
    steps_indent: int | None = None

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
                steps_indent = None
            elif in_jobs:
                finish_job()
                in_jobs = False
                current_job = None
                current_runner_count = 0
                steps_indent = None

        if not in_jobs:
            if BLOCK_HEADER.search(skeleton):
                block_indent = indentation(line)
            continue

        if steps_indent is not None:
            physical_indent = indentation(line)
            if physical_indent <= steps_indent:
                steps_indent = None
            elif sequence_mapping is not None:
                dash_indent = len(sequence_mapping.group("indent"))
                require(
                    dash_indent == steps_indent + 2,
                    f"{label}:{line_number}: workflow steps must use canonical sequence indentation",
                )

        if logical_indent == 2:
            finish_job()
            current_job = key
            current_runner_count = 0
            steps_indent = None
            jobs += 1
        elif current_job is not None and logical_indent == 4:
            if key == "steps":
                steps_indent = logical_indent
            elif key == "runs-on":
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
        reject_ambiguous_inline_comment(line, label, line_number)

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
    validate_shell_run_blocks(text, label)
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
      - uses: actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
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

    quoted_newline_data = safe.replace(
        "          data='{\"k\":[1,2]}'",
        "          printf '%s\\n' safe\n          data=$'one\\ntwo'\n          value=\"quoted\\nvalue\"",
        1,
    )
    validate_text(quoted_newline_data, "self-test-quoted-newline-data.yml")

    heredoc_data = safe.replace(
        "          [[ -n \"$VALUE\" ]]",
        "          cat <<'EOF'\n          literal \\n payload\n          EOF\n          [[ -n \"$VALUE\" ]]",
        1,
    )
    validate_text(heredoc_data, "self-test-heredoc-data.yml")

    quoted_hash = safe.replace(
        "  plan:\n    runs-on: ubuntu-24.04",
        "  plan:\n    if: \"${{ always() && startsWith(github.event.pull_request.title, 'Fix #687') }}\"\n    runs-on: ubuntu-24.04",
        1,
    )
    validate_text(quoted_hash, "self-test-quoted-hash.yml")

    cases = (
        (
            safe.replace(
                '          [[ -n "$VALUE" ]]',
                '          [[ -n "$VALUE" ]]\\n          test -n "$VALUE"',
                1,
            ),
            "unquoted escaped-newline token",
        ),
        (safe.replace("        run: |", "        run: >", 1), "folded run blocks are forbidden"),
        (safe.replace("          set -euo pipefail", "          if true; then", 1), "Bash syntax validation failed"),
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
        (
            safe.replace(
                "  plan:\n    runs-on: ubuntu-24.04",
                "  plan:\n    if: always() && (github.event_name == 'push' && startsWith(github.event.head_commit.message, 'Merge pull request #685 from portyu9/recover-ruleset-receipt-attestation'))\n    runs-on: ubuntu-24.04",
                1,
            ),
            "plain-scalar inline YAML comments are forbidden",
        ),
        (safe.replace("name: Safe", "name: Safe # truncated"), "plain-scalar inline YAML comments are forbidden"),
        (safe.replace("          VALUE: ${{ github.ref }}", "          VALUE: literal # truncated"), "plain-scalar inline YAML comments are forbidden"),
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
        (safe.replace("      - run: echo safe", "        - shell: python\n          run: echo safe", 1), "canonical sequence indentation"),
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
            "block-style canonical YAML enforced, structural plain-scalar inline comments rejected except immutable Action version annotations, "
            "every structural mapping scope uses unique keys, trigger/job authority identities are unique, flow mappings/structural aliases "
            "rejected, only reviewed simple needs sequences allowed, and every job remains an ordinary "
            f"{REVIEWED_RUNNER} job with reviewed implicit shell semantics and no reusable-workflow/secret-inheritance call authority; "
            "literal run blocks are Bash-syntax parsed and reject unquoted escaped-newline command separators."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
