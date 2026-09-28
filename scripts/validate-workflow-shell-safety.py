#!/usr/bin/env python3
"""Extend the frozen workflow shell-safety scanner with item-11 ADR signers."""
from __future__ import annotations

import sys

import workflow_shell_safety_item10_core as core


ITEM11_PRIVILEGED_JOBS = {
    "profile-stats.yml": ("publish", "dispatch", "decision_receipt_attest"),
    "spotlight-link-sync.yml": (
        "reconcile", "propose", "approve", "authorize_attest", "merge", "decision_receipt_attest"
    ),
}
EXACT_COMPRESSED_ATTESTATION_VERIFY = (
    'gh attestation verify "$SUBJECT" --repo "$GITHUB_REPOSITORY" '
    '--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/'
    'spotlight-merge-authorization-v1.schema.json '
    '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml" '
    '--signer-digest "$BASE_SHA" --source-digest "$BASE_SHA" --source-ref refs/heads/main '
    '--deny-self-hosted-runners --format json > verified-merge-authorization.json'
)
FROZEN_SELF_TEST_VERIFY_HEAD = 'gh attestation verify "$SUBJECT" \\'
ORIGINAL_SELF_TEST = core.self_test



def shell_comment_start(line: str, index: int) -> bool:
    """Return whether # is unambiguously a Bash comment at this lexical position."""
    if index == 0:
        return True

    previous = line[index - 1]
    if previous.isspace():
        backslashes = 0
        cursor = index - 2
        while cursor >= 0 and line[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        return backslashes % 2 == 0

    # Deliberately exclude ')' from the unambiguous boundary set: it may close
    # $(...) or $((...)) inside the current shell word, where an adjacent # is
    # data rather than a comment. Top-level comments after ')' should use
    # ordinary separating whitespace so this guard never truncates word data.
    if previous not in ";&|(<>":
        return False

    backslashes = 0
    cursor = index - 2
    while cursor >= 0 and line[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 0



def shell_reserved_word_at(line: str, index: int, word: str) -> bool:
    """Return whether word is a shell token at this lexical position."""
    if not line.startswith(word, index):
        return False
    before = line[index - 1] if index > 0 else ""
    end = index + len(word)
    after = line[end] if end < len(line) else ""
    before_ok = index == 0 or before.isspace() or before in ";&|()<>"
    after_ok = end == len(line) or after.isspace() or after in ";&|()<>"
    return before_ok and after_ok



def normalized_shell_lines(source: str) -> list[str]:
    """Project YAML block indentation away before shell lexical analysis."""
    lines = source.splitlines()
    indents = [core.indentation(line) for line in lines if line.strip()]
    if not indents:
        return lines
    base_indent = min(indents)
    return [line[base_indent:] if line.strip() else "" for line in lines]


def parse_heredoc_delimiter(line: str, cursor: int, label: str) -> tuple[str, int, bool]:
    """Parse a closed heredoc delimiter and report whether quote removal makes its body inert."""
    result: list[str] = []
    quoted = False
    while cursor < len(line) and line[cursor] not in " \t;&|()<>":
        char = line[cursor]
        if char in {"$", "`"}:
            raise ValueError(
                f"{label}: unsupported heredoc delimiter syntax; use a literal, quoted, "
                "or backslash-quoted delimiter"
            )
        if char == "\\":
            if cursor + 1 >= len(line):
                raise ValueError(f"{label}: trailing backslash in heredoc delimiter")
            quoted = True
            result.append(line[cursor + 1])
            cursor += 2
            continue
        if char in {"'", '"'}:
            quoted = True
            quote = char
            cursor += 1
            while cursor < len(line) and line[cursor] != quote:
                if quote == '"' and line[cursor] == "\\" and cursor + 1 < len(line):
                    escaped = line[cursor + 1]
                    if escaped in {"$", "`", '"', "\\"}:
                        result.append(escaped)
                    else:
                        result.extend(("\\", escaped))
                    cursor += 2
                    continue
                result.append(line[cursor])
                cursor += 1
            if cursor >= len(line):
                raise ValueError(f"{label}: unterminated quote in heredoc delimiter")
            cursor += 1
            continue
        result.append(char)
        cursor += 1
    delimiter = "".join(result)
    if not delimiter:
        raise ValueError(f"{label}: empty or unsupported heredoc delimiter")
    return delimiter, cursor, quoted



def skip_parameter_expansion(
    line: str,
    cursor: int,
    label: str,
    line_number: int,
) -> int:
    """Skip a same-line ${...} expansion without letting its data syntax poison shell context."""
    depth = 1
    inner_quote: str | None = None
    index = cursor + 2
    while index < len(line):
        char = line[index]
        if inner_quote == "ansi_single":
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if char == "'":
                inner_quote = None
            index += 1
            continue

        if inner_quote == "'":
            if char == "'":
                inner_quote = None
            index += 1
            continue
        if inner_quote == '"':
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if line.startswith("$(", index):
                raise ValueError(
                    f"{label}:{line_number}: command substitution inside a parameter expansion is unsupported "
                    "by the shell-source guard"
                )
            if char == "`":
                raise ValueError(
                    f"{label}:{line_number}: legacy backtick substitution is unsupported by the "
                    "shell-source guard"
                )
            if char == '"':
                inner_quote = None
            index += 1
            continue
        if char == "\\" and index + 1 < len(line):
            if line[index + 1] == "n":
                raise ValueError(
                    f"{label}:{line_number}: unquoted literal \\n inside a parameter expansion is "
                    "unsupported by the shell-source guard"
                )
            index += 2
            continue
        if line.startswith(("<(", ">("), index):
            raise ValueError(
                f"{label}:{line_number}: process substitution inside a parameter expansion is unsupported "
                "by the shell-source guard"
            )
        if line.startswith("$'", index):
            inner_quote = "ansi_single"
            index += 2
            continue
        if char in {"'", '"'}:
            inner_quote = char
            index += 1
            continue
        if line.startswith("$(", index):
            raise ValueError(
                f"{label}:{line_number}: command substitution inside a parameter expansion is unsupported "
                "by the shell-source guard"
            )
        if char == "`":
            raise ValueError(
                f"{label}:{line_number}: legacy backtick substitution is unsupported by the "
                "shell-source guard"
            )
        if line.startswith("${", index):
            depth += 1
            index += 2
            continue
        if char == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return index
            continue
        index += 1
    raise ValueError(
        f"{label}:{line_number}: multiline or unterminated parameter expansion is unsupported "
        "by the shell-source guard"
    )


def reject_serialized_command_separator(source: str, label: str) -> None:
    """Reject escaped newline text that is acting as a serialized physical command break.

    The #1226 incident embedded the characters backslash+n plus the original YAML body
    indentation between two intended shell commands. Any unquoted backslash+n is rejected:
    Bash consumes that backslash rather than producing newline data, so it is both unnecessary
    for legitimate newline data and unsafe as serialized source. Quoted data escapes and
    payloads with quoted heredoc delimiters remain valid. Unquoted heredocs are rejected
    because Bash expands command/arithmetic/parameter substitutions in their bodies. Command
    substitutions suspend an enclosing double-quote context and restore it only after
    their balanced closing parenthesis so nested quotes cannot poison later scanning.
    """
    quote: str | None = None
    heredocs: list[tuple[str, bool]] = []
    arithmetic_depth = 0
    arithmetic_resume_quote: str | None = None
    command_depths: list[int] = []
    command_resume_quotes: list[str | None] = []

    for line_number, line in enumerate(normalized_shell_lines(source), start=1):
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate == delimiter:
                heredocs.pop(0)
            continue

        discovered_heredocs: list[tuple[str, bool]] = []
        index = 0
        while index < len(line):
            char = line[index]

            if quote == "ansi_single":
                if char == "\\" and index + 1 < len(line):
                    index += 2
                    continue
                if char == "'":
                    quote = None
                index += 1
                continue

            if quote == "'":
                if char == "'":
                    quote = None
                index += 1
                continue

            if quote == '"':
                if char == "\\" and index + 1 < len(line):
                    index += 2
                    continue
                if line.startswith("${", index):
                    index = skip_parameter_expansion(
                        line,
                        index,
                        label,
                        line_number,
                    )
                    continue
                if line.startswith("$((", index):
                    arithmetic_depth = 1
                    arithmetic_resume_quote = '"'
                    quote = None
                    index += 3
                    continue
                if line.startswith("$(", index):
                    command_depths.append(1)
                    command_resume_quotes.append('"')
                    quote = None
                    index += 2
                    continue
                if char == "`":
                    raise ValueError(
                        f"{label}:{line_number}: legacy backtick command substitution is unsupported; "
                        "use $(...) so lexical command boundaries remain explicit"
                    )
                if char == '"':
                    quote = None
                index += 1
                continue

            if line.startswith("${", index):
                index = skip_parameter_expansion(
                    line,
                    index,
                    label,
                    line_number,
                )
                continue

            if (
                command_depths
                and arithmetic_depth == 0
                and shell_reserved_word_at(line, index, "case")
            ):
                raise ValueError(
                    f"{label}:{line_number}: case statements inside command substitution are "
                    "unsupported by the shell-source guard because case-pattern ')' tokens are "
                    "not balanced command-substitution delimiters"
                )

            if arithmetic_depth == 0 and line.startswith("$'", index):
                quote = "ansi_single"
                index += 2
                continue

            if arithmetic_depth > 0:
                if line.startswith("$(", index) and not line.startswith("$((", index):
                    raise ValueError(
                        f"{label}:{line_number}: command substitution inside arithmetic expansion is "
                        "unsupported by the shell-source guard"
                    )
                if char in {"'", '"', "`"}:
                    raise ValueError(
                        f"{label}:{line_number}: quoted/backtick syntax inside arithmetic expansion is "
                        "unsupported by the shell-source guard"
                    )
                if line.startswith("$((", index) or line.startswith("((", index):
                    arithmetic_depth += 1
                    index += 3 if line.startswith("$((", index) else 2
                    continue
                if line.startswith("))", index):
                    arithmetic_depth -= 1
                    index += 2
                    if arithmetic_depth == 0 and arithmetic_resume_quote is not None:
                        quote = arithmetic_resume_quote
                        arithmetic_resume_quote = None
                    continue

            if char in {"'", '"'}:
                quote = char
                index += 1
                continue

            if char == "#" and shell_comment_start(line, index):
                break

            if char == "`":
                raise ValueError(
                    f"{label}:{line_number}: legacy backtick command substitution is unsupported; "
                    "use $(...) so lexical command boundaries remain explicit"
                )

            if line.startswith("$[", index):
                raise ValueError(
                    f"{label}:{line_number}: legacy $[...] arithmetic syntax is unsupported; "
                    "use $((...)) so shift operators cannot alias heredoc syntax"
                )

            if line.startswith("$((", index):
                arithmetic_depth += 1
                index += 3
                continue

            if line.startswith("((", index):
                arithmetic_depth += 1
                index += 2
                continue

            if line.startswith("$(", index):
                command_depths.append(1)
                command_resume_quotes.append(None)
                index += 2
                continue

            if command_depths and char == "(":
                command_depths[-1] += 1
                index += 1
                continue

            if command_depths and char == ")":
                command_depths[-1] -= 1
                index += 1
                if command_depths[-1] == 0:
                    command_depths.pop()
                    quote = command_resume_quotes.pop()
                continue

            if line.startswith("<<<", index):
                index += 3
                continue

            if line.startswith("<<", index):
                if arithmetic_depth > 0:
                    index += 2
                    continue
                cursor = index + 2
                strip_tabs = False
                if cursor < len(line) and line[cursor] == "-":
                    strip_tabs = True
                    cursor += 1
                while cursor < len(line) and line[cursor] in " \t":
                    cursor += 1

                delimiter, cursor, delimiter_quoted = parse_heredoc_delimiter(
                    line,
                    cursor,
                    f"{label}:{line_number}",
                )
                if not delimiter_quoted:
                    raise ValueError(
                        f"{label}:{line_number}: unquoted heredoc delimiter is unsupported by the "
                        "shell-source guard because Bash expands executable substitutions in its body; "
                        "quote or backslash-quote the delimiter so the body is inert data"
                    )
                discovered_heredocs.append((delimiter, strip_tabs))
                index = cursor
                continue

            if char == "\\" and index + 1 < len(line):
                if line[index + 1] == "n":
                    raise ValueError(
                        f"{label}:{line_number}: unquoted literal \\n in shell source is a serialized "
                        "command separator risk; use a physical newline between commands or quote data"
                    )
                index += 2
                continue

            index += 1

        if quote is None and discovered_heredocs:
            heredocs.extend(discovered_heredocs)

    if quote is not None:
        raise ValueError(f"{label}: unterminated shell quote in run source")
    if heredocs:
        raise ValueError(f"{label}: unterminated heredoc in run source: {heredocs[0][0]}")
    if arithmetic_depth != 0 or arithmetic_resume_quote is not None:
        raise ValueError(f"{label}: unterminated arithmetic context in run source")
    if command_depths or command_resume_quotes:
        raise ValueError(f"{label}: unterminated command substitution in run source")


def reject_ambiguous_run_scalar_topology(text: str, label: str) -> None:
    """Require runtime shell line topology to be explicit in physical YAML source."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = core.RUN_KEY.match(line)
        if not match:
            continue

        line_number = index + 1
        value = match.group("value").strip()
        if value.startswith(">"):
            raise ValueError(
                f"{label}:{line_number}: folded run block is unsupported by the serialized-separator "
                "guard; use a literal | block so physical source lines equal runtime shell lines"
            )
        if value.startswith("|"):
            continue

        run_indent = len(match.group("indent")) + len(match.group("item") or "")
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                cursor += 1
                continue
            if core.indentation(candidate) > run_indent:
                raise ValueError(
                    f"{label}:{line_number}: multiline plain run scalar is unsupported by the "
                    "serialized-separator guard; use a literal | block so every runtime shell "
                    "line is explicit in physical YAML source"
                )
            break


def validate_serialized_separator_inventory() -> tuple[int, int]:
    paths = sorted({*core.WORKFLOWS.glob("*.yml"), *core.WORKFLOWS.glob("*.yaml")})
    core.require(paths, "No workflow files found")
    run_count = 0
    for path in paths:
        label = path.name
        text = path.read_text(encoding="utf-8")
        reject_ambiguous_run_scalar_topology(text, label)
        for block in core.extract_run_blocks(text, label):
            block_label = f"{label}:run@{block.line}"
            reject_serialized_command_separator(block.source, block_label)
            run_count += 1
    return len(paths), run_count


def self_test_serialized_separator() -> None:
    safe = """printf '%s\\n' "$VALUE"
printf "%s\\n" "$VALUE"
# literal data marker \\n          test inside a comment is inert
true;# separator-adjacent comment \\n          test remains inert
cat <<'EOF'
payload \\n          test
EOF
"""
    reject_serialized_command_separator(safe, "serialized-separator-safe")

    ambiguous_run_scalars = (
        (
            """run: >
  true <<EOF payload \\n          && echo BYPASS EOF
""",
            "folded run block is unsupported",
        ),
        (
            """- run: true
    \\n          && echo BYPASS
""",
            "multiline plain run scalar is unsupported",
        ),
    )
    for source, fragment in ambiguous_run_scalars:
        try:
            reject_ambiguous_run_scalar_topology(
                source,
                "serialized-separator-yaml-topology-self-test",
            )
        except ValueError as exc:
            core.require(
                fragment in str(exc),
                f"run-scalar topology self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "serialized-separator self-test accepted YAML run source whose runtime shell "
                "line topology differs from physical source"
            )

    arithmetic_safe = """value=$((1 << SHIFT))
(( value = value << 1 ))
printf '%s\\n' "$value"
"""
    reject_serialized_command_separator(arithmetic_safe, "serialized-separator-arithmetic-safe")

    quoted_arithmetic_safe = 'printf "%s\\n" "$((VALUE + 1))"'
    reject_serialized_command_separator(
        quoted_arithmetic_safe,
        "serialized-separator-quoted-arithmetic-safe",
    )

    command_substitution_safe = """value="$(printf "%s" "$INPUT")"
nested="$(printf "%s" "$(printf "%s" "$INPUT")")"
fallback="${INPUT:-"fallback"}"
printf '%s\\n' "$value:$nested:$fallback"
"""
    reject_serialized_command_separator(
        command_substitution_safe,
        "serialized-separator-command-substitution-safe",
    )

    parameter_parenthesis_safe = 'response="$(printf "%s" ${INPUT//)/x})"'
    reject_serialized_command_separator(
        parameter_parenthesis_safe,
        "serialized-separator-parameter-parenthesis-safe",
    )

    top_level_case_safe = """case "$INPUT" in
  foo) printf '%s\\n' ok ;;
  *) printf '%s\\n' fallback ;;
esac
"""
    reject_serialized_command_separator(
        top_level_case_safe,
        "serialized-separator-top-level-case-safe",
    )

    ansi_c_safe = """tab=$'\\t'
quote=$'it\\'s'
printf '%s\\n' "$tab:$quote"
"""
    reject_serialized_command_separator(
        ansi_c_safe,
        "serialized-separator-ansi-c-safe",
    )

    unquoted_heredoc_expansion = """cat <<EOF
$(test "$LEFT" = "$RIGHT" \n          test "$NEXT" = "$VALUE")
EOF
"""
    try:
        reject_serialized_command_separator(
            unquoted_heredoc_expansion,
            "serialized-separator-unquoted-heredoc-expansion",
        )
    except ValueError as exc:
        core.require(
            "unquoted heredoc delimiter is unsupported" in str(exc),
            f"unquoted-heredoc self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError(
            "serialized-separator self-test accepted an expansion-active unquoted heredoc body"
        )

    unsupported_heredoc = """cat <<$(echo EOF)
payload
$(echo EOF)
test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"
"""
    try:
        reject_serialized_command_separator(
            unsupported_heredoc,
            "serialized-separator-unsupported-heredoc",
        )
    except ValueError as exc:
        core.require(
            "unsupported heredoc delimiter syntax" in str(exc),
            f"unsupported-heredoc self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("serialized-separator self-test accepted ambiguous heredoc delimiter syntax")

    ansi_c_poison = """value=$'it\\'s'; test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"; printf '%s' \\'
"""
    for source in (
        ansi_c_poison,
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        'set -euo pipefail\\n          test -n "$VALUE"',
        'set -euo pipefail\\n test -n "$VALUE"',
        'printf %s prefix\\nsuffix',
        'test "$LEFT" = "$RIGHT" \\n          && test "$NEXT" = "$VALUE"',
        'false \\n          || true',
        'printf "%s" x\\n          ; true',
        'printf "%s" x\\n          | cat',
        'printf "%s" x\\n          & wait',
        'set -euo pipefail\\n          # intended next physical line is a comment',
        'printf "%s" \\ #not-comment \\n          && true',
        'printf "%s" $(printf x)#not-comment \\n          && true',
        'printf "%s" $((1))#not-comment \\n          && true',
        'printf "%s" x\\;#not-comment\\n          test -n "$VALUE"',
        "shifted=$((1 << MASK))\n"
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        'printf "%s" "$((1\\n          + 2))"',
        "(( shifted = 1 << MASK ))\n"
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        'response="$(printf "%s" "$INPUT")"\n'
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        'response="$(printf "%s" "$(printf "%s" "$INPUT")")"\n'
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        'response="$(printf "%s" ${INPUT//)/x}; printf "%s" ok \\n          test "$NEXT")"',
        "cat <<\\EOF\npayload \\n          inert\nEOF\n"
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
        "cat <<E'OF'\npayload\nEOF\n"
        'test "$LEFT" = "$RIGHT" \\n          test "$NEXT" = "$VALUE"',
    ):
        try:
            reject_serialized_command_separator(source, "serialized-separator-self-test")
        except ValueError as exc:
            core.require(
                "serialized command separator" in str(exc),
                f"serialized-separator self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError("serialized-separator self-test accepted a literal escaped command break")

    unsupported_case_substitution = """value="$(
  case "$INPUT" in
    foo) printf '%s' ok \\n          test "$NEXT" ;;
    *) printf '%s' fallback ;;
  esac
)"
"""
    try:
        reject_serialized_command_separator(
            unsupported_case_substitution,
            "serialized-separator-case-command-substitution-self-test",
        )
    except ValueError as exc:
        core.require(
            "case statements inside command substitution are unsupported" in str(exc),
            f"case-substitution self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError(
            "serialized-separator self-test accepted case syntax inside command substitution"
        )

    try:
        reject_serialized_command_separator(
            'printf "%s" ${INPUT:-prefix\\n          suffix}',
            "serialized-separator-parameter-literal-newline-self-test",
        )
    except ValueError as exc:
        core.require(
            "unquoted literal \\n inside a parameter expansion is unsupported" in str(exc),
            f"parameter-literal-newline self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError(
            "serialized-separator self-test accepted an unquoted literal newline escape inside parameter expansion"
        )

    unsupported_parameter_substitution = 'value="${INPUT:-$(printf "%s" "$OTHER")}"'
    try:
        reject_serialized_command_separator(
            unsupported_parameter_substitution,
            "serialized-separator-parameter-command-substitution-self-test",
        )
    except ValueError as exc:
        core.require(
            "command substitution inside a parameter expansion is unsupported" in str(exc),
            f"parameter-expansion self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError(
            "serialized-separator self-test accepted command substitution inside parameter expansion"
        )

    for source in (
        'cat ${INPUT:-<(printf "%s" x\\n          ; echo BYPASS)}',
        'cat ${INPUT:->(printf "%s" x\\n          ; cat >/tmp/bypass)}',
    ):
        try:
            reject_serialized_command_separator(
                source,
                "serialized-separator-parameter-process-substitution-self-test",
            )
        except ValueError as exc:
            core.require(
                "process substitution inside a parameter expansion is unsupported" in str(exc),
                f"parameter-process-substitution self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "serialized-separator self-test accepted process substitution inside parameter expansion"
            )

    malformed_cases = (
        ("printf '%s' 'unterminated", "unterminated shell quote"),
        ("cat <<'EOF'\npayload", "unterminated heredoc"),
        ("value=$((1 << SHIFT)", "unterminated arithmetic context"),
        ('value="$(printf "%s" "$INPUT"', "unterminated command substitution"),
        ("value=$[1 << 2]", "legacy $[...] arithmetic syntax"),
    )
    for source, fragment in malformed_cases:
        try:
            reject_serialized_command_separator(source, "serialized-separator-malformed-self-test")
        except ValueError as exc:
            core.require(
                fragment in str(exc),
                f"malformed-shell self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(f"serialized-separator self-test accepted malformed shell source: {fragment}")


def self_test_with_frozen_fixture() -> None:
    production_verify = core.GH_ATTESTATION_VERIFY_HEAD
    core.GH_ATTESTATION_VERIFY_HEAD = FROZEN_SELF_TEST_VERIFY_HEAD
    try:
        ORIGINAL_SELF_TEST()
    finally:
        core.GH_ATTESTATION_VERIFY_HEAD = production_verify


def main() -> int:
    original_jobs = core.PRIVILEGED_JOBS
    original_verify = core.GH_ATTESTATION_VERIFY_HEAD
    original_self_test = core.self_test
    core.PRIVILEGED_JOBS = ITEM11_PRIVILEGED_JOBS
    core.GH_ATTESTATION_VERIFY_HEAD = EXACT_COMPRESSED_ATTESTATION_VERIFY
    core.self_test = self_test_with_frozen_fixture
    try:
        self_test_serialized_separator()
        result = core.main()
        if result != 0:
            return result
        workflow_count, run_count = validate_serialized_separator_inventory()
        print(
            f"Workflow serialized-separator validation passed: scanned {run_count} run blocks across "
            f"{workflow_count} workflows; quoted/quoted-heredoc \\n data remains valid while every unquoted "
            "literal backslash-n in shell source is rejected."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        core.PRIVILEGED_JOBS = original_jobs
        core.GH_ATTESTATION_VERIFY_HEAD = original_verify
        core.self_test = original_self_test


if __name__ == "__main__":
    raise SystemExit(main())