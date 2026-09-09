#!/usr/bin/env python3
"""Fail closed on unsafe workflow shell source and privileged command indirection.

GitHub evaluates ${{ ... }} expressions before a `run:` script reaches the shell. If
attacker-controlled event data is interpolated directly into shell source, characters in
that data can become shell syntax. This validator requires dynamic values to cross a
non-shell boundary such as `env:`, `with:`, or `if:` instead.

The scanner intentionally accepts only canonical plain single-line run scalars or
literal/folded block scalars. YAML aliases, anchors, tags, or quoted whole-command
scalars are rejected for `run:` because they can obscure the bytes that will become
shell source and make a dependency-free source validator ambiguous.

Jobs holding repository-write, PR-write, Actions-write, or check-observation authority
also use a narrower execution model: reviewed `gh api` calls must remain literal, shell
variables cannot become command names, and runner-resident interpreters/network clients
cannot create an alternate mutation path outside the closed workflow authority surface.
Git execution is permitted only in the one reviewed generated-branch publisher; every
other token-authorized job must remain outside Git's mutation surface entirely.
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
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
GH_WORD = re.compile(r"(?<![A-Za-z0-9_])gh(?![A-Za-z0-9_])")
COMMAND_TOKEN_SPLICE = re.compile(r"(?<=[A-Za-z0-9_])\\\n[ \t]*(?=[A-Za-z0-9_])")
SHELL_CONTINUATION = re.compile(r"\\\n[ \t]*")
DYNAMIC_COMMAND = re.compile(
    r"(?m)(?:^\s*(?:(?:if|elif|while|until)\s+)?|[;&|]\s*)"
    r"(?:\"[^\"\n]*\$[^\"\n]*\"|'[^'\n]*\$[^'\n]*'|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)(?=\s)"
)
INDIRECT_EXECUTION = re.compile(
    r"(?m)(?:^\s*(?:(?:if|elif|while|until)\s+)?|[;&|]\s*)"
    r"(?:eval|exec|source|alias|unalias|command|env)(?=\s|$)"
)
SOURCE_DOT = re.compile(r"(?m)(?:^\s*|[;&|]\s*)\.\s+")
COMMAND_PREFIX = r"(?m)(?:^\s*(?:(?:if|elif|while|until)\s+)?|[;&|]\s*|\$\(\s*)(?:/[A-Za-z0-9_./-]+/)?"
ALTERNATE_EXECUTABLE = re.compile(
    COMMAND_PREFIX
    + r"(?:curl|wget|python(?:[0-9.]*)?|node|ruby|perl|php|lua|bash|sh|dash|zsh|"
      r"ssh|scp|rsync|nc|ncat|socat|openssl)(?=\s|$)"
)
GIT_EXECUTABLE = re.compile(COMMAND_PREFIX + r"git(?=\s|$)")
SYSTEM_ESCAPE = re.compile(r"\bsystem\s*\(")

PRIVILEGED_JOBS = {
    "profile-stats.yml": ("publish", "dispatch"),
    "spotlight-link-sync.yml": ("propose", "approve", "merge"),
}
GIT_AUTHORIZED_JOB = ("profile-stats.yml", "publish")


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


def logical_shell_source(source: str, label: str) -> str:
    """Collapse reviewed shell line continuations without allowing command-token splicing."""
    require(
        COMMAND_TOKEN_SPLICE.search(source) is None,
        f"{label}: shell continuation must not splice command-name/identifier tokens",
    )
    return SHELL_CONTINUATION.sub(" ", source)


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


def job_block(text: str, job: str, label: str) -> str:
    """Return one exact two-space workflow job block."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"  {job}:"]
    require(len(starts) == 1, f"{label}: privileged job identity changed or is ambiguous: {job}")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if JOB_KEY.fullmatch(lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def validate_privileged_shell_source(source: str, label: str, *, allow_git: bool = False) -> None:
    """Reject alternate/dynamic command paths in token-authorized workflow shell."""
    for line_number, line in enumerate(source.splitlines(), start=1):
        gh_words = len(GH_WORD.findall(line))
        literal_gh_api = line.count("gh api ")
        require(
            gh_words == literal_gh_api,
            f"{label}:{line_number}: GitHub CLI token must appear only as a literal reviewed `gh api` command",
        )

    logical = logical_shell_source(source, label)
    require(
        DYNAMIC_COMMAND.search(logical) is None,
        f"{label}: shell variables/expansions must not become command names in privileged workflow jobs",
    )
    require(
        INDIRECT_EXECUTION.search(logical) is None and SOURCE_DOT.search(logical) is None,
        f"{label}: indirect shell execution/wrappers are forbidden in privileged workflow jobs",
    )
    require(
        ALTERNATE_EXECUTABLE.search(logical) is None,
        f"{label}: alternate runner-resident interpreter/network executable is forbidden in privileged workflow jobs",
    )
    require(
        allow_git or GIT_EXECUTABLE.search(logical) is None,
        f"{label}: Git execution is forbidden outside the reviewed generated-branch publisher",
    )
    require(
        SYSTEM_ESCAPE.search(logical) is None,
        f"{label}: subprocess escape primitives are forbidden in privileged workflow jobs",
    )


def validate_text(text: str, label: str) -> int:
    blocks = extract_run_blocks(text, label)
    for block in blocks:
        require(
            EXPRESSION not in block.source,
            f"{label}:{block.line}: GitHub expression interpolation is forbidden inside run shell source; pass dynamic data through env:/with:/if: instead",
        )
    return len(blocks)


def validate_privileged_inventory() -> int:
    run_count = 0
    for workflow_name, jobs in PRIVILEGED_JOBS.items():
        path = WORKFLOWS / workflow_name
        require(path.is_file(), f"Privileged workflow is missing: {workflow_name}")
        text = path.read_text(encoding="utf-8")
        for job in jobs:
            block = job_block(text, job, workflow_name)
            runs = extract_run_blocks(block, f"{workflow_name}:{job}")
            require(runs, f"{workflow_name}:{job}: privileged job contains no reviewed shell source")
            allow_git = (workflow_name, job) == GIT_AUTHORIZED_JOB
            for run in runs:
                validate_privileged_shell_source(
                    run.source,
                    f"{workflow_name}:{job}:run@{run.line}",
                    allow_git=allow_git,
                )
            run_count += len(runs)
    return run_count


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
        "python3 scripts/validate-workflow-source-shape.py" in text,
        "Profile Quality must execute the canonical workflow YAML source-shape gate before shell parsing is trusted",
    )
    require(
        "python3 scripts/validate-workflow-authority-contract.py" in text,
        "Profile Quality must execute the closed workflow authority inventory alongside shell command closure",
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


def expect_privileged_failure(source: str, fragment: str, *, allow_git: bool = False) -> None:
    try:
        validate_privileged_shell_source(source, "privileged-self-test", allow_git=allow_git)
    except ValueError as exc:
        require(fragment in str(exc), f"privileged shell self-test failed for wrong reason: {exc}")
    else:
        fail(f"privileged shell self-test accepted forbidden command path: {fragment}")


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

    privileged_safe = """set -euo pipefail
PR=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}\")\"
test \"$(jq -r .head.sha <<<\"$PR\")\" = \"$HEAD_SHA\"
gh api --method POST \\
  \"repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve\" >/dev/null
"""
    validate_privileged_shell_source(privileged_safe, "privileged-self-test-safe")
    validate_privileged_shell_source(
        privileged_safe + 'git -C artifacts -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $AUTH_HEADER" push origin HEAD:generated\n',
        "privileged-self-test-publisher",
        allow_git=True,
    )

    for source, fragment in (
        (privileged_safe + 'GH=gh\n"$GH" api --method DELETE "repos/x/y"\n', "GitHub CLI token"),
        (privileged_safe + 'G=g\nH=h\n"$G$H" api --method DELETE "repos/x/y"\n', "must not become command names"),
        (privileged_safe + 'python3 -c "import urllib.request"\n', "alternate runner-resident"),
        (privileged_safe + 'if /usr/bin/curl https://example.invalid; then exit 1; fi\n', "alternate runner-resident"),
        (privileged_safe + 'eval "$COMMAND"\n', "indirect shell execution"),
        (privileged_safe + 'command "$CLIENT" api repos/x/y\n', "indirect shell execution"),
        (privileged_safe + 'awk \'BEGIN { system("client --write") }\'\n', "subprocess escape"),
        (privileged_safe + 'git -C repo push origin HEAD:main\n', "Git execution is forbidden"),
        (privileged_safe + '/usr/bin/git push origin HEAD:main\n', "Git execution is forbidden"),
        (privileged_safe + 'g\\\nh api --method DELETE repos/x/y\n', "must not splice command-name/identifier tokens"),
    ):
        expect_privileged_failure(source, fragment)


def main() -> int:
    try:
        self_test()
        require(QUALITY.is_file(), "Profile Quality workflow is missing")
        workflow_count, run_count = validate_inventory()
        privileged_run_count = validate_privileged_inventory()
        validate_quality_binding(QUALITY.read_text(encoding="utf-8"))
        print(
            f"Workflow shell-safety validation passed: scanned {run_count} run blocks across {workflow_count} workflows; "
            f"{privileged_run_count} token-authorized run blocks retain literal command closure; "
            "GitHub expressions remain outside shell source, dynamic data crosses explicit non-shell boundaries, and privileged jobs reject command aliases/alternate interpreters with Git isolated to the reviewed publisher."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
