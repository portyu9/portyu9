#!/usr/bin/env python3
"""Executable deterministic retry taxonomy for governed automation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/automation-retry-policy-v1.json"
WORKFLOWS = ROOT / ".github/workflows"
PINNED_GENERATOR = "shinpr/github-profile-stats@49b5f7091182a45f3ef93923505b660c6da5f835 # v0.2.0"

SEQ_LOOP = re.compile(
    r"^\s*for\s+(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+\$\(seq\s+1\s+(?P<maximum>[1-9][0-9]*)\);\s*do\s*$"
)
SHELL_LOOP = re.compile(r"^(?:for|while|until)\b.*;\s*do\s*$")
DONE = re.compile(r"^done(?:\s|$)")
SLEEP = re.compile(r"\bsleep\s+([1-9][0-9]*)\b")
JOB = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+):\s*$")
STEP = re.compile(r"^\s{6}- name:\s*(?P<step>.+?)\s*$")
MUTATION = re.compile(
    r"--method\s+(?:POST|PUT|PATCH|DELETE)\b|\bgh\s+pr\s+(?:merge|review)\b|\bgit\s+push\b"
)

EXPECTED_TERMINAL_IDS = {
    "profile-quality-live-generator-fallback",
    "dependabot-live-generator-validation",
    "ruleset-successor-mutation",
}
EXPECTED_REENTRY_IDS = {
    "dependabot-controller-reentry",
    "codeql-autofix-controller-reentry",
    "bot-pr-user-approval-reentry",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"retry policy contains duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def workflow_texts(root: Path = ROOT) -> dict[str, str]:
    directory = root / ".github/workflows"
    return {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in sorted(directory.glob("*.yml"))
    }


def named_step(text: str, job_name: str, step_name: str) -> str:
    lines = text.splitlines(keepends=True)
    job_start: int | None = None
    job_end = len(lines)
    for index, line in enumerate(lines):
        match = JOB.match(line.rstrip("\n"))
        if match and match.group("job") == job_name:
            job_start = index
            break
    require(job_start is not None, f"retry-policy job is missing: {job_name}")
    for index in range(job_start + 1, len(lines)):
        if JOB.match(lines[index].rstrip("\n")):
            job_end = index
            break

    step_start: int | None = None
    step_end = job_end
    for index in range(job_start + 1, job_end):
        match = STEP.match(lines[index].rstrip("\n"))
        if match and match.group("step") == step_name:
            step_start = index
            break
    require(step_start is not None, f"retry-policy step is missing: {job_name}/{step_name}")
    for index in range(step_start + 1, job_end):
        if STEP.match(lines[index].rstrip("\n")):
            step_end = index
            break
    return "".join(lines[step_start:step_end])


def loop_block(lines: list[str], start: int) -> list[str]:
    depth = 0
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if SHELL_LOOP.match(stripped):
            depth += 1
        if DONE.match(stripped):
            depth -= 1
            require(depth >= 0, "retry-policy shell-loop parser underflow")
            if depth == 0:
                return lines[start:index + 1]
    raise ValueError("retry-policy bounded loop is unterminated")


def observed_bounded_loops(texts: dict[str, str]) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    for path, text in sorted(texts.items()):
        lines = text.splitlines()
        job: str | None = None
        step: str | None = None
        ordinal_by_step: dict[tuple[str, str], int] = {}
        for index, line in enumerate(lines):
            job_match = JOB.match(line)
            if job_match:
                job = job_match.group("job")
            step_match = STEP.match(line)
            if step_match:
                step = step_match.group("step")
            loop_match = SEQ_LOOP.match(line)
            if loop_match is None:
                continue
            require(job is not None and step is not None,
                    f"bounded loop is outside one named job/step: {path}:{index + 1}")
            key = (job, step)
            ordinal_by_step[key] = ordinal_by_step.get(key, 0) + 1
            block = loop_block(lines, index)
            sleeps = {int(match.group(1)) for row in block for match in SLEEP.finditer(row)}
            require(len(sleeps) == 1,
                    f"bounded observation loop must own one deterministic sleep interval: {path}:{index + 1}")
            mutations = [row.strip() for row in block if MUTATION.search(row)]
            observed.append({
                "workflow": path,
                "job": job,
                "step": step,
                "ordinal": ordinal_by_step[key],
                "variable": loop_match.group("variable"),
                "maxIterations": int(loop_match.group("maximum")),
                "sleepSeconds": next(iter(sleeps)),
                "mutations": mutations,
                "block": "\n".join(block),
            })
    return observed


def policy_loop_identity(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("workflow"),
        item.get("job"),
        item.get("step"),
        item.get("ordinal"),
        item.get("variable"),
        item.get("maxIterations"),
        item.get("sleepSeconds"),
    )


def validate_bounded_observation(policy: dict[str, Any], texts: dict[str, str]) -> None:
    declared = policy.get("boundedObservation")
    require(isinstance(declared, list), "retry policy boundedObservation must be an array")
    require(len(declared) == 17, "retry policy must classify exactly the current 17 bounded seq loops")
    ids = [item.get("id") for item in declared if isinstance(item, dict)]
    require(len(ids) == len(set(ids)) == 17 and all(isinstance(value, str) and value for value in ids),
            "retry policy bounded observation IDs must be unique nonempty strings")

    observed = observed_bounded_loops(texts)
    require(len(observed) == len(declared),
            "unclassified bounded workflow loop appeared or a declared loop disappeared")
    by_identity = {policy_loop_identity(item): item for item in declared}
    require(len(by_identity) == len(declared),
            "retry policy bounded observation identities must be unique")

    for loop in observed:
        identity = policy_loop_identity(loop)
        require(identity in by_identity,
                "bounded workflow loop is not declared by deterministic retry policy: "
                f"{loop['workflow']}::{loop['job']}::{loop['step']}#{loop['ordinal']}")
        rule = by_identity[identity]
        require(rule.get("class") == "bounded-observation" and rule.get("operationRetry") is False,
                f"bounded observation classification changed: {rule.get('id')}")
        require(isinstance(rule.get("purpose"), str) and bool(rule["purpose"].strip()),
                f"bounded observation purpose is missing: {rule.get('id')}")
        mode = rule.get("mutationMode")
        mutations = loop["mutations"]
        if mode == "none":
            require(not mutations,
                    f"observation-only loop acquired mutation authority: {rule.get('id')}")
        elif mode == "guarded-once-per-run-id":
            require(mutations and all("/approve" in row and "--method POST" in row for row in mutations),
                    f"guarded observation mutation surface changed: {rule.get('id')}")
            block = loop["block"]
            owner = named_step(texts[loop["workflow"]], loop["job"], loop["step"])
            require('APPROVAL_REQUESTED_RUN_IDS=""' in owner,
                    f"guarded observation lost once-per-run approval dedupe initialization: {rule.get('id')}")
            for fragment in (
                'case " $APPROVAL_REQUESTED_RUN_IDS " in',
                'APPROVAL_REQUESTED_RUN_IDS="',
            ):
                require(fragment in block,
                        f"guarded observation lost once-per-run approval dedupe: {rule.get('id')}")
        elif mode == "state-conditioned-single-pass":
            require(mutations and all("/approve" in row and "--method POST" in row for row in mutations),
                    f"single-pass observation mutation surface changed: {rule.get('id')}")
            require("return 0" in loop["block"],
                    f"single-pass observation no longer exits after one materialized decision pass: {rule.get('id')}")
        else:
            raise ValueError(f"unsupported bounded observation mutationMode: {mode}")


def validate_terminal_operations(policy: dict[str, Any], texts: dict[str, str]) -> None:
    terminal = policy.get("terminalOperations")
    require(isinstance(terminal, list), "retry policy terminalOperations must be an array")
    require({item.get("id") for item in terminal if isinstance(item, dict)} == EXPECTED_TERMINAL_IDS,
            "retry policy terminal operation identities changed")
    by_id = {item["id"]: item for item in terminal}

    profile = texts[".github/workflows/profile-quality.yml"]
    dependabot = texts[".github/workflows/dependabot-controller.yml"]
    for workflow in (profile, dependabot):
        for forbidden in (
            "Back off before one exact pinned upstream retry",
            "Retry exact pinned upstream Signal Field once",
            "stats_retry",
            "run: sleep 60",
        ):
            require(forbidden not in workflow,
                    f"unclassified pinned-generator automatic retry returned: {forbidden}")

    for identifier, text in (
        ("profile-quality-live-generator-fallback", profile),
        ("dependabot-live-generator-validation", dependabot),
    ):
        item = by_id[identifier]
        require(item.get("failureClassifier") == "none" and item.get("disposition") == "terminal",
                f"unclassified generator failure must remain terminal: {identifier}")
        block = named_step(text, item["job"], item["step"])
        require(block.count(f"uses: {PINNED_GENERATOR}") == 1,
                f"terminal generator operation identity changed: {identifier}")
        require("continue-on-error:" not in block,
                f"terminal generator operation must fail its job directly: {identifier}")

    ruleset_item = by_id["ruleset-successor-mutation"]
    ruleset = texts[ruleset_item["workflow"]]
    block = named_step(ruleset, ruleset_item["job"], ruleset_item["step"])
    require(ruleset_item.get("failureClassifier") == "none"
            and ruleset_item.get("disposition") == "terminal",
            "ruleset mutation retry disposition changed")
    require(block.count("--method PUT") == 1,
            "ruleset terminal mutation must retain exactly one reviewed PUT")
    require("no automatic retry will occur" in block,
            "ruleset terminal mutation lost explicit no-retry failure disposition")
    require(SEQ_LOOP.search(block) is None,
            "ruleset terminal mutation acquired an in-step retry/wait loop")


def validate_reentry(policy: dict[str, Any], texts: dict[str, str]) -> None:
    entries = policy.get("trustedReentry")
    require(isinstance(entries, list), "retry policy trustedReentry must be an array")
    require({item.get("id") for item in entries if isinstance(item, dict)} == EXPECTED_REENTRY_IDS,
            "retry policy trusted re-entry identities changed")
    for item in entries:
        require(item.get("workflow") in texts,
                f"trusted re-entry workflow is missing: {item.get('id')}")
        require(isinstance(item.get("semantics"), str) and "does not" in item["semantics"],
                f"trusted re-entry semantics must explicitly deny retry carry-over: {item.get('id')}")


def validate(policy: dict[str, Any], texts: dict[str, str]) -> None:
    require(isinstance(policy, dict) and set(policy) == {
        "schemaVersion", "automaticRetries", "terminalOperations", "boundedObservation", "trustedReentry"
    }, "retry policy top-level shape changed")
    require(policy.get("schemaVersion") == 1, "retry policy schemaVersion changed")
    require(policy.get("automaticRetries") == [],
            "automatic operation retries require a future reviewed transient classifier; none are authorized today")
    validate_terminal_operations(policy, texts)
    validate_bounded_observation(policy, texts)
    validate_reentry(policy, texts)


def expect_failure(policy: dict[str, Any], texts: dict[str, str], expected: str) -> None:
    try:
        validate(policy, texts)
    except ValueError as exc:
        require(expected in str(exc), f"retry-policy self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"retry-policy self-test accepted forbidden drift: {expected}")


def self_test(policy: dict[str, Any], texts: dict[str, str]) -> None:
    unauthorized = copy.deepcopy(policy)
    unauthorized["automaticRetries"] = [{"id": "unreviewed"}]
    expect_failure(unauthorized, dict(texts), "none are authorized today")

    profile_drift = dict(texts)
    profile_drift[".github/workflows/profile-quality.yml"] = profile_drift[
        ".github/workflows/profile-quality.yml"
    ].replace(
        "        uses: " + PINNED_GENERATOR + "\n",
        "        continue-on-error: true\n        uses: " + PINNED_GENERATOR + "\n",
        1,
    )
    expect_failure(copy.deepcopy(policy), profile_drift, "must fail its job directly")

    loop_drift = dict(texts)
    loop_drift[".github/workflows/bot-pr-user-approval.yml"] = loop_drift[
        ".github/workflows/bot-pr-user-approval.yml"
    ].replace("for attempt in $(seq 1 48); do", "for attempt in $(seq 1 49); do", 1)
    expect_failure(copy.deepcopy(policy), loop_drift, "not declared")

    autofix_drift = dict(texts)
    autofix_drift[".github/workflows/codeql-autofix.yml"] = autofix_drift[
        ".github/workflows/codeql-autofix.yml"
    ].replace('APPROVAL_REQUESTED_RUN_IDS=""\n', "", 1)
    expect_failure(copy.deepcopy(policy), autofix_drift, "once-per-run approval dedupe")


def validate_repository(root: Path = ROOT) -> None:
    policy = strict_json(root / ".github/automation-retry-policy-v1.json")
    texts = workflow_texts(root)
    validate(policy, texts)
    self_test(policy, texts)


if __name__ == "__main__":
    validate_repository()
    print(
        "Automation retry taxonomy validation passed: no automatic operation retries are authorized; "
        "unclassified generator/ruleset failures are terminal; all 17 bounded seq loops are declared "
        "as observation/re-entry semantics with guarded approval mutations explicitly constrained."
    )
