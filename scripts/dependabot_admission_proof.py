#!/usr/bin/env python3
"""Build and verify exact retry-history evidence for delegated Dependabot admission proofs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

REPOSITORY = "portyu9/portyu9"
WORKFLOW_NAME = "Capability admission"
WORKFLOW_PATH = ".github/workflows/capability-admission.yml"
WORKFLOW_EVENT = "repository_dispatch"
CHECK_NAME = "trusted-capability-admission"
CHECK_APP_ID = 15368
MAX_RECORDED_ATTEMPTS = 20
CLAIM = (
    "This delegated Dependabot admission proof binds the exact trusted Capability Admission "
    "workflow run/attempt and its bounded prior retry history. Earlier attempts are evidence only "
    "and never authorize the candidate."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
EXTERNAL_ID = re.compile(
    r"^dependabot-delegated-admission:"
    r"(?P<run>[1-9][0-9]*):(?P<attempt>[1-9][0-9]*):(?P<digest>[0-9a-f]{64}):"
    r"(?P<pr>[1-9][0-9]*):(?P<base>[0-9a-f]{40}):(?P<head>[0-9a-f]{40})$"
)
TERMINAL_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "success",
    "timed_out",
}


class ProofError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


def strict_json_text(text: str, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            require(key not in result, f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise ProofError(f"{label} is invalid JSON: {exc}") from exc


def load(path: Path, label: str) -> Any:
    return strict_json_text(path.read_text(encoding="utf-8"), label)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def positive(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be one positive integer")
    return value


def sha40(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None, f"{label} must be lowercase SHA-40")
    return value


def login(value: Any, label: str) -> str:
    require(isinstance(value, Mapping), f"{label} must be an object")
    observed = value.get("login")
    require(isinstance(observed, str) and bool(observed), f"{label}.login must be non-empty")
    return observed


def validate_prior_attempt(
    raw: Any,
    *,
    run_id: int,
    expected_attempt: int,
    base_sha: str,
) -> dict[str, Any]:
    require(isinstance(raw, Mapping), "Dependabot admission retry history contains a non-object")
    require(positive(raw.get("id"), "prior attempt run id") == run_id, "prior attempt run id changed")
    require(
        positive(raw.get("run_attempt"), "prior attempt number") == expected_attempt,
        "Dependabot admission retry-history attempts are not contiguous",
    )
    require(raw.get("name") == WORKFLOW_NAME, "prior attempt workflow name changed")
    require(raw.get("path") == WORKFLOW_PATH, "prior attempt workflow path changed")
    require(raw.get("event") == WORKFLOW_EVENT, "prior attempt event changed")
    require(raw.get("head_branch") == "main", "prior attempt head branch changed")
    require(sha40(raw.get("head_sha"), "prior attempt head SHA") == base_sha, "prior attempt base SHA changed")
    repository = raw.get("repository")
    head_repository = raw.get("head_repository")
    require(
        isinstance(repository, Mapping) and repository.get("full_name") == REPOSITORY,
        "prior attempt repository identity changed",
    )
    require(
        isinstance(head_repository, Mapping) and head_repository.get("full_name") == REPOSITORY,
        "prior attempt head-repository identity changed",
    )
    require(raw.get("status") == "completed", "prior attempt is not terminal")
    conclusion = raw.get("conclusion")
    require(conclusion in TERMINAL_CONCLUSIONS, "prior attempt conclusion is invalid")
    return {
        "attempt": expected_attempt,
        "checkSuiteId": positive(raw.get("check_suite_id"), "prior attempt check-suite id"),
        "status": "completed",
        "conclusion": conclusion,
        "actor": login(raw.get("actor"), "prior attempt actor"),
        "triggeringActor": login(raw.get("triggering_actor"), "prior attempt triggering actor"),
    }


def build_summary(
    attempts: Any,
    *,
    run_id: int,
    run_attempt: int,
    base_sha: str,
) -> tuple[dict[str, Any], str]:
    run_id = positive(run_id, "current run id")
    run_attempt = positive(run_attempt, "current run attempt")
    base_sha = sha40(base_sha, "current base SHA")
    require(run_attempt <= MAX_RECORDED_ATTEMPTS, "current run attempt exceeds bounded retry-history limit")
    require(isinstance(attempts, list), "prior-attempt input must be an array")
    require(
        len(attempts) == run_attempt - 1,
        "prior-attempt input must contain every earlier attempt exactly once",
    )
    history = [
        validate_prior_attempt(raw, run_id=run_id, expected_attempt=index, base_sha=base_sha)
        for index, raw in enumerate(attempts, start=1)
    ]
    summary = {
        "schemaVersion": 1,
        "kind": "dependabot-delegated-admission-proof",
        "workflowRun": {
            "runId": run_id,
            "runAttempt": run_attempt,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "event": WORKFLOW_EVENT,
            "headBranch": "main",
            "headSha": base_sha,
        },
        "retryHistory": history,
        "claim": CLAIM,
    }
    return summary, digest(summary)


def validate_summary(value: Any, *, run_id: int, run_attempt: int, base_sha: str) -> dict[str, Any]:
    require(isinstance(value, Mapping), "proof summary must be an object")
    require(
        set(value) == {"schemaVersion", "kind", "workflowRun", "retryHistory", "claim"},
        "proof summary shape changed",
    )
    require(value.get("schemaVersion") == 1, "proof summary schema version changed")
    require(value.get("kind") == "dependabot-delegated-admission-proof", "proof summary kind changed")
    require(value.get("claim") == CLAIM, "proof summary claim changed")
    workflow = value.get("workflowRun")
    require(isinstance(workflow, Mapping), "proof workflowRun must be an object")
    require(
        workflow == {
            "runId": run_id,
            "runAttempt": run_attempt,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "event": WORKFLOW_EVENT,
            "headBranch": "main",
            "headSha": base_sha,
        },
        "proof workflow-run identity changed",
    )
    history = value.get("retryHistory")
    require(isinstance(history, list), "proof retryHistory must be an array")
    require(len(history) == run_attempt - 1, "proof retryHistory length changed")
    for expected_attempt, item in enumerate(history, start=1):
        require(isinstance(item, Mapping), "proof retryHistory contains a non-object")
        require(
            set(item) == {"attempt", "checkSuiteId", "status", "conclusion", "actor", "triggeringActor"},
            "proof retryHistory attempt shape changed",
        )
        require(item.get("attempt") == expected_attempt, "proof retryHistory attempts are not contiguous")
        positive(item.get("checkSuiteId"), "proof retryHistory checkSuiteId")
        require(item.get("status") == "completed", "proof retryHistory contains a nonterminal attempt")
        require(item.get("conclusion") in TERMINAL_CONCLUSIONS, "proof retryHistory conclusion changed")
        require(isinstance(item.get("actor"), str) and bool(item["actor"]), "proof retryHistory actor is missing")
        require(
            isinstance(item.get("triggeringActor"), str) and bool(item["triggeringActor"]),
            "proof retryHistory triggering actor is missing",
        )
    return dict(value)


def verify_check(
    check: Any,
    *,
    pr_number: int,
    base_sha: str,
    head_sha: str,
) -> dict[str, Any]:
    pr_number = positive(pr_number, "expected PR number")
    base_sha = sha40(base_sha, "expected base SHA")
    head_sha = sha40(head_sha, "expected head SHA")
    require(isinstance(check, Mapping), "delegated admission check must be an object")
    positive(check.get("id"), "delegated admission check id")
    require(check.get("name") == CHECK_NAME, "delegated admission check name changed")
    require(check.get("head_sha") == head_sha, "delegated admission check head SHA changed")
    app = check.get("app")
    require(isinstance(app, Mapping) and app.get("id") == CHECK_APP_ID, "delegated admission check app identity changed")
    require(check.get("status") == "completed" and check.get("conclusion") == "success",
            "delegated admission check is not completed success")
    external = check.get("external_id")
    require(isinstance(external, str), "delegated admission external identity is missing")
    match = EXTERNAL_ID.fullmatch(external)
    require(match is not None, "delegated admission external identity shape changed")
    run_id = int(match.group("run"))
    run_attempt = int(match.group("attempt"))
    require(run_attempt <= MAX_RECORDED_ATTEMPTS, "delegated admission run attempt exceeds reviewed bound")
    require(int(match.group("pr")) == pr_number, "delegated admission PR identity changed")
    require(match.group("base") == base_sha and match.group("head") == head_sha,
            "delegated admission candidate identity changed")
    details_url = check.get("details_url")
    require(
        details_url == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        "delegated admission details URL changed",
    )
    pulls = check.get("pull_requests")
    require(isinstance(pulls, list), "delegated admission check pull_requests must be an array")
    matching_pulls = [
        item for item in pulls
        if isinstance(item, Mapping)
        and item.get("number") == pr_number
        and isinstance(item.get("head"), Mapping)
        and item["head"].get("sha") == head_sha
        and isinstance(item.get("base"), Mapping)
        and item["base"].get("sha") == base_sha
    ]
    require(len(matching_pulls) == 1, "delegated admission check lost exact PR association")
    output = check.get("output")
    require(isinstance(output, Mapping), "delegated admission check output is missing")
    require(output.get("title") == "Trusted capability admission passed",
            "delegated admission proof title changed")
    summary_text = output.get("summary")
    require(isinstance(summary_text, str) and bool(summary_text), "delegated admission proof summary is missing")
    summary = strict_json_text(summary_text, "delegated admission proof summary")
    validate_summary(summary, run_id=run_id, run_attempt=run_attempt, base_sha=base_sha)
    require(digest(summary) == match.group("digest"), "delegated admission proof summary digest changed")
    return {
        "runId": run_id,
        "runAttempt": run_attempt,
        "summarySha256": match.group("digest"),
        "priorAttempts": run_attempt - 1,
        "prNumber": pr_number,
        "baseSha": base_sha,
        "headSha": head_sha,
    }


def verify_current_run(current_run: Any, proof: Any) -> dict[str, Any]:
    require(isinstance(proof, Mapping), "verified delegated admission proof must be an object")
    expected_keys = {"runId", "runAttempt", "summarySha256", "priorAttempts", "prNumber", "baseSha", "headSha"}
    require(set(proof) == expected_keys, "verified delegated admission proof shape changed")
    run_id = positive(proof.get("runId"), "verified admission run id")
    run_attempt = positive(proof.get("runAttempt"), "verified admission run attempt")
    require(run_attempt <= MAX_RECORDED_ATTEMPTS, "verified admission run attempt exceeds reviewed bound")
    base_sha = sha40(proof.get("baseSha"), "verified admission base SHA")
    require(isinstance(proof.get("summarySha256"), str) and SHA64.fullmatch(proof["summarySha256"]) is not None,
            "verified admission summary digest is invalid")
    require(proof.get("priorAttempts") == run_attempt - 1, "verified admission prior-attempt count changed")
    positive(proof.get("prNumber"), "verified admission PR number")
    sha40(proof.get("headSha"), "verified admission head SHA")

    require(isinstance(current_run, Mapping), "current Capability Admission attempt must be an object")
    require(positive(current_run.get("id"), "current admission run id") == run_id, "current admission run id changed")
    require(
        positive(current_run.get("run_attempt"), "current admission run attempt") == run_attempt,
        "current admission run attempt changed",
    )
    require(current_run.get("name") == WORKFLOW_NAME, "current admission workflow name changed")
    require(current_run.get("path") == WORKFLOW_PATH, "current admission workflow path changed")
    require(current_run.get("event") == WORKFLOW_EVENT, "current admission event changed")
    require(current_run.get("head_branch") == "main", "current admission head branch changed")
    require(sha40(current_run.get("head_sha"), "current admission head SHA") == base_sha,
            "current admission base SHA changed")
    repository = current_run.get("repository")
    head_repository = current_run.get("head_repository")
    require(
        isinstance(repository, Mapping) and repository.get("full_name") == REPOSITORY,
        "current admission repository identity changed",
    )
    require(
        isinstance(head_repository, Mapping) and head_repository.get("full_name") == REPOSITORY,
        "current admission head-repository identity changed",
    )
    positive(current_run.get("check_suite_id"), "current admission check-suite id")
    require(
        current_run.get("status") == "completed" and current_run.get("conclusion") == "success",
        "current admission attempt is not completed success",
    )
    return dict(proof)

def self_test() -> None:
    base = "a" * 40
    head = "b" * 40
    prior = {
        "id": 123,
        "run_attempt": 1,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "event": WORKFLOW_EVENT,
        "head_branch": "main",
        "head_sha": base,
        "check_suite_id": 301,
        "status": "completed",
        "conclusion": "cancelled",
        "actor": {"login": "github-actions[bot]"},
        "triggering_actor": {"login": "github-actions[bot]"},
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    summary, summary_digest = build_summary([prior], run_id=123, run_attempt=2, base_sha=base)
    check = {
        "id": 901,
        "name": CHECK_NAME,
        "head_sha": head,
        "app": {"id": CHECK_APP_ID},
        "status": "completed",
        "conclusion": "success",
        "external_id": f"dependabot-delegated-admission:123:2:{summary_digest}:77:{base}:{head}",
        "details_url": f"https://github.com/{REPOSITORY}/actions/runs/123",
        "pull_requests": [{"number": 77, "head": {"sha": head}, "base": {"sha": base}}],
        "output": {"title": "Trusted capability admission passed", "summary": canonical(summary)},
    }
    current = {
        **prior,
        "run_attempt": 2,
        "check_suite_id": 302,
        "status": "completed",
        "conclusion": "success",
    }
    observed = verify_check(check, pr_number=77, base_sha=base, head_sha=head)
    require(observed["runAttempt"] == 2 and observed["priorAttempts"] == 1, "positive proof fixture changed")
    require(verify_current_run(current, observed) == observed, "current-run positive fixture changed")

    mutations = (
        ({**prior, "run_attempt": 2}, "not contiguous"),
        ({**prior, "status": "in_progress", "conclusion": None}, "not terminal"),
        ({**prior, "head_sha": "c" * 40}, "base SHA changed"),
    )
    for bad, expected in mutations:
        try:
            build_summary([bad], run_id=123, run_attempt=2, base_sha=base)
        except ProofError as exc:
            require(expected in str(exc), f"producer self-test failed for wrong reason: {exc}")
        else:
            raise ProofError(f"producer self-test accepted forbidden mutation: {expected}")

    bad_check = dict(check)
    bad_check["external_id"] = check["external_id"].replace(summary_digest, "c" * 64)
    try:
        verify_check(bad_check, pr_number=77, base_sha=base, head_sha=head)
    except ProofError as exc:
        require("summary digest changed" in str(exc), f"digest self-test failed for wrong reason: {exc}")
    else:
        raise ProofError("digest self-test accepted a mismatched summary")

    bad_current = dict(current)
    bad_current["conclusion"] = "failure"
    try:
        verify_current_run(bad_current, observed)
    except ProofError as exc:
        require("not completed success" in str(exc), f"current-attempt self-test failed for wrong reason: {exc}")
    else:
        raise ProofError("current-attempt self-test accepted failure")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--attempts", type=Path, required=True)
    build.add_argument("--run-id", type=int, required=True)
    build.add_argument("--run-attempt", type=int, required=True)
    build.add_argument("--base-sha", required=True)
    build.add_argument("--summary-out", type=Path, required=True)
    build.add_argument("--meta-out", type=Path, required=True)

    verify_check_parser = sub.add_parser("verify-check")
    verify_check_parser.add_argument("--check", type=Path, required=True)
    verify_check_parser.add_argument("--pr-number", type=int, required=True)
    verify_check_parser.add_argument("--base-sha", required=True)
    verify_check_parser.add_argument("--head-sha", required=True)
    verify_check_parser.add_argument("--out", type=Path, required=True)

    verify_current_parser = sub.add_parser("verify-current")
    verify_current_parser.add_argument("--current-run", type=Path, required=True)
    verify_current_parser.add_argument("--proof", type=Path, required=True)
    verify_current_parser.add_argument("--out", type=Path, required=True)

    sub.add_parser("self-test")

    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        print("Dependabot delegated admission retry-history proof self-test passed")
        return 0
    if args.command == "build":
        summary, summary_digest = build_summary(
            load(args.attempts, "prior-attempt input"),
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            base_sha=args.base_sha,
        )
        args.summary_out.write_text(canonical(summary) + "\n", encoding="utf-8")
        args.meta_out.write_text(
            canonical({
                "runId": args.run_id,
                "runAttempt": args.run_attempt,
                "summarySha256": summary_digest,
                "priorAttempts": args.run_attempt - 1,
            }) + "\n",
            encoding="utf-8",
        )
        return 0

    if args.command == "verify-check":
        observed = verify_check(
            load(args.check, "delegated admission check"),
            pr_number=args.pr_number,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
        )
    else:
        observed = verify_current_run(
            load(args.current_run, "current Capability Admission attempt"),
            load(args.proof, "verified delegated admission proof"),
        )
    args.out.write_text(canonical(observed) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
