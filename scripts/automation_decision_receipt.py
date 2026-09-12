#!/usr/bin/env python3
"""Build deterministic append-only Automation Decision Receipt v1 predicates and subjects."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
PROFILE_WORKFLOW = ".github/workflows/profile-stats.yml"
SPOTLIGHT_WORKFLOW = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_PATHS = (PROFILE_WORKFLOW, SPOTLIGHT_WORKFLOW)
SCHEMA_VERSION = 1
KIND = "automation-decision-receipt"
SUBJECT_KIND = "automation-decision-receipt-subject"
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "automation-decision-receipt-v1.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/automation-decision-receipt-v1.schema.json"
CLAIM = (
    "This append-only receipt records the exact reviewed automation decision and observed outcome "
    "for the privileged semantic side effects listed here. It does not replace freshness, "
    "mutation-lease validation, required checks, branch protection, or any stronger domain-specific "
    "authorization or publication attestation."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
CANDIDATE_BRANCH = re.compile(r"^automation/spotlight-links/[0-9a-f]{64}$")
PROFILE_EVENTS = {"push", "schedule", "workflow_dispatch"}
SPOTLIGHT_EVENTS = {"schedule", "workflow_dispatch"}
WORKFLOW_NAMES = {"CodeQL", "Dependency review", "Profile quality"}
EFFECT_KEYS = {"ordinal", "job", "kind", "outcome", "target", "observation"}
EFFECT_KINDS = {
    "spotlight-workflow-dispatch",
    "stale-candidate-reconciliation",
    "spotlight-candidate-publication",
    "workflow-run-approval-request",
    "spotlight-terminal-merge",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"automation decision receipt JSON contains duplicate key: {key}")
        result[key] = value
    return result


def strict_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} keys changed: {sorted(value)}")
    return value


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be one positive integer")
    return value


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def write_canonical(path: Path, value: dict[str, Any]) -> str:
    data = canonical_bytes(value)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def schema_identity() -> dict[str, str]:
    require(PREDICATE_SCHEMA.is_file() and not PREDICATE_SCHEMA.is_symlink(),
            "Automation Decision Receipt schema is missing or aliased")
    return {
        "id": PREDICATE_TYPE,
        "digest": f"sha256:{hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()}",
    }


def workflow_path(env: dict[str, str]) -> str:
    workflow_ref = env_value(env, "GITHUB_WORKFLOW_REF")
    matches = [path for path in WORKFLOW_PATHS if workflow_ref == f"{REPOSITORY}/{path}@refs/heads/main"]
    require(len(matches) == 1, "Automation Decision Receipt workflow identity changed")
    return matches[0]


def transaction(env: dict[str, str]) -> dict[str, str]:
    issued = env_value(env, "LEASE_ISSUED_AT", POSITIVE)
    expires = env_value(env, "LEASE_EXPIRES_AT", POSITIVE)
    require(int(expires) == int(issued) + 1800,
            "Automation Decision Receipt lease expiry differs from reviewed 30-minute lifetime")
    base = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(env_value(env, "GITHUB_SHA", SHA40) == base,
            "Automation Decision Receipt event source SHA differs from leased base")
    require(env_value(env, "GITHUB_WORKFLOW_SHA", SHA40) == base,
            "Automation Decision Receipt workflow source SHA differs from leased base")
    return {
        "leaseId": env_value(env, "LEASE_ID", SHA64),
        "candidateId": env_value(env, "LEASE_CANDIDATE_ID", SHA64),
        "baseSha": base,
        "issuedAt": issued,
        "expiresAt": expires,
    }


def sha40(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be one lowercase 40-character Git SHA")
    return value


def candidate_branch(value: Any, label: str) -> str:
    require(isinstance(value, str) and CANDIDATE_BRANCH.fullmatch(value) is not None,
            f"{label} must be one content-addressed Spotlight candidate branch")
    return value


def boolean(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} must be one JSON boolean")
    return value


def validate_dispatch(effect: dict[str, Any], path: str) -> None:
    require(path == PROFILE_WORKFLOW, "Spotlight dispatch receipts must originate from Profile Stats")
    require(effect["job"] == "dispatch" and effect["outcome"] == "applied",
            "Spotlight dispatch receipt job/outcome changed")
    target = exact_object(effect["target"], {"workflowPath", "ref"}, "Spotlight dispatch target")
    require(target == {"workflowPath": SPOTLIGHT_WORKFLOW, "ref": "main"},
            "Spotlight dispatch target changed")
    observation = exact_object(effect["observation"], {"acceptedStatus"}, "Spotlight dispatch observation")
    require(observation["acceptedStatus"] == 204,
            "Spotlight dispatch must record exact HTTP 204 acceptance")


def validate_stale_cleanup(effect: dict[str, Any], path: str) -> None:
    require(path == SPOTLIGHT_WORKFLOW, "stale-candidate receipts must originate from Spotlight")
    require(effect["job"] == "reconcile" and effect["outcome"] == "applied",
            "stale-candidate receipt job/outcome changed")
    target = exact_object(effect["target"], {"candidateBranch", "headSha", "prNumber"},
                          "stale-candidate target")
    candidate_branch(target["candidateBranch"], "stale-candidate branch")
    sha40(target["headSha"], "stale-candidate head")
    pr_number = target["prNumber"]
    require(pr_number is None or (type(pr_number) is int and pr_number > 0),
            "stale-candidate PR number must be null or one positive integer")
    observation = exact_object(effect["observation"], {"prClosed", "candidateRefAbsent"},
                               "stale-candidate observation")
    pr_closed = boolean(observation["prClosed"], "stale-candidate prClosed")
    require(observation["candidateRefAbsent"] is True,
            "stale-candidate receipt requires proven candidate-ref absence")
    require((pr_number is None and not pr_closed) or (pr_number is not None and pr_closed),
            "stale-candidate PR closure result differs from PR identity")


def validate_candidate_publication(effect: dict[str, Any], path: str) -> None:
    require(path == SPOTLIGHT_WORKFLOW, "candidate-publication receipts must originate from Spotlight")
    require(effect["job"] == "propose" and effect["outcome"] in {"applied", "reused"},
            "candidate-publication receipt job/outcome changed")
    target = exact_object(effect["target"], {"candidateBranch", "headSha", "prNumber"},
                          "candidate-publication target")
    candidate_branch(target["candidateBranch"], "candidate-publication branch")
    sha40(target["headSha"], "candidate-publication head")
    positive_int(target["prNumber"], "candidate-publication PR number")
    observation = exact_object(effect["observation"], {"refCreated", "prCreated"},
                               "candidate-publication observation")
    ref_created = boolean(observation["refCreated"], "candidate-publication refCreated")
    pr_created = boolean(observation["prCreated"], "candidate-publication prCreated")
    mutated = ref_created or pr_created
    require((effect["outcome"] == "applied") == mutated,
            "candidate-publication applied/reused outcome differs from observed mutation")


def validate_approval(effect: dict[str, Any], path: str) -> None:
    require(path == SPOTLIGHT_WORKFLOW, "workflow-run approval receipts must originate from Spotlight")
    require(effect["job"] == "approve" and effect["outcome"] == "applied",
            "workflow-run approval receipt job/outcome changed")
    target = exact_object(
        effect["target"],
        {"workflowName", "workflowId", "runId", "runAttempt", "checkSuiteId"},
        "workflow-run approval target",
    )
    require(target["workflowName"] in WORKFLOW_NAMES, "workflow-run approval workflow name changed")
    for key in ("workflowId", "runId", "runAttempt", "checkSuiteId"):
        positive_int(target[key], f"workflow-run approval {key}")
    observation = exact_object(effect["observation"], {"approvalRequested"},
                               "workflow-run approval observation")
    require(observation["approvalRequested"] is True,
            "workflow-run approval receipt requires an actual approval request")


def validate_merge(effect: dict[str, Any], path: str, lease: dict[str, str]) -> None:
    require(path == SPOTLIGHT_WORKFLOW, "terminal merge receipts must originate from Spotlight")
    require(effect["job"] == "merge" and effect["outcome"] == "applied",
            "terminal merge receipt job/outcome changed")
    target = exact_object(effect["target"], {"prNumber", "candidateBranch", "headSha", "baseSha"},
                          "terminal merge target")
    positive_int(target["prNumber"], "terminal merge PR number")
    candidate_branch(target["candidateBranch"], "terminal merge candidate branch")
    sha40(target["headSha"], "terminal merge candidate head")
    require(sha40(target["baseSha"], "terminal merge base") == lease["baseSha"],
            "terminal merge base differs from leased base")
    observation = exact_object(effect["observation"], {"mergeSha", "mainSha", "candidateRefAbsent"},
                               "terminal merge observation")
    merge_sha = sha40(observation["mergeSha"], "terminal merge result SHA")
    require(sha40(observation["mainSha"], "terminal merge current main") == merge_sha,
            "terminal merge receipt must bind returned merge SHA to current main")
    require(observation["candidateRefAbsent"] is True,
            "terminal merge receipt requires proven consumed-candidate absence")


def validate_effect(effect: Any, path: str, lease: dict[str, str], ordinal: int) -> dict[str, Any]:
    item = exact_object(effect, EFFECT_KEYS, f"Automation Decision Receipt effect {ordinal}")
    require(item["ordinal"] == ordinal,
            "Automation Decision Receipt effect ordinals must be contiguous and start at one")
    require(isinstance(item["job"], str) and item["job"], "Automation Decision Receipt effect job is invalid")
    kind = item["kind"]
    require(kind in EFFECT_KINDS, f"Automation Decision Receipt effect kind is unreviewed: {kind}")
    require(item["outcome"] in {"applied", "reused"},
            "Automation Decision Receipt effect outcome is unreviewed")

    if kind == "spotlight-workflow-dispatch":
        validate_dispatch(item, path)
    elif kind == "stale-candidate-reconciliation":
        validate_stale_cleanup(item, path)
    elif kind == "spotlight-candidate-publication":
        validate_candidate_publication(item, path)
    elif kind == "workflow-run-approval-request":
        validate_approval(item, path)
    else:
        validate_merge(item, path, lease)
    return item


def effect_identity(
    effect: dict[str, Any], *, workflow_ref: str, run_id: str, run_attempt: str, lease: dict[str, str]
) -> str:
    identity = {
        "workflowRef": workflow_ref,
        "runId": run_id,
        "runAttempt": run_attempt,
        "leaseId": lease["leaseId"],
        "candidateId": lease["candidateId"],
        "effect": effect,
    }
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()


def build(state: dict[str, Any], env: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    require(env_value(env, "GITHUB_REPOSITORY") == REPOSITORY,
            "Automation Decision Receipt repository identity changed")
    path = workflow_path(env)
    workflow_ref = env_value(env, "GITHUB_WORKFLOW_REF")
    run_id = env_value(env, "GITHUB_RUN_ID", POSITIVE)
    run_attempt = env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    event = env_value(env, "GITHUB_EVENT_NAME")
    allowed_events = PROFILE_EVENTS if path == PROFILE_WORKFLOW else SPOTLIGHT_EVENTS
    require(event in allowed_events, "Automation Decision Receipt event identity changed")
    server = env_value(env, "GITHUB_SERVER_URL").rstrip("/")
    require(server == "https://github.com", "Automation Decision Receipt GitHub server identity changed")
    lease = transaction(env)
    exact_object(state, {"effects"}, "Automation Decision Receipt state")
    raw_effects = state["effects"]
    require(isinstance(raw_effects, list) and 1 <= len(raw_effects) <= 32,
            "Automation Decision Receipt must contain between one and 32 semantic effects")

    effects: list[dict[str, Any]] = []
    effect_ids: set[str] = set()
    for ordinal, raw in enumerate(raw_effects, start=1):
        effect = validate_effect(raw, path, lease, ordinal)
        effect_id = effect_identity(
            effect,
            workflow_ref=workflow_ref,
            run_id=run_id,
            run_attempt=run_attempt,
            lease=lease,
        )
        require(effect_id not in effect_ids, "Automation Decision Receipt effect identity is duplicated")
        effect_ids.add(effect_id)
        effects.append({"ordinal": ordinal, "effectId": effect_id, **{key: effect[key] for key in EFFECT_KEYS if key != "ordinal"}})

    receipt = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "workflowRef": workflow_ref,
        "run": {
            "id": run_id,
            "attempt": run_attempt,
            "event": event,
            "sourceSha": lease["baseSha"],
            "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}",
        },
        "predicateSchema": schema_identity(),
        "transaction": lease,
        "effects": effects,
        "claim": CLAIM,
    }
    receipt_sha = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    subject = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUBJECT_KIND,
        "repository": REPOSITORY,
        "workflowRef": workflow_ref,
        "run": {"id": run_id, "attempt": run_attempt},
        "transaction": {"leaseId": lease["leaseId"], "candidateId": lease["candidateId"]},
        "receiptSha256": receipt_sha,
    }
    return receipt, subject


def fixture(path: str) -> tuple[dict[str, Any], dict[str, str]]:
    base = "a" * 40
    candidate_id = "b" * 64
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{path}@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": base,
        "GITHUB_SHA": base,
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SERVER_URL": "https://github.com",
        "LEASE_ID": "c" * 64,
        "LEASE_CANDIDATE_ID": candidate_id,
        "LEASE_BASE_SHA": base,
        "LEASE_ISSUED_AT": "1000000",
        "LEASE_EXPIRES_AT": "1001800",
    }
    if path == PROFILE_WORKFLOW:
        return {
            "effects": [{
                "ordinal": 1,
                "job": "dispatch",
                "kind": "spotlight-workflow-dispatch",
                "outcome": "applied",
                "target": {"workflowPath": SPOTLIGHT_WORKFLOW, "ref": "main"},
                "observation": {"acceptedStatus": 204},
            }]
        }, env

    branch = f"automation/spotlight-links/{candidate_id}"
    return {
        "effects": [
            {
                "ordinal": 1,
                "job": "reconcile",
                "kind": "stale-candidate-reconciliation",
                "outcome": "applied",
                "target": {"candidateBranch": f"automation/spotlight-links/{'d' * 64}", "headSha": "1" * 40,
                           "prNumber": 123},
                "observation": {"prClosed": True, "candidateRefAbsent": True},
            },
            {
                "ordinal": 2,
                "job": "propose",
                "kind": "spotlight-candidate-publication",
                "outcome": "applied",
                "target": {"candidateBranch": branch, "headSha": "2" * 40, "prNumber": 124},
                "observation": {"refCreated": True, "prCreated": True},
            },
            {
                "ordinal": 3,
                "job": "approve",
                "kind": "workflow-run-approval-request",
                "outcome": "applied",
                "target": {"workflowName": "CodeQL", "workflowId": 101, "runId": 201,
                           "runAttempt": 1, "checkSuiteId": 301},
                "observation": {"approvalRequested": True},
            },
            {
                "ordinal": 4,
                "job": "merge",
                "kind": "spotlight-terminal-merge",
                "outcome": "applied",
                "target": {"prNumber": 124, "candidateBranch": branch, "headSha": "2" * 40, "baseSha": base},
                "observation": {"mergeSha": "3" * 40, "mainSha": "3" * 40, "candidateRefAbsent": True},
            },
        ]
    }, env


def expect_failure(state: dict[str, Any], env: dict[str, str], expected: str) -> None:
    try:
        build(state, env)
    except ValueError as exc:
        require(expected in str(exc), f"Automation Decision Receipt self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Automation Decision Receipt self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    for path in WORKFLOW_PATHS:
        state, env = fixture(path)
        receipt, subject = build(copy.deepcopy(state), dict(env))
        require(hashlib.sha256(canonical_bytes(receipt)).hexdigest() == subject["receiptSha256"],
                "Automation Decision Receipt subject does not bind exact receipt bytes")

    spotlight, spotlight_env = fixture(SPOTLIGHT_WORKFLOW)
    wrong_ordinal = copy.deepcopy(spotlight)
    wrong_ordinal["effects"][1]["ordinal"] = 3
    expect_failure(wrong_ordinal, dict(spotlight_env), "ordinals")

    fake_reuse = copy.deepcopy(spotlight)
    fake_reuse["effects"][1]["outcome"] = "reused"
    expect_failure(fake_reuse, dict(spotlight_env), "applied/reused")

    wrong_main = copy.deepcopy(spotlight)
    wrong_main["effects"][3]["observation"]["mainSha"] = "4" * 40
    expect_failure(wrong_main, dict(spotlight_env), "bind returned merge SHA")

    dispatch, profile_env = fixture(PROFILE_WORKFLOW)
    wrong_status = copy.deepcopy(dispatch)
    wrong_status["effects"][0]["observation"]["acceptedStatus"] = 200
    expect_failure(wrong_status, dict(profile_env), "HTTP 204")

    wrong_ttl = dict(profile_env)
    wrong_ttl["LEASE_EXPIRES_AT"] = "1001799"
    expect_failure(copy.deepcopy(dispatch), wrong_ttl, "30-minute lifetime")

    wrong_source = dict(profile_env)
    wrong_source["GITHUB_WORKFLOW_SHA"] = "f" * 40
    expect_failure(copy.deepcopy(dispatch), wrong_source, "workflow source SHA differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--subject", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Automation Decision Receipt v1 builder self-test passed")
            return 0
        require(args.state is not None and args.receipt is not None and args.subject is not None,
                "--state, --receipt, and --subject are required outside --self-test")
        state = strict_json(args.state, "Automation Decision Receipt state")
        receipt, subject = build(state, dict(os.environ))
        receipt_sha = write_canonical(args.receipt, receipt)
        subject_sha = write_canonical(args.subject, subject)
        require(subject["receiptSha256"] == receipt_sha,
                "written Automation Decision Receipt subject does not bind written receipt")
        print(json.dumps({"receiptSha256": receipt_sha, "subjectSha256": subject_sha},
                         sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
