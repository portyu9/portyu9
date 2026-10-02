#!/usr/bin/env python3
"""Closed-world contract for the deliberate Protect Main ruleset transition.

This module performs no network I/O and holds no credentials. GitHub API reads/writes
remain statically visible in the trusted workflow so the Workflow Capability BOM can
model every remote surface. This module only validates exact JSON state, compiles the
reviewed PUT payload, classifies readback, and builds non-secret reconciliation evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "ruleset-transitions-v1.json"
REPOSITORY = "portyu9/portyu9"
REPOSITORY_ID = 1355082509
RULESET_ID = 22148161
TRANSITION_ID = "protect-main-add-trusted-governed-bot-review-v1"
RECOVERY_ID = "trusted-capability-admission-recovery-v1"
METHOD = "PUT"
ENDPOINT = "repos/portyu9/portyu9/rulesets/22148161"
EXPECTED_RULE_TYPES = ("deletion", "non_fast_forward", "pull_request", "required_status_checks")
EXPECTED_PR_KEYS = {
    "required_approving_review_count",
    "dismiss_stale_reviews_on_push",
    "required_reviewers",
    "require_code_owner_review",
    "require_last_push_approval",
    "required_review_thread_resolution",
    "require_extra_approval_for_unattributed_changes",
    "allowed_merge_methods",
}
EXPECTED_STATUS_KEYS = {
    "strict_required_status_checks_policy",
    "do_not_enforce_on_create",
    "required_status_checks",
}
EXPECTED_CHECK_KEYS = {"context", "integration_id"}
EXPECTED_CONTEXT_ORDER = (
    "validate-contracts",
    "trusted-capability-admission",
    "trusted-governed-bot-review",
    "integration-pinned-upstream",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
)
EXPECTED_CONTEXTS = frozenset(EXPECTED_CONTEXT_ORDER)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RECOVERY_CONTEXT = re.compile(
    r"^trusted-control-plane-recovery/r([1-9][0-9]*)-a([1-9][0-9]*)-([0-9a-f]{12})$"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def exact_int(value: Any, expected: int | None = None) -> int:
    require(type(value) is int, "expected exact JSON integer")
    if expected is not None:
        require(value == expected, f"integer differs from reviewed value: {value!r}")
    return value


def normalize_payload(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "ruleset payload must be an object")
    require(
        set(value) == {"name", "target", "enforcement", "bypass_actors", "conditions", "rules"},
        "ruleset payload top-level field inventory changed",
    )
    require(value["name"] == "Protect Main", "ruleset payload name changed")
    require(value["target"] == "branch", "ruleset payload target changed")
    require(value["enforcement"] == "active", "ruleset payload enforcement changed")
    require(value["bypass_actors"] == [], "ruleset payload must contain no bypass actors")

    conditions = value["conditions"]
    require(isinstance(conditions, dict) and set(conditions) == {"ref_name"}, "ruleset conditions changed")
    ref_name = conditions["ref_name"]
    require(isinstance(ref_name, dict) and set(ref_name) == {"include", "exclude"}, "ruleset ref_name condition changed")
    require(ref_name["include"] == ["~DEFAULT_BRANCH"] and ref_name["exclude"] == [], "ruleset target refs changed")

    rules = value["rules"]
    require(isinstance(rules, list) and len(rules) == len(EXPECTED_RULE_TYPES), "ruleset rule count changed")
    observed: dict[str, dict[str, Any]] = {}
    for rule in rules:
        require(isinstance(rule, dict), "ruleset rule must be an object")
        rule_type = rule.get("type")
        require(isinstance(rule_type, str) and rule_type not in observed, "ruleset rule identity malformed/duplicated")
        observed[rule_type] = rule
    require(set(observed) == set(EXPECTED_RULE_TYPES), "ruleset rule inventory changed")

    for rule_type in ("deletion", "non_fast_forward"):
        require(set(observed[rule_type]) == {"type"}, f"{rule_type} rule gained parameters")

    pr = observed["pull_request"]
    require(set(pr) == {"type", "parameters"}, "pull_request rule shape changed")
    params = pr["parameters"]
    require(isinstance(params, dict) and set(params) == EXPECTED_PR_KEYS, "pull_request parameter inventory changed")
    exact_int(params["required_approving_review_count"], 0)
    for key in (
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "require_extra_approval_for_unattributed_changes",
    ):
        require(type(params[key]) is bool and params[key] is False, f"pull_request boolean changed: {key}")
    require(
        type(params["required_review_thread_resolution"]) is bool
        and params["required_review_thread_resolution"] is True,
        "review thread resolution changed",
    )
    require(params["required_reviewers"] == [], "required reviewers changed")
    require(params["allowed_merge_methods"] == ["merge"], "merge method contract changed")

    status = observed["required_status_checks"]
    require(set(status) == {"type", "parameters"}, "required_status_checks rule shape changed")
    status_params = status["parameters"]
    require(
        isinstance(status_params, dict) and set(status_params) == EXPECTED_STATUS_KEYS,
        "required_status_checks parameter inventory changed",
    )
    require(
        type(status_params["strict_required_status_checks_policy"]) is bool
        and status_params["strict_required_status_checks_policy"] is True,
        "strict required status policy changed",
    )
    require(
        type(status_params["do_not_enforce_on_create"]) is bool
        and status_params["do_not_enforce_on_create"] is False,
        "status checks create policy changed",
    )
    checks = status_params["required_status_checks"]
    require(isinstance(checks, list) and checks, "required status check inventory missing")
    names: set[str] = set()
    for check in checks:
        require(isinstance(check, dict) and set(check) == EXPECTED_CHECK_KEYS, "required status check shape changed")
        context = check.get("context")
        require(isinstance(context, str) and context and context not in names, "required status context malformed/duplicated")
        names.add(context)
        exact_int(check.get("integration_id"), 15368)
    require(names <= EXPECTED_CONTEXTS, "required status context inventory contains unreviewed identity")

    # GitHub does not define semantic ordering for rules or required-status entries and
    # may return the same ruleset in a different array order than it was submitted.
    # Canonicalize those arrays before hashing while preserving exact closed-world
    # identities, primitive types, parameters, and membership.
    canonical = json.loads(json.dumps(value))
    canonical_rules = {rule["type"]: rule for rule in canonical["rules"]}
    canonical["rules"] = [canonical_rules[rule_type] for rule_type in EXPECTED_RULE_TYPES]
    canonical_checks = canonical_rules["required_status_checks"]["parameters"]["required_status_checks"]
    canonical_checks.sort(key=lambda check: EXPECTED_CONTEXT_ORDER.index(check["context"]))
    return canonical


def load_contract() -> dict[str, Any]:
    payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
    require(isinstance(payload, dict), "transition contract root must be an object")
    exact_int(payload.get("schemaVersion"), 1)
    require(payload.get("repository") == REPOSITORY, "transition repository changed")
    exact_int(payload.get("repositoryId"), REPOSITORY_ID)
    transitions = payload.get("transitions")
    require(isinstance(transitions, list) and len(transitions) == 1,
            "transition inventory must contain exactly one reviewed transition")
    transition = transitions[0]
    require(isinstance(transition, dict), "transition entry must be an object")
    require(transition.get("id") == TRANSITION_ID, "transition id changed")
    exact_int(transition.get("rulesetId"), RULESET_ID)
    require(transition.get("rulesetName") == "Protect Main", "ruleset name changed")
    require(transition.get("method") == METHOD, "ruleset transition method changed")
    require(transition.get("endpoint") == ENDPOINT, "ruleset transition endpoint changed")
    predecessor = transition.get("predecessor")
    successor = transition.get("successor")
    require(isinstance(predecessor, dict) and isinstance(successor, dict), "transition states must be objects")
    require(transition.get("predecessorDigest") == sha256(predecessor), "predecessor digest is stale")
    require(transition.get("successorDigest") == sha256(successor), "successor digest is stale")
    core = {
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "rulesetId": RULESET_ID,
        "method": METHOD,
        "endpoint": ENDPOINT,
        "predecessorDigest": transition["predecessorDigest"],
        "successorDigest": transition["successorDigest"],
    }
    require(transition.get("transitionDigest") == sha256(core), "transition digest is stale")
    normalize_payload(predecessor)
    normalize_payload(successor)
    require(predecessor != successor, "reviewed predecessor/successor unexpectedly identical")
    return transition


def normalize_live(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "live ruleset detail must be an object")
    exact_int(value.get("id"), RULESET_ID)
    payload = {
        "name": value.get("name"),
        "target": value.get("target"),
        "enforcement": value.get("enforcement"),
        "bypass_actors": value.get("bypass_actors"),
        "conditions": value.get("conditions"),
        "rules": value.get("rules"),
    }
    return normalize_payload(payload)


def classify(value: Any, transition: dict[str, Any]) -> tuple[str, str]:
    normalized = normalize_live(value)
    digest = sha256(normalized)
    if digest == transition["predecessorDigest"]:
        return "predecessor", digest
    if digest == transition["successorDigest"]:
        return "successor", digest
    raise ValueError(f"live Protect Main state is outside the reviewed transition envelope: {digest}")

def classify_observable(value: Any, transition: dict[str, Any]) -> tuple[str, str, bool]:
    """Classify observable state without treating a redacted bypass list as an exact empty list.

    Planning may establish a predecessor/successor hint when the ordinary Actions
    token does not expose bypass_actors. The administration-scope writer must still
    call classify() on its exact live response before any mutation.
    """
    require(isinstance(value, dict), "live ruleset detail must be an object")
    exact_int(value.get("id"), RULESET_ID)
    bypass = value.get("bypass_actors")
    if isinstance(bypass, list):
        state, digest = classify(value, transition)
        return state, digest, True

    projected = {
        "id": value.get("id"),
        "name": value.get("name"),
        "target": value.get("target"),
        "enforcement": value.get("enforcement"),
        "bypass_actors": [],
        "conditions": value.get("conditions"),
        "rules": value.get("rules"),
    }
    state, digest = classify(projected, transition)
    return state, digest, False



def require_sha40(value: str, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None, f"{label} malformed")
    return value


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _status_rule(payload: dict[str, Any]) -> dict[str, Any]:
    matches = [rule for rule in payload["rules"] if rule.get("type") == "required_status_checks"]
    require(len(matches) == 1, "ruleset must contain exactly one required_status_checks rule")
    return matches[0]


def load_recovery_contract(transition: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
    recovery = payload.get("recovery")
    require(isinstance(recovery, dict), "recovery contract must be an object")
    require(
        set(recovery) == {
            "id", "rulesetId", "rulesetName", "method", "endpoint", "normalDigest",
            "brokenContext", "integrationId", "contextPrefix", "contextPattern",
            "leaseSeconds", "watchdogMaxAgeSeconds", "allowedChangedPaths",
            "allowedProtectedChangedPaths", "survivingContexts",
        },
        "recovery contract field inventory changed",
    )
    require(recovery["id"] == RECOVERY_ID, "recovery id changed")
    exact_int(recovery["rulesetId"], RULESET_ID)
    require(recovery["rulesetName"] == "Protect Main", "recovery ruleset name changed")
    require(recovery["method"] == METHOD and recovery["endpoint"] == ENDPOINT,
            "recovery mutation endpoint changed")
    require(recovery["normalDigest"] == transition["successorDigest"],
            "recovery normal digest diverged from historical successor")
    require(recovery["brokenContext"] == "trusted-capability-admission",
            "recoverable context changed")
    exact_int(recovery["integrationId"], 15368)
    require(recovery["contextPrefix"] == "trusted-control-plane-recovery",
            "recovery context prefix changed")
    require(recovery["contextPattern"] == RECOVERY_CONTEXT.pattern,
            "recovery context grammar changed")
    exact_int(recovery["leaseSeconds"], 600)
    exact_int(recovery["watchdogMaxAgeSeconds"], 900)
    require(
        recovery["allowedChangedPaths"] == [
            ".github/workflows/capability-admission.yml",
            "scripts/capability_admission_workflow_contract.py",
        ],
        "recovery changed-path scope changed",
    )
    require(
        recovery["allowedProtectedChangedPaths"] == [".github/workflows/capability-admission.yml"],
        "recovery protected-source scope changed",
    )
    require(
        recovery["survivingContexts"] == [
            "validate-contracts",
            "trusted-governed-bot-review",
            "integration-pinned-upstream",
            "dependency-review",
            "analyze-actions",
            "analyze-python",
        ],
        "recovery surviving-context inventory changed",
    )
    return recovery


def recovery_context(run_id: int, run_attempt: int, head_sha: str) -> str:
    exact_int(run_id)
    exact_int(run_attempt)
    require(run_id > 0 and run_attempt > 0, "recovery run identity malformed")
    require_sha40(head_sha, "recovery head SHA")
    value = f"trusted-control-plane-recovery/r{run_id}-a{run_attempt}-{head_sha[:12]}"
    require(len(value) <= 100 and RECOVERY_CONTEXT.fullmatch(value) is not None,
            "derived recovery context violates frozen grammar")
    return value


def recovery_temporary_payload(
    transition: dict[str, Any],
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> dict[str, Any]:
    normal = json.loads(json.dumps(transition["successor"]))
    checks = _status_rule(normal)["parameters"]["required_status_checks"]
    matches = [check for check in checks if check["context"] == "trusted-capability-admission"]
    require(len(matches) == 1, "normal ruleset lost exact recoverable context")
    matches[0]["context"] = recovery_context(run_id, run_attempt, head_sha)
    return normal


def _normalize_recovery_temporary(value: Any, recovery: dict[str, Any]) -> tuple[dict[str, Any], str]:
    require(isinstance(value, dict), "temporary ruleset payload must be an object")
    projected = json.loads(json.dumps(value))
    rules = projected.get("rules")
    require(isinstance(rules, list), "temporary ruleset rules are malformed")
    status = [rule for rule in rules if isinstance(rule, dict) and rule.get("type") == "required_status_checks"]
    require(len(status) == 1, "temporary ruleset status rule changed")
    checks = status[0].get("parameters", {}).get("required_status_checks")
    require(isinstance(checks, list) and len(checks) == 7, "temporary required-check count changed")
    dynamic = []
    for check in checks:
        require(isinstance(check, dict) and set(check) == EXPECTED_CHECK_KEYS,
                "temporary required-check shape changed")
        exact_int(check.get("integration_id"), 15368)
        context = check.get("context")
        require(isinstance(context, str) and context, "temporary context malformed")
        if context not in EXPECTED_CONTEXTS:
            dynamic.append(context)
    require(len(dynamic) == 1 and RECOVERY_CONTEXT.fullmatch(dynamic[0]) is not None,
            "temporary ruleset must contain exactly one frozen recovery context")
    contexts = {check["context"] for check in checks}
    require(
        contexts == (EXPECTED_CONTEXTS - {"trusted-capability-admission"}) | {dynamic[0]},
        "temporary required-check inventory changed",
    )
    for check in checks:
        if check["context"] == dynamic[0]:
            check["context"] = "trusted-capability-admission"
    normalized_normal = normalize_payload(projected)
    require(sha256(normalized_normal) == recovery["normalDigest"],
            "temporary state changes fields beyond the admission-context substitution")
    temporary = json.loads(json.dumps(normalized_normal))
    for check in _status_rule(temporary)["parameters"]["required_status_checks"]:
        if check["context"] == "trusted-capability-admission":
            check["context"] = dynamic[0]
    return temporary, dynamic[0]


def _recovery_live_payload(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "live ruleset detail must be an object")
    exact_int(value.get("id"), RULESET_ID)
    return {
        "name": value.get("name"),
        "target": value.get("target"),
        "enforcement": value.get("enforcement"),
        "bypass_actors": value.get("bypass_actors"),
        "conditions": value.get("conditions"),
        "rules": value.get("rules"),
    }


def _project_recovery_observable(value: Any) -> tuple[dict[str, Any], bool]:
    require(isinstance(value, dict), "live ruleset detail must be an object")
    bypass = value.get("bypass_actors")
    if isinstance(bypass, list):
        return value, True
    projected = json.loads(json.dumps(value))
    projected["bypass_actors"] = []
    return projected, False


def classify_recovery_exact(
    value: Any,
    transition: dict[str, Any],
    recovery: dict[str, Any],
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> tuple[str, str, str, str]:
    payload = _recovery_live_payload(value)
    context = recovery_context(run_id, run_attempt, head_sha)
    temporary = recovery_temporary_payload(transition, run_id, run_attempt, head_sha)
    temporary_digest = sha256(temporary)
    try:
        normal = normalize_payload(payload)
    except ValueError:
        normalized, observed_context = _normalize_recovery_temporary(payload, recovery)
        digest = sha256(normalized)
        require(observed_context == context and digest == temporary_digest,
                "live Protect Main state is outside the exact recovery transaction")
        return "temporary", digest, context, temporary_digest
    digest = sha256(normal)
    require(digest == recovery["normalDigest"],
            "live Protect Main state is outside the exact recovery transaction")
    return "normal", digest, context, temporary_digest


def classify_recovery_observable_exact(
    value: Any,
    transition: dict[str, Any],
    recovery: dict[str, Any],
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> tuple[str, str, str, str, bool]:
    projected, observable = _project_recovery_observable(value)
    state, digest, context, temporary_digest = classify_recovery_exact(
        projected, transition, recovery, run_id, run_attempt, head_sha
    )
    return state, digest, context, temporary_digest, observable


def classify_recovery_shape(
    value: Any,
    transition: dict[str, Any],
    recovery: dict[str, Any],
    *,
    observable: bool = False,
) -> dict[str, Any]:
    bypass_observable = True
    if observable:
        value, bypass_observable = _project_recovery_observable(value)
    payload = _recovery_live_payload(value)
    try:
        normal = normalize_payload(payload)
        digest = sha256(normal)
        require(digest == recovery["normalDigest"], "normal recovery state digest changed")
        return {"state": "normal", "digest": digest, "bypassActorsObservable": bypass_observable}
    except ValueError:
        temporary, context = _normalize_recovery_temporary(payload, recovery)
        match = RECOVERY_CONTEXT.fullmatch(context)
        require(match is not None, "temporary-shape context violates frozen grammar")
        return {
            "state": "temporary-shape",
            "digest": sha256(temporary),
            "transactionContext": context,
            "originRunId": int(match.group(1)),
            "originRunAttempt": int(match.group(2)),
            "headPrefix": match.group(3),
            "bypassActorsObservable": bypass_observable,
        }


def recovery_transition_digest(
    direction: str,
    normal_digest: str,
    temporary_digest: str,
    transaction_context: str,
) -> str:
    require(direction in {"open", "close", "watchdog-close"},
            "recovery transition direction changed")
    return sha256({
        "recoveryId": RECOVERY_ID,
        "direction": direction,
        "rulesetId": RULESET_ID,
        "method": METHOD,
        "endpoint": ENDPOINT,
        "normalDigest": normal_digest,
        "temporaryDigest": temporary_digest,
        "transactionContext": transaction_context,
    })


def recovery_transition_receipt(
    *,
    direction: str,
    before: Any,
    after: Any,
    transition: dict[str, Any],
    recovery: dict[str, Any],
    trusted_main_sha: str,
    run_id: int,
    run_attempt: int,
    candidate_pr: int,
    candidate_head_sha: str,
    check_id: int,
    issued_at: int,
    expires_at: int,
    write_status: int,
) -> dict[str, Any]:
    require(direction in {"open", "close"}, "transaction receipt direction changed")
    require_sha40(trusted_main_sha, "trusted main SHA")
    require_sha40(candidate_head_sha, "candidate head SHA")
    exact_int(candidate_pr)
    exact_int(check_id)
    require(candidate_pr > 0 and check_id > 0, "recovery PR/check identity malformed")
    require(issued_at > 0 and expires_at > issued_at
            and expires_at - issued_at <= recovery["leaseSeconds"],
            "recovery transaction validity window malformed")
    require(write_status >= 0, "write status malformed")
    before_state, before_digest, context, temporary_digest = classify_recovery_exact(
        before, transition, recovery, run_id, run_attempt, candidate_head_sha
    )
    after_state, after_digest, after_context, after_temp = classify_recovery_exact(
        after, transition, recovery, run_id, run_attempt, candidate_head_sha
    )
    require(context == after_context and temporary_digest == after_temp,
            "recovery transition identity changed across readback")
    if direction == "open":
        require(before_state == "normal" and after_state == "temporary",
                "open receipt requires exact normal -> temporary transition")
    else:
        require(before_state == "temporary" and after_state == "normal",
                "close receipt requires exact temporary -> normal transition")
    outcome = "applied" if write_status == 0 else "ambiguous-response-readback-applied"
    return {
        "schemaVersion": 1,
        "receiptKind": "control-plane-recovery-transition-v1",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "workflow": ".github/workflows/ruleset-reconciler.yml",
        "trustedMainSha": trusted_main_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
        "rulesetId": RULESET_ID,
        "endpoint": ENDPOINT,
        "method": METHOD,
        "recoveryId": RECOVERY_ID,
        "direction": direction,
        "candidatePr": candidate_pr,
        "candidateHeadSha": candidate_head_sha,
        "transactionContext": context,
        "checkId": check_id,
        "normalDigest": recovery["normalDigest"],
        "temporaryDigest": temporary_digest,
        "transitionDigest": recovery_transition_digest(
            direction, recovery["normalDigest"], temporary_digest, context
        ),
        "predecessorDigest": before_digest,
        "successorDigest": after_digest,
        "issuedAtEpoch": issued_at,
        "expiresAtEpoch": expires_at,
        "writeStatus": write_status,
        "outcome": outcome,
    }


def recovery_watchdog_receipt(
    *,
    before: Any,
    after: Any,
    transition: dict[str, Any],
    recovery: dict[str, Any],
    trusted_main_sha: str,
    run_id: int,
    run_attempt: int,
    issued_at: int,
    write_status: int,
) -> dict[str, Any]:
    require_sha40(trusted_main_sha, "watchdog trusted main SHA")
    shape = classify_recovery_shape(before, transition, recovery)
    after_shape = classify_recovery_shape(after, transition, recovery)
    require(shape["state"] == "temporary-shape" and after_shape["state"] == "normal",
            "watchdog receipt requires exact temporary-shape -> normal")
    require(run_id > 0 and run_attempt > 0 and issued_at > 0 and write_status >= 0,
            "watchdog receipt identity/timing malformed")
    outcome = "applied" if write_status == 0 else "ambiguous-response-readback-applied"
    return {
        "schemaVersion": 1,
        "receiptKind": "control-plane-recovery-watchdog-v1",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "workflow": ".github/workflows/ruleset-reconciler.yml",
        "trustedMainSha": trusted_main_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
        "rulesetId": RULESET_ID,
        "endpoint": ENDPOINT,
        "method": METHOD,
        "recoveryId": RECOVERY_ID,
        "direction": "watchdog-close",
        "originRunId": shape["originRunId"],
        "originRunAttempt": shape["originRunAttempt"],
        "headPrefix": shape["headPrefix"],
        "transactionContext": shape["transactionContext"],
        "normalDigest": recovery["normalDigest"],
        "temporaryDigest": shape["digest"],
        "transitionDigest": recovery_transition_digest(
            "watchdog-close", recovery["normalDigest"], shape["digest"], shape["transactionContext"]
        ),
        "predecessorDigest": shape["digest"],
        "successorDigest": after_shape["digest"],
        "issuedAtEpoch": issued_at,
        "writeStatus": write_status,
        "outcome": outcome,
    }


def recovery_result_receipt(
    *,
    trusted_main_sha: str,
    run_id: int,
    run_attempt: int,
    candidate_pr: int,
    candidate_head_sha: str,
    check_id: int,
    transaction_context: str,
    merged: bool,
    merge_sha: str | None,
    open_receipt_sha256: str,
    restore_receipt_sha256: str,
) -> dict[str, Any]:
    require_sha40(trusted_main_sha, "result trusted main SHA")
    require_sha40(candidate_head_sha, "result candidate head SHA")
    require(type(merged) is bool, "result merged flag malformed")
    require(candidate_pr > 0 and check_id > 0 and run_id > 0 and run_attempt > 0,
            "result recovery identity malformed")
    require(RECOVERY_CONTEXT.fullmatch(transaction_context) is not None,
            "result transaction context malformed")
    require(SHA256.fullmatch(open_receipt_sha256) is not None,
            "open receipt digest malformed")
    require(SHA256.fullmatch(restore_receipt_sha256) is not None,
            "restore receipt digest malformed")
    if merged:
        require(isinstance(merge_sha, str) and SHA40.fullmatch(merge_sha) is not None,
                "merged result requires exact merge SHA")
    else:
        require(merge_sha in {None, ""}, "unmerged result must not carry merge SHA")
    return {
        "schemaVersion": 1,
        "receiptKind": "control-plane-recovery-result-v1",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "workflow": ".github/workflows/ruleset-reconciler.yml",
        "trustedMainSha": trusted_main_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
        "recoveryId": RECOVERY_ID,
        "candidatePr": candidate_pr,
        "candidateHeadSha": candidate_head_sha,
        "transactionContext": transaction_context,
        "checkId": check_id,
        "merged": merged,
        "mergeSha": merge_sha or None,
        "openReceiptSha256": open_receipt_sha256,
        "restoreReceiptSha256": restore_receipt_sha256,
    }


def evaluate_recovery_candidate(
    *,
    candidate_root: Path,
    changed_paths: Path,
    candidate_tree_sha: str,
) -> dict[str, Any]:
    require_sha40(candidate_tree_sha, "candidate tree SHA")
    lines = [line.strip() for line in changed_paths.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(lines == sorted(set(lines)), "candidate changed-path list must be canonical and unique")
    transition = load_contract()
    recovery = load_recovery_contract(transition)
    require(lines == recovery["allowedChangedPaths"],
            "recovery candidate changed-path scope differs from reviewed V1 scope")

    import trusted_workflow_capability
    import workflow_capability_diff
    import workflow_capability_tcb

    candidate_root = candidate_root.resolve(strict=True)
    base_bom = trusted_workflow_capability.compile_repository(ROOT)
    candidate_bom = trusted_workflow_capability.compile_repository(candidate_root)
    semantic = workflow_capability_diff.semantic_diff(base_bom, candidate_bom)
    require(semantic["expansions"] == [] and semantic["reductions"] == [],
            "recovery candidate changes modeled Workflow Capability semantics")

    base_protected = workflow_capability_tcb.protected_files(ROOT)
    candidate_protected = workflow_capability_tcb.protected_files(candidate_root)
    changed_protected = sorted(
        path for path in set(base_protected) | set(candidate_protected)
        if base_protected.get(path) != candidate_protected.get(path)
    )
    require(changed_protected == recovery["allowedProtectedChangedPaths"],
            "recovery candidate protected-source diff differs from reviewed V1 scope")
    for relative in recovery["allowedChangedPaths"]:
        candidate_path = candidate_root / relative
        base_path = ROOT / relative
        require(candidate_path.is_file() and not candidate_path.is_symlink(),
                f"recovery candidate path missing/aliased: {relative}")
        require(candidate_path.read_bytes() != base_path.read_bytes(),
                f"recovery candidate path is byte-identical to accepted main: {relative}")

    return {
        "schemaVersion": 1,
        "recoveryId": RECOVERY_ID,
        "candidateTreeSha": candidate_tree_sha,
        "baseBomSha256": semantic["baseBomSha256"],
        "candidateBomSha256": semantic["candidateBomSha256"],
        "expansions": semantic["expansions"],
        "reductions": semantic["reductions"],
        "changedPaths": lines,
        "changedProtectedPaths": changed_protected,
    }


def recovery_self_test(transition: dict[str, Any]) -> None:
    recovery = load_recovery_contract(transition)
    context = recovery_context(123, 2, "a" * 40)
    require(context == "trusted-control-plane-recovery/r123-a2-" + "a" * 12,
            "recovery context derivation changed")
    temporary = recovery_temporary_payload(transition, 123, 2, "a" * 40)
    normal = transition["successor"]
    normal_checks = _status_rule(normal)["parameters"]["required_status_checks"]
    temporary_checks = _status_rule(temporary)["parameters"]["required_status_checks"]
    require(len(normal_checks) == len(temporary_checks) == 7,
            "recovery substitution changed check count")
    require(
        [(a["context"], b["context"]) for a, b in zip(normal_checks, temporary_checks) if a != b]
        == [("trusted-capability-admission", context)],
        "recovery temporary state changed more than the admission context",
    )
    temp_live = {"id": RULESET_ID, **temporary}
    state, digest, observed_context, temp_digest = classify_recovery_exact(
        temp_live, transition, recovery, 123, 2, "a" * 40
    )
    require(state == "temporary" and digest == temp_digest and observed_context == context,
            "exact temporary recovery classification changed")
    shape = classify_recovery_shape(temp_live, transition, recovery)
    require(
        shape["state"] == "temporary-shape"
        and shape["originRunId"] == 123
        and shape["originRunAttempt"] == 2
        and shape["headPrefix"] == "a" * 12,
        "temporary-shape watchdog classifier changed",
    )
    try:
        classify_recovery_exact(temp_live, transition, recovery, 124, 2, "a" * 40)
    except ValueError:
        pass
    else:
        raise ValueError("stale recovery transaction context was accepted")
    bad = json.loads(json.dumps(temporary))
    _status_rule(bad)["parameters"]["required_status_checks"][1]["integration_id"] = 1
    try:
        classify_recovery_shape({"id": RULESET_ID, **bad}, transition, recovery)
    except ValueError:
        pass
    else:
        raise ValueError("recovery classifier accepted integration-id drift")

def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def expect_classification_failure(value: dict[str, Any], transition: dict[str, Any], label: str) -> None:
    try:
        classify(value, transition)
    except ValueError:
        return
    raise ValueError(f"self-test accepted forbidden ruleset state: {label}")


def self_test() -> None:
    transition = load_contract()
    predecessor = json.loads(json.dumps(transition["predecessor"]))
    successor = json.loads(json.dumps(transition["successor"]))
    require(classify({"id": RULESET_ID, **predecessor}, transition)[0] == "predecessor",
            "predecessor classification changed")
    require(classify({"id": RULESET_ID, **successor}, transition)[0] == "successor",
            "successor classification changed")

    # GitHub's live Protect Main currently returns the exact predecessor checks in
    # this semantically equivalent order. The reconciler must not mistake ordering
    # drift for control-plane drift.
    reordered_predecessor = json.loads(json.dumps(predecessor))
    predecessor_checks = reordered_predecessor["rules"][3]["parameters"]["required_status_checks"]
    predecessor_checks[:] = [predecessor_checks[index] for index in (0, 2, 4, 5, 3, 1)]
    state, digest = classify({"id": RULESET_ID, **reordered_predecessor}, transition)
    require(state == "predecessor" and digest == transition["predecessorDigest"],
            "live-order predecessor canonicalization changed")

    reordered_successor = json.loads(json.dumps(successor))
    reordered_successor["rules"].reverse()
    status_rule = next(rule for rule in reordered_successor["rules"] if rule["type"] == "required_status_checks")
    status_rule["parameters"]["required_status_checks"].reverse()
    state, digest = classify({"id": RULESET_ID, **reordered_successor}, transition)
    require(state == "successor" and digest == transition["successorDigest"],
            "rules/check ordering canonicalization changed")

    redacted_predecessor = {"id": RULESET_ID, **json.loads(json.dumps(predecessor))}
    redacted_predecessor.pop("bypass_actors")
    state, digest, bypass_observable = classify_observable(redacted_predecessor, transition)
    require(state == "predecessor" and digest == transition["predecessorDigest"] and not bypass_observable,
            "read-only predecessor classification changed")

    redacted_successor = {"id": RULESET_ID, **json.loads(json.dumps(successor))}
    redacted_successor["bypass_actors"] = None
    state, digest, bypass_observable = classify_observable(redacted_successor, transition)
    require(state == "successor" and digest == transition["successorDigest"] and not bypass_observable,
            "read-only successor classification changed")

    expect_classification_failure({"id": RULESET_ID + 1, **predecessor}, transition, "wrong ruleset id")

    mutated = json.loads(json.dumps(predecessor))
    mutated["enforcement"] = "disabled"
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "enforcement downgrade")

    mutated = json.loads(json.dumps(predecessor))
    mutated["target"] = "tag"
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "target change")

    mutated = json.loads(json.dumps(predecessor))
    mutated["conditions"]["ref_name"]["include"] = ["refs/heads/release"]
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "include change")

    mutated = json.loads(json.dumps(predecessor))
    mutated["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "exclude change")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][2]["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "merge-method broadening")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][2]["parameters"]["required_review_thread_resolution"] = False
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "pull-request rule change")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][2]["parameters"]["required_approving_review_count"] = False
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "malformed integer primitive")

    mutated = json.loads(json.dumps(predecessor))
    mutated["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "bypass actor addition")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][3]["parameters"]["required_status_checks"][0]["integration_id"] = 1
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "wrong integration id")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][3]["parameters"]["required_status_checks"][0]["integration_id"] = True
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "malformed integration primitive")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][3]["parameters"]["required_status_checks"].pop()
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "required context removal")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][3]["parameters"]["required_status_checks"][0]["context"] = "unexpected-context"
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "required context substitution")

    mutated = json.loads(json.dumps(predecessor))
    checks = mutated["rules"][3]["parameters"]["required_status_checks"]
    checks.append(json.loads(json.dumps(checks[0])))
    expect_classification_failure({"id": RULESET_ID, **mutated}, transition, "duplicate required context")

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--transition-digest", required=True)

    classify_cmd = sub.add_parser("classify")
    classify_cmd.add_argument("--live", required=True, type=Path)

    observable_cmd = sub.add_parser("classify-observable")
    observable_cmd.add_argument("--live", required=True, type=Path)

    emit = sub.add_parser("emit-put")
    emit.add_argument("--transition-digest", required=True)
    emit.add_argument("--output", required=True, type=Path)

    receipt = sub.add_parser("receipt")
    receipt.add_argument("--before", required=True, type=Path)
    receipt.add_argument("--after", required=True, type=Path)
    receipt.add_argument("--trusted-main-sha", required=True)
    receipt.add_argument("--run-id", required=True, type=int)
    receipt.add_argument("--run-attempt", required=True, type=int)
    receipt.add_argument("--issued-at", required=True, type=int)
    receipt.add_argument("--expires-at", required=True, type=int)
    receipt.add_argument("--write-status", required=True, type=int)
    receipt.add_argument("--output", required=True, type=Path)


    context = sub.add_parser("recovery-context")
    context.add_argument("--run-id", required=True, type=int)
    context.add_argument("--run-attempt", required=True, type=int)
    context.add_argument("--head-sha", required=True)

    recovery_classify = sub.add_parser("recovery-classify")
    recovery_classify.add_argument("--live", required=True, type=Path)
    recovery_classify.add_argument("--run-id", required=True, type=int)
    recovery_classify.add_argument("--run-attempt", required=True, type=int)
    recovery_classify.add_argument("--head-sha", required=True)
    recovery_classify.add_argument("--observable", action="store_true")

    shape = sub.add_parser("recovery-classify-shape")
    shape.add_argument("--live", required=True, type=Path)
    shape.add_argument("--observable", action="store_true")

    open_emit = sub.add_parser("recovery-emit-open")
    open_emit.add_argument("--run-id", required=True, type=int)
    open_emit.add_argument("--run-attempt", required=True, type=int)
    open_emit.add_argument("--head-sha", required=True)
    open_emit.add_argument("--output", required=True, type=Path)

    close_emit = sub.add_parser("recovery-emit-close")
    close_emit.add_argument("--output", required=True, type=Path)

    candidate = sub.add_parser("recovery-evaluate-candidate")
    candidate.add_argument("--candidate-root", required=True, type=Path)
    candidate.add_argument("--changed-paths", required=True, type=Path)
    candidate.add_argument("--candidate-tree-sha", required=True)
    candidate.add_argument("--output", required=True, type=Path)

    recovery_receipt = sub.add_parser("recovery-transition-receipt")
    recovery_receipt.add_argument("--direction", choices=("open", "close"), required=True)
    recovery_receipt.add_argument("--before", required=True, type=Path)
    recovery_receipt.add_argument("--after", required=True, type=Path)
    recovery_receipt.add_argument("--trusted-main-sha", required=True)
    recovery_receipt.add_argument("--run-id", required=True, type=int)
    recovery_receipt.add_argument("--run-attempt", required=True, type=int)
    recovery_receipt.add_argument("--candidate-pr", required=True, type=int)
    recovery_receipt.add_argument("--candidate-head-sha", required=True)
    recovery_receipt.add_argument("--check-id", required=True, type=int)
    recovery_receipt.add_argument("--issued-at", required=True, type=int)
    recovery_receipt.add_argument("--expires-at", required=True, type=int)
    recovery_receipt.add_argument("--write-status", required=True, type=int)
    recovery_receipt.add_argument("--output", required=True, type=Path)

    watchdog = sub.add_parser("recovery-watchdog-receipt")
    watchdog.add_argument("--before", required=True, type=Path)
    watchdog.add_argument("--after", required=True, type=Path)
    watchdog.add_argument("--trusted-main-sha", required=True)
    watchdog.add_argument("--run-id", required=True, type=int)
    watchdog.add_argument("--run-attempt", required=True, type=int)
    watchdog.add_argument("--issued-at", required=True, type=int)
    watchdog.add_argument("--write-status", required=True, type=int)
    watchdog.add_argument("--output", required=True, type=Path)

    result_cmd = sub.add_parser("recovery-result-receipt")
    result_cmd.add_argument("--trusted-main-sha", required=True)
    result_cmd.add_argument("--run-id", required=True, type=int)
    result_cmd.add_argument("--run-attempt", required=True, type=int)
    result_cmd.add_argument("--candidate-pr", required=True, type=int)
    result_cmd.add_argument("--candidate-head-sha", required=True)
    result_cmd.add_argument("--check-id", required=True, type=int)
    result_cmd.add_argument("--transaction-context", required=True)
    result_cmd.add_argument("--merged", choices=("true", "false"), required=True)
    result_cmd.add_argument("--merge-sha")
    result_cmd.add_argument("--open-receipt-sha256", required=True)
    result_cmd.add_argument("--restore-receipt-sha256", required=True)
    result_cmd.add_argument("--output", required=True, type=Path)
    return result


def require_transition_digest(transition: dict[str, Any], supplied: str) -> None:
    require(supplied == transition["transitionDigest"],
            "workflow-dispatch transition digest does not match reviewed source")


def main() -> int:
    try:
        args = parser().parse_args()
        transition = load_contract()
        self_test()
        recovery_self_test(transition)

        if args.command == "validate":
            require_transition_digest(transition, args.transition_digest)
            print(transition["transitionDigest"])
            return 0

        if args.command == "classify":
            value = json.loads(args.live.read_text(encoding="utf-8"))
            state, digest = classify(value, transition)
            print(json.dumps({"state": state, "digest": digest}, sort_keys=True))
            return 0

        if args.command == "classify-observable":
            value = json.loads(args.live.read_text(encoding="utf-8"))
            state, digest, bypass_observable = classify_observable(value, transition)
            print(json.dumps({
                "stateHint": state,
                "expectedStateDigest": digest,
                "bypassActorsObservable": bypass_observable,
            }, sort_keys=True))
            return 0

        if args.command == "emit-put":
            require_transition_digest(transition, args.transition_digest)
            write_json(args.output, transition["successor"])
            print(transition["successorDigest"])
            return 0

        if args.command == "receipt":
            before = json.loads(args.before.read_text(encoding="utf-8"))
            after = json.loads(args.after.read_text(encoding="utf-8"))
            before_state, before_digest = classify(before, transition)
            after_state, after_digest = classify(after, transition)
            require(before_state == "predecessor",
                    "reconciliation receipt requires exact predecessor immediately before write")
            require(after_state == "successor",
                    "reconciliation receipt requires exact successor readback")
            require(
                len(args.trusted_main_sha) == 40
                and all(c in "0123456789abcdef" for c in args.trusted_main_sha),
                "trusted main SHA malformed",
            )
            require(args.run_id > 0 and args.run_attempt > 0, "workflow run identity malformed")
            require(args.issued_at > 0 and args.expires_at > args.issued_at,
                    "transaction validity window malformed")
            require(args.expires_at - args.issued_at <= 600,
                    "transaction validity window exceeds ten minutes")
            require(args.write_status >= 0, "write status malformed")
            outcome = "applied" if args.write_status == 0 else "ambiguous-response-readback-applied"
            evidence = {
                "schemaVersion": 1,
                "repository": REPOSITORY,
                "repositoryId": REPOSITORY_ID,
                "workflow": ".github/workflows/ruleset-reconciler.yml",
                "trustedMainSha": args.trusted_main_sha,
                "runId": args.run_id,
                "runAttempt": args.run_attempt,
                "rulesetId": RULESET_ID,
                "endpoint": ENDPOINT,
                "method": METHOD,
                "transitionId": TRANSITION_ID,
                "transitionDigest": transition["transitionDigest"],
                "predecessorDigest": before_digest,
                "successorDigest": after_digest,
                "issuedAtEpoch": args.issued_at,
                "expiresAtEpoch": args.expires_at,
                "writeStatus": args.write_status,
                "outcome": outcome,
            }
            write_json(args.output, evidence)
            print("sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest())
            return 0



        if args.command == "recovery-context":
            print(recovery_context(args.run_id, args.run_attempt, args.head_sha))
            return 0

        if args.command == "recovery-classify":
            recovery = load_recovery_contract(transition)
            value = json.loads(args.live.read_text(encoding="utf-8"))
            if args.observable:
                state, digest, context, temporary_digest, bypass_observable = classify_recovery_observable_exact(
                    value, transition, recovery, args.run_id, args.run_attempt, args.head_sha
                )
                payload = {
                    "state": state, "digest": digest, "transactionContext": context,
                    "normalDigest": recovery["normalDigest"], "temporaryDigest": temporary_digest,
                    "bypassActorsObservable": bypass_observable,
                }
            else:
                state, digest, context, temporary_digest = classify_recovery_exact(
                    value, transition, recovery, args.run_id, args.run_attempt, args.head_sha
                )
                payload = {
                    "state": state, "digest": digest, "transactionContext": context,
                    "normalDigest": recovery["normalDigest"], "temporaryDigest": temporary_digest,
                }
            print(json.dumps(payload, sort_keys=True))
            return 0

        if args.command == "recovery-classify-shape":
            recovery = load_recovery_contract(transition)
            value = json.loads(args.live.read_text(encoding="utf-8"))
            print(json.dumps(
                classify_recovery_shape(value, transition, recovery, observable=args.observable),
                sort_keys=True,
            ))
            return 0

        if args.command == "recovery-emit-open":
            payload = recovery_temporary_payload(
                transition, args.run_id, args.run_attempt, args.head_sha
            )
            write_json(args.output, payload)
            print(sha256(payload))
            return 0

        if args.command == "recovery-emit-close":
            recovery = load_recovery_contract(transition)
            write_json(args.output, transition["successor"])
            print(recovery["normalDigest"])
            return 0

        if args.command == "recovery-evaluate-candidate":
            evidence = evaluate_recovery_candidate(
                candidate_root=args.candidate_root,
                changed_paths=args.changed_paths,
                candidate_tree_sha=args.candidate_tree_sha,
            )
            write_json(args.output, evidence)
            print(sha256_file(args.output))
            return 0

        if args.command == "recovery-transition-receipt":
            recovery = load_recovery_contract(transition)
            evidence = recovery_transition_receipt(
                direction=args.direction,
                before=json.loads(args.before.read_text(encoding="utf-8")),
                after=json.loads(args.after.read_text(encoding="utf-8")),
                transition=transition,
                recovery=recovery,
                trusted_main_sha=args.trusted_main_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                candidate_pr=args.candidate_pr,
                candidate_head_sha=args.candidate_head_sha,
                check_id=args.check_id,
                issued_at=args.issued_at,
                expires_at=args.expires_at,
                write_status=args.write_status,
            )
            write_json(args.output, evidence)
            print(sha256_file(args.output))
            return 0

        if args.command == "recovery-watchdog-receipt":
            recovery = load_recovery_contract(transition)
            evidence = recovery_watchdog_receipt(
                before=json.loads(args.before.read_text(encoding="utf-8")),
                after=json.loads(args.after.read_text(encoding="utf-8")),
                transition=transition,
                recovery=recovery,
                trusted_main_sha=args.trusted_main_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                issued_at=args.issued_at,
                write_status=args.write_status,
            )
            write_json(args.output, evidence)
            print(sha256_file(args.output))
            return 0

        if args.command == "recovery-result-receipt":
            evidence = recovery_result_receipt(
                trusted_main_sha=args.trusted_main_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                candidate_pr=args.candidate_pr,
                candidate_head_sha=args.candidate_head_sha,
                check_id=args.check_id,
                transaction_context=args.transaction_context,
                merged=args.merged == "true",
                merge_sha=args.merge_sha,
                open_receipt_sha256=args.open_receipt_sha256,
                restore_receipt_sha256=args.restore_receipt_sha256,
            )
            write_json(args.output, evidence)
            print(sha256_file(args.output))
            return 0

        raise ValueError("unsupported command")
    except (OSError, json.JSONDecodeError, ValueError, ImportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
