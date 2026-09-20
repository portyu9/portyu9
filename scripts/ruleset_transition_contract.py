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
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "ruleset-transitions-v1.json"
REPOSITORY = "portyu9/portyu9"
REPOSITORY_ID = 1355082509
RULESET_ID = 22148161
TRANSITION_ID = "protect-main-add-trusted-governed-bot-review-v1"
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
    require(tuple(observed) == EXPECTED_RULE_TYPES, "ruleset rule ordering/inventory changed")

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
    return value


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


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> None:
    transition = load_contract()
    predecessor = dict(transition["predecessor"])
    successor = dict(transition["successor"])
    require(classify({"id": RULESET_ID, **predecessor}, transition)[0] == "predecessor",
            "predecessor classification changed")
    require(classify({"id": RULESET_ID, **successor}, transition)[0] == "successor",
            "successor classification changed")
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

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][2]["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
    try:
        classify({"id": RULESET_ID, **mutated}, transition)
    except ValueError:
        pass
    else:
        raise ValueError("self-test accepted merge-method broadening")

    mutated = json.loads(json.dumps(predecessor))
    mutated["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
    try:
        classify({"id": RULESET_ID, **mutated}, transition)
    except ValueError:
        pass
    else:
        raise ValueError("self-test accepted bypass actor")

    mutated = json.loads(json.dumps(predecessor))
    mutated["rules"][3]["parameters"]["required_status_checks"][0]["integration_id"] = 1
    try:
        classify({"id": RULESET_ID, **mutated}, transition)
    except ValueError:
        pass
    else:
        raise ValueError("self-test accepted wrong integration id")


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
    return result


def require_transition_digest(transition: dict[str, Any], supplied: str) -> None:
    require(supplied == transition["transitionDigest"],
            "workflow-dispatch transition digest does not match reviewed source")


def main() -> int:
    try:
        args = parser().parse_args()
        transition = load_contract()
        self_test()

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

        raise ValueError("unsupported command")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
