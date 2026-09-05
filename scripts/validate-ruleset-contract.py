#!/usr/bin/env python3
"""Validate the source-controlled GitHub repository ruleset contract.

Default mode is deterministic and read-only: validate the checked-in contract and
its governance documentation. ``--live`` additionally reads GitHub's repository
ruleset API and requires the control-plane state to match the checked-in target.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"
DOC = ROOT / ".github" / "RULESETS.md"
QUALITY = ROOT / ".github" / "workflows" / "profile-quality.yml"
REPOSITORY = "portyu9/portyu9"
API = f"https://api.github.com/repos/{REPOSITORY}/rulesets"

EXPECTED_CONTEXTS = {
    "validate-contracts",
    "integration-pinned-upstream",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_contract() -> dict[str, Any]:
    payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
    require(payload.get("schemaVersion") == 1, "ruleset contract schema version changed")
    require(payload.get("repository") == REPOSITORY, "ruleset contract repository changed")
    rulesets = payload.get("rulesets")
    require(isinstance(rulesets, dict), "ruleset contract inventory is missing")
    require(set(rulesets) == {"Protect Main", "Protect generated"}, "ruleset contract inventory changed")
    return payload


def validate_source(payload: dict[str, Any]) -> None:
    rulesets = payload["rulesets"]
    main = rulesets["Protect Main"]
    generated = rulesets["Protect generated"]

    require(main.get("target") == "branch" and main.get("enforcement") == "active", "Protect Main must be an active branch ruleset")
    require(main.get("include") == ["~DEFAULT_BRANCH"] and main.get("exclude") == [], "Protect Main target changed")
    require(main.get("bypassActors") == [], "Protect Main must have no bypass actors")
    main_rules = main.get("rules")
    require(isinstance(main_rules, dict), "Protect Main rules are missing")
    require(set(main_rules) == {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}, "Protect Main rule inventory changed")
    require(main_rules.get("deletion") is True, "Protect Main must block deletion")
    require(main_rules.get("non_fast_forward") is True, "Protect Main must block non-fast-forward updates")

    pr = main_rules.get("pull_request")
    require(isinstance(pr, dict), "Protect Main pull-request parameters are missing")
    require(pr.get("required_approving_review_count") == 0, "solo-maintainer review-count contract changed")
    require(pr.get("required_review_thread_resolution") is True, "Protect Main must require review-thread resolution")
    require(pr.get("dismiss_stale_reviews_on_push") is False, "stale-review policy changed")
    require(pr.get("require_code_owner_review") is False, "code-owner review policy changed")
    require(pr.get("require_last_push_approval") is False, "last-push approval policy changed")
    require(pr.get("allowed_merge_methods") == ["merge"], "Protect Main must permit only merge commits")

    checks = main_rules.get("required_status_checks")
    require(isinstance(checks, dict), "Protect Main status-check parameters are missing")
    require(checks.get("strict_required_status_checks_policy") is True, "Protect Main must require a current head")
    require(checks.get("do_not_enforce_on_create") is False, "required checks must be enforced on branch creation")
    contexts = checks.get("contexts")
    require(isinstance(contexts, list) and set(contexts) == EXPECTED_CONTEXTS and len(contexts) == 5, "Protect Main required status contexts changed")

    require(generated.get("target") == "branch" and generated.get("enforcement") == "active", "Protect generated must be an active branch ruleset")
    require(generated.get("include") == ["refs/heads/generated"] and generated.get("exclude") == [], "Protect generated target changed")
    require(generated.get("bypassActors") == [], "Protect generated must have no bypass actors")
    generated_rules = generated.get("rules")
    require(generated_rules == {"deletion": True, "non_fast_forward": True}, "Protect generated must contain only deletion/non-fast-forward protection")

    doc = DOC.read_text(encoding="utf-8")
    for phrase in (
        "required_approving_review_count: 0",
        "required_review_thread_resolution: true",
        "solo-maintainer",
        "Protect generated",
        "no bypass actors",
        "--live",
        "control-plane",
        "merge-blocking",
    ):
        require(phrase in doc, f"ruleset governance documentation is missing: {phrase}")

    quality = QUALITY.read_text(encoding="utf-8")
    require(
        "name: Validate repository ruleset source + live control-plane contract" in quality,
        "Profile Quality must expose the ruleset source + live control-plane gate",
    )
    require(
        "run: python3 scripts/validate-ruleset-contract.py --live" in quality,
        "Profile Quality must compare the source ruleset contract with live GitHub state",
    )
    require(
        "GITHUB_TOKEN: ${{ github.token }}" in quality,
        "live ruleset comparison must receive the workflow's read-only GitHub token through env",
    )
    require(
        "run: python3 scripts/validate-ruleset-contract.py\n" not in quality,
        "Profile Quality must not regress to source-only ruleset validation",
    )


def request_json(url: str, *, authenticated: bool = True) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "portyu9-ruleset-contract-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if authenticated and token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        mode = "authenticated" if authenticated and token else "public"
        raise ValueError(f"could not read GitHub ruleset API ({mode} view): {exc}") from exc


def rule_map(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    rules = detail.get("rules")
    require(isinstance(rules, list), "live ruleset rule inventory is malformed")
    for rule in rules:
        require(isinstance(rule, dict) and isinstance(rule.get("type"), str), "live ruleset rule is malformed")
        result[str(rule["type"])] = rule
    return result


def visible_bypass_actors(name: str, ruleset_id: int, detail: dict[str, Any]) -> list[Any]:
    """Resolve bypass actors without granting the workflow administration authority.

    GitHub's short-lived Actions token can redact ``bypass_actors`` even when all
    other public ruleset fields are visible. For this public repository, retry only
    that read through the unauthenticated public API view. If GitHub does not expose
    an actual list there either, fail closed rather than treating redaction as empty.
    """
    observed = detail.get("bypass_actors")
    if isinstance(observed, list):
        return observed
    public_detail = request_json(f"{API}/{ruleset_id}", authenticated=False)
    require(isinstance(public_detail, dict), f"{name}: public ruleset detail is malformed")
    observed = public_detail.get("bypass_actors")
    require(
        isinstance(observed, list),
        f"{name}: bypass actors are not observable to either the read-only workflow token or public API",
    )
    return observed


def validate_live(payload: dict[str, Any]) -> None:
    collection = request_json(API)
    require(isinstance(collection, list), "live ruleset collection is malformed")
    by_name = {item.get("name"): item for item in collection if isinstance(item, dict)}
    require(set(by_name) == {"Protect Main", "Protect generated"}, "live repository ruleset inventory differs from contract")

    details: dict[str, dict[str, Any]] = {}
    ids: dict[str, int] = {}
    for name, item in by_name.items():
        ruleset_id = item.get("id")
        require(isinstance(ruleset_id, int), f"live ruleset id is missing: {name}")
        detail = request_json(f"{API}/{ruleset_id}")
        require(isinstance(detail, dict), f"live ruleset detail is malformed: {name}")
        details[str(name)] = detail
        ids[str(name)] = ruleset_id

    expected = payload["rulesets"]
    for name in ("Protect Main", "Protect generated"):
        detail = details[name]
        target = expected[name]
        require(detail.get("target") == target["target"], f"{name}: live target differs from contract")
        require(detail.get("enforcement") == target["enforcement"], f"{name}: live enforcement differs from contract")
        conditions = detail.get("conditions", {}).get("ref_name", {})
        require(conditions.get("include") == target["include"], f"{name}: live include target differs from contract")
        require(conditions.get("exclude") == target["exclude"], f"{name}: live exclude target differs from contract")
        bypass_actors = visible_bypass_actors(name, ids[name], detail)
        require(bypass_actors == [], f"{name}: live bypass actors must remain empty; observed={bypass_actors!r}")

    main_rules = rule_map(details["Protect Main"])
    require(set(main_rules) == {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}, "Protect Main: live rule inventory differs from contract")
    pr = main_rules["pull_request"].get("parameters", {})
    desired_pr = expected["Protect Main"]["rules"]["pull_request"]
    for key in (
        "required_approving_review_count",
        "required_review_thread_resolution",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "allowed_merge_methods",
    ):
        require(pr.get(key) == desired_pr[key], f"Protect Main: live {key}={pr.get(key)!r}, expected {desired_pr[key]!r}")

    status = main_rules["required_status_checks"].get("parameters", {})
    desired_status = expected["Protect Main"]["rules"]["required_status_checks"]
    require(status.get("strict_required_status_checks_policy") is desired_status["strict_required_status_checks_policy"], "Protect Main: live strict status policy differs")
    require(status.get("do_not_enforce_on_create") is desired_status["do_not_enforce_on_create"], "Protect Main: live create enforcement differs")
    live_contexts = status.get("required_status_checks")
    require(isinstance(live_contexts, list), "Protect Main: live required statuses are malformed")
    observed = {entry.get("context") for entry in live_contexts if isinstance(entry, dict)}
    require(observed == EXPECTED_CONTEXTS and len(live_contexts) == 5, "Protect Main: live required status contexts differ from contract")

    generated_rules = rule_map(details["Protect generated"])
    require(set(generated_rules) == {"deletion", "non_fast_forward"}, "Protect generated: live rule inventory differs from contract")


def self_test(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload)
    mutation = json.loads(encoded)
    mutation["rulesets"]["Protect Main"]["rules"]["pull_request"]["required_review_thread_resolution"] = False
    try:
        validate_source(mutation)
    except ValueError as exc:
        require("review-thread resolution" in str(exc), f"ruleset self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted disabled review-thread resolution")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compare the checked-in target with GitHub control-plane state")
    args = parser.parse_args()
    try:
        for path in (CONTRACT, DOC, QUALITY):
            require(path.is_file(), f"ruleset contract input is missing: {path.relative_to(ROOT)}")
        payload = load_contract()
        validate_source(payload)
        self_test(payload)
        if args.live:
            validate_live(payload)
        suffix = " + live GitHub control-plane state" if args.live else ""
        print(f"Repository ruleset contract passed: source-controlled target{suffix} is fail-closed and internally consistent.")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
