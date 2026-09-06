#!/usr/bin/env python3
"""Validate the source-controlled GitHub repository ruleset contract.

Default mode is deterministic and read-only: validate the checked-in contract and
its governance documentation. ``--live`` additionally reads GitHub's repository
ruleset API and requires every control-plane field observable to the read-only
workflow identity to match the checked-in target.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"
DOC = ROOT / ".github" / "RULESETS.md"
QUALITY = ROOT / ".github" / "workflows" / "profile-quality.yml"
REPOSITORY = "portyu9/portyu9"
API_ORIGIN = "https://api.github.com"
API_PATH = f"/repos/{REPOSITORY}/rulesets"
API = f"{API_ORIGIN}{API_PATH}"
EXPECTED_INTEGRATION_ID = 15368

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
    require(checks.get("integration_id") == EXPECTED_INTEGRATION_ID,
            f"required checks must bind to GitHub Actions integration_id {EXPECTED_INTEGRATION_ID}")
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
        "integration_id: 15368",
        "solo-maintainer",
        "Protect generated",
        "no bypass actors",
        "--live",
        "control-plane",
        "merge-blocking",
        "admin-scope",
    ):
        require(phrase in doc, f"ruleset governance documentation is missing: {phrase}")

    quality = QUALITY.read_text(encoding="utf-8")
    require(
        "name: Validate repository ruleset source + live observable control-plane contract" in quality,
        "Profile Quality must expose the ruleset source + live observable control-plane gate",
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


def validate_api_url(url: str) -> str:
    """Return a credential-safe GitHub ruleset URL or fail closed.

    The authenticated workflow token may be attached only to the exact repository
    ruleset collection or one numeric ruleset-detail child. No alternate origin,
    scheme, port, userinfo, query, fragment, encoded id, traversal, or deeper path is
    accepted.
    """
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https", f"ruleset API URL must use https: {url}")
    require(parsed.netloc == "api.github.com", f"ruleset API URL origin changed: {url}")
    require(parsed.username is None and parsed.password is None, f"ruleset API URL must not contain userinfo: {url}")
    require(parsed.query == "" and parsed.fragment == "", f"ruleset API URL must not contain query/fragment data: {url}")

    if parsed.path == API_PATH:
        return url
    prefix = API_PATH + "/"
    require(parsed.path.startswith(prefix), f"ruleset API URL path changed: {url}")
    suffix = parsed.path[len(prefix):]
    require(suffix.isascii() and suffix.isdigit() and suffix == str(int(suffix)) and int(suffix) > 0,
            f"ruleset API detail path must end in one canonical positive integer id: {url}")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so Authorization can never leave the validated origin."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def request_json(url: str, *, authenticated: bool = True) -> Any:
    safe_url = validate_api_url(url)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "portyu9-ruleset-contract-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if authenticated and token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(safe_url, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
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


def observable_bypass_actors(name: str, ruleset_id: int, detail: dict[str, Any]) -> list[Any] | None:
    """Return bypass actors only when GitHub actually exposes them to this gate.

    GitHub's short-lived Actions token currently redacts ``bypass_actors``. The
    public view for this public repository can redact the same field. We never map
    an omitted field to an empty list: visible values are enforced, while omission
    remains an explicit admin-scope verification gap documented by the contract.
    """
    observed = detail.get("bypass_actors")
    if isinstance(observed, list):
        return observed
    public_detail = request_json(f"{API}/{ruleset_id}", authenticated=False)
    require(isinstance(public_detail, dict), f"{name}: public ruleset detail is malformed")
    observed = public_detail.get("bypass_actors")
    return observed if isinstance(observed, list) else None


def validate_live(payload: dict[str, Any]) -> tuple[str, ...]:
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
    bypass_unobservable: list[str] = []
    for name in ("Protect Main", "Protect generated"):
        detail = details[name]
        target = expected[name]
        require(detail.get("target") == target["target"], f"{name}: live target differs from contract")
        require(detail.get("enforcement") == target["enforcement"], f"{name}: live enforcement differs from contract")
        conditions = detail.get("conditions", {}).get("ref_name", {})
        require(conditions.get("include") == target["include"], f"{name}: live include target differs from contract")
        require(conditions.get("exclude") == target["exclude"], f"{name}: live exclude target differs from contract")
        bypass_actors = observable_bypass_actors(name, ids[name], detail)
        if bypass_actors is None:
            bypass_unobservable.append(name)
        else:
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
    require(len(live_contexts) == 5 and all(isinstance(entry, dict) for entry in live_contexts),
            "Protect Main: live required status entries are malformed")
    observed = {str(entry.get("context")): entry.get("integration_id") for entry in live_contexts}
    require(set(observed) == EXPECTED_CONTEXTS and len(observed) == 5,
            "Protect Main: live required status contexts differ from contract")
    expected_integration = desired_status["integration_id"]
    require(all(value == expected_integration for value in observed.values()),
            f"Protect Main: required status integration identity differs; expected integration_id={expected_integration}, observed={observed}")

    generated_rules = rule_map(details["Protect generated"])
    require(set(generated_rules) == {"deletion", "non_fast_forward"}, "Protect generated: live rule inventory differs from contract")
    return tuple(bypass_unobservable)


def expect_unsafe_url(url: str, expected: str) -> None:
    try:
        validate_api_url(url)
    except ValueError as exc:
        require(expected in str(exc), f"ruleset URL self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"ruleset URL self-test accepted unsafe endpoint: {url}")


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

    integration_drift = json.loads(encoded)
    integration_drift["rulesets"]["Protect Main"]["rules"]["required_status_checks"]["integration_id"] = 1
    try:
        validate_source(integration_drift)
    except ValueError as exc:
        require("integration_id" in str(exc), f"ruleset integration self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted required-check integration identity drift")

    require(validate_api_url(API) == API, "ruleset URL self-test rejected canonical collection endpoint")
    require(validate_api_url(f"{API}/123") == f"{API}/123", "ruleset URL self-test rejected canonical detail endpoint")
    for url, expected in (
        (API.replace("https://", "http://"), "must use https"),
        (API.replace("api.github.com", "evil.example"), "origin changed"),
        (API.replace("api.github.com", "api.github.com.evil.example"), "origin changed"),
        (API.replace("api.github.com", "token@api.github.com"), "origin changed"),
        (API.replace("api.github.com", "api.github.com:443"), "origin changed"),
        (API + "?page=1", "query/fragment"),
        (API + "#fragment", "query/fragment"),
        (API + "/../actions", "positive integer"),
        (API + "/%31%32%33", "positive integer"),
        (API + "/abc", "positive integer"),
        (API + "/123/extra", "positive integer"),
        (API + "/0123", "positive integer"),
    ):
        expect_unsafe_url(url, expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compare checked-in target with GitHub control-plane fields observable to this identity")
    args = parser.parse_args()
    try:
        for path in (CONTRACT, DOC, QUALITY):
            require(path.is_file(), f"ruleset contract input is missing: {path.relative_to(ROOT)}")
        payload = load_contract()
        validate_source(payload)
        self_test(payload)
        unobservable: tuple[str, ...] = ()
        if args.live:
            unobservable = validate_live(payload)
        suffix = " + live observable GitHub control-plane state" if args.live else ""
        print(
            f"Repository ruleset contract passed: source-controlled target{suffix} is internally consistent; "
            f"five required contexts are bound to integration_id {EXPECTED_INTEGRATION_ID}; observable drift fails closed."
        )
        if unobservable:
            print(
                "NOTICE: bypass_actors is not exposed to the read-only workflow/public API for: "
                + ", ".join(unobservable)
                + "; empty bypass actors remains an admin-scope control-plane audit invariant and omission was not interpreted as empty."
            )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
