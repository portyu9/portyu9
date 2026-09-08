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
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"
DOC = ROOT / ".github" / "RULESETS.md"
QUALITY = ROOT / ".github" / "workflows" / "profile-quality.yml"
REPOSITORY = "portyu9/portyu9"
API_ORIGIN = "https://api.github.com"
API_PATH = f"/repos/{REPOSITORY}/rulesets"
API = f"{API_ORIGIN}{API_PATH}"
EXPECTED_INTEGRATION_ID = 15368
EXPECTED_RULESET_NAMES = ("Protect Main", "Protect generated")

EXPECTED_CONTEXTS = {
    "validate-contracts",
    "integration-pinned-upstream",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
}


class PublicRateLimitError(ValueError):
    """The unauthenticated supplemental ruleset view exhausted its public quota."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_int(value: Any, expected: int | None = None, *, minimum: int | None = None) -> bool:
    """Accept JSON integer primitives only; bool/float equality must not erase type identity."""
    if type(value) is not int:
        return False
    if expected is not None and value != expected:
        return False
    return minimum is None or value >= minimum


def exact_bool(value: Any, expected: bool) -> bool:
    """Accept JSON boolean primitives only; integer 0/1 are not equivalent policy values."""
    return type(value) is bool and value is expected


def validate_live_pr_parameters(pr: Any, desired: dict[str, Any]) -> None:
    require(isinstance(pr, dict), "Protect Main: live pull-request parameters are malformed")
    review_count = pr.get("required_approving_review_count")
    require(
        exact_int(review_count, desired["required_approving_review_count"]),
        "Protect Main: live required_approving_review_count primitive/value differs from contract",
    )
    for key in (
        "required_review_thread_resolution",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
    ):
        require(
            exact_bool(pr.get(key), desired[key]),
            f"Protect Main: live {key} primitive/value differs from contract",
        )
    methods = pr.get("allowed_merge_methods")
    require(
        isinstance(methods, list)
        and all(isinstance(method, str) for method in methods)
        and methods == desired["allowed_merge_methods"],
        "Protect Main: live allowed_merge_methods differs from contract",
    )


def required_status_context_map(entries: Any, expected_integration: int) -> dict[str, int]:
    """Return exact required-check identities without string/numeric coercion or duplicate collapse."""
    require(isinstance(entries, list), "Protect Main: live required statuses are malformed")
    require(len(entries) == len(EXPECTED_CONTEXTS), "Protect Main: live required status count differs from contract")
    observed: dict[str, int] = {}
    for entry in entries:
        require(isinstance(entry, dict), "Protect Main: live required status entry is malformed")
        context = entry.get("context")
        integration_id = entry.get("integration_id")
        require(isinstance(context, str) and context, "Protect Main: live required status context is malformed")
        require(context not in observed, f"Protect Main: duplicate live required status context: {context}")
        require(
            exact_int(integration_id, expected_integration),
            f"Protect Main: required status integration identity differs for {context}: {integration_id!r}",
        )
        observed[context] = integration_id
    require(set(observed) == EXPECTED_CONTEXTS, "Protect Main: live required status contexts differ from contract")
    return observed


def validate_detail_identity(detail: Any, name: str, ruleset_id: int) -> dict[str, Any]:
    require(isinstance(detail, dict), f"live ruleset detail is malformed: {name}")
    require(
        exact_int(detail.get("id"), ruleset_id),
        f"{name}: live ruleset detail id primitive/value differs from collection identity",
    )
    require(
        isinstance(detail.get("name"), str) and detail.get("name") == name,
        f"{name}: live ruleset detail name differs from collection identity",
    )
    return detail


def load_contract() -> dict[str, Any]:
    payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
    require(exact_int(payload.get("schemaVersion"), 1), "ruleset contract schema version changed")
    require(payload.get("repository") == REPOSITORY, "ruleset contract repository changed")
    rulesets = payload.get("rulesets")
    require(isinstance(rulesets, dict), "ruleset contract inventory is missing")
    require(set(rulesets) == set(EXPECTED_RULESET_NAMES), "ruleset contract inventory changed")
    return payload


def validate_source(payload: dict[str, Any]) -> None:
    require(isinstance(payload, dict), "ruleset contract root must be an object")
    require(exact_int(payload.get("schemaVersion"), 1), "ruleset contract schema version changed")
    require(payload.get("repository") == REPOSITORY, "ruleset contract repository changed")
    rulesets = payload.get("rulesets")
    require(isinstance(rulesets, dict), "ruleset contract inventory is missing")
    require(set(rulesets) == set(EXPECTED_RULESET_NAMES), "ruleset contract inventory changed")
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
    require(exact_int(pr.get("required_approving_review_count"), 0), "solo-maintainer review-count contract changed")
    require(pr.get("required_review_thread_resolution") is True, "Protect Main must require review-thread resolution")
    require(pr.get("dismiss_stale_reviews_on_push") is False, "stale-review policy changed")
    require(pr.get("require_code_owner_review") is False, "code-owner review policy changed")
    require(pr.get("require_last_push_approval") is False, "last-push approval policy changed")
    require(pr.get("allowed_merge_methods") == ["merge"], "Protect Main must permit only merge commits")

    checks = main_rules.get("required_status_checks")
    require(isinstance(checks, dict), "Protect Main status-check parameters are missing")
    require(checks.get("strict_required_status_checks_policy") is True, "Protect Main must require a current head")
    require(checks.get("do_not_enforce_on_create") is False, "required checks must be enforced on branch creation")
    require(
        exact_int(checks.get("integration_id"), EXPECTED_INTEGRATION_ID),
        f"required checks must bind to GitHub Actions integration_id {EXPECTED_INTEGRATION_ID}",
    )
    contexts = checks.get("contexts")
    require(
        isinstance(contexts, list)
        and len(contexts) == 5
        and all(isinstance(context, str) and context for context in contexts)
        and set(contexts) == EXPECTED_CONTEXTS,
        "Protect Main required status contexts changed",
    )

    require(generated.get("target") == "branch" and generated.get("enforcement") == "active", "Protect generated must be an active branch ruleset")
    require(generated.get("include") == ["refs/heads/generated"] and generated.get("exclude") == [], "Protect generated target changed")
    require(generated.get("bypassActors") == [], "Protect generated must have no bypass actors")
    generated_rules = generated.get("rules")
    require(isinstance(generated_rules, dict) and set(generated_rules) == {"deletion", "non_fast_forward"},
            "Protect generated must contain only deletion/non-fast-forward protection")
    require(generated_rules.get("deletion") is True and generated_rules.get("non_fast_forward") is True,
            "Protect generated deletion/non-fast-forward values must be boolean true")

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
        "X-RateLimit-Remaining: 0",
        "all other public API failures remain merge-blocking",
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


def is_proven_public_rate_limit(exc: urllib.error.HTTPError) -> bool:
    """Recognize only GitHub's explicit exhausted unauthenticated core-rate signal."""
    remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers is not None else None
    return exc.code == 403 and remaining == "0"


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
    except urllib.error.HTTPError as exc:
        mode = "authenticated" if authenticated and token else "public"
        if not authenticated and is_proven_public_rate_limit(exc):
            raise PublicRateLimitError(
                "GitHub public ruleset API rate limit exhausted; supplemental bypass_actors view is temporarily unobservable"
            ) from exc
        raise ValueError(f"could not read GitHub ruleset API ({mode} view): {exc}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        mode = "authenticated" if authenticated and token else "public"
        raise ValueError(f"could not read GitHub ruleset API ({mode} view): {exc}") from exc


def ruleset_collection_map(collection: Any) -> dict[str, dict[str, Any]]:
    """Return the exact live ruleset inventory without filtering or collapsing identities."""
    require(isinstance(collection, list), "live ruleset collection is malformed")
    require(
        len(collection) == len(EXPECTED_RULESET_NAMES),
        f"live repository ruleset inventory must contain exactly {len(EXPECTED_RULESET_NAMES)} entries",
    )
    result: dict[str, dict[str, Any]] = {}
    seen_ids: set[int] = set()
    for item in collection:
        require(isinstance(item, dict), "live repository ruleset inventory contains a malformed entry")
        name = item.get("name")
        require(isinstance(name, str) and name, "live repository ruleset name is malformed")
        require(name not in result, f"live repository ruleset inventory contains duplicate name: {name}")
        ruleset_id = item.get("id")
        require(exact_int(ruleset_id, minimum=1), f"live ruleset id is malformed: {name}")
        require(ruleset_id not in seen_ids, f"live repository ruleset inventory contains duplicate id: {ruleset_id}")
        result[name] = item
        seen_ids.add(ruleset_id)
    require(set(result) == set(EXPECTED_RULESET_NAMES), "live repository ruleset inventory differs from contract")
    return result


def rule_map(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return rules by type only when every live rule identity is unique and well formed."""
    result: dict[str, dict[str, Any]] = {}
    rules = detail.get("rules")
    require(isinstance(rules, list), "live ruleset rule inventory is malformed")
    for rule in rules:
        require(isinstance(rule, dict), "live ruleset rule is malformed")
        rule_type = rule.get("type")
        require(isinstance(rule_type, str) and rule_type, "live ruleset rule type is malformed")
        require(rule_type not in result, f"live ruleset rule inventory contains duplicate type: {rule_type}")
        result[rule_type] = rule
    return result


def observable_bypass_actors(
    name: str,
    ruleset_id: int,
    detail: dict[str, Any],
    *,
    public_reader: Callable[..., Any] = request_json,
) -> list[Any] | None:
    """Return bypass actors only when GitHub actually exposes them to this gate.

    GitHub's short-lived Actions token currently redacts ``bypass_actors``. The
    public view for this public repository can redact the same field. We never map
    an omitted field to an empty list: visible values are enforced, while omission
    remains an explicit admin-scope verification gap documented by the contract.

    The public lookup is supplemental only. A proven unauthenticated GitHub public
    rate-limit exhaustion leaves this admin-scope field unobservable; every other
    public read failure remains a hard validation error.
    """
    observed = detail.get("bypass_actors")
    if isinstance(observed, list):
        return observed
    try:
        public_detail = public_reader(f"{API}/{ruleset_id}", authenticated=False)
    except PublicRateLimitError:
        return None
    require(isinstance(public_detail, dict), f"{name}: public ruleset detail is malformed")
    observed = public_detail.get("bypass_actors")
    return observed if isinstance(observed, list) else None


def validate_live(payload: dict[str, Any]) -> tuple[str, ...]:
    by_name = ruleset_collection_map(request_json(API))

    details: dict[str, dict[str, Any]] = {}
    ids: dict[str, int] = {}
    for name, item in by_name.items():
        ruleset_id = item["id"]
        detail = validate_detail_identity(request_json(f"{API}/{ruleset_id}"), name, ruleset_id)
        details[name] = detail
        ids[name] = ruleset_id

    expected = payload["rulesets"]
    bypass_unobservable: list[str] = []
    for name in EXPECTED_RULESET_NAMES:
        detail = details[name]
        target = expected[name]
        require(detail.get("target") == target["target"], f"{name}: live target differs from contract")
        require(detail.get("enforcement") == target["enforcement"], f"{name}: live enforcement differs from contract")
        conditions = detail.get("conditions")
        require(isinstance(conditions, dict), f"{name}: live conditions are malformed")
        ref_name = conditions.get("ref_name")
        require(isinstance(ref_name, dict), f"{name}: live ref_name conditions are malformed")
        require(ref_name.get("include") == target["include"], f"{name}: live include target differs from contract")
        require(ref_name.get("exclude") == target["exclude"], f"{name}: live exclude target differs from contract")
        bypass_actors = observable_bypass_actors(name, ids[name], detail)
        if bypass_actors is None:
            bypass_unobservable.append(name)
        else:
            require(bypass_actors == [], f"{name}: live bypass actors must remain empty; observed={bypass_actors!r}")

    main_rules = rule_map(details["Protect Main"])
    require(set(main_rules) == {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}, "Protect Main: live rule inventory differs from contract")
    pr = main_rules["pull_request"].get("parameters")
    desired_pr = expected["Protect Main"]["rules"]["pull_request"]
    validate_live_pr_parameters(pr, desired_pr)

    status = main_rules["required_status_checks"].get("parameters")
    require(isinstance(status, dict), "Protect Main: live required status parameters are malformed")
    desired_status = expected["Protect Main"]["rules"]["required_status_checks"]
    require(
        exact_bool(status.get("strict_required_status_checks_policy"), desired_status["strict_required_status_checks_policy"]),
        "Protect Main: live strict status policy primitive/value differs",
    )
    require(
        exact_bool(status.get("do_not_enforce_on_create"), desired_status["do_not_enforce_on_create"]),
        "Protect Main: live create enforcement primitive/value differs",
    )
    expected_integration = desired_status["integration_id"]
    require(exact_int(expected_integration, EXPECTED_INTEGRATION_ID), "Protect Main: source integration identity is malformed")
    required_status_context_map(status.get("required_status_checks"), expected_integration)

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


def expect_collection_failure(collection: Any, expected: str) -> None:
    try:
        ruleset_collection_map(collection)
    except ValueError as exc:
        require(expected in str(exc), f"ruleset collection self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"ruleset collection self-test accepted ambiguous inventory: {expected}")


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

    schema_bool = json.loads(encoded)
    schema_bool["schemaVersion"] = True
    try:
        validate_source(schema_bool)
    except (ValueError, KeyError):
        pass
    else:
        raise ValueError("ruleset self-test accepted boolean schema version")

    review_count_bool = json.loads(encoded)
    review_count_bool["rulesets"]["Protect Main"]["rules"]["pull_request"]["required_approving_review_count"] = False
    try:
        validate_source(review_count_bool)
    except ValueError as exc:
        require("review-count" in str(exc), f"ruleset review-count type self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted boolean review count as integer zero")

    review_thread_int = json.loads(encoded)
    review_thread_int["rulesets"]["Protect Main"]["rules"]["pull_request"]["required_review_thread_resolution"] = 1
    try:
        validate_source(review_thread_int)
    except ValueError as exc:
        require("review-thread resolution" in str(exc), f"ruleset review-thread type self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted integer one as boolean review-thread policy")

    integration_drift = json.loads(encoded)
    integration_drift["rulesets"]["Protect Main"]["rules"]["required_status_checks"]["integration_id"] = 1
    try:
        validate_source(integration_drift)
    except ValueError as exc:
        require("integration_id" in str(exc), f"ruleset integration self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted required-check integration identity drift")

    integration_float = json.loads(encoded)
    integration_float["rulesets"]["Protect Main"]["rules"]["required_status_checks"]["integration_id"] = float(EXPECTED_INTEGRATION_ID)
    try:
        validate_source(integration_float)
    except ValueError as exc:
        require("integration_id" in str(exc), f"ruleset integration primitive self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted floating-point integration identity")

    generated_numeric = json.loads(encoded)
    generated_numeric["rulesets"]["Protect generated"]["rules"]["deletion"] = 1
    try:
        validate_source(generated_numeric)
    except ValueError as exc:
        require("boolean true" in str(exc), f"generated rules primitive self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted integer one as generated deletion boolean")

    desired_pr = payload["rulesets"]["Protect Main"]["rules"]["pull_request"]
    validate_live_pr_parameters(dict(desired_pr), desired_pr)
    for field, value in (
        ("required_approving_review_count", False),
        ("required_review_thread_resolution", 1),
        ("dismiss_stale_reviews_on_push", 0),
    ):
        malformed_pr = dict(desired_pr)
        malformed_pr[field] = value
        try:
            validate_live_pr_parameters(malformed_pr, desired_pr)
        except ValueError:
            pass
        else:
            raise ValueError(f"live ruleset PR primitive self-test accepted malformed {field}")

    canonical_collection = [
        {"id": 1, "name": "Protect Main"},
        {"id": 2, "name": "Protect generated"},
    ]
    require(
        tuple(ruleset_collection_map(canonical_collection)) == EXPECTED_RULESET_NAMES,
        "ruleset collection self-test did not preserve the exact reviewed inventory",
    )
    expect_collection_failure(
        [{"id": 1, "name": "Protect Main"}, {"id": 2, "name": "Protect Main"}],
        "duplicate name",
    )
    expect_collection_failure(
        [{"id": 1, "name": "Protect Main"}, "malformed"],
        "malformed entry",
    )
    expect_collection_failure(
        [{"id": 1, "name": "Protect Main"}, {"id": 1, "name": "Protect generated"}],
        "duplicate id",
    )
    expect_collection_failure(
        canonical_collection + [{"id": 3, "name": "Unexpected"}],
        "exactly 2 entries",
    )
    expect_collection_failure(
        [{"id": True, "name": "Protect Main"}, {"id": 2, "name": "Protect generated"}],
        "id is malformed",
    )
    try:
        rule_map({"rules": [{"type": "deletion"}, {"type": "deletion"}]})
    except ValueError as exc:
        require("duplicate type" in str(exc), f"rule-map ambiguity self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("rule-map self-test accepted duplicate live rule types")

    validate_detail_identity({"id": 1, "name": "Protect Main"}, "Protect Main", 1)
    try:
        validate_detail_identity({"id": True, "name": "Protect Main"}, "Protect Main", 1)
    except ValueError as exc:
        require("id primitive/value" in str(exc), f"detail identity type self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset detail self-test accepted boolean id as integer one")

    canonical_statuses = [
        {"context": context, "integration_id": EXPECTED_INTEGRATION_ID}
        for context in sorted(EXPECTED_CONTEXTS)
    ]
    require(set(required_status_context_map(canonical_statuses, EXPECTED_INTEGRATION_ID)) == EXPECTED_CONTEXTS,
            "required status identity fixture changed")
    malformed_statuses = [dict(entry) for entry in canonical_statuses]
    malformed_statuses[0]["integration_id"] = float(EXPECTED_INTEGRATION_ID)
    try:
        required_status_context_map(malformed_statuses, EXPECTED_INTEGRATION_ID)
    except ValueError as exc:
        require("integration identity differs" in str(exc), f"required status primitive self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted floating-point required status integration id")
    duplicate_statuses = [dict(entry) for entry in canonical_statuses]
    duplicate_statuses[-1]["context"] = duplicate_statuses[0]["context"]
    try:
        required_status_context_map(duplicate_statuses, EXPECTED_INTEGRATION_ID)
    except ValueError as exc:
        require("duplicate live required status context" in str(exc), f"required status duplicate self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted duplicate required status context")

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

    limited = urllib.error.HTTPError(
        API,
        403,
        "rate limit exceeded",
        {"X-RateLimit-Remaining": "0"},
        None,
    )
    require(is_proven_public_rate_limit(limited), "public rate-limit self-test rejected GitHub's exhausted 403 signal")
    non_exhausted = urllib.error.HTTPError(
        API,
        403,
        "forbidden",
        {"X-RateLimit-Remaining": "1"},
        None,
    )
    require(not is_proven_public_rate_limit(non_exhausted), "public rate-limit self-test accepted a non-exhausted 403")
    not_found = urllib.error.HTTPError(API, 404, "not found", {"X-RateLimit-Remaining": "0"}, None)
    require(not is_proven_public_rate_limit(not_found), "public rate-limit self-test accepted a non-403 response")

    def rate_limited_reader(url: str, *, authenticated: bool = True) -> Any:
        raise PublicRateLimitError("fixture public rate limit")

    require(
        observable_bypass_actors("fixture", 123, {}, public_reader=rate_limited_reader) is None,
        "public rate-limit self-test must leave bypass_actors unobservable",
    )

    def broken_public_reader(url: str, *, authenticated: bool = True) -> Any:
        raise ValueError("fixture public failure")

    try:
        observable_bypass_actors("fixture", 123, {}, public_reader=broken_public_reader)
    except ValueError as exc:
        require("fixture public failure" in str(exc), f"public failure self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test softened a non-rate-limit public API failure")


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
            f"five required contexts are bound to integration_id {EXPECTED_INTEGRATION_ID}; exact JSON primitive identity and observable drift fail closed."
        )
        if unobservable:
            print(
                "NOTICE: bypass_actors could not be observed by the read-only workflow/public fallback for: "
                + ", ".join(unobservable)
                + "; empty bypass actors remains an admin-scope control-plane audit invariant and unobservability was not interpreted as empty."
            )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
