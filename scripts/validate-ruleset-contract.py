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
import shutil
import tempfile
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

import ruleset_transition_contract

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".github" / "rulesets" / "repository-rulesets-v1.json"
DOC = ROOT / ".github" / "RULESETS.md"
QUALITY = ROOT / ".github" / "workflows" / "profile-quality.yml"
RECONCILER = ROOT / ".github" / "workflows" / "ruleset-reconciler.yml"
SENTINEL = ROOT / ".github" / "workflows" / "ruleset-drift-sentinel.yml"
REPOSITORY = "portyu9/portyu9"
API_ORIGIN = "https://api.github.com"
API_PATH = f"/repos/{REPOSITORY}/rulesets"
API = f"{API_ORIGIN}{API_PATH}"
EXPECTED_INTEGRATION_ID = 15368
EXPECTED_RULESET_NAMES = ("Protect Main", "Protect generated")

TRANSITION_PREDECESSOR_CONTEXTS = frozenset({
    "validate-contracts",
    "trusted-capability-admission",
    "integration-pinned-upstream",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
})
EXPECTED_CONTEXTS = frozenset({*TRANSITION_PREDECESSOR_CONTEXTS, "trusted-governed-bot-review"})


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
    """Return the exact final required-check identities without coercion or duplicate collapse."""
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
    require(
        frozenset(observed) == EXPECTED_CONTEXTS,
        "Protect Main: live required status contexts differ from the final reviewed state",
    )
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
        and len(contexts) == len(EXPECTED_CONTEXTS)
        and all(isinstance(context, str) and context for context in contexts)
        and frozenset(contexts) == EXPECTED_CONTEXTS,
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



def validate_reconciler_wake_contract(text: str) -> None:
    require(text.count("  plan:\n") == 1 and text.count("  reconcile:\n") == 1,
            "Ruleset reconciler plan/reconcile job boundary changed")
    plan_start = text.index("  plan:\n")
    reconcile_start = text.index("  reconcile:\n", plan_start)
    plan = text[plan_start:reconcile_start]

    live_capture = 'LIVE_MAIN_REF_RESPONSE="$(python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main")"'
    live_normalize = 'LIVE_MAIN_SHA="$(jq -er \''
    strict_current = 'test "$LIVE_MAIN_SHA" = "$TRUSTED_MAIN_SHA"'
    event_case = 'case "$GITHUB_EVENT_NAME" in'
    workflow_run = 'workflow_run)'
    allowlist = (
        '"CodeQL Autofix controller:.github/workflows/codeql-autofix.yml"|'
        '"Dependabot controller:.github/workflows/dependabot-controller.yml"|'
        '"Sync Spotlight profile links:.github/workflows/spotlight-link-sync.yml")'
    )
    stale_guard = 'if [ "$LIVE_MAIN_SHA" != "$TRUSTED_MAIN_SHA" ]; then'
    stale_message = (
        'Ignoring superseded Ruleset reconciler workflow_run wake: '
        'trusted=${TRUSTED_MAIN_SHA} live=${LIVE_MAIN_SHA}.'
    )
    parent_current = 'if [ "$WAKE_HEAD_SHA" = "$TRUSTED_MAIN_SHA" ]; then'
    transition_validate = 'python3 scripts/ruleset_transition_contract.py validate --transition-digest "$TRANSITION_DIGEST"'

    for fragment in (
        live_capture,
        live_normalize,
        'push|workflow_dispatch)',
        strict_current,
        workflow_run,
        'test "$WAKE_STATUS" = "completed"',
        'test "$WAKE_HEAD_BRANCH" = "main"',
        '[[ "$WAKE_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$WAKE_REPOSITORY" = "$TARGET_REPOSITORY"',
        'test "$WAKE_HEAD_REPOSITORY" = "$TARGET_REPOSITORY"',
        allowlist,
        stale_guard,
        stale_message,
        'echo "live_state=not-applicable" >> "$GITHUB_OUTPUT"',
        parent_current,
        transition_validate,
    ):
        require(fragment in plan, f"Ruleset reconciler wake-freshness contract is missing: {fragment}")

    require(plan.count(live_capture) == 1 and plan.count(live_normalize) == 1,
            "Ruleset reconciler must fetch and normalize live main exactly once before event classification")
    require(plan.count(strict_current) == 1,
            "Ruleset reconciler push/manual freshness must remain one exact-main equality gate")
    require(plan.count(stale_guard) == 1 and plan.count(stale_message) == 1,
            "Ruleset reconciler superseded workflow_run no-op must remain singular and explicit")

    old_unconditional = (
        'test "$(gh api "repos/portyu9/portyu9/git/ref/heads/main" --jq .object.sha)" '
        '= "$TRUSTED_MAIN_SHA"'
    )
    require(old_unconditional not in plan,
            "Ruleset reconciler plan must not reject a validated queued workflow_run before stale-wake classification")

    checkout_proof = 'test "$(git rev-parse HEAD)" = "$TRUSTED_MAIN_SHA"'
    positions = (
        plan.index(checkout_proof),
        plan.index(live_capture),
        plan.index(event_case),
        plan.index(workflow_run, plan.index(event_case)),
        plan.index(allowlist),
        plan.index(stale_guard),
        plan.index(parent_current),
        plan.index(transition_validate),
    )
    require(list(positions) == sorted(positions) and len(set(positions)) == len(positions),
            "Ruleset reconciler stale-wake validation moved out of reviewed order")

    push_pos = plan.index('push|workflow_dispatch)')
    strict_pos = plan.index(strict_current)
    workflow_pos = plan.index(workflow_run)
    require(push_pos < strict_pos < workflow_pos,
            "Ruleset reconciler must keep push/manual exact-main freshness before workflow_run handling")


def validate_recovery_autonomy_contract(text: str) -> None:
    """Lock autonomous recovery selection to bounded read-only evidence."""
    for forbidden in (
        "ruleset-recovery-approval",
        "authorize-control-plane-recovery-human-gate",
        "inputs.recovery_pr",
        "inputs.recovery_head_sha",
        'test "$DISPATCH_ACTOR" = "portyu9"',
        "human-approved trusted-capability-admission recovery",
    ):
        require(forbidden not in text, f"Ruleset recovery retained human/manual authorization residue: {forbidden}")

    require(
        "  workflow_dispatch:\n" in text
        and "  workflow_dispatch:\n    inputs:\n" not in text,
        "Ruleset reconciler manual dispatch must not carry recovery candidate inputs",
    )
    require(
        "  group: ${{ github.event_name == 'schedule' && 'ruleset-control-plane-recovery-v1' || format('ruleset-reconciler-{0}', github.run_id) }}\n"
        in text,
        "Scheduled recovery/watchdog runs lost transaction serialization",
    )

    selector = reconciler_job_slice(text, "recovery_authorize", "recovery_plan")
    for fragment in (
        "    if: github.event_name == 'schedule'\n",
        "    name: select-control-plane-recovery-candidate-read-only\n",
        "      checks: read\n",
        "      contents: read\n",
        "      pull-requests: read\n",
        "      selected: ${{ steps.authorize.outputs.selected }}\n",
        '          echo "selected=false" >> "$GITHUB_OUTPUT"\n',
        '          test "$GITHUB_EVENT_NAME" = "schedule"\n',
        'recovery-classify-shape --live selector-live-ruleset.json --observable',
        'pulls?state=open&base=main&per_page=100',
        "scripts/workflow_capability_api_collection.py pull-requests",
        ".github/workflows/capability-admission.yml",
        "scripts/capability_admission_workflow_contract.py",
        "validate-contracts",
        "trusted-governed-bot-review",
        "integration-pinned-upstream",
        "dependency-review",
        "analyze-actions",
        "analyze-python",
        "trusted-capability-admission",
        'CANDIDATE_COUNT="$(jq -s \'length\' "$CANDIDATES")"',
        'echo "ERROR: multiple exact autonomous recovery candidates are simultaneously eligible."',
        '          echo "selected=true" >> "$GITHUB_OUTPUT"\n',
    ):
        require(fragment in selector, f"Autonomous recovery selector contract is missing: {fragment}")

    require(
        selector.count("scripts/automation_github_paginated_read.py") == 2
        and selector.count("scripts/workflow_capability_api_collection.py") == 2,
        "Autonomous recovery selector read/normalization budget changed",
    )
    require(
        selector.count('echo "selected=false" >> "$GITHUB_OUTPUT"') == 1
        and selector.count('echo "selected=true" >> "$GITHUB_OUTPUT"') == 1,
        "Autonomous recovery selector decision outputs are no longer singular",
    )

    plan = reconciler_job_slice(text, "recovery_plan", "recovery_create_certificate")
    require(
        "    if: needs.recovery_authorize.outputs.selected == 'true'\n" in plan,
        "Recovery plan is not gated on an exact autonomous selector decision",
    )
    require(
        'SUMMARY="Incomplete transaction certificate for the exact autonomous trusted-capability-admission recovery."'
        in text,
        "Recovery certificate summary still describes human authorization",
    )


def validate_reconciler_main_ref_evidence(text: str) -> None:
    endpoint = 'python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main"'
    legacy = 'gh api "repos/portyu9/portyu9/git/ref/heads/main" --jq .object.sha'
    schema_fragments = (
        'error("Ruleset main ref response must be an object")',
        '.ref != "refs/heads/main"',
        'error("Ruleset main ref identity changed")',
        '((.node_id | type) != "string") or ((.node_id | length) == 0)',
        'error("Ruleset main ref node id is invalid")',
        '((.url | type) != "string") or ((.url | length) == 0)',
        'error("Ruleset main ref URL is invalid")',
        '((.object | type) != "object") or (.object.type != "commit")',
        'error("Ruleset main ref object identity changed")',
        '((.object.sha | type) != "string") or ((.object.sha | test("^[0-9a-f]{40}$")) | not)',
        'error("Ruleset main ref SHA is invalid")',
        '((.object.url | type) != "string") or ((.object.url | length) == 0)',
        'error("Ruleset main ref object URL is invalid")',
        '\n              .object.sha\n            end',
    )
    require(text.count(endpoint) == 5,
            "Ruleset reconciler must retain exactly five reviewed governed main-ref GET call sites")
    require('gh api "repos/portyu9/portyu9/git/ref/heads/main"' not in text,
            "Ruleset reconciler main-ref reads must not regress to direct gh api transport")
    require(legacy not in text,
            "Ruleset reconciler must not consume main-ref SHA through direct gh api --jq")
    require(
        text.count('\n          LIVE_MAIN_REF_RESPONSE="$(python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main")"') == 1,
        "Ruleset plan main-ref response capture changed",
    )
    require(
        text.count('\n          MAIN_REF_RESPONSE="$(python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main")"') == 4,
        "Ruleset privileged main-ref response capture count changed",
    )
    for fragment in schema_fragments:
        require(
            text.count(fragment) == 5,
            f"Ruleset main-ref singleton schema must appear at all five call sites: {fragment}",
        )

    fetch_positions: list[int] = []
    cursor = 0
    while True:
        position = text.find(endpoint, cursor)
        if position < 0:
            break
        fetch_positions.append(position)
        cursor = position + len(endpoint)
    require(len(fetch_positions) == 5,
            "Ruleset main-ref endpoint position inventory changed")

    for index, fetch_pos in enumerate(fetch_positions):
        next_fetch = fetch_positions[index + 1] if index + 1 < len(fetch_positions) else len(text)
        block = text[fetch_pos:next_fetch]
        schema_start = block.find('if type != "object" then')
        schema_end = block.find('\n              .object.sha\n            end', schema_start + 1)
        require(
            schema_start >= 0 and schema_end > schema_start,
            f"Ruleset main-ref call {index + 1} must validate the complete object before SHA projection",
        )
        if index == 0:
            compare = block.find('test "$LIVE_MAIN_SHA" = "$TRUSTED_MAIN_SHA"')
            require(
                'LIVE_MAIN_SHA="$(jq -er' in block,
                "Ruleset plan main-ref normalization variable changed",
            )
        else:
            compare = block.find('test "$MAIN_REF_SHA" = "$TRUSTED_MAIN_SHA"')
            require(
                'MAIN_REF_SHA="$(jq -er' in block,
                f"Ruleset privileged main-ref normalization variable changed at call {index + 1}",
            )
        require(
            compare > schema_end,
            f"Ruleset main-ref call {index + 1} consumed freshness state before schema validation",
        )

    # Negative fixtures: weakening any one required primitive or reintroducing scalar
    # extraction must be rejected by this contract.
    mutated = text.replace(
        'elif .ref != "refs/heads/main" then',
        'elif false then',
        1,
    )
    try:
        validate_reconciler_main_ref_evidence_fixture(mutated)
    except ValueError:
        pass
    else:
        raise ValueError("Ruleset main-ref self-test accepted weakened ref identity")

    mutated = text.replace(
        'MAIN_REF_RESPONSE="$(python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main")"',
        'MAIN_REF_RESPONSE="$(gh api "repos/portyu9/portyu9/git/ref/heads/main" --jq .object.sha)"',
        1,
    )
    try:
        validate_reconciler_main_ref_evidence_fixture(mutated)
    except ValueError:
        pass
    else:
        raise ValueError("Ruleset main-ref self-test accepted direct scalar extraction")


def validate_reconciler_main_ref_evidence_fixture(text: str) -> None:
    endpoint = 'python3 scripts/automation_github_read.py "repos/portyu9/portyu9/git/ref/heads/main"'
    legacy = 'gh api "repos/portyu9/portyu9/git/ref/heads/main" --jq .object.sha'
    require(text.count(endpoint) == 5, "fixture governed endpoint count changed")
    require('gh api "repos/portyu9/portyu9/git/ref/heads/main"' not in text,
            "fixture regained direct main-ref transport")
    require(legacy not in text, "fixture regained direct scalar extraction")
    for fragment in (
        'elif .ref != "refs/heads/main" then',
        '((.object | type) != "object") or (.object.type != "commit")',
        '((.object.sha | type) != "string") or ((.object.sha | test("^[0-9a-f]{40}$")) | not)',
        '((.object.url | type) != "string") or ((.object.url | length) == 0)',
    ):
        require(text.count(fragment) == 5, f"fixture main-ref schema changed: {fragment}")



def validate_reconciler_admin_response_evidence(text: str) -> None:
    """Require typed App/bootstrap responses before authority-bearing scalar use."""
    fragments = (
        'type == "object" and\n            (.id | type == "number" and floor == . and . == $installation)',
        '(.app_id | type == "number" and floor == . and . == $app)',
        '(.account.id | type == "number" and floor == . and . == 35150859)',
        '(.permissions.administration | type == "string" and . == "write")',
        '(.expires_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))',
        '(.total_count | type == "number" and floor == . and . == 1)',
        '(.repositories | type == "array" and length == 1)',
        '(.repositories[0].id | type == "number" and floor == . and . == 1355082509)',
        '(.repositories[0].private | type == "boolean")',
        '(.repositories[0].owner.login | type == "string" and . == "portyu9")',
    )
    for fragment in fragments:
        require(fragment in text, f"Ruleset admin response schema fragment missing: {fragment}")

    admin_read_pin = (
        'test "$(git rev-parse HEAD:scripts/automation_github_ruleset_admin_read.py)" = '
        '"ef7c2306ac7007494a4c6bd951b0160d55c502a2"'
    )
    require(admin_read_pin in text,
            "Ruleset admin governed-read helper identity changed")
    installation_call = (
        'GH_TOKEN="$APP_JWT" python3 scripts/automation_github_ruleset_admin_read.py '
        '"app/installations/${ADMIN_INSTALLATION_ID}" > installation.json'
    )
    repositories_call = (
        'GH_TOKEN="$ADMIN_TOKEN" python3 scripts/automation_github_ruleset_admin_read.py '
        '"installation/repositories?per_page=100" > token-repositories.json'
    )
    for call, label in (
        (installation_call, "App installation"),
        (repositories_call, "installation repository scope"),
    ):
        require(text.count(call) == 1,
                f"Ruleset admin governed {label} read call changed")
    for legacy in (
        'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" '
        '"app/installations/${ADMIN_INSTALLATION_ID}" > installation.json',
        'GH_TOKEN="$ADMIN_TOKEN" gh api "installation/repositories?per_page=100" '
        '> token-repositories.json',
    ):
        require(legacy not in text,
                f"Ruleset admin specialist read regained direct transport: {legacy}")

    installation_fetch = text.index(installation_call)
    installation_schema = text.index('type == "object" and\n            (.id | type == "number"', installation_fetch)
    token_fetch = text.index('"app/installations/${ADMIN_INSTALLATION_ID}/access_tokens"', installation_schema)
    token_schema = text.index('type == "object" and\n            (.token | type == "string"', token_fetch)
    token_consume = text.index('ADMIN_TOKEN="$(jq -r .token installation-token.json)"', token_schema)
    repos_fetch = text.index(repositories_call, token_consume)
    repos_schema = text.index('type == "object" and\n            (.total_count | type == "number"', repos_fetch)
    prewrite = text.index('GH_TOKEN="$ADMIN_TOKEN" python3 scripts/automation_github_read.py "repos/portyu9/portyu9/rulesets/22148161"', repos_schema)
    require(
        installation_fetch < installation_schema < token_fetch < token_schema < token_consume < repos_fetch < repos_schema < prewrite,
        "Ruleset admin response validation must precede token consumption and privileged ruleset reads",
    )



def validate_reconciler_admin_status_evidence(text: str) -> None:
    """Require exact transport status before privileged admin response consumption."""
    token_fetch = (
        'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" '
        '--include --method POST'
    )
    token_status = (
        'INSTALLATION_TOKEN_STATUS_LINE="$(head -n 1 "$INSTALLATION_TOKEN_HTTP_RESPONSE" '
        '| tr -d \'\\r\')"'
    )
    token_guard = (
        '[[ "$INSTALLATION_TOKEN_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    )
    token_extract = (
        'sed \'1,/^[[:space:]]*$/d\' "$INSTALLATION_TOKEN_HTTP_RESPONSE" '
        '> installation-token.json'
    )
    for fragment, label in (
        (token_fetch, "token mutation"),
        (token_status, "token status extraction"),
        (token_guard, "token HTTP 201 guard"),
        (token_extract, "token body extraction"),
    ):
        require(
            text.count(fragment) == 1,
            f"Ruleset admin {label} contract changed",
        )
    require(
        'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" --method POST'
        not in text,
        "Ruleset admin token creation must not discard HTTP transport status",
    )
    token_fetch_pos = text.index(token_fetch)
    token_status_pos = text.index(token_status)
    token_guard_pos = text.index(token_guard)
    token_extract_pos = text.index(token_extract)
    token_schema_pos = text.index(
        'type == "object" and\n            (.token | type == "string"',
        token_extract_pos,
    )
    require(
        token_fetch_pos < token_status_pos < token_guard_pos < token_extract_pos < token_schema_pos,
        "Ruleset admin token HTTP 201 proof must precede body extraction and schema consumption",
    )

    put_fetch = 'GH_TOKEN="$ADMIN_TOKEN" gh api --include --method PUT'
    write_status = 'WRITE_STATUS="$?"'
    success_branch = 'if [ "$WRITE_STATUS" -eq 0 ]; then'
    put_status = (
        'RULESET_PUT_STATUS_LINE="$(head -n 1 "$RULESET_PUT_HTTP_RESPONSE" | tr -d \'\\r\')"'
    )
    put_guard = (
        '[[ "$RULESET_PUT_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {'
    )
    put_extract = (
        'sed \'1,/^[[:space:]]*$/d\' "$RULESET_PUT_HTTP_RESPONSE" '
        '> ruleset-put-response.json'
    )
    readback = (
        'GH_TOKEN="$ADMIN_TOKEN" python3 scripts/automation_github_read.py '
        '"repos/portyu9/portyu9/rulesets/22148161" > live-after.json'
    )
    for fragment, label in (
        (put_fetch, "ruleset mutation"),
        (write_status, "ruleset command status"),
        (success_branch, "ruleset success branch"),
        (put_status, "ruleset HTTP status extraction"),
        (put_guard, "ruleset HTTP 200 guard"),
        (put_extract, "ruleset success-body extraction"),
        (readback, "ruleset successor readback"),
    ):
        require(
            text.count(fragment) == 1,
            f"Ruleset admin {label} contract changed",
        )
    require(
        'GH_TOKEN="$ADMIN_TOKEN" gh api --method PUT' not in text,
        "Ruleset admin PUT must not discard HTTP transport status",
    )
    put_fetch_pos = text.index(put_fetch)
    write_status_pos = text.index(write_status)
    success_branch_pos = text.index(success_branch)
    put_status_pos = text.index(put_status)
    put_guard_pos = text.index(put_guard)
    put_extract_pos = text.index(put_extract)
    readback_pos = text.index(readback)
    require(
        put_fetch_pos < write_status_pos < success_branch_pos < put_status_pos
        < put_guard_pos < put_extract_pos < readback_pos,
        "Ruleset admin successful PUT must prove HTTP 200 before body extraction and successor readback",
    )
    require(
        'if [ "$WRITE_STATUS" -ne 0 ]; then' not in text,
        "Ruleset admin must preserve nonzero-write successor-readback ambiguity handling without retry",
    )


def self_test_reconciler_admin_status_evidence(text: str) -> None:
    validate_reconciler_admin_status_evidence(text)
    token_fetch = (
        'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" '
        '--include --method POST'
    )
    token_guard = (
        '[[ "$INSTALLATION_TOKEN_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {'
    )
    put_fetch = 'GH_TOKEN="$ADMIN_TOKEN" gh api --include --method PUT'
    put_guard = (
        '[[ "$RULESET_PUT_STATUS_LINE" =~ '
        '^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {'
    )
    mutations = (
        (
            text.replace(token_fetch, token_fetch.replace("--include ", ""), 1),
            "token mutation contract changed",
        ),
        (
            text.replace(
                token_guard,
                token_guard.replace("+201", "+200"),
                1,
            ),
            "token HTTP 201 guard contract changed",
        ),
        (
            text.replace(put_fetch, put_fetch.replace("--include ", ""), 1),
            "ruleset mutation contract changed",
        ),
        (
            text.replace(
                put_guard,
                put_guard.replace("+200", "+201"),
                1,
            ),
            "ruleset HTTP 200 guard contract changed",
        ),
    )
    for mutated, expected in mutations:
        try:
            validate_reconciler_admin_status_evidence(mutated)
        except ValueError as exc:
            require(
                expected in str(exc),
                f"Ruleset admin HTTP-status self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                f"Ruleset admin HTTP-status self-test accepted weakened transport proof: {expected}"
            )

    token_guard_block = (
        '          [[ "$INSTALLATION_TOKEN_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
        '            echo "ERROR: Ruleset Administration App token creation returned unexpected status: ${INSTALLATION_TOKEN_STATUS_LINE}" >&2\n'
        '            exit 1\n'
        '          }\n'
        '          sed \'1,/^[[:space:]]*$/d\' "$INSTALLATION_TOKEN_HTTP_RESPONSE" > installation-token.json\n'
    )
    token_reordered = (
        '          sed \'1,/^[[:space:]]*$/d\' "$INSTALLATION_TOKEN_HTTP_RESPONSE" > installation-token.json\n'
        '          [[ "$INSTALLATION_TOKEN_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$) ]] || {\n'
        '            echo "ERROR: Ruleset Administration App token creation returned unexpected status: ${INSTALLATION_TOKEN_STATUS_LINE}" >&2\n'
        '            exit 1\n'
        '          }\n'
    )
    reordered = text.replace(token_guard_block, token_reordered, 1)
    try:
        validate_reconciler_admin_status_evidence(reordered)
    except ValueError as exc:
        require(
            "must precede body extraction" in str(exc),
            f"Ruleset admin token-order self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Ruleset admin HTTP-status self-test accepted token body before status proof")

    put_guard_block = (
        '            [[ "$RULESET_PUT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
        '              echo "ERROR: Protect Main ruleset update returned unexpected status: ${RULESET_PUT_STATUS_LINE}" >&2\n'
        '              exit 1\n'
        '            }\n'
        '            sed \'1,/^[[:space:]]*$/d\' "$RULESET_PUT_HTTP_RESPONSE" > ruleset-put-response.json\n'
    )
    put_reordered = (
        '            sed \'1,/^[[:space:]]*$/d\' "$RULESET_PUT_HTTP_RESPONSE" > ruleset-put-response.json\n'
        '            [[ "$RULESET_PUT_STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$) ]] || {\n'
        '              echo "ERROR: Protect Main ruleset update returned unexpected status: ${RULESET_PUT_STATUS_LINE}" >&2\n'
        '              exit 1\n'
        '            }\n'
    )
    reordered = text.replace(put_guard_block, put_reordered, 1)
    try:
        validate_reconciler_admin_status_evidence(reordered)
    except ValueError as exc:
        require(
            "successful PUT must prove HTTP 200 before body extraction" in str(exc),
            f"Ruleset admin PUT-order self-test failed for wrong reason: {exc}",
        )
    else:
        raise ValueError("Ruleset admin HTTP-status self-test accepted PUT body before status proof")


def reconciler_job_slice(text: str, job_id: str, next_job_id: str) -> str:
    start_marker = f"  {job_id}:\n"
    end_marker = f"  {next_job_id}:\n"
    require(text.count(start_marker) == 1, f"Ruleset reconciler job boundary changed: {job_id}")
    require(text.count(end_marker) == 1, f"Ruleset reconciler job boundary changed: {next_job_id}")
    start = text.index(start_marker)
    end = text.index(end_marker, start + len(start_marker))
    require(start < end, f"Ruleset reconciler job order changed: {job_id} -> {next_job_id}")
    return text[start:end]


def validate_recovery_admin_transport_evidence(text: str) -> None:
    """Bind every recovery ruleset writer to serialized, status-checked admin transport."""
    specs = (
        ("recovery_open", "recovery_complete_certificate", "recovery open"),
        ("recovery_restore", "recovery_attest", "recovery restore"),
        ("watchdog_restore", "watchdog_attest", "watchdog restore"),
    )
    for job_id, next_job_id, label in specs:
        block = reconciler_job_slice(text, job_id, next_job_id)
        for fragment in (
            "    concurrency:\n"
            "      group: ruleset-reconciler-admin-write\n"
            "      cancel-in-progress: false\n",
            "    environment: ruleset-admin-identity\n",
            "          ADMIN_APP_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_APP_ID }}\n",
            "          ADMIN_INSTALLATION_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_INSTALLATION_ID }}\n",
            "          ADMIN_PRIVATE_KEY: ${{ secrets.PORTYU9_RULESET_ADMIN_PRIVATE_KEY }}\n",
            'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" --include --method POST',
            '"app/installations/${ADMIN_INSTALLATION_ID}/access_tokens"',
            '^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$)',
            'GH_TOKEN="$ADMIN_TOKEN" gh api --include --method PUT',
            '^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$)',
            'WRITE_STATUS="$?"',
            'if [ "$WRITE_STATUS" -eq 0 ]; then',
        ):
            require(fragment in block, f"Ruleset {label} transport contract is missing: {fragment}")
        require(
            block.count('GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" --include --method POST') == 1
            and block.count('GH_TOKEN="$ADMIN_TOKEN" gh api --include --method PUT') == 1,
            f"Ruleset {label} must retain exactly one token POST and one ruleset PUT",
        )
        require(
            block.index('GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" --include --method POST')
            < block.index('^HTTP/[0-9.]+[[:space:]]+201([[:space:]]|$)')
            < block.index('GH_TOKEN="$ADMIN_TOKEN" gh api --include --method PUT')
            < block.index('WRITE_STATUS="$?"')
            < block.index('if [ "$WRITE_STATUS" -eq 0 ]; then')
            < block.index('^HTTP/[0-9.]+[[:space:]]+200([[:space:]]|$)'),
            f"Ruleset {label} transport proof moved out of reviewed order",
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
    required_status_context_map(
        status.get("required_status_checks"),
        expected_integration,
    )

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



def validate_sentinel_main_ref_evidence(text: str, *, run_self_test: bool = True) -> None:
    capture = 'LIVE_MAIN_REF_RESPONSE="$(python3 scripts/automation_github_read.py "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"'
    normalize = 'LIVE_MAIN_SHA="$(jq -er \''
    consume = 'test "$LIVE_MAIN_SHA" = "$EXPECTED_MAIN_SHA"'
    endpoint = 'python3 scripts/automation_github_read.py "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"'
    legacy = 'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq \' .object.sha\''

    for marker in (capture, normalize, consume):
        require(
            text.count(marker) == 1,
            f"Ruleset sentinel main-ref evidence anchor changed: {marker}",
        )
    require(
        text.count(endpoint) == 1,
        "Ruleset sentinel must retain exactly one reviewed main-ref GET",
    )
    require(
        'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"' not in text,
        "Ruleset sentinel regressed to direct main-ref GitHub transport",
    )
    require(
        'test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"' in text,
        "Ruleset sentinel governed main-ref read lost exact helper identity",
    )
    require(
        "GH_TOKEN: ${{ github.token }}" in text,
        "Ruleset sentinel governed main-ref read lost run-scoped token binding",
    )
    require(
        "permissions:\n  contents: read" in text
        and "permissions:\n      contents: read" in text,
        "Ruleset sentinel must retain workflow/job contents-read-only authority",
    )
    require(
        "run: python3 scripts/validate-ruleset-contract.py --live" in text,
        "Ruleset sentinel must retain live fail-closed ruleset validation",
    )

    start = text.index(normalize)
    normalize_end_marker = '\' <<<"$LIVE_MAIN_REF_RESPONSE")"'
    normalize_end = text.index(normalize_end_marker, start) + len(normalize_end_marker)
    schema = text[start:normalize_end]
    for fragment in (
        'error("Ruleset sentinel main ref response must be an object")',
        '.ref != "refs/heads/main"',
        'error("Ruleset sentinel main ref identity changed")',
        '((.node_id | type) != "string") or ((.node_id | length) == 0)',
        'error("Ruleset sentinel main ref node id is invalid")',
        '((.url | type) != "string") or ((.url | length) == 0)',
        'error("Ruleset sentinel main ref URL is invalid")',
        '((.object | type) != "object") or (.object.type != "commit")',
        'error("Ruleset sentinel main ref object identity changed")',
        '((.object.sha | type) != "string") or ((.object.sha | test("^[0-9a-f]{40}$")) | not)',
        'error("Ruleset sentinel main ref SHA is invalid")',
        '((.object.url | type) != "string") or ((.object.url | length) == 0)',
        'error("Ruleset sentinel main ref object URL is invalid")',
        ".object.sha",
    ):
        require(
            fragment in schema,
            f"Ruleset sentinel main-ref schema changed: {fragment}",
        )

    schema_proof = text.index(
        'error("Ruleset sentinel main ref response must be an object")',
        start,
    )
    consume_pos = text.index(consume)
    positions = (text.index(capture), start, schema_proof, normalize_end, consume_pos)
    require(
        list(positions) == sorted(positions) and len(set(positions)) == len(positions),
        "Ruleset sentinel main-ref schema must precede trusted-main SHA consumption",
    )

    if run_self_test:
        mutations = (
            (
                '.ref != "refs/heads/main"',
                '(.ref | tostring) != "refs/heads/main"',
                "main-ref schema changed",
            ),
            (
                '((.node_id | type) != "string") or ((.node_id | length) == 0)',
                '((.node_id | tostring | length) == 0)',
                "main-ref schema changed",
            ),
            (
                '((.object | type) != "object") or (.object.type != "commit")',
                '(.object.type | tostring) != "commit"',
                "main-ref schema changed",
            ),
            (
                '((.object.sha | type) != "string") or ((.object.sha | test("^[0-9a-f]{40}$")) | not)',
                '((.object.sha | tostring | test("^[0-9a-f]{40}$")) | not)',
                "main-ref schema changed",
            ),
            (
                '((.object.url | type) != "string") or ((.object.url | length) == 0)',
                '((.object.url | tostring | length) == 0)',
                "main-ref schema changed",
            ),
        )
        for current, replacement, expected in mutations:
            require(
                current in schema,
                f"Ruleset sentinel main-ref self-test fixture anchor changed: {current}",
            )
            mutated = text.replace(current, replacement, 1)
            try:
                validate_sentinel_main_ref_evidence(mutated, run_self_test=False)
            except ValueError as exc:
                require(
                    expected in str(exc),
                    f"Ruleset sentinel main-ref self-test failed for wrong reason: {exc}",
                )
            else:
                raise ValueError(
                    "Ruleset sentinel main-ref self-test accepted weakened evidence: "
                    f"{current}"
                )

        schema_block = text[start:normalize_end]
        displaced = text[:start] + text[normalize_end:]
        consume_pos = displaced.index(consume)
        consume_end = displaced.index("\n", consume_pos) + 1
        reordered = displaced[:consume_end] + schema_block + displaced[consume_end:]
        try:
            validate_sentinel_main_ref_evidence(reordered, run_self_test=False)
        except ValueError as exc:
            require(
                "schema must precede trusted-main SHA consumption" in str(exc),
                f"Ruleset sentinel main-ref order self-test failed for wrong reason: {exc}",
            )
        else:
            raise ValueError(
                "Ruleset sentinel main-ref self-test accepted schema-after-consumption ordering"
            )



def expect_recovery_candidate_failure(
    *,
    candidate_root: Path,
    changed_paths: Path,
    candidate_tree_sha: str,
    label: str,
) -> None:
    try:
        ruleset_transition_contract.evaluate_recovery_candidate(
            candidate_root=candidate_root,
            changed_paths=changed_paths,
            candidate_tree_sha=candidate_tree_sha,
        )
    except ValueError:
        return
    raise ValueError(f"recovery acceptance fixture unexpectedly accepted: {label}")


def self_test_recovery_acceptance() -> None:
    transition = ruleset_transition_contract.load_contract()
    recovery = ruleset_transition_contract.load_recovery_contract(transition)
    require(
        recovery["allowedChangedPaths"] == [
            ".github/workflows/capability-admission.yml",
            "scripts/capability_admission_workflow_contract.py",
        ],
        "recovery acceptance fixture scope drifted",
    )

    workflow_relative = Path(".github/workflows/capability-admission.yml")
    companion_relative = Path("scripts/capability_admission_workflow_contract.py")
    reconciler_relative = Path(".github/workflows/ruleset-reconciler.yml")
    changed_paths_text = "\n".join(recovery["allowedChangedPaths"]) + "\n"

    with tempfile.TemporaryDirectory() as tmp:
        fixture_root = Path(tmp)
        positive_root = fixture_root / "positive"
        shutil.copytree(
            ROOT,
            positive_root,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__"),
        )

        workflow_path = positive_root / workflow_relative
        workflow_text = workflow_path.read_text(encoding="utf-8")
        identity_anchor = (
            '          test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = '
            '"1b779bcea0acd290826fef8f60fd01480113a31a"\n'
            '          test "$(git rev-parse HEAD:scripts/automation_github_repository_read.py)" = '
            '"12acd01e53c84558617e868e9f3489f9770c85d8"\n'
        )
        require(
            workflow_text.count(identity_anchor) == 1,
            "recovery acceptance positive workflow anchor changed",
        )
        repaired_identity = identity_anchor.replace("\n          test", "\n\n          test", 1)
        workflow_text = workflow_text.replace(identity_anchor, repaired_identity, 1)
        workflow_path.write_text(workflow_text, encoding="utf-8")

        # Git blob identities for the exact accepted workflow and this one-line
        # physical fixture repair. The fixture never computes a cryptographic digest.
        base_blob = "bac9f39e9489c0b542d2fee3a03d72fb86c12bbb"
        candidate_blob = "e16e1972ac857bbbbebe6554228a4c3bc2562402"

        companion_path = positive_root / companion_relative
        companion_text = companion_path.read_text(encoding="utf-8")
        blob_anchor = f'EXPECTED_GIT_BLOB = "{base_blob}"'
        require(
            companion_text.count(blob_anchor) == 1,
            "recovery acceptance companion blob anchor changed",
        )
        companion_text = companion_text.replace(
            blob_anchor,
            f'EXPECTED_GIT_BLOB = "{candidate_blob}"',
            1,
        )
        companion_identity_anchor = (
            '        \'          test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = '
            '"1b779bcea0acd290826fef8f60fd01480113a31a"\\n\'\n'
            '        \'          test "$(git rev-parse HEAD:scripts/automation_github_repository_read.py)" = '
            '"12acd01e53c84558617e868e9f3489f9770c85d8"\\n\'\n'
        )
        require(
            companion_text.count(companion_identity_anchor) == 1,
            "recovery acceptance companion identity anchor changed",
        )
        companion_text = companion_text.replace(
            companion_identity_anchor,
            companion_identity_anchor.splitlines(keepends=True)[0]
            + "        '\\n'\n"
            + companion_identity_anchor.splitlines(keepends=True)[1],
            1,
        )
        companion_path.write_text(companion_text, encoding="utf-8")

        changed_paths = fixture_root / "changed-paths.txt"
        changed_paths.write_text(changed_paths_text, encoding="utf-8")
        positive = ruleset_transition_contract.evaluate_recovery_candidate(
            candidate_root=positive_root,
            changed_paths=changed_paths,
            candidate_tree_sha="1" * 40,
        )
        require(
            positive["expansions"] == []
            and positive["reductions"] == []
            and positive["changedPaths"] == recovery["allowedChangedPaths"]
            and positive["changedProtectedPaths"] == [str(workflow_relative)],
            "recovery acceptance positive fixture no longer proves raw semantic identity and exact repair scope",
        )

        permission_anchor = (
            "    permissions:\n"
            "      actions: read\n"
            "      checks: write\n"
            "      contents: read\n"
            "      pull-requests: read\n"
        )
        trigger_anchor = "on:\n  pull_request_target:\n"
        reference_anchor = "    timeout-minutes: 6\n"
        api_anchor = (
            "      - name: Verify exact governed read transport identity\n"
            "        run: |\n"
            "          set -euo pipefail\n"
        )
        dependency_anchor = "  admission:\n    name: trusted-capability-admission\n"
        reference_expression = "$" + "{{ vars.RECOVERY_ACCEPTANCE_FIXTURE }}"

        variants = (
            (
                "write-permission",
                permission_anchor,
                permission_anchor.replace("      contents: read\n", "      contents: write\n"),
            ),
            (
                "trigger",
                trigger_anchor,
                "on:\n  push:\n    branches:\n      - main\n  pull_request_target:\n",
            ),
            (
                "expression-reference",
                reference_anchor,
                reference_anchor + "    env:\n      RECOVERY_ACCEPTANCE_FIXTURE: " + reference_expression + "\n",
            ),
            (
                "api-mutation",
                api_anchor,
                api_anchor
                + '          gh api --method POST "repos/$GITHUB_REPOSITORY/actions/workflows/'
                + 'capability-admission.yml/dispatches" -f ref=main\n',
            ),
            (
                "job-dependency",
                dependency_anchor,
                "  admission:\n    needs: recovery-acceptance-parent\n    name: trusted-capability-admission\n",
            ),
        )

        for index, (label, anchor, replacement) in enumerate(variants, start=2):
            variant_root = fixture_root / label
            shutil.copytree(positive_root, variant_root, symlinks=True)
            variant_workflow = variant_root / workflow_relative
            variant_text = variant_workflow.read_text(encoding="utf-8")
            require(
                variant_text.count(anchor) == 1,
                f"recovery acceptance {label} fixture anchor changed",
            )
            variant_workflow.write_text(
                variant_text.replace(anchor, replacement, 1),
                encoding="utf-8",
            )
            expect_recovery_candidate_failure(
                candidate_root=variant_root,
                changed_paths=changed_paths,
                candidate_tree_sha=str(index) * 40,
                label=label,
            )

        second_protected_root = fixture_root / "second-protected-source"
        shutil.copytree(positive_root, second_protected_root, symlinks=True)
        second_reconciler = second_protected_root / reconciler_relative
        second_reconciler.write_text(
            second_reconciler.read_text(encoding="utf-8")
            + "\n# recovery acceptance forbidden second protected-source fixture\n",
            encoding="utf-8",
        )
        expect_recovery_candidate_failure(
            candidate_root=second_protected_root,
            changed_paths=changed_paths,
            candidate_tree_sha="7" * 40,
            label="second-protected-source",
        )

    run_id = 424242
    run_attempt = 3
    candidate_head_sha = "a" * 40
    trusted_main_sha = "b" * 40
    candidate_pr = 1234
    check_id = 987654
    issued_at = 1_800_000_000
    expires_at = issued_at + recovery["leaseSeconds"]
    context = ruleset_transition_contract.recovery_context(
        run_id, run_attempt, candidate_head_sha
    )
    normal_live = {
        "id": ruleset_transition_contract.RULESET_ID,
        **json.loads(json.dumps(transition["successor"])),
    }
    temporary_live = {
        "id": ruleset_transition_contract.RULESET_ID,
        **ruleset_transition_contract.recovery_temporary_payload(
            transition, run_id, run_attempt, candidate_head_sha
        ),
    }
    open_receipt = ruleset_transition_contract.recovery_transition_receipt(
        direction="open",
        before=normal_live,
        after=temporary_live,
        transition=transition,
        recovery=recovery,
        trusted_main_sha=trusted_main_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        candidate_pr=candidate_pr,
        candidate_head_sha=candidate_head_sha,
        check_id=check_id,
        issued_at=issued_at,
        expires_at=expires_at,
        write_status=0,
    )
    close_receipt = ruleset_transition_contract.recovery_transition_receipt(
        direction="close",
        before=temporary_live,
        after=normal_live,
        transition=transition,
        recovery=recovery,
        trusted_main_sha=trusted_main_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        candidate_pr=candidate_pr,
        candidate_head_sha=candidate_head_sha,
        check_id=check_id,
        issued_at=issued_at,
        expires_at=expires_at,
        write_status=0,
    )
    watchdog_receipt = ruleset_transition_contract.recovery_watchdog_receipt(
        before=temporary_live,
        after=normal_live,
        transition=transition,
        recovery=recovery,
        trusted_main_sha=trusted_main_sha,
        run_id=run_id + 100,
        run_attempt=1,
        issued_at=issued_at,
        write_status=0,
    )
    result_receipt = ruleset_transition_contract.recovery_result_receipt(
        trusted_main_sha=trusted_main_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        candidate_pr=candidate_pr,
        candidate_head_sha=candidate_head_sha,
        check_id=check_id,
        transaction_context=context,
        merged=True,
        merge_sha="c" * 40,
        open_receipt_sha256=ruleset_transition_contract.sha256(open_receipt),
        restore_receipt_sha256=ruleset_transition_contract.sha256(close_receipt),
    )
    require(
        open_receipt["direction"] == "open"
        and close_receipt["direction"] == "close"
        and watchdog_receipt["direction"] == "watchdog-close"
        and result_receipt["merged"] is True
        and result_receipt["transactionContext"] == context,
        "recovery acceptance receipt constructor invariants changed",
    )

    future_context = ruleset_transition_contract.recovery_context(
        run_id + 1, run_attempt, candidate_head_sha
    )
    require(
        future_context != context,
        "recovery transaction context is not unique across runs",
    )
    try:
        ruleset_transition_contract.classify_recovery_exact(
            temporary_live,
            transition,
            recovery,
            run_id + 1,
            run_attempt,
            candidate_head_sha,
        )
    except ValueError:
        pass
    else:
        raise ValueError("stale recovery context satisfied a future transaction")


def self_test(payload: dict[str, Any]) -> None:
    # The deliberate administration transition is pure source logic. Exercise its
    # exact predecessor/successor classifier here so runtime-only ordering or digest
    # regressions fail in ordinary protected PR validation before any admin run.
    ruleset_transition_contract.self_test()
    self_test_recovery_acceptance()
    transition = ruleset_transition_contract.load_contract()
    transition_predecessor = next(
        rule for rule in transition["predecessor"]["rules"] if rule["type"] == "required_status_checks"
    )["parameters"]["required_status_checks"]
    transition_successor = next(
        rule for rule in transition["successor"]["rules"] if rule["type"] == "required_status_checks"
    )["parameters"]["required_status_checks"]
    require(
        frozenset(entry["context"] for entry in transition_predecessor) == TRANSITION_PREDECESSOR_CONTEXTS
        and all(entry["integration_id"] == EXPECTED_INTEGRATION_ID for entry in transition_predecessor),
        "ruleset transition predecessor no longer matches the exact legacy required-check state",
    )
    require(
        frozenset(entry["context"] for entry in transition_successor) == EXPECTED_CONTEXTS
        and all(entry["integration_id"] == EXPECTED_INTEGRATION_ID for entry in transition_successor),
        "ruleset transition successor no longer matches the exact desired required-check state",
    )

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
    require(
        set(required_status_context_map(canonical_statuses, EXPECTED_INTEGRATION_ID)) == set(EXPECTED_CONTEXTS),
        "required status identity fixture changed",
    )
    predecessor_statuses = [
        {"context": context, "integration_id": EXPECTED_INTEGRATION_ID}
        for context in sorted(TRANSITION_PREDECESSOR_CONTEXTS)
    ]
    try:
        required_status_context_map(predecessor_statuses, EXPECTED_INTEGRATION_ID)
    except ValueError as exc:
        require("count differs from contract" in str(exc),
                f"final-state predecessor rejection self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted the retired six-context predecessor as live final state")

    unexpected_statuses = [dict(entry) for entry in canonical_statuses]
    unexpected_statuses[-1]["context"] = "unexpected-context"
    try:
        required_status_context_map(unexpected_statuses, EXPECTED_INTEGRATION_ID)
    except ValueError as exc:
        require("final reviewed state" in str(exc),
                f"final-state context self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("ruleset self-test accepted an unreviewed final context set")
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
        for path in (CONTRACT, DOC, QUALITY, RECONCILER, SENTINEL):
            require(path.is_file(), f"ruleset contract input is missing: {path.relative_to(ROOT)}")
        payload = load_contract()
        validate_source(payload)
        reconciler = RECONCILER.read_text(encoding="utf-8")
        validate_reconciler_wake_contract(reconciler)
        validate_recovery_autonomy_contract(reconciler)
        validate_reconciler_main_ref_evidence(reconciler)
        historical_reconcile = reconciler_job_slice(reconciler, "reconcile", "attest")
        validate_reconciler_admin_response_evidence(historical_reconcile)
        validate_reconciler_admin_status_evidence(historical_reconcile)
        self_test_reconciler_admin_status_evidence(historical_reconcile)
        validate_recovery_admin_transport_evidence(reconciler)
        sentinel = SENTINEL.read_text(encoding="utf-8")
        validate_sentinel_main_ref_evidence(sentinel)
        self_test(payload)
        unobservable: tuple[str, ...] = ()
        if args.live:
            unobservable = validate_live(payload)
        suffix = " + live observable GitHub control-plane state" if args.live else ""
        print(
            f"Repository ruleset contract passed: source-controlled target{suffix} is internally consistent; "
            f"seven required contexts are bound to integration_id {EXPECTED_INTEGRATION_ID}; exact JSON primitive identity, "
            f"superseded trusted workflow-run wakes reduce to read-only no-ops, all five historical privileged reconciler main-ref reads plus the read-only drift-sentinel main-ref read are typed before SHA consumption, every historical/recovery Administration token and ruleset writer proves exact HTTP 201/200 on nominal success under one non-cancellable serialization group, and observable drift fails closed."
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