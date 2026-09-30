#!/usr/bin/env python3
"""Executable deterministic retry taxonomy for governed automation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from typing import Any

import automation_github_paginated_read
import automation_github_read

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/automation-retry-policy-v1.json"
WORKFLOWS = ROOT / ".github/workflows"
PINNED_GENERATOR = "shinpr/github-profile-stats@49b5f7091182a45f3ef93923505b660c6da5f835 # v0.2.0"
GOVERNED_REVIEW_GATE = ROOT / "scripts/governed_bot_review_gate.py"
ACTION_RELEASE_PROVENANCE = ROOT / "scripts/validate-action-release-provenance.py"
SPOTLIGHT_MERGE_AUTHORIZATION = ROOT / "scripts/prepare-spotlight-merge-authorization.py"

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

EXPECTED_AUTOMATIC_RETRY_IDS = {
    "governed-bot-review-read-transient",
    "bot-pr-user-approval-shell-read-transient",
    "bot-pr-review-convergence-shell-read-transient",
    "action-release-provenance-read-transient",
    "canonical-github-api-read-transient",
    "spotlight-approve-shell-read-transient",
    "spotlight-reconcile-shell-read-transient",
    "spotlight-propose-shell-read-transient",
    "spotlight-merge-shell-read-transient",
}
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
    require(len(declared) == 15, "retry policy must classify exactly the current 15 bounded seq loops")
    ids = [item.get("id") for item in declared if isinstance(item, dict)]
    require(len(ids) == len(set(ids)) == 15 and all(isinstance(value, str) and value for value in ids),
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
        elif mode == "guarded-once-per-run-id-plus-state-conditioned-review-dispatch":
            approval_mutations = [
                row for row in mutations
                if "/actions/runs/" in row and "/approve" in row and "--method POST" in row
            ]
            reviewer_dispatch_mutations = [
                row for row in mutations
                if "/actions/workflows/bot-pr-user-approval.yml/dispatches" in row
                and "--method POST" in row
            ]
            require(
                len(mutations) == 2
                and len(approval_mutations) == 1
                and len(reviewer_dispatch_mutations) == 1,
                f"mixed guarded observation mutation surface changed: {rule.get('id')}",
            )
            block = loop["block"]
            owner = named_step(texts[loop["workflow"]], loop["job"], loop["step"])
            require(
                'APPROVAL_REQUESTED_RUN_IDS=""' in owner,
                f"mixed guarded observation lost once-per-run approval dedupe initialization: {rule.get('id')}",
            )
            for fragment in (
                'case " $APPROVAL_REQUESTED_RUN_IDS " in',
                'APPROVAL_REQUESTED_RUN_IDS="',
            ):
                require(
                    fragment in block,
                    f"mixed guarded observation lost once-per-run approval dedupe: {rule.get('id')}",
                )
            require(
                'REVIEW_DISPATCHED=false' in owner,
                f"mixed guarded observation lost reviewer-dispatch dedupe initialization: {rule.get('id')}",
            )
            for fragment in (
                'if [ "$REVIEW_DISPATCHED" = "false" ] &&',
                '[ "$CODEQL_SUCCESS" = "true" ] &&',
                '[ "$DEPENDENCY_SUCCESS" = "true" ]; then',
                'REVIEW_READY=true',
                'for CONTEXT in validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review trusted-capability-admission; do',
                'if [ "$REVIEW_READY" = "true" ]; then',
                'REVIEW_DISPATCHED=true',
                'test "$REVIEW_DISPATCHED" = "true"',
            ):
                require(
                    fragment in owner,
                    f"mixed guarded observation lost state-conditioned reviewer-dispatch guard: {rule.get('id')}: {fragment}",
                )
            require(
                block.index('if [ "$REVIEW_DISPATCHED" = "false" ] &&')
                < block.index('if [ "$REVIEW_READY" = "true" ]; then')
                < block.index('/actions/workflows/bot-pr-user-approval.yml/dispatches')
                < block.index('REVIEW_DISPATCHED=true'),
                f"mixed guarded observation reviewer-dispatch ordering changed: {rule.get('id')}",
            )
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


def validate_automatic_retries(policy: dict[str, Any], texts: dict[str, str]) -> None:
    entries = policy.get("automaticRetries")
    require(isinstance(entries, list), "retry policy automaticRetries must be an array")
    require(
        {item.get("id") for item in entries if isinstance(item, dict)} == EXPECTED_AUTOMATIC_RETRY_IDS,
        "automatic retry identities changed",
    )
    require(len(entries) == 9 and all(isinstance(item, dict) for item in entries),
            "retry policy must authorize exactly nine classified automatic read retries")
    by_id = {item["id"]: item for item in entries}
    require(len(by_id) == 9, "automatic retry IDs must remain unique")

    for identifier in sorted(EXPECTED_AUTOMATIC_RETRY_IDS):
        item = by_id[identifier]
        require(item.get("operation") == "read-only-github-api-get",
                f"automatic retry operation must remain read-only GitHub GET: {identifier}")
        require(item.get("failureClassifier") == "transport-or-github-transient-v1",
                f"automatic retry transient classifier changed: {identifier}")
        require(item.get("maxAttempts") == 3 and item.get("timeoutSeconds") == 20,
                f"automatic retry attempt/timeout budget changed: {identifier}")
        require(item.get("backoffSeconds") == [1.0, 2.0],
                f"automatic retry deterministic backoff changed: {identifier}")
        require(item.get("retryableHttpStatus") == [408, 429, 500, 502, 503, 504],
                f"automatic retry HTTP status allowlist changed: {identifier}")
        require(item.get("rateLimited403") is True and item.get("retryAfterCapSeconds") == 5.0,
                f"automatic retry GitHub rate-limit classifier changed: {identifier}")
        require(item.get("mutationRetry") is False,
                f"automatic retry must never authorize mutation replay: {identifier}")
        require(isinstance(item.get("rationale"), str) and "read-only" in item["rationale"],
                f"automatic retry rationale must preserve read-only scope: {identifier}")

    review_item = by_id["governed-bot-review-read-transient"]
    require(review_item.get("source") == "scripts/governed_bot_review_gate.py",
            "governed-review automatic retry source changed")
    gate = GOVERNED_REVIEW_GATE.read_text(encoding="utf-8")
    for fragment in (
        "READ_ATTEMPTS = 3",
        "READ_TIMEOUT_SECONDS = 20",
        "READ_BACKOFF_SECONDS = (1.0, 2.0)",
        "READ_MAX_RETRY_AFTER_SECONDS = 5.0",
        "READ_RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})",
        "def retryable_read_http_error(exc: urllib.error.HTTPError) -> bool:",
        'headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))',
        "for attempt in range(READ_ATTEMPTS):",
        'method="GET"',
        "attempt + 1 >= READ_ATTEMPTS or not retryable_read_http_error(exc)",
        "except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:",
        "except (json.JSONDecodeError, UnicodeDecodeError) as exc:",
    ):
        require(fragment in gate, f"classified review-gate read retry contract is missing: {fragment}")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"'):
        require(forbidden not in gate,
                f"review-gate automatic retry source acquired mutation method: {forbidden}")

    provenance_item = by_id["action-release-provenance-read-transient"]
    require(provenance_item.get("source") == "scripts/validate-action-release-provenance.py",
            "Action provenance automatic retry source changed")
    provenance = ACTION_RELEASE_PROVENANCE.read_text(encoding="utf-8")
    for fragment in (
        "PUBLIC_API_ATTEMPTS = 3",
        "PUBLIC_API_TIMEOUT_SECONDS = 20",
        "PUBLIC_API_BACKOFF_SECONDS = (1.0, 2.0)",
        "PUBLIC_API_MAX_RETRY_AFTER_SECONDS = 5.0",
        "PUBLIC_API_RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})",
        "def retryable_public_api_http_error(exc: urllib.error.HTTPError) -> bool:",
        'headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))',
        "for attempt in range(PUBLIC_API_ATTEMPTS):",
        'method="GET"',
        "attempt + 1 >= PUBLIC_API_ATTEMPTS or not retryable_public_api_http_error(exc)",
        "except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:",
        'headers=public_api_headers(os.environ.get("GH_TOKEN"))',
    ):
        require(fragment in provenance,
                f"classified Action provenance read retry contract is missing: {fragment}")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"'):
        require(forbidden not in provenance,
                f"Action provenance automatic retry source acquired mutation method: {forbidden}")

    canonical_item = by_id["canonical-github-api-read-transient"]
    require(canonical_item.get("source") == "scripts/automation_github_read.py",
            "canonical GitHub read retry source changed")
    require(canonical_item.get("endpointScope") == "repository-relative",
            "canonical GitHub read endpoint scope changed")
    require(canonical_item.get("maxResponseBytes") == 8_000_000,
            "canonical GitHub read response-size bound changed")
    automation_github_read.self_test()
    canonical_source = (ROOT / canonical_item["source"]).read_text(encoding="utf-8")
    for fragment in (
        'API_ROOT = "https://api.github.com/"',
        "ATTEMPTS = 3",
        "TIMEOUT_SECONDS = 20",
        "BACKOFF_SECONDS = (1.0, 2.0)",
        "MAX_RETRY_AFTER_SECONDS = 5.0",
        "MAX_RESPONSE_BYTES = 8_000_000",
        "RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})",
        "def retryable_http_error(exc: urllib.error.HTTPError) -> bool:",
        'headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))',
        "for attempt in range(ATTEMPTS):",
        'method="GET"',
        'require(credential is not None, "GH_TOKEN is required for governed GitHub API reads")',
        'segments[0] == "repos"',
        "strict_json(text)",
    ):
        require(fragment in canonical_source,
                f"canonical governed GitHub read contract is missing: {fragment}")
    for forbidden in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"'):
        require(forbidden not in canonical_source,
                f"canonical GitHub read source acquired mutation method: {forbidden}")

    bot_review = texts[".github/workflows/bot-pr-user-approval.yml"]
    reviewer_item = by_id["bot-pr-user-approval-shell-read-transient"]
    require(
        reviewer_item.get("source") == ".github/workflows/bot-pr-user-approval.yml"
        and reviewer_item.get("workflow") == ".github/workflows/bot-pr-user-approval.yml"
        and reviewer_item.get("job") == "approve"
        and reviewer_item.get("step") == "Approve only exact green governed bot PRs as portyu9",
        "governed reviewer shell-read retry identity changed",
    )
    require(
        reviewer_item.get("endpointScope") == "enumerated-static-literal"
        and reviewer_item.get("maxResponseBytes") == 8_000_000
        and reviewer_item.get("maxPages") == 30
        and reviewer_item.get("pageSize") == 100,
        "governed reviewer shell-read retry bounds changed",
    )
    reviewer = named_step(
        bot_review, "approve", "Approve only exact green governed bot PRs as portyu9"
    )
    for fragment in (
        "bot_reviewer_get() {",
        "for attempt in 1 2 3; do",
        "timeout 20s gh api --include",
        'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)",
        'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then',
        "delay=1",
        "delay=2",
        'if [ "$requested" -ge 5 ]; then',
        "delay=5",
        'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {',
        "application/json*) : ;;",
        'test "${#body}" -le 8000000 || {',
        "bot_reviewer_paginated_get() {",
        "local page=1 max_pages body count first=true",
        "open-prs) max_pages=30",
        "reviews) max_pages=20",
        'while [ "$page" -le "$max_pages" ]; do',
        'error("governed reviewer paginated GET page shape changed")',
        'if [ "$count" -lt 100 ]; then',
        'if [ "$page" -ge "$max_pages" ]; then',
    ):
        require(fragment in reviewer,
                f"governed reviewer shell-read retry contract is missing: {fragment}")
    require(
        reviewer.count("timeout 20s gh api --include") == 9
        and reviewer.count('timeout 20s gh api --include --method GET -F page="$page"') == 2,
        "governed reviewer enumerated GET retry case inventory changed",
    )
    require(
        reviewer.count('GH_TOKEN="$REVIEW_TOKEN" timeout 20s gh api --include user') == 1,
        "governed reviewer identity GET must use the reviewed owner token only inside the read kernel",
    )
    require(
        reviewer.count("gh api --paginate --slurp") == 0
        and reviewer.count('gh api "repos/') == 0
        and reviewer.count("gh api user") == 0,
        "governed reviewer regained raw ordinary REST GET transport",
    )
    require(
        reviewer.count("gh api graphql") == 1
        and "reviewThreads(first:100)" in reviewer
        and "pageInfo{hasNextPage}" in reviewer,
        "governed reviewer fixed GraphQL review-thread boundary changed",
    )
    require(
        reviewer.count("gh api --include --method POST") == 1,
        "governed reviewer mutation inventory changed while hardening GETs",
    )
    for forbidden in (
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in reviewer,
                f"governed reviewer read retry acquired mutation replay surface: {forbidden}")
    for key in (
        "review-user", "main-ref", "open-prs-page", "required-checks", "quiescent-runs",
        "prior-attempt", "pr", "head-ref", "reviews-page",
    ):
        require(reviewer.count(f"                {key})\n") == 1,
                f"governed reviewer retry case arm changed: {key}")
    require(
        reviewer.count("bot_reviewer_paginated_get open-prs") == 1
        and reviewer.count("bot_reviewer_paginated_get reviews") == 2
        and reviewer.count('bot_reviewer_get open-prs-page "$page"') == 1
        and reviewer.count('bot_reviewer_get reviews-page "$page"') == 1,
        "governed reviewer paginated retry invocation inventory changed",
    )

    convergence_item = by_id["bot-pr-review-convergence-shell-read-transient"]
    require(
        convergence_item.get("source") == ".github/workflows/bot-pr-user-approval.yml"
        and convergence_item.get("workflow") == ".github/workflows/bot-pr-user-approval.yml"
        and convergence_item.get("job") == "converge"
        and convergence_item.get("step") == "Re-enter exact reviewed candidate without owner secret",
        "governed convergence shell-read retry identity changed",
    )
    require(
        convergence_item.get("endpointScope") == "enumerated-static-literal"
        and convergence_item.get("maxResponseBytes") == 8_000_000
        and convergence_item.get("maxPages") == 20
        and convergence_item.get("pageSize") == 100,
        "governed convergence shell-read retry bounds changed",
    )
    convergence = named_step(
        bot_review, "converge", "Re-enter exact reviewed candidate without owner secret"
    )
    for fragment in (
        "bot_convergence_get() {",
        "for attempt in 1 2 3; do",
        "timeout 20s gh api --include",
        'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)",
        'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then',
        "delay=1",
        "delay=2",
        'if [ "$requested" -ge 5 ]; then',
        "delay=5",
        'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {',
        "application/json*) : ;;",
        'test "${#body}" -le 8000000 || {',
        "bot_convergence_paginated_get() {",
        "local page=1 body count first=true",
        'while [ "$page" -le 20 ]; do',
        'error("governed convergence paginated GET page shape changed")',
    ):
        require(fragment in convergence,
                f"governed convergence shell-read retry contract is missing: {fragment}")
    require(
        convergence.count("timeout 20s gh api --include") == 7
        and convergence.count('timeout 20s gh api --include --method GET -F page="$page"') == 1,
        "governed convergence enumerated GET retry case inventory changed",
    )
    require(
        convergence.count("gh api --paginate --slurp") == 0
        and convergence.count('gh api "repos/') == 0,
        "governed convergence regained raw ordinary REST GET transport",
    )
    require(
        convergence.count("gh api --include --method POST") == 3,
        "governed convergence mutation inventory changed while hardening GETs",
    )
    for forbidden in (
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in convergence,
                f"governed convergence read retry acquired mutation replay surface: {forbidden}")
    for key in ("main-ref", "head-ref", "pr", "reviews-page", "gate-checks", "gate-run", "gate-job"):
        require(convergence.count(f"                {key})\n") == 1,
                f"governed convergence retry case arm changed: {key}")
    require(
        convergence.count("bot_convergence_paginated_get reviews") == 1
        and convergence.count('bot_convergence_get reviews-page "$page"') == 1
        and convergence.count("bot_convergence_get gate-checks") == 2,
        "governed convergence retry invocation inventory changed",
    )

    spotlight_shell_item = by_id["spotlight-approve-shell-read-transient"]
    require(
        spotlight_shell_item.get("source") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_shell_item.get("workflow") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_shell_item.get("job") == "approve"
        and spotlight_shell_item.get("step") == "Approve and wait for only the exact README-only automation checks",
        "Spotlight privileged shell-read retry identity changed",
    )
    require(
        spotlight_shell_item.get("endpointScope") == "enumerated-static-literal"
        and spotlight_shell_item.get("maxResponseBytes") == 8_000_000
        and spotlight_shell_item.get("maxPages") == 20
        and spotlight_shell_item.get("pageSize") == 100,
        "Spotlight privileged shell-read retry bounds changed",
    )
    spotlight = texts[".github/workflows/spotlight-link-sync.yml"]
    spotlight_approve = named_step(
        spotlight,
        "approve",
        "Approve and wait for only the exact README-only automation checks",
    )
    for fragment in (
        "spotlight_singleton_get() {",
        "for attempt in 1 2 3; do",
        "timeout 20s gh api --include",
        'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)",
        'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then',
        "delay=1",
        "delay=2",
        'if [ "$requested" -ge 5 ]; then',
        "delay=5",
        'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {',
        "application/json*) : ;;",
        'test "${#body}" -le 8000000 || {',
        "spotlight_paginated_get() {",
        'local page=1 body count first=true',
        'while [ "$page" -le 20 ]; do',
        'error("Spotlight paginated GET page shape changed")',
        'if [ "$count" -lt 100 ]; then',
        'if [ "$page" -ge 20 ]; then',
        'echo "ERROR: Spotlight paginated GET exceeds the 20-page bound: $request" >&2',
        'page=$((page + 1))',
    ):
        require(fragment in spotlight_approve,
                f"Spotlight privileged shell-read retry contract is missing: {fragment}")
    require(
        spotlight_approve.count('timeout 20s gh api --include "repos/') == 14,
        "Spotlight approval must retain exactly fourteen enumerated singleton GET retry case arms",
    )
    require(
        spotlight_approve.count('timeout 20s gh api --include --method GET -F page="$page"') == 2
        and spotlight_approve.count("timeout 20s gh api --include --method") == 2,
        "Spotlight approval must retain exactly two enumerated paginated page GET retry case arms",
    )
    require(
        spotlight_approve.count("gh api --paginate --slurp") == 0,
        "Spotlight approval regained raw gh pagination transport",
    )
    require(
        spotlight_approve.count("spotlight_paginated_get approval-comments") == 1
        and spotlight_approve.count("spotlight_paginated_get owner-reviews") == 1,
        "Spotlight approval paginated retry invocation inventory changed",
    )
    require(
        spotlight_approve.count('spotlight_singleton_get approval-comments-page "$page"') == 1
        and spotlight_approve.count('spotlight_singleton_get owner-reviews-page "$page"') == 1,
        "Spotlight approval paginated retry must delegate each page to the singleton classifier",
    )
    require(
        spotlight_approve.count("gh api --include --method POST") == 4,
        "Spotlight approval mutation inventory changed while hardening GETs",
    )
    for forbidden in (
        "python3 ",
        "curl ",
        "wget ",
        "git ",
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in spotlight_approve,
                f"Spotlight privileged shell-read retry acquired forbidden transport/mutation surface: {forbidden}")
    for key in (
        "main-initial", "generated-initial", "candidate-initial", "compare-initial",
        "pr-initial", "codeql-workflow", "dependency-workflow", "profile-workflow",
        "protected-runs", "reviewer-checks", "open-pr-list", "main-final",
        "candidate-final", "pr-final",
    ):
        require(spotlight_approve.count(f"                {key})\n") == 1,
                f"Spotlight privileged shell-read retry case arm changed: {key}")
        require(spotlight_approve.count(f"spotlight_singleton_get {key}") == 1,
                f"Spotlight privileged shell-read retry invocation changed: {key}")
    for key in ("approval-comments-page", "owner-reviews-page"):
        require(spotlight_approve.count(f"                {key})\n") == 1,
                f"Spotlight privileged page-read retry case arm changed: {key}")


    spotlight_reconcile_item = by_id["spotlight-reconcile-shell-read-transient"]
    require(
        spotlight_reconcile_item.get("source") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_reconcile_item.get("workflow") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_reconcile_item.get("job") == "reconcile"
        and spotlight_reconcile_item.get("step") == "Remove only stale validated automation candidates",
        "Spotlight reconciler shell-read retry identity changed",
    )
    require(
        spotlight_reconcile_item.get("endpointScope") == "enumerated-static-literal"
        and spotlight_reconcile_item.get("maxResponseBytes") == 8_000_000,
        "Spotlight reconciler shell-read retry bounds changed",
    )
    spotlight_reconcile = named_step(
        spotlight,
        "reconcile",
        "Remove only stale validated automation candidates",
    )
    for fragment in (
        "spotlight_reconcile_get() {",
        "for attempt in 1 2 3; do",
        "timeout 20s gh api --include",
        'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)",
        'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then',
        "delay=1",
        "delay=2",
        'if [ "$requested" -ge 5 ]; then',
        "delay=5",
        'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {',
        "application/json*) : ;;",
        'test "${#body}" -le 8000000 || {',
    ):
        require(fragment in spotlight_reconcile,
                f"Spotlight reconciler shell-read retry contract is missing: {fragment}")
    require(
        spotlight_reconcile.count('timeout 20s gh api --include "repos/') == 9,
        "Spotlight reconciler must retain exactly nine enumerated GET retry case arms",
    )
    require(
        spotlight_reconcile.count("gh api --include --method POST") == 0
        and spotlight_reconcile.count("gh api --include --method PUT") == 0
        and spotlight_reconcile.count("gh api --include --method PATCH") == 1
        and spotlight_reconcile.count("gh api --include --method DELETE") == 1,
        "Spotlight reconciler mutation inventory changed while hardening GETs",
    )
    require(
        spotlight_reconcile.count('gh api "repos/') == 0,
        "Spotlight reconciler regained raw direct GitHub GET transport",
    )
    for forbidden in (
        "python3 ",
        "curl ",
        "wget ",
        "git ",
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in spotlight_reconcile,
                f"Spotlight reconciler shell-read retry acquired forbidden transport/mutation surface: {forbidden}")
    for key in (
        "main-ref", "generated-ref", "candidate-refs", "candidate-commit",
        "ancestry-compare", "candidate-compare", "open-prs", "pr", "remaining-refs",
    ):
        require(spotlight_reconcile.count(f"                {key})\n") == 1,
                f"Spotlight reconciler shell-read retry case arm changed: {key}")
        require(spotlight_reconcile.count(f"$(spotlight_reconcile_get {key})") == 1,
                f"Spotlight reconciler shell-read retry invocation changed: {key}")


    spotlight_propose_item = by_id["spotlight-propose-shell-read-transient"]
    require(
        spotlight_propose_item.get("source") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_propose_item.get("workflow") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_propose_item.get("job") == "propose"
        and spotlight_propose_item.get("step") == "Create or reuse immutable README-only candidate",
        "Spotlight proposer shell-read retry identity changed",
    )
    require(
        spotlight_propose_item.get("endpointScope") == "enumerated-static-literal"
        and spotlight_propose_item.get("maxResponseBytes") == 8_000_000,
        "Spotlight proposer shell-read retry bounds changed",
    )
    spotlight_propose = named_step(
        spotlight,
        "propose",
        "Create or reuse immutable README-only candidate",
    )
    for fragment in (
        "spotlight_propose_get() {",
        "for attempt in 1 2 3; do",
        "timeout 20s gh api --include",
        'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)",
        'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then',
        "delay=1",
        "delay=2",
        'if [ "$requested" -ge 5 ]; then',
        "delay=5",
        'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {',
        "application/json*) : ;;",
        'test "${#body}" -le 8000000 || {',
    ):
        require(fragment in spotlight_propose,
                f"Spotlight proposer shell-read retry contract is missing: {fragment}")
    require(
        spotlight_propose.count('timeout 20s gh api --include "repos/') == 10,
        "Spotlight proposer must retain exactly ten enumerated GET retry case arms",
    )
    require(
        spotlight_propose.count("gh api --include --method POST") == 5
        and spotlight_propose.count("gh api --include --method PUT") == 0
        and spotlight_propose.count("gh api --include --method PATCH") == 0
        and spotlight_propose.count("gh api --include --method DELETE") == 0,
        "Spotlight proposer mutation inventory changed while hardening GETs",
    )
    require(
        spotlight_propose.count('gh api "repos/') == 0,
        "Spotlight proposer regained raw direct GitHub GET transport",
    )
    for forbidden in (
        "python3 ",
        "curl ",
        "wget ",
        "git ",
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in spotlight_propose,
                f"Spotlight proposer shell-read retry acquired forbidden transport/mutation surface: {forbidden}")
    for key in (
        "main-ref", "main-readme", "candidate-refs", "base-commit", "candidate-commit",
        "compare", "candidate-readme", "candidate-ref", "open-prs", "pr",
    ):
        require(spotlight_propose.count(f"                {key})\n") == 1,
                f"Spotlight proposer shell-read retry case arm changed: {key}")
        require(spotlight_propose.count(f"$(spotlight_propose_get {key})") == 1,
                f"Spotlight proposer shell-read retry invocation changed: {key}")


    spotlight_merge_item = by_id["spotlight-merge-shell-read-transient"]
    require(
        spotlight_merge_item.get("source") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_merge_item.get("workflow") == ".github/workflows/spotlight-link-sync.yml"
        and spotlight_merge_item.get("job") == "merge"
        and spotlight_merge_item.get("step") == "Merge exact approved head and clean up immutable candidate branch",
        "Spotlight terminal shell-read retry identity changed",
    )
    require(
        spotlight_merge_item.get("endpointScope") == "enumerated-static-literal"
        and spotlight_merge_item.get("maxResponseBytes") == 8_000_000
        and spotlight_merge_item.get("maxPages") == 20
        and spotlight_merge_item.get("pageSize") == 100,
        "Spotlight terminal shell-read retry bounds changed",
    )
    spotlight_merge = named_step(spotlight, "merge", "Merge exact approved head and clean up immutable candidate branch")
    for fragment in (
        "spotlight_merge_get() {", "for attempt in 1 2 3; do",
        "timeout 20s gh api --include", 'if [ "$exit_code" -eq 124 ]; then',
        'elif [ "$exit_code" -eq 1 ] && [ "$status_count" -eq 0 ]; then',
        "408|429|500|502|503|504)", 'if [ "$rate_remaining" = "0" ] || [ -n "$retry_after" ]; then',
        'if [ "$attempt" -eq 1 ]; then', "delay=1", "delay=2",
        'if [ "$requested" -ge 5 ]; then', "delay=5", 'test "$status_count" -eq 1 || {',
        'test "$status" = "200" || {', "application/json*) : ;;", 'test "${#body}" -le 8000000 || {',
        "spotlight_merge_paginated_get() {", 'local page=1 body count first=true',
        'while [ "$page" -le 20 ]; do', 'error("Spotlight terminal paginated GET page shape changed")',
        'if [ "$count" -lt 100 ]; then', 'if [ "$page" -ge 20 ]; then',
        'echo "ERROR: Spotlight terminal paginated GET exceeds the 20-page bound: $request" >&2',
        'page=$((page + 1))',
    ):
        require(fragment in spotlight_merge, f"Spotlight terminal shell-read retry contract is missing: {fragment}")
    require(spotlight_merge.count("gh api --paginate --slurp") == 0,
            "Spotlight terminal merge regained raw gh pagination transport")
    require(spotlight_merge.count("spotlight_merge_paginated_get owner-reviews") == 1
            and spotlight_merge.count('spotlight_merge_get owner-reviews-page "$page"') == 1,
            "Spotlight terminal owner-review pagination retry topology changed")
    require(
        spotlight_merge.count("gh api --include --method PUT") == 1
        and spotlight_merge.count("gh api --include --method DELETE") == 1
        and spotlight_merge.count("gh api --include --method POST") == 0
        and spotlight_merge.count("gh api --include --method PATCH") == 0,
        "Spotlight terminal mutation inventory changed while hardening GETs",
    )
    for forbidden in (
        "python3 ", "curl ", "wget ", "git ",
        "timeout 20s gh api --include --method POST",
        "timeout 20s gh api --include --method PUT",
        "timeout 20s gh api --include --method PATCH",
        "timeout 20s gh api --include --method DELETE",
    ):
        require(forbidden not in spotlight_merge,
                f"Spotlight terminal shell-read retry acquired forbidden transport/mutation surface: {forbidden}")
    for key in (
        "pr-initial", "main-initial", "generated-initial", "candidate-initial", "files",
        "candidate-commit", "candidate-readme", "codeql-run", "dependency-run", "profile-run",
        "trusted-workflow", "trusted-run", "trusted-check", "exact-head-checks", "main-premerge",
        "generated-premerge", "candidate-premerge", "pr-postmerge", "main-postmerge",
        "candidate-refs-postmerge", "candidate-refs-after-delete",
    ):
        require(spotlight_merge.count(f"                {key})\n") == 1,
                f"Spotlight terminal shell-read retry case arm changed: {key}")
        require(spotlight_merge.count(f"spotlight_merge_get {key}") == 1,
                f"Spotlight terminal shell-read retry invocation changed: {key}")
    require(spotlight_merge.count("                owner-reviews-page)\n") == 1,
            "Spotlight terminal page-read retry case arm changed")

    automation_github_paginated_read.self_test()
    pagination_source = (ROOT / "scripts/automation_github_paginated_read.py").read_text(encoding="utf-8")
    for fragment in (
        "import automation_github_read",
        "PAGE_SIZE = 100",
        "MAX_PAGES = 30",
        "SENTINEL_PAGE = MAX_PAGES + 1",
        "automation_github_read.normalize_endpoint(value)",
        "reader: Callable[[str], str | None] = automation_github_read.get_json_text",
        "for page_number in range(1, SENTINEL_PAGE + 1):",
        "automation_github_read.strict_json(text)",
        'f"paginated GitHub collection exceeds the {MAX_PAGES}-page bound"',
    ):
        require(fragment in pagination_source,
                f"governed pagination composition is missing: {fragment}")
    for forbidden in (
        "import urllib.request",
        "urllib.request.Request(",
        "subprocess.",
        "gh api",
        'method="POST"',
        'method="PUT"',
        'method="PATCH"',
        'method="DELETE"',
    ):
        require(forbidden not in pagination_source,
                f"governed pagination must delegate transport without mutation/direct API access: {forbidden}")


    dependabot_controller = texts[".github/workflows/dependabot-controller.yml"]
    dependabot_discovery_step = named_step(
        dependabot_controller,
        "controller",
        "Bind current main and one native Dependabot candidate",
    )
    dependabot_discovery_endpoint = (
        '"repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100"'
    )
    dependabot_discovery_direct = (
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100"'
    )
    require(
        dependabot_discovery_step.count("python3 scripts/automation_github_paginated_read.py") == 1
        and dependabot_discovery_endpoint in dependabot_discovery_step
        and "> open-pr-pages.json" in dependabot_discovery_step,
        "Dependabot controller open-PR discovery must use exactly one governed paginated GitHub collection",
    )
    require(
        dependabot_discovery_direct not in dependabot_discovery_step,
        "Dependabot controller open-PR discovery regained direct pagination transport",
    )
    require(
        "GH_TOKEN: ${{ github.token }}" in dependabot_discovery_step,
        "Dependabot controller open-PR discovery governed pagination lost run-scoped token binding",
    )

    dependabot_file_endpoint = (
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"'
    )
    for job_name, step_name, label in (
        (
            "controller",
            "Assemble exact candidate tree as data",
            "candidate-tree changed-file collection",
        ),
        (
            "validation_bind",
            "Bind exact controller-issued validation target",
            "validation-target changed-file collection",
        ),
    ):
        step = named_step(dependabot_controller, job_name, step_name)
        require(
            step.count("python3 scripts/automation_github_paginated_read.py") == 1
            and dependabot_file_endpoint in step
            and "> pr-file-pages.json" in step,
            f"Dependabot {label} must use exactly one governed paginated GitHub collection",
        )
        require(
            "gh api --paginate --slurp" not in step,
            f"Dependabot {label} regained direct gh pagination transport",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"Dependabot {label} governed pagination lost run-scoped token binding",
        )

    dependabot_git_read_pin = (
        'GOVERNED_READ_BLOB="$(git rev-parse HEAD:scripts/automation_github_read.py)"\n'
        '          test "$GOVERNED_READ_BLOB" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    for job_name, step_name, label in (
        (
            "controller",
            "Assemble exact candidate tree as data",
            "candidate-tree Git-object reconstruction",
        ),
        (
            "validation_bind",
            "Reconstruct exact reconciled candidate as data",
            "validation Git-object reconstruction",
        ),
    ):
        step = named_step(dependabot_controller, job_name, step_name)
        require(
            step.count("python3 scripts/automation_github_read.py") == 3,
            f"Dependabot {label} must use exactly three governed singleton Git-object reads",
        )
        require(
            dependabot_git_read_pin in step,
            f"Dependabot {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"Dependabot {label} governed Git-object reads lost run-scoped token binding",
        )
        for endpoint in (
            '"repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}"',
            '"repos/${TARGET_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
            '"repos/${TARGET_REPOSITORY}/git/blobs/${BLOB_SHA}"',
        ):
            require(
                step.count(endpoint) == 1,
                f"Dependabot {label} governed Git-object endpoint topology changed: {endpoint}",
            )
        for forbidden in (
            'gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}"',
            'gh api "repos/${TARGET_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1"',
            'gh api "repos/${TARGET_REPOSITORY}/git/blobs/${BLOB_SHA}"',
        ):
            require(
                forbidden not in step,
                f"Dependabot {label} regained direct singleton Git-object transport: {forbidden}",
            )

    dependabot_ref_read_pin = (
        'GOVERNED_READ_BLOB="$(git rev-parse HEAD:scripts/automation_github_read.py)"\n'
        '          test "$GOVERNED_READ_BLOB" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    for job_name, step_name, expected_main, expected_head, label in (
        ("controller", "Bind current main and one native Dependabot candidate", 1, 0, "initial main binding"),
        ("controller", "Atomically reconcile canonical governance files onto the bot head", 1, 1, "atomic reconciliation"),
        ("controller", "Validate reconciled candidate and inspect protected checks", 1, 1, "reconciled validation"),
        ("controller", "Perform exact-head protected Dependabot merge", 1, 1, "terminal merge"),
        ("validation_bind", "Bind exact controller-issued validation target", 1, 1, "validation target binding"),
        ("validation_bind", "Verify exact delegated admission proof", 1, 1, "delegated admission proof"),
        ("dispatch_codeql", "Dispatch CodeQL after exact read-only validation", 1, 1, "CodeQL dispatch validation"),
    ):
        step = named_step(dependabot_controller, job_name, step_name)
        main_read = 'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/git/ref/heads/main"'
        head_read = 'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}"'
        require(
            step.count(main_read) == expected_main and step.count(head_read) == expected_head,
            f"Dependabot {label} governed Git-ref read topology changed",
        )
        require(dependabot_ref_read_pin in step,
                f"Dependabot {label} lost exact governed-read helper identity")
        require("GH_TOKEN: ${{ github.token }}" in step,
                f"Dependabot {label} governed Git-ref reads lost run-scoped token binding")
        for forbidden in (
            'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main"',
            'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}"',
        ):
            require(forbidden not in step,
                    f"Dependabot {label} regained direct Git-ref transport: {forbidden}")

    dependabot_pr_read_pin = (
        'GOVERNED_READ_BLOB="$(git rev-parse HEAD:scripts/automation_github_read.py)"\n'
        '          test "$GOVERNED_READ_BLOB" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    dependabot_pr_read = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
    )
    for job_name, step_name, expected_reads, label in (
        ("controller", "Bind current main and one native Dependabot candidate", 2, "initial/update convergence"),
        ("controller", "Perform exact-head protected Dependabot merge", 1, "terminal merge"),
        ("validation_bind", "Bind exact controller-issued validation target", 1, "validation target binding"),
        ("dispatch_codeql", "Dispatch CodeQL after exact read-only validation", 1, "CodeQL dispatch validation"),
    ):
        step = named_step(dependabot_controller, job_name, step_name)
        require(
            step.count(dependabot_pr_read) == expected_reads,
            f"Dependabot {label} governed singleton PR read topology changed",
        )
        require(
            dependabot_pr_read_pin in step,
            f"Dependabot {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"Dependabot {label} governed PR reads lost run-scoped token binding",
        )
        require(
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"' not in step,
            f"Dependabot {label} regained direct singleton PR transport",
        )

    dependabot_workflow_singleton_pin = (
        'GOVERNED_READ_BLOB="$(git rev-parse HEAD:scripts/automation_github_read.py)"\n'
        '          test "$GOVERNED_READ_BLOB" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    for job_name, step_name, endpoints, label in (
        (
            "controller",
            "Bind current main and one native Dependabot candidate",
            ('"repos/${TARGET_REPOSITORY}/actions/runs/${WAKE_RUN_ID}"',),
            "workflow-run wake",
        ),
        (
            "controller",
            "Validate reconciled candidate and inspect protected checks",
            (
                '"repos/${TARGET_REPOSITORY}/actions/runs/${proof_run_id}/attempts/${proof_run_attempt}"',
                '"repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml"',
                '"repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml"',
                '"repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml"',
            ),
            "protected workflow/proof metadata",
        ),
    ):
        step = named_step(dependabot_controller, job_name, step_name)
        for endpoint in endpoints:
            governed = f"python3 scripts/automation_github_read.py {endpoint}"
            direct = f"gh api {endpoint}"
            require(
                step.count(governed) == 1,
                f"Dependabot {label} governed singleton read topology changed: {endpoint}",
            )
            require(
                direct not in step,
                f"Dependabot {label} regained direct singleton GET transport: {endpoint}",
            )
        require(
            dependabot_workflow_singleton_pin in step,
            f"Dependabot {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"Dependabot {label} governed singleton reads lost run-scoped token binding",
        )

    dependabot_residual_snapshot_contracts = (
        (
            "controller",
            "Validate reconciled candidate and inspect protected checks",
            (
                '"repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=workflow_dispatch&per_page=100"',
                '"repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100"',
                '"repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100"',
            ),
            "reconciled collection snapshots",
        ),
        (
            "validation_bind",
            "Bind exact controller-issued validation target",
            ('"repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&head=portyu9:${HEAD_REF}&per_page=10"',),
            "validation-target PR snapshot",
        ),
        (
            "validation_bind",
            "Verify exact delegated admission proof",
            ('"repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100"',),
            "validation delegated-admission snapshot",
        ),
    )
    for job_name, step_name, endpoints, label in dependabot_residual_snapshot_contracts:
        step = named_step(dependabot_controller, job_name, step_name)
        for endpoint in endpoints:
            governed = f"python3 scripts/automation_github_read.py {endpoint}"
            direct = f"gh api {endpoint}"
            require(
                step.count(governed) == 1,
                f"Dependabot {label} governed snapshot read topology changed: {endpoint}",
            )
            require(
                direct not in step,
                f"Dependabot {label} regained direct snapshot GET transport: {endpoint}",
            )
        require(
            dependabot_workflow_singleton_pin in step,
            f"Dependabot {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"Dependabot {label} governed snapshot reads lost run-scoped token binding",
        )

    dependabot_terminal_merge_step = named_step(
        dependabot_controller,
        "controller",
        "Perform exact-head protected Dependabot merge",
    )
    dependabot_terminal_page_endpoints = (
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100"',
        '"repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100"',
    )
    require(
        dependabot_terminal_merge_step.count(
            "python3 scripts/automation_github_paginated_read.py"
        ) == 2,
        "Dependabot terminal review/comment evidence must use exactly two governed paginated reads",
    )
    for endpoint in dependabot_terminal_page_endpoints:
        require(
            dependabot_terminal_merge_step.count(endpoint) == 1,
            f"Dependabot terminal governed page endpoint topology changed: {endpoint}",
        )
    require(
        "gh api --paginate --slurp" not in dependabot_terminal_merge_step,
        "Dependabot terminal review/comment evidence regained direct gh pagination transport",
    )
    require(
        "GH_TOKEN: ${{ github.token }}" in dependabot_terminal_merge_step,
        "Dependabot terminal governed pagination lost run-scoped token binding",
    )

    codeql_autofix = texts[".github/workflows/codeql-autofix.yml"]
    for step_name, endpoint, output_name, label in (
        (
            "Discover one exact-main CodeQL alert",
            '"repos/${TARGET_REPOSITORY}/code-scanning/alerts?state=open&tool_name=CodeQL&per_page=100"',
            "> alert-pages.json",
            "alert discovery",
        ),
        (
            "Locate an existing remediation PR",
            '"repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100"',
            "> open-pr-pages.json",
            "remediation PR discovery",
        ),
    ):
        step = named_step(codeql_autofix, "controller", step_name)
        require(
            step.count("python3 scripts/automation_github_paginated_read.py") == 1
            and endpoint in step
            and output_name in step,
            f"CodeQL Autofix {label} must use exactly one governed paginated GitHub collection",
        )
        require(
            "gh api --paginate --slurp" not in step,
            f"CodeQL Autofix {label} regained direct gh pagination transport",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"CodeQL Autofix {label} governed pagination lost run-scoped token binding",
        )

    codeql_workflow_step = named_step(
        codeql_autofix,
        "controller",
        "Approve exact protected checks and queue admission retry",
    )
    require(
        codeql_workflow_step.count("python3 scripts/automation_github_read.py") == 5,
        "CodeQL Autofix protected workflow metadata governed-read topology changed",
    )
    for endpoint, output_name, label in (
        (
            '"repos/${TARGET_REPOSITORY}/actions/workflows/codeql.yml"',
            '> "$RUNNER_TEMP/codeql-workflow-definition.json"',
            "CodeQL workflow metadata",
        ),
        (
            '"repos/${TARGET_REPOSITORY}/actions/workflows/dependency-review.yml"',
            '> "$RUNNER_TEMP/dependency-workflow-definition.json"',
            "Dependency Review workflow metadata",
        ),
        (
            '"repos/${TARGET_REPOSITORY}/actions/workflows/profile-quality.yml"',
            '> "$RUNNER_TEMP/profile-workflow-definition.json"',
            "Profile Quality workflow metadata",
        ),
    ):
        governed = (
            "python3 scripts/automation_github_read.py "
            + "\\"
            + "\n            "
            + endpoint
            + " "
            + "\\"
            + "\n            "
            + output_name
        )
        require(
            codeql_workflow_step.count(governed) == 1,
            f"CodeQL Autofix {label} must use exactly one governed singleton GitHub read",
        )
        require(
            ("gh api " + endpoint) not in codeql_workflow_step,
            f"CodeQL Autofix {label} regained direct gh API GET transport",
        )
    require(
        "GH_TOKEN: ${{ github.token }}" in codeql_workflow_step,
        "CodeQL Autofix protected workflow governed reads lost run-scoped token binding",
    )

    for step_name, output_name, label in (
        (
            "Approve exact protected checks and queue admission retry",
            '> "$RUNNER_TEMP/codeql-autofix-candidate-pr.json"',
            "candidate PR snapshot",
        ),
        (
            "Approve exact protected checks and queue admission retry",
            '> "$RUNNER_TEMP/codeql-autofix-continuation-pr.json"',
            "continuation PR snapshot",
        ),
        (
            "Verify an existing Autofix PR and perform protected merge",
            "> pr.json",
            "terminal PR snapshot",
        ),
        (
            "Verify an existing Autofix PR and perform protected merge",
            "> final-pr.json",
            "final pre-merge PR snapshot",
        ),
    ):
        step = named_step(codeql_autofix, "controller", step_name)
        endpoint = '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
        governed = (
            "python3 scripts/automation_github_read.py "
            + "\\"
            + "\n            "
            + endpoint
            + " "
            + "\\"
            + "\n            "
            + output_name
        )
        require(
            step.count(governed) == 1,
            f"CodeQL Autofix {label} must use exactly one governed singleton GitHub read",
        )
        require(
            ("gh api " + endpoint) not in step,
            f"CodeQL Autofix {label} regained direct gh API GET transport",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in step,
            f"CodeQL Autofix {label} governed read lost run-scoped token binding",
        )

    spotlight_merge_authorization = SPOTLIGHT_MERGE_AUTHORIZATION.read_text(encoding="utf-8")
    for fragment in (
        "import automation_github_read",
        "def gh_json(endpoint: str) -> Any:",
        "text = automation_github_read.get_json_text(endpoint)",
        "return automation_github_read.strict_json(text)",
    ):
        require(
            fragment in spotlight_merge_authorization,
            f"Spotlight merge authorization governed-read delegation is missing: {fragment}",
        )
    for forbidden in (
        "import subprocess",
        "subprocess.run(",
        '["gh", "api", endpoint]',
    ):
        require(
            forbidden not in spotlight_merge_authorization,
            f"Spotlight merge authorization regained direct GitHub transport: {forbidden}",
        )

    witness = texts[".github/workflows/action-provenance-witness.yml"]
    live_step = named_step(
        witness,
        "prepare",
        "Prove exact live Action release provenance",
    )
    require("GH_TOKEN: ${{ github.token }}" in live_step,
            "Action provenance witness must authenticate classified public metadata reads")
    require("python3 scripts/validate-action-release-provenance.py" in live_step,
            "Action provenance witness live proof invocation changed")

    producer_step = named_step(
        witness,
        "prepare",
        "Bind exact trusted run identity and issuance",
    )
    require(producer_step.count("python3 scripts/automation_github_read.py") == 2,
            "Action provenance witness producer must use exactly two governed GitHub read call sites")
    require("gh api " not in producer_step,
            "Action provenance witness producer regained direct gh api read transport")
    require("GH_TOKEN: ${{ github.token }}" in producer_step,
            "Action provenance witness producer governed reads lost run-scoped token binding")

    compatibility_witness = texts[".github/workflows/profile-generator-compatibility-witness.yml"]
    compatibility_producer_step = named_step(
        compatibility_witness,
        "prepare",
        "Bind exact trusted run identity and issuance",
    )
    require(compatibility_producer_step.count("python3 scripts/automation_github_read.py") == 2,
            "Profile generator compatibility witness producer must use exactly two governed GitHub read call sites")
    require("gh api " not in compatibility_producer_step,
            "Profile generator compatibility witness producer regained direct gh api read transport")
    require("GH_TOKEN: ${{ github.token }}" in compatibility_producer_step,
            "Profile generator compatibility witness producer governed reads lost run-scoped token binding")


    dependabot_controller = texts[".github/workflows/dependabot-controller.yml"]
    dependabot_release_pin = (
        'test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = '
        '"1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    for job_name, step_name, label in (
        ("controller", "Prove bot identity, atomic pin closure, and public release provenance", "canonical release proof"),
        ("validation_bind", "Independently re-prove deterministic reconciliation", "independent release reproof"),
    ):
        release_step = named_step(dependabot_controller, job_name, step_name)
        require(
            release_step.count("python3 scripts/automation_github_read.py") == 2,
            f"Dependabot {label} must use exactly two governed singleton release reads",
        )
        require(
            dependabot_release_pin in release_step,
            f"Dependabot {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in release_step,
            f"Dependabot {label} governed reads lost run-scoped token binding",
        )
        for forbidden in (
            'gh api "repos/${DEPENDENCY_REPOSITORY}"',
            'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}"',
        ):
            require(
                forbidden not in release_step,
                f"Dependabot {label} regained direct singleton release transport: {forbidden}",
            )

    profile_quality = texts[".github/workflows/profile-quality.yml"]
    dependabot_transport_identity_step = named_step(
        profile_quality,
        "dependabot_admission",
        "Verify exact accepted-base governed read transport identity",
    )
    require(
        'test "$(git -C trusted-base rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
        in dependabot_transport_identity_step,
        "Profile Quality Dependabot lost exact governed singleton-read helper identity",
    )
    require(
        'test "$(git -C trusted-base rev-parse HEAD:scripts/automation_github_paginated_read.py)" = "03c48844349950a1396c9b95290091076966226e"'
        in dependabot_transport_identity_step,
        "Profile Quality Dependabot lost exact governed paginated-read helper identity",
    )
    for job_name, step_name, label in (
        ("validate", "Discover exact fresh signed Action provenance witness", "Action provenance witness"),
        ("integration", "Discover exact fresh signed Profile Generator Compatibility Witness", "Profile generator compatibility witness"),
    ):
        discovery_step = named_step(profile_quality, job_name, step_name)
        require(discovery_step.count("python3 scripts/automation_github_read.py") == 3,
                f"Profile Quality {label} discovery must use exactly three governed GitHub read call sites")
        require("gh api " not in discovery_step,
                f"Profile Quality {label} discovery regained direct gh api read transport")
        require("GH_TOKEN: ${{ github.token }}" in discovery_step,
                f"Profile Quality {label} discovery lost run-scoped token binding")

    dependabot_context_step = named_step(
        profile_quality,
        "dependabot_admission",
        "Prove exact PR-native Dependabot context",
    )
    require(dependabot_context_step.count("python3 trusted-base/scripts/automation_github_read.py") == 5,
            "Profile Quality Dependabot context proof must use exactly five governed GitHub read call sites")
    require("gh api " not in dependabot_context_step,
            "Profile Quality Dependabot context proof regained direct gh api read transport")
    require("GH_TOKEN: ${{ github.token }}" in dependabot_context_step,
            "Profile Quality Dependabot context proof governed reads lost run-scoped token binding")

    dependabot_release_step = named_step(
        profile_quality,
        "dependabot_admission",
        "Fetch exact candidate release evidence",
    )
    require(dependabot_release_step.count("python3 trusted-base/scripts/automation_github_read.py") == 2,
            "Profile Quality Dependabot release proof must use exactly two governed singleton GitHub read call sites")
    paginated_files = (
        'python3 trusted-base/scripts/automation_github_paginated_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"'
    )
    require(dependabot_release_step.count("python3 trusted-base/scripts/automation_github_paginated_read.py") == 1
            and dependabot_release_step.count(paginated_files) == 1,
            "Profile Quality Dependabot release proof must use exactly one governed paginated GitHub collection")
    require("gh api " not in dependabot_release_step,
            "Profile Quality Dependabot release proof regained direct gh api transport")
    for forbidden in (
        'gh api "repos/${DEPENDENCY_REPOSITORY}"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}"',
    ):
        require(forbidden not in dependabot_release_step,
                f"Profile Quality Dependabot release proof regained direct singleton transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in dependabot_release_step,
            "Profile Quality Dependabot release proof governed reads lost run-scoped token binding")

    capability_admission = texts[".github/workflows/capability-admission.yml"]
    capability_identity_step = named_step(
        capability_admission,
        "admission",
        "Verify exact governed read transport identity",
    )
    require(
        'test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
        in capability_identity_step,
        "Capability Admission candidate binding lost exact governed-read helper identity",
    )
    require(
        'test "$(git rev-parse HEAD:scripts/automation_github_paginated_read.py)" = "03c48844349950a1396c9b95290091076966226e"'
        in capability_identity_step,
        "Capability Admission lost exact governed paginated-read helper identity",
    )

    capability_bind_step = named_step(
        capability_admission,
        "admission",
        "Bind exact candidate context",
    )
    require(capability_bind_step.count("python3 scripts/automation_github_read.py") == 10,
            "Capability Admission candidate binding must use exactly ten governed singleton GitHub reads")
    capability_paginated_prs = (
        'python3 scripts/automation_github_paginated_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100"'
    )
    require(capability_bind_step.count("python3 scripts/automation_github_paginated_read.py") == 1
            and capability_bind_step.count(capability_paginated_prs) == 1,
            "Capability Admission candidate binding must use exactly one governed paginated GitHub collection")
    require("gh api " not in capability_bind_step,
            "Capability Admission candidate binding regained direct gh api transport")
    require("GH_TOKEN: ${{ github.token }}" in capability_bind_step,
            "Capability Admission candidate binding governed reads lost run-scoped token binding")
    for forbidden in (
        'PR="$(gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}")"',
        'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}" > "$RUNNER_TEMP/dependabot-pr.json"',
        'MAIN_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main")"',
        'HEAD_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}")"',
        'CANDIDATE_COMMIT="$(gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'COMPARE="$(gh api "repos/${TARGET_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"',
        'GENERATED_REF_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/generated")"',
        'README_CONTENTS_RESPONSE="$(gh api "repos/${TARGET_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}")"',
    ):
        require(forbidden not in capability_bind_step,
                f"Capability Admission candidate binding regained direct singleton transport: {forbidden}")

    capability_source_step = named_step(
        capability_admission,
        "admission",
        "Fetch exact candidate capability source as data",
    )
    require(capability_source_step.count("python3 scripts/automation_github_read.py") == 4,
            "Capability Admission candidate source must use exactly four governed singleton JSON reads")
    capability_source_paginated_files = (
        'python3 scripts/automation_github_paginated_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"'
    )
    require(capability_source_step.count("python3 scripts/automation_github_paginated_read.py") == 1
            and capability_source_step.count(capability_source_paginated_files) == 1,
            "Capability Admission candidate source must use exactly one governed paginated GitHub collection")
    require("gh api " not in capability_source_step,
            "Capability Admission candidate source regained direct gh api transport")
    for forbidden in (
        'COMMIT="$(gh api "repos/${HEAD_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'TREE="$(gh api "repos/${HEAD_REPOSITORY}/git/trees/${TREE_SHA}?recursive=1")"',
        'BLOB="$(gh api "repos/${HEAD_REPOSITORY}/git/blobs/${BLOB_SHA}")"',
    ):
        require(forbidden not in capability_source_step,
                f"Capability Admission candidate source regained direct singleton transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in capability_source_step,
            "Capability Admission candidate-source governed reads lost run-scoped token binding")

    capability_release_step = named_step(
        capability_admission,
        "admission",
        "Verify delegated Dependabot release provenance",
    )
    require(capability_release_step.count("python3 scripts/automation_github_read.py") == 2,
            "Capability Admission delegated release proof must use exactly two governed singleton JSON reads")
    require("gh api " not in capability_release_step,
            "Capability Admission delegated release proof regained direct gh api transport")
    for forbidden in (
        'gh api "repos/${DEPENDENCY_REPOSITORY}" > dependabot-release-repository.json',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}" > dependabot-release.json',
    ):
        require(forbidden not in capability_release_step,
                f"Capability Admission delegated release proof regained direct singleton transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in capability_release_step,
            "Capability Admission delegated release governed reads lost run-scoped token binding")

    capability_autofix_step = named_step(
        capability_admission,
        "admission",
        "Verify immutable Autofix controller provenance",
    )
    require(capability_autofix_step.count("python3 scripts/automation_github_read.py") == 2,
            "Capability Admission Autofix provenance must use exactly two governed singleton JSON reads")
    capability_autofix_zip = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip" > receipt.zip'
    )
    require(capability_autofix_step.count("gh api ") == 1
            and capability_autofix_step.count(capability_autofix_zip) == 1,
            "Capability Admission Autofix provenance must retain exactly one raw binary artifact ZIP read")
    for forbidden in (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/artifacts?per_page=100" > artifacts.json',
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/attempts/${RECEIPT_ATTEMPT}" > origin-run.json',
    ):
        require(forbidden not in capability_autofix_step,
                f"Capability Admission Autofix provenance regained direct singleton JSON transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in capability_autofix_step,
            "Capability Admission Autofix provenance governed reads lost run-scoped token binding")

    capability_publish_step = named_step(
        capability_admission,
        "admission",
        "Publish exact candidate trusted admission check",
    )
    require(capability_publish_step.count("python3 scripts/automation_github_read.py") == 1,
            "Capability Admission prior-attempt proof must use exactly one governed singleton JSON read call site")
    require(capability_publish_step.count("gh api ") == 1,
            "Capability Admission publisher must retain exactly one raw GitHub mutation surface and no raw reads")
    require(
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${HISTORY_ATTEMPT}"'
        not in capability_publish_step,
        "Capability Admission prior-attempt proof regained direct singleton transport",
    )
    require("for HISTORY_ATTEMPT in $(seq 1 20); do" in capability_publish_step
            and "sleep 1" in capability_publish_step,
            "Capability Admission prior-attempt bounded observation semantics changed")
    require("GH_TOKEN: ${{ github.token }}" in capability_publish_step,
            "Capability Admission prior-attempt governed read lost run-scoped token binding")

    ruleset_sentinel = texts[".github/workflows/ruleset-drift-sentinel.yml"]
    ruleset_main_step = named_step(
        ruleset_sentinel,
        "detect",
        "Require current trusted main",
    )
    require(ruleset_main_step.count("python3 scripts/automation_github_read.py") == 1,
            "Ruleset drift sentinel must use exactly one governed GitHub singleton read")
    require(
        'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"' not in ruleset_main_step,
        "Ruleset drift sentinel regained direct main-ref GitHub transport",
    )
    require("GH_TOKEN: ${{ github.token }}" in ruleset_main_step,
            "Ruleset drift sentinel governed read lost run-scoped token binding")
    require(
        'test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
        in ruleset_main_step,
        "Ruleset drift sentinel lost exact governed-read helper identity",
    )


    ruleset_reconciler = texts[".github/workflows/ruleset-reconciler.yml"]
    ruleset_reconciler_pin = (
        'test "$(git rev-parse HEAD:scripts/automation_github_read.py)" = '
        '"1b779bcea0acd290826fef8f60fd01480113a31a"'
    )
    ruleset_plan_step = named_step(
        ruleset_reconciler,
        "plan",
        "Prove exact reviewed transition state",
    )
    ruleset_reconcile_step = named_step(
        ruleset_reconciler,
        "reconcile",
        "Apply only exact reviewed predecessor to successor",
    )
    ruleset_attest_step = named_step(
        ruleset_reconciler,
        "attest",
        "Re-prove successor and receipt identity",
    )
    for label, block, expected in (
        ("plan", ruleset_plan_step, 2),
        ("reconcile", ruleset_reconcile_step, 5),
        ("attest", ruleset_attest_step, 2),
    ):
        require(
            block.count("python3 scripts/automation_github_read.py") == expected,
            f"Ruleset reconciler {label} must use exactly {expected} governed repository singleton reads",
        )
        require(
            ruleset_reconciler_pin in block,
            f"Ruleset reconciler {label} lost exact governed-read helper identity",
        )
        require(
            "GH_TOKEN: ${{ github.token }}" in block,
            f"Ruleset reconciler {label} governed reads lost run-scoped token binding",
        )
    for forbidden in (
        'gh api "repos/portyu9/portyu9/git/ref/heads/main"',
        'gh api "repos/portyu9/portyu9/rulesets/22148161"',
    ):
        require(
            forbidden not in ruleset_reconciler,
            f"Ruleset reconciler regained direct repository singleton transport: {forbidden}",
        )
    require(
        ruleset_reconcile_step.count(
            'GH_TOKEN="$ADMIN_TOKEN" python3 scripts/automation_github_read.py '
            '"repos/portyu9/portyu9/rulesets/22148161"'
        ) == 2,
        "Ruleset reconciler admin-token ruleset read count changed",
    )
    require(
        ruleset_reconcile_step.count(
            'GH_TOKEN="$APP_JWT" gh api -H "Authorization: Bearer ${APP_JWT}" '
            '"app/installations/${ADMIN_INSTALLATION_ID}"'
        ) == 1
        and ruleset_reconcile_step.count(
            'GH_TOKEN="$ADMIN_TOKEN" gh api "installation/repositories?per_page=100"'
        ) == 1,
        "Ruleset reconciler specialist non-repository read boundary changed",
    )
    require(
        ruleset_reconcile_step.count("gh api ") == 4
        and ruleset_reconcile_step.count("--method POST") == 1
        and ruleset_reconcile_step.count("--method PUT") == 1,
        "Ruleset reconciler raw transport must remain exactly two specialist reads and two mutations",
    )

    profile_stats = texts[".github/workflows/profile-stats.yml"]
    lease_step = named_step(
        profile_stats,
        "lease",
        "Mint exact short-lived mutation lease",
    )
    require(lease_step.count("python3 source/scripts/automation_github_read.py") == 1,
            "Profile Stats lease mint must use exactly one governed GitHub singleton read")
    require(
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"' not in lease_step,
        "Profile Stats lease mint regained direct singleton GitHub transport",
    )
    require("GH_TOKEN: ${{ github.token }}" in lease_step,
            "Profile Stats lease governed read lost run-scoped token binding")

    spotlight = texts[".github/workflows/spotlight-link-sync.yml"]
    spotlight_checkout_step = named_step(
        spotlight,
        "lease",
        "Checkout exact trusted source for governed reads",
    )
    require("ref: main" in spotlight_checkout_step,
            "Spotlight lease governed read lost static trusted-main checkout")
    require("ref: ${{ github.sha }}" not in spotlight_checkout_step,
            "Spotlight lease governed read regained dynamic event-SHA checkout")
    spotlight_lease_step = named_step(
        spotlight,
        "lease",
        "Mint exact short-lived mutation lease",
    )
    require(spotlight_lease_step.count("python3 source/scripts/automation_github_read.py") == 1,
            "Spotlight lease mint must use exactly one governed GitHub singleton read")
    require(
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"' not in spotlight_lease_step,
        "Spotlight lease mint regained direct singleton GitHub transport",
    )
    require("GH_TOKEN: ${{ github.token }}" in spotlight_lease_step,
            "Spotlight lease governed read lost run-scoped token binding")
    spotlight_identity_step = named_step(
        spotlight,
        "lease",
        "Verify exact governed read source identity",
    )
    require(
        'test "$(git -C source rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
        in spotlight_identity_step,
        "Spotlight lease lost exact governed-read helper identity",
    )
    require(
        'test "$(git -C source rev-parse HEAD)" = "$BASE_SHA"' in spotlight_identity_step,
        "Spotlight lease lost sealed-base governed-read source identity",
    )

    spotlight_budget_checkout_step = named_step(
        spotlight,
        "budget",
        "Checkout exact trusted source for governed reads",
    )
    require("ref: main" in spotlight_budget_checkout_step,
            "Spotlight budget governed read lost static trusted-main checkout")
    require("ref: ${{ github.sha }}" not in spotlight_budget_checkout_step,
            "Spotlight budget governed read regained dynamic event-SHA checkout")
    spotlight_budget_step = named_step(
        spotlight,
        "budget",
        "Admit exact source epoch within bounded mutation budget",
    )
    require(spotlight_budget_step.count("python3 source/scripts/automation_github_read.py") == 1,
            "Spotlight budget must use exactly one governed GitHub singleton read")
    require(
        'gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100"' not in spotlight_budget_step,
        "Spotlight budget regained direct singleton GitHub transport",
    )
    require("GH_TOKEN: ${{ github.token }}" in spotlight_budget_step,
            "Spotlight budget governed read lost run-scoped token binding")
    spotlight_budget_identity_step = named_step(
        spotlight,
        "budget",
        "Verify exact governed read source identity",
    )
    require(
        'test "$(git -C source rev-parse HEAD:scripts/automation_github_read.py)" = "1b779bcea0acd290826fef8f60fd01480113a31a"'
        in spotlight_budget_identity_step,
        "Spotlight budget lost exact governed-read helper identity",
    )
    require(
        'test "$(git -C source rev-parse HEAD)" = "$BASE_SHA"' in spotlight_budget_identity_step,
        "Spotlight budget lost sealed-base governed-read source identity",
    )

    dispatch_plan_step = named_step(
        profile_stats,
        "dispatch_plan",
        "Plan exact Spotlight reconciliation dispatch",
    )
    require(dispatch_plan_step.count("python3 source/scripts/automation_github_read.py") == 2,
            "Profile Stats dispatch plan must use exactly two governed GitHub singleton reads")
    for forbidden in (
        'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml/runs?event=workflow_dispatch&branch=main&per_page=1"',
    ):
        require(forbidden not in dispatch_plan_step,
                f"Profile Stats dispatch plan regained direct singleton GitHub transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in dispatch_plan_step,
            "Profile Stats dispatch-plan governed reads lost run-scoped token binding")

    dispatch_step = named_step(
        profile_stats,
        "dispatch",
        "Dispatch exact Spotlight reconciliation workflow",
    )
    require("python3 source/scripts/automation_github_read.py" not in dispatch_step,
            "Profile Stats write-only dispatcher must not execute governed read client")
    require(dispatch_step.count("gh api ") == 1
            and dispatch_step.count("--method POST") == 1
            and "actions/workflows/spotlight-link-sync.yml/dispatches" in dispatch_step,
            "Profile Stats dispatcher must retain exactly one non-retried workflow-dispatch POST")


def validate(policy: dict[str, Any], texts: dict[str, str]) -> None:
    require(isinstance(policy, dict) and set(policy) == {
        "schemaVersion", "automaticRetries", "terminalOperations", "boundedObservation", "trustedReentry"
    }, "retry policy top-level shape changed")
    require(policy.get("schemaVersion") == 1, "retry policy schemaVersion changed")
    validate_automatic_retries(policy, texts)
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
    unauthorized["automaticRetries"].append({"id": "unreviewed"})
    expect_failure(unauthorized, dict(texts), "automatic retry identities changed")

    retry_budget_drift = copy.deepcopy(policy)
    retry_budget_drift["automaticRetries"][0]["maxAttempts"] = 4
    expect_failure(retry_budget_drift, dict(texts), "attempt/timeout budget changed")

    profile_drift = dict(texts)
    profile_drift[".github/workflows/profile-quality.yml"] = profile_drift[
        ".github/workflows/profile-quality.yml"
    ].replace(
        "        uses: " + PINNED_GENERATOR + "\n",
        "        continue-on-error: true\n        uses: " + PINNED_GENERATOR + "\n",
        1,
    )
    expect_failure(copy.deepcopy(policy), profile_drift, "must fail its job directly")

    compatibility_transport_drift = dict(texts)
    compatibility_transport_drift[".github/workflows/profile-generator-compatibility-witness.yml"] = (
        compatibility_transport_drift[".github/workflows/profile-generator-compatibility-witness.yml"].replace(
            "python3 scripts/automation_github_read.py",
            "gh api",
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        compatibility_transport_drift,
        "must use exactly two governed GitHub read call sites",
    )

    for endpoint, label in (
        ("actions/workflows/action-provenance-witness.yml/runs?branch=main&status=success&per_page=100", "Action provenance witness"),
        ("actions/workflows/profile-generator-compatibility-witness.yml/runs?branch=main&status=success&per_page=100", "Profile generator compatibility witness"),
    ):
        consumer_transport_drift = dict(texts)
        source = consumer_transport_drift[".github/workflows/profile-quality.yml"]
        governed = f'python3 scripts/automation_github_read.py "repos/${{GITHUB_REPOSITORY}}/{endpoint}"'
        direct = f'gh api "repos/${{GITHUB_REPOSITORY}}/{endpoint}"'
        require(governed in source, f"retry-policy self-test fixture missing Profile Quality {label} governed read")
        consumer_transport_drift[".github/workflows/profile-quality.yml"] = source.replace(governed, direct, 1)
        expect_failure(
            copy.deepcopy(policy),
            consumer_transport_drift,
            "must use exactly three governed GitHub read call sites",
        )

    capability_transport_drift = dict(texts)
    capability_source = capability_transport_drift[".github/workflows/capability-admission.yml"]
    capability_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
    )
    require(capability_governed in capability_source,
            "retry-policy self-test fixture missing Capability Admission governed read")
    capability_transport_drift[".github/workflows/capability-admission.yml"] = (
        capability_source.replace(
            capability_governed,
            'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        capability_transport_drift,
        "must use exactly ten governed singleton GitHub reads",
    )

    capability_source_transport_drift = dict(texts)
    capability_candidate_source = capability_source_transport_drift[".github/workflows/capability-admission.yml"]
    capability_source_governed = (
        'COMMIT="$(python3 scripts/automation_github_read.py '
        '"repos/${HEAD_REPOSITORY}/git/commits/${HEAD_SHA}")"'
    )
    require(capability_source_governed in capability_candidate_source,
            "retry-policy self-test fixture missing Capability Admission candidate-source governed read")
    capability_source_transport_drift[".github/workflows/capability-admission.yml"] = (
        capability_candidate_source.replace(
            capability_source_governed,
            'COMMIT="$(gh api "repos/${HEAD_REPOSITORY}/git/commits/${HEAD_SHA}")"',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        capability_source_transport_drift,
        "must use exactly four governed singleton JSON reads",
    )


    dependabot_discovery_transport_drift = dict(texts)
    dependabot_discovery_source = dependabot_discovery_transport_drift[
        ".github/workflows/dependabot-controller.yml"
    ]
    dependabot_discovery_governed = (
        'python3 scripts/automation_github_paginated_read.py \\\n'
        '            "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100" \\\n'
        '            > open-pr-pages.json'
    )
    dependabot_discovery_direct = (
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&per_page=100" '
        '> open-pr-pages.json'
    )
    require(
        dependabot_discovery_governed in dependabot_discovery_source,
        "retry-policy self-test fixture missing Dependabot controller governed open-PR discovery",
    )
    dependabot_discovery_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_discovery_source.replace(
            dependabot_discovery_governed,
            dependabot_discovery_direct,
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_discovery_transport_drift,
        "Dependabot controller open-PR discovery must use exactly one governed paginated GitHub collection",
    )

    dependabot_file_pages_source = texts[".github/workflows/dependabot-controller.yml"]
    dependabot_file_pages_governed = (
        'python3 scripts/automation_github_paginated_read.py \\\n'
        '            "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" \\\n'
        '            > pr-file-pages.json'
    )
    dependabot_file_pages_direct = (
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" '
        '> pr-file-pages.json'
    )
    require(
        dependabot_file_pages_source.count(dependabot_file_pages_governed) == 2,
        "retry-policy self-test fixture missing both Dependabot governed changed-file collections",
    )

    dependabot_candidate_file_transport_drift = dict(texts)
    dependabot_candidate_file_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_file_pages_source.replace(
            dependabot_file_pages_governed,
            dependabot_file_pages_direct,
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_candidate_file_transport_drift,
        "Dependabot candidate-tree changed-file collection must use exactly one governed paginated GitHub collection",
    )

    dependabot_validation_file_transport_drift = dict(texts)
    dependabot_file_parts = dependabot_file_pages_source.rsplit(
        dependabot_file_pages_governed,
        1,
    )
    require(
        len(dependabot_file_parts) == 2,
        "retry-policy self-test could not isolate Dependabot validation changed-file collection",
    )
    dependabot_validation_file_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_file_pages_direct.join(dependabot_file_parts)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_validation_file_transport_drift,
        "Dependabot validation-target changed-file collection must use exactly one governed paginated GitHub collection",
    )

    dependabot_git_read_source = texts[".github/workflows/dependabot-controller.yml"]
    dependabot_commit_read_governed = (
        'python3 scripts/automation_github_read.py \\\n'
        '            "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}" \\\n'
        '            > "$RUNNER_TEMP/dependabot-candidate-commit-read.json"'
    )
    dependabot_commit_read_direct = (
        'gh api "repos/${TARGET_REPOSITORY}/git/commits/${HEAD_SHA}" \\\n'
        '            > "$RUNNER_TEMP/dependabot-candidate-commit-read.json"'
    )
    require(
        dependabot_git_read_source.count(dependabot_commit_read_governed) == 2,
        "retry-policy self-test fixture missing both Dependabot governed candidate Git commit reads",
    )

    dependabot_candidate_git_transport_drift = dict(texts)
    dependabot_candidate_git_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_git_read_source.replace(
            dependabot_commit_read_governed,
            dependabot_commit_read_direct,
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_candidate_git_transport_drift,
        "Dependabot candidate-tree Git-object reconstruction must use exactly three governed singleton Git-object reads",
    )

    dependabot_validation_git_transport_drift = dict(texts)
    dependabot_git_parts = dependabot_git_read_source.rsplit(
        dependabot_commit_read_governed,
        1,
    )
    require(
        len(dependabot_git_parts) == 2,
        "retry-policy self-test could not isolate Dependabot validation Git commit read",
    )
    dependabot_validation_git_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_commit_read_direct.join(dependabot_git_parts)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_validation_git_transport_drift,
        "Dependabot validation Git-object reconstruction must use exactly three governed singleton Git-object reads",
    )

    dependabot_ref_source = texts[".github/workflows/dependabot-controller.yml"]
    governed_initial_ref = (
        'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/git/ref/heads/main" '
        '> "$RUNNER_TEMP/dependabot-initial-main-ref.json"'
    )
    direct_initial_ref = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/main" '
        '> "$RUNNER_TEMP/dependabot-initial-main-ref.json"'
    )
    require(
        dependabot_ref_source.count(governed_initial_ref) == 1,
        "retry-policy self-test fixture missing singular governed Dependabot initial main-ref read",
    )
    dependabot_initial_ref_transport_drift = dict(texts)
    dependabot_initial_ref_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_ref_source.replace(governed_initial_ref, direct_initial_ref, 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_initial_ref_transport_drift,
        "Dependabot initial main binding governed Git-ref read topology changed",
    )

    governed_head_ref = (
        'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}" '
        '> "$RUNNER_TEMP/dependabot-head-ref.json"'
    )
    direct_head_ref = (
        'gh api "repos/${TARGET_REPOSITORY}/git/ref/heads/${HEAD_REF}" '
        '> "$RUNNER_TEMP/dependabot-head-ref.json"'
    )
    require(
        dependabot_ref_source.count(governed_head_ref) == 5,
        "retry-policy self-test fixture changed for shared Dependabot head-ref reads",
    )
    last_head = dependabot_ref_source.rfind(governed_head_ref)
    require(last_head >= 0, "retry-policy self-test could not isolate terminal Dependabot head-ref read")
    dependabot_terminal_ref_transport_drift = dict(texts)
    dependabot_terminal_ref_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_ref_source[:last_head] + direct_head_ref
        + dependabot_ref_source[last_head + len(governed_head_ref):]
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_terminal_ref_transport_drift,
        "Dependabot CodeQL dispatch validation governed Git-ref read topology changed",
    )

    dependabot_pr_source = texts[".github/workflows/dependabot-controller.yml"]
    governed_pr_read = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
    )
    direct_pr_read = 'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
    require(
        dependabot_pr_source.count(governed_pr_read) == 5,
        "retry-policy self-test fixture changed for governed Dependabot PR snapshot reads",
    )

    dependabot_initial_pr_transport_drift = dict(texts)
    dependabot_initial_pr_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_pr_source.replace(governed_pr_read, direct_pr_read, 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_initial_pr_transport_drift,
        "Dependabot initial/update convergence governed singleton PR read topology changed",
    )

    terminal_marker = "      - name: Perform exact-head protected Dependabot merge\n"
    terminal_start = dependabot_pr_source.index(terminal_marker)
    terminal_read = dependabot_pr_source.index(governed_pr_read, terminal_start)
    dependabot_terminal_pr_transport_drift = dict(texts)
    dependabot_terminal_pr_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_pr_source[:terminal_read]
        + direct_pr_read
        + dependabot_pr_source[terminal_read + len(governed_pr_read):]
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_terminal_pr_transport_drift,
        "Dependabot terminal merge governed singleton PR read topology changed",
    )

    dependabot_workflow_singleton_source = texts[".github/workflows/dependabot-controller.yml"]
    governed_wake_read = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/actions/runs/${WAKE_RUN_ID}"'
    )
    direct_wake_read = 'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${WAKE_RUN_ID}"'
    require(
        dependabot_workflow_singleton_source.count(governed_wake_read) == 1,
        "retry-policy self-test fixture changed for governed Dependabot workflow-run wake read",
    )
    dependabot_wake_transport_drift = dict(texts)
    dependabot_wake_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_workflow_singleton_source.replace(governed_wake_read, direct_wake_read, 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_wake_transport_drift,
        "Dependabot workflow-run wake governed singleton read topology changed",
    )

    governed_proof_run_read = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/actions/runs/${proof_run_id}/attempts/${proof_run_attempt}"'
    )
    direct_proof_run_read = (
        'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${proof_run_id}/attempts/${proof_run_attempt}"'
    )
    require(
        dependabot_workflow_singleton_source.count(governed_proof_run_read) == 1,
        "retry-policy self-test fixture changed for governed Dependabot proof-run read",
    )
    dependabot_proof_run_transport_drift = dict(texts)
    dependabot_proof_run_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_workflow_singleton_source.replace(
            governed_proof_run_read, direct_proof_run_read, 1
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_proof_run_transport_drift,
        "Dependabot protected workflow/proof metadata governed singleton read topology changed",
    )

    dependabot_residual_source = texts[".github/workflows/dependabot-controller.yml"]
    residual_snapshot_fixtures = (
        (
            'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=workflow_dispatch&per_page=100"',
            'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=workflow_dispatch&per_page=100"',
            "Dependabot reconciled collection snapshots governed snapshot read topology changed",
        ),
        (
            'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100"',
            'gh api "repos/${TARGET_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100"',
            "Dependabot reconciled collection snapshots governed snapshot read topology changed",
        ),
        (
            'python3 scripts/automation_github_read.py "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&head=portyu9:${HEAD_REF}&per_page=10"',
            'gh api "repos/${TARGET_REPOSITORY}/pulls?state=open&base=main&head=portyu9:${HEAD_REF}&per_page=10"',
            "Dependabot validation-target PR snapshot governed snapshot read topology changed",
        ),
    )
    for governed, direct, expected in residual_snapshot_fixtures:
        require(
            dependabot_residual_source.count(governed) == 1,
            f"retry-policy residual snapshot fixture changed: {governed}",
        )
        drift = dict(texts)
        drift[".github/workflows/dependabot-controller.yml"] = (
            dependabot_residual_source.replace(governed, direct, 1)
        )
        expect_failure(copy.deepcopy(policy), drift, expected)

    proof_snapshot_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100"'
    )
    proof_snapshot_direct = (
        'gh api '
        '"repos/${TARGET_REPOSITORY}/commits/${HEAD_SHA}/check-runs?app_id=15368&check_name=trusted-capability-admission-proof&filter=latest&per_page=100"'
    )
    require(
        dependabot_residual_source.count(proof_snapshot_governed) == 2,
        "retry-policy residual delegated-admission snapshot fixture count changed",
    )
    for proof_index, expected in (
        (dependabot_residual_source.index(proof_snapshot_governed),
         "Dependabot reconciled collection snapshots governed snapshot read topology changed"),
        (dependabot_residual_source.rfind(proof_snapshot_governed),
         "Dependabot validation delegated-admission snapshot governed snapshot read topology changed"),
    ):
        proof_drift = dict(texts)
        proof_drift[".github/workflows/dependabot-controller.yml"] = (
            dependabot_residual_source[:proof_index]
            + proof_snapshot_direct
            + dependabot_residual_source[
                proof_index + len(proof_snapshot_governed):
            ]
        )
        expect_failure(copy.deepcopy(policy), proof_drift, expected)

    for endpoint in (
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100"',
        '"repos/${TARGET_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100"',
    ):
        governed = "python3 scripts/automation_github_paginated_read.py"
        endpoint_pos = dependabot_residual_source.index(endpoint)
        helper_pos = dependabot_residual_source.rfind(governed, 0, endpoint_pos)
        require(
            helper_pos >= 0 and endpoint_pos - helper_pos < 300,
            f"retry-policy residual pagination fixture changed: {endpoint}",
        )
        pagination_drift = dict(texts)
        pagination_drift[".github/workflows/dependabot-controller.yml"] = (
            dependabot_residual_source[:helper_pos]
            + "gh api --paginate --slurp"
            + dependabot_residual_source[helper_pos + len(governed):]
        )
        expect_failure(
            copy.deepcopy(policy),
            pagination_drift,
            "Dependabot terminal review/comment evidence must use exactly two governed paginated reads",
        )

    dependabot_release_transport_drift = dict(texts)
    dependabot_release_source = dependabot_release_transport_drift[".github/workflows/dependabot-controller.yml"]
    canonical_release_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${DEPENDENCY_REPOSITORY}" > release-repository.json'
    )
    require(
        dependabot_release_source.count(canonical_release_governed) == 2,
        "retry-policy self-test fixture missing Dependabot governed release repository reads",
    )
    dependabot_release_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_release_source.replace(
            canonical_release_governed,
            'gh api "repos/${DEPENDENCY_REPOSITORY}" > release-repository.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_release_transport_drift,
        "Dependabot canonical release proof must use exactly two governed singleton release reads",
    )

    dependabot_delegated_release_transport_drift = dict(texts)
    dependabot_delegated_source = dependabot_delegated_release_transport_drift[".github/workflows/dependabot-controller.yml"]
    delegated_release_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}" > release.json'
    )
    require(
        dependabot_delegated_source.count(delegated_release_governed) == 2,
        "retry-policy self-test fixture missing Dependabot governed release metadata reads",
    )
    last = dependabot_delegated_source.rfind(delegated_release_governed)
    require(last >= 0, "retry-policy self-test could not locate delegated release read")
    dependabot_delegated_release_transport_drift[".github/workflows/dependabot-controller.yml"] = (
        dependabot_delegated_source[:last]
        + 'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}" > release.json'
        + dependabot_delegated_source[last + len(delegated_release_governed):]
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_delegated_release_transport_drift,
        "Dependabot independent release reproof must use exactly two governed singleton release reads",
    )

    capability_release_transport_drift = dict(texts)
    capability_release_source = capability_release_transport_drift[".github/workflows/capability-admission.yml"]
    capability_release_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${DEPENDENCY_REPOSITORY}" > dependabot-release-repository.json'
    )
    require(capability_release_governed in capability_release_source,
            "retry-policy self-test fixture missing Capability Admission delegated-release governed read")
    capability_release_transport_drift[".github/workflows/capability-admission.yml"] = (
        capability_release_source.replace(
            capability_release_governed,
            'gh api "repos/${DEPENDENCY_REPOSITORY}" > dependabot-release-repository.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        capability_release_transport_drift,
        "must use exactly two governed singleton JSON reads",
    )

    capability_autofix_transport_drift = dict(texts)
    capability_autofix_source = capability_autofix_transport_drift[".github/workflows/capability-admission.yml"]
    capability_autofix_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/attempts/${RECEIPT_ATTEMPT}" > origin-run.json'
    )
    require(capability_autofix_governed in capability_autofix_source,
            "retry-policy self-test fixture missing Capability Admission Autofix governed read")
    capability_autofix_transport_drift[".github/workflows/capability-admission.yml"] = (
        capability_autofix_source.replace(
            capability_autofix_governed,
            'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${ORIGIN_RUN_ID}/attempts/${RECEIPT_ATTEMPT}" > origin-run.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        capability_autofix_transport_drift,
        "must use exactly two governed singleton JSON reads",
    )

    capability_history_transport_drift = dict(texts)
    capability_history_source = capability_history_transport_drift[".github/workflows/capability-admission.yml"]
    capability_history_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${HISTORY_ATTEMPT}"'
    )
    require(capability_history_governed in capability_history_source,
            "retry-policy self-test fixture missing Capability Admission prior-attempt governed read")
    capability_history_transport_drift[".github/workflows/capability-admission.yml"] = (
        capability_history_source.replace(
            capability_history_governed,
            'gh api "repos/${TARGET_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${HISTORY_ATTEMPT}"',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        capability_history_transport_drift,
        "must use exactly one governed singleton JSON read call site",
    )

    ruleset_sentinel_transport_drift = dict(texts)
    sentinel_source = ruleset_sentinel_transport_drift[".github/workflows/ruleset-drift-sentinel.yml"]
    sentinel_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/git/ref/heads/main"'
    )
    require(sentinel_governed in sentinel_source,
            "retry-policy self-test fixture missing Ruleset drift sentinel governed read")
    ruleset_sentinel_transport_drift[".github/workflows/ruleset-drift-sentinel.yml"] = (
        sentinel_source.replace(
            sentinel_governed,
            'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        ruleset_sentinel_transport_drift,
        "must use exactly one governed GitHub singleton read",
    )


    ruleset_plan_transport_drift = dict(texts)
    ruleset_plan_source = ruleset_plan_transport_drift[".github/workflows/ruleset-reconciler.yml"]
    ruleset_plan_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/portyu9/portyu9/rulesets/22148161" > live-plan.json'
    )
    require(
        ruleset_plan_governed in ruleset_plan_source,
        "retry-policy self-test fixture missing Ruleset reconciler plan governed read",
    )
    ruleset_plan_transport_drift[".github/workflows/ruleset-reconciler.yml"] = (
        ruleset_plan_source.replace(
            ruleset_plan_governed,
            'gh api "repos/portyu9/portyu9/rulesets/22148161" > live-plan.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        ruleset_plan_transport_drift,
        "Ruleset reconciler plan must use exactly 2 governed repository singleton reads",
    )

    ruleset_reconcile_transport_drift = dict(texts)
    ruleset_reconcile_source = ruleset_reconcile_transport_drift[".github/workflows/ruleset-reconciler.yml"]
    ruleset_reconcile_governed = (
        'GH_TOKEN="$ADMIN_TOKEN" python3 scripts/automation_github_read.py '
        '"repos/portyu9/portyu9/rulesets/22148161" > live-prewrite.json'
    )
    require(
        ruleset_reconcile_governed in ruleset_reconcile_source,
        "retry-policy self-test fixture missing Ruleset reconciler admin governed read",
    )
    ruleset_reconcile_transport_drift[".github/workflows/ruleset-reconciler.yml"] = (
        ruleset_reconcile_source.replace(
            ruleset_reconcile_governed,
            'GH_TOKEN="$ADMIN_TOKEN" gh api '
            '"repos/portyu9/portyu9/rulesets/22148161" > live-prewrite.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        ruleset_reconcile_transport_drift,
        "Ruleset reconciler reconcile must use exactly 5 governed repository singleton reads",
    )

    ruleset_attest_transport_drift = dict(texts)
    ruleset_attest_source = ruleset_attest_transport_drift[".github/workflows/ruleset-reconciler.yml"]
    ruleset_attest_governed = (
        'python3 scripts/automation_github_read.py '
        '"repos/portyu9/portyu9/rulesets/22148161" > live-attest.json'
    )
    require(
        ruleset_attest_governed in ruleset_attest_source,
        "retry-policy self-test fixture missing Ruleset reconciler attest governed read",
    )
    ruleset_attest_transport_drift[".github/workflows/ruleset-reconciler.yml"] = (
        ruleset_attest_source.replace(
            ruleset_attest_governed,
            'gh api "repos/portyu9/portyu9/rulesets/22148161" > live-attest.json',
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        ruleset_attest_transport_drift,
        "Ruleset reconciler attest must use exactly 2 governed repository singleton reads",
    )

    profile_stats_transport_drift = dict(texts)
    stats_source = profile_stats_transport_drift[".github/workflows/profile-stats.yml"]
    lease_governed = (
        'python3 source/scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"'
    )
    require(lease_governed in stats_source,
            "retry-policy self-test fixture missing Profile Stats lease governed read")
    profile_stats_transport_drift[".github/workflows/profile-stats.yml"] = stats_source.replace(
        lease_governed,
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"',
        1,
    )
    expect_failure(
        copy.deepcopy(policy),
        profile_stats_transport_drift,
        "must use exactly one governed GitHub singleton read",
    )

    spotlight_transport_drift = dict(texts)
    spotlight_source = spotlight_transport_drift[".github/workflows/spotlight-link-sync.yml"]
    spotlight_lease_governed = (
        'python3 source/scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"'
    )
    require(spotlight_lease_governed in spotlight_source,
            "retry-policy self-test fixture missing Spotlight lease governed read")
    spotlight_transport_drift[".github/workflows/spotlight-link-sync.yml"] = spotlight_source.replace(
        spotlight_lease_governed,
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"',
        1,
    )
    expect_failure(
        copy.deepcopy(policy),
        spotlight_transport_drift,
        "must use exactly one governed GitHub singleton read",
    )

    spotlight_budget_transport_drift = dict(texts)
    spotlight_budget_source = spotlight_budget_transport_drift[".github/workflows/spotlight-link-sync.yml"]
    spotlight_budget_governed = (
        'python3 source/scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100"'
    )
    require(spotlight_budget_governed in spotlight_budget_source,
            "retry-policy self-test fixture missing Spotlight budget governed read")
    spotlight_budget_transport_drift[".github/workflows/spotlight-link-sync.yml"] = spotlight_budget_source.replace(
        spotlight_budget_governed,
        'gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100"',
        1,
    )
    expect_failure(
        copy.deepcopy(policy),
        spotlight_budget_transport_drift,
        "Spotlight budget must use exactly one governed GitHub singleton read",
    )

    profile_stats_plan_drift = dict(texts)
    stats_source = profile_stats_plan_drift[".github/workflows/profile-stats.yml"]
    plan_governed = (
        'python3 source/scripts/automation_github_read.py '
        '"repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml"'
    )
    require(plan_governed in stats_source,
            "retry-policy self-test fixture missing Profile Stats dispatch-plan governed read")
    profile_stats_plan_drift[".github/workflows/profile-stats.yml"] = stats_source.replace(
        plan_governed,
        'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/spotlight-link-sync.yml"',
        1,
    )
    expect_failure(
        copy.deepcopy(policy),
        profile_stats_plan_drift,
        "must use exactly two governed GitHub singleton reads",
    )

    dependabot_context_transport_drift = dict(texts)
    context_source = dependabot_context_transport_drift[".github/workflows/profile-quality.yml"]
    context_governed = (
        'python3 trusted-base/scripts/automation_github_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"'
    )
    require(context_governed in context_source,
            "retry-policy self-test fixture missing Dependabot context governed read")
    dependabot_context_transport_drift[".github/workflows/profile-quality.yml"] = (
        context_source.replace(context_governed, 'gh api "repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}"', 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_context_transport_drift,
        "must use exactly five governed GitHub read call sites",
    )

    dependabot_release_transport_drift = dict(texts)
    release_source = dependabot_release_transport_drift[".github/workflows/profile-quality.yml"]
    release_governed = (
        'python3 trusted-base/scripts/automation_github_read.py '
        '"repos/${DEPENDENCY_REPOSITORY}"'
    )
    require(release_governed in release_source,
            "retry-policy self-test fixture missing Dependabot release governed read")
    dependabot_release_transport_drift[".github/workflows/profile-quality.yml"] = (
        release_source.replace(release_governed, 'gh api "repos/${DEPENDENCY_REPOSITORY}"', 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_release_transport_drift,
        "must use exactly two governed singleton GitHub read call sites",
    )

    dependabot_pagination_transport_drift = dict(texts)
    pagination_source = dependabot_pagination_transport_drift[".github/workflows/profile-quality.yml"]
    pagination_governed = (
        'python3 trusted-base/scripts/automation_github_paginated_read.py '
        '"repos/${TARGET_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100"'
    )
    pagination_direct = (
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/'
        '${PR_NUMBER}/files?per_page=100"'
    )
    require(pagination_governed in pagination_source,
            "retry-policy self-test fixture missing Dependabot governed paginated read")
    dependabot_pagination_transport_drift[".github/workflows/profile-quality.yml"] = (
        pagination_source.replace(pagination_governed, pagination_direct, 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_pagination_transport_drift,
        "must use exactly one governed paginated GitHub collection",
    )

    dependabot_pagination_identity_drift = dict(texts)
    pagination_identity_source = dependabot_pagination_identity_drift[".github/workflows/profile-quality.yml"]
    pagination_identity = (
        'test "$(git -C trusted-base rev-parse HEAD:scripts/automation_github_paginated_read.py)" '
        '= "03c48844349950a1396c9b95290091076966226e"'
    )
    require(pagination_identity in pagination_identity_source,
            "retry-policy self-test fixture missing Dependabot governed paginated helper identity")
    dependabot_pagination_identity_drift[".github/workflows/profile-quality.yml"] = (
        pagination_identity_source.replace(
            pagination_identity,
            pagination_identity.replace(
                "03c48844349950a1396c9b95290091076966226e",
                "0000000000000000000000000000000000000000",
            ),
            1,
        )
    )
    expect_failure(
        copy.deepcopy(policy),
        dependabot_pagination_identity_drift,
        "lost exact governed paginated-read helper identity",
    )

    loop_drift = dict(texts)
    loop_drift[".github/workflows/bot-pr-user-approval.yml"] = loop_drift[
        ".github/workflows/bot-pr-user-approval.yml"
    ].replace("for HISTORY_ATTEMPT in $(seq 1 20); do", "for HISTORY_ATTEMPT in $(seq 1 21); do", 1)
    expect_failure(copy.deepcopy(policy), loop_drift, "not declared")

    spotlight_dispatch_guard_drift = dict(texts)
    spotlight_dispatch_source = spotlight_dispatch_guard_drift[".github/workflows/spotlight-link-sync.yml"]
    require(
        "          REVIEW_DISPATCHED=false\n" in spotlight_dispatch_source,
        "retry-policy self-test fixture missing Spotlight reviewer-dispatch guard",
    )
    spotlight_dispatch_guard_drift[".github/workflows/spotlight-link-sync.yml"] = (
        spotlight_dispatch_source.replace("          REVIEW_DISPATCHED=false\n", "", 1)
    )
    expect_failure(
        copy.deepcopy(policy),
        spotlight_dispatch_guard_drift,
        "reviewer-dispatch dedupe initialization",
    )

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
        "Automation retry taxonomy validation passed: exactly three classified read-only GitHub retries are authorized; "
        "unclassified generator/ruleset and mutation failures remain terminal; all 15 bounded seq loops are declared "
        "as observation/re-entry semantics with guarded approval mutations explicitly constrained."
    )
