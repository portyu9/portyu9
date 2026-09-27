#!/usr/bin/env python3
"""Executable deterministic retry taxonomy for governed automation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
from typing import Any

import automation_github_read

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/automation-retry-policy-v1.json"
WORKFLOWS = ROOT / ".github/workflows"
PINNED_GENERATOR = "shinpr/github-profile-stats@49b5f7091182a45f3ef93923505b660c6da5f835 # v0.2.0"
GOVERNED_REVIEW_GATE = ROOT / "scripts/governed_bot_review_gate.py"
ACTION_RELEASE_PROVENANCE = ROOT / "scripts/validate-action-release-provenance.py"

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
    "action-release-provenance-read-transient",
    "canonical-github-api-read-transient",
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


def validate_automatic_retries(policy: dict[str, Any], texts: dict[str, str]) -> None:
    entries = policy.get("automaticRetries")
    require(isinstance(entries, list), "retry policy automaticRetries must be an array")
    require(
        {item.get("id") for item in entries if isinstance(item, dict)} == EXPECTED_AUTOMATIC_RETRY_IDS,
        "automatic retry identities changed",
    )
    require(len(entries) == 3 and all(isinstance(item, dict) for item in entries),
            "retry policy must authorize exactly three classified automatic read retries")
    by_id = {item["id"]: item for item in entries}
    require(len(by_id) == 3, "automatic retry IDs must remain unique")

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

    profile_quality = texts[".github/workflows/profile-quality.yml"]
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
        'gh api --paginate --slurp "repos/${TARGET_REPOSITORY}/pulls/'
        '${PR_NUMBER}/files?per_page=100"'
    )
    require(dependabot_release_step.count("gh api ") == 1
            and dependabot_release_step.count(paginated_files) == 1,
            "Profile Quality Dependabot release proof must retain exactly one bounded paginated gh api collection")
    for forbidden in (
        'gh api "repos/${DEPENDENCY_REPOSITORY}"',
        'gh api "repos/${DEPENDENCY_REPOSITORY}/releases/tags/${CANDIDATE_TAG}"',
    ):
        require(forbidden not in dependabot_release_step,
                f"Profile Quality Dependabot release proof regained direct singleton transport: {forbidden}")
    require("GH_TOKEN: ${{ github.token }}" in dependabot_release_step,
            "Profile Quality Dependabot release proof governed reads lost run-scoped token binding")

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
        "Automation retry taxonomy validation passed: exactly three classified read-only GitHub retries are authorized; "
        "unclassified generator/ruleset and mutation failures remain terminal; all 17 bounded seq loops are declared "
        "as observation/re-entry semantics with guarded approval mutations explicitly constrained."
    )
