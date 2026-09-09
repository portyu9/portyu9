#!/usr/bin/env python3
"""Fail closed on GitHub Actions workflow authority drift.

The repository treats workflow token authority as a closed allowlist. Structural
permissions, privileged command surfaces, and terminal write/signing jobs are reviewed
independently from byte-level workflow identity so a future workflow change must satisfy
both the exact-source lock and the least-privilege authority model.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

import spotlight_profile_links as spotlight_links

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
PROFILE_STATS = WORKFLOWS / "profile-stats.yml"
SYNC = WORKFLOWS / "spotlight-link-sync.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
README = ROOT / "README.md"

WORKFLOW_SCOPE = "__workflow__"
EXPECTED = {
    "codeql.yml": {
        "triggers": {"pull_request", "push", "schedule", "workflow_dispatch"},
        "jobs": {"analyze"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "analyze": {"contents": "read", "security-events": "write"},
        },
    },
    "dependency-review.yml": {
        "triggers": {"pull_request"},
        "jobs": {"dependency-review"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "dependency-review": {"contents": "read"},
        },
    },
    "profile-quality.yml": {
        "triggers": {"pull_request", "push"},
        "jobs": {"validate", "integration"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "validate": {"contents": "read"},
            "integration": {"contents": "read"},
        },
    },
    "profile-stats.yml": {
        "triggers": {"workflow_dispatch", "push", "schedule"},
        "jobs": {"generate", "attest", "attest_publish", "stage", "publish", "dispatch"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "generate": {"contents": "read"},
            "attest": {"contents": "read"},
            "attest_publish": {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
            },
            "stage": {"contents": "read"},
            "publish": {"contents": "write"},
            "dispatch": {"actions": "write"},
        },
    },
    "spotlight-link-sync.yml": {
        "triggers": {"workflow_dispatch", "schedule"},
        "jobs": {"plan", "propose", "approve", "merge"},
        "permissions": {
            WORKFLOW_SCOPE: {"contents": "read"},
            "plan": {"contents": "read"},
            "propose": {"contents": "write", "pull-requests": "write"},
            "approve": {"contents": "read", "actions": "write"},
            "merge": {"contents": "write", "pull-requests": "write", "checks": "read"},
        },
    },
}

JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
PERMISSIONS_KEY = re.compile(r"^(\s*)permissions:\s*(.*)$")
PERMISSION_ENTRY = re.compile(r"^([A-Za-z0-9-]+):\s*(read|write|none)\s*$")
TRIGGER_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):(?:\s.*)?$")


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_triggers(text: str, label: str) -> set[str]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "on:"]
    require(len(starts) == 1, f"{label}: workflow must use exactly one mapping-style on: block")
    triggers: set[str] = set()
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 0:
            break
        match = TRIGGER_KEY.match(line)
        if match:
            triggers.add(match.group(1))
    require(triggers, f"{label}: workflow trigger set is empty")
    return triggers


def parse_jobs(text: str, label: str) -> set[str]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "jobs:"]
    require(len(starts) == 1, f"{label}: workflow must contain exactly one jobs: block")
    jobs: set[str] = set()
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indentation(line) == 0:
            break
        match = JOB_KEY.match(line)
        if match:
            jobs.add(match.group(1))
    require(jobs, f"{label}: workflow job set is empty")
    return jobs


def parse_permissions(text: str, label: str) -> dict[str, dict[str, str]]:
    lines = text.splitlines()
    result: dict[str, dict[str, str]] = {}
    in_jobs = False
    current_job: str | None = None
    for index, line in enumerate(lines):
        if line == "jobs:":
            in_jobs = True
            current_job = None
            continue
        if in_jobs:
            job = JOB_KEY.match(line)
            if job:
                current_job = job.group(1)
        match = PERMISSIONS_KEY.match(line)
        if not match:
            continue
        indent = len(match.group(1))
        require(not match.group(2).strip(), f"{label}:{index + 1}: scalar/inline permissions are forbidden")
        if indent == 0:
            scope = WORKFLOW_SCOPE
        elif indent == 4 and current_job is not None:
            scope = current_job
        else:
            fail(f"{label}:{index + 1}: permissions block appears at an unreviewed scope")
        require(scope not in result, f"{label}: duplicate permissions block for {scope}")
        entries: dict[str, str] = {}
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                cursor += 1
                continue
            candidate_indent = indentation(candidate)
            if candidate_indent <= indent:
                break
            require(candidate_indent == indent + 2,
                    f"{label}:{cursor + 1}: nested/indirect permissions syntax is forbidden")
            entry = PERMISSION_ENTRY.fullmatch(candidate.strip())
            require(entry is not None, f"{label}:{cursor + 1}: unsupported permissions entry: {candidate.strip()}")
            key, value = entry.groups()
            require(key not in entries, f"{label}:{cursor + 1}: duplicate permission key: {key}")
            entries[key] = value
            cursor += 1
        require(entries, f"{label}: empty permissions block for {scope}")
        result[scope] = entries
    return result


def validate_workflow_text(filename: str, text: str, spec: dict[str, object]) -> None:
    triggers = parse_triggers(text, filename)
    jobs = parse_jobs(text, filename)
    permissions = parse_permissions(text, filename)
    require(triggers == spec["triggers"], f"{filename}: trigger authority changed: {sorted(triggers)}")
    require(jobs == spec["jobs"], f"{filename}: job inventory changed: {sorted(jobs)}")
    require(permissions == spec["permissions"], f"{filename}: token authority changed: {permissions!r}")


def job_block(text: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", text)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return text[start.start():]
    relative = text[start.end():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", relative)
    require(end is not None, f"workflow job boundary is missing after {key}: {next_key}")
    return text[start.start(): start.end() + end.start()]


def require_exact_gh_api_surface(block: str, *, label: str, expected_lines: tuple[str, ...]) -> None:
    observed = tuple(line.strip() for line in block.splitlines() if "gh api " in line)
    require(observed == expected_lines,
            f"{label}: gh api surface changed: expected={expected_lines!r} observed={observed!r}")
    for line in block.splitlines():
        stripped = line.strip()
        if re.search(r"(^|\s)gh\s+", stripped):
            require("gh api " in stripped,
                    f"{label}: non-api GitHub CLI command is forbidden: {stripped}")
    for forbidden in ("curl ", "wget ", "git push", "git fetch", "git clone"):
        require(forbidden not in block,
                f"{label}: alternate network/mutation path is forbidden: {forbidden.strip()}")


def validate_inventory() -> None:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    observed = {path.name for path in paths}
    require(observed == set(EXPECTED),
            f"Workflow inventory changed without authority review: expected={sorted(EXPECTED)} observed={sorted(observed)}")
    for path in paths:
        validate_workflow_text(path.name, path.read_text(encoding="utf-8"), EXPECTED[path.name])


def validate_quality_contract(text: str) -> None:
    require("python3 scripts/validate-workflow-authority-contract.py" in text,
            "Profile Quality must execute the workflow authority firewall")
    require('- ".github/workflows/**"' in text,
            "Profile Quality push paths must cover every workflow authority change")


def validate_profile_stats_contract(workflow: str) -> None:
    prepare = job_block(workflow, "attest", "attest_publish")
    attest_write = job_block(workflow, "attest_publish", "stage")
    stage = job_block(workflow, "stage", "publish")
    publish = job_block(workflow, "publish", "dispatch")
    dispatch = job_block(workflow, "dispatch", None)

    require("name: prepare-attestation-read-only" in prepare and "needs: generate" in prepare,
            "Attestation preparation identity/dependency changed")
    require("permissions:\n      contents: read" in prepare,
            "Attestation preparation must remain contents: read")
    for forbidden in ("id-token: write", "attestations: write", "contents: write", "uses: actions/attest@"):
        require(forbidden not in prepare,
                f"Attestation preparation acquired terminal signing/write surface: {forbidden}")
    require(prepare.count("uses: actions/download-artifact@") == 3,
            "Attestation preparation must download exactly three evidence artifacts")
    require(prepare.count("uses: actions/upload-artifact@") == 1,
            "Attestation preparation must upload exactly one reviewed predicate artifact")
    require("name: profile-evidence-attestation-predicate" in prepare and
            "path: attestation-predicate.json" in prepare,
            "Attestation preparation predicate artifact identity changed")

    require("name: attest-write-only" in attest_write and "needs: attest" in attest_write,
            "Terminal attestation identity/dependency changed")
    require("id-token: write" in attest_write and "attestations: write" in attest_write and "contents: read" in attest_write,
            "Terminal attestation authority changed")
    for forbidden in (
        "      - name: Checkout",
        "actions/checkout@",
        "actions/setup-python@",
        "        run:",
        "python3 ",
        "GITHUB_TOKEN:",
        "GH_TOKEN:",
        "git ",
        "gh ",
        "curl ",
        "wget ",
        "contents: write",
        "actions: write",
        "pull-requests: write",
        "checks: read",
    ):
        require(forbidden not in attest_write,
                f"Terminal attestation job acquired authored shell/code or unrelated authority: {forbidden}")
    require(attest_write.count("      - name: ") == 5,
            "Terminal attestation must contain exactly four artifact downloads plus one attest action")
    require(attest_write.count("uses: actions/download-artifact@") == 4,
            "Terminal attestation must execute exactly four reviewed artifact downloads")
    require(attest_write.count("digest-mismatch: error") == 4,
            "Terminal attestation downloads must fail closed on every digest mismatch")
    require(attest_write.count("uses: actions/attest@") == 1,
            "Terminal attestation must execute exactly one reviewed actions/attest step")
    require("name: profile-evidence-attestation-predicate" in attest_write and
            "predicate-path: attestation-input/attestation-predicate.json" in attest_write,
            "Terminal attestation predicate transport/path changed")
    guard = "if: github.event_name != 'schedule' || needs.attest.outputs.changed == 'true'"
    require(attest_write.startswith(f"  attest_publish:\n    {guard}\n"),
            "Terminal attestation must use the exact reviewed scheduled-delta guard at the job boundary")
    require(attest_write.count(guard) == 6,
            "Terminal attestation job and all five terminal steps must share the exact reviewed scheduled-delta guard")

    require("name: stage-publication-read-only" in stage and
            "needs: [generate, attest, attest_publish]" in stage,
            "Publication staging must wait for generation, preparation, and terminal attestation")
    require("permissions:\n      contents: read" in stage,
            "Profile stats publication staging must remain read-only")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", "git push", "GITHUB_TOKEN:"):
        require(forbidden not in stage,
                f"Publication staging acquired forbidden authority/mutation surface: {forbidden}")

    require("name: publish-write-only" in publish and "needs: stage" in publish,
            "Terminal publisher identity/dependency changed")
    require("permissions:\n      contents: write" in publish,
            "Terminal publisher must retain only repository-content write authority")
    publish_guard = "if: needs.stage.outputs.changed == 'true'"
    require(publish.startswith(f"  publish:\n    {publish_guard}\n"),
            "Terminal publisher must use the exact staged-candidate guard at the job boundary")
    require(publish.count(publish_guard) == 4,
            "Terminal publisher job and all three changed-candidate steps must share the exact staged-candidate guard")
    for forbidden in (
        "actions/checkout@", "actions/setup-python@", "python3 ", "id-token:", "attestations:",
        "actions:", "pull-requests:", "checks:", "security-events:", "packages:",
    ):
        require(forbidden not in publish,
                f"Terminal publisher acquired forbidden capability/code surface: {forbidden}")
    require(publish.count("uses: actions/download-artifact@") == 1,
            "Terminal publisher must execute only one candidate-transport Action")
    require(publish.count("${{ github.token }}") == 1,
            "Terminal publisher explicit token surface changed")
    require("git -C artifacts -c \"http.https://github.com/.extraheader=AUTHORIZATION: basic ${AUTH_HEADER}\" push origin HEAD:generated" in publish,
            "Terminal publisher exact generated push changed")

    require("needs: publish" in dispatch and "name: dispatch-spotlight-link-sync" in dispatch,
            "Spotlight dispatcher identity/dependency changed")
    require('GH_TOKEN: ${{ github.token }}' in dispatch,
            "Spotlight dispatcher must use only the job-scoped GitHub token")
    require_exact_gh_api_surface(
        dispatch,
        label="Profile stats Spotlight dispatcher",
        expected_lines=("gh api --method POST \\",),
    )
    for forbidden in (
        "actions/checkout@", "actions/setup-python@", "contents:", "pull-requests:", "checks:",
        "id-token:", "attestations:", "security-events:", "packages:",
    ):
        require(forbidden not in dispatch,
                f"Spotlight dispatcher acquired forbidden capability/code surface: {forbidden}")


def validate_sync_contract(workflow: str, readme: str) -> None:
    for forbidden in ("pull_request_target", "workflow_run", "repository_dispatch", "issues: write", "id-token: write", "attestations: write"):
        require(forbidden not in workflow, f"Spotlight direct-link sync contains forbidden authority/trigger: {forbidden}")
    require('BOT_BRANCH: "automation/spotlight-links"' in workflow, "Spotlight bot branch identity changed")
    require('ref: generated' in workflow and 'persist-credentials: false' in workflow,
            "Spotlight plan must read generated evidence without persisted credentials")
    require("validate-portfolio-evidence-ledger.py published/portfolio-evidence --require-live" in workflow,
            "Spotlight plan must revalidate published Ledger evidence")

    propose = job_block(workflow, "propose", "approve")
    approve = job_block(workflow, "approve", "merge")
    merge = job_block(workflow, "merge", None)
    require_exact_gh_api_surface(
        propose,
        label="Spotlight propose",
        expected_lines=(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$SOURCE_SHA"',
            'gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=main" --jq .content \\',
            'if gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${BOT_BRANCH}" >/dev/null 2>&1; then',
            'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BOT_BRANCH}" \\',
            'gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \\',
            'README_BLOB="$(gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${BOT_BRANCH}" --jq .sha)"',
            'gh api --method PUT "repos/${GITHUB_REPOSITORY}/contents/README.md" --input update.json > update-response.json',
            'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BOT_BRANCH}&base=main&per_page=10")"',
            'gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" --input pr.json > pr-response.json',
            'PR_HEAD="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --jq .head.sha)"',
        ),
    )
    require_exact_gh_api_surface(
        approve,
        label="Spotlight approve",
        expected_lines=(
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${BASE_SHA}...${HEAD_SHA}")"',
            'CODEQL_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/codeql.yml" --jq .id)"',
            'DEPENDENCY_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/dependency-review.yml" --jq .id)"',
            'PROFILE_WORKFLOW_ID="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-quality.yml" --jq .id)"',
            'RUNS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${HEAD_SHA}&event=pull_request&per_page=100")"',
            'gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/approve" >/dev/null',
        ),
    )
    require_exact_gh_api_surface(
        merge,
        label="Spotlight merge",
        expected_lines=(
            'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'FILES="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100")"',
            'CHECKS="$(gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs?filter=latest&per_page=100")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/generated" --jq .object.sha)" = "$GENERATED_SHA"',
            'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
            'MERGED_PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"',
            'test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$MERGE_SHA"',
            'if BRANCH_REF="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${BOT_BRANCH}" 2>/dev/null)"; then',
            'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BOT_BRANCH}" >/dev/null',
        ),
    )
    for block, label in ((propose, "propose"), (approve, "approve"), (merge, "merge")):
        require("actions/checkout@" not in block and "actions/setup-python@" not in block,
                f"Spotlight {label} authority job must not checkout or execute authored Python")
    require('compare/${BASE_SHA}...${HEAD_SHA}' in approve,
            "Spotlight approval must compare exact proposed head against reviewed base")
    for check in ("analyze-actions", "analyze-python", "dependency-review", "integration-pinned-upstream", "validate-contracts"):
        require(check in merge, f"Spotlight merge is missing required check: {check}")
    for fragment in (
        'test "$(jq -r .merged <<<"$MERGED_PR")" = "true"',
        'test "$(jq -r .head.sha <<<"$MERGED_PR")" = "$HEAD_SHA"',
        'test "$(jq -r .object.sha <<<"$BRANCH_REF")" = "$HEAD_SHA"',
        'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BOT_BRANCH}" >/dev/null',
    ):
        require(fragment in merge, f"Spotlight merge lost exact-head cleanup closure: {fragment}")

    require(readme.count(spotlight_links.START) == 1 and readme.count(spotlight_links.END) == 1,
            "README must contain exactly one guarded Spotlight direct-link block")
    start = readme.index(spotlight_links.START)
    end = readme.index(spotlight_links.END, start) + len(spotlight_links.END)
    block = readme[start:end]
    card_targets = re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+)"><picture>', block)
    workflow_targets = re.findall(r'<a href="(https://github\.com/portyu9/[A-Za-z0-9_.-]+/actions/workflows/(?:ci|security)\.yml)">', block)
    require(len(card_targets) == 3 and len(set(card_targets)) == 3,
            "Spotlight block must contain three distinct repository targets")
    require(len(workflow_targets) == 6 and len(set(workflow_targets)) == 6,
            "Spotlight block must contain six distinct direct workflow targets")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Workflow authority firewall", "closed allowlist", "security-events: write",
        "id-token: write", "attestations: write", "contents: write", "pull-requests: write",
        "actions: write", "checks: read", "stage-publication-read-only", "sealed Git bundle",
        "Spotlight direct-link synchronization", "pull_request_target", "new workflow",
        "one README-only commit", "canonical default-branch workflow", "generated evidence head",
        "post-publication", "actions: write only", "attest-write-only",
    ):
        require(phrase in text, f"Workflow authority governance documentation is missing: {phrase}")


def expect_failure(text: str, expected_fragment: str) -> None:
    spec = {
        "triggers": {"pull_request"},
        "jobs": {"scan"},
        "permissions": {WORKFLOW_SCOPE: {"contents": "read"}, "scan": {"contents": "read"}},
    }
    try:
        validate_workflow_text("self-test.yml", text, spec)
    except ValueError as exc:
        require(expected_fragment in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden workflow drift: {expected_fragment}")


def self_test() -> None:
    good = """name: Self test
on:
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    permissions:
      contents: read
    runs-on: ubuntu-24.04
"""
    validate_workflow_text(
        "self-test.yml", good,
        {"triggers": {"pull_request"}, "jobs": {"scan"},
         "permissions": {WORKFLOW_SCOPE: {"contents": "read"}, "scan": {"contents": "read"}}},
    )
    expect_failure(good.replace("  contents: read", "  contents: write", 1), "token authority changed")
    expect_failure(good.replace("  pull_request:\n", "  pull_request:\n  pull_request_target:\n"), "trigger authority changed")
    expect_failure(good.replace("jobs:\n", "jobs:\n  publish:\n    runs-on: ubuntu-24.04\n"), "job inventory changed")
    expect_failure(good.replace("permissions:\n  contents: read", "permissions: write-all", 1), "scalar/inline permissions")
    spotlight_links.self_test()


def main() -> int:
    try:
        for path in (QUALITY, PROFILE_STATS, GOVERNANCE, README, SYNC):
            require(path.is_file(), f"Workflow authority input is missing: {path.relative_to(ROOT)}")
        self_test()
        validate_inventory()
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_profile_stats_contract(PROFILE_STATS.read_text(encoding="utf-8"))
        validate_sync_contract(SYNC.read_text(encoding="utf-8"), README.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            "Workflow authority validation passed: five workflows form a closed authority inventory; "
            "attestation preparation is read-only and terminal OIDC/attestation authority executes no authored shell/code; "
            "publication staging remains isolated from terminal repository-write authority and terminal contents-write publication is job-gated on a sealed changed candidate; post-publication dispatch remains actions-only; "
            "Spotlight synchronization stays PR-gated with closed gh api surfaces and exact-head branch cleanup."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())