#!/usr/bin/env python3
"""Pure exact-candidate identity and artwork proof for future banner PR governance.

Consumes untrusted API snapshots only as inert data. Does not contact GitHub, mint
tokens, change the approved catalog, approve reviews, forge checks or merge refs.
Trusted callers must separately prove API transport, exact main, schedule/UTC
date, GitHub Actions check provenance and user veto before any authority step.
"""
from __future__ import annotations

import copy
from datetime import date, timedelta
import hashlib
import re
from typing import Any

import approved_banner_rotation as approved

REPOSITORY = "portyu9/portyu9"
BOT_LOGIN = "github-actions[bot]"
BOT_ID = 41898282
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise ValueError(explanation)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def blob_sha(text: str) -> str:
    value = text.encode("utf-8")
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value, usedforsecurity=False
    ).hexdigest()


def expected_branch(day: date, base_sha: str) -> str:
    return f"automation/banner-rotation/{day.isoformat()}-{base_sha[:12]}"


def expected_body(
    base_sha: str, readme_sha256: str, *, native_app: bool = False,
) -> str:
    version = "v8" if native_app else "v7"
    return (
        f"README-only UTC banner rotation using the reviewed approved {version} catalog. "
        "Three image surfaces and marker only; external CI evidence unchanged. "
        f"Base {base_sha}. Output SHA256 {readme_sha256}. Requires normal protected checks."
    )


 
def verified_native_banner_app_identity(
    *, installation: Any, bot_user: Any,
    expected_app_id: int, expected_installation_id: int,
    expected_repository_id: int,
) -> dict[str, str | int]:
    """Read-only App bot identity; no JWT or installation token required.

    Caller must bind authenticated responses to THIS repository's native
    installation endpoint and exact trusted-main expected installation IDs.
    This cannot authorize PR creation or merge by itself.
    """
    require(all(type(n) is int and n > 0 for n in (
        expected_app_id, expected_installation_id, expected_repository_id,
    )), "App/install/repository IDs must be positive integers")
    require(type(installation) is dict and type(bot_user) is dict,
            "read-only App identity response is malformed")
    slug = installation.get("app_slug")
    perms = installation.get("permissions")
    account = installation.get("account")
    require(type(installation.get("id")) is int
            and installation["id"] == expected_installation_id
            and type(installation.get("app_id")) is int
            and installation["app_id"] == expected_app_id
            and installation.get("repository_selection") == "selected"
            and type(account) is dict
            and account.get("login") == REPOSITORY.split("/")[0]
            and type(slug) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{2,100}", slug) is not None
            and type(perms) is dict
            and perms.get("contents") == "write"
            and perms.get("pull_requests") == "write",
            "App is not the exact reviewed selected repository installation")
    require(bot_user.get("login") == slug + "[bot]"
            and bot_user.get("type") == "Bot"
            and type(bot_user.get("id")) is int and bot_user["id"] > 0,
            "App bot user does not match reviewed installation slug")
    return {
        "appId": expected_app_id,
        "installationId": expected_installation_id,
        "repositoryId": expected_repository_id,
        "login": bot_user["login"], "userId": bot_user["id"],
    }


def verified_scoped_banner_app(
    *, installation: Any, token_response: Any, bot_user: Any,
    expected_app_id: int, expected_installation_id: int,
    expected_repository_id: int, observed_at: Any,
) -> dict[str, str | int]:
    """Validate *authenticated caller-provided* GitHub App producer evidence.

    The caller, NOT this predicate, must independently prove HTTPS response
    origins and that the installation/token were obtained from the reviewed
    ruleset-admin App JWT for the verified main. Tokens are never returned,
    emitted, stored in artifacts or written to logs by this pure function.
    """
    from datetime import datetime, timezone
    proof = verified_native_banner_app_identity(
        installation=installation, bot_user=bot_user,
        expected_app_id=expected_app_id,
        expected_installation_id=expected_installation_id,
        expected_repository_id=expected_repository_id,
    )
    require(type(observed_at) is datetime and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timezone.utc.utcoffset(observed_at),
            "App token observation must be UTC aware")
    require(type(token_response) is dict, "App token response is absent")
    # Request only two repository-scoped write permissions; refuse the
    # installation's wider administration/workflow authority in this token.
    token_permissions = token_response.get("permissions")
    allowed = {"contents": "write", "pull_requests": "write"}
    require(type(token_permissions) is dict
            and {k: v for k, v in token_permissions.items()
                 if k != "metadata"} == allowed
            and token_permissions.get("metadata", "read") == "read",
            "banner publisher token exceeded reviewed content/PR capability")
    repositories = token_response.get("repositories")
    require(token_response.get("repository_selection") == "selected"
            and type(repositories) is list and len(repositories) == 1
            and type(repositories[0]) is dict
            and repositories[0].get("full_name") == REPOSITORY
            and type(repositories[0].get("id")) is int
            and repositories[0]["id"] == expected_repository_id,
            "App token is not scoped to exactly the protected profile repository")
    expiration = token_response.get("expires_at")
    require(type(expiration) is str and expiration.endswith("Z"),
            "App token expiry is absent or has changed format")
    try:
        expiration_utc = datetime.fromisoformat(
            expiration.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("App token expiry is malformed") from exc
    seconds = (expiration_utc - observed_at).total_seconds()
    require(0 < seconds <= 3600,
            "App token is expired or exceeds a one-hour publication lease")
    require(type(token_response.get("token")) is str
            and len(token_response["token"]) >= 32,
            "App publication token is not present")
    return proof


def valid_candidate(
    *, pr: Any, commit: Any, files: Any,
    accepted_readme: str, proposed_readme: str,
    base_sha: str, utc_day: date,
    native_app: Any = None,
) -> dict[str, str | int]:
    require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None,
            "trusted current-main SHA is malformed")
    require(type(utc_day) is date, "trusted UTC date must be a date")
    require(type(accepted_readme) is str and type(proposed_readme) is str,
            "readme payload must be UTF-8 text")
    slots = approved.load_catalog()
    approved.validate_readme_state(accepted_readme, slots)
    exact = approved.propose(accepted_readme, approved.chosen(utc_day, slots), slots)
    require(exact != accepted_readme and exact == proposed_readme,
            "candidate README is unchanged, stale or not exact approved artwork")
    # Independently check every non-banner byte remains the same; prohibit
    # badges, Ledger/Spotlight epoch, metrics, unrelated prose and SVG mutation.
    import independent_banner_rotation as rotation
    rotation.only_banner_changes(accepted_readme, proposed_readme)

    require(type(pr) is dict and type(commit) is dict
            and type(files) is list and len(files) == 1,
            "candidate PR/commit/file response shape is malformed")
    require(type(pr.get("number")) is int and pr["number"] > 0
            and pr.get("state") == "open" and pr.get("draft") is False
            and pr.get("changed_files") == 1 and type(pr.get("changed_files")) is int,
            "banner PR cardinality/open/non-draft invariant failed")
    require(pr.get("title") ==
            f"chore(profile): independently rotate approved banners for {utc_day.isoformat()}",
            "banner PR title is not exact reviewed producer")
    require(pr.get("body") == expected_body(
            base_sha, sha256(proposed_readme), native_app=native_app is not None
        ),
            "banner PR body binds a different base, artwork or source")
    user = pr.get("user")
    producer = ({"login": BOT_LOGIN, "userId": BOT_ID}
                if native_app is None
                else verified_native_banner_app_identity(**native_app))
    require(type(user) is dict and user.get("login") == producer["login"]
            and type(user.get("id")) is int and user.get("id") == producer["userId"],
            "banner PR was not opened by the separately verified producer identity")
    base, head = pr.get("base"), pr.get("head")
    require(type(base) is dict and type(head) is dict,
            "banner PR base/head identities are absent")
    require(base.get("ref") == "main" and base.get("sha") == base_sha
            and type(base.get("repo")) is dict
            and base["repo"].get("full_name") == REPOSITORY,
            "banner PR accepted main binding changed")
    head_sha = head.get("sha")
    require(type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
            and head_sha != base_sha
            and head.get("ref") == expected_branch(utc_day, base_sha)
            and type(head.get("repo")) is dict
            and head["repo"].get("full_name") == REPOSITORY,
            "banner PR head identity/ref is not a same-repo reviewed lane")

    require(commit.get("sha") == head_sha
            and type(commit.get("parents")) is list
            and len(commit["parents"]) == 1
            and type(commit["parents"][0]) is dict
            and commit["parents"][0].get("sha") == base_sha,
            "banner candidate commit is not a one-commit exact-main child")
    payload = commit.get("commit")
    # App-authored publication needs a native event-eligible commit. The
    # old Actions path deliberately remains distinguishable and cannot be
    # passed off as a real native PR-triggering producer.
    message = f"chore(profile): rotate approved banner triplet for {utc_day.isoformat()}"
    if native_app is None:
        message += " [skip ci]"
    require(type(payload) is dict and payload.get("message") == message,
            "banner candidate commit message is not exact producer version")
    author, committer = payload.get("author"), payload.get("committer")
    require(type(author) is dict and type(committer) is dict
            and author.get("name") == BOT_LOGIN and committer.get("name") == BOT_LOGIN
            and author.get("email") == BOT_EMAIL and committer.get("email") == BOT_EMAIL,
            "banner candidate was not produced with reviewed bot commit identity")
    require(type(commit.get("author")) is dict
            and commit["author"].get("login") == BOT_LOGIN,
            "banner head commit author account is not GitHub Actions")
    row = files[0]
    require(type(row) is dict and row.get("filename") == "README.md"
            and row.get("status") == "modified"
            and row.get("sha") == blob_sha(proposed_readme),
            "candidate changed a file beyond the exact README output blob")
    require(type(row.get("additions")) is int and row["additions"] >= 0
            and type(row.get("deletions")) is int and row["deletions"] >= 0
            and row["additions"] + row["deletions"] > 0,
            "candidate file lacks a nonempty reviewed diff")
    return {
        "prNumber": pr["number"],
        "baseSha": base_sha,
        "headSha": head_sha,
        "utcDay": utc_day.isoformat(),
        "readmeSha256": sha256(proposed_readme),
        "readmeBlob": blob_sha(proposed_readme),
    }



# Read-only evidence projection for a *future separately authorized* banner
# reconciler. Never create or infer GitHub checks or owner approval here.
REQUIRED_CHECK_NAMES = frozenset({
    "validate-contracts",
    "integration-pinned-upstream",
    "trusted-governed-bot-review",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
    "trusted-capability-admission",
})
PROFILE_CHECK_NAMES = frozenset({
    "validate-contracts", "integration-pinned-upstream",
    "trusted-governed-bot-review",
})
CODEQL_CHECK_NAMES = frozenset({"analyze-actions", "analyze-python"})
GITHUB_ACTIONS_APP_ID = 15368


def verified_required_check_snapshot(check_runs: Any, head_sha: str) -> dict[str, int]:
    """Reject missing/duplicate/foreign/non-success exact-head check observations.

    The trusted future caller must first prove the authenticated GitHub API
    transport and total_count/pagination completeness. This pure predicate
    does not create statuses and never treats its own output as a check.
    """
    require(type(head_sha) is str and HEX40.fullmatch(head_sha) is not None,
            "required check head SHA is malformed")
    require(type(check_runs) is list and len(check_runs) <= 100,
            "required check inventory is malformed or incomplete")
    seen: dict[str, dict[str, Any]] = {}
    ids: set[int] = set()
    for row in check_runs:
        require(type(row) is dict and type(row.get("name")) is str,
                "required check response has an invalid record")
        name = row["name"]
        if name not in REQUIRED_CHECK_NAMES:
            continue  # An unrelated check cannot satisfy a required context.
        require(name not in seen, f"duplicate required check context: {name}")
        run_id = row.get("id")
        suite = row.get("check_suite")
        app = row.get("app")
        require(type(run_id) is int and run_id > 0 and run_id not in ids,
                f"required check id invalid: {name}")
        require(type(app) is dict and type(app.get("id")) is int
                and app["id"] == GITHUB_ACTIONS_APP_ID,
                f"required check is not GitHub Actions: {name}")
        require(type(suite) is dict and type(suite.get("id")) is int
                and suite["id"] > 0,
                f"required check suite missing: {name}")
        require(row.get("head_sha") == head_sha
                and row.get("status") == "completed"
                and row.get("conclusion") == "success",
                f"required check is not successful on exact head: {name}")
        seen[name] = row
        ids.add(run_id)
    require(set(seen) == REQUIRED_CHECK_NAMES,
            "one or more required protected checks are missing")
    require(len({seen[n]["check_suite"]["id"] for n in PROFILE_CHECK_NAMES}) == 1,
            "Profile Quality checks do not share one verified suite")
    require(len({seen[n]["check_suite"]["id"] for n in CODEQL_CHECK_NAMES}) == 1,
            "CodeQL Actions and Python checks do not share one verified suite")
    return {name: seen[name]["id"] for name in sorted(seen)}



# These identities are workflow *contracts*, not hardcoded alert IDs or run IDs.
# A reconciler must acquire each native run from the corresponding observed
# check suite and independently verify authenticated API result completeness.
EXPECTED_PROTECTED_WORKFLOWS = {
    "Profile quality": (
        ".github/workflows/profile-quality.yml", "pull_request",
        PROFILE_CHECK_NAMES,
    ),
    "CodeQL": (
        ".github/workflows/codeql.yml", "pull_request",
        CODEQL_CHECK_NAMES,
    ),
    "Dependency review": (
        ".github/workflows/dependency-review.yml", "pull_request",
        frozenset({"dependency-review"}),
    ),
    "Capability admission": (
        ".github/workflows/capability-admission.yml", "pull_request_target",
        frozenset({"trusted-capability-admission"}),
    ),
}


def verified_required_workflow_runs(
    check_runs: Any, workflow_runs: Any, head_ref: str, head_sha: str,
) -> dict[str, int]:
    """Bind seven successful check contexts to four genuine native run suites.

    The authenticated caller must separately verify complete GitHub API pages,
    exact current main, associated PR number, review threads and any prior
    attempts. This read-only function does not issue checks or dispatches.
    """
    verified_required_check_snapshot(check_runs, head_sha)
    require(type(head_ref) is str and
            head_ref.startswith("automation/banner-rotation/") and
            re.fullmatch(r"automation/banner-rotation/\d{4}-\d{2}-\d{2}-[0-9a-f]{12}", head_ref) is not None,
            "protected banner workflow head ref is not canonical")
    require(type(workflow_runs) is list and
            len(workflow_runs) == len(EXPECTED_PROTECTED_WORKFLOWS),
            "protected workflow evidence must have exactly four native runs")
    checks_by_name = {row["name"]: row for row in check_runs
                      if row["name"] in REQUIRED_CHECK_NAMES}
    seen: dict[str, int] = {}
    seen_run_ids: set[int] = set()
    seen_suite_ids: set[int] = set()
    for run in workflow_runs:
        require(type(run) is dict and type(run.get("name")) is str,
                "protected workflow run is malformed")
        name = run["name"]
        require(name in EXPECTED_PROTECTED_WORKFLOWS and name not in seen,
                "unknown or duplicate protected workflow run")
        path, event, context_names = EXPECTED_PROTECTED_WORKFLOWS[name]
        suite_ids = {checks_by_name[n]["check_suite"]["id"]
                     for n in context_names}
        require(len(suite_ids) == 1,
                "protected workflow contexts bind to different check suites")
        suite_id = next(iter(suite_ids))
        run_id = run.get("id")
        workflow_id = run.get("workflow_id")
        attempt = run.get("run_attempt")
        require(type(run_id) is int and run_id > 0
                and run_id not in seen_run_ids
                and type(workflow_id) is int and workflow_id > 0
                and type(attempt) is int and 1 <= attempt <= 20,
                "protected workflow execution identity/attempt invalid")
        require(type(run.get("check_suite_id")) is int
                and run["check_suite_id"] == suite_id
                and suite_id not in seen_suite_ids,
                "protected workflow run is not bound to required native suite")
        require(run.get("path") == path and run.get("event") == event
                and run.get("head_sha") == head_sha
                and run.get("head_branch") == head_ref
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and type(run.get("repository")) is dict
                and run["repository"].get("full_name") == REPOSITORY
                and type(run.get("head_repository")) is dict
                and run["head_repository"].get("full_name") == REPOSITORY,
                "protected workflow event/path/head/repository provenance changed")
        seen[name] = run_id
        seen_run_ids.add(run_id)
        seen_suite_ids.add(suite_id)
    require(set(seen) == set(EXPECTED_PROTECTED_WORKFLOWS),
            "protected workflow run inventory incomplete")
    return {name: seen[name] for name in sorted(seen)}

def verified_owner_review_snapshot(
    reviews: Any, base_sha: str, head_sha: str,
) -> None:
    """Require exact-marker owner APPROVED review, honoring explicit veto.

    Does not submit reviews, mint owner credentials or trigger a job rerun.
    """
    require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None
            and type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
            and base_sha != head_sha,
            "governed owner review base/head binding malformed")
    require(type(reviews) is list and len(reviews) <= 2000,
            "governed owner review snapshot malformed or incomplete")
    from automation_governed_bot_review_gate import review_decision
    require(review_decision(reviews, base_sha, head_sha) == "approved",
            "exact-head governed owner approval is absent, revoked or vetoed")


def qualified_banner_candidate(
    *, pr: Any, commit: Any, files: Any,
    accepted_readme: str, proposed_readme: str,
    base_sha: str, utc_day: date,
    check_runs: Any, reviews: Any, workflow_runs: Any,
    native_app: Any = None,
) -> dict[str, str | int]:
    """Compose reviewed artwork/ancestry, genuine-check and owner-veto gates.

    Caller must independently bind the exact live GitHub main ref, complete
    API pages, run-to-suite/event provenance and review-thread resolution.
    This helper does not grant merge permission or certify unattended runs.
    """
    result = valid_candidate(
        pr=pr, commit=commit, files=files,
        accepted_readme=accepted_readme, proposed_readme=proposed_readme,
        base_sha=base_sha, utc_day=utc_day, native_app=native_app,
    )
    verified_required_check_snapshot(check_runs, str(result["headSha"]))
    verified_required_workflow_runs(
        check_runs, workflow_runs, pr["head"]["ref"], str(result["headSha"])
    )
    verified_owner_review_snapshot(reviews, base_sha, str(result["headSha"]))
    return result



def verified_native_ref_leases(
    *, main_ref: Any, candidate_ref: Any,
    base_sha: str, head_ref: str, head_sha: str,
) -> None:
    """Bind two *authenticated* native ref snapshots to the reviewed PR.

    The caller must acquire fresh GET responses immediately before mutation,
    repeat them after any interposed Actions/review gate, and fail closed if
    GitHub returned a stale or incomplete snapshot.
    """
    require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None
            and type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
            and base_sha != head_sha,
            "banner native ref SHAs are invalid or identical")
    require(type(head_ref) is str
            and re.fullmatch(
                r"automation/banner-rotation/\d{4}-\d{2}-\d{2}-[0-9a-f]{12}",
                head_ref,
            ) is not None,
            "banner native candidate ref is not canonical")
    for observed, expected_ref, sha in (
        (main_ref, "refs/heads/main", base_sha),
        (candidate_ref, "refs/heads/" + head_ref, head_sha),
    ):
        require(type(observed) is dict and observed.get("ref") == expected_ref
                and type(observed.get("object")) is dict
                and observed["object"].get("type") == "commit"
                and observed["object"].get("sha") == sha,
                "banner native Git ref does not bind to exact accepted head")


def verified_review_thread_connection(connection: Any) -> None:
    """One complete native GraphQL page; refuse unresolved or hidden threads.

    An additional page must be fetched and normalized by a future caller,
    or the decision is not ready. A missing review-thread API response is
    never interpreted as an empty/approved inventory.
    """
    require(type(connection) is dict
            and set(connection) == {"nodes", "pageInfo", "totalCount"},
            "review thread connection has missing or unexpected fields")
    nodes = connection["nodes"]
    info = connection["pageInfo"]
    total = connection["totalCount"]
    require(type(nodes) is list and type(total) is int and 0 <= total <= 100
            and len(nodes) == total,
            "review thread inventory is incomplete, oversized or malformed")
    require(type(info) is dict and
            set(info) == {"hasNextPage", "endCursor"}
            and info["hasNextPage"] is False
            and (info["endCursor"] is None or type(info["endCursor"]) is str),
            "review thread pagination is incomplete or malformed")
    seen: set[str] = set()
    for thread in nodes:
        require(type(thread) is dict
                and set(thread) == {"id", "isResolved"}
                and type(thread["id"]) is str and thread["id"]
                and type(thread["isResolved"]) is bool
                and thread["id"] not in seen,
                "review thread identity or resolution is malformed")
        require(thread["isResolved"] is True,
                "unresolved review thread blocks banner terminal merge")
        seen.add(thread["id"])


def terminal_banner_readiness(
    *, pr: Any, commit: Any, files: Any,
    accepted_readme: str, proposed_readme: str,
    base_sha: str, utc_day: date, observed_now: Any,
    check_runs: Any, workflow_runs: Any, reviews: Any,
    review_threads: Any, main_ref: Any, candidate_ref: Any,
    native_app: Any = None,
) -> dict[str, str | int]:
    """Pure terminal authorization *evidence*; does not authorize a mutation.

    Exactly one reviewed immutable README candidate, fresh native refs,
    seven successful required checks from four trusted workflows, genuine
    owner approval without manual veto, no unresolved review threads,
    and valid current UTC day are all mandatory. The future authority job
    must independently re-read all live resources after this decision and
    perform a protected exact-head merge without a bypass.
    """
    from datetime import datetime, timezone
    require(type(observed_now) is datetime
            and observed_now.tzinfo is not None
            and observed_now.utcoffset() == timezone.utc.utcoffset(observed_now)
            and observed_now.date() == utc_day,
            "banner candidate is not for the current timezone-aware UTC day")
    result = qualified_banner_candidate(
        pr=pr, commit=commit, files=files,
        accepted_readme=accepted_readme, proposed_readme=proposed_readme,
        base_sha=base_sha, utc_day=utc_day,
        check_runs=check_runs, workflow_runs=workflow_runs, reviews=reviews,
        native_app=native_app,
    )
    verified_native_ref_leases(
        main_ref=main_ref, candidate_ref=candidate_ref,
        base_sha=base_sha, head_ref=pr["head"]["ref"],
        head_sha=str(result["headSha"]),
    )
    verified_review_thread_connection(review_threads)
    require(pr.get("mergeable") is True
            and pr.get("mergeable_state") == "clean",
            "banner PR is unmergeable, contested or still awaiting GitHub checks")
    require(all(run["run_attempt"] == 1 for run in workflow_runs),
            "unattended terminal witness must use first-attempt protected runs")
    return {
        "decision": "exact-reviewed-banner-ready-read-only",
        "prNumber": result["prNumber"],
        "baseSha": result["baseSha"],
        "headSha": result["headSha"],
        "utcDay": result["utcDay"],
        "readmeSha256": result["readmeSha256"],
        "readmeBlob": result["readmeBlob"],
    }


def select_read_only_banner_candidate(
    open_prs: Any, *, current_main_sha: str, utc_day: date,
    native_app: Any = None,
) -> dict[str, Any]:
    """Select zero or one canonical banner PR from a COMPLETE live PR page.

    Never delete an apparently stale candidate based only on listing data:
    stale-banner-candidate-requires-proof must be independently checked
    against historical accepted base/readme, one-commit ancestry, live refs
    and an explicit comment-before-close policy. No GitHub API is called here.
    """
    require(type(current_main_sha) is str
            and HEX40.fullmatch(current_main_sha) is not None
            and type(utc_day) is date,
            "banner selection requires exact current main and UTC date")
    require(type(open_prs) is list and len(open_prs) < 100,
            "banner open-PR list missing, oversized or possibly incomplete")
    # Native App authority requires its own complete installation and
    # token provenance; never equate any arbitrary "[bot]" actor with trust.
    producer = ({"login": BOT_LOGIN, "userId": BOT_ID}
                if native_app is None
                else verified_native_banner_app_identity(**native_app))
    candidates: list[dict[str, Any]] = []
    pr_numbers: set[int] = set()
    for pr in open_prs:
        require(type(pr) is dict and type(pr.get("number")) is int
                and pr["number"] > 0 and pr["number"] not in pr_numbers
                and pr.get("state") == "open" and type(pr.get("draft")) is bool
                and type(pr.get("base")) is dict
                and pr["base"].get("ref") == "main"
                and type(pr.get("head")) is dict
                and type(pr["head"].get("ref")) is str,
                "banner selector received malformed or duplicated open PR")
        pr_numbers.add(pr["number"])
        ref = pr["head"]["ref"]
        if not ref.startswith("automation/banner-rotation/"):
            continue
        match = re.fullmatch(
            r"automation/banner-rotation/(\d{4}-\d{2}-\d{2})-([0-9a-f]{12})",
            ref,
        )
        require(match is not None, "unreviewed banner-shaped branch ref")
        candidate_day = date.fromisoformat(match.group(1))
        base_sha = pr["base"].get("sha")
        head_sha = pr["head"].get("sha")
        actor = pr.get("user")
        require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None
                and type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
                and head_sha != base_sha
                and type(actor) is dict and actor.get("login") == producer["login"]
                and type(actor.get("id")) is int
                and actor["id"] == producer["userId"]
                and type(pr["head"].get("repo")) is dict
                and pr["head"]["repo"].get("full_name") == REPOSITORY
                and pr["draft"] is False,
                "banner-shaped PR was not the expected reviewed producer")
        require(candidate_day <= utc_day,
                "future-day banner candidate must not be auto-admitted")
        candidates.append({
            "prNumber": pr["number"],
            "headRef": ref,
            "headSha": head_sha,
            "baseSha": base_sha,
            "originalBasePrefix": match.group(2),
            "utcDay": candidate_day.isoformat(),
        })
    require(len(candidates) <= 1,
            "multiple banner candidates block safe automatic selection")
    if not candidates:
        return {
            "decision": "no-open-banner-candidate",
            "currentMainSha": current_main_sha, "utcDay": utc_day.isoformat(),
        }
    chosen = candidates[0]
    if (chosen["baseSha"] != current_main_sha
            or chosen["originalBasePrefix"] != current_main_sha[:12]
            or chosen["utcDay"] != utc_day.isoformat()):
        state = "stale-banner-candidate-requires-proof"
    else:
        state = "current-banner-candidate-requires-proof"
    return {"decision": state, "currentMainSha": current_main_sha, **chosen}

def self_test() -> None:
    require(blob_sha("hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a",
            "git blob SHA1 NUL delimiter regression")
    source = approved.read_file(approved.ROOT / "README.md")
    slots = approved.load_catalog()
    approved.validate_assets(slots)
    match = approved.MARKER.search(source)
    require(match is not None, "banner test requires the accepted rotation marker")
    day = date.fromisoformat(match.group(2)) + timedelta(days=1)
    proposed = approved.propose(source, approved.chosen(day, slots), slots)
    require(proposed != source, "candidate fixture must have a real banner change")
    base, head = "a" * 40, "b" * 40
    title = f"chore(profile): independently rotate approved banners for {day.isoformat()}"
    commit_message = f"chore(profile): rotate approved banner triplet for {day.isoformat()} [skip ci]"
    pr: dict[str, Any] = {
        "number": 19, "state": "open", "draft": False, "changed_files": 1,
        "title": title, "body": expected_body(base, sha256(proposed)),
        "user": {"login": BOT_LOGIN, "id": BOT_ID},
        "base": {"ref": "main", "sha": base, "repo": {"full_name": REPOSITORY}},
        "head": {"ref": expected_branch(day, base), "sha": head,
                 "repo": {"full_name": REPOSITORY}},
    }
    commit: dict[str, Any] = {
        "sha": head, "parents": [{"sha": base}],
        "author": {"login": BOT_LOGIN},
        "commit": {"message": commit_message,
                   "author": {"name": BOT_LOGIN, "email": BOT_EMAIL},
                   "committer": {"name": BOT_LOGIN, "email": BOT_EMAIL}},
    }
    files: list[dict[str, Any]] = [{
        "filename": "README.md", "status": "modified",
        "sha": blob_sha(proposed), "additions": 4, "deletions": 4,
    }]
    fixture = {
        "pr": pr, "commit": commit, "files": files,
        "accepted_readme": source, "proposed_readme": proposed,
        "base_sha": base, "utc_day": day,
    }
    result = valid_candidate(**fixture)
    require(result["headSha"] == head and result["readmeBlob"] == blob_sha(proposed),
            "valid exact banner candidate was rejected")
    corruptions: list[tuple[str, tuple[Any, ...], Any]] = [
        ("pr", ("state",), "closed"),
        ("pr", ("draft",), True),
        ("pr", ("changed_files",), True),
        ("pr", ("title",), title + " (spoof)"),
        ("pr", ("body",), "unbound proposal"),
        ("pr", ("user", "login"), "portyu9"),
        ("pr", ("user", "id"), True),
        ("pr", ("base", "sha"), "c" * 40),
        ("pr", ("base", "ref"), "generated"),
        ("pr", ("head", "repo", "full_name"), "outsider/fork"),
        ("pr", ("head", "ref"), "automation/banner-rotation/spoof"),
        ("pr", ("head", "sha"), "d" * 40),
        ("commit", ("sha",), "d" * 40),
        ("commit", ("parents",), [{"sha": "c" * 40}]),
        ("commit", ("commit", "message"), "unreviewed"),
        ("commit", ("commit", "committer", "email"), "attacker@example.com"),
        ("files", (0, "filename"), "scripts/generate.py"),
        ("files", (0, "sha"), "f" * 40),
        ("files", (0, "status"), "added"),
        ("files", (0, "additions"), True),
        ("proposed_readme", (), proposed.replace("© 2026", "© 2027", 1)),
        ("proposed_readme", (), source),
        ("utc_day", (), day + timedelta(days=1)),
    ]
    for section, path, value in corruptions:
        mutant = copy.deepcopy(fixture)
        if not path:
            mutant[section] = value
        else:
            item: Any = mutant[section]
            for part in path[:-1]:
                item = item[part]
            item[path[-1]] = value
        try:
            valid_candidate(**mutant)
        except ValueError:
            pass
        else:
            raise ValueError(f"unreviewed banner PR mutation accepted: {section}.{path}")
    try:
        valid_candidate(**{**fixture, "files": files + files})
    except ValueError:
        pass
    else:
        raise ValueError("extra candidate file escaped exact-one-file gate")

    # Phase 2: check-run and owner-veto evidence is independent of candidate art.
    checks: list[dict[str, Any]] = []
    for index, name in enumerate(sorted(REQUIRED_CHECK_NAMES), start=1):
        suite = (100 if name in PROFILE_CHECK_NAMES
                 else 200 if name in CODEQL_CHECK_NAMES
                 else 300 + index)
        checks.append({
            "id": index, "name": name, "head_sha": head,
            "status": "completed", "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID},
            "check_suite": {"id": suite},
        })
    from automation_governed_bot_review_gate import review_marker
    owner_review = {
        "id": 1000, "user": {"login": "portyu9"},
        "state": "APPROVED", "commit_id": head,
        "body": review_marker(base, head),
    }
    verified_required_check_snapshot(checks, head)
    verified_owner_review_snapshot([owner_review], base, head)

    # Four independent suites must bind real event/path/repository/head tuples.
    run_fixtures: list[dict[str, Any]] = []
    for index, (name, (workflow_path, event, contexts)) in enumerate(
        EXPECTED_PROTECTED_WORKFLOWS.items(), start=1
    ):
        suite_id = next(row["check_suite"]["id"] for row in checks
                        if row["name"] in contexts)
        run_fixtures.append({
            "id": 1000 + index, "workflow_id": 2000 + index,
            "name": name, "path": workflow_path, "event": event,
            "head_sha": head, "head_branch": pr["head"]["ref"],
            "run_attempt": 1, "check_suite_id": suite_id,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
        })
    verified_required_workflow_runs(
        checks, run_fixtures, pr["head"]["ref"], head
    )
    qualified_banner_candidate(
        **fixture, check_runs=checks, reviews=[owner_review],
        workflow_runs=run_fixtures,
    )
    check_mutants: list[tuple[int, str, Any]] = [
        (0, "head_sha", "f" * 40),
        (0, "status", "queued"),
        (0, "conclusion", "failure"),
        (0, "id", True),
        (0, "app", {"id": 123}),
        (0, "check_suite", {"id": False}),
        (0, "name", "untrusted-check-name"),
    ]
    for index, key, value in check_mutants:
        mutation = copy.deepcopy(checks)
        mutation[index][key] = value
        try:
            verified_required_check_snapshot(mutation, head)
        except ValueError:
            pass
        else:
            raise ValueError(f"mutated required check was accepted: {key}")
    for mutation in (checks[:-1], checks + [checks[0]], "not-a-list"):
        try:
            verified_required_check_snapshot(mutation, head)
        except ValueError:
            pass
        else:
            raise ValueError("missing, duplicated or malformed required checks accepted")
    mismatched_suite = copy.deepcopy(checks)
    one_profile = next(i for i, row in enumerate(checks)
                       if row["name"] == "validate-contracts")
    mismatched_suite[one_profile]["check_suite"]["id"] = 900
    try:
        verified_required_check_snapshot(mismatched_suite, head)
    except ValueError:
        pass
    else:
        raise ValueError("split profile required-check suite was accepted")
    stale_review = {**owner_review, "commit_id": "e" * 40}
    revoked_review = {**owner_review, "state": "DISMISSED"}
    manual_veto = {
        "id": 1001, "user": {"login": "portyu9"},
        "state": "CHANGES_REQUESTED", "commit_id": head, "body": "Stop",
    }
    for evidence in (
        [], [stale_review], [revoked_review],
        [owner_review, manual_veto],
        [{**owner_review, "body": "ordinary manual review"}],
    ):
        try:
            verified_owner_review_snapshot(evidence, base, head)
        except ValueError:
            pass
        else:
            raise ValueError("unapproved, revoked or vetoed owner review was accepted")

    # Adversarial provenance: no lookalike named job can stand in for its
    # actual check suite, workflow path/event or native repository identity.
    for run_index, key, bad in [
        (0, "check_suite_id", 999),
        (0, "head_sha", "f" * 40),
        (0, "head_branch", "automation/banner-rotation/spoof"),
        (0, "name", "CodeQL"),
        (0, "path", ".github/workflows/fake.yml"),
        (0, "event", "workflow_dispatch"),
        (0, "status", "queued"),
        (0, "conclusion", "failure"),
        (0, "run_attempt", True),
        (0, "run_attempt", 21),
        (0, "id", True),
        (0, "workflow_id", 0),
        (3, "event", "pull_request"),
        (3, "repository", {"full_name": "attacker/repo"}),
        (3, "head_repository", {"full_name": "attacker/repo"}),
    ]:
        mutant = copy.deepcopy(run_fixtures)
        mutant[run_index][key] = bad
        try:
            verified_required_workflow_runs(
                checks, mutant, pr["head"]["ref"], head
            )
        except ValueError:
            pass
        else:
            raise ValueError(f"untrusted workflow provenance admitted: {key}")
    for bad_runs in (
        run_fixtures[:-1], run_fixtures + [run_fixtures[0]], "fake",
    ):
        try:
            verified_required_workflow_runs(
                checks, bad_runs, pr["head"]["ref"], head
            )
        except ValueError:
            pass
        else:
            raise ValueError("missing, duplicated or malformed workflow runs admitted")
    try:
        verified_required_workflow_runs(
            checks, run_fixtures,
            "automation/banner-rotation/spoof", head
        )
    except ValueError:
        pass
    else:
        raise ValueError("noncanonical banner branch admitted")

    # Terminal evidence must bind actual native ref leases and never infer
    # missing reviews, unresolved threads, staleness or mergeability.
    from datetime import datetime, timezone
    now = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    live_main_ref = {
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": base},
    }
    live_candidate_ref = {
        "ref": "refs/heads/" + pr["head"]["ref"],
        "object": {"type": "commit", "sha": head},
    }
    complete_threads = {
        "totalCount": 1,
        "nodes": [{"id": "PRRT_test", "isResolved": True}],
        "pageInfo": {"hasNextPage": False, "endCursor": "cursor"},
    }
    ready_pr = {**pr, "mergeable": True, "mergeable_state": "clean"}
    terminal = {
        **fixture, "pr": ready_pr,
        "observed_now": now,
        "check_runs": checks, "workflow_runs": run_fixtures,
        "reviews": [owner_review], "review_threads": complete_threads,
        "main_ref": live_main_ref, "candidate_ref": live_candidate_ref,
    }
    decision = terminal_banner_readiness(**terminal)
    require(decision["decision"] == "exact-reviewed-banner-ready-read-only"
            and decision["prNumber"] == pr["number"]
            and decision["headSha"] == head,
            "exact terminal banner readiness fixture did not qualify")

    for fragment, overrides in [
        ("stale utc day", {"observed_now": now + timedelta(days=1)}),
        ("unbound utc time", {"observed_now": now.replace(tzinfo=None)}),
        ("main sha", {"main_ref": {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": "c" * 40},
        }}),
        ("main ref spoof", {"main_ref": {
            "ref": "refs/heads/generated",
            "object": {"type": "commit", "sha": base},
        }}),
        ("head ref spoof", {"candidate_ref": {
            "ref": "refs/heads/automation/banner-rotation/spoof",
            "object": {"type": "commit", "sha": head},
        }}),
        ("head sha spoof", {"candidate_ref": {
            "ref": "refs/heads/" + pr["head"]["ref"],
            "object": {"type": "commit", "sha": "c" * 40},
        }}),
        ("unresolved thread", {"review_threads": {
            **complete_threads,
            "nodes": [{"id": "PRRT_test", "isResolved": False}],
        }}),
        ("missing thread page", {"review_threads": {
            **complete_threads,
            "pageInfo": {"hasNextPage": True, "endCursor": "cursor"},
        }}),
        ("missing thread response", {"review_threads": None}),
        ("truncated threads", {"review_threads": {
            **complete_threads, "totalCount": 2,
        }}),
        ("unmergeable", {"pr": {**ready_pr, "mergeable": False}}),
        ("unknown mergeability", {"pr": {**ready_pr, "mergeable": None}}),
        ("dirty mergeability", {"pr": {
            **ready_pr, "mergeable_state": "dirty",
        }}),
        ("explicit owner veto", {"reviews": [owner_review, manual_veto]}),
        ("review not yet submitted", {"reviews": []}),
        ("failed check", {"check_runs": [
            {**row, "conclusion": "failure"} if row["name"] == "analyze-python"
            else row for row in checks
        ]}),
        ("manual re-run", {"workflow_runs": [
            {**row, "run_attempt": 2} if row["name"] == "CodeQL"
            else row for row in run_fixtures
        ]}),
    ]:
        try:
            terminal_banner_readiness(**{**terminal, **overrides})
        except ValueError:
            pass
        else:
            raise ValueError(f"untrusted banner terminal evidence accepted: {fragment}")

    # Selection is read-only and must never turn stale/hijacked candidate
    # observations into a merge or a blind branch deletion.
    listing_candidate = copy.deepcopy(pr)
    unrelated = {
        "number": 77, "state": "open", "draft": False,
        "base": {"ref": "main", "sha": base},
        "head": {"ref": "automation/spotlight-links/" + "c" * 64,
                 "sha": "d" * 40},
    }
    empty_selection = select_read_only_banner_candidate(
        [unrelated], current_main_sha=base, utc_day=day
    )
    require(empty_selection["decision"] == "no-open-banner-candidate",
            "unrelated Spotlight PR incorrectly entered banner lane")
    current_selection = select_read_only_banner_candidate(
        [unrelated, listing_candidate], current_main_sha=base, utc_day=day
    )
    require(current_selection["decision"] ==
            "current-banner-candidate-requires-proof"
            and current_selection["prNumber"] == 19,
            "current canonical banner candidate was not selected")
    stale_selection = select_read_only_banner_candidate(
        [listing_candidate], current_main_sha="c" * 40,
        utc_day=day + timedelta(days=1),
    )
    require(stale_selection["decision"] ==
            "stale-banner-candidate-requires-proof"
            and stale_selection["headSha"] == head,
            "stale candidate was not quarantined for historical proof")

    # GitHub PR base.sha may track the newly advanced main even though the
    # immutable candidate branch still records the older source prefix.
    advanced_listing = copy.deepcopy(listing_candidate)
    advanced_listing["base"]["sha"] = "c" * 40
    advanced = select_read_only_banner_candidate(
        [advanced_listing], current_main_sha="c" * 40, utc_day=day
    )
    require(advanced["decision"] ==
            "stale-banner-candidate-requires-proof"
            and advanced["originalBasePrefix"] == base[:12],
            "advanced GitHub PR base was falsely classified as a new candidate")
    for label, mutation in [
        ("extra banner candidate", [listing_candidate, {
            **listing_candidate, "number": 20,
        }]),
        ("duplicate PR number", [listing_candidate, listing_candidate]),
        ("incomplete listing", [unrelated] * 100),
        ("malformed listing", {"items": [listing_candidate]}),
        ("fake head actor", [{**listing_candidate,
                              "user": {"login": "attacker", "id": 1}}]),
        ("bot ID spoof", [{**listing_candidate,
                           "user": {"login": BOT_LOGIN, "id": False}}]),
        ("fork", [{**listing_candidate, "head": {
            **listing_candidate["head"], "repo": {
                "full_name": "outsider/fork",
            },
        }}]),
        ("draft", [{**listing_candidate, "draft": True}]),
        ("future banner day", [{**listing_candidate, "head": {
            **listing_candidate["head"],
            "ref": expected_branch(day + timedelta(days=1), base),
        }}]),
        ("malformed branch", [{**listing_candidate, "head": {
            **listing_candidate["head"],
            "ref": "automation/banner-rotation/spoof",
        }}]),
        ("malformed base SHA", [{**listing_candidate, "base": {
            **listing_candidate["base"], "sha": "not-an-object-id",
        }}]),
        ("non-main PR", [{**listing_candidate, "base": {
            **listing_candidate["base"], "ref": "generated",
        }}]),
    ]:
        try:
            select_read_only_banner_candidate(
                mutation, current_main_sha=base, utc_day=day
            )
        except ValueError:
            pass
        else:
            raise ValueError(f"banner selector accepted: {label}")

    # The native-event producer must bind an authenticated *installation*,
    # repository-scoped two-permission token and exact App bot account.
    # It must never accept the old [skip ci] Actions PR as App-origin.
    from datetime import datetime, timezone
    native_now = datetime(2026, 10, 25, 1, 1, tzinfo=timezone.utc)
    installation = {
        "id": 101, "app_id": 202, "app_slug": "portyu9-reviewed-publisher",
        "account": {"login": "portyu9"},
        "permissions": {
            "administration": "write",
            "contents": "write", "pull_requests": "write",
        },
    }
    app_user = {
        "id": 303, "login": "portyu9-reviewed-publisher[bot]", "type": "Bot",
    }
    token_response = {
        "token": "masked-native-lease-" + "a" * 40,
        "permissions": {
            "contents": "write", "pull_requests": "write", "metadata": "read",
        },
        "repositories": [{"id": 404, "full_name": REPOSITORY}],
        "repository_selection": "selected",
        "expires_at": "2026-10-25T01:51:00Z",
    }
    app_evidence = {
        "installation": installation, "token_response": token_response,
        "bot_user": app_user, "expected_app_id": 202,
        "expected_installation_id": 101, "expected_repository_id": 404,
        "observed_at": native_now,
    }
    app_proof = verified_scoped_banner_app(**app_evidence)
    require(app_proof["login"] == app_user["login"]
            and app_proof["userId"] == app_user["id"]
            and "token" not in app_proof,
            "native App provenance did not enforce a non-secret identity")
    app_pr = copy.deepcopy(pr)
    app_pr["user"] = {"login": app_user["login"], "id": app_user["id"]}
    app_pr["body"] = expected_body(base, sha256(proposed), native_app=True)
    app_commit = copy.deepcopy(commit)
    app_commit["commit"]["message"] = (
        f"chore(profile): rotate approved banner triplet for {day.isoformat()}"
    )
    # Later reviewer and merge jobs receive NON-SECRET App identity only.
    public_app_evidence = {
        key: app_evidence[key] for key in (
            "installation", "bot_user", "expected_app_id",
            "expected_installation_id", "expected_repository_id",
        )
    }
    public_proof = verified_native_banner_app_identity(**public_app_evidence)
    require(public_proof == app_proof,
            "App identity differed between scoped writer and read-only reviewer")
    app_fixture = {
        **fixture, "pr": app_pr, "commit": app_commit,
        "native_app": public_app_evidence,
    }
    require("approved v8 catalog" in app_pr["body"]
            and "approved v7 catalog" in pr["body"],
            "native and legacy producer metadata lost explicit catalog versions")
    app_result = valid_candidate(**app_fixture)
    require(app_result["headSha"] == head, "App-origin candidate did not qualify")
    require(select_read_only_banner_candidate(
        [app_pr], current_main_sha=base, utc_day=day,
        native_app=app_evidence,
    )["decision"] == "current-banner-candidate-requires-proof",
        "authenticated App-origin open-PR selector did not qualify")
    qualified_banner_candidate(
        **app_fixture, check_runs=checks, workflow_runs=run_fixtures,
        reviews=[owner_review],
    )
    for label, changes in [
        ("public all-repos app", {"installation": {
            **installation, "repository_selection": "all",
        }}),
        ("public wrong app slug", {"installation": {
            **installation, "app_slug": "untrusted-service",
        }}),
        ("public bot ID boolean", {"bot_user": {**app_user, "id": True}}),
        ("public app id boolean", {"expected_app_id": True}),
        ("public missing content permission", {"installation": {
            **installation, "permissions": {
                "contents": "read", "pull_requests": "write",
            },
        }}),
    ]:
        try:
            verified_native_banner_app_identity(
                **{**public_app_evidence, **changes}
            )
        except ValueError:
            pass
        else:
            raise ValueError(f"public App identity witness accepted: {label}")
    for label, changes in [
        ("installation id spoof", {"expected_installation_id": 102}),
        ("app id spoof", {"expected_app_id": 204}),
        ("repository id spoof", {"expected_repository_id": 405}),
        ("expired lease", {"observed_at": native_now + timedelta(days=1)}),
        ("naive observation", {"observed_at": native_now.replace(tzinfo=None)}),
        ("overlong lease", {"token_response": {
            **token_response, "expires_at": "2026-10-25T02:30:00Z",
        }}),
        ("all repositories", {"token_response": {
            **token_response, "repository_selection": "all",
        }}),
        ("extra token privilege", {"token_response": {
            **token_response, "permissions": {
                **token_response["permissions"], "administration": "write",
            },
        }}),
        ("lost PR capability", {"token_response": {
            **token_response, "permissions": {
                "contents": "write", "pull_requests": "read",
            },
        }}),
        ("two repositories", {"token_response": {
            **token_response, "repositories": token_response["repositories"] + [
                {"id": 405, "full_name": "outsider/other"},
            ],
        }}),
        ("outside repository", {"token_response": {
            **token_response, "repositories": [
                {"id": 404, "full_name": "outsider/other"},
            ],
        }}),
        ("fork installation", {"installation": {
            **installation, "account": {"login": "attacker"},
        }}),
        ("app lacks content scope", {"installation": {
            **installation, "permissions": {
                "administration": "write", "pull_requests": "write",
            },
        }}),
        ("bot user ID boolean", {"bot_user": {
            **app_user, "id": True,
        }}),
        ("bot user spoof", {"bot_user": {
            **app_user, "login": "github-actions[bot]",
        }}),
        ("secret absent", {"token_response": {
            **token_response, "token": "",
        }}),
    ]:
        try:
            verified_scoped_banner_app(**{**app_evidence, **changes})
        except ValueError:
            pass
        else:
            raise ValueError(f"native App authority witness accepted: {label}")
    for label, app_mutant in [
        ("legacy v7 manifest", {**app_pr, "body": pr["body"]}),
        ("legacy GH Actions actor", pr),
        ("foreign app actor", {**app_pr, "user": {
            "login": "foreign-app[bot]", "id": app_user["id"],
        }}),
        ("spoofed app bot id", {**app_pr, "user": {
            "login": app_user["login"], "id": True,
        }}),
    ]:
        try:
            valid_candidate(**{**app_fixture, "pr": app_mutant})
        except ValueError:
            pass
        else:
            raise ValueError(f"native App PR identity accepted: {label}")
    for label, attempted_message in [
        ("suppressed native CI", commit_message),
        ("unreviewed native commit", "chore: native review bypass"),
    ]:
        mutate_commit = copy.deepcopy(app_commit)
        mutate_commit["commit"]["message"] = attempted_message
        try:
            valid_candidate(**{**app_fixture, "commit": mutate_commit})
        except ValueError:
            pass
        else:
            raise ValueError(f"native App candidate commit accepted: {label}")
    try:
        valid_candidate(**{**fixture, "pr": app_pr, "commit": app_commit})
    except ValueError:
        pass
    else:
        raise ValueError("legacy Actions contract silently admitted native App PR")
