#!/usr/bin/env python3
"""One-shot external certifier for exact ai-qa protected-owner maintenance subjects."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com/"
TARGET_REPOSITORY = "portyu9/ai-qa-automation"
AUTHORIZATION_ID = "aiqa-291-bootstrap-v1"
MANIFEST_PATH = Path(".github/aiqa-owner-protected-authorizations-v1.json")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ATTEMPTS = 3
TIMEOUT_SECONDS = 20
BACKOFF_SECONDS = (1.0, 2.0)
MAX_RESPONSE_BYTES = 8_000_000
TRANSIENT_HTTP = frozenset({408, 429, 500, 502, 503, 504})
EXPECTED_RULE_TYPES = {
    "deletion",
    "non_fast_forward",
    "pull_request",
    "required_status_checks",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"JSON contains duplicate object key: {key}")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=unique)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class PublicGitHub:
    def __init__(
        self,
        *,
        opener: Callable[..., Any] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._opener = opener
        self._sleeper = sleeper

    def get(self, endpoint: str) -> Any:
        require(
            endpoint.startswith(f"repos/{TARGET_REPOSITORY}/"),
            "certifier GitHub read escaped the exact target repository",
        )
        require("\\" not in endpoint and ".." not in urllib.parse.urlsplit(endpoint).path.split("/"),
                "certifier GitHub read endpoint is malformed")
        url = urllib.parse.urljoin(API_ROOT, endpoint)
        for attempt in range(ATTEMPTS):
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "portyu9-aiqa-owner-certifier-v1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                if self._opener is None:
                    context = urllib.request.build_opener(NoRedirect()).open(
                        request,
                        timeout=TIMEOUT_SECONDS,
                    )
                else:
                    context = self._opener(request, timeout=TIMEOUT_SECONDS)
                with context as response:
                    require(response.status == 200, f"GitHub GET returned HTTP {response.status}")
                    require(response.geturl() == url, "GitHub GET redirected unexpectedly")
                    require(
                        response.headers.get_content_type() == "application/json",
                        "GitHub GET response content type is not application/json",
                    )
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                    require(len(raw) <= MAX_RESPONSE_BYTES, "GitHub response exceeds ingestion bound")
                try:
                    return strict_json(raw.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise ValueError("GitHub response is not UTF-8") from exc
            except urllib.error.HTTPError as exc:
                if attempt + 1 >= ATTEMPTS or exc.code not in TRANSIENT_HTTP:
                    raise ValueError(f"GitHub GET returned HTTP {exc.code}: {endpoint}") from exc
                self._sleeper(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
            except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
                if attempt + 1 >= ATTEMPTS:
                    raise ValueError(f"GitHub GET exhausted transport retries: {endpoint}") from exc
                self._sleeper(BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS) - 1)])
        raise ValueError("unreachable certifier GitHub retry state")


def require_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None,
            f"{label} must be a canonical SHA")
    return value


def require_positive_int(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
            f"{label} must be a positive integer")
    return value


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "authorization manifest is missing or aliased")
    raw = path.read_text(encoding="utf-8")
    payload = strict_json(raw)
    require(isinstance(payload, dict), "authorization manifest root must be an object")
    require(
        set(payload) == {
            "schemaVersion",
            "policyId",
            "targetRepository",
            "ruleset",
            "authorizations",
        },
        "authorization manifest root keys changed",
    )
    require(payload["schemaVersion"] == 1, "authorization manifest schema changed")
    require(payload["policyId"] == "aiqa-owner-protected-authorizations-v1",
            "authorization policy identity changed")
    require(payload["targetRepository"] == TARGET_REPOSITORY,
            "authorization target repository changed")
    ruleset = payload["ruleset"]
    require(isinstance(ruleset, dict), "authorization ruleset policy must be an object")
    require(
        set(ruleset) == {
            "id",
            "name",
            "requiredContext",
            "requiredIntegrationId",
            "trustedBotLogin",
            "trustedBotId",
        },
        "authorization ruleset policy keys changed",
    )
    require(ruleset["id"] == 21201916 and ruleset["name"] == "Protect Main",
            "authorization ruleset identity changed")
    require(ruleset["requiredContext"] == "Trusted PR Gate",
            "authorization required status context changed")
    require(ruleset["requiredIntegrationId"] == 4766700,
            "authorization required status integration changed")
    require(ruleset["trustedBotLogin"] == "trusted-pr-gate[bot]" and
            ruleset["trustedBotId"] == 322661847,
            "authorization trusted App identity changed")

    authorizations = payload["authorizations"]
    require(isinstance(authorizations, dict) and set(authorizations) == {AUTHORIZATION_ID},
            "authorization inventory must contain exactly the reviewed bootstrap subject")
    auth = authorizations[AUTHORIZATION_ID]
    require(isinstance(auth, dict), "bootstrap authorization must be an object")
    require(
        set(auth) == {
            "issue",
            "prNumber",
            "ownerLogin",
            "ownerId",
            "headRef",
            "baseSha",
            "headSha",
            "mergeSha",
            "treeSha",
            "changedPaths",
            "evidenceRuns",
        },
        "bootstrap authorization keys changed",
    )
    require(auth["issue"] == "portyu9/ai-qa-automation#293",
            "bootstrap authorization issue binding changed")
    require(auth["prNumber"] == 291, "bootstrap authorization PR changed")
    require(auth["ownerLogin"] == "portyu9" and auth["ownerId"] == 35150859,
            "bootstrap owner identity changed")
    require(auth["headRef"] == "fix/event-driven-dependency-qualification",
            "bootstrap head ref changed")
    for key in ("baseSha", "headSha", "mergeSha", "treeSha"):
        require_sha(auth[key], f"bootstrap {key}")
    changed_paths = auth["changedPaths"]
    require(isinstance(changed_paths, list) and changed_paths,
            "bootstrap changed-path inventory must be nonempty")
    require(all(isinstance(path, str) and path and path == path.strip() for path in changed_paths),
            "bootstrap changed-path inventory is malformed")
    require(len(changed_paths) == len(set(changed_paths)),
            "bootstrap changed-path inventory contains duplicates")
    require(changed_paths == sorted(changed_paths),
            "bootstrap changed-path inventory must remain canonically sorted")
    require(any(path.startswith(".github/") or path.startswith("scripts/") for path in changed_paths),
            "bootstrap authorization no longer covers protected control-plane changes")
    runs = auth["evidenceRuns"]
    require(isinstance(runs, list) and len(runs) == 3,
            "bootstrap evidence must contain exactly three workflow runs")
    observed_run_ids: set[int] = set()
    for run in runs:
        require(isinstance(run, dict), "bootstrap evidence run must be an object")
        require(
            set(run) == {
                "id",
                "workflowId",
                "name",
                "path",
                "event",
                "runAttempt",
                "jobs",
            },
            "bootstrap evidence run keys changed",
        )
        run_id = require_positive_int(run["id"], "bootstrap evidence run id")
        require(run_id not in observed_run_ids, "bootstrap evidence run ids must be unique")
        observed_run_ids.add(run_id)
        require_positive_int(run["workflowId"], "bootstrap evidence workflow id")
        require(run["event"] == "pull_request" and run["runAttempt"] == 1,
                "bootstrap evidence must be first-attempt pull-request runs")
        require(isinstance(run["name"], str) and run["name"], "bootstrap evidence run name invalid")
        require(isinstance(run["path"], str) and run["path"].startswith(".github/workflows/"),
                "bootstrap evidence workflow path invalid")
        jobs = run["jobs"]
        require(isinstance(jobs, dict) and jobs, "bootstrap evidence job map must be nonempty")
        require(
            all(isinstance(name, str) and name and conclusion in {"success", "skipped"}
                for name, conclusion in jobs.items()),
            "bootstrap evidence job map contains unsupported conclusion",
        )
    return payload


def _require_ruleset(api: PublicGitHub, policy: dict[str, Any]) -> None:
    ruleset_policy = policy["ruleset"]
    ruleset = api.get(f"repos/{TARGET_REPOSITORY}/rulesets/{ruleset_policy['id']}")
    require(isinstance(ruleset, dict), "live Protect Main ruleset is malformed")
    require(ruleset.get("id") == ruleset_policy["id"] and
            ruleset.get("name") == ruleset_policy["name"] and
            ruleset.get("enforcement") == "active" and
            ruleset.get("target") == "branch",
            "live Protect Main ruleset identity/enforcement drifted")
    require(ruleset.get("bypass_actors") == [], "live Protect Main gained bypass actors")
    conditions = ruleset.get("conditions")
    require(
        isinstance(conditions, dict)
        and conditions.get("ref_name") == {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
        "live Protect Main target conditions drifted",
    )
    rules = ruleset.get("rules")
    require(isinstance(rules, list), "live Protect Main rules are malformed")
    by_type: dict[str, dict[str, Any]] = {}
    for rule in rules:
        require(isinstance(rule, dict) and isinstance(rule.get("type"), str),
                "live Protect Main contains malformed rule")
        rule_type = str(rule["type"])
        require(rule_type not in by_type, "live Protect Main contains duplicate rule type")
        by_type[rule_type] = rule
    require(set(by_type) == EXPECTED_RULE_TYPES, "live Protect Main rule inventory drifted")
    pr_params = by_type["pull_request"].get("parameters")
    require(
        isinstance(pr_params, dict)
        and pr_params.get("required_approving_review_count") == 0
        and pr_params.get("required_review_thread_resolution") is True
        and pr_params.get("allowed_merge_methods") == ["merge"],
        "live Protect Main pull-request policy drifted",
    )
    status_params = by_type["required_status_checks"].get("parameters")
    require(
        isinstance(status_params, dict)
        and status_params.get("strict_required_status_checks_policy") is True
        and status_params.get("do_not_enforce_on_create") is False
        and status_params.get("required_status_checks") == [
            {
                "context": ruleset_policy["requiredContext"],
                "integration_id": ruleset_policy["requiredIntegrationId"],
            }
        ],
        "live Protect Main required-status policy drifted",
    )


def _require_evidence_run(api: PublicGitHub, auth: dict[str, Any], expected: dict[str, Any]) -> None:
    run_id = require_positive_int(expected["id"], "evidence run id")
    run = api.get(f"repos/{TARGET_REPOSITORY}/actions/runs/{run_id}")
    require(isinstance(run, dict), "evidence workflow run is malformed")
    require(
        run.get("id") == run_id
        and run.get("workflow_id") == expected["workflowId"]
        and run.get("name") == expected["name"]
        and run.get("path") == expected["path"]
        and run.get("event") == expected["event"]
        and run.get("run_attempt") == expected["runAttempt"]
        and run.get("head_branch") == auth["headRef"]
        and run.get("head_sha") == auth["headSha"]
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and (run.get("repository") or {}).get("full_name") == TARGET_REPOSITORY
        and (run.get("head_repository") or {}).get("full_name") == TARGET_REPOSITORY,
        f"evidence workflow run drifted: {run_id}",
    )
    pull_numbers = [
        row.get("number")
        for row in (run.get("pull_requests") or [])
        if isinstance(row, dict)
    ]
    require(pull_numbers == [auth["prNumber"]],
            f"evidence workflow run PR binding drifted: {run_id}")

    jobs_payload = api.get(f"repos/{TARGET_REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100")
    require(isinstance(jobs_payload, dict), "evidence jobs payload is malformed")
    jobs = jobs_payload.get("jobs")
    require(
        isinstance(jobs, list)
        and jobs_payload.get("total_count") == len(jobs)
        and len(jobs) <= 100,
        "evidence jobs response is incomplete or unbounded",
    )
    observed: dict[str, str] = {}
    for job in jobs:
        require(isinstance(job, dict), "evidence job is malformed")
        name = job.get("name")
        conclusion = job.get("conclusion")
        require(isinstance(name, str) and name and name not in observed,
                "evidence job names must be unique")
        require(job.get("status") == "completed" and isinstance(conclusion, str),
                f"evidence job is not terminal: {name}")
        observed[name] = conclusion
    require(observed == expected["jobs"],
            f"evidence job conclusions drifted for run {run_id}")


def verify_live(policy: dict[str, Any], api: PublicGitHub) -> dict[str, Any]:
    auth = policy["authorizations"][AUTHORIZATION_ID]
    main = api.get(f"repos/{TARGET_REPOSITORY}/branches/main")
    require(
        isinstance(main, dict)
        and ((main.get("commit") or {}).get("sha")) == auth["baseSha"],
        "target main moved from the authorized base SHA",
    )

    pr = api.get(f"repos/{TARGET_REPOSITORY}/pulls/{auth['prNumber']}")
    require(isinstance(pr, dict), "authorized pull request is malformed")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    user = pr.get("user") or {}
    require(
        pr.get("number") == auth["prNumber"]
        and pr.get("state") == "open"
        and pr.get("draft") is False
        and pr.get("mergeable") is True
        and user.get("login") == auth["ownerLogin"]
        and user.get("id") == auth["ownerId"]
        and pr.get("author_association") == "OWNER"
        and head.get("ref") == auth["headRef"]
        and head.get("sha") == auth["headSha"]
        and (head.get("repo") or {}).get("full_name") == TARGET_REPOSITORY
        and base.get("ref") == "main"
        and base.get("sha") == auth["baseSha"]
        and (base.get("repo") or {}).get("full_name") == TARGET_REPOSITORY,
        "authorized pull request identity/lifecycle drifted",
    )

    files = api.get(f"repos/{TARGET_REPOSITORY}/pulls/{auth['prNumber']}/files?per_page=100")
    require(isinstance(files, list) and len(files) == len(auth["changedPaths"]) and len(files) < 100,
            "authorized pull request file response is incomplete or changed")
    observed_paths: list[str] = []
    for row in files:
        require(isinstance(row, dict) and row.get("status") in {"added", "modified", "removed", "renamed"},
                "authorized pull request file row is malformed")
        filename = row.get("filename")
        require(isinstance(filename, str) and filename, "authorized pull request filename invalid")
        observed_paths.append(filename)
    require(sorted(observed_paths) == auth["changedPaths"],
            "authorized pull request changed-path set drifted")

    merge_ref = api.get(f"repos/{TARGET_REPOSITORY}/git/ref/pull/{auth['prNumber']}/merge")
    require(
        isinstance(merge_ref, dict)
        and merge_ref.get("ref") == f"refs/pull/{auth['prNumber']}/merge"
        and (merge_ref.get("object") or {}).get("type") == "commit"
        and (merge_ref.get("object") or {}).get("sha") == auth["mergeSha"],
        "authorized prospective merge ref drifted",
    )
    merge_commit = api.get(f"repos/{TARGET_REPOSITORY}/git/commits/{auth['mergeSha']}")
    require(isinstance(merge_commit, dict) and merge_commit.get("sha") == auth["mergeSha"],
            "authorized prospective merge commit drifted")
    parents = merge_commit.get("parents")
    require(
        isinstance(parents, list)
        and [row.get("sha") for row in parents if isinstance(row, dict)]
        == [auth["baseSha"], auth["headSha"]],
        "authorized prospective merge parent order drifted",
    )
    merge_tree = (merge_commit.get("tree") or {}).get("sha")
    require(merge_tree == auth["treeSha"], "authorized prospective merge tree drifted")
    head_commit = api.get(f"repos/{TARGET_REPOSITORY}/git/commits/{auth['headSha']}")
    require(
        isinstance(head_commit, dict)
        and head_commit.get("sha") == auth["headSha"]
        and (head_commit.get("tree") or {}).get("sha") == auth["treeSha"],
        "authorized head tree drifted from prospective merge tree",
    )

    _require_ruleset(api, policy)
    for expected_run in auth["evidenceRuns"]:
        _require_evidence_run(api, auth, expected_run)

    statuses = api.get(
        f"repos/{TARGET_REPOSITORY}/commits/{auth['headSha']}/statuses?per_page=100"
    )
    require(isinstance(statuses, list) and len(statuses) < 100,
            "trusted status history is incomplete or unbounded")
    conflicting = [
        row
        for row in statuses
        if isinstance(row, dict) and row.get("context") == policy["ruleset"]["requiredContext"]
    ]
    require(not conflicting, "authorized head already carries a Trusted PR Gate status")

    return {
        "authorizationId": AUTHORIZATION_ID,
        "repository": TARGET_REPOSITORY,
        "prNumber": auth["prNumber"],
        "baseSha": auth["baseSha"],
        "headSha": auth["headSha"],
        "mergeSha": auth["mergeSha"],
        "treeSha": auth["treeSha"],
        "rulesetId": policy["ruleset"]["id"],
        "requiredIntegrationId": policy["ruleset"]["requiredIntegrationId"],
        "evidenceRunIds": [run["id"] for run in auth["evidenceRuns"]],
        "result": "PASS",
    }


class FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return "application/json"


class FixtureResponse:
    def __init__(self, url: str, payload: Any) -> None:
        self.status = 200
        self._url = url
        self._raw = json.dumps(payload).encode("utf-8")
        self.headers = FixtureHeaders()

    def __enter__(self) -> "FixtureResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._raw


def self_test() -> None:
    require(ATTEMPTS == 3 and TIMEOUT_SECONDS == 20,
            "certifier bounded-read retry contract changed")
    require(BACKOFF_SECONDS == (1.0, 2.0),
            "certifier deterministic retry delays changed")
    require(MAX_RESPONSE_BYTES == 8_000_000,
            "certifier response ingestion bound changed")
    policy = load_manifest()
    auth = policy["authorizations"][AUTHORIZATION_ID]
    require(len(auth["changedPaths"]) == 26, "bootstrap changed-path count changed")
    require([run["id"] for run in auth["evidenceRuns"]] ==
            [36344365191, 36344365180, 36344365542],
            "bootstrap evidence run identities changed")

    try:
        require_sha("g" * 40, "fixture")
    except ValueError:
        pass
    else:
        raise ValueError("certifier accepted malformed SHA")

    target = API_ROOT + f"repos/{TARGET_REPOSITORY}/branches/main"
    sequence: list[Any] = [
        urllib.error.HTTPError(target, 503, "fixture", {}, None),
        FixtureResponse(target, {"commit": {"sha": auth["baseSha"]}}),
    ]
    sleeps: list[float] = []

    def fixture_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.full_url == target and request.get_method() == "GET",
                "certifier fixture observed wrong request")
        require(timeout == TIMEOUT_SECONDS, "certifier fixture timeout changed")
        item = sequence.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    observed = PublicGitHub(opener=fixture_open, sleeper=sleeps.append).get(
        f"repos/{TARGET_REPOSITORY}/branches/main"
    )
    require(observed == {"commit": {"sha": auth["baseSha"]}},
            "certifier bounded-read fixture result changed")
    require(sleeps == [1.0], "certifier transient retry schedule changed")

    for endpoint in (
        "repos/portyu9/portyu9/branches/main",
        f"repos/{TARGET_REPOSITORY}/../other",
        "https://api.github.com/repos/portyu9/ai-qa-automation/branches/main",
    ):
        try:
            PublicGitHub().get(endpoint)
        except ValueError:
            pass
        else:
            raise ValueError(f"certifier accepted escaped endpoint: {endpoint}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exact ai-qa protected-owner certifier")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    require(args.self_test ^ args.verify_live, "choose exactly one certifier mode")
    if args.self_test:
        self_test()
        print("aiqa owner-protected certifier self-test: ok")
        return 0
    policy = load_manifest()
    result = verify_live(policy, PublicGitHub())
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(payload)
    else:
        require(not args.out.exists() or args.out.is_file(),
                "certifier output path must be a regular file or absent")
        args.out.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
