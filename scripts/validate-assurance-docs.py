#!/usr/bin/env python3
"""Extend frozen assurance documentation checks with item-11 ADR semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import assurance_docs_item10_core as core
import automation_policy

ROOT = Path(__file__).resolve().parents[1]
ADR_DOC = ROOT / ".github" / "AUTOMATION_DECISION_RECEIPTS.md"
ORIGINAL_VALIDATE_DOC_JOB_GRAPH = core.validate_doc_job_graph

SPOTLIGHT_ADR_JOB_IDS = ("decision_receipt", "decision_receipt_attest")
PROFILE_ADR_JOB_IDS = ("decision_receipt", "decision_receipt_attest")
REQUIRED_ADR_PHRASES = (
    "Automation Decision Receipt",
    "automation-decision-receipt-v1.schema.json",
    "append-only",
    "semantic effect",
    "self-attested",
    "recovery",
    "failed receipt signing",
    "generated-publication-receipt-v1.schema.json",
    "workflow dispatch",
    "stale cleanup",
    "candidate publication",
    "approval POST",
    "merge and candidate cleanup",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def workflow_jobs(policy: dict[str, object], path: str) -> dict[str, object]:
    _workflow_id, workflow = automation_policy.workflow_by_path(policy, path)
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), f"Automation Policy IR jobs are malformed for {path}")
    return jobs


def exact_row(scope: str, job: dict[str, object]) -> str:
    name = job.get("name")
    permissions = job.get("permissions")
    require(isinstance(name, str) and isinstance(permissions, dict),
            f"ADR assurance job semantics are malformed: {job!r}")
    rendered = core.permission_markdown(tuple(permissions.items()))
    return f"| {scope} / `{name}` | {rendered} |"


def validate_item11_doc(text: str, policy: dict[str, object]) -> None:
    for phrase in REQUIRED_ADR_PHRASES:
        require(phrase in text, f"ADR assurance supplement is missing current architecture phrase: {phrase}")

    spotlight = workflow_jobs(policy, ".github/workflows/spotlight-link-sync.yml")
    profile = workflow_jobs(policy, ".github/workflows/profile-stats.yml")

    for job_id in SPOTLIGHT_ADR_JOB_IDS:
        job = spotlight.get(job_id)
        require(isinstance(job, dict), f"Spotlight ADR assurance job is missing from policy: {job_id}")
        for scope in ("Spotlight link sync", "Spotlight"):
            prefix = exact_row(scope, job)
            rows = [line for line in text.splitlines() if line.startswith(prefix)]
            require(len(rows) == 1,
                    f"ADR assurance supplement must contain exactly one {scope} authority row for {job.get('name')}")

    for job_id in PROFILE_ADR_JOB_IDS:
        job = profile.get(job_id)
        require(isinstance(job, dict), f"Profile ADR assurance job is missing from policy: {job_id}")
        prefix = exact_row("Profile stats", job)
        rows = [line for line in text.splitlines() if line.startswith(prefix)]
        require(len(rows) == 1,
                f"ADR assurance supplement must contain exactly one Profile stats authority row for {job.get('name')}")


def validate_doc_job_graph_with_item11(
    text: str,
    expected_jobs: dict[str, tuple[str, tuple[tuple[str, str], ...]]],
    *,
    label: str,
    table_scope: str,
) -> None:
    adr = ADR_DOC.read_text(encoding="utf-8")
    ORIGINAL_VALIDATE_DOC_JOB_GRAPH(
        text + "\n" + adr,
        expected_jobs,
        label=label,
        table_scope=table_scope,
    )


def self_test_item11_doc(text: str, policy: dict[str, object]) -> None:
    spotlight = workflow_jobs(policy, ".github/workflows/spotlight-link-sync.yml")
    for job_id in SPOTLIGHT_ADR_JOB_IDS:
        name = spotlight[job_id]["name"]
        altered = "\n".join(
            line for line in text.splitlines()
            if not (line.startswith("| Spotlight link sync / ") and f"`{name}`" in line)
        ) + "\n"
        try:
            validate_item11_doc(altered, policy)
        except ValueError as exc:
            require(str(name) in str(exc), f"ADR assurance self-test failed for wrong reason: {exc}")
        else:
            raise ValueError(f"ADR assurance self-test accepted missing authority row: {name}")


def main() -> int:
    original = core.validate_doc_job_graph
    core.validate_doc_job_graph = validate_doc_job_graph_with_item11
    try:
        require(ADR_DOC.is_file() and not ADR_DOC.is_symlink(),
                "ADR assurance supplement is missing or aliased")
        policy = automation_policy.load_policy()
        text = ADR_DOC.read_text(encoding="utf-8")
        validate_item11_doc(text, policy)
        self_test_item11_doc(text, policy)
        result = core.main()
        if result != 0:
            return result
        print(
            "Item-11 ADR assurance supplement passed: Profile Stats and Spotlight preparer/signer authority rows match Automation Policy IR; "
            "generic semantic-effect receipts, specialized generated-publication receipts, self-attested issuance effects, recovery semantics, "
            "and fail-closed receipt-signing completion are documented without weakening frozen item-10 assurance claims."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        core.validate_doc_job_graph = original


if __name__ == "__main__":
    raise SystemExit(main())
