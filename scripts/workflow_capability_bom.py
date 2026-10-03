#!/usr/bin/env python3
"""Compile the reviewed GitHub Actions workflow subset into a capability BOM.

This module is deliberately descriptive: it derives capabilities from workflow source and
from the canonical Automation Policy IR. It grants no authority and performs no network
access. The workflow source-shape gate owns the YAML subset; this compiler fails closed on
capability-bearing forms outside the subset it understands.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import automation_policy
import workflow_authority_contract_core as authority

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCHEMA_VERSION = 1
BOM_ID = "workflow-capability-bom-v1"
FIRST_PARTY_ACTION_OWNERS = frozenset({"actions", "github"})
MAX_REVIEWED_THIRD_PARTY_AUTHORITY_ACTION_EXCEPTIONS = 2
REVIEWED_THIRD_PARTY_AUTHORITY_ACTION_EXCEPTIONS: frozenset[tuple[str, str, str, str, str]] = frozenset()

ARTIFACT_RETENTION_POLICY_SCHEMA_VERSION = 1
ARTIFACT_RETENTION_POLICY_ID = "artifact-retention-policy-v1"
ARTIFACT_RETENTION_LIMITS = {
    "authority": 1,
    "ephemeral-validation": 1,
    "evidence": 30,
}
MAX_REVIEWED_LONG_LIVED_AUTHORITY_RETENTION_DAYS = 7

AUTHORITY_ARTIFACT_ANTI_REPLAY_MODES = frozenset({
    "same-run-container-bound",
    "cross-run-attested-explicit-ttl",
    "cross-run-current-main-expiry",
})
REVIEWED_AUTHORITY_ARTIFACT_ANTI_REPLAY: dict[tuple[str, str, str], str] = {
    (".github/workflows/action-provenance-witness.yml", "prepare", "Upload unsigned reviewed witness bundle"): "cross-run-attested-explicit-ttl",
    (".github/workflows/codeql-autofix.yml", "controller", "Upload immutable controller provenance receipt"): "cross-run-current-main-expiry",
    (".github/workflows/profile-generator-compatibility-witness.yml", "prepare", "Upload unsigned reviewed compatibility witness bundle"): "cross-run-attested-explicit-ttl",
    (".github/workflows/profile-stats.yml", "attest", "Upload reviewed attestation predicate"): "same-run-container-bound",
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Engineering Spotlight"): "same-run-container-bound",
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Portfolio Evidence Ledger"): "same-run-container-bound",
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Signal Field"): "same-run-container-bound",
    (".github/workflows/profile-stats.yml", "stage", "Upload sealed generated publication candidate"): "same-run-container-bound",
    (".github/workflows/spotlight-link-sync.yml", "authorize", "Upload exact merge authorization artifact"): "same-run-container-bound",
    (".github/workflows/spotlight-link-sync.yml", "plan", "Upload reviewed direct-link proposal"): "same-run-container-bound",
}
REVIEWED_CROSS_RUN_AUTHORITY_DOWNLOADS: dict[tuple[str, str, str], dict[str, Any]] = {
    (".github/workflows/action-provenance-witness.yml", "prepare", "Upload unsigned reviewed witness bundle"): {
        "consumer": (".github/workflows/profile-quality.yml", "validate", "Download exact fresh signed Action provenance witness"),
        "runId": "${{ steps.action_provenance_witness_discovery.outputs.run_id }}",
        "githubToken": "${{ github.token }}",
        "repository": "",
    },
    (".github/workflows/profile-generator-compatibility-witness.yml", "prepare", "Upload unsigned reviewed compatibility witness bundle"): {
        "consumer": (".github/workflows/profile-quality.yml", "integration", "Download exact fresh signed Profile Generator Compatibility Witness"),
        "runId": "${{ steps.profile_generator_witness_discovery.outputs.run_id }}",
        "githubToken": "${{ github.token }}",
        "repository": "",
    },
}
REVIEWED_ARTIFACT_RETENTION_CLASSIFICATIONS: dict[tuple[str, str, str], dict[str, str]] = {
    (".github/workflows/action-provenance-witness.yml", "prepare", "Upload unsigned reviewed witness bundle"): {"classification": "authority", "consumerMode": "cross-run-attested-authority"},
    (".github/workflows/codeql-autofix.yml", "controller", "Upload immutable controller provenance receipt"): {"classification": "authority", "consumerMode": "cross-run-custom-api-authority"},
    (".github/workflows/dependabot-controller.yml", "integration", "Upload exact validation Signal Field"): {"classification": "ephemeral-validation", "consumerMode": "same-job-roundtrip-validation"},
    (".github/workflows/profile-generator-compatibility-witness.yml", "prepare", "Upload unsigned reviewed compatibility witness bundle"): {"classification": "authority", "consumerMode": "cross-run-attested-authority"},
    (".github/workflows/profile-quality.yml", "integration", "Upload Signal Field review artifacts"): {"classification": "ephemeral-validation", "consumerMode": "same-job-roundtrip-validation"},
    (".github/workflows/profile-stats.yml", "attest", "Upload reviewed attestation predicate"): {"classification": "authority", "consumerMode": "same-run-attestation-authority"},
    (".github/workflows/profile-stats.yml", "decision_receipt", "Upload exact Automation Decision Receipt artifact"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Engineering Spotlight"): {"classification": "authority", "consumerMode": "same-run-publication-authority"},
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Portfolio Evidence Ledger"): {"classification": "authority", "consumerMode": "same-run-publication-authority"},
    (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Signal Field"): {"classification": "authority", "consumerMode": "same-run-publication-authority"},
    (".github/workflows/profile-stats.yml", "receipt", "Upload exact post-publication receipt predicate"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/profile-stats.yml", "stage", "Upload sealed generated publication candidate"): {"classification": "authority", "consumerMode": "same-run-publication-authority"},
    (".github/workflows/ruleset-reconciler.yml", "reconcile", "Preserve exact non-secret reconciliation receipt"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/ruleset-reconciler.yml", "recovery_open", "Preserve recovery-open receipt"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/ruleset-reconciler.yml", "recovery_plan", "Preserve immutable recovery candidate evidence"): {"classification": "evidence", "consumerMode": "evidence-preservation-only"},
    (".github/workflows/ruleset-reconciler.yml", "recovery_restore", "Preserve recovery-restoration receipt"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/ruleset-reconciler.yml", "watchdog_restore", "Preserve watchdog-restoration receipt"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/spotlight-link-sync.yml", "authorize", "Upload exact merge authorization artifact"): {"classification": "authority", "consumerMode": "same-run-terminal-merge-authority"},
    (".github/workflows/spotlight-link-sync.yml", "decision_receipt", "Upload exact Automation Decision Receipt artifact"): {"classification": "evidence", "consumerMode": "evidence-attestation-only"},
    (".github/workflows/spotlight-link-sync.yml", "plan", "Upload reviewed direct-link proposal"): {"classification": "authority", "consumerMode": "same-run-proposal-authority"},
}
REVIEWED_LONG_LIVED_AUTHORITY_RETENTION_DAYS: dict[tuple[str, str, str], int] = {
    (".github/workflows/codeql-autofix.yml", "controller", "Upload immutable controller provenance receipt"): 7,
}
REVIEWED_ARTIFACT_DOWNLOAD_BINDINGS: dict[tuple[str, str, str], dict[str, Any]] = {
    (".github/workflows/action-provenance-witness.yml", "attest", "Download exact prepared witness bundle"): {"producer": (".github/workflows/action-provenance-witness.yml", "prepare", "Upload unsigned reviewed witness bundle"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "action-provenance-witness-v1"},
    (".github/workflows/dependabot-controller.yml", "integration", "Download exact validation Signal Field"): {"producer": (".github/workflows/dependabot-controller.yml", "integration", "Upload exact validation Signal Field"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "dependabot-signal-field-${{ needs.validation_bind.outputs.head_sha }}"},
    (".github/workflows/profile-generator-compatibility-witness.yml", "attest", "Download exact prepared compatibility witness bundle"): {"producer": (".github/workflows/profile-generator-compatibility-witness.yml", "prepare", "Upload unsigned reviewed compatibility witness bundle"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "profile-generator-compatibility-witness-v1"},
    (".github/workflows/profile-quality.yml", "integration", "Download exact fresh signed Profile Generator Compatibility Witness"): {"producer": (".github/workflows/profile-generator-compatibility-witness.yml", "prepare", "Upload unsigned reviewed compatibility witness bundle"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "profile-generator-compatibility-witness-v1"},
    (".github/workflows/profile-quality.yml", "integration", "Download Signal Field review artifacts"): {"producer": (".github/workflows/profile-quality.yml", "integration", "Upload Signal Field review artifacts"), "selectorMode": "artifact-id-same-job", "selector": "artifactIds", "selectorValue": "${{ steps.signal_field_review_upload.outputs.artifact-id }}"},
    (".github/workflows/profile-quality.yml", "validate", "Download exact fresh signed Action provenance witness"): {"producer": (".github/workflows/action-provenance-witness.yml", "prepare", "Upload unsigned reviewed witness bundle"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "action-provenance-witness-v1"},
    (".github/workflows/profile-stats.yml", "attest_publish", "Download reviewed attestation predicate"): {"producer": (".github/workflows/profile-stats.yml", "attest", "Upload reviewed attestation predicate"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "profile-evidence-attestation-predicate"},
    (".github/workflows/profile-stats.yml", "attest_publish", "Download validated Engineering Spotlight for terminal attestation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Engineering Spotlight"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "engineering-spotlight-svg"},
    (".github/workflows/profile-stats.yml", "attest_publish", "Download validated Portfolio Evidence Ledger for terminal attestation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Portfolio Evidence Ledger"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "portfolio-evidence-ledger"},
    (".github/workflows/profile-stats.yml", "attest_publish", "Download validated Signal Field for terminal attestation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Signal Field"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "signal-field-svg"},
    (".github/workflows/profile-stats.yml", "attest", "Download validated Engineering Spotlight for attestation preparation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Engineering Spotlight"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "engineering-spotlight-svg"},
    (".github/workflows/profile-stats.yml", "attest", "Download validated Portfolio Evidence Ledger for attestation preparation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Portfolio Evidence Ledger"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "portfolio-evidence-ledger"},
    (".github/workflows/profile-stats.yml", "attest", "Download validated Signal Field for attestation preparation"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Signal Field"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "signal-field-svg"},
    (".github/workflows/profile-stats.yml", "decision_receipt_attest", "Download exact Automation Decision Receipt artifact"): {"producer": (".github/workflows/profile-stats.yml", "decision_receipt", "Upload exact Automation Decision Receipt artifact"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "automation-decision-receipt-profile-${{ github.run_id }}-${{ github.run_attempt }}"},
    (".github/workflows/profile-stats.yml", "publish", "Download sealed generated publication candidate"): {"producer": (".github/workflows/profile-stats.yml", "stage", "Upload sealed generated publication candidate"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "generated-publication-candidate"},
    (".github/workflows/profile-stats.yml", "receipt_attest", "Download exact post-publication receipt predicate"): {"producer": (".github/workflows/profile-stats.yml", "receipt", "Upload exact post-publication receipt predicate"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "generated-publication-receipt-predicate"},
    (".github/workflows/profile-stats.yml", "receipt", "Download reviewed profile evidence predicate for receipt"): {"producer": (".github/workflows/profile-stats.yml", "attest", "Upload reviewed attestation predicate"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "profile-evidence-attestation-predicate"},
    (".github/workflows/profile-stats.yml", "stage", "Download validated Engineering Spotlight for publication staging"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Engineering Spotlight"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "engineering-spotlight-svg"},
    (".github/workflows/profile-stats.yml", "stage", "Download validated Portfolio Evidence Ledger for publication staging"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Portfolio Evidence Ledger"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "portfolio-evidence-ledger"},
    (".github/workflows/profile-stats.yml", "stage", "Download validated Signal Field for publication staging"): {"producer": (".github/workflows/profile-stats.yml", "generate", "Upload immutable validated Signal Field"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "signal-field-svg"},
    (".github/workflows/ruleset-reconciler.yml", "attest", "Download exact reconciliation receipt"): {"producer": (".github/workflows/ruleset-reconciler.yml", "reconcile", "Preserve exact non-secret reconciliation receipt"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "ruleset-reconciliation-receipt"},
    (".github/workflows/ruleset-reconciler.yml", "recovery_attest", "Download exact recovery-open receipt"): {"producer": (".github/workflows/ruleset-reconciler.yml", "recovery_open", "Preserve recovery-open receipt"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "control-plane-recovery-open-receipt"},
    (".github/workflows/ruleset-reconciler.yml", "recovery_attest", "Download exact recovery-restoration receipt"): {"producer": (".github/workflows/ruleset-reconciler.yml", "recovery_restore", "Preserve recovery-restoration receipt"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "control-plane-recovery-restore-receipt"},
    (".github/workflows/ruleset-reconciler.yml", "watchdog_attest", "Download watchdog restoration receipt"): {"producer": (".github/workflows/ruleset-reconciler.yml", "watchdog_restore", "Preserve watchdog-restoration receipt"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "control-plane-recovery-watchdog-receipt"},
    (".github/workflows/spotlight-link-sync.yml", "authorize_attest", "Download exact merge authorization artifact"): {"producer": (".github/workflows/spotlight-link-sync.yml", "authorize", "Upload exact merge authorization artifact"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}"},
    (".github/workflows/spotlight-link-sync.yml", "decision_receipt_attest", "Download exact Automation Decision Receipt artifact"): {"producer": (".github/workflows/spotlight-link-sync.yml", "decision_receipt", "Upload exact Automation Decision Receipt artifact"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "automation-decision-receipt-spotlight-${{ github.run_id }}-${{ github.run_attempt }}"},
    (".github/workflows/spotlight-link-sync.yml", "merge", "Download attested merge authorization artifact"): {"producer": (".github/workflows/spotlight-link-sync.yml", "authorize", "Upload exact merge authorization artifact"), "selectorMode": "name-exact", "selector": "name", "selectorValue": "spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}"},
    (".github/workflows/spotlight-link-sync.yml", "propose", "Download reviewed direct-link proposal"): {"producer": (".github/workflows/spotlight-link-sync.yml", "plan", "Upload reviewed direct-link proposal"), "selectorMode": "reviewed-name-rebind", "selector": "name", "selectorValue": "spotlight-link-plan-${{ needs.plan.outputs.base_sha }}-${{ needs.plan.outputs.generated_sha }}"},
}
REMOTE_ACTION = re.compile(
    r"^(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<subpath>/[^@]+)?@(?P<ref>[0-9a-f]{40})$"
)
JOB_KEY = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+):\s*$")
STEP_KEY = re.compile(r"^      - name:\s*(?P<name>.+?)\s*$")
USES_KEY = re.compile(r"^        uses:\s*(?P<uses>\S+)\s*(?:#.*)?$")
RUN_BLOCK = re.compile(r"^        run:\s*[|>]\s*$")
WITH_BLOCK = re.compile(r"^        with:\s*$")
WITH_ENTRY = re.compile(r"^          (?P<key>[A-Za-z0-9_.-]+):\s*(?P<value>.*?)\s*$")
BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?[1-9]?|[1-9][+-]?)?$")
TOP_NAME = re.compile(r"^name:\s*(?P<name>.+?)\s*$", re.M)
EXPR_REF = re.compile(r"\b(?P<scope>secrets|vars|env)\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
GITHUB_TOKEN = re.compile(r"\bgithub\.token\b")
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_NETWORK = re.compile(r"(^|[;&|()\s])(curl|wget)(?:\s|$)")
GH_API_VALUE_OPTIONS = {
    "-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field",
    "--input", "--jq", "-q", "--cache", "--hostname", "--preview",
}
GH_API_FLAG_OPTIONS = {"-i", "--include", "--paginate", "--slurp", "--silent", "--verbose"}
GRAPHQL_QUERY_FIELD = re.compile(
    r"(?:^|\s)(?:-f|--raw-field|-F|--field)\s+query=(?:'|\")?(?P<operation>query|mutation)\b"
)
SHELL_CONTROL = {"|", "||", "&&", ";"}
GIT_GLOBAL_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
GIT_NETWORK_OPERATIONS = {"push", "fetch", "clone", "ls-remote"}
GIT_OPERATION_FLAG_OPTIONS = {
    "push": {
        "-f", "--force", "--force-with-lease", "--atomic", "--dry-run", "--porcelain",
        "-q", "--quiet", "-v", "--verbose", "--follow-tags", "--no-verify",
    },
    "fetch": {
        "-f", "--force", "-k", "--keep", "-p", "--prune", "--prune-tags", "--tags",
        "--no-tags", "--dry-run", "-q", "--quiet", "-v", "--verbose",
    },
    "clone": {
        "--bare", "--mirror", "--single-branch", "--no-single-branch", "--no-tags",
        "--recurse-submodules", "-q", "--quiet", "-v", "--verbose",
    },
    "ls-remote": {"--exit-code", "--heads", "--tags", "--refs", "-q", "--quiet"},
}
GIT_OPERATION_VALUE_OPTIONS = {
    "push": {"--repo"},
    "fetch": {"--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--refmap", "--upload-pack"},
    "clone": {"-b", "--branch", "-o", "--origin", "--depth", "--reference", "--separate-git-dir"},
    "ls-remote": {"--sort", "--upload-pack"},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def shell_tokens(value: str) -> list[str]:
    return re.findall(r"(?:'[^']*'|\"[^\"]*\"|\S+)", value)


def workflow_sources(policy: dict[str, Any]) -> list[tuple[str, str, Path]]:
    specs: list[tuple[str, str, Path]] = []
    for workflow_id, workflow in policy["workflows"].items():
        relative = workflow["path"]
        require(isinstance(relative, str), f"workflow path is malformed: {workflow_id}")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"workflow source is missing or aliased: {relative}")
        specs.append((relative, workflow_id, path))
    specs.sort()
    observed = sorted(
        path.relative_to(ROOT).as_posix()
        for path in {*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")}
    )
    expected = [relative for relative, _, _ in specs]
    require(observed == expected,
            f"workflow capability BOM inventory changed: expected={expected} observed={observed}")
    return specs


def parse_trigger_details(text: str, label: str) -> dict[str, Any]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "on:"]
    require(len(starts) == 1, f"{label}: expected one mapping-style on block")
    result: dict[str, Any] = {}
    current_event: str | None = None
    current_key: str | None = None
    current_dispatch_input: str | None = None
    for line_number, line in enumerate(lines[starts[0] + 1:], start=starts[0] + 2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = indentation(line)
        if indent == 0:
            break
        if indent == 2:
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
            require(match is not None, f"{label}:{line_number}: unsupported trigger event syntax")
            current_event = match.group(1)
            require(current_event not in result, f"{label}:{line_number}: duplicate trigger event")
            result[current_event] = {}
            current_key = None
            current_dispatch_input = None
            continue
        require(current_event is not None, f"{label}:{line_number}: trigger detail precedes event")
        if indent == 4:
            cron = re.fullmatch(r"    - cron:\s*(.+?)\s*", line)
            if cron:
                require(current_event == "schedule", f"{label}:{line_number}: cron outside schedule")
                result[current_event].setdefault("cron", []).append(unquote(cron.group(1)))
                current_key = None
                continue
            mapping = re.fullmatch(r"    ([A-Za-z0-9_-]+):\s*(.*?)\s*", line)
            require(mapping is not None, f"{label}:{line_number}: unsupported trigger mapping")
            current_key, scalar = mapping.groups()
            require(current_key not in result[current_event],
                    f"{label}:{line_number}: duplicate trigger key: {current_event}.{current_key}")
            current_dispatch_input = None
            if scalar:
                result[current_event][current_key] = unquote(scalar)
                current_key = None
            elif current_event == "workflow_dispatch" and current_key == "inputs":
                result[current_event][current_key] = {}
            else:
                result[current_event][current_key] = []
            continue
        if indent == 6:
            if current_event == "workflow_dispatch" and current_key == "inputs":
                declared = re.fullmatch(r"      ([A-Za-z0-9_-]+):\s*", line)
                require(declared is not None,
                        f"{label}:{line_number}: unsupported workflow_dispatch input syntax")
                inputs = result[current_event][current_key]
                require(isinstance(inputs, dict),
                        f"{label}:{line_number}: workflow_dispatch inputs parent is not a mapping")
                current_dispatch_input = declared.group(1)
                require(current_dispatch_input not in inputs,
                        f"{label}:{line_number}: duplicate workflow_dispatch input: {current_dispatch_input}")
                inputs[current_dispatch_input] = {}
                continue
            item = re.fullmatch(r"      -\s+(.+?)\s*", line)
            require(item is not None and current_key is not None,
                    f"{label}:{line_number}: unsupported trigger list syntax")
            value = result[current_event][current_key]
            require(isinstance(value, list), f"{label}:{line_number}: trigger list parent is not a list")
            value.append(unquote(item.group(1)))
            continue
        if indent == 8:
            require(
                current_event == "workflow_dispatch"
                and current_key == "inputs"
                and current_dispatch_input is not None,
                f"{label}:{line_number}: trigger input detail precedes workflow_dispatch input",
            )
            detail = re.fullmatch(r"        ([A-Za-z0-9_-]+):\s*(.+?)\s*", line)
            require(detail is not None,
                    f"{label}:{line_number}: unsupported workflow_dispatch input detail syntax")
            detail_key, detail_value = detail.groups()
            require(detail_key in {"description", "required", "type", "default"},
                    f"{label}:{line_number}: unsupported workflow_dispatch input detail: {detail_key}")
            input_spec = result[current_event][current_key][current_dispatch_input]
            require(detail_key not in input_spec,
                    f"{label}:{line_number}: duplicate workflow_dispatch input detail: {detail_key}")
            input_spec[detail_key] = unquote(detail_value)
            continue
        raise ValueError(f"{label}:{line_number}: unsupported trigger capability syntax")
    require(result, f"{label}: empty trigger detail set")
    return {key: result[key] for key in sorted(result)}


def effective_permissions(
    permissions: dict[str, dict[str, str]], jobs: list[str], label: str
) -> dict[str, dict[str, str]]:
    workflow_permissions = permissions.get(authority.WORKFLOW_SCOPE)
    require(workflow_permissions is not None, f"{label}: workflow-level permissions are required")
    result: dict[str, dict[str, str]] = {}
    for job in jobs:
        selected = permissions.get(job, workflow_permissions)
        result[job] = {key: selected[key] for key in sorted(selected)}
    return result


def parse_with_values(
    lines: list[str], start: int, *, workflow: str, job: str, step: str
) -> dict[str, str]:
    values: dict[str, str] = {}
    cursor = start
    while cursor < len(lines):
        line = lines[cursor]
        if line.strip() and indentation(line) <= 8:
            break
        if not line.strip():
            cursor += 1
            continue
        entry = WITH_ENTRY.fullmatch(line)
        require(entry is not None,
                f"{workflow}/{job}/{step}: unsupported with syntax: {line.strip()}")
        key = entry.group("key")
        require(key not in values, f"{workflow}/{job}/{step}: duplicate with key: {key}")
        raw = entry.group("value")
        if BLOCK_SCALAR.fullmatch(raw):
            style = raw[0]
            cursor += 1
            payload: list[str] = []
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and indentation(candidate) <= 10:
                    break
                if not candidate.strip():
                    payload.append("")
                    cursor += 1
                    continue
                require(indentation(candidate) >= 12,
                        f"{workflow}/{job}/{step}: malformed with block scalar for {key}")
                payload.append(candidate[12:])
                cursor += 1
            while payload and payload[-1] == "":
                payload.pop()
            values[key] = ("\n" if style == "|" else " ").join(payload)
            continue
        values[key] = unquote(raw)
        cursor += 1
    return values


def normalize_shell_command(lines: list[str], start: int) -> tuple[str, int]:
    parts: list[str] = []
    index = start
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            break
        continuation = stripped.endswith("\\")
        if continuation:
            stripped = stripped[:-1].rstrip()
        parts.append(stripped)
        index += 1
        if not continuation:
            break
    return " ".join(parts), index


def api_surface(command: str, *, workflow: str, job: str, step: str) -> dict[str, Any]:
    position = command.find("gh api ")
    require(position >= 0, "internal gh api parser misuse")
    fragment = command[position + len("gh api "):]
    tokens = shell_tokens(fragment)
    method = "GET"
    endpoint: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if endpoint is not None and (
            token in SHELL_CONTROL or re.match(r"^\d*[<>]", token) is not None
        ):
            break
        if token in {"-X", "--method"}:
            require(index + 1 < len(tokens), f"{workflow}/{job}/{step}: gh api method value is missing")
            method = unquote(tokens[index + 1]).upper().rstrip(")\"")
            require(method in {"GET", "POST", "PUT", "PATCH", "DELETE"},
                    f"{workflow}/{job}/{step}: unsupported gh api method: {method}")
            index += 2
            continue
        if token.startswith("--method="):
            method = unquote(token.split("=", 1)[1]).upper().rstrip(")\"")
            require(method in {"GET", "POST", "PUT", "PATCH", "DELETE"},
                    f"{workflow}/{job}/{step}: unsupported gh api method: {method}")
            index += 1
            continue
        if token in GH_API_VALUE_OPTIONS:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: gh api option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in GH_API_VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if token in GH_API_FLAG_OPTIONS:
            index += 1
            continue
        require(not token.startswith("-"),
                f"{workflow}/{job}/{step}: unclassified gh api option: {token}")
        if endpoint is None:
            endpoint = unquote(token).rstrip(")\"")
        index += 1
    require(endpoint is not None and endpoint,
            f"{workflow}/{job}/{step}: gh api endpoint is not statically visible")

    if endpoint == "graphql":
        require(method in {"GET", "POST"},
                f"{workflow}/{job}/{step}: GraphQL transport method must be POST/default")
        operations = [match.group("operation") for match in GRAPHQL_QUERY_FIELD.finditer(fragment)]
        require(len(operations) == 1,
                f"{workflow}/{job}/{step}: GraphQL query operation must be statically visible exactly once")
        operation = operations[0]
        return {
            "client": "gh-api",
            "endpoint": endpoint,
            "graphqlOperation": operation,
            "method": "POST",
            "mutating": operation == "mutation",
        }

    return {
        "client": "gh-api",
        "endpoint": endpoint,
        "method": method,
        "mutating": method in MUTATING_METHODS,
    }


def mutation_class(surface: dict[str, Any]) -> str:
    endpoint = surface["endpoint"]
    method = surface["method"]
    if endpoint == "graphql":
        require(surface.get("graphqlOperation") == "mutation", "non-mutating GraphQL surface reached mutation classifier")
        return "graphql-mutation"
    if "/actions/workflows/" in endpoint and "/dispatches" in endpoint:
        return "workflow-dispatch"
    if "/actions/runs/" in endpoint and endpoint.rstrip("/").endswith("/approve"):
        return "workflow-run-approval"
    if "/git/refs" in endpoint:
        return "git-ref"
    if "/pulls" in endpoint and endpoint.rstrip("/").endswith("/merge"):
        return "pull-request-merge"
    if "/pulls" in endpoint:
        return "pull-request"
    if "/issues" in endpoint:
        return "issue-or-pr-metadata"
    return f"github-api-{method.lower()}"


def git_surface(command: str, *, workflow: str, job: str, step: str) -> dict[str, Any] | None:
    position = command.find("git ")
    if position < 0:
        return None
    tokens = shell_tokens(command[position + len("git "):])
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_GLOBAL_VALUE_OPTIONS:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: git global option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in GIT_GLOBAL_VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if token.startswith("-"):
            return None
        operation = token.rstrip(")\"")
        break
    else:
        return None
    if operation not in GIT_NETWORK_OPERATIONS:
        return None

    flag_options = GIT_OPERATION_FLAG_OPTIONS[operation]
    value_options = GIT_OPERATION_VALUE_OPTIONS[operation]
    positional: list[str] = []
    index += 1
    while index < len(tokens):
        token = unquote(tokens[index]).rstrip(")\"")
        if token in SHELL_CONTROL or re.match(r"^\d*[<>]", token) is not None:
            break
        if token in flag_options:
            index += 1
            continue
        if token in value_options:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: git {operation} option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in value_options if option.startswith("--")):
            index += 1
            continue
        require(not token.startswith("-"),
                f"{workflow}/{job}/{step}: unclassified git {operation} option: {token}")
        positional.append(token)
        index += 1

    require(positional, f"{workflow}/{job}/{step}: git {operation} remote is not statically visible")
    surface: dict[str, Any] = {
        "client": "git",
        "operation": operation,
        "mutating": operation == "push",
        "remote": positional[0],
    }
    if len(positional) > 1:
        surface["targets"] = positional[1:]
    return surface


def job_blocks(text: str, jobs: list[str], label: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    jobs_roots = [index for index, line in enumerate(lines) if line.rstrip("\n") == "jobs:"]
    require(len(jobs_roots) == 1, f"{label}: workflow must contain exactly one jobs block")
    starts: list[tuple[int, str]] = []
    for index in range(jobs_roots[0] + 1, len(lines)):
        line = lines[index]
        if line.strip() and indentation(line) == 0:
            break
        match = JOB_KEY.fullmatch(line.rstrip("\n"))
        if match:
            starts.append((index, match.group("job")))
    observed = [job for _, job in starts]
    require(set(observed) == set(jobs) and len(observed) == len(jobs),
            f"{label}: job block inventory changed: expected={sorted(jobs)} observed={observed}")
    blocks: dict[str, str] = {}
    for offset, (start, job) in enumerate(starts):
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        blocks[job] = "".join(lines[start:end])
    return blocks


def expression_references(text: str) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {"secrets": set(), "vars": set(), "env": set(), "githubToken": set()}
    for match in EXPR_REF.finditer(text):
        result[match.group("scope")].add(match.group("name"))
    if GITHUB_TOKEN.search(text):
        result["githubToken"].add("github.token")
    return {key: sorted(values) for key, values in result.items()}


def validate_job_authority(filename: str, entry: dict[str, Any]) -> None:
    for action in entry["actions"]:
        if action.get("repository") in {"actions/attest", "actions/attest-build-provenance"}:
            require(entry["oidc"] and entry["permissions"].get("attestations") == "write",
                    f"{filename}/{entry['id']}: attestation action lacks exact OIDC/attestations write authority")
    write_permissions = sorted(
        permission for permission, level in entry["permissions"].items() if level == "write"
    )
    if write_permissions:
        require(entry["mutations"],
                f"{filename}/{entry['id']}: write permissions lack a classified mutation: {write_permissions}")


def job_is_authority_bearing(entry: dict[str, Any]) -> bool:
    permissions = entry.get("permissions")
    references = entry.get("references")
    require(isinstance(permissions, dict), f"{entry.get('id', '<unknown>')}: permissions are malformed")
    require(isinstance(references, dict), f"{entry.get('id', '<unknown>')}: references are malformed")
    secrets = references.get("secrets")
    require(isinstance(secrets, list), f"{entry.get('id', '<unknown>')}: secret references are malformed")
    return (
        any(level == "write" for level in permissions.values())
        or entry.get("oidc") is True
        or bool(entry.get("mutations"))
        or bool(secrets)
    )


def validate_authority_action_origins(
    workflows: list[dict[str, Any]],
    reviewed_exceptions: frozenset[tuple[str, str, str, str, str]] = REVIEWED_THIRD_PARTY_AUTHORITY_ACTION_EXCEPTIONS,
) -> None:
    require(
        len(reviewed_exceptions) <= MAX_REVIEWED_THIRD_PARTY_AUTHORITY_ACTION_EXCEPTIONS,
        "too many reviewed third-party authority Action exceptions",
    )
    for exception in reviewed_exceptions:
        require(
            isinstance(exception, tuple) and len(exception) == 5,
            f"malformed reviewed third-party authority Action exception: {exception!r}",
        )
        workflow_path, job_id, repository, action_path, action_ref = exception
        require(
            all(isinstance(value, str) for value in exception)
            and bool(workflow_path)
            and bool(job_id)
            and repository.count("/") == 1
            and all(repository.split("/", 1))
            and not action_path.startswith("/")
            and re.fullmatch(r"[0-9a-f]{40}", action_ref) is not None,
            f"malformed reviewed third-party authority Action exception: {exception!r}",
        )

    observed: set[tuple[str, str, str, str, str]] = set()
    for workflow in workflows:
        workflow_path = workflow.get("path")
        jobs = workflow.get("jobs")
        require(isinstance(workflow_path, str) and workflow_path, "workflow path is malformed")
        require(isinstance(jobs, list), f"{workflow_path}: workflow jobs are malformed")
        for job in jobs:
            require(isinstance(job, dict), f"{workflow_path}: workflow job is malformed")
            if not job_is_authority_bearing(job):
                continue
            job_id = job.get("id")
            actions = job.get("actions")
            require(isinstance(job_id, str) and job_id, f"{workflow_path}: job identity is malformed")
            require(isinstance(actions, list), f"{workflow_path}/{job_id}: actions are malformed")
            for action in actions:
                require(isinstance(action, dict), f"{workflow_path}/{job_id}: action is malformed")
                if action.get("kind") != "remote":
                    continue
                repository = action.get("repository")
                require(
                    isinstance(repository, str)
                    and repository.count("/") == 1
                    and all(repository.split("/", 1)),
                    f"{workflow_path}/{job_id}: remote Action repository is malformed: {repository!r}",
                )
                action_path = action.get("path")
                action_ref = action.get("ref")
                require(
                    isinstance(action_path, str) and not action_path.startswith("/"),
                    f"{workflow_path}/{job_id}: remote Action path is malformed: {action_path!r}",
                )
                require(
                    isinstance(action_ref, str) and re.fullmatch(r"[0-9a-f]{40}", action_ref) is not None,
                    f"{workflow_path}/{job_id}: remote Action ref is malformed: {action_ref!r}",
                )
                owner = repository.split("/", 1)[0]
                if owner not in FIRST_PARTY_ACTION_OWNERS:
                    observed.add((workflow_path, job_id, repository, action_path, action_ref))

    unexpected = sorted(observed - reviewed_exceptions)
    stale = sorted(reviewed_exceptions - observed)
    require(
        not unexpected,
        f"unreviewed third-party Action entered authority-bearing job: {unexpected}",
    )
    require(
        not stale,
        f"reviewed third-party authority Action exception is stale: {stale}",
    )


def compile_steps(text: str, workflow: str, jobs: list[str]) -> dict[str, dict[str, Any]]:
    lines = text.splitlines()
    compiled: dict[str, dict[str, Any]] = {
        job: {"actions": [], "apiSurfaces": [], "artifacts": [], "mutations": []} for job in jobs
    }
    current_job: str | None = None
    current_step = ""
    in_jobs = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "jobs:":
            in_jobs = True
            current_job = None
            index += 1
            continue
        if in_jobs and line.strip() and indentation(line) == 0:
            break
        if not in_jobs:
            index += 1
            continue
        job_match = JOB_KEY.fullmatch(line)
        if job_match:
            current_job = job_match.group("job")
            current_step = ""
            index += 1
            continue
        if current_job is None:
            index += 1
            continue
        step_match = STEP_KEY.fullmatch(line)
        if step_match:
            current_step = unquote(step_match.group("name"))
            index += 1
            continue
        uses_match = USES_KEY.fullmatch(line)
        if uses_match:
            require(current_step, f"{workflow}/{current_job}: uses step has no explicit name")
            uses = uses_match.group("uses")
            with_values: dict[str, str] = {}
            cursor = index + 1
            while cursor < len(lines):
                if WITH_BLOCK.fullmatch(lines[cursor]):
                    with_values = parse_with_values(
                        lines, cursor + 1, workflow=workflow, job=current_job, step=current_step
                    )
                    break
                if lines[cursor].strip() and indentation(lines[cursor]) <= 8:
                    break
                cursor += 1

            remote = REMOTE_ACTION.fullmatch(uses)
            if remote:
                action: dict[str, Any] = {
                    "kind": "remote",
                    "repository": remote.group("repository"),
                    "path": (remote.group("subpath") or "").lstrip("/"),
                    "ref": remote.group("ref"),
                    "step": current_step,
                }
            elif uses.startswith("./"):
                require("@" not in uses, f"{workflow}/{current_job}/{current_step}: malformed local action")
                action = {"kind": "local", "path": uses, "step": current_step}
            else:
                raise ValueError(
                    f"{workflow}/{current_job}/{current_step}: external action is not immutable: {uses}"
                )
            compiled[current_job]["actions"].append(action)

            repository = action.get("repository")
            if repository in {"actions/upload-artifact", "actions/download-artifact"}:
                operation = "upload" if repository == "actions/upload-artifact" else "download"
                artifact: dict[str, Any] = {
                    "operation": operation,
                    "step": current_step,
                }
                name = with_values.get("name", "")
                artifact_ids = with_values.get("artifact-ids", "")
                if operation == "upload":
                    require(name,
                            f"{workflow}/{current_job}/{current_step}: artifact upload must name its artifact")
                    artifact["name"] = name
                else:
                    require(bool(name) != bool(artifact_ids),
                            f"{workflow}/{current_job}/{current_step}: artifact download must select exactly one name or artifact-ids")
                    if name:
                        artifact["name"] = name
                    else:
                        artifact["artifactIds"] = artifact_ids
                if operation == "download":
                    for source_key, compiled_key in (
                        ("repository", "repository"),
                        ("run-id", "runId"),
                        ("github-token", "githubToken"),
                    ):
                        if source_key in with_values:
                            artifact[compiled_key] = with_values[source_key]
                    require(
                        ("runId" in artifact) == ("githubToken" in artifact),
                        f"{workflow}/{current_job}/{current_step}: cross-run artifact download must provide both run-id and github-token",
                    )
                for key in ("path", "retention-days", "if-no-files-found", "digest-mismatch"):
                    if key in with_values:
                        artifact[key] = with_values[key]
                require(artifact.get("path"),
                        f"{workflow}/{current_job}/{current_step}: artifact action must expose its path")
                compiled[current_job]["artifacts"].append(artifact)
            if repository in {"actions/attest", "actions/attest-build-provenance"}:
                target = with_values.get("subject-path") or with_values.get("subject-digest")
                require(target,
                        f"{workflow}/{current_job}/{current_step}: attestation subject is not statically visible")
                compiled[current_job]["mutations"].append({
                    "class": "attestation",
                    "step": current_step,
                    "target": target,
                })
            if repository == "github/codeql-action" and action.get("path") == "analyze":
                compiled[current_job]["mutations"].append({
                    "class": "code-scanning-results-upload",
                    "step": current_step,
                    "target": "repository-code-scanning",
                })
            index += 1
            continue

        if RUN_BLOCK.fullmatch(line):
            require(current_step, f"{workflow}/{current_job}: run step has no explicit name")
            block: list[str] = []
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and indentation(candidate) <= 8:
                    break
                block.append(candidate[10:] if candidate.startswith("          ") else candidate.lstrip())
                cursor += 1
            shell_index = 0
            while shell_index < len(block):
                shell_line = block[shell_index]
                require(FORBIDDEN_NETWORK.search(shell_line) is None,
                        f"{workflow}/{current_job}/{current_step}: unclassified network client: {shell_line.strip()}")
                if "gh api " in shell_line:
                    command, next_index = normalize_shell_command(block, shell_index)
                    surface = api_surface(command, workflow=workflow, job=current_job, step=current_step)
                    surface["step"] = current_step
                    compiled[current_job]["apiSurfaces"].append(surface)
                    if surface["mutating"]:
                        compiled[current_job]["mutations"].append({
                            "class": mutation_class(surface),
                            "step": current_step,
                            "target": surface["endpoint"],
                            "method": surface["method"],
                        })
                    shell_index = next_index
                    continue
                git = git_surface(shell_line, workflow=workflow, job=current_job, step=current_step)
                if git is not None:
                    git["step"] = current_step
                    compiled[current_job]["apiSurfaces"].append(git)
                    if git["mutating"]:
                        remote = git.get("remote", "")
                        targets = git.get("targets", [])
                        require(remote and targets,
                                f"{workflow}/{current_job}/{current_step}: git push target is not statically visible")
                        compiled[current_job]["mutations"].append({
                            "class": "git-ref-push",
                            "step": current_step,
                            "target": f"{remote} {' '.join(targets)}",
                        })
                shell_index += 1
            index = cursor
            continue
        index += 1

    for job in jobs:
        for key in ("actions", "apiSurfaces", "artifacts", "mutations"):
            compiled[job][key].sort(key=lambda value: canonical_json(value))
    return compiled



def artifact_identity(workflow: str, job: str, step: str) -> tuple[str, str, str]:
    return (workflow, job, step)


def _compile_artifact_retention_policy(
    workflows: list[dict[str, Any]],
    repository: str,
    *,
    classifications: dict[tuple[str, str, str], dict[str, str]] | None = None,
    long_lived_authority: dict[tuple[str, str, str], int] | None = None,
    download_bindings: dict[tuple[str, str, str], dict[str, Any]] | None = None,
    anti_replay: dict[tuple[str, str, str], str] | None = None,
    cross_run_downloads: dict[tuple[str, str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    reviewed = classifications if classifications is not None else REVIEWED_ARTIFACT_RETENTION_CLASSIFICATIONS
    long_lived = (
        long_lived_authority
        if long_lived_authority is not None
        else REVIEWED_LONG_LIVED_AUTHORITY_RETENTION_DAYS
    )
    bindings = download_bindings if download_bindings is not None else REVIEWED_ARTIFACT_DOWNLOAD_BINDINGS
    anti_replay_modes = (
        anti_replay
        if anti_replay is not None
        else REVIEWED_AUTHORITY_ARTIFACT_ANTI_REPLAY
    )
    cross_run_specs = (
        cross_run_downloads
        if cross_run_downloads is not None
        else REVIEWED_CROSS_RUN_AUTHORITY_DOWNLOADS
    )
    require(len(long_lived) <= 1, "reviewed long-lived authority artifact exception budget exceeded")

    producer_lookup: dict[tuple[str, str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    download_lookup: dict[tuple[str, str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for workflow in workflows:
        workflow_path = workflow["path"]
        for job in workflow["jobs"]:
            for artifact in job["artifacts"]:
                identity = artifact_identity(workflow_path, job["id"], artifact["step"])
                if artifact["operation"] == "upload":
                    require(identity not in producer_lookup, f"duplicate artifact upload producer identity: {identity}")
                    producer_lookup[identity] = (job, artifact)
                elif artifact["operation"] == "download":
                    require(identity not in download_lookup, f"duplicate artifact download consumer identity: {identity}")
                    download_lookup[identity] = (job, artifact)
                else:
                    raise ValueError(f"unclassified artifact operation: {artifact['operation']}")

    observed_producers = set(producer_lookup)
    reviewed_producers = set(reviewed)
    require(
        observed_producers <= reviewed_producers,
        f"unclassified artifact upload producer entered repository: {sorted(observed_producers - reviewed_producers)}",
    )
    require(
        reviewed_producers <= observed_producers,
        f"reviewed artifact upload producer is stale or missing: {sorted(reviewed_producers - observed_producers)}",
    )
    observed_downloads = set(download_lookup)
    reviewed_downloads = set(bindings)
    require(
        observed_downloads <= reviewed_downloads,
        f"unclassified artifact download consumer entered repository: {sorted(observed_downloads - reviewed_downloads)}",
    )
    require(
        reviewed_downloads <= observed_downloads,
        f"reviewed artifact download consumer is stale or missing: {sorted(reviewed_downloads - observed_downloads)}",
    )

    consumers_by_producer: dict[tuple[str, str, str], list[dict[str, str]]] = {
        identity: [] for identity in producer_lookup
    }
    for consumer_identity in sorted(download_lookup):
        consumer_job, consumer = download_lookup[consumer_identity]
        binding = bindings[consumer_identity]
        require(set(binding) == {"producer", "selectorMode", "selector", "selectorValue"},
                f"artifact download binding shape changed: {consumer_identity}")
        producer_identity = tuple(binding["producer"])
        require(
            len(producer_identity) == 3 and producer_identity in producer_lookup,
            f"artifact download binding names an unknown producer: {consumer_identity}",
        )
        _, producer = producer_lookup[producer_identity]
        selector = binding["selector"]
        require(selector in {"name", "artifactIds"}, f"artifact download binding selector changed: {consumer_identity}")
        observed_selector = consumer.get(selector)
        require(
            isinstance(observed_selector, str) and observed_selector == binding["selectorValue"],
            f"artifact download selector drifted: {consumer_identity}",
        )
        selector_mode = binding["selectorMode"]
        if selector_mode == "name-exact":
            require(selector == "name" and observed_selector == producer.get("name"),
                    f"artifact exact-name binding drifted: {consumer_identity}")
        elif selector_mode == "artifact-id-same-job":
            require(selector == "artifactIds", f"artifact-id binding selector drifted: {consumer_identity}")
            require(
                consumer_identity[:2] == producer_identity[:2],
                f"artifact-id binding escaped producer job: {consumer_identity}",
            )
        elif selector_mode == "reviewed-name-rebind":
            require(selector == "name" and observed_selector != producer.get("name"),
                    f"reviewed artifact expression-rebind boundary changed: {consumer_identity}")
        else:
            raise ValueError(f"unclassified artifact download selector mode: {selector_mode}")

        producer_class = reviewed[producer_identity]["classification"]
        write_permissions = {
            name for name, level in consumer_job["permissions"].items() if level == "write"
        }
        mutations = consumer_job["mutations"]
        secret_refs = consumer_job["references"]["secrets"]
        if producer_class == "ephemeral-validation":
            require(
                consumer_identity[:2] == producer_identity[:2]
                and not write_permissions
                and not mutations
                and consumer_job["oidc"] is False
                and not secret_refs,
                f"ephemeral validation artifact escaped its read-only producer job: {consumer_identity}",
            )
        elif producer_class == "evidence":
            if mutations:
                require(
                    all(mutation["class"] == "attestation" for mutation in mutations)
                    and write_permissions <= {"attestations", "id-token"}
                    and consumer_job["oidc"] is True
                    and not secret_refs,
                    f"evidence artifact entered non-attestation mutation authority: {consumer_identity}",
                )
            else:
                require(
                    not write_permissions and consumer_job["oidc"] is False and not secret_refs,
                    f"evidence artifact entered non-read-only authority: {consumer_identity}",
                )

        consumers_by_producer[producer_identity].append({
            "workflow": consumer_identity[0],
            "job": consumer_identity[1],
            "step": consumer_identity[2],
            "selectorMode": selector_mode,
            "selector": selector,
            "selectorValue": observed_selector,
            "runId": consumer.get("runId", ""),
            "githubToken": consumer.get("githubToken", ""),
            "repository": consumer.get("repository", ""),
        })

    entries: list[dict[str, Any]] = []
    for identity in sorted(producer_lookup):
        _, artifact = producer_lookup[identity]
        spec = reviewed[identity]
        require(set(spec) == {"classification", "consumerMode"},
                f"artifact retention classification shape changed: {identity}")
        classification = spec["classification"]
        require(classification in ARTIFACT_RETENTION_LIMITS,
                f"artifact retention classification is invalid: {identity}")
        retention = artifact.get("retention-days")
        require(
            isinstance(retention, str) and re.fullmatch(r"[1-9][0-9]*", retention) is not None,
            f"artifact upload retention must be a literal positive day count: {identity}",
        )
        retention_days = int(retention)
        require(
            artifact.get("if-no-files-found") == "error",
            f"artifact upload must fail closed when payload is missing: {identity}",
        )
        default_max = ARTIFACT_RETENTION_LIMITS[classification]
        max_retention_days = long_lived.get(identity, default_max)
        if identity in long_lived:
            require(
                classification == "authority"
                and default_max < max_retention_days <= MAX_REVIEWED_LONG_LIVED_AUTHORITY_RETENTION_DAYS,
                f"reviewed long-lived authority artifact exception is invalid: {identity}",
            )
        else:
            require(max_retention_days == default_max,
                    f"artifact retention maximum drifted from class default: {identity}")
        require(
            retention_days <= max_retention_days,
            f"artifact retention exceeds reviewed class maximum: {identity}",
        )

        consumers = sorted(consumers_by_producer[identity], key=lambda value: canonical_json(value))
        consumer_mode = spec["consumerMode"]
        if classification == "evidence":
            if consumer_mode == "evidence-preservation-only":
                require(not consumers, f"preservation-only evidence gained an artifact consumer: {identity}")
            elif consumer_mode == "evidence-attestation-only":
                require(consumers, f"attestation evidence lost all artifact consumers: {identity}")
            else:
                raise ValueError(f"evidence artifact consumer mode changed: {identity}")
        elif classification == "ephemeral-validation":
            require(consumer_mode == "same-job-roundtrip-validation" and consumers,
                    f"ephemeral validation artifact consumer mode changed: {identity}")
        else:
            if consumer_mode == "cross-run-custom-api-authority":
                require(identity in long_lived and not consumers,
                        f"custom API authority artifact boundary changed: {identity}")
            elif consumer_mode == "cross-run-attested-authority":
                require(
                    consumers and any(consumer["workflow"] != identity[0] for consumer in consumers),
                    f"cross-run attested authority artifact lost its external consumer: {identity}",
                )
            elif consumer_mode in {
                "same-run-attestation-authority",
                "same-run-publication-authority",
                "same-run-terminal-merge-authority",
                "same-run-proposal-authority",
            }:
                require(
                    consumers and all(consumer["workflow"] == identity[0] for consumer in consumers),
                    f"same-run authority artifact escaped its workflow: {identity}",
                )
            else:
                raise ValueError(f"authority artifact consumer mode changed: {identity}")

        entries.append({
            "workflow": identity[0],
            "job": identity[1],
            "step": identity[2],
            "name": artifact["name"],
            "path": artifact["path"],
            "ifNoFilesFound": artifact["if-no-files-found"],
            "retentionDays": retention_days,
            "maxRetentionDays": max_retention_days,
            "classification": classification,
            "consumerMode": consumer_mode,
            "reviewedLongLivedAuthorityException": identity in long_lived,
            "consumers": consumers,
        })

    if long_lived:
        codeql_identity = next(iter(long_lived))
        require(
            codeql_identity == (
                ".github/workflows/codeql-autofix.yml",
                "controller",
                "Upload immutable controller provenance receipt",
            ),
            "reviewed long-lived authority exception identity changed",
        )
        controller = (ROOT / "scripts" / "codeql_autofix_controller.py").read_text(encoding="utf-8")
        contract = (ROOT / "scripts" / "codeql_autofix_controller_contract.py").read_text(encoding="utf-8")
        for fragment in (
            'require(artifact["expired"] is False, "controller receipt artifact is expired")',
            'current_main_sha = current_main(main_ref, provenance["baseSha"])["baseSha"]',
        ):
            require(fragment in controller, "CodeQL Autofix long-lived authority freshness guard changed")
        require(
            'require(artifact_value.get("expired") is False, "Autofix provenance artifact is expired")'
            in contract,
            "CodeQL Autofix provenance artifact expiry guard changed",
        )

    authority_identities = {
        identity
        for identity, spec in reviewed.items()
        if spec["classification"] == "authority"
    }
    require(
        set(anti_replay_modes) == authority_identities,
        "authority artifact anti-replay classification coverage changed",
    )
    require(
        set(anti_replay_modes.values()) <= AUTHORITY_ARTIFACT_ANTI_REPLAY_MODES,
        "authority artifact anti-replay mode is invalid",
    )
    reviewed_cross_run = {
        identity
        for identity, mode in anti_replay_modes.items()
        if mode == "cross-run-attested-explicit-ttl"
    }
    require(
        set(cross_run_specs) == reviewed_cross_run,
        "cross-run authority artifact selector inventory changed",
    )

    for identity in sorted(authority_identities):
        mode = anti_replay_modes[identity]
        consumers = consumers_by_producer[identity]
        consumer_mode = reviewed[identity]["consumerMode"]
        if mode == "same-run-container-bound":
            require(
                consumer_mode in {
                    "same-run-attestation-authority",
                    "same-run-publication-authority",
                    "same-run-terminal-merge-authority",
                    "same-run-proposal-authority",
                },
                f"same-run authority artifact mode changed: {identity}",
            )
            require(
                consumers
                and all(
                    consumer["workflow"] == identity[0]
                    and consumer["runId"] == ""
                    and consumer["githubToken"] == ""
                    and consumer["repository"] == ""
                    for consumer in consumers
                ),
                f"same-run authority artifact gained cross-run selector or escaped its workflow: {identity}",
            )
        elif mode == "cross-run-attested-explicit-ttl":
            require(
                consumer_mode == "cross-run-attested-authority",
                f"cross-run attested authority artifact mode changed: {identity}",
            )
            external = [consumer for consumer in consumers if consumer["workflow"] != identity[0]]
            internal = [consumer for consumer in consumers if consumer["workflow"] == identity[0]]
            require(
                len(external) == 1 and internal
                and all(
                    consumer["runId"] == ""
                    and consumer["githubToken"] == ""
                    and consumer["repository"] == ""
                    for consumer in internal
                ),
                f"cross-run attested authority artifact consumer topology changed: {identity}",
            )
            expected = cross_run_specs[identity]
            require(
                set(expected) == {"consumer", "runId", "githubToken", "repository"},
                f"cross-run authority artifact selector contract shape changed: {identity}",
            )
            selected = external[0]
            require(
                (selected["workflow"], selected["job"], selected["step"]) == tuple(expected["consumer"])
                and selected["runId"] == expected["runId"]
                and selected["githubToken"] == expected["githubToken"]
                and selected["repository"] == expected["repository"],
                f"cross-run authority artifact selector drifted: {identity}",
            )

            if identity[0] == ".github/workflows/action-provenance-witness.yml":
                source_path = ROOT / "scripts" / "action_provenance_witness.py"
                schema_path = ROOT / ".github" / "attestation" / "action-provenance-witness-v1.schema.json"
                source_fragments = (
                    "TTL_SECONDS = 21600",
                    'return validity["issuedAtEpoch"] <= now_epoch < validity["expiresAtEpoch"]',
                    'require(artifact["expired"] is False, "witness artifact is expired")',
                    'require(source["runId"] == selected["id"],',
                    'require(source["runAttempt"] == selected["runAttempt"],',
                )
            else:
                require(
                    identity[0] == ".github/workflows/profile-generator-compatibility-witness.yml",
                    f"unreviewed explicit-TTL authority artifact entered policy: {identity}",
                )
                source_path = ROOT / "scripts" / "profile_generator_compatibility_witness.py"
                schema_path = ROOT / ".github" / "attestation" / "profile-generator-compatibility-witness-v1.schema.json"
                source_fragments = (
                    "TTL_SECONDS = 21600",
                    'require(value["validity"]["issuedAtEpoch"] <= now_epoch < value["validity"]["expiresAtEpoch"],',
                    'require(artifact["expired"] is False, "compatibility witness artifact is expired")',
                    'require(source["runId"] == selected["id"],',
                    'require(source["runAttempt"] == selected["runAttempt"],',
                )
            source_text = source_path.read_text(encoding="utf-8")
            schema_text = schema_path.read_text(encoding="utf-8")
            for fragment in source_fragments:
                require(
                    fragment in source_text,
                    f"cross-run explicit-TTL authority freshness guard changed: {identity}",
                )
            for fragment in ('"runId"', '"runAttempt"', '"issuedAtEpoch"', '"expiresAtEpoch"', '"ttlSeconds"'):
                require(
                    fragment in schema_text,
                    f"cross-run explicit-TTL authority schema binding changed: {identity}",
                )
        elif mode == "cross-run-current-main-expiry":
            require(
                identity == (
                    ".github/workflows/codeql-autofix.yml",
                    "controller",
                    "Upload immutable controller provenance receipt",
                )
                and consumer_mode == "cross-run-custom-api-authority"
                and identity in long_lived
                and not consumers,
                f"cross-run current-main/expiry authority boundary changed: {identity}",
            )
        else:
            raise ValueError(f"unclassified authority artifact anti-replay mode: {mode}")

    spotlight_authorization = (
        ".github/workflows/spotlight-link-sync.yml",
        "authorize",
        "Upload exact merge authorization artifact",
    )
    require(
        anti_replay_modes.get(spotlight_authorization) == "same-run-container-bound",
        "Spotlight merge authorization anti-replay mode changed",
    )
    spotlight_source = (ROOT / "scripts" / "spotlight_merge_authorization.py").read_text(encoding="utf-8")
    spotlight_schema = (
        ROOT / ".github" / "attestation" / "spotlight-merge-authorization-v1.schema.json"
    ).read_text(encoding="utf-8")
    for fragment in (
        'issued = env_value(env, "LEASE_ISSUED_AT", POSITIVE)',
        'expires = env_value(env, "LEASE_EXPIRES_AT", POSITIVE)',
        "require(int(expires) == int(issued) + 1800,",
        'run_id = env_value(env, "GITHUB_RUN_ID", POSITIVE)',
        'run_attempt = env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)',
    ):
        require(fragment in spotlight_source, "Spotlight merge authorization issuance/lease guard changed")
    for fragment in (
        '"required": ["leaseId", "candidateId", "issuedAt", "expiresAt"]',
        "cannot authorize merge without independent terminal live revalidation",
        "an unexpired matching mutation lease",
    ):
        require(fragment in spotlight_schema, "Spotlight merge authorization schema freshness guard changed")

    for entry in entries:
        identity = (entry["workflow"], entry["job"], entry["step"])
        if identity in authority_identities:
            entry["antiReplayMode"] = anti_replay_modes[identity]

    return {
        "schemaVersion": ARTIFACT_RETENTION_POLICY_SCHEMA_VERSION,
        "policyId": ARTIFACT_RETENTION_POLICY_ID,
        "repository": repository,
        "uploadProducerCount": len(producer_lookup),
        "downloadConsumerCount": len(download_lookup),
        "limits": {
            "authorityDefaultRetentionDays": ARTIFACT_RETENTION_LIMITS["authority"],
            "ephemeralValidationMaxRetentionDays": ARTIFACT_RETENTION_LIMITS["ephemeral-validation"],
            "evidenceMaxRetentionDays": ARTIFACT_RETENTION_LIMITS["evidence"],
            "reviewedLongLivedAuthorityMaxRetentionDays": MAX_REVIEWED_LONG_LIVED_AUTHORITY_RETENTION_DAYS,
            "reviewedLongLivedAuthorityExceptionCount": len(long_lived),
        },
        "entries": entries,
    }


def compile_artifact_retention_policy(
    workflows: list[dict[str, Any]], repository: str
) -> dict[str, Any]:
    return _compile_artifact_retention_policy(workflows, repository)

def compile_bom(root: Path = ROOT) -> dict[str, Any]:
    require(root == ROOT, "workflow capability compiler root substitution is not supported")
    policy = automation_policy.load_policy()
    policy_specs = authority.policy_specs(policy)
    workflows: list[dict[str, Any]] = []
    for relative, workflow_id, path in workflow_sources(policy):
        text = path.read_text(encoding="utf-8")
        filename = path.name
        require(filename in policy_specs, f"workflow missing from policy specs: {filename}")
        authority.validate_workflow_text(filename, text, policy_specs[filename])
        names, needs = authority.parse_job_metadata(text, filename)
        permissions = authority.parse_permissions(text, filename)
        jobs = sorted(names)
        effective = effective_permissions(permissions, jobs, filename)
        compiled_steps = compile_steps(text, relative, jobs)
        blocks = job_blocks(text, jobs, filename)
        top_name = TOP_NAME.search(text)
        require(top_name is not None, f"{filename}: workflow name is missing")
        job_entries: list[dict[str, Any]] = []
        for job in jobs:
            entry = {
                "id": job,
                "name": names[job],
                "needs": needs[job],
                "permissions": effective[job],
                "oidc": effective[job].get("id-token") == "write",
                "references": expression_references(blocks[job]),
                **compiled_steps[job],
            }
            validate_job_authority(filename, entry)
            job_entries.append(entry)
        workflows.append({
            "id": workflow_id,
            "name": unquote(top_name.group("name")),
            "path": relative,
            "triggers": parse_trigger_details(text, filename),
            "workflowPermissions": {
                key: permissions[authority.WORKFLOW_SCOPE][key]
                for key in sorted(permissions[authority.WORKFLOW_SCOPE])
            },
            "jobs": job_entries,
            "references": expression_references(text),
        })
    validate_authority_action_origins(workflows)
    compile_artifact_retention_policy(workflows, policy["repository"])
    return {
        "schemaVersion": SCHEMA_VERSION,
        "bomId": BOM_ID,
        "repository": policy["repository"],
        "automationPolicyId": policy["policyId"],
        "workflows": workflows,
    }


def expect_failure(callback, fragment: str) -> None:
    try:
        callback()
    except ValueError as exc:
        require(fragment in str(exc), f"capability BOM self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"capability BOM self-test accepted forbidden input: {fragment}")


def self_test() -> None:
    require(unquote('"main"') == "main" and unquote("'main'") == "main", "scalar unquote failed")
    fixture = (
        "name: Fixture\n\n"
        "on:\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      source_sha:\n"
        "        description: \"Exact source\"\n"
        "        required: false\n"
        "        type: string\n\n"
    )
    parsed = parse_trigger_details(fixture, "fixture.yml")
    require(
        parsed == {
            "push": {"branches": ["main"]},
            "workflow_dispatch": {
                "inputs": {
                    "source_sha": {
                        "description": "Exact source",
                        "required": "false",
                        "type": "string",
                    }
                }
            },
        },
        f"trigger parser self-test drifted: {parsed!r}",
    )
    action = REMOTE_ACTION.fullmatch(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    require(action is not None and action.group("repository") == "actions/checkout",
            "immutable action parser self-test failed")
    require(REMOTE_ACTION.fullmatch("actions/checkout@main") is None,
            "mutable action ref self-test was accepted")

    with_lines = [
        "          name: receipt",
        "          path: |",
        "            receipt.json",
        "            receipt.sha256",
        "          retention-days: 1",
    ]
    values = parse_with_values(with_lines, 0, workflow="fixture.yml", job="job", step="artifact")
    require(values["path"] == "receipt.json\nreceipt.sha256" and values["retention-days"] == "1",
            f"with block scalar self-test drifted: {values!r}")

    gh = api_surface(
        'gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs" --jq .total_count | tr -d \'\\n\'',
        workflow="fixture.yml", job="job", step="api",
    )
    require(gh["endpoint"] == "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs" and gh["method"] == "GET",
            f"gh api option parser self-test drifted: {gh!r}")
    post = api_surface(
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/x.yml/dispatches" -f ref=main)',
        workflow="fixture.yml", job="job", step="api",
    )
    require(post["method"] == "POST" and post["mutating"], f"gh api method self-test drifted: {post!r}")
    graphql_query = api_surface(
        "gh api graphql -f query='query($owner:String!){viewer{login}}' -f owner=x",
        workflow="fixture.yml", job="job", step="graphql-read",
    )
    require(graphql_query == {
        "client": "gh-api", "endpoint": "graphql", "graphqlOperation": "query",
        "method": "POST", "mutating": False,
    }, f"GraphQL read classification self-test drifted: {graphql_query!r}")
    graphql_mutation = api_surface(
        "gh api graphql -f query='mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id}){clientMutationId}}' -f id=x",
        workflow="fixture.yml", job="job", step="graphql-write",
    )
    require(graphql_mutation["method"] == "POST" and graphql_mutation["mutating"]
            and graphql_mutation["graphqlOperation"] == "mutation"
            and mutation_class(graphql_mutation) == "graphql-mutation",
            f"GraphQL mutation classification self-test drifted: {graphql_mutation!r}")
    expect_failure(
        lambda: api_surface("gh api graphql -f query=$DYNAMIC", workflow="fixture.yml", job="job", step="api"),
        "GraphQL query operation must be statically visible exactly once",
    )
    expect_failure(
        lambda: api_surface("gh api graphql -f query='mutation{x}' -f query='query{x}'", workflow="fixture.yml", job="job", step="api"),
        "GraphQL query operation must be statically visible exactly once",
    )
    expect_failure(
        lambda: api_surface("gh api --unknown value repos/x", workflow="fixture.yml", job="job", step="api"),
        "unclassified gh api option",
    )

    git = git_surface(
        'git -C artifacts -c "http.https://github.com/.extraheader=AUTHORIZATION: basic x" push origin HEAD:generated',
        workflow="fixture.yml", job="job", step="publish",
    )
    require(git is not None and git["operation"] == "push" and git.get("remote") == "origin"
            and git.get("targets") == ["HEAD:generated"] and git["mutating"],
            f"git push parser self-test drifted: {git!r}")
    fetch = git_surface(
        "git -C published fetch -q ../candidate.bundle refs/heads/generated:refs/heads/generated",
        workflow="fixture.yml", job="job", step="fetch",
    )
    require(fetch is not None and fetch.get("remote") == "../candidate.bundle"
            and fetch.get("targets") == ["refs/heads/generated:refs/heads/generated"],
            f"git fetch parser self-test drifted: {fetch!r}")
    ls_remote = git_surface(
        "git -C published ls-remote --exit-code origin refs/heads/generated",
        workflow="fixture.yml", job="job", step="ls-remote",
    )
    require(ls_remote is not None and ls_remote.get("remote") == "origin"
            and ls_remote.get("targets") == ["refs/heads/generated"],
            f"git ls-remote parser self-test drifted: {ls_remote!r}")
    expect_failure(
        lambda: git_surface("git fetch --mystery origin main", workflow="fixture.yml", job="job", step="fetch"),
        "unclassified git fetch option",
    )

    refs = expression_references("${{ secrets.ONE }} ${{ vars.TWO }} ${{ env.THREE }} ${{ github.token }}")
    require(refs == {
        "secrets": ["ONE"], "vars": ["TWO"], "env": ["THREE"], "githubToken": ["github.token"]
    }, f"expression reference self-test drifted: {refs!r}")

    network_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Bad network\n"
        "        run: |\n"
        "          curl https://example.invalid\n"
    )
    expect_failure(lambda: compile_steps(network_fixture, "fixture.yml", ["job"]), "unclassified network client")

    artifact_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Missing artifact path\n"
        "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"
        "        with:\n"
        "          name: fixture\n"
    )
    expect_failure(lambda: compile_steps(artifact_fixture, "fixture.yml", ["job"]),
                   "artifact action must expose its path")

    artifact_id_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Exact artifact download\n"
        "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\n"
        "        with:\n"
        "          artifact-ids: ${{ steps.upload.outputs.artifact-id }}\n"
        "          path: artifact-out\n"
        "          digest-mismatch: error\n"
    )
    artifact_id_compiled = compile_steps(artifact_id_fixture, "fixture.yml", ["job"])
    require(
        artifact_id_compiled["job"]["artifacts"] == [{
            "artifactIds": "${{ steps.upload.outputs.artifact-id }}",
            "digest-mismatch": "error",
            "operation": "download",
            "path": "artifact-out",
            "step": "Exact artifact download",
        }],
        f"artifact-id selector self-test drifted: {artifact_id_compiled!r}",
    )

    cross_run_artifact_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Cross-run artifact download\n"
        "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\n"
        "        with:\n"
        "          name: witness\n"
        "          path: witness-out\n"
        "          github-token: ${{ github.token }}\n"
        "          run-id: ${{ steps.discovery.outputs.run_id }}\n"
        "          digest-mismatch: error\n"
    )
    cross_run_artifact_compiled = compile_steps(
        cross_run_artifact_fixture, "fixture.yml", ["job"]
    )
    require(
        cross_run_artifact_compiled["job"]["artifacts"] == [{
            "digest-mismatch": "error",
            "githubToken": "${{ github.token }}",
            "name": "witness",
            "operation": "download",
            "path": "witness-out",
            "runId": "${{ steps.discovery.outputs.run_id }}",
            "step": "Cross-run artifact download",
        }],
        f"cross-run artifact selector self-test drifted: {cross_run_artifact_compiled!r}",
    )
    expect_failure(
        lambda: compile_steps(
            cross_run_artifact_fixture.replace(
                "          github-token: ${{ github.token }}\n", "", 1
            ),
            "fixture.yml",
            ["job"],
        ),
        "cross-run artifact download must provide both run-id and github-token",
    )
    conflicting_artifact_selector = artifact_id_fixture.replace(
        "          artifact-ids: ${{ steps.upload.outputs.artifact-id }}\n",
        "          name: fixture\n          artifact-ids: ${{ steps.upload.outputs.artifact-id }}\n",
        1,
    )
    expect_failure(
        lambda: compile_steps(conflicting_artifact_selector, "fixture.yml", ["job"]),
        "artifact download must select exactly one name or artifact-ids",
    )

    expect_failure(
        lambda: validate_job_authority("fixture.yml", {
            "id": "write-job", "actions": [], "permissions": {"contents": "write"},
            "oidc": False, "mutations": [],
        }),
        "write permissions lack a classified mutation",
    )
    expect_failure(
        lambda: validate_job_authority("fixture.yml", {
            "id": "attest-job",
            "actions": [{"repository": "actions/attest"}],
            "permissions": {"attestations": "write"}, "oidc": False,
            "mutations": [{"class": "attestation"}],
        }),
        "attestation action lacks exact OIDC/attestations write authority",
    )

    def action_origin_fixture(
        *,
        permissions: dict[str, str],
        oidc: bool = False,
        mutations: list[dict[str, Any]] | None = None,
        secrets: list[str] | None = None,
        action_path: str = "",
        action_ref: str = "0" * 40,
    ) -> list[dict[str, Any]]:
        return [{
            "path": ".github/workflows/fixture.yml",
            "jobs": [{
                "id": "job",
                "actions": [{
                    "kind": "remote",
                    "repository": "example/third-party-action",
                    "path": action_path,
                    "ref": action_ref,
                    "step": "Third-party fixture",
                }],
                "permissions": permissions,
                "oidc": oidc,
                "mutations": mutations or [],
                "references": {"secrets": secrets or []},
            }],
        }]

    validate_authority_action_origins(
        action_origin_fixture(permissions={"contents": "read"})
    )
    authority_variants = (
        action_origin_fixture(permissions={"contents": "write"}, mutations=[{"class": "git-ref-push"}]),
        action_origin_fixture(permissions={"contents": "read", "id-token": "write"}, oidc=True),
        action_origin_fixture(permissions={"contents": "read"}, mutations=[{"class": "pull-request"}]),
        action_origin_fixture(permissions={"contents": "read"}, secrets=["AUTHORITY_SECRET"]),
    )
    for fixture_workflows in authority_variants:
        expect_failure(
            lambda fixture_workflows=fixture_workflows: validate_authority_action_origins(fixture_workflows),
            "unreviewed third-party Action entered authority-bearing job",
        )

    exact_exception = frozenset({
        (".github/workflows/fixture.yml", "job", "example/third-party-action", "", "0" * 40)
    })
    validate_authority_action_origins(
        action_origin_fixture(permissions={"contents": "write"}, mutations=[{"class": "git-ref-push"}]),
        exact_exception,
    )
    expect_failure(
        lambda: validate_authority_action_origins(
            action_origin_fixture(
                permissions={"contents": "write"},
                mutations=[{"class": "git-ref-push"}],
                action_path="alternate",
            ),
            exact_exception,
        ),
        "unreviewed third-party Action entered authority-bearing job",
    )
    expect_failure(
        lambda: validate_authority_action_origins(
            action_origin_fixture(
                permissions={"contents": "write"},
                mutations=[{"class": "git-ref-push"}],
                action_ref="1" * 40,
            ),
            exact_exception,
        ),
        "unreviewed third-party Action entered authority-bearing job",
    )
    expect_failure(
        lambda: validate_authority_action_origins(
            action_origin_fixture(permissions={"contents": "read"}),
            exact_exception,
        ),
        "reviewed third-party authority Action exception is stale",
    )


    live_bom = compile_bom()
    live_workflows = live_bom["workflows"]
    live_retention = compile_artifact_retention_policy(live_workflows, live_bom["repository"])
    require(
        live_retention["uploadProducerCount"] == 20
        and live_retention["downloadConsumerCount"] == 28
        and sum(
            1 for entry in live_retention["entries"]
            if entry.get("antiReplayMode") in AUTHORITY_ARTIFACT_ANTI_REPLAY_MODES
        ) == 10,
        "artifact retention/anti-replay live inventory cardinality changed",
    )

    def mutated_workflows() -> list[dict[str, Any]]:
        return json.loads(json.dumps(live_workflows))

    broadened = mutated_workflows()
    broadened_target = next(
        artifact
        for workflow in broadened
        if workflow["path"] == ".github/workflows/profile-stats.yml"
        for job in workflow["jobs"]
        if job["id"] == "stage"
        for artifact in job["artifacts"]
        if artifact["operation"] == "upload"
    )
    broadened_target["retention-days"] = "2"
    expect_failure(
        lambda: _compile_artifact_retention_policy(broadened, live_bom["repository"]),
        "retention exceeds reviewed class maximum",
    )

    dynamic = mutated_workflows()
    dynamic_target = next(
        artifact
        for workflow in dynamic
        for job in workflow["jobs"]
        for artifact in job["artifacts"]
        if artifact["operation"] == "upload"
    )
    dynamic_target["retention-days"] = "$" + "{{ vars.RETENTION_DAYS }}"
    expect_failure(
        lambda: _compile_artifact_retention_policy(dynamic, live_bom["repository"]),
        "retention must be a literal positive day count",
    )

    missing = mutated_workflows()
    missing_job = next(
        job
        for workflow in missing
        if workflow["path"] == ".github/workflows/dependabot-controller.yml"
        for job in workflow["jobs"]
        if job["id"] == "integration"
    )
    missing_job["artifacts"] = [
        artifact for artifact in missing_job["artifacts"]
        if artifact["step"] != "Upload exact validation Signal Field"
    ]
    expect_failure(
        lambda: _compile_artifact_retention_policy(missing, live_bom["repository"]),
        "reviewed artifact upload producer is stale or missing",
    )

    duplicated = mutated_workflows()
    duplicate_job = next(
        job
        for workflow in duplicated
        if workflow["path"] == ".github/workflows/profile-quality.yml"
        for job in workflow["jobs"]
        if job["id"] == "integration"
    )
    duplicate_upload = next(
        artifact for artifact in duplicate_job["artifacts"]
        if artifact["operation"] == "upload"
    )
    duplicate_job["artifacts"].append(json.loads(json.dumps(duplicate_upload)))
    expect_failure(
        lambda: _compile_artifact_retention_policy(duplicated, live_bom["repository"]),
        "duplicate artifact upload producer identity",
    )

    unbound_download = mutated_workflows()
    unbound_job = next(
        job
        for workflow in unbound_download
        if workflow["path"] == ".github/workflows/profile-quality.yml"
        for job in workflow["jobs"]
        if job["id"] == "validate"
    )
    unbound_job["artifacts"].append({
        "operation": "download",
        "step": "Unreviewed artifact consumer",
        "name": "action-provenance-witness-v1",
        "path": "unreviewed",
        "digest-mismatch": "error",
    })
    expect_failure(
        lambda: _compile_artifact_retention_policy(unbound_download, live_bom["repository"]),
        "unclassified artifact download consumer entered repository",
    )

    evidence_as_authority = {
        identity: dict(spec)
        for identity, spec in REVIEWED_ARTIFACT_RETENTION_CLASSIFICATIONS.items()
    }
    evidence_identity = (
        ".github/workflows/ruleset-reconciler.yml",
        "reconcile",
        "Preserve exact non-secret reconciliation receipt",
    )
    evidence_as_authority[evidence_identity]["classification"] = "authority"
    evidence_as_authority[evidence_identity]["consumerMode"] = "same-run-attestation-authority"
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            live_workflows,
            live_bom["repository"],
            classifications=evidence_as_authority,
        ),
        "retention exceeds reviewed class maximum",
    )

    same_run_escape = mutated_workflows()
    same_run_consumer = next(
        artifact
        for workflow in same_run_escape
        if workflow["path"] == ".github/workflows/profile-stats.yml"
        for job in workflow["jobs"]
        if job["id"] == "publish"
        for artifact in job["artifacts"]
        if artifact["step"] == "Download sealed generated publication candidate"
    )
    same_run_consumer["runId"] = "${{ github.run_id }}"
    same_run_consumer["githubToken"] = "${{ github.token }}"
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            same_run_escape, live_bom["repository"]
        ),
        "same-run authority artifact gained cross-run selector or escaped its workflow",
    )

    cross_run_selector_drift = mutated_workflows()
    cross_run_consumer = next(
        artifact
        for workflow in cross_run_selector_drift
        if workflow["path"] == ".github/workflows/profile-quality.yml"
        for job in workflow["jobs"]
        if job["id"] == "validate"
        for artifact in job["artifacts"]
        if artifact["step"] == "Download exact fresh signed Action provenance witness"
    )
    cross_run_consumer["runId"] = "${{ steps.wrong.outputs.run_id }}"
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            cross_run_selector_drift, live_bom["repository"]
        ),
        "cross-run authority artifact selector drifted",
    )

    missing_anti_replay = dict(REVIEWED_AUTHORITY_ARTIFACT_ANTI_REPLAY)
    missing_anti_replay.pop((
        ".github/workflows/profile-stats.yml",
        "stage",
        "Upload sealed generated publication candidate",
    ))
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            live_workflows,
            live_bom["repository"],
            anti_replay=missing_anti_replay,
        ),
        "authority artifact anti-replay classification coverage changed",
    )

    stale_anti_replay = dict(REVIEWED_AUTHORITY_ARTIFACT_ANTI_REPLAY)
    stale_anti_replay[(
        ".github/workflows/ruleset-reconciler.yml",
        "reconcile",
        "Preserve exact non-secret reconciliation receipt",
    )] = "same-run-container-bound"
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            live_workflows,
            live_bom["repository"],
            anti_replay=stale_anti_replay,
        ),
        "authority artifact anti-replay classification coverage changed",
    )

    authority_as_evidence = {
        identity: dict(spec)
        for identity, spec in REVIEWED_ARTIFACT_RETENTION_CLASSIFICATIONS.items()
    }
    authority_identity = (
        ".github/workflows/profile-stats.yml",
        "stage",
        "Upload sealed generated publication candidate",
    )
    authority_as_evidence[authority_identity]["classification"] = "evidence"
    authority_as_evidence[authority_identity]["consumerMode"] = "evidence-attestation-only"
    expect_failure(
        lambda: _compile_artifact_retention_policy(
            live_workflows,
            live_bom["repository"],
            classifications=authority_as_evidence,
        ),
        "evidence artifact entered non-attestation mutation authority",
    )


if __name__ == "__main__":
    self_test()
    print(canonical_json(compile_bom()), end="")
