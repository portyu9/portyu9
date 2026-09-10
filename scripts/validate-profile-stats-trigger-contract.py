#!/usr/bin/env python3
"""Fail closed when production profile refresh triggers or source epochs drift."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
WORKFLOW = ROOT / ".github/workflows/profile-stats.yml"
CADENCE = ROOT / ".github/REFRESH_CADENCE.md"
SOURCE_EPOCH = SCRIPTS / "profile-stats-source-epoch-v1.json"
GENERATION_MANIFEST = SCRIPTS / "profile-evidence-generation-v1.json"
SIGNAL_MANIFEST = SCRIPTS / "signal-field-pipeline-v2.json"
SIGNAL_HISTORICAL_MANIFEST = SCRIPTS / "signal-field-pipeline-v1.json"
VALIDATION_MANIFEST = SCRIPTS / "profile-evidence-validation-boundary-v1.json"
DELEGATED_LOCK = SCRIPTS / "profile-delegated-implementation-lock-v1.json"
SUBJECT_MANIFEST = SCRIPTS / "profile-evidence-subjects-v1.json"
ATTESTATION_SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"

VERSION = "profile-stats-source-epoch-v1"
ALGORITHM = "sha256-sorted-path-nul-git-blob-oid-lf-v1"
MAIN_REF_EXPR = "github.ref == 'refs/heads/main'"
ATTEST_DELTA_EXPR = "github.event_name != 'schedule' || needs.attest.outputs.changed == 'true'"
PUBLICATION_DELTA_EXPR = "needs.stage.outputs.changed == 'true'"
JOB_IF_LINE = re.compile(r"(?m)^    if:\s*(?P<expr>.+?)\s*$")
DIRECT_SCRIPT = re.compile(r"python3 source/scripts/(?P<name>[A-Za-z0-9_.-]+\.py)(?:\s|\\|$)")
TRIGGER_PATHS = (
    ".github/workflows/profile-stats.yml",
    "scripts/profile-stats-source-epoch-v1.json",
)
STATIC_SOURCE_ROOTS = {
    ".github/workflows/profile-stats.yml",
    ".github/attestation/profile-evidence-v3.schema.json",
    "scripts/profile-evidence-generation-v1.json",
    "scripts/signal-field-pipeline-v1.json",
    "scripts/signal-field-pipeline-v2.json",
    "scripts/profile-evidence-validation-boundary-v1.json",
    "scripts/profile-delegated-implementation-lock-v1.json",
    "scripts/profile_delegated_implementation_lock.py",
    "scripts/profile_evidence_validation.py",
    "scripts/profile-evidence-subjects-v1.json",
    "scripts/profile_evidence_subjects.py",
}
CLOSURE_SENTINELS = {
    "scripts/generate-profile-evidence.py",
    "scripts/signal_field_pipeline.py",
    "scripts/sync-profile-contribution-total.py",
    "scripts/portfolio_evidence_ledger.py",
    "scripts/engineering_spotlight_renderer.py",
    "scripts/validate-profile-evidence-boundary.py",
    "scripts/stage-profile-evidence.py",
    "scripts/build-profile-evidence-attestation.py",
    ".github/attestation/profile-evidence-v3.schema.json",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"source-epoch authority JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def strict_json(path: Path) -> Any:
    require_real_file(path)
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object)


def require_real_file(path: Path) -> Path:
    require(path.exists() or path.is_symlink(), f"source-epoch input is missing: {path.relative_to(ROOT)}")
    require(path.absolute() == path.resolve(strict=True),
            f"source-epoch input resolves through an alias: {path.relative_to(ROOT)}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(),
            f"source-epoch input must be a real regular file: {path.relative_to(ROOT)}")
    return path


def repository_path(relative: str) -> Path:
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts,
            f"source-epoch path escaped repository: {relative}")
    return require_real_file(ROOT / path)


def manifest_scripts(path: Path, label: str) -> set[str]:
    payload = strict_json(path)
    require(isinstance(payload, dict) and isinstance(payload.get("stages"), list),
            f"{label} manifest is malformed")
    scripts: set[str] = set()
    for stage in payload["stages"]:
        require(isinstance(stage, dict), f"{label} manifest contains malformed stage")
        script = stage.get("script")
        require(isinstance(script, str) and Path(script).name == script and script.endswith(".py"),
                f"{label} manifest contains malformed script authority: {script!r}")
        relative = f"scripts/{script}"
        repository_path(relative)
        scripts.add(relative)
    require(scripts, f"{label} manifest produced an empty script closure")
    return scripts


def delegated_files() -> set[str]:
    payload = strict_json(DELEGATED_LOCK)
    require(isinstance(payload, dict) and isinstance(payload.get("files"), dict) and payload["files"],
            "delegated implementation lock is malformed")
    files = set(payload["files"])
    for relative in files:
        require(isinstance(relative, str) and relative.startswith("scripts/"),
                f"delegated implementation path is malformed: {relative!r}")
        repository_path(relative)
    return files


def direct_workflow_scripts(workflow: str) -> set[str]:
    scripts = {f"scripts/{match.group('name')}" for match in DIRECT_SCRIPT.finditer(workflow)}
    require(scripts, "profile-stats workflow exposes no reviewed direct Python roots")
    for relative in scripts:
        repository_path(relative)
    return scripts


def source_components(workflow: str) -> dict[str, set[str]]:
    return {
        "static": set(STATIC_SOURCE_ROOTS),
        "direct-workflow": direct_workflow_scripts(workflow),
        "generation": manifest_scripts(GENERATION_MANIFEST, "generation"),
        "signal-field": manifest_scripts(SIGNAL_MANIFEST, "Signal Field"),
        "validation": manifest_scripts(VALIDATION_MANIFEST, "validation boundary"),
        "delegated": delegated_files(),
    }


def derive_source_closure(workflow: str) -> tuple[str, ...]:
    components = source_components(workflow)
    closure = set().union(*components.values())
    for relative in closure:
        repository_path(relative)
    require(CLOSURE_SENTINELS <= closure,
            f"profile-stats source closure lost reviewed sentinels: {sorted(CLOSURE_SENTINELS - closure)!r}")
    require("scripts/validate-profile-stats-trigger-contract.py" not in closure,
            "trigger validator itself must remain validation-only, not a production refresh input")
    return tuple(sorted(closure))


def git_blob_oid(path: Path) -> str:
    data = path.read_bytes()
    payload = f"blob {len(data)}\0".encode("ascii") + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def closure_digest(files: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for relative in files:
        oid = git_blob_oid(repository_path(relative))
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(oid.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_epoch(payload: Any, files: tuple[str, ...], digest: str) -> None:
    require(isinstance(payload, dict), "profile-stats source epoch root must be an object")
    require(set(payload) == {"version", "algorithm", "file_count", "closure_sha256"},
            "profile-stats source epoch keys changed")
    require(payload.get("version") == VERSION, "profile-stats source epoch version changed")
    require(payload.get("algorithm") == ALGORITHM, "profile-stats source epoch algorithm changed")
    require(type(payload.get("file_count")) is int and payload["file_count"] == len(files),
            f"profile-stats source epoch file_count is stale: expected {len(files)}, got {payload.get('file_count')!r}")
    locked = payload.get("closure_sha256")
    require(isinstance(locked, str) and re.fullmatch(r"[0-9a-f]{64}", locked) is not None,
            "profile-stats source epoch digest is malformed")
    require(locked == digest,
            f"profile-stats source epoch digest is stale: expected {digest}, got {locked}")


def push_paths(workflow: str) -> tuple[str, ...]:
    lines = workflow.splitlines()
    push_index = next((i for i, line in enumerate(lines) if line == "  push:"), None)
    require(push_index is not None, "profile-stats push trigger is missing")
    paths_index = next(
        (i for i in range(push_index + 1, len(lines)) if lines[i] == "    paths:"),
        None,
    )
    require(paths_index is not None, "profile-stats push paths block is missing")
    collected: list[str] = []
    for line in lines[paths_index + 1:]:
        if line.startswith("      - "):
            value = line[len("      - "):].strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            collected.append(value)
            continue
        break
    require(collected, "profile-stats push paths block is empty")
    return tuple(collected)


def require_trigger_paths(paths: tuple[str, ...]) -> None:
    require(paths == TRIGGER_PATHS,
            f"profile-stats push paths must be exact source-epoch invalidation tokens: {TRIGGER_PATHS!r}; got {paths!r}")


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    require(start is not None, f"profile-stats job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", workflow[start.end():])
    require(end is not None, f"profile-stats job boundary is missing: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def exact_job_if(block: str, label: str) -> str:
    expressions = [match.group("expr") for match in JOB_IF_LINE.finditer(block)]
    require(len(expressions) == 1, f"{label} must contain exactly one job-level if condition")
    return expressions[0]


def expect_failure(callable_obj, expected: str) -> None:
    try:
        callable_obj()
    except ValueError as exc:
        require(expected in str(exc), f"source-epoch self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"source-epoch self-test accepted drift: {expected}")


def self_test(workflow: str) -> None:
    canonical = (
        "  generate:\n"
        f"    if: {MAIN_REF_EXPR}\n"
        "    runs-on: ubuntu-24.04\n"
    )
    require(exact_job_if(canonical, "fixture generation") == MAIN_REF_EXPR,
            "job-level if parser rejected canonical main guard")
    require_trigger_paths(TRIGGER_PATHS)
    expect_failure(
        lambda: require_trigger_paths(TRIGGER_PATHS + ("scripts/validate-governance-contract.py",)),
        "exact source-epoch invalidation tokens",
    )
    expect_failure(
        lambda: require_trigger_paths(TRIGGER_PATHS[:-1]),
        "exact source-epoch invalidation tokens",
    )

    components = source_components(workflow)
    closure = set().union(*components.values())
    delegated_example = "scripts/portfolio_evidence_ledger.py"
    require(delegated_example in components["delegated"],
            "self-test delegated production fixture disappeared")
    incomplete = closure - {delegated_example}
    expect_failure(
        lambda: require(CLOSURE_SENTINELS <= incomplete and components["delegated"] <= incomplete,
                        "required transitive production input is missing"),
        "required transitive production input is missing",
    )

    duplicate_json = '{"version":"profile-stats-source-epoch-v1","version":"other"}'
    expect_failure(
        lambda: json.loads(duplicate_json, object_pairs_hook=unique_json_object),
        "duplicate object key: version",
    )


def main() -> int:
    try:
        workflow = require_real_file(WORKFLOW).read_text(encoding="utf-8")
        cadence = require_real_file(CADENCE).read_text(encoding="utf-8")
        self_test(workflow)

        files = derive_source_closure(workflow)
        digest = closure_digest(files)
        epoch = strict_json(SOURCE_EPOCH)
        validate_epoch(epoch, files, digest)
        require_trigger_paths(push_paths(workflow))
        require("scripts/**" not in workflow,
                "broad scripts/** production trigger must remain retired")

        require("  workflow_dispatch:" in workflow, "manual main refresh path must remain available")
        require("  push:\n    branches:\n      - main\n" in workflow,
                "push-triggered production refresh must remain restricted to main")
        require("pull_request:" not in workflow,
                "production refresh workflow must never run from pull_request events")
        generate = job_block(workflow, "generate", "attest")
        attest = job_block(workflow, "attest", "attest_publish")
        attest_publish = job_block(workflow, "attest_publish", "stage")
        stage = job_block(workflow, "stage", "publish")
        publish = job_block(workflow, "publish", "dispatch")
        require(exact_job_if(generate, "production generation") == MAIN_REF_EXPR,
                "production generation job-level if must be the exact refs/heads/main guard")
        require("needs: generate" in attest,
                "read-only attestation preparation must remain downstream of main-guarded generation")
        require("needs: attest" in attest_publish,
                "terminal attestation authority must consume only reviewed attestation preparation")
        require(exact_job_if(attest_publish, "terminal attestation") == ATTEST_DELTA_EXPR,
                "terminal attestation job-level if must be the exact scheduled-delta guard")
        require("needs: [generate, attest, attest_publish]" in stage,
                "publication staging must remain downstream of generation, attestation preparation, and terminal attestation")
        require(exact_job_if(stage, "publication staging") == ATTEST_DELTA_EXPR,
                "publication staging job-level if must remain aligned with the exact attestation scheduled-delta guard")
        require("needs: stage" in publish,
                "terminal publication must remain downstream of read-only publication staging")
        require(exact_job_if(publish, "terminal publication") == PUBLICATION_DELTA_EXPR,
                "terminal publication job-level if must be the exact staged-candidate delta guard")

        for phrase in (
            "content-addressed source epoch",
            "production source closure",
            "validation-only changes do not trigger",
            "required Profile Quality",
        ):
            require(phrase in cadence,
                    f"refresh cadence rationale must document source-epoch triggering: {phrase}")
        require("scripts/**" not in cadence,
                "refresh cadence rationale must not retain the retired broad scripts wildcard")
        print(
            f"Profile stats trigger contract passed: {len(files)} exact trusted production inputs compile to "
            f"source epoch sha256:{digest}; push invalidation is workflow-or-epoch only, validation-only scripts do not trigger publication; "
            "main/manual/schedule guards and terminal attestation/publication delta boundaries remain unchanged."
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, StopIteration, IndexError, SyntaxError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
