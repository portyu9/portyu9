#!/usr/bin/env python3
"""Run the versioned Signal Field production pipeline from one ordered manifest.

Pipeline v2 makes mutation/validation boundaries explicit: v2.15 and v2.16 are
standalone transformer stages, while validators only observe finalized candidate bytes.
The historical v1 manifest remains in the repository as the reviewed predecessor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = SCRIPTS / "signal-field-pipeline-v2.json"
HISTORICAL_MANIFEST = SCRIPTS / "signal-field-pipeline-v1.json"
PIPELINE_VERSION = "signal-field-pipeline-v2"
TERMINAL_CONTRACT = "signal-field-v2.18+signal-field-v2.19-compact-eid+profile-refresh-v2"

# id, contract, script, kind, self_test, required_predecessor, responsive_scope
EXPECTED_STAGE_AUTHORITY = (
    ("customize-v2", "yunior-portal-neon-v2", "customize-signal-field.py", "transform", True, None, "wide+compact"),
    ("polish-v2.1", "signal-field-v2.1", "polish-signal-field-v2.py", "transform", True, "customize-v2", "wide+compact"),
    ("evidence-v2.2", "signal-field-v2.2", "enhance-signal-field-v2.py", "transform", True, "polish-v2.1", "wide+compact"),
    ("background-v2.3", "signal-field-v2.3", "background-signal-field-v2.py", "transform", True, "evidence-v2.2", "wide+compact"),
    ("portal-v2.4", "signal-field-v2.4", "portal-signal-field-v2.py", "transform", True, "background-v2.3", "wide+compact"),
    ("layout-v2.5", "signal-field-v2.5", "align-signal-field-v2.py", "transform", True, "portal-v2.4", "wide+compact"),
    ("metrics-v2.6", "signal-field-v2.6", "phosphor-signal-field-v2.py", "transform", True, "layout-v2.5", "wide+compact"),
    ("activity-v2.7", "signal-field-v2.7", "phosphor-activity-signal-field-v2.py", "transform", True, "metrics-v2.6", "wide+compact"),
    ("lines-v2.8", "signal-field-v2.8", "phosphor-lines-signal-field-v2.py", "transform", True, "activity-v2.7", "wide+compact"),
    ("profile-total-v2.9", "signal-field-v2.9", "sync-profile-contribution-total.py", "transform", True, "lines-v2.8", "wide+compact"),
    ("labels-v2.10", "signal-field-v2.10", "relabel-signal-field-metrics.py", "transform", True, "profile-total-v2.9", "wide+compact"),
    ("glyphs-v2.11", "signal-field-v2.11", "glyphs-signal-field-metrics.py", "transform", True, "labels-v2.10", "wide+compact"),
    ("balance-v2.12", "signal-field-v2.12", "balance-signal-field-secondary-metrics.py", "transform", True, "glyphs-v2.11", "wide+compact"),
    ("clarity-v2.13", "signal-field-v2.13", "clarify-signal-field-evidence-window.py", "transform", True, "balance-v2.12", "wide+compact"),
    ("validate-v2.13", "signal-field-v2.13", "validate-signal-field-v213.py", "validate", False, "clarity-v2.13", "wide+compact"),
    ("identity-v2.14", "signal-field-v2.14", "identify-signal-field-evidence.py", "transform", False, "validate-v2.13", "wide+compact"),
    ("presentation-v2.15", "signal-field-v2.15", "polish-signal-field-evidence-v215.py", "transform", True, "identity-v2.14", "wide+compact"),
    ("issues-balance-v2.16", "signal-field-v2.16", "balance-signal-field-issues-label.py", "transform", True, "presentation-v2.15", "wide+compact"),
    ("validate-v2.14-plus-presentation", "signal-field-v2.14+v2.15+v2.16", "validate-signal-field-v214.py", "validate", True, "issues-balance-v2.16", "wide+compact"),
    ("refresh-and-wide-v2.18", "profile-refresh-v2+signal-field-v2.18+signal-field-v2.19-compact-eid", "set-signal-field-refresh-cadence.py", "transform", True, "validate-v2.14-plus-presentation", "wide+compact-with-desktop-finalizer"),
    ("validate-publishable", "publishable-signal-field", "validate-generated-signal-field.py", "validate", False, "refresh-and-wide-v2.18", "wide+compact"),
)
EXPECTED_STAGE_IDS = tuple(stage[0] for stage in EXPECTED_STAGE_AUTHORITY)
EXPECTED_SELF_TEST_IDS = tuple(stage[0] for stage in EXPECTED_STAGE_AUTHORITY if stage[4])
STAGE_KEYS = {"id", "contract", "script", "kind", "self_test", "required_predecessor", "responsive_scope"}
ALLOWED_KINDS = {"transform", "validate"}
ALLOWED_SCOPES = {"wide+compact", "wide+compact-with-desktop-finalizer"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_real_script(path: Path, label: str) -> None:
    require(not path.is_symlink(), f"{label} must not be a symlink: {path.relative_to(ROOT)}")
    require(path.is_file(), f"{label} is missing: {path.relative_to(ROOT)}")
    require(path.resolve().parent == SCRIPTS.resolve(), f"{label} escaped the scripts directory: {path}")


def stage_authority(stage: dict[str, Any]) -> tuple[object, ...]:
    return (
        stage.get("id"),
        stage.get("contract"),
        stage.get("script"),
        stage.get("kind"),
        stage.get("self_test"),
        stage.get("required_predecessor"),
        stage.get("responsive_scope"),
    )


def validate_manifest(data: dict[str, Any]) -> dict[str, Any]:
    require(set(data) == {"version", "description", "terminal_contract", "stages"}, "pipeline manifest keys changed")
    require(data.get("version") == PIPELINE_VERSION, "Signal Field pipeline version changed")
    require(isinstance(data.get("description"), str) and data["description"], "pipeline description is missing")
    require(data.get("terminal_contract") == TERMINAL_CONTRACT, "pipeline terminal contract changed")
    stages = data.get("stages")
    require(isinstance(stages, list), "pipeline stages must be an array")
    require(len(stages) == len(EXPECTED_STAGE_AUTHORITY), "Signal Field pipeline stage count changed")

    self_test_ids: list[str] = []
    seen_scripts: set[str] = set()
    for index, expected in enumerate(EXPECTED_STAGE_AUTHORITY):
        stage = stages[index]
        require(isinstance(stage, dict), f"stage {index} must be an object")
        stage_id = expected[0]
        require(set(stage) == STAGE_KEYS, f"{stage_id}: stage keys changed")
        require(stage_authority(stage) == expected, f"{stage_id}: reviewed stage authority changed")

        script = stage["script"]
        assert isinstance(script, str)
        require(Path(script).name == script, f"{stage_id}: script must be one scripts-directory basename")
        require(script not in seen_scripts, f"{stage_id}: script is duplicated in pipeline: {script}")
        require_real_script(SCRIPTS / script, f"{stage_id} executable")
        require(stage["kind"] in ALLOWED_KINDS, f"{stage_id}: unsupported kind: {stage['kind']!r}")
        require(stage["responsive_scope"] in ALLOWED_SCOPES, f"{stage_id}: unsupported responsive scope: {stage['responsive_scope']!r}")
        if stage["self_test"]:
            self_test_ids.append(str(stage_id))
        seen_scripts.add(script)

    require(tuple(stage["id"] for stage in stages) == EXPECTED_STAGE_IDS, "Signal Field pipeline stage order changed")
    require(tuple(self_test_ids) == EXPECTED_SELF_TEST_IDS, "Signal Field pipeline self-test coverage changed")
    require(stages[-1]["kind"] == "validate" and stages[-1]["id"] == "validate-publishable", "pipeline terminal validator changed")
    return data


def load_manifest() -> dict[str, Any]:
    require_real_script(HISTORICAL_MANIFEST, "historical pipeline v1 manifest")
    require_real_script(MANIFEST, "pipeline v2 manifest")
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "pipeline manifest root must be an object")
    return validate_manifest(data)


def manifest_digest() -> str:
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def execute(command: list[str], label: str) -> None:
    print(label, flush=True)
    subprocess.run(command, check=True, cwd=ROOT, env=os.environ.copy())


def run_pipeline(directory: Path) -> None:
    require(directory.is_dir(), f"Signal Field directory is missing: {directory}")
    data = load_manifest()
    stages = data["stages"]
    assert isinstance(stages, list)
    print(f"Signal Field pipeline {PIPELINE_VERSION} start; manifest_sha256={manifest_digest()}")
    for index, stage in enumerate(stages, start=1):
        assert isinstance(stage, dict)
        script = str(stage["script"])
        stage_id = str(stage["id"])
        kind = str(stage["kind"])
        contract = str(stage["contract"])
        execute(
            [sys.executable, str(SCRIPTS / script), str(directory)],
            f"[{index:02d}/{len(stages):02d}] {kind} {stage_id} -> {contract}: {script}",
        )
    print(f"Signal Field pipeline complete: {data['terminal_contract']}; manifest_sha256={manifest_digest()}")


def expect_manifest_failure(payload: dict[str, Any], expected: str) -> None:
    try:
        validate_manifest(payload)
    except ValueError as exc:
        require(expected in str(exc), f"pipeline manifest self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("pipeline manifest self-test accepted unreviewed stage authority")


def self_test() -> None:
    data = load_manifest()
    stages = data["stages"]
    assert isinstance(stages, list)

    mutation = json.loads(json.dumps(data))
    mutation["stages"][0]["script"] = "polish-signal-field-v2.py"
    expect_manifest_failure(mutation, "reviewed stage authority changed")

    mutation = json.loads(json.dumps(data))
    mutation["stages"][18]["contract"] = "signal-field-v2.14"
    expect_manifest_failure(mutation, "reviewed stage authority changed")

    mutation = json.loads(json.dumps(data))
    mutation["stages"][20]["self_test"] = True
    expect_manifest_failure(mutation, "reviewed stage authority changed")

    mutation = json.loads(json.dumps(data))
    mutation["stages"][0]["unexpected"] = "value"
    expect_manifest_failure(mutation, "stage keys changed")

    selected = [stage for stage in stages if isinstance(stage, dict) and stage["self_test"]]
    for index, stage in enumerate(selected, start=1):
        execute(
            [sys.executable, str(SCRIPTS / str(stage["script"])), "--self-test"],
            f"[self-test {index:02d}/{len(selected):02d}] {stage['id']}: {stage['script']}",
        )
    print(
        f"Signal Field pipeline contract passed: {PIPELINE_VERSION}; "
        f"{len(stages)} exact-authority ordered stages; {len(selected)} stage self-tests; "
        f"manifest_sha256={manifest_digest()}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--print-manifest-digest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.print_manifest_digest:
            require(args.directory is None and not args.self_test, "--print-manifest-digest cannot be combined with other modes")
            load_manifest()
            print(manifest_digest())
            return 0
        if args.self_test:
            require(args.directory is None, "--self-test cannot be combined with a directory")
            self_test()
            return 0
        require(args.directory is not None, "usage: signal_field_pipeline.py <directory> | --self-test | --print-manifest-digest")
        run_pipeline(args.directory)
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
