#!/usr/bin/env python3
"""Run the versioned Signal Field production pipeline from one ordered manifest.

This replaces duplicated stage ordering in Profile Quality and production workflows.
The manifest is the reviewed stage registry; this orchestrator validates its exact v1
order, logs each stage, executes every production stage with the current interpreter,
and centralizes the same stage self-tests previously listed one-by-one in workflow YAML.
No network or repository-write authority is added here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = SCRIPTS / "signal-field-pipeline-v1.json"
PIPELINE_VERSION = "signal-field-pipeline-v1"
EXPECTED_STAGE_IDS = (
    "customize-v2",
    "polish-v2.1",
    "evidence-v2.2",
    "background-v2.3",
    "portal-v2.4",
    "layout-v2.5",
    "metrics-v2.6",
    "activity-v2.7",
    "lines-v2.8",
    "profile-total-v2.9",
    "labels-v2.10",
    "glyphs-v2.11",
    "balance-v2.12",
    "clarity-v2.13",
    "validate-v2.13",
    "identity-v2.14",
    "validate-v2.14",
    "refresh-and-wide-v2.18",
    "validate-publishable",
)
EXPECTED_SELF_TEST_IDS = (
    "customize-v2",
    "polish-v2.1",
    "evidence-v2.2",
    "background-v2.3",
    "portal-v2.4",
    "layout-v2.5",
    "metrics-v2.6",
    "activity-v2.7",
    "lines-v2.8",
    "profile-total-v2.9",
    "labels-v2.10",
    "glyphs-v2.11",
    "balance-v2.12",
    "clarity-v2.13",
    "validate-v2.14",
    "refresh-and-wide-v2.18",
)
ALLOWED_KINDS = {"transform", "validate"}
ALLOWED_SCOPES = {"wide+compact", "wide+compact-with-desktop-finalizer"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_manifest() -> dict[str, object]:
    require(MANIFEST.is_file(), f"pipeline manifest is missing: {MANIFEST.relative_to(ROOT)}")
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "pipeline manifest root must be an object")
    require(data.get("version") == PIPELINE_VERSION, "Signal Field pipeline version changed")
    require(data.get("terminal_contract") == "signal-field-v2.18+profile-refresh-v1", "pipeline terminal contract changed")
    stages = data.get("stages")
    require(isinstance(stages, list), "pipeline stages must be an array")
    require(tuple(stage.get("id") for stage in stages if isinstance(stage, dict)) == EXPECTED_STAGE_IDS, "Signal Field pipeline stage order changed")

    previous: str | None = None
    seen_scripts: set[str] = set()
    self_test_ids: list[str] = []
    for index, stage in enumerate(stages):
        require(isinstance(stage, dict), f"stage {index} must be an object")
        stage_id = stage.get("id")
        script = stage.get("script")
        kind = stage.get("kind")
        scope = stage.get("responsive_scope")
        predecessor = stage.get("required_predecessor")
        self_test_enabled = stage.get("self_test")
        require(isinstance(stage_id, str) and stage_id, f"stage {index} id is invalid")
        require(isinstance(stage.get("contract"), str) and stage.get("contract"), f"{stage_id}: contract is missing")
        require(isinstance(script, str) and script.endswith(".py"), f"{stage_id}: script is invalid")
        require(script not in seen_scripts, f"{stage_id}: script is duplicated in pipeline: {script}")
        require((SCRIPTS / script).is_file(), f"{stage_id}: script is missing: {script}")
        require(kind in ALLOWED_KINDS, f"{stage_id}: unsupported kind: {kind!r}")
        require(scope in ALLOWED_SCOPES, f"{stage_id}: unsupported responsive scope: {scope!r}")
        require(isinstance(self_test_enabled, bool), f"{stage_id}: self_test must be boolean")
        require(predecessor == previous, f"{stage_id}: predecessor must be {previous!r}, got {predecessor!r}")
        if self_test_enabled:
            self_test_ids.append(stage_id)
        seen_scripts.add(script)
        previous = stage_id
    require(tuple(self_test_ids) == EXPECTED_SELF_TEST_IDS, "Signal Field pipeline self-test coverage changed")
    return data


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


def self_test() -> None:
    data = load_manifest()
    stages = data["stages"]
    assert isinstance(stages, list)
    require(len(stages) == len(EXPECTED_STAGE_IDS), "pipeline stage count changed")
    require(stages[-1]["kind"] == "validate", "pipeline must terminate in a validation stage")
    require(stages[-1]["id"] == "validate-publishable", "pipeline terminal validator changed")
    selected = [stage for stage in stages if isinstance(stage, dict) and stage["self_test"]]
    for index, stage in enumerate(selected, start=1):
        execute(
            [sys.executable, str(SCRIPTS / str(stage["script"])), "--self-test"],
            f"[self-test {index:02d}/{len(selected):02d}] {stage['id']}: {stage['script']}",
        )
    print(
        f"Signal Field pipeline contract passed: {PIPELINE_VERSION}; "
        f"{len(stages)} ordered stages; {len(selected)} stage self-tests; "
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
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
