#!/usr/bin/env python3
"""Load the versioned profile-evidence candidate validation boundary.

The JSON manifest is the single reviewed inventory for validator order, live flags,
predicate validator identities, and the attestation validation-boundary name. This
module is dependency-free and performs no evidence mutation.
"""
from __future__ import annotations

import json
from pathlib import Path
import string
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = SCRIPTS / "profile-evidence-validation-boundary-v1.json"
VERSION = "profile-evidence-validation-boundary-v1"
PREDICATE_GROUPS = ("signalField", "engineeringSpotlight", "portfolioEvidenceLedger")
EXPECTED_STAGE_IDS = (
    "signal-field-v213",
    "signal-field-v214",
    "signal-field-publishable",
    "portfolio-ledger-live",
    "engineering-spotlight-live",
    "exact-subject-closure",
)
EXPECTED_STAGE_GROUPS = (
    "signalField",
    "signalField",
    "signalField",
    "portfolioEvidenceLedger",
    "engineeringSpotlight",
    None,
)
ALLOWED_PLACEHOLDERS = {
    "signal_field_dir",
    "spotlight_dir",
    "portfolio_ledger_dir",
    "portfolio_ledger_json",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def placeholders(value: str) -> set[str]:
    names: set[str] = set()
    for _, field_name, _, _ in string.Formatter().parse(value):
        if field_name:
            names.add(field_name)
    return names


def load_manifest() -> dict[str, Any]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(set(payload) == {"version", "description", "predicateBoundary", "stages"}, "validation boundary manifest keys changed")
    require(payload.get("version") == VERSION, "validation boundary manifest version changed")
    require(payload.get("predicateBoundary") == "attest-validated-evidence", "predicate validation boundary changed")
    description = payload.get("description")
    require(isinstance(description, str) and description, "validation boundary description is missing")
    stages = payload.get("stages")
    require(isinstance(stages, list), "validation boundary stages are missing")
    require(tuple(stage.get("id") for stage in stages if isinstance(stage, dict)) == EXPECTED_STAGE_IDS, "validation boundary stage order changed")
    require(len(stages) == len(EXPECTED_STAGE_IDS), "validation boundary stage count changed")

    observed_groups: list[str | None] = []
    for index, stage in enumerate(stages):
        require(isinstance(stage, dict), f"validation boundary stage {index} is malformed")
        require(set(stage) == {"id", "script", "args", "predicateGroup", "predicateIdentity"}, f"validation boundary stage keys changed: {stage.get('id')}")
        stage_id = stage.get("id")
        script = stage.get("script")
        args = stage.get("args")
        group = stage.get("predicateGroup")
        identity = stage.get("predicateIdentity")
        require(isinstance(stage_id, str) and stage_id, "validation boundary stage id is missing")
        require(isinstance(script, str) and script.startswith("validate-") and script.endswith(".py"), f"{stage_id}: validator script name is invalid")
        require((SCRIPTS / script).is_file(), f"{stage_id}: validator script is missing: {script}")
        require(isinstance(args, list) and args and all(isinstance(arg, str) and arg for arg in args), f"{stage_id}: validator args are invalid")
        used = set().union(*(placeholders(arg) for arg in args))
        require(used <= ALLOWED_PLACEHOLDERS, f"{stage_id}: unknown placeholder(s): {sorted(used - ALLOWED_PLACEHOLDERS)}")
        residual = "".join(args)
        for placeholder in ALLOWED_PLACEHOLDERS:
            residual = residual.replace("{" + placeholder + "}", "")
        require("{" not in residual and "}" not in residual, f"{stage_id}: malformed placeholder syntax")

        if group is None:
            require(identity is None, f"{stage_id}: non-predicate stage must not declare predicate identity")
            observed_groups.append(None)
        else:
            require(group in PREDICATE_GROUPS, f"{stage_id}: unknown predicate group: {group!r}")
            require(isinstance(identity, str) and identity.startswith(f"scripts/{script}"), f"{stage_id}: predicate identity must bind its validator script")
            if "--require-live" in args:
                require(identity.endswith(" --require-live"), f"{stage_id}: live predicate identity must record --require-live")
            else:
                require("--require-live" not in identity, f"{stage_id}: predicate identity advertises unexecuted --require-live")
            observed_groups.append(str(group))

    require(tuple(observed_groups) == EXPECTED_STAGE_GROUPS, "validation boundary predicate-group assignment changed")
    return payload


def boundary_name() -> str:
    return str(load_manifest()["predicateBoundary"])


def predicate_validators() -> dict[str, tuple[str, ...]]:
    payload = load_manifest()
    result: dict[str, list[str]] = {name: [] for name in PREDICATE_GROUPS}
    for stage in payload["stages"]:
        group = stage["predicateGroup"]
        identity = stage["predicateIdentity"]
        if group is not None:
            result[str(group)].append(str(identity))
    return {name: tuple(values) for name, values in result.items()}


def candidate_commands(*, signal_field_dir: Path, spotlight_dir: Path, portfolio_ledger_dir: Path) -> tuple[tuple[Path, tuple[str, ...]], ...]:
    payload = load_manifest()
    context = {
        "signal_field_dir": str(signal_field_dir),
        "spotlight_dir": str(spotlight_dir),
        "portfolio_ledger_dir": str(portfolio_ledger_dir),
        "portfolio_ledger_json": str(portfolio_ledger_dir / "portfolio-evidence-ledger.json"),
    }
    commands: list[tuple[Path, tuple[str, ...]]] = []
    for stage in payload["stages"]:
        script = SCRIPTS / str(stage["script"])
        args = tuple(str(arg).format(**context) for arg in stage["args"])
        commands.append((script, args))
    return tuple(commands)


def main() -> int:
    try:
        payload = load_manifest()
        validators = predicate_validators()
        require(sum(len(values) for values in validators.values()) == 5, "predicate validator identity count changed")
        print(
            f"Profile evidence validation boundary passed: {payload['version']} · "
            f"{len(payload['stages'])} ordered read-only stages · predicate boundary={payload['predicateBoundary']} · "
            f"five predicate validator identities sourced from one manifest"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
