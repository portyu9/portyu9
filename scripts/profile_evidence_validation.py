#!/usr/bin/env python3
"""Load the versioned profile-evidence candidate validation boundary.

The JSON manifest is the single reviewed inventory for validator order, live flags,
predicate validator identities, and the attestation validation-boundary name. This
module is dependency-free and performs no evidence mutation.
"""
from __future__ import annotations

import json
from pathlib import Path
import stat
import string
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = SCRIPTS / "profile-evidence-validation-boundary-v1.json"
VERSION = "profile-evidence-validation-boundary-v1"
PREDICATE_GROUPS = ("signalField", "engineeringSpotlight", "portfolioEvidenceLedger")
EXPECTED_STAGE_CONTRACT = (
    (
        "signal-field-v213",
        "validate-signal-field-v213.py",
        ("{signal_field_dir}",),
        "signalField",
        "scripts/validate-signal-field-v213.py",
    ),
    (
        "signal-field-v214",
        "validate-signal-field-v214.py",
        ("{signal_field_dir}",),
        "signalField",
        "scripts/validate-signal-field-v214.py",
    ),
    (
        "signal-field-publishable",
        "validate-generated-signal-field.py",
        ("{signal_field_dir}",),
        "signalField",
        "scripts/validate-generated-signal-field.py",
    ),
    (
        "portfolio-ledger-live",
        "validate-portfolio-evidence-ledger.py",
        ("{portfolio_ledger_dir}", "--require-live"),
        "portfolioEvidenceLedger",
        "scripts/validate-portfolio-evidence-ledger.py --require-live",
    ),
    (
        "engineering-spotlight-live",
        "validate-engineering-spotlight.py",
        ("{spotlight_dir}", "--require-live", "--ledger", "{portfolio_ledger_json}"),
        "engineeringSpotlight",
        "scripts/validate-engineering-spotlight.py --require-live",
    ),
    (
        "exact-subject-closure",
        "validate-profile-evidence-subjects.py",
        (
            "--signal-field-dir",
            "{signal_field_dir}",
            "--spotlight-dir",
            "{spotlight_dir}",
            "--portfolio-ledger-dir",
            "{portfolio_ledger_dir}",
        ),
        None,
        None,
    ),
)
EXPECTED_STAGE_IDS = tuple(item[0] for item in EXPECTED_STAGE_CONTRACT)
EXPECTED_STAGE_GROUPS = tuple(item[3] for item in EXPECTED_STAGE_CONTRACT)
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


def require_real_validator(script: str, stage_id: str) -> None:
    path = SCRIPTS / script
    require(path.exists() or path.is_symlink(), f"{stage_id}: validator script is missing: {script}")
    require(path.absolute() == path.resolve(strict=True),
            f"{stage_id}: validator script must not resolve through a symlink/traversal alias: {script}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(),
            f"{stage_id}: validator script must be a real regular repository file: {script}")


def validate_manifest(payload: Any, *, verify_scripts: bool = True) -> dict[str, Any]:
    require(isinstance(payload, dict), "validation boundary manifest root must be an object")
    require(set(payload) == {"version", "description", "predicateBoundary", "stages"}, "validation boundary manifest keys changed")
    require(payload.get("version") == VERSION, "validation boundary manifest version changed")
    require(payload.get("predicateBoundary") == "attest-validated-evidence", "predicate validation boundary changed")
    description = payload.get("description")
    require(isinstance(description, str) and description, "validation boundary description is missing")
    stages = payload.get("stages")
    require(isinstance(stages, list), "validation boundary stages are missing")
    require(tuple(stage.get("id") for stage in stages if isinstance(stage, dict)) == EXPECTED_STAGE_IDS, "validation boundary stage order changed")
    require(len(stages) == len(EXPECTED_STAGE_CONTRACT), "validation boundary stage count changed")

    observed_groups: list[str | None] = []
    for index, (stage, expected) in enumerate(zip(stages, EXPECTED_STAGE_CONTRACT, strict=True)):
        require(isinstance(stage, dict), f"validation boundary stage {index} is malformed")
        require(set(stage) == {"id", "script", "args", "predicateGroup", "predicateIdentity"}, f"validation boundary stage keys changed: {stage.get('id')}")
        stage_id = stage.get("id")
        script = stage.get("script")
        args = stage.get("args")
        group = stage.get("predicateGroup")
        identity = stage.get("predicateIdentity")
        expected_id, expected_script, expected_args, expected_group, expected_identity = expected

        require(stage_id == expected_id, f"validation boundary stage id changed at index {index}")
        require(script == expected_script, f"{expected_id}: validator script authority changed: {script!r}")
        require(isinstance(args, list) and tuple(args) == expected_args,
                f"{expected_id}: validator argument vector changed: {args!r}")
        require(group == expected_group, f"{expected_id}: predicate group authority changed: {group!r}")
        require(identity == expected_identity, f"{expected_id}: predicate validator identity changed: {identity!r}")
        if verify_scripts:
            require_real_validator(expected_script, expected_id)

        require(all(isinstance(arg, str) and arg for arg in args), f"{expected_id}: validator args are invalid")
        used = set().union(*(placeholders(arg) for arg in args))
        require(used <= ALLOWED_PLACEHOLDERS, f"{expected_id}: unknown placeholder(s): {sorted(used - ALLOWED_PLACEHOLDERS)}")
        residual = "".join(args)
        for placeholder in ALLOWED_PLACEHOLDERS:
            residual = residual.replace("{" + placeholder + "}", "")
        require("{" not in residual and "}" not in residual, f"{expected_id}: malformed placeholder syntax")

        if group is None:
            require(identity is None, f"{expected_id}: non-predicate stage must not declare predicate identity")
            observed_groups.append(None)
        else:
            require(group in PREDICATE_GROUPS, f"{expected_id}: unknown predicate group: {group!r}")
            require(isinstance(identity, str) and identity.startswith(f"scripts/{script}"), f"{expected_id}: predicate identity must bind its validator script")
            if "--require-live" in args:
                require(identity.endswith(" --require-live"), f"{expected_id}: live predicate identity must record --require-live")
            else:
                require("--require-live" not in identity, f"{expected_id}: predicate identity advertises unexecuted --require-live")
            observed_groups.append(str(group))

    require(tuple(observed_groups) == EXPECTED_STAGE_GROUPS, "validation boundary predicate-group assignment changed")
    return payload


def load_manifest() -> dict[str, Any]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return validate_manifest(payload)


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


def expect_manifest_failure(payload: dict[str, Any], expected: str) -> None:
    try:
        validate_manifest(payload, verify_scripts=False)
    except ValueError as exc:
        require(expected in str(exc), f"validation-boundary self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"validation-boundary self-test accepted authority drift: {expected}")


def self_test(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload)

    script_drift = json.loads(encoded)
    script_drift["stages"][0]["script"] = "validate-generated-signal-field.py"
    script_drift["stages"][0]["predicateIdentity"] = "scripts/validate-generated-signal-field.py"
    expect_manifest_failure(script_drift, "validator script authority changed")

    args_drift = json.loads(encoded)
    args_drift["stages"][3]["args"] = ["{portfolio_ledger_dir}"]
    args_drift["stages"][3]["predicateIdentity"] = "scripts/validate-portfolio-evidence-ledger.py"
    expect_manifest_failure(args_drift, "validator argument vector changed")

    group_drift = json.loads(encoded)
    group_drift["stages"][4]["predicateGroup"] = "portfolioEvidenceLedger"
    expect_manifest_failure(group_drift, "predicate group authority changed")

    identity_drift = json.loads(encoded)
    identity_drift["stages"][1]["predicateIdentity"] = "scripts/validate-signal-field-v214.py --require-live"
    expect_manifest_failure(identity_drift, "predicate validator identity changed")


def main() -> int:
    try:
        payload = load_manifest()
        validators = predicate_validators()
        require(sum(len(values) for values in validators.values()) == 5, "predicate validator identity count changed")
        self_test(payload)
        print(
            f"Profile evidence validation boundary passed: {payload['version']} · "
            f"{len(payload['stages'])} exact ordered read-only stages · predicate boundary={payload['predicateBoundary']} · "
            f"scripts/args/groups/identities authority-locked and five predicate validators sourced from one manifest"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
