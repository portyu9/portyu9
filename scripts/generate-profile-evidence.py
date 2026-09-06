#!/usr/bin/env python3
"""Run the canonical authored profile-evidence generation pipeline.

The reviewed third-party Signal Field Action remains outside this script. It supplies an
existing candidate directory; this orchestrator owns all authored generation sequencing
after that boundary: Signal Field transformation/validation, one Portfolio Evidence
Ledger snapshot, and the Engineering Spotlight projection from that exact Ledger.

Generation outputs are destructive-reset workspaces. They are therefore constrained to
non-symlink direct children of the current execution workspace and revalidated at the
exact deletion boundary before any ``shutil.rmtree`` call.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import string
import subprocess
import sys
import tempfile
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MANIFEST = SCRIPTS / "profile-evidence-generation-v1.json"
VERSION = "profile-evidence-generation-v1"
EXPECTED_STAGE_IDS = (
    "signal-field-pipeline",
    "portfolio-ledger-generate",
    "portfolio-ledger-validate",
    "engineering-spotlight-generate",
    "engineering-spotlight-validate",
)
EXPECTED_KINDS = ("transform-validate", "generate", "validate", "generate", "validate")
ALLOWED_PLACEHOLDERS = {
    "signal_field_dir",
    "portfolio_ledger_dir",
    "portfolio_ledger_json",
    "spotlight_dir",
    "date",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def placeholders(value: str) -> set[str]:
    result: set[str] = set()
    for _, field_name, _, _ in string.Formatter().parse(value):
        if field_name:
            result.add(field_name)
    return result


def load_manifest() -> dict[str, Any]:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(set(payload) == {"version", "description", "stages"}, "generation manifest keys changed")
    require(payload.get("version") == VERSION, "generation manifest version changed")
    require(isinstance(payload.get("description"), str) and payload["description"], "generation manifest description is missing")
    stages = payload.get("stages")
    require(isinstance(stages, list) and len(stages) == len(EXPECTED_STAGE_IDS), "generation stage count changed")
    require(tuple(stage.get("id") for stage in stages if isinstance(stage, dict)) == EXPECTED_STAGE_IDS, "generation stage order changed")

    for index, stage in enumerate(stages):
        require(isinstance(stage, dict), f"generation stage {index} is malformed")
        require(
            set(stage) == {"id", "script", "kind", "liveArgs", "offlineArgs"},
            f"generation stage keys changed: {stage.get('id')}",
        )
        stage_id = stage["id"]
        script = stage["script"]
        require(stage.get("kind") == EXPECTED_KINDS[index], f"{stage_id}: generation stage kind changed")
        require(isinstance(script, str) and script.endswith(".py"), f"{stage_id}: script name is invalid")
        require((SCRIPTS / script).is_file(), f"{stage_id}: script is missing: {script}")
        for mode_key in ("liveArgs", "offlineArgs"):
            args = stage.get(mode_key)
            require(isinstance(args, list) and args and all(isinstance(arg, str) and arg for arg in args), f"{stage_id}: {mode_key} is invalid")
            used = set().union(*(placeholders(arg) for arg in args))
            require(used <= ALLOWED_PLACEHOLDERS, f"{stage_id}: unknown placeholder(s): {sorted(used - ALLOWED_PLACEHOLDERS)}")
            residual = "".join(args)
            for placeholder in ALLOWED_PLACEHOLDERS:
                residual = residual.replace("{" + placeholder + "}", "")
            require("{" not in residual and "}" not in residual, f"{stage_id}: malformed placeholder syntax")

    live = {stage["id"]: stage["liveArgs"] for stage in stages}
    offline = {stage["id"]: stage["offlineArgs"] for stage in stages}
    require("--require-live" in live["portfolio-ledger-validate"], "live Ledger validation must require live evidence")
    require("--require-live" in live["engineering-spotlight-validate"], "live Spotlight validation must require live evidence")
    require("--require-live" not in offline["portfolio-ledger-validate"], "offline Ledger validation must not claim live evidence")
    require("--require-live" not in offline["engineering-spotlight-validate"], "offline Spotlight validation must not claim live evidence")
    require("--offline" in offline["portfolio-ledger-generate"], "offline generation must use synthetic Ledger evidence")
    require("--offline" not in live["portfolio-ledger-generate"], "live generation must not use synthetic Ledger evidence")
    return payload


def manifest_digest() -> str:
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def command_plan(
    *,
    signal_field_dir: Path,
    portfolio_ledger_dir: Path,
    spotlight_dir: Path,
    day: dt.date,
    offline: bool,
) -> tuple[tuple[str, Path, tuple[str, ...]], ...]:
    payload = load_manifest()
    context = {
        "signal_field_dir": str(signal_field_dir),
        "portfolio_ledger_dir": str(portfolio_ledger_dir),
        "portfolio_ledger_json": str(portfolio_ledger_dir / "portfolio-evidence-ledger.json"),
        "spotlight_dir": str(spotlight_dir),
        "date": day.isoformat(),
    }
    mode_key = "offlineArgs" if offline else "liveArgs"
    plan: list[tuple[str, Path, tuple[str, ...]]] = []
    for stage in payload["stages"]:
        args = tuple(str(value).format(**context) for value in stage[mode_key])
        plan.append((str(stage["id"]), SCRIPTS / str(stage["script"]), args))
    return tuple(plan)


def paths_overlap(left: Path, right: Path) -> bool:
    """Return whether either resolved path contains the other."""
    return left == right or left in right.parents or right in left.parents


def safe_output_path(
    raw: Path,
    *,
    label: str,
    workspace: Path,
    protected: Iterable[Path] = (),
) -> Path:
    """Resolve and prove a destructive generation output is a safe workspace child."""
    workspace_resolved = workspace.resolve()
    require(".." not in raw.parts, f"{label} output path must not contain parent traversal: {raw}")
    require(not raw.is_symlink(), f"{label} output path must not be a symlink: {raw}")
    resolved = raw.resolve()
    require(resolved != workspace_resolved, f"{label} output path must not be the execution workspace")
    require(
        resolved.parent == workspace_resolved,
        f"{label} output must be a direct child of the execution workspace: {resolved}",
    )
    require(resolved not in {ROOT.resolve(), SCRIPTS.resolve()}, f"{label} output path is a protected repository path")
    for candidate in protected:
        candidate_resolved = candidate.resolve()
        require(
            not paths_overlap(resolved, candidate_resolved),
            f"{label} output overlaps protected input/output path: {candidate_resolved}",
        )
    if raw.exists() or raw.is_symlink():
        require(not raw.is_symlink(), f"{label} output path must not resolve through a symlink: {raw}")
        require(raw.is_dir(), f"{label} output exists but is not a directory: {raw}")
    return resolved


def validate_paths(
    signal_field_dir: Path,
    portfolio_ledger_dir: Path,
    spotlight_dir: Path,
    *,
    workspace: Path | None = None,
) -> tuple[Path, Path, Path]:
    execution_root = (workspace or Path.cwd()).resolve()
    require(signal_field_dir.is_dir(), f"upstream Signal Field candidate directory is missing: {signal_field_dir}")
    signal = signal_field_dir.resolve()
    require(signal not in {execution_root, ROOT.resolve(), SCRIPTS.resolve()}, "Signal Field candidate must not be a workspace/repository/scripts root")

    ledger = safe_output_path(
        portfolio_ledger_dir,
        label="Portfolio Ledger",
        workspace=execution_root,
        protected=(signal, spotlight_dir),
    )
    spotlight = safe_output_path(
        spotlight_dir,
        label="Spotlight",
        workspace=execution_root,
        protected=(signal, portfolio_ledger_dir),
    )
    require(len({signal, ledger, spotlight}) == 3, "generation input/output directories must be distinct")
    return signal, ledger, spotlight


def reset_output(
    path: Path,
    *,
    label: str,
    workspace: Path,
    protected: Iterable[Path],
) -> Path:
    """Defense-in-depth safety proof at the exact destructive reset boundary."""
    resolved = safe_output_path(path, label=label, workspace=workspace, protected=protected)
    if resolved.exists():
        require(resolved.is_dir() and not resolved.is_symlink(), f"{label} generation output is not a safe directory: {resolved}")
        shutil.rmtree(resolved)
    resolved.mkdir(parents=False, exist_ok=False)
    return resolved


def expect_path_failure(callable_obj, expected: str) -> None:
    try:
        callable_obj()
    except ValueError as exc:
        require(expected in str(exc), f"path-safety self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"path-safety self-test accepted unsafe output: {expected}")


def self_test() -> None:
    payload = load_manifest()
    plan_live = command_plan(
        signal_field_dir=Path("fixture-signal"),
        portfolio_ledger_dir=Path("fixture-ledger"),
        spotlight_dir=Path("fixture-spotlight"),
        day=dt.date(2026, 9, 4),
        offline=False,
    )
    plan_offline = command_plan(
        signal_field_dir=Path("fixture-signal"),
        portfolio_ledger_dir=Path("fixture-ledger"),
        spotlight_dir=Path("fixture-spotlight"),
        day=dt.date(2026, 9, 4),
        offline=True,
    )
    require(tuple(item[0] for item in plan_live) == EXPECTED_STAGE_IDS, "live generation plan order changed")
    require(tuple(item[0] for item in plan_offline) == EXPECTED_STAGE_IDS, "offline generation plan order changed")
    require("--offline" not in plan_live[1][2] and "--offline" in plan_offline[1][2], "Ledger live/offline mode separation changed")
    require("--require-live" in plan_live[2][2] and "--require-live" not in plan_offline[2][2], "Ledger validation mode separation changed")
    require("--require-live" in plan_live[4][2] and "--require-live" not in plan_offline[4][2], "Spotlight validation mode separation changed")
    require("2026-09-04" in plan_live[1][2] and "2026-09-04" in plan_live[3][2], "generation date is not bound across Ledger and Spotlight")

    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        signal = workspace / "signal"
        signal.mkdir()
        ledger = workspace / "ledger"
        spotlight = workspace / "spotlight"
        _, resolved_ledger, resolved_spotlight = validate_paths(signal, ledger, spotlight, workspace=workspace)
        require(resolved_ledger == ledger.resolve() and resolved_spotlight == spotlight.resolve(), "safe direct-child outputs did not resolve canonically")

        nested = workspace / "nested" / "ledger"
        expect_path_failure(
            lambda: safe_output_path(nested, label="nested", workspace=workspace),
            "direct child",
        )
        expect_path_failure(
            lambda: safe_output_path(workspace, label="root", workspace=workspace),
            "execution workspace",
        )
        expect_path_failure(
            lambda: safe_output_path(Path("..") / workspace.name / "escape", label="traversal", workspace=workspace),
            "parent traversal",
        )
        outside = workspace.parent / f"{workspace.name}-outside"
        expect_path_failure(
            lambda: safe_output_path(outside, label="outside", workspace=workspace),
            "direct child",
        )
        overlap = workspace / "overlap"
        overlap.mkdir()
        child_signal = overlap / "signal"
        child_signal.mkdir()
        expect_path_failure(
            lambda: safe_output_path(overlap, label="overlap", workspace=workspace, protected=(child_signal,)),
            "overlaps protected",
        )

        link = workspace / "linked-output"
        try:
            link.symlink_to(workspace / "real-output", target_is_directory=True)
        except (OSError, NotImplementedError):
            pass
        else:
            expect_path_failure(
                lambda: safe_output_path(link, label="symlink", workspace=workspace),
                "symlink",
            )

        ledger.mkdir()
        sentinel = ledger / "sentinel"
        sentinel.write_text("remove me\n", encoding="utf-8")
        reset = reset_output(
            ledger,
            label="Portfolio Ledger",
            workspace=workspace,
            protected=(signal, spotlight),
        )
        require(reset == ledger.resolve() and reset.is_dir(), "safe destructive reset did not recreate output directory")
        require(not sentinel.exists(), "safe destructive reset did not remove stale output")

    print(
        f"Profile evidence generation contract passed: {payload['version']} · {len(plan_live)} ordered authored stages · "
        f"manifest_sha256={manifest_digest()} · live/offline policies separated · destructive outputs workspace-contained"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal-field-dir", type=Path)
    parser.add_argument("--portfolio-ledger-dir", type=Path)
    parser.add_argument("--spotlight-dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Use synthetic Ledger evidence; Signal Field input must still be pre-generated")
    parser.add_argument("--self-test", action="store_true", help="Validate the generation manifest and command plans without executing stages")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            require(args.signal_field_dir is None and args.portfolio_ledger_dir is None and args.spotlight_dir is None and args.date is None and not args.offline, "--self-test cannot be combined with generation arguments")
            self_test()
            return 0

        require(args.signal_field_dir is not None, "--signal-field-dir is required")
        require(args.portfolio_ledger_dir is not None, "--portfolio-ledger-dir is required")
        require(args.spotlight_dir is not None, "--spotlight-dir is required")
        day = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.timezone.utc).date()
        workspace = Path.cwd().resolve()
        signal, ledger, spotlight = validate_paths(
            args.signal_field_dir,
            args.portfolio_ledger_dir,
            args.spotlight_dir,
            workspace=workspace,
        )
        reset_output(
            args.portfolio_ledger_dir,
            label="Portfolio Ledger",
            workspace=workspace,
            protected=(signal, spotlight),
        )
        reset_output(
            args.spotlight_dir,
            label="Spotlight",
            workspace=workspace,
            protected=(signal, ledger),
        )
        plan = command_plan(
            signal_field_dir=args.signal_field_dir,
            portfolio_ledger_dir=args.portfolio_ledger_dir,
            spotlight_dir=args.spotlight_dir,
            day=day,
            offline=args.offline,
        )
        mode = "offline" if args.offline else "live"
        print(
            f"Profile evidence generation {VERSION} start · {mode} · date={day.isoformat()} · "
            f"manifest_sha256={manifest_digest()}",
            flush=True,
        )
        for index, (stage_id, script, command_args) in enumerate(plan, start=1):
            print(f"[profile-evidence-generation {index:02d}/{len(plan):02d}] {stage_id}: {script.name}", flush=True)
            subprocess.run([sys.executable, str(script), *command_args], check=True)
        print(f"Profile evidence generation complete: {VERSION} · {len(plan)} ordered authored stages · {mode}")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: profile evidence generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
