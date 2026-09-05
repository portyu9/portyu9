#!/usr/bin/env python3
"""Stage exactly the canonical eleven generated profile-evidence subjects for publication."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys
import tempfile

import profile_evidence_subjects as subjects


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--signal-field-dir", type=Path, required=True)
    parser.add_argument("--spotlight-dir", type=Path, required=True)
    parser.add_argument("--portfolio-ledger-dir", type=Path, required=True)
    return parser.parse_args()


def top_level_files(directory: Path) -> set[str]:
    require(directory.is_dir(), f"profile evidence source directory is missing: {directory}")
    return {path.name for path in directory.iterdir() if path.is_file()}


def allowed_internal_basenames(group_name: str) -> set[str]:
    prefix = {
        "signal_field": "profile-stats/profile/",
        "engineering_spotlight": "engineering-spotlight/",
        "portfolio_evidence_ledger": "portfolio-evidence/",
    }[group_name]
    return {
        Path(path).name
        for path in subjects.internal_artifacts()
        if path.startswith(prefix)
    }


def validate_source(group_name: str, directory: Path) -> None:
    expected = set(subjects.source_basenames(group_name))
    internal = allowed_internal_basenames(group_name)
    actual = top_level_files(directory)
    require(expected <= actual, f"{group_name} source is missing publishable subjects: {sorted(expected - actual)}")
    require(actual <= expected | internal, f"{group_name} source contains unreviewed artifacts: {sorted(actual - expected - internal)}")
    if internal:
        require(internal <= actual, f"{group_name} source is missing reviewed internal artifacts: {sorted(internal - actual)}")


def stage(destination: Path, signal_field_dir: Path, spotlight_dir: Path, portfolio_ledger_dir: Path) -> None:
    subjects.load_manifest()
    sources = {
        "signal_field": signal_field_dir,
        "engineering_spotlight": spotlight_dir,
        "portfolio_evidence_ledger": portfolio_ledger_dir,
    }
    for group_name, directory in sources.items():
        validate_source(group_name, directory)

    destination.mkdir(parents=True, exist_ok=True)
    existing = set(subjects.relative_files(destination))
    require(not existing, f"publication destination must be empty before staging; found: {sorted(existing)}")

    for group_name in subjects.EXPECTED_GROUPS:
        source_root = sources[group_name]
        for published_path in subjects.group_paths(group_name):
            source = source_root / Path(published_path).name
            require(source.is_file() and source.stat().st_size > 0, f"publishable subject is missing or empty: {source}")
            target = destination / published_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    subjects.validate_published_root(destination)
    print(
        f"Profile evidence publication staged: {subjects.VERSION} · "
        f"{len(subjects.published_paths())} exact subjects · sha256:{subjects.manifest_digest()}"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        signal = root / "signal"
        spotlight = root / "spotlight"
        ledger = root / "ledger"
        destination = root / "published"
        for directory in (signal, spotlight, ledger):
            directory.mkdir()
        sources = {
            "signal_field": signal,
            "engineering_spotlight": spotlight,
            "portfolio_evidence_ledger": ledger,
        }
        for group_name, directory in sources.items():
            for basename in subjects.source_basenames(group_name):
                (directory / basename).write_text(f"fixture:{basename}\n", encoding="utf-8")
        for path in subjects.internal_artifacts():
            if path.startswith("engineering-spotlight/"):
                (spotlight / Path(path).name).write_text("{}\n", encoding="utf-8")
        stage(destination, signal, spotlight, ledger)
        subjects.validate_published_root(destination)
        require(not (destination / "engineering-spotlight/spotlight-manifest.json").exists(), "internal Spotlight manifest reached publication")
    print("Profile evidence publication staging self-test passed")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        args = parse_args()
        stage(args.destination, args.signal_field_dir, args.spotlight_dir, args.portfolio_ledger_dir)
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
