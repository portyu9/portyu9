#!/usr/bin/env python3
"""Stage exactly the canonical eleven generated profile-evidence subjects for publication."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import stat
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


def require_unaliased(path: Path, label: str, *, strict: bool) -> Path:
    """Reject traversal/symlink aliases and return the canonical absolute path."""
    absolute = path.absolute()
    resolved = path.resolve(strict=strict)
    require(absolute == resolved, f"{label} must not resolve through symlink/traversal aliases: {path}")
    return resolved


def require_real_directory(directory: Path, label: str) -> Path:
    resolved = require_unaliased(directory, label, strict=True)
    mode = directory.lstat().st_mode
    require(stat.S_ISDIR(mode) and not directory.is_symlink(), f"{label} must be a real directory: {directory}")
    return resolved


def require_regular_file(path: Path, label: str, *, nonempty: bool = False) -> None:
    require(path.exists() or path.is_symlink(), f"{label} is missing: {path}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), f"{label} must be a real regular file: {path}")
    if nonempty:
        require(path.stat().st_size > 0, f"{label} is empty: {path}")


def top_level_files(directory: Path) -> set[str]:
    require_real_directory(directory, "profile evidence source directory")
    names: set[str] = set()
    for path in directory.iterdir():
        require_regular_file(path, "profile evidence source entry")
        names.add(path.name)
    return names


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


def prepare_destination(destination: Path) -> None:
    """Create/validate a staging root without following pre-existing path aliases."""
    parent = destination.parent if destination.parent != Path("") else Path(".")
    require_real_directory(parent, "publication destination parent")
    require(not destination.is_symlink(), f"publication destination must not be a symlink: {destination}")

    if destination.exists():
        require_real_directory(destination, "publication destination")
    else:
        # The parent is already proven real; avoid recursive mkdir so an unreviewed
        # intermediate path can never be created or traversed implicitly.
        destination.mkdir(parents=False, exist_ok=False)
        require_real_directory(destination, "publication destination")

    # A checked-out generated branch legitimately retains only its real .git directory.
    # Every other pre-existing top-level entry could redirect or collide with subjects.
    for entry in destination.iterdir():
        require(entry.name == ".git", f"publication destination contains a pre-existing unreviewed entry: {entry.name}")
        require(not entry.is_symlink() and stat.S_ISDIR(entry.lstat().st_mode),
                "publication destination .git entry must be a real directory")


def stage(destination: Path, signal_field_dir: Path, spotlight_dir: Path, portfolio_ledger_dir: Path) -> None:
    subjects.load_manifest()
    sources = {
        "signal_field": signal_field_dir,
        "engineering_spotlight": spotlight_dir,
        "portfolio_evidence_ledger": portfolio_ledger_dir,
    }
    for group_name, directory in sources.items():
        validate_source(group_name, directory)

    prepare_destination(destination)

    for group_name in subjects.EXPECTED_GROUPS:
        source_root = sources[group_name]
        for published_path in subjects.group_paths(group_name):
            source = source_root / Path(published_path).name
            # Re-prove the leaf immediately before copying; validation above must not
            # be the only protection around a filesystem operation that follows paths.
            require_regular_file(source, "publishable subject", nonempty=True)
            target = destination / published_path
            require(not target.exists() and not target.is_symlink(), f"publish target already exists: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            require_real_directory(target.parent, "publish target parent")
            shutil.copyfile(source, target)
            require_regular_file(target, "staged publish subject", nonempty=True)

    subjects.validate_published_root(destination)
    print(
        f"Profile evidence publication staged: {subjects.VERSION} · "
        f"{len(subjects.published_paths())} exact subjects · sha256:{subjects.manifest_digest()}"
    )


def expect_stage_failure(
    destination: Path,
    signal: Path,
    spotlight: Path,
    ledger: Path,
    expected: str,
) -> None:
    try:
        stage(destination, signal, spotlight, ledger)
    except ValueError as exc:
        require(expected in str(exc), f"publication staging self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"publication staging self-test accepted unsafe filesystem shape: {expected}")


def fixture_sources(root: Path) -> tuple[Path, Path, Path]:
    signal = root / "signal"
    spotlight = root / "spotlight"
    ledger = root / "ledger"
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
    return signal, spotlight, ledger


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        signal, spotlight, ledger = fixture_sources(root)
        destination = root / "published"
        stage(destination, signal, spotlight, ledger)
        subjects.validate_published_root(destination)
        require(not (destination / "engineering-spotlight/spotlight-manifest.json").exists(),
                "internal Spotlight manifest reached publication")

        # A source leaf symlink must not inherit regular-file status from its target.
        source_leaf = signal / subjects.source_basenames("signal_field")[0]
        source_bytes = source_leaf.read_bytes()
        external_leaf = root / "external-source.svg"
        external_leaf.write_bytes(source_bytes)
        source_leaf.unlink()
        source_leaf.symlink_to(external_leaf)
        expect_stage_failure(root / "symlink-source-dest", signal, spotlight, ledger, "real regular file")
        source_leaf.unlink()
        source_leaf.write_bytes(source_bytes)

        # A source directory alias must not be trusted merely because is_dir() follows it.
        real_signal = root / "real-signal"
        signal.rename(real_signal)
        signal.symlink_to(real_signal, target_is_directory=True)
        expect_stage_failure(root / "symlink-root-dest", signal, spotlight, ledger, "symlink/traversal aliases")
        signal.unlink()
        real_signal.rename(signal)

        # A destination symlink could otherwise redirect all publication writes.
        external_destination = root / "external-destination"
        external_destination.mkdir()
        destination_alias = root / "destination-alias"
        destination_alias.symlink_to(external_destination, target_is_directory=True)
        expect_stage_failure(destination_alias, signal, spotlight, ledger, "must not be a symlink")

        # Pre-existing subject trees are rejected before any target path is opened.
        occupied = root / "occupied"
        occupied.mkdir()
        (occupied / "profile-stats").mkdir()
        expect_stage_failure(occupied, signal, spotlight, ledger, "pre-existing unreviewed entry")

        # The generated-branch checkout shape may retain only a real .git directory.
        checkout = root / "checkout"
        checkout.mkdir()
        (checkout / ".git").mkdir()
        stage(checkout, signal, spotlight, ledger)
        subjects.validate_published_root(checkout)
    print("Profile evidence publication staging self-test passed: sources and destination are real, unaliased filesystem objects")


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
