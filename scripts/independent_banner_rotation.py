#!/usr/bin/env python3
"""Prepare and re-prove a banner-only UTC-day README PR, independent of CI/ledger.

This program reads the already approved asset catalog. It never fetches external
CI/Security evidence, modifies the Spotlight set, or changes the publication
epoch. The output is only an exact README proposal plus a bound manifest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, date
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import approved_banner_rotation as approved
import independent_banner_candidate_contract as banner_candidate

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{40}$")
MARKER = re.compile(r"<!-- banner-rotation:v[3-8] utc-day=\d{4}-\d{2}-\d{2} slot=\d+ slug=[a-z0-9-]+ -->")


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def git_head() -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()


def only_banner_changes(before: str, after: str) -> None:
    """Exactly the banner marker and three approved SVG paths may change."""
    def canonical(text: str) -> str:
        require(len(MARKER.findall(text)) == 1, "banner marker inventory changed")
        stripped, n = MARKER.subn("<!-- approved-banner-marker -->", text)
        require(n == 1, "banner marker is missing")
        for surface, expression in approved.historical.BANNER_REFERENCE.items():
            stripped, n = expression.subn(
                lambda m: m.group(1) + "<approved-" + surface + ">", stripped
            )
            require(n == 1, f"{surface}: exactly one reviewed image required")
        return stripped

    require(canonical(before) == canonical(after),
            "independent banner proposal touched non-banner README content")


def proposal(base_sha: str, day: date) -> tuple[str, dict[str, object]]:
    require(bool(SHA.fullmatch(base_sha)), "base SHA must be exact hexadecimal Git identity")
    require(git_head() == base_sha, "source checkout differs from exact accepted main")
    slots = approved.load_catalog()
    approved.validate_assets(slots)
    source = approved.read_file(ROOT / "README.md")
    selected = approved.chosen(day, slots)
    candidate = approved.propose(source, selected, slots)
    only_banner_changes(source, candidate)
    manifest = {
        "schemaVersion": 1,
        "baseSha": base_sha,
        "utcDay": day.isoformat(),
        "slot": selected["slot"],
        "slug": selected["slug"],
        "inputSha256": digest(source),
        "outputSha256": digest(candidate),
        "changed": candidate != source,
        "scope": "exact-approved-banner-triplet-only",
    }
    return candidate, manifest


def check_dir(directory: Path) -> None:
    require(directory.is_dir() and not directory.is_symlink(),
            "banner candidate directory is missing or aliased")
    require(sorted(p.name for p in directory.iterdir()) == ["README.md", "plan.json"],
            "banner candidate inventory differs from exact README and plan")
    for name in ("README.md", "plan.json"):
        p = directory / name
        require(p.is_file() and not p.is_symlink(), f"untrusted banner artifact type: {name}")


def verify(directory: Path, base_sha: str, day: date) -> dict[str, object]:
    check_dir(directory)
    expected, metadata = proposal(base_sha, day)
    actual = (directory / "README.md").read_text(encoding="utf-8")
    obj = json.loads((directory / "plan.json").read_text(encoding="utf-8"))
    require(type(obj) is dict and obj == metadata, "banner plan is stale or forged")
    require(actual == expected and digest(actual) == metadata["outputSha256"],
            "banner proposal no longer matches trusted approved selector")
    return metadata


def self_test() -> None:
    slots = approved.load_catalog()
    approved.validate_assets(slots)
    approved.self_test(slots)
    source = approved.read_file(ROOT / "README.md")
    approved.validate_readme_state(source, slots)
    marker = approved.MARKER.search(source)
    day = date.fromisoformat(marker.group(2)) if marker else approved.EPOCH
    correct = approved.propose(source, approved.chosen(day, slots), slots)
    only_banner_changes(source, correct)
    for approved_version in ("v7", "v8"):
        marker_fixture = (
            "<!-- banner-rotation:" + approved_version
            + " utc-day=2026-10-24 slot=1 slug=01-luminous-singularity -->"
        )
        require(MARKER.fullmatch(marker_fixture) is not None,
                f"historical/present banner marker version rejected: {approved_version}")
    require(MARKER.fullmatch(
        "<!-- banner-rotation:v9 utc-day=2026-10-24 slot=1 slug=01-luminous-singularity -->"
    ) is None, "unreviewed future banner marker version accepted")
    require(only_banner_changes.__name__ == "only_banner_changes", "scope guard renamed")
    corrupt = correct.replace("© 2026", "© 2027", 1)
    require(corrupt != correct, "non-banner mutation fixture is ineffective")
    try:
        only_banner_changes(source, corrupt)
    except ValueError as exc:
        require("non-banner" in str(exc), "scope mutation rejected for wrong reason")
    else:
        raise ValueError("scope guard admitted non-banner README mutation")
    require(approved.propose(correct, approved.chosen(day, slots), slots) == correct,
            "independent banner PR must be idempotent")
    banner_candidate.self_test()
    # This existing protected-quality self-test entrypoint also exercises the
    # read-only native reviewer/terminal admission against approved artwork.
    # Imported lazily: ordinary daily proposal and verification remain isolated
    # from review snapshot processing and retain zero privileged API access.
    import banner_native_live_admission
    banner_native_live_admission.self_test()


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--self-test", action="store_true")
    g.add_argument("--plan", type=Path)
    g.add_argument("--verify", type=Path)
    ap.add_argument("--base-sha")
    ap.add_argument("--date")
    args = ap.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Banner-only approved triplet invariants passed")
            return 0
        require(args.base_sha is not None and bool(SHA.fullmatch(args.base_sha)),
                "exact base SHA required")
        day = date.fromisoformat(args.date) if args.date else datetime.now(timezone.utc).date()
        if args.verify is not None:
            plan = verify(args.verify, args.base_sha, day)
        else:
            destination = args.plan
            require(destination is not None and not destination.exists(),
                    "banner staging directory must not preexist")
            candidate, plan = proposal(args.base_sha, day)
            destination.mkdir(parents=True)
            (destination / "README.md").write_text(candidate, encoding="utf-8")
            (destination / "plan.json").write_text(
                json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            check_dir(destination)
        print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        print(f"ERROR: independent approved banner rotation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
