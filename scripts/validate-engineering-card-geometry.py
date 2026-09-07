#!/usr/bin/env python3
"""Validate the shared 620×198 geometry contract for engineering profile cards."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FLAGSHIP_SVGS = (
    "assets/profile-systems/qualification-ai-qa-control-plane-light.svg",
    "assets/profile-systems/qualification-ai-qa-control-plane-dark.svg",
    "assets/profile-systems/qualification-agent-evaluation-tevv-light.svg",
    "assets/profile-systems/qualification-agent-evaluation-tevv-dark.svg",
    "assets/profile-systems/qualification-graphql-qe-light.svg",
    "assets/profile-systems/qualification-graphql-qe-dark.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe-light.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe-dark.svg",
)
SPOTLIGHT_SVGS = tuple(
    f"spotlight-{slot}-{theme}.svg"
    for slot in range(1, 4)
    for theme in ("light", "dark")
)
CANVAS = 'width="620" height="198" viewBox="0 0 620 198"'
FLAGSHIP_OUTER = '<rect x="1" y="1" width="618" height="196"'
FLAGSHIP_WASH = '<rect x="2" y="2" width="616" height="194"'
FLAGSHIP_RAIL = '<rect x="20" y="20" width="4" height="158"'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_svg(path: Path, label: str) -> str:
    require(path.is_file(), f"{label} is missing: {path}")
    require(not path.is_symlink(), f"{label} must be a real repository/artifact file: {path}")
    content = path.read_text(encoding="utf-8")
    require(content.startswith("<svg "), f"{label} is not an SVG root: {path}")
    require(CANVAS in content.splitlines()[0], f"{label} must use exact 620×198 geometry: {path}")
    return content


def validate_flagships() -> None:
    for relative in FLAGSHIP_SVGS:
        content = read_svg(ROOT / relative, "flagship engineering card")
        require('data-system-card="selected-engineering-systems-v4"' in content,
                f"flagship system-card identity changed: {relative}")
        require(FLAGSHIP_OUTER in content, f"flagship outer surface no longer fills 620×198 canvas: {relative}")
        require(FLAGSHIP_WASH in content, f"flagship wash no longer fills 620×198 canvas: {relative}")
        require(FLAGSHIP_RAIL in content, f"flagship rail no longer preserves 20px vertical insets: {relative}")
        require(content.count(' y="132"') == 3,
                f"flagship capability row must occupy the reviewed y=132 band: {relative}")
        require(content.count(' y="152"') == 3,
                f"flagship capability labels must occupy the reviewed y=152 baseline: {relative}")


def validate_spotlights(directory: Path) -> None:
    require(directory.is_dir(), f"generated Spotlight directory is missing: {directory}")
    for basename in SPOTLIGHT_SVGS:
        content = read_svg(directory / basename, "generated Spotlight card")
        require('data-spotlight="engineering-spotlight-v2.1"' in content,
                f"generated Spotlight identity changed: {basename}")
        require('data-status-presentation="external-clickable-only"' in content,
                f"generated Spotlight status presentation must remain external/clickable: {basename}")
        require(content.count(' y="166"') == 2,
                f"generated Spotlight provenance row must occupy the reviewed y=166 band: {basename}")
        require(' y="145"' not in content,
                f"duplicate in-card Spotlight status controls returned: {basename}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spotlight-dir", type=Path)
    args = parser.parse_args()
    try:
        validate_flagships()
        if args.spotlight_dir is not None:
            validate_spotlights(args.spotlight_dir)
        scope = "flagships + generated Spotlight" if args.spotlight_dir is not None else "flagships"
        print(f"Engineering card geometry validation passed: {scope} use exact 620×198 canvases with reviewed interior balance")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
