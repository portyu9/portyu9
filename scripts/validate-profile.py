from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

REMOVED_SVGS = (
    ROOT / "assets" / "qe-command-center.svg",
    ROOT / "assets" / "qe-systems-map.svg",
    ROOT / "assets" / "repository-signal.svg",
)
REMOVED_SECTIONS = (
    "## Systems portfolio",
    "## Engineering surface",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if not README.exists():
    fail("README.md is missing")

readme = README.read_text(encoding="utf-8")

for path in REMOVED_SVGS:
    relative = path.relative_to(ROOT).as_posix()
    if path.exists():
        fail(f"Removed profile SVG is still present: {relative}")
    if relative in readme:
        fail(f"README still references removed profile SVG: {relative}")

for heading in REMOVED_SECTIONS:
    if heading in readme:
        fail(f"Removed profile section is still present: {heading}")

svg_reference = re.search(
    r'''(?:<img\b[^>]*\bsrc=["'][^"']+\.svg(?:[?#][^"']*)?["']|!\[[^\]]*\]\([^)]*\.svg(?:[?#][^)]*)?\))''',
    readme,
    re.I,
)
if svg_reference:
    fail(f"README still contains an SVG image reference: {svg_reference.group(0)}")

print(
    "Profile cleanup validation passed: the three profile SVGs are absent, "
    "the removed sections are absent, and README.md contains no SVG image references."
)
