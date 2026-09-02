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
ALLOWED_SVGS = (
    "assets/profile-badges/identity-quality-engineering.svg",
    "assets/profile-badges/identity-automation-architecture.svg",
    "assets/profile-badges/identity-ai-quality-systems.svg",
    "assets/profile-badges/principle-evidence-confidence.svg",
    "assets/profile-badges/principle-reasoning-authorization.svg",
    "assets/profile-badges/principle-attribution-abstraction.svg",
    "assets/profile-badges/principle-oracle-discipline.svg",
    "assets/profile-badges/principle-reproducibility-optics.svg",
    "assets/profile-badges/principle-safety-architecture.svg",
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

svg_pattern = re.compile(
    r'''(?:<img\b[^>]*\bsrc=["']([^"']+\.svg(?:[?#][^"']*)?)["']|!\[[^\]]*\]\(([^)]+\.svg(?:[?#][^)]*)?)\))''',
    re.I,
)
references = []
for match in svg_pattern.finditer(readme):
    reference = match.group(1) or match.group(2)
    reference = reference.split("?", 1)[0].split("#", 1)[0].lstrip("./")
    references.append(reference)

allowed = set(ALLOWED_SVGS)
unexpected = sorted(set(references) - allowed)
missing_refs = sorted(allowed - set(references))
if unexpected:
    fail(f"README contains unapproved SVG references: {', '.join(unexpected)}")
if missing_refs:
    fail(f"README is missing approved SVG references: {', '.join(missing_refs)}")

for relative in ALLOWED_SVGS:
    path = ROOT / relative
    if not path.exists():
        fail(f"Approved profile badge SVG is missing: {relative}")
    content = path.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > 50_000:
        fail(f"Profile badge SVG exceeds 50 KB: {relative}")
    lowered = content.lower()
    for forbidden in ("<image", "<foreignobject", "<script", "javascript:", "data:image"):
        if forbidden in lowered:
            fail(f"Profile badge SVG contains forbidden content {forbidden!r}: {relative}")

print(
    "Profile validation passed: removed artwork stays absent, approved local badge SVGs are present, "
    "and README SVG references are restricted to the reviewed badge set."
)
