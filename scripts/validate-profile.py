from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
HERO_IMAGE = ROOT / "assets" / "profile-badges" / "ff16b3b6-41d3-43eb-ad02-34a7316da6a8.png"
HERO_REFERENCE = "assets/profile-badges/ff16b3b6-41d3-43eb-ad02-34a7316da6a8.png"
HERO_SIZE = 2_947_658
HERO_SHA256 = "f99901f3da31c68441d471a92dcf9c7829681c8ec390286159b78eea97a5bcd0"

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
    "assets/profile-badges/table-header-principle-v2.svg",
    "assets/profile-badges/table-header-engineering-contract-v2.svg",
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

if not HERO_IMAGE.exists():
    fail(f"Profile hero image is missing: {HERO_REFERENCE}")

hero_bytes = HERO_IMAGE.read_bytes()
if len(hero_bytes) != HERO_SIZE:
    fail(f"Profile hero image size changed: expected {HERO_SIZE}, got {len(hero_bytes)}")
if hashlib.sha256(hero_bytes).hexdigest() != HERO_SHA256:
    fail("Profile hero image bytes differ from the reviewed original attachment")

hero_position = readme.find(HERO_REFERENCE)
name_position = readme.find("Ƴunior Ƥortal")
if hero_position < 0:
    fail("README does not reference the approved profile hero image")
if name_position < 0 or hero_position > name_position:
    fail("Profile hero image must appear before the profile name")

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
    "Profile validation passed: exact hero bytes are preserved above the profile name, removed artwork "
    "stays absent, approved local badge SVGs are present, and README SVG references are restricted "
    "to the reviewed badge set."
)
