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
HEADER_ASSET_COMMIT = "a79b9a3a39c708a5f5ae7995ed8af0bae489a902"

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
    "assets/profile-badges/nameplate-yunior-portal-v2.svg",
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
PRINCIPLE_BADGES = (
    "assets/profile-badges/principle-evidence-confidence.svg",
    "assets/profile-badges/principle-reasoning-authorization.svg",
    "assets/profile-badges/principle-attribution-abstraction.svg",
    "assets/profile-badges/principle-oracle-discipline.svg",
    "assets/profile-badges/principle-reproducibility-optics.svg",
    "assets/profile-badges/principle-safety-architecture.svg",
)
HEADER_SVGS = (
    "assets/profile-badges/thesis-header-principle-mobile-light.svg",
    "assets/profile-badges/thesis-header-principle-mobile-dark.svg",
    "assets/profile-badges/thesis-header-principle-desktop-light.svg",
    "assets/profile-badges/thesis-header-principle-desktop-dark.svg",
    "assets/profile-badges/thesis-header-engineering-contract-mobile-light.svg",
    "assets/profile-badges/thesis-header-engineering-contract-mobile-dark.svg",
    "assets/profile-badges/thesis-header-engineering-contract-desktop-light.svg",
    "assets/profile-badges/thesis-header-engineering-contract-desktop-dark.svg",
)
HEADER_REFERENCES = tuple(
    f"https://raw.githubusercontent.com/portyu9/portyu9/{HEADER_ASSET_COMMIT}/{path}"
    for path in HEADER_SVGS
)
GENERATED_SVG_REFERENCES = (
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/profile-stats/profile/signal-field-wide-light.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/profile-stats/profile/signal-field-wide-dark.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/profile-stats/profile/signal-field-compact-light.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/profile-stats/profile/signal-field-compact-dark.svg",
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

if readme.count('<table width="100%">') != 1:
    fail("Principle table must render at 100% README width")
if readme.count('<th width="33%" align="center"><picture>') != 1:
    fail("Principle header must use the responsive 33% picture cell")
if readme.count('<th width="67%" align="center"><picture>') != 1:
    fail("Engineering Contract header must use the responsive 67% picture cell")
if '<img alt="◆ Principle"' not in readme:
    fail("Responsive Principle header fallback is missing")
if '<img alt="▤ Engineering Contract"' not in readme:
    fail("Responsive Engineering Contract header fallback is missing")
if readme.count('media="(min-width: 641px) and (prefers-color-scheme: dark)"') != 2:
    fail("Both thesis headers must provide explicit desktop dark variants")
if readme.count('media="(min-width: 641px)"') != 2:
    fail("Both thesis headers must provide explicit desktop light variants")
if "<h3>◆" in readme or "<h3>▤" in readme:
    fail("Thesis table headers must not use headings because GitHub injects anchor links")
if '<big><strong>◆' in readme or '<big><strong>▤' in readme or '<big><big><strong>◆' in readme:
    fail("Thesis headers must use responsive SVG variants, not one-size HTML typography")
if "Engineering contract" in readme:
    fail("Engineering Contract must use a capital C")

for suffix in "abcdef":
    if f"font23r-{suffix}" not in readme:
        fail("README must cache-bust every restored 23px Principle badge revision")

svg_pattern = re.compile(
    r'''(?:<img\b[^>]*\bsrc=["']([^"']+\.svg(?:[?#][^"']*)?)["']|<source\b[^>]*\bsrcset=["']([^"']+\.svg(?:[?#][^"']*)?)["']|!\[[^\]]*\]\(([^)]+\.svg(?:[?#][^)]*)?)\))''',
    re.I,
)
references = []
for match in svg_pattern.finditer(readme):
    reference = match.group(1) or match.group(2) or match.group(3)
    reference = reference.split("?", 1)[0].split("#", 1)[0].lstrip("./")
    references.append(reference)

allowed = set(ALLOWED_SVGS) | set(HEADER_REFERENCES) | set(GENERATED_SVG_REFERENCES)
unexpected = sorted(set(references) - allowed)
missing_refs = sorted(allowed - set(references))
if unexpected:
    fail(f"README contains unapproved SVG references: {', '.join(unexpected)}")
if missing_refs:
    fail(f"README is missing approved SVG references: {', '.join(missing_refs)}")

for relative in ALLOWED_SVGS + HEADER_SVGS:
    path = ROOT / relative
    if not path.exists():
        fail(f"Approved profile SVG is missing: {relative}")
    content = path.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > 50_000:
        fail(f"Profile SVG exceeds 50 KB: {relative}")
    lowered = content.lower()
    for forbidden in ("<image", "<foreignobject", "<script", "javascript:", "data:image"):
        if forbidden in lowered:
            fail(f"Profile SVG contains forbidden content {forbidden!r}: {relative}")

for relative in PRINCIPLE_BADGES:
    content = (ROOT / relative).read_text(encoding="utf-8")
    if 'font-size="23"' not in content or 'font-size="24"' in content:
        fail(f"Principle badge labels must use the restored 23px type size: {relative}")

oracle = (ROOT / "assets/profile-badges/principle-oracle-discipline.svg").read_text(encoding="utf-8")
if 'width="210" height="54" viewBox="0 0 210 54"' not in oracle:
    fail("Oracle Discipline must retain the requested wider 210px canvas")

repro = (ROOT / "assets/profile-badges/principle-reproducibility-optics.svg").read_text(encoding="utf-8")
if ">Reproducibility</text>" not in repro or ">over Optics</text>" not in repro:
    fail("Reproducibility principle must render as 'Reproducibility' over 'over Optics'")

for relative in HEADER_SVGS:
    content = (ROOT / relative).read_text(encoding="utf-8")
    expected_size = 'font-size="22"' if "desktop" in relative else 'font-size="23"'
    if expected_size not in content:
        fail(f"Responsive thesis header has the wrong reviewed type size: {relative}")
    expected_fill = '#F0F6FC' if "dark" in relative else '#1F2328'
    if f'fill="{expected_fill}"' not in content:
        fail(f"Responsive thesis header has the wrong explicit theme color: {relative}")
    if "principle" in relative and ">◆ Principle</text>" not in content:
        fail(f"Principle header text changed: {relative}")
    if "engineering-contract" in relative and ">▤ Engineering Contract</text>" not in content:
        fail(f"Engineering Contract header text changed: {relative}")

print(
    "Profile validation passed: the thesis table keeps its responsive 33/67 split; Principle badges use "
    "the restored fitted 23px typography; Oracle retains its wider canvas; anchor-free responsive thesis "
    "header SVGs use reviewed 22px desktop and 23px mobile sizing with explicit light/dark colors; "
    "and all Signal Field and reviewed profile SVG references remain restricted and deterministic."
)
