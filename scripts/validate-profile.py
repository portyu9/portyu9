#!/usr/bin/env python3
"""Validate the reviewed GitHub profile presentation contract.

The profile intentionally mixes authored SVG assets, responsive HTML, and generated
Signal Field artifacts. This validator protects the user-visible contract rather than
merely checking file existence: exact responsive tiers, mobile-landscape behavior,
reviewed wording, copyright posture, asset safety, and immutable thesis-header refs.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
HERO_REFERENCE = "assets/profile-badges/ff16b3b6-41d3-43eb-ad02-34a7316da6a8.png"
HERO_IMAGE = ROOT / HERO_REFERENCE
HERO_SIZE = 2_947_658
HERO_SHA256 = "f99901f3da31c68441d471a92dcf9c7829681c8ec390286159b78eea97a5bcd0"
HEADER_ASSET_COMMIT = "44471c9ba38958e601bc602557dfa0642633f897"

BADGES = (
    ("badge-ai-enabled-qe.svg", "AI-Enabled QE", 91, "#FF2BD6"),
    ("badge-web-ui.svg", "Web / UI", 59, "#7A5CFF"),
    ("badge-api.svg", "API", 29, "#00AEEF"),
    ("badge-graphql.svg", "GraphQL", 59, "#E10098"),
    ("badge-mobile.svg", "Mobile", 45, "#00BFA6"),
    ("badge-ci-cd.svg", "CI/CD", 43, "#665CFF"),
    ("badge-unit.svg", "Unit", 33, "#16A34A"),
    ("badge-component.svg", "Component", 73, "#00A6C7"),
    ("badge-integration.svg", "Integration", 71, "#7F5AF0"),
    ("badge-contract.svg", "Contract", 57, "#FF3CAC"),
    ("badge-e2e.svg", "E2E", 31, "#008CFF"),
    ("badge-database-persistence.svg", "Database / Persistence", 137, "#0D9488"),
    ("badge-visual-regression.svg", "Visual Regression", 107, "#A020F0"),
    ("badge-accessibility.svg", "Accessibility", 77, "#EA580C"),
    ("badge-security.svg", "Security", 55, "#EA2B2B"),
    ("badge-performance.svg", "Performance", 79, "#6FAF00"),
)

IDENTITY_AND_PRINCIPLE_SVGS = (
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
PRINCIPLE_BADGES = tuple(path for path in IDENTITY_AND_PRINCIPLE_SVGS if "/principle-" in path)
BADGE_PATHS = tuple(f"assets/profile-badges/{filename}" for filename, _, _, _ in BADGES)

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

REQUIRED_WORDING = (
    "I engineer quality systems that turn software change into attributable evidence",
    "I treat quality engineering as the discipline of <strong>reducing uncertainty about change</strong>.",
    "collect evidence at the narrowest layer sufficient to support a conclusion",
    "terminal pass/fail state",
    "explicit and verifiable; a green workflow should claim no more than those signals establish.",
    "#### Confidence does not scale with automation volume alone.",
    "#### It is earned when evidence is traceable, oracles are explicit, and failure is attributable.",
    "Except where a specific file or component expressly states otherwise, no license is granted to copy, modify, redistribute, or reuse original README text and composition, branding, artwork, or custom Signal Field modifications and visual treatment.",
    "Third-party components remain subject to their respective licenses and terms.",
)
FORBIDDEN_WORDING = (
    "terminal truth",
    "Confidence is not proportional to automation volume.",
    "Original branding, artwork, README design, and custom Signal Field visuals are not licensed for reuse or redistribution.",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def safe_svg(path: Path, label: str) -> str:
    require(path.is_file(), f"Missing reviewed SVG: {label}")
    content = path.read_text(encoding="utf-8")
    require(len(content.encode("utf-8")) <= 50_000, f"SVG exceeds 50 KB: {label}")
    lowered = content.lower()
    for forbidden in ("<image", "<foreignobject", "<script", "javascript:", "data:image"):
        require(forbidden not in lowered, f"SVG contains forbidden content {forbidden!r}: {label}")
    return content


def validate_badges(readme: str) -> None:
    require("img.shields.io" not in readme, "Profile badges must be self-hosted; Shields.io runtime dependency remains")
    require(
        readme.count('media="(min-width: 1025px)"') == 16,
        "Exactly 16 badge variants must use the reviewed wide-desktop 1025px breakpoint",
    )
    require(
        readme.count('media="(min-width: 641px)" srcset="assets/profile-badges/badge-') == 0,
        "Badges must not switch to desktop sizing at the phone-landscape 641px breakpoint",
    )

    for filename, label, width, color in BADGES:
        relative = f"assets/profile-badges/{filename}"
        content = safe_svg(ROOT / relative, relative)
        require(
            f'width="{width}" height="20" viewBox="0 0 {width} 20"' in content,
            f"Self-hosted badge geometry changed: {relative}",
        )
        require(f'aria-label="{label}"' in content, f"Badge accessible label changed: {relative}")
        require(f"<title>{label}</title>" in content, f"Badge title changed: {relative}")
        require(f'fill="{color}"' in content, f"Badge reviewed color changed: {relative}")

        source = (
            f'<source media="(min-width: 1025px)" srcset="{relative}" '
            f'width="{width}" height="24">'
        )
        fallback = f'<img alt="{label}" src="{relative}" width="{width}" height="20">'
        require(readme.count(source) == 1, f"Wide-desktop 24px badge source missing: {label}")
        require(readme.count(fallback) == 1, f"20px mobile/tablet badge fallback missing: {label}")


def validate_thesis_headers(readme: str) -> None:
    require(readme.count('<table width="100%">') == 1, "Principle table must render at 100% README width")
    require(readme.count('<th width="37%" align="center"><picture>') == 1, "Principle column must remain 37%")
    require(readme.count('<th width="63%" align="center"><picture>') == 1, "Engineering Contract column must remain 63%")

    landscape_dark = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape) and (prefers-color-scheme: dark)"'
    landscape_light = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape)"'
    require(readme.count(landscape_dark) == 2, "Both thesis headers must retain the dark mobile-landscape override")
    require(readme.count(landscape_light) == 2, "Both thesis headers must retain the light mobile-landscape override")

    for family in ("principle", "engineering-contract"):
        landscape_marker = f"thesis-header-{family}-mobile-dark.svg"
        desktop_marker = f"thesis-header-{family}-desktop-dark.svg"
        require(
            readme.find(landscape_marker) < readme.find(desktop_marker),
            f"{family} landscape source must precede desktop source so phone landscape cannot regress",
        )

    for relative in HEADER_SVGS:
        content = safe_svg(ROOT / relative, relative)
        expected_size = 'font-size="21"' if "desktop" in relative else 'font-size="23"'
        require(expected_size in content, f"Responsive thesis header type size changed: {relative}")
        expected_fill = '#F0F6FC' if "dark" in relative else '#1F2328'
        require(f'fill="{expected_fill}"' in content, f"Responsive thesis header theme fill changed: {relative}")

    for relative in (
        "assets/profile-badges/thesis-header-principle-mobile-light.svg",
        "assets/profile-badges/thesis-header-principle-mobile-dark.svg",
    ):
        content = (ROOT / relative).read_text(encoding="utf-8")
        require(
            'width="136" height="40" viewBox="0 0 136 40"' in content and 'x="68"' in content,
            f"Mobile Principle header must retain the confirmed 136px canvas: {relative}",
        )
    for relative in (
        "assets/profile-badges/thesis-header-engineering-contract-mobile-light.svg",
        "assets/profile-badges/thesis-header-engineering-contract-mobile-dark.svg",
    ):
        content = (ROOT / relative).read_text(encoding="utf-8")
        require(
            'width="276" height="40" viewBox="0 0 276 40"' in content and 'x="138"' in content,
            f"Mobile Engineering Contract header must retain the confirmed 276px canvas: {relative}",
        )


def validate_references(readme: str) -> None:
    svg_pattern = re.compile(
        r'''(?:<img\b[^>]*\bsrc=["']([^"']+\.svg(?:[?#][^"']*)?)["']|<source\b[^>]*\bsrcset=["']([^"']+\.svg(?:[?#][^"']*)?)["']|!\[[^\]]*\]\(([^)]+\.svg(?:[?#][^)]*)?)\))''',
        re.I,
    )
    references: list[str] = []
    for match in svg_pattern.finditer(readme):
        reference = match.group(1) or match.group(2) or match.group(3)
        references.append(reference.split("?", 1)[0].split("#", 1)[0].lstrip("./"))

    allowed = set(IDENTITY_AND_PRINCIPLE_SVGS) | set(BADGE_PATHS) | set(HEADER_REFERENCES) | set(GENERATED_SVG_REFERENCES)
    unexpected = sorted(set(references) - allowed)
    missing = sorted(allowed - set(references))
    require(not unexpected, "README contains unapproved SVG references: " + ", ".join(unexpected))
    require(not missing, "README is missing approved SVG references: " + ", ".join(missing))


def main() -> int:
    require(README.is_file(), "README.md is missing")
    readme = README.read_text(encoding="utf-8")

    require(HERO_IMAGE.is_file(), f"Profile hero image is missing: {HERO_REFERENCE}")
    hero_bytes = HERO_IMAGE.read_bytes()
    require(len(hero_bytes) == HERO_SIZE, f"Profile hero image size changed: expected {HERO_SIZE}, got {len(hero_bytes)}")
    require(hashlib.sha256(hero_bytes).hexdigest() == HERO_SHA256, "Profile hero image bytes differ from the reviewed original")
    require(readme.find(HERO_REFERENCE) < readme.find("Ƴunior Ƥortal"), "Hero image must appear before the profile name")

    engineering_heading = re.compile(r'<h2\s+align="center">\s*✦ Engineering Thesis\s*</h2>', re.I)
    require(len(engineering_heading.findall(readme)) == 1, "Engineering Thesis must remain one centered H2")
    require(readme.count('<h2 align="center">◉ Activity Metrics</h2>') == 1, "Activity Metrics must remain one centered H2")
    require("## ✦ Engineering Thesis" not in readme, "Engineering Thesis must not regress to a left-aligned Markdown H2")

    for phrase in REQUIRED_WORDING:
        require(phrase in readme, f"Reviewed wording is missing: {phrase}")
    for phrase in FORBIDDEN_WORDING:
        require(phrase not in readme, f"Retired wording returned: {phrase}")
    require(readme.count("© 2026 Ƴunior Ƥortal. All rights reserved.") == 1, "Copyright owner/year must appear exactly once")

    validate_badges(readme)
    validate_thesis_headers(readme)

    for relative in IDENTITY_AND_PRINCIPLE_SVGS:
        safe_svg(ROOT / relative, relative)
    for relative in PRINCIPLE_BADGES:
        content = (ROOT / relative).read_text(encoding="utf-8")
        require('font-size="23"' in content and 'font-size="24"' not in content, f"Principle badge typography changed: {relative}")
    oracle = (ROOT / "assets/profile-badges/principle-oracle-discipline.svg").read_text(encoding="utf-8")
    require('width="210" height="54" viewBox="0 0 210 54"' in oracle, "Oracle Discipline must retain its 210px canvas")
    repro = (ROOT / "assets/profile-badges/principle-reproducibility-optics.svg").read_text(encoding="utf-8")
    require(">Reproducibility</text>" in repro and ">over Optics</text>" in repro, "Reproducibility principle wording changed")

    validate_references(readme)

    require(readme.find('<h2 align="center">◉ Activity Metrics</h2>') < readme.find('alt="GitHub activity signal field"'), "Activity Metrics heading must precede Signal Field")
    require(readme.find('alt="GitHub activity signal field"') < readme.find("© 2026 Ƴunior Ƥortal"), "Copyright notice must remain below Signal Field")

    print(
        "Profile validation passed: all 16 badges are self-hosted; 24px sizing is restricted to wide desktop "
        "viewports >=1025px while mobile/tablet/phone-landscape remains 20px; the 37/63 thesis table preserves "
        "its explicit landscape overrides and reviewed mobile canvases; centered headings, engineering wording, "
        "copyright posture, immutable header refs, and all approved SVG safety contracts are locked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
