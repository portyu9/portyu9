#!/usr/bin/env python3
"""Validate the reviewed GitHub profile presentation contract.

The profile intentionally mixes reviewed third-party badges, authored SVG assets,
responsive HTML, and generated Signal Field artifacts. This validator protects the
user-visible contract: exact badge rendering tiers, mobile-landscape behavior,
reviewed wording, copyright posture, asset safety, immutable thesis-header refs,
and repository asset hygiene.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
HERO_REFERENCE = "assets/profile-badges/quality-engineering-automation-systems.png"
HERO_IMAGE = ROOT / HERO_REFERENCE
HERO_SIZE = 1_472_916
HERO_WIDTH = 1_280
HERO_HEIGHT = 854
HERO_SHA256 = "d840734c78ec59f3c53644330bc2166c51e1bb5eb8e768595035a37767eb5452"
HEADER_ASSET_COMMIT = "3849d500a7a09960e1b2ec562c7f3f9339a3b6d6"

SELF_HOSTED_BADGES = (
    "assets/profile-badges/badge-ai-enabled-qe.svg",
    "assets/profile-badges/badge-web-ui.svg",
    "assets/profile-badges/badge-api.svg",
    "assets/profile-badges/badge-graphql.svg",
    "assets/profile-badges/badge-mobile.svg",
    "assets/profile-badges/badge-ci-cd.svg",
    "assets/profile-badges/badge-unit.svg",
    "assets/profile-badges/badge-component.svg",
    "assets/profile-badges/badge-integration.svg",
    "assets/profile-badges/badge-contract.svg",
    "assets/profile-badges/badge-e2e.svg",
    "assets/profile-badges/badge-database-persistence.svg",
    "assets/profile-badges/badge-visual-regression.svg",
    "assets/profile-badges/badge-accessibility.svg",
    "assets/profile-badges/badge-security.svg",
    "assets/profile-badges/badge-performance.svg",
)

RETIRED_ASSETS = (
    "assets/profile-badges/ff16b3b6-41d3-43eb-ad02-34a7316da6a8.png",
    "assets/profile-badges/nameplate-yunior-portal-v1.svg",
    "assets/profile-badges/table-header-engineering-contract-v1.svg",
    "assets/profile-badges/table-header-engineering-contract-v2.svg",
    "assets/profile-badges/table-header-principle-v1.svg",
    "assets/profile-badges/table-header-principle-v2.svg",
) + SELF_HOSTED_BADGES

SHIELD_BADGES = (
    ("AI-Enabled QE", 91, "https://img.shields.io/badge/-AI--Enabled%20QE-FF2BD6?style=flat-square"),
    ("Web / UI", 59, "https://img.shields.io/badge/-Web%20%2F%20UI-7A5CFF?style=flat-square"),
    ("API", 29, "https://img.shields.io/badge/-API-00AEEF?style=flat-square"),
    ("GraphQL", 59, "https://img.shields.io/badge/-GraphQL-E10098?style=flat-square"),
    ("Mobile", 45, "https://img.shields.io/badge/-Mobile-00BFA6?style=flat-square"),
    ("CI/CD", 43, "https://img.shields.io/badge/-CI%2FCD-665CFF?style=flat-square"),
    ("Unit", 33, "https://img.shields.io/badge/-Unit-16A34A?style=flat"),
    ("Component", 73, "https://img.shields.io/badge/-Component-00A6C7?style=flat"),
    ("Integration", 71, "https://img.shields.io/badge/-Integration-7F5AF0?style=flat"),
    ("Contract", 57, "https://img.shields.io/badge/-Contract-FF3CAC?style=flat"),
    ("E2E", 31, "https://img.shields.io/badge/-E2E-008CFF?style=flat"),
    ("Database / Persistence", 137, "https://img.shields.io/badge/-Database%20%2F%20Persistence-0D9488?style=flat"),
    ("Visual Regression", 107, "https://img.shields.io/badge/-Visual%20Regression-A020F0?style=flat"),
    ("Accessibility", 77, "https://img.shields.io/badge/-Accessibility-EA580C?style=flat"),
    ("Security", 55, "https://img.shields.io/badge/-Security-EA2B2B?style=flat"),
    ("Performance", 79, "https://img.shields.io/badge/-Performance-6FAF00?style=flat"),
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
    "assets/profile-badges/principle-evidence-confidence-mobile-v2.svg",
    "assets/profile-badges/principle-reasoning-authorization-mobile-v2.svg",
    "assets/profile-badges/principle-attribution-abstraction-mobile-v2.svg",
    "assets/profile-badges/principle-oracle-discipline-mobile-v2.svg",
    "assets/profile-badges/principle-reproducibility-optics-mobile-v2.svg",
    "assets/profile-badges/principle-safety-architecture-mobile-v2.svg",
)
PRINCIPLE_BADGES = tuple(path for path in IDENTITY_AND_PRINCIPLE_SVGS if "/principle-" in path)

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
QUALIFICATION_CARD_SVGS = (
    "assets/profile-systems/qualification-ai-qa-control-plane.svg",
    "assets/profile-systems/qualification-graphql-qe.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe.svg",
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
    prefix = '<picture><source media="(min-width: 641px)" srcset="https://img.shields.io/badge/'
    require(readme.count(prefix) == 16, "Exactly 16 badges must use the restored Shields.io responsive contract")
    require(readme.count('media="(min-width: 1025px)" srcset="assets/profile-badges/badge-') == 0, "Regressed self-hosted wide-desktop badge tier remains")
    require(readme.count('height="24"><img alt=') == 16, "Every restored badge must render at 24px on the reviewed desktop tier")
    require(readme.count('height="20"></picture>') == 16, "Every restored badge must retain its 20px mobile fallback")

    for label, width, url in SHIELD_BADGES:
        source = f'<source media="(min-width: 641px)" srcset="{url}" width="{width}" height="24">'
        fallback = f'<img alt="{label}" src="{url}" width="{width}" height="20">'
        require(readme.count(source) == 1, f"Restored 24px badge source changed: {label}")
        require(readme.count(fallback) == 1, f"Restored 20px badge fallback changed: {label}")


def validate_thesis_headers(readme: str) -> None:
    require(readme.count('<table width="100%">') == 1, "Principle table must render at 100% README width")
    require(readme.count('<th width="45%" align="center"><picture>') == 1, "Principle column must remain 45%")
    require(readme.count('<th width="55%" align="center"><picture>') == 1, "Engineering Contract column must remain 55%")

    landscape_dark = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape) and (prefers-color-scheme: dark)"'
    landscape_light = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape)"'
    require(readme.count(landscape_dark) == 2, "Both thesis headers must retain the dark mobile-landscape override")
    require(readme.count(landscape_light) == 2, "Both thesis headers must retain the light mobile-landscape override")

    # Phone-sized devices must select the mobile assets before any narrow-desktop
    # fine-pointer override. This keeps mobile wording/scale deterministic even when
    # a browser reports a wide layout viewport or surprising pointer capabilities.
    phone_device_dark = 'media="(max-device-width: 640px) and (prefers-color-scheme: dark)"'
    phone_device_light = 'media="(max-device-width: 640px)"'
    require(readme.count(phone_device_dark) == 2 and readme.count(phone_device_light) == 2,
            "Both thesis headers must prioritize explicit phone-device mobile sources")

    pointer_media = "(min-width: 641px) and (max-width: 1024px) and (hover: hover) and (pointer: fine)"
    pointer_dark = f'media="{pointer_media} and (prefers-color-scheme: dark)"'
    pointer_light = f'media="{pointer_media}"'
    require(readme.count(pointer_dark) == 2 and readme.count(pointer_light) == 2,
            "Both headers must retain the fine-pointer desktop scale within the intermediate viewport")

    for width, family in (("45", "principle"), ("55", "engineering-contract")):
        prefix = f"https://raw.githubusercontent.com/portyu9/portyu9/{HEADER_ASSET_COMMIT}/assets/profile-badges/thesis-header-{family}"
        phone_dark = f'<source {phone_device_dark} srcset="{prefix}-mobile-dark.svg">'
        phone_light = f'<source {phone_device_light} srcset="{prefix}-mobile-light.svg">'
        desktop_dark = f'<source {pointer_dark} srcset="{prefix}-desktop-dark.svg">'
        desktop_light = f'<source {pointer_light} srcset="{prefix}-desktop-light.svg">'
        mobile_landscape_dark = f'<source {landscape_dark} srcset="{prefix}-mobile-dark.svg">'
        mobile_landscape_light = f'<source {landscape_light} srcset="{prefix}-mobile-light.svg">'
        expected = (
            f'<th width="{width}%" align="center"><picture>'
            + phone_dark + phone_light + desktop_dark + desktop_light + mobile_landscape_dark + mobile_landscape_light
        )
        require(readme.count(expected) == 1,
                f"{family}: phone sources must precede desktop overrides while preserving laptop desktop scale")

    for relative in HEADER_SVGS:
        content = safe_svg(ROOT / relative, relative)
        expected_size = 'font-size="18"' if "desktop" in relative else 'font-size="23"'
        require(expected_size in content, f"Responsive thesis header type size changed: {relative}")
        expected_fill = '#F0F6FC' if "dark" in relative else '#1F2328'
        require(f'fill="{expected_fill}"' in content, f"Responsive thesis header theme fill changed: {relative}")
        if "engineering-contract" in relative:
            expected_label = "Engineering Contract" if "desktop" in relative else "Eng. Contract"
            require(f'aria-label="{expected_label}"' in content and f'<title>{expected_label}</title>' in content,
                    f"Responsive Engineering Contract accessibility wording changed: {relative}")
            if "desktop" in relative:
                require('>▤ Engineering Contract</text>' in content,
                        f"Desktop Engineering Contract header wording changed: {relative}")
            else:
                require(content.count("<text ") == 2 and '>▤</text>' in content and '>Eng. Contract</text>' in content,
                        f"Mobile Eng. Contract optical composition changed: {relative}")

    for relative in (
        "assets/profile-badges/thesis-header-principle-mobile-light.svg",
        "assets/profile-badges/thesis-header-principle-mobile-dark.svg",
    ):
        content = (ROOT / relative).read_text(encoding="utf-8")
        require('width="147" height="40" viewBox="0 0 147 40"' in content,
                f"Mobile Principle header canvas changed: {relative}")
        require(content.count("<text ") == 2 and 'x="23"' in content and 'x="36"' in content and '>◆</text>' in content and '>Principle</text>' in content,
                f"Mobile Principle header optical composition changed: {relative}")
        require(content.count('font-size="23"') == 1 and content.count('font-size="24"') == 1 and 'font-size="25"' not in content,
                f"Mobile Principle icon must remain 23px while its label uses the reviewed 24px optical scale: {relative}")
    for relative in (
        "assets/profile-badges/thesis-header-engineering-contract-mobile-light.svg",
        "assets/profile-badges/thesis-header-engineering-contract-mobile-dark.svg",
    ):
        content = (ROOT / relative).read_text(encoding="utf-8")
        require('width="180" height="40" viewBox="0 0 180 40"' in content,
                f"Mobile Eng. Contract header canvas changed: {relative}")
        require(content.count("<text ") == 2 and 'x="12"' in content and 'x="26"' in content and '>▤</text>' in content and '>Eng. Contract</text>' in content,
                f"Mobile Eng. Contract header optical composition changed: {relative}")


def validate_references(readme: str) -> None:
    svg_pattern = re.compile(
        r'''(?:<img\b[^>]*\bsrc=["']([^"']+\.svg(?:[?#][^"']*)?)["']|<source\b[^>]*\bsrcset=["']([^"']+\.svg(?:[?#][^"']*)?)["']|!\[[^\]]*\]\(([^)]+\.svg(?:[?#][^)]*)?)\))''',
        re.I,
    )
    references: list[str] = []
    for match in svg_pattern.finditer(readme):
        reference = match.group(1) or match.group(2) or match.group(3)
        references.append(reference.split("?", 1)[0].split("#", 1)[0].lstrip("./"))

    allowed = set(IDENTITY_AND_PRINCIPLE_SVGS) | set(HEADER_REFERENCES) | set(GENERATED_SVG_REFERENCES) | set(QUALIFICATION_CARD_SVGS)
    unexpected = sorted(set(references) - allowed)
    missing = sorted(allowed - set(references))
    require(not unexpected, "README contains unapproved SVG references: " + ", ".join(unexpected))
    require(not missing, "README is missing approved SVG references: " + ", ".join(missing))


def main() -> int:
    require(README.is_file(), "README.md is missing")
    readme = README.read_text(encoding="utf-8")

    for retired in RETIRED_ASSETS:
        require(not (ROOT / retired).exists(), f"Retired asset must remain removed: {retired}")
        require(retired not in readme, f"README references retired asset: {retired}")

    require(HERO_IMAGE.is_file(), f"Profile hero image is missing: {HERO_REFERENCE}")
    hero_bytes = HERO_IMAGE.read_bytes()
    require(len(hero_bytes) == HERO_SIZE, f"Profile hero image size changed: expected {HERO_SIZE}, got {len(hero_bytes)}")
    require(hashlib.sha256(hero_bytes).hexdigest() == HERO_SHA256, "Profile hero image bytes differ from the reviewed optimized fallback")
    require(hero_bytes[:8] == b"\x89PNG\r\n\x1a\n", "Profile hero must remain a PNG")
    require(len(hero_bytes) >= 24 and hero_bytes[12:16] == b"IHDR", "Profile hero PNG IHDR is missing")
    hero_width = int.from_bytes(hero_bytes[16:20], "big")
    hero_height = int.from_bytes(hero_bytes[20:24], "big")
    require(
        (hero_width, hero_height) == (HERO_WIDTH, HERO_HEIGHT),
        f"Profile hero dimensions changed: expected {HERO_WIDTH}x{HERO_HEIGHT}, got {hero_width}x{hero_height}",
    )
    require(readme.find(HERO_REFERENCE) < readme.find("Ƴunior Ƥortal"), "Hero image must appear before the profile name")

    engineering_heading = re.compile(r'<h2\s+align="center">\s*✦ Engineering Thesis\s*</h2>', re.I)
    require(len(engineering_heading.findall(readme)) == 1, "Engineering Thesis must remain one centered H2")
    require(readme.count('<h2 align="center">◉ Activity Metrics</h2>') == 1, "Activity Metrics must remain one centered H2")
    require(readme.count('<h2 align="center">◇ Qualification Matrix</h2>') == 1, "Qualification Matrix must remain one centered H2")
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
    for relative in QUALIFICATION_CARD_SVGS:
        content = safe_svg(ROOT / relative, relative)
        require("SELECTED ENGINEERING SYSTEM" in content, f"Qualification card identity marker missing: {relative}")
        require("topology" in content.lower(), f"Qualification card topology treatment missing: {relative}")
        require(readme.count(relative) == 1, f"Qualification card must be referenced exactly once: {relative}")
    for relative in PRINCIPLE_BADGES:
        content = (ROOT / relative).read_text(encoding="utf-8")
        if relative.endswith("-mobile-v2.svg"):
            require('font-size="24"' in content and 'font-size="23"' not in content,
                    f"Reviewed mobile principle typography changed: {relative}")
        else:
            require('font-size="23"' in content and 'font-size="24"' not in content,
                    f"Legacy principle fallback typography changed: {relative}")
    oracle = (ROOT / "assets/profile-badges/principle-oracle-discipline.svg").read_text(encoding="utf-8")
    require('width="210" height="54" viewBox="0 0 210 54"' in oracle, "Oracle Discipline must retain its 210px canvas")
    repro = (ROOT / "assets/profile-badges/principle-reproducibility-optics.svg").read_text(encoding="utf-8")
    require(">Reproducibility</text>" in repro and ">over Optics</text>" in repro, "Reproducibility principle wording changed")

    validate_references(readme)

    activity_heading = readme.find('<h2 align="center">◉ Activity Metrics</h2>')
    signal_field = readme.find('alt="GitHub activity signal field"')
    qualification_heading = readme.find('<h2 align="center">◇ Qualification Matrix</h2>')
    copyright_notice = readme.find("© 2026 Ƴunior Ƥortal")
    require(activity_heading < signal_field, "Activity Metrics heading must precede Signal Field")
    require(signal_field < qualification_heading < copyright_notice, "Qualification Matrix must remain below Signal Field and above copyright")
    footer_separator = '\n---\n\n<p align="center">\n<sub><strong>© 2026 Ƴunior Ƥortal. All rights reserved.</strong></sub>'
    require(readme.count(footer_separator) == 1, "A horizontal rule must exist immediately above the copyright footer")
    require("release-candidate.yml?branch=main" not in readme, "Qualification Matrix must not present an RC workflow with no current main status")

    print(
        "Profile validation passed: the exact reviewed Shields badge contract is restored at 24px desktop / 20px "
        "mobile with its original font metrics; the regressed self-hosted badge assets remain absent; hero, 45/55 "
        "thesis layout, mobile-landscape headers, centered headings, engineering wording, qualification topology cards, "
        "footer separator, copyright posture, immutable header refs, and approved SVG safety contracts remain locked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
