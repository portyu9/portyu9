#!/usr/bin/env python3
"""Validate the reviewed profile plus Selected Engineering Systems v4 contracts.

Established profile contracts remain delegated to validate-profile.py helpers; this
validator replaces only the former Qualification Matrix contract with deterministic
light/dark flagship cards and generated daily Evidence Spotlight references. It also
owns the current responsive QE taxonomy scale and desktop-only thesis scale contracts.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LEGACY_PATH = ROOT / "scripts/validate-profile.py"


def load_legacy():
    spec = importlib.util.spec_from_file_location("profile_legacy", LEGACY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load established profile validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

legacy = load_legacy()

TAXONOMY_BADGES = legacy.SHIELD_BADGES + (
    (
        "Agent Evaluation / TEVV",
        145,
        "https://img.shields.io/badge/-Agent%20Evaluation%20%2F%20TEVV-9C4DFF?style=flat-square",
    ),
)

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
ANIMATED_HERO_SVG = "assets/profile-badges/quality-engineering-automation-systems-nebula-portal-animated-v2-optimized.svg"
RETIRED_ANIMATED_HERO_SVG = "assets/profile-badges/quality-engineering-automation-systems-nebula-portal-animated-v2.svg"
ANIMATED_HERO_SVG_SIZE = 524_447
ANIMATED_HERO_SVG_SHA256 = "b7a6bb60e85e6304a2e561849174bd305ed73d25848e886ea83df753baa7a5d3"
ANIMATED_HERO_WIDTH = 2_560
ANIMATED_HERO_HEIGHT = 1_708
ANIMATED_HERO_WEBP_SIZE = 372_702
ANIMATED_HERO_WEBP_SHA256 = "fcb9d112ff3447ef1671e58be169051ddde0dd83016b88386cf4a3f2e39c7824"
ANIMATED_HERO_ANIMATION_COUNTS = (86, 22, 14)
ANIMATED_HERO_NORMALIZED_SHELL_SHA256 = "e5cfe5f0ccfbaf11d5d09ccfb2fed6696edaed60f0c6c88367bbf2fb87b85314"

PROFILE_BANNER_SVGS = (
    "assets/profile-banners/quantum-apex-signal-crown-hero.svg",
    "assets/profile-banners/quantum-apex-signal-crown-hero-compact.svg",
    "assets/profile-banners/elite-evidence-horizon-bottom.svg",
    ANIMATED_HERO_SVG,
)
BOTTOM_HORIZON_BLOCK = (
    '<p align="center">\n'
    '<picture>\n'
    '  <img alt="Animated evidence horizon" src="assets/profile-banners/elite-evidence-horizon-bottom.svg" width="100%">\n'
    '</picture>\n'
    '</p>'
)
BOTTOM_HORIZON_ANCHOR = re.compile(
    r'<a\b[^>]*>(?:(?!</a>).)*elite-evidence-horizon-bottom\.svg(?:(?!</a>).)*</a>',
    re.I | re.S,
)
RETIRED_FLAGSHIP_SVGS = (
    "assets/profile-systems/qualification-ai-qa-control-plane.svg",
    "assets/profile-systems/qualification-graphql-qe.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe.svg",
)
SPOTLIGHT_PATHS = tuple(
    f"engineering-spotlight/spotlight-{slot}-{theme}.svg"
    for slot in range(1, 4)
    for theme in ("light", "dark")
)
SPOTLIGHT_REF = re.compile(
    r"^https://raw\.githubusercontent\.com/portyu9/portyu9/([0-9a-f]{40})/"
    r"(engineering-spotlight/spotlight-[123]-(?:light|dark)\.svg)$"
)
THESIS_HEADER_ASSET_COMMIT = "825ca413dbff50cff8559c46b1b395b6a485bb6e"
THESIS_HEADER_REFS = tuple(
    f"https://raw.githubusercontent.com/portyu9/portyu9/{THESIS_HEADER_ASSET_COMMIT}/{path}"
    for path in legacy.HEADER_SVGS
)
DESKTOP_PRINCIPLES = (
    ("Evidence before / Confidence", "assets/profile-badges/principle-evidence-confidence-desktop.svg", 170, 79, "assets/profile-badges/principle-evidence-confidence.svg?fit=20260903-font23r-a", 84),
    ("Reasoning without / Self-authorization", "assets/profile-badges/principle-reasoning-authorization-desktop.svg", 187, 79, "assets/profile-badges/principle-reasoning-authorization.svg?fit=20260903-font23r-b", 84),
    ("Attribution before / Abstraction", "assets/profile-badges/principle-attribution-abstraction-desktop.svg", 173, 79, "assets/profile-badges/principle-attribution-abstraction.svg?fit=20260903-font23r-c", 84),
    ("Oracle Discipline", "assets/profile-badges/principle-oracle-discipline-desktop.svg", 171, 39, "assets/profile-badges/principle-oracle-discipline.svg?fit=20260903-font23r-d", 44),
    ("Reproducibility over Optics", "assets/profile-badges/principle-reproducibility-optics-desktop.svg", 166, 79, "assets/profile-badges/principle-reproducibility-optics.svg?fit=20260903-font23r-e", 84),
    ("Safety by / Architecture", "assets/profile-badges/principle-safety-architecture-desktop.svg", 152, 79, "assets/profile-badges/principle-safety-architecture.svg?fit=20260903-font23r-f", 84),
)
DESKTOP_PRINCIPLE_SVGS = tuple(item[1] for item in DESKTOP_PRINCIPLES)
MOBILE_PHONE_PRINCIPLES = (
    ("Evidence before / Confidence", "assets/profile-badges/principle-evidence-confidence-mobile-v2.svg", 214, 104, 173, 84, ["Evidence","before","Confidence"], [20,52,84]),
    ("Reasoning without / Self-authorization", "assets/profile-badges/principle-reasoning-authorization-mobile-v2.svg", 214, 104, 173, 84, ["Reasoning","without","Self-authorization"], [20,52,84]),
    ("Attribution before / Abstraction", "assets/profile-badges/principle-attribution-abstraction-mobile-v2.svg", 214, 104, 173, 84, ["Attribution","before","Abstraction"], [20,52,84]),
    ("Oracle Discipline", "assets/profile-badges/principle-oracle-discipline-mobile-v2.svg", 214, 104, 173, 84, ["Oracle","Discipline"], [34,70]),
    ("Reproducibility over Optics", "assets/profile-badges/principle-reproducibility-optics-mobile-v2.svg", 214, 104, 173, 84, ["Reproducibility","over","Optics"], [20,52,84]),
    ("Safety by / Architecture", "assets/profile-badges/principle-safety-architecture-mobile-v2.svg", 214, 104, 173, 84, ["Safety","by","Architecture"], [20,52,84]),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        legacy.fail(message)


def validate_references(readme: str) -> None:
    pattern = re.compile(
        r'''(?:<img\b[^>]*\bsrc=["']([^"']+\.svg(?:[?#][^"']*)?)["']|<source\b[^>]*\bsrcset=["']([^"']+\.svg(?:[?#][^"']*)?)["']|!\[[^\]]*\]\(([^)]+\.svg(?:[?#][^)]*)?)\))''',
        re.I,
    )
    references=[]
    spotlight_refs: list[tuple[str, str]] = []
    for match in pattern.finditer(readme):
        ref=match.group(1) or match.group(2) or match.group(3)
        cleaned=ref.split("?",1)[0].split("#",1)[0].lstrip("./")
        spotlight=SPOTLIGHT_REF.fullmatch(cleaned)
        if spotlight is not None:
            spotlight_refs.append((spotlight.group(1), spotlight.group(2)))
        else:
            references.append(cleaned)
    allowed = set(legacy.IDENTITY_AND_PRINCIPLE_SVGS) | set(DESKTOP_PRINCIPLE_SVGS) | set(THESIS_HEADER_REFS) | set(legacy.GENERATED_SVG_REFERENCES) | set(FLAGSHIP_SVGS) | set(PROFILE_BANNER_SVGS)
    unexpected=sorted(set(references)-allowed); missing=sorted(allowed-set(references))
    require(not unexpected, "README contains unapproved SVG references: " + ", ".join(unexpected))
    require(not missing, "README is missing approved SVG references: " + ", ".join(missing))
    require(len(spotlight_refs) == 6, "README must reference exactly six immutable Spotlight SVGs")
    require({path for _, path in spotlight_refs} == set(SPOTLIGHT_PATHS), "README immutable Spotlight slot/theme inventory changed")
    require(len({revision for revision, _ in spotlight_refs}) == 1, "All six Spotlight SVGs must pin one immutable generated commit")


def validate_taxonomy_scale(readme: str) -> None:
    """Protect the reviewed H2 hierarchy and responsive desktop/mobile badge scale."""
    require(readme.count('<h2 align="center">◈&nbsp;&nbsp;QE Domains</h2>') == 1,
            "QE Domains must match the centered H2 hierarchy")
    require(readme.count('<h2 align="center">▦&nbsp;&nbsp;Test Architecture</h2>') == 1,
            "Test Architecture must match the centered H2 hierarchy")
    require('<h3 align="center"><big>◈&nbsp;&nbsp;QE Domains</big></h3>' not in readme,
            "Legacy QE Domains H3 hierarchy returned")
    require('<h3 align="center"><big>▦&nbsp;&nbsp;Test Architecture</big></h3>' not in readme,
            "Legacy Test Architecture H3 hierarchy returned")
    require(readme.count('<big>Designed for Reproducibility · Attribution · Evidence-backed Decisions</big>') == 1,
            "Taxonomy evidence-design tagline scale changed")

    prefix = '<picture><source media="(min-width: 641px)" srcset="https://img.shields.io/badge/'
    require(readme.count(prefix) == 17,
            "Exactly 17 taxonomy badges must use the responsive Shields.io contract")
    require(readme.count('height="29"><img alt=') == 17,
            "Every taxonomy badge must render at 29px on desktop")
    require(readme.count('height="29"></picture>') == 17,
            "Every taxonomy badge must render at 29px on mobile")
    require(readme.count('media="(min-width: 1025px)" srcset="assets/profile-badges/badge-') == 0,
            "Regressed self-hosted wide-desktop badge tier remains")

    for label, base_width, url in TAXONOMY_BADGES:
        desktop_width = round(base_width * 29 / 24)
        # Shields static badges do not expose an independent text-size query;
        # 29px is the reviewed desktop target that yields an effective ~16px label.
        # Mobile remains at its existing 29px target and proportions.
        mobile_width = round(base_width * 29 / 20)
        source = (
            f'<source media="(min-width: 641px)" srcset="{url}" '
            f'width="{desktop_width}" height="29">'
        )
        fallback = (
            f'<img alt="{label}" src="{url}" '
            f'width="{mobile_width}" height="29">'
        )
        require(readme.count(source) == 1,
                f"Reviewed 29px desktop taxonomy badge changed: {label}")
        require(readme.count(fallback) == 1,
                f"Reviewed 29px mobile taxonomy badge changed: {label}")


def validate_thesis_scale(readme: str) -> None:
    """Lock the reviewed desktop thesis scale while preserving mobile assets."""
    require(readme.count('<table width="100%">') == 1, "Principle table must render at 100% README width")
    require(readme.count('<th width="45%" align="center"><picture>') == 1, "Principle column must remain 45%")
    require(readme.count('<th width="55%" align="center"><picture>') == 1, "Engineering Contract column must remain 55%")

    landscape_dark = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape) and (prefers-color-scheme: dark)"'
    landscape_light = 'media="(min-width: 641px) and (max-width: 1024px) and (orientation: landscape)"'
    require(readme.count(landscape_dark) == 2, "Both thesis headers must retain the dark mobile-landscape override")
    require(readme.count(landscape_light) == 2, "Both thesis headers must retain the light mobile-landscape override")

    for family in ("principle", "engineering-contract"):
        mobile_dark = f"https://raw.githubusercontent.com/portyu9/portyu9/{THESIS_HEADER_ASSET_COMMIT}/assets/profile-badges/thesis-header-{family}-mobile-dark.svg"
        mobile_light = f"https://raw.githubusercontent.com/portyu9/portyu9/{THESIS_HEADER_ASSET_COMMIT}/assets/profile-badges/thesis-header-{family}-mobile-light.svg"
        desktop_dark = f"https://raw.githubusercontent.com/portyu9/portyu9/{THESIS_HEADER_ASSET_COMMIT}/assets/profile-badges/thesis-header-{family}-desktop-dark.svg"
        desktop_light = f"https://raw.githubusercontent.com/portyu9/portyu9/{THESIS_HEADER_ASSET_COMMIT}/assets/profile-badges/thesis-header-{family}-desktop-light.svg"
        require(readme.count(f'media="(min-width: 1025px) and (prefers-color-scheme: dark)" srcset="{desktop_dark}"') == 1,
                f"{family} dark desktop header must start at 1025px")
        require(readme.count(f'media="(min-width: 1025px)" srcset="{desktop_light}"') == 1,
                f"{family} light desktop header must start at 1025px")
        require(readme.count(f'media="(prefers-color-scheme: dark)" srcset="{mobile_dark}"') == 1,
                f"{family} dark mobile fallback changed")
        require(readme.count(f'src="{mobile_light}"') == 1,
                f"{family} light mobile fallback changed")
        require(readme.find(f"thesis-header-{family}-mobile-dark.svg") < readme.find(f"thesis-header-{family}-desktop-dark.svg"),
                f"{family} mobile-landscape source must precede desktop source")

    for relative in legacy.HEADER_SVGS:
        content = legacy.safe_svg(ROOT / relative, relative)
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
        content=(ROOT/relative).read_text(encoding="utf-8")
        require('width="147" height="40" viewBox="0 0 147 40"' in content,
                f"Mobile Principle header canvas changed: {relative}")
        require(content.count("<text ") == 2 and 'x="23"' in content and 'x="36"' in content and '>◆</text>' in content and '>Principle</text>' in content,
                f"Mobile Principle header optical composition changed: {relative}")
    for relative in (
        "assets/profile-badges/thesis-header-engineering-contract-mobile-light.svg",
        "assets/profile-badges/thesis-header-engineering-contract-mobile-dark.svg",
    ):
        content=(ROOT/relative).read_text(encoding="utf-8")
        require('width="180" height="40" viewBox="0 0 180 40"' in content,
                f"Mobile Eng. Contract header canvas changed: {relative}")
        require(content.count("<text ") == 2 and 'x="12"' in content and 'x="26"' in content and '>▤</text>' in content and '>Eng. Contract</text>' in content,
                f"Mobile Eng. Contract header optical composition changed: {relative}")
        require('font-size="23"' in content,
                f"Mobile Eng. Contract must match the 23px Principle header scale: {relative}")
    mobile_principle_sizes = {
        size
        for relative in (
            "assets/profile-badges/thesis-header-principle-mobile-light.svg",
            "assets/profile-badges/thesis-header-principle-mobile-dark.svg",
        )
        for size in re.findall(r'font-size="(\d+)"', (ROOT / relative).read_text(encoding="utf-8"))
    }
    mobile_contract_sizes = {
        size
        for relative in (
            "assets/profile-badges/thesis-header-engineering-contract-mobile-light.svg",
            "assets/profile-badges/thesis-header-engineering-contract-mobile-dark.svg",
        )
        for size in re.findall(r'font-size="(\d+)"', (ROOT / relative).read_text(encoding="utf-8"))
    }
    require(mobile_principle_sizes == mobile_contract_sizes == {"23"},
            "Mobile Principle and Eng. Contract headers must share the same 23px text scale")
    require(abs((180 / 147) - (55 / 45)) < 0.003,
            "Mobile thesis header intrinsic widths must track the 45/55 table-column ratio")

    phone_portrait = 'media="(max-width: 640px)"'
    phone_landscape = 'media="(orientation: landscape) and (min-width: 641px) and (max-width: 1024px)"'
    require({item[2:6] for item in MOBILE_PHONE_PRINCIPLES} == {(214, 104, 173, 84)},
            "All mobile principle cards must share one intrinsic/render geometry")
    for alt, mobile_path, canvas_width, canvas_height, render_width, render_height, lines, y_positions in MOBILE_PHONE_PRINCIPLES:
        content = legacy.safe_svg(ROOT / mobile_path, mobile_path)
        require(
            f'width="{canvas_width}" height="{canvas_height}" viewBox="0 0 {canvas_width} {canvas_height}"' in content,
            f"Phone principle dimensions changed: {mobile_path}",
        )
        require('font-size="24"' in content and 'font-size="23"' not in content,
                f"Phone principle typography must retain the shared 24px optical scale: {mobile_path}")
        require(content.count('x="107"') == len(lines) and '<rect x="4" y="1" width="206" height="102"' in content,
                f"Phone principle shared optical geometry changed: {mobile_path}")
        require(content.count("<text ") == len(lines),
                f"Phone principle line count changed: {mobile_path}")
        for line, y_position in zip(lines, y_positions, strict=True):
            require(f'y="{y_position}"' in content and f'>{line}</text>' in content,
                    f"Phone principle line layout changed: {mobile_path}: {line}")
        portrait_source = (
            f'<source {phone_portrait} srcset="{mobile_path}" '
            f'width="{render_width}" height="{render_height}">'
        )
        landscape_source = (
            f'<source {phone_landscape} srcset="{mobile_path}" '
            f'width="{render_width}" height="{render_height}">'
        )
        require(readme.count(portrait_source) == 1,
                f"Phone portrait principle source changed: {alt}")
        require(readme.count(landscape_source) == 1,
                f"Phone landscape principle source changed: {alt}")
        desktop_path = next(item[1] for item in DESKTOP_PRINCIPLES if item[0] == alt)
        desktop_source = f'<source media="(min-width: 1025px)" srcset="{desktop_path}"'
        fallback = f'<img alt="{alt}"'
        portrait_index = readme.find(portrait_source)
        landscape_index = readme.find(landscape_source)
        desktop_index = readme.find(desktop_source)
        fallback_index = readme.find(fallback, desktop_index)
        require(
            0 <= portrait_index < landscape_index < desktop_index < fallback_index,
            f"Phone principle source ordering changed: {alt}",
        )

    for alt, desktop_path, width, height, mobile_path, mobile_height in DESKTOP_PRINCIPLES:
        content=legacy.safe_svg(ROOT/desktop_path, desktop_path)
        require(f'width="{width}" height="{height}" viewBox="0 0 {width} {height}"' in content,
                f"Desktop principle dimensions changed: {desktop_path}")
        require('font-size="16"' in content,
                f"Desktop principle typography must retain the reviewed 16px label scale: {desktop_path}")
        source = f'<source media="(min-width: 1025px)" srcset="{desktop_path}" width="{width}" height="{height}">'
        fallback = f'<img alt="{alt}" height="{mobile_height}" src="{mobile_path}">'
        require(readme.count(source) == 1, f"Desktop-only principle source changed: {alt}")
        require(readme.count(fallback) == 1, f"Mobile principle fallback changed: {alt}")


def validate_flagships(readme: str) -> None:
    for old in RETIRED_FLAGSHIP_SVGS:
        require(not (ROOT / old).exists(), f"Retired single-theme system card must remain removed: {old}")
        require(old not in readme, f"README references retired single-theme system card: {old}")
    for relative in FLAGSHIP_SVGS:
        content=legacy.safe_svg(ROOT/relative, relative)
        require('data-system-card="selected-engineering-systems-v4"' in content, f"System-card v4 provenance missing: {relative}")
        expected_theme="dark" if relative.endswith("-dark.svg") else "light"
        require(f'data-theme="{expected_theme}"' in content, f"Explicit theme marker changed: {relative}")
        require("@media" not in content, f"System card must not depend on internal theme media queries: {relative}")
        require('<linearGradient id="edge"' in content and '<linearGradient id="wash"' in content and 'fill="url(#edge)"' in content and 'fill="url(#wash)"' in content, f"Rich gradient visual system regressed: {relative}")
        require(content.count("<circle") >= 4, f"Flagship topology nodes regressed: {relative}")
        require(readme.count(relative)==1, f"System card variant must be referenced exactly once: {relative}")
    require(readme.count('media="(prefers-color-scheme: dark)" srcset="assets/profile-systems/qualification-') == 4, "Each flagship must select an explicit dark SVG in README picture markup")
    require(readme.count('Four flagship systems · scoped live <code>main</code>-branch evidence') == 1,
            "Selected Engineering Systems must describe exactly four flagship systems")
    require('Three flagship systems · scoped live <code>main</code>-branch evidence' not in readme,
            "Legacy three-flagship subtitle returned")
    for phrase in (
        "Bounded AI reasoning · deterministic policy authority",
        "DETERMINISTIC POLICY",
        "TRACEABLE EVIDENCE",
        "FAIL-CLOSED MUTATIONS",
        "Evidence-bound agent trials · deterministic evaluation authority",
        "OUTCOME ORACLES",
        "AUTHORITY BOUNDARIES",
        "REPLAY + RELEASE GATES",
        "Schema · execution · authorization contracts",
        "AUTHORIZATION BOUNDARY",
        "Visual evidence · explicit accessibility oracles",
        "AXE-CORE + KEYBOARD",
        "BASELINE GOVERNANCE",
    ):
        require(any(phrase in (ROOT/path).read_text(encoding="utf-8") for path in FLAGSHIP_SVGS), f"Reviewed flagship language missing: {phrase}")
    require(readme.count('ai-qa-automation/ci.yml?branch=main')==1 and readme.count('ai-qa-automation/security.yml?branch=main')==1, "AI flagship must expose CI + Security")
    require(readme.count('qa-automation-ai-agent-evals/ci.yml?branch=main')==1 and readme.count('qa-automation-ai-agent-evals/security.yml?branch=main')==1, "Agent Evaluation / TEVV flagship must expose CI + Security")
    require(readme.count('qa-automation-graphql/ci.yml?branch=main')==1 and readme.count('qa-automation-graphql/security.yml?branch=main')==1, "GraphQL flagship must expose CI + Security")
    require(readme.count('qa-automation-visual-and-accessibility-playwright-axe/ci.yml?branch=main')==1 and readme.count('qa-automation-visual-and-accessibility-playwright-axe/security.yml?branch=main')==1, "Visual/accessibility flagship must expose CI + Security")

    sequence = (
        ("qualification-ai-qa-control-plane", "01"),
        ("qualification-agent-evaluation-tevv", "02"),
        ("qualification-graphql-qe", "03"),
        ("qualification-visual-accessibility-qe", "04"),
    )
    for family, number in sequence:
        for theme in ("light", "dark"):
            path = ROOT / f"assets/profile-systems/{family}-{theme}.svg"
            content = path.read_text(encoding="utf-8")
            require(f"ENGINEERING SYSTEM · {number}" in content,
                    f"Engineering system sequence changed: {family}-{theme}")

    agent_dark=(ROOT/"assets/profile-systems/qualification-agent-evaluation-tevv-dark.svg").read_text(encoding="utf-8")
    agent_light=(ROOT/"assets/profile-systems/qualification-agent-evaluation-tevv-light.svg").read_text(encoding="utf-8")
    require('#FF4D4D' in agent_dark and '#FF3131' in agent_dark,
            "Agent Evaluation dark phosphorescent-red treatment changed")
    require('#C81D25' in agent_light and '#FF3131' in agent_light,
            "Agent Evaluation light phosphorescent-red treatment changed")


def validate_animated_hero(readme: str) -> None:
    """Pin the cache-safe, payload-bounded animated hero without weakening its motion contract."""
    path = ROOT / ANIMATED_HERO_SVG
    require(path.is_file(), f"Optimized animated hero is missing: {ANIMATED_HERO_SVG}")
    require(not (ROOT / RETIRED_ANIMATED_HERO_SVG).exists(),
            "Retired oversized animated hero must remain removed")
    require(readme.count(ANIMATED_HERO_SVG) == 1,
            "README must reference the optimized animated hero exactly once")
    require(RETIRED_ANIMATED_HERO_SVG not in readme,
            "README must not reference the retired oversized animated hero")

    svg_bytes = path.read_bytes()
    require(len(svg_bytes) == ANIMATED_HERO_SVG_SIZE,
            f"Optimized animated hero size changed: {len(svg_bytes)}")
    require(hashlib.sha256(svg_bytes).hexdigest() == ANIMATED_HERO_SVG_SHA256,
            "Optimized animated hero bytes changed")
    try:
        text = svg_bytes.decode("utf-8")
    except UnicodeDecodeError:
        legacy.fail("Optimized animated hero must remain UTF-8 SVG")

    require(
        f'width="{ANIMATED_HERO_WIDTH}" height="{ANIMATED_HERO_HEIGHT}" viewBox="0 0 1535 1024"' in text,
        "Optimized animated hero intrinsic dimensions changed",
    )
    payload_matches = re.findall(r'data:image/webp;base64,([^"\'<>]+)', text)
    require(len(payload_matches) == 1,
            "Optimized animated hero must contain exactly one embedded WebP base")
    try:
        payload = base64.b64decode(payload_matches[0], validate=True)
    except (ValueError, binascii.Error):
        legacy.fail("Optimized animated hero contains invalid base64 WebP data")

    require(len(payload) == ANIMATED_HERO_WEBP_SIZE,
            f"Optimized animated hero WebP size changed: {len(payload)}")
    require(hashlib.sha256(payload).hexdigest() == ANIMATED_HERO_WEBP_SHA256,
            "Optimized animated hero embedded WebP bytes changed")
    require(payload[:4] == b"RIFF" and payload[8:12] == b"WEBP" and payload[12:16] == b"VP8X",
            "Optimized animated hero embedded payload is not the reviewed extended WebP")
    require(len(payload) >= 30 and int.from_bytes(payload[16:20], "little") == 10,
            "Optimized animated hero VP8X header changed")
    width = int.from_bytes(payload[24:27], "little") + 1
    height = int.from_bytes(payload[27:30], "little") + 1
    require((width, height) == (ANIMATED_HERO_WIDTH, ANIMATED_HERO_HEIGHT),
            "Optimized animated hero embedded WebP dimensions changed")

    counts = (
        len(re.findall(r"<animate\b", text)),
        len(re.findall(r"<animateTransform\b", text)),
        len(re.findall(r"<animateMotion\b", text)),
    )
    require(counts == ANIMATED_HERO_ANIMATION_COUNTS,
            f"Animated hero motion inventory changed: {counts}")
    require(text.count("<filter ") == 6 and text.count("<feGaussianBlur ") == 6,
            "Animated hero reviewed glow/filter inventory changed")
    require(text.count("<feTurbulence ") == 1 and text.count("<feDisplacementMap ") == 1,
            "Animated hero reviewed atmospheric filter inventory changed")
    require(text.count("@media (prefers-reduced-motion: reduce)") == 1,
            "Animated hero reduced-motion contract changed")

    normalized = re.sub(
        r'data:image/webp;base64,[^"\'<>]+',
        "data:image/webp;base64,<EMBEDDED_WEBP>",
        text,
        count=1,
    )
    normalized, dimension_count = re.subn(
        r'width="\d+" height="\d+" viewBox="0 0 1535 1024"',
        'width="<WIDTH>" height="<HEIGHT>" viewBox="0 0 1535 1024"',
        normalized,
        count=1,
    )
    require(dimension_count == 1, "Animated hero normalized dimension contract changed")
    require(
        hashlib.sha256(normalized.encode("utf-8")).hexdigest() == ANIMATED_HERO_NORMALIZED_SHELL_SHA256,
        "Animated hero vector/animation shell changed independently of the reviewed payload optimization",
    )


def main() -> int:
    readme=README.read_text(encoding="utf-8")
    for retired in legacy.RETIRED_ASSETS:
        require(not (ROOT/retired).exists(), f"Retired asset must remain removed: {retired}")
        require(retired not in readme, f"README references retired asset: {retired}")
    for relative in PROFILE_BANNER_SVGS:
        require((ROOT / relative).is_file(), f"Approved profile banner is missing: {relative}")
    validate_animated_hero(readme)
    require(readme.count(BOTTOM_HORIZON_BLOCK) == 1,
            "Bottom evidence horizon must remain visible exactly once in non-linked picture markup")
    require(BOTTOM_HORIZON_ANCHOR.search(readme) is None,
            "Bottom evidence horizon must never be wrapped by a clickable anchor")
    require('<strong>Review paths</strong>' not in readme,
            "Retired Review paths row returned")
    require(legacy.HERO_IMAGE.is_file(), f"Profile hero image is missing: {legacy.HERO_REFERENCE}")
    hero_bytes=legacy.HERO_IMAGE.read_bytes()
    require(len(hero_bytes)==legacy.HERO_SIZE, f"Profile hero image size changed: expected {legacy.HERO_SIZE}, got {len(hero_bytes)}")
    require(hashlib.sha256(hero_bytes).hexdigest()==legacy.HERO_SHA256, "Profile hero image bytes differ from the reviewed optimized fallback")
    require(hero_bytes[:8] == b"\x89PNG\r\n\x1a\n" and len(hero_bytes) >= 24 and hero_bytes[12:16] == b"IHDR",
            "Profile hero optimized fallback is not a valid PNG header")
    require((int.from_bytes(hero_bytes[16:20], "big"), int.from_bytes(hero_bytes[20:24], "big")) ==
            (legacy.HERO_WIDTH, legacy.HERO_HEIGHT),
            "Profile hero optimized fallback dimensions changed")
    require(readme.count(legacy.HERO_REFERENCE)==1, "Profile hero fallback reference must appear exactly once")
    require(len(re.findall(r'<h2\s+align="center">\s*✦ Engineering Thesis\s*</h2>', readme, re.I))==1, "Engineering Thesis must remain one centered H2")
    require(readme.count('<h2 align="center">◉ Activity Metrics</h2>')==1, "Activity Metrics must remain one centered H2")
    require(readme.count('<h2 align="center">◇ Selected Engineering Systems</h2>')==1, "Selected Engineering Systems must remain one centered H2")
    require('<h2 align="center">◇ Qualification Matrix</h2>' not in readme, "Retired Qualification Matrix heading returned")
    require(readme.count('<h3 align="center">↻ Evidence Spotlight</h3>')==1, "Evidence Spotlight must remain one centered H3")
    for phrase in legacy.REQUIRED_WORDING:
        require(phrase in readme, f"Reviewed wording is missing: {phrase}")
    for phrase in legacy.FORBIDDEN_WORDING:
        require(phrase not in readme, f"Retired wording returned: {phrase}")
    require(readme.count("© 2026 Ƴunior Ƥortal. All rights reserved.")==1, "Copyright owner/year must appear exactly once")

    validate_taxonomy_scale(readme); validate_thesis_scale(readme)
    for relative in legacy.IDENTITY_AND_PRINCIPLE_SVGS: legacy.safe_svg(ROOT/relative, relative)
    for relative in legacy.PRINCIPLE_BADGES:
        content=(ROOT/relative).read_text(encoding="utf-8")
        require('font-size="23"' in content and 'font-size="24"' not in content, f"Mobile principle badge typography changed: {relative}")
    oracle=(ROOT/"assets/profile-badges/principle-oracle-discipline.svg").read_text(encoding="utf-8")
    require('width="210" height="54" viewBox="0 0 210 54"' in oracle, "Mobile Oracle Discipline must retain its 210px canvas")
    repro=(ROOT/"assets/profile-badges/principle-reproducibility-optics.svg").read_text(encoding="utf-8")
    require(">Reproducibility</text>" in repro and ">over Optics</text>" in repro, "Reproducibility principle wording changed")
    validate_flagships(readme); validate_references(readme)
    require("3 systems · deterministic daily rotation" in readme, "Three-system daily deterministic spotlight policy must remain explicit")
    require("From my QE systems portfolio" in readme, "Spotlight ownership wording changed")
    require("engineering-systems-preview-pr50" not in readme, "PR-only Spotlight preview references must not reach production")
    require(readme.count('width="620"') >= 3, "Three Spotlight cards must retain native-width desktop proportions")
    systems=readme.find('<h2 align="center">◇ Selected Engineering Systems</h2>'); spotlight=readme.find('<h3 align="center">↻ Evidence Spotlight</h3>'); activity=readme.find('<h2 align="center">◉ Activity Metrics</h2>'); signal=readme.find('alt="GitHub activity signal field"'); copyright_notice=readme.find("© 2026 Ƴunior Ƥortal")
    require(systems<spotlight<activity<signal<copyright_notice, "Systems-first portfolio information architecture changed")
    footer='\n---\n\n<p align="center">\n<sub><strong>© 2026 Ƴunior Ƥortal. All rights reserved.</strong></sub>'
    require(readme.count(footer)==1, "A horizontal rule must exist immediately above the copyright footer")
    require("release-candidate.yml?branch=main" not in readme, "Profile must not present an RC workflow with no current main status")
    print("Profile v4 validation passed: Review paths are retired; the bottom evidence horizon is visible in non-anchor picture markup; 17 evidence-linked capabilities, four numbered flagship systems, and three Evidence Spotlights precede Activity Metrics; responsive thesis and evidence contracts remain fail-closed.")
    return 0
if __name__ == "__main__": raise SystemExit(main())
