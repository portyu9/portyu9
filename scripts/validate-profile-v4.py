#!/usr/bin/env python3
"""Validate the reviewed profile plus Selected Engineering Systems v4 contracts.

Established profile contracts remain delegated to validate-profile.py helpers; this
validator replaces only the former Qualification Matrix contract with deterministic
light/dark flagship cards and generated daily Evidence Spotlight references.
"""
from __future__ import annotations
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

FLAGSHIP_SVGS = (
    "assets/profile-systems/qualification-ai-qa-control-plane-light.svg",
    "assets/profile-systems/qualification-ai-qa-control-plane-dark.svg",
    "assets/profile-systems/qualification-graphql-qe-light.svg",
    "assets/profile-systems/qualification-graphql-qe-dark.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe-light.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe-dark.svg",
)
RETIRED_FLAGSHIP_SVGS = (
    "assets/profile-systems/qualification-ai-qa-control-plane.svg",
    "assets/profile-systems/qualification-graphql-qe.svg",
    "assets/profile-systems/qualification-visual-accessibility-qe.svg",
)
SPOTLIGHT_REFS = (
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/engineering-spotlight/spotlight-1-light.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/engineering-spotlight/spotlight-1-dark.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/engineering-spotlight/spotlight-2-light.svg",
    "https://raw.githubusercontent.com/portyu9/portyu9/generated/engineering-spotlight/spotlight-2-dark.svg",
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
    for match in pattern.finditer(readme):
        ref=match.group(1) or match.group(2) or match.group(3)
        references.append(ref.split("?",1)[0].split("#",1)[0].lstrip("./"))
    allowed = set(legacy.IDENTITY_AND_PRINCIPLE_SVGS) | set(legacy.HEADER_REFERENCES) | set(legacy.GENERATED_SVG_REFERENCES) | set(FLAGSHIP_SVGS) | set(SPOTLIGHT_REFS)
    unexpected=sorted(set(references)-allowed); missing=sorted(allowed-set(references))
    require(not unexpected, "README contains unapproved SVG references: " + ", ".join(unexpected))
    require(not missing, "README is missing approved SVG references: " + ", ".join(missing))


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
        require(readme.count(relative)==1, f"System card variant must be referenced exactly once: {relative}")
    require(readme.count('media="(prefers-color-scheme: dark)" srcset="assets/profile-systems/qualification-') == 3, "Each flagship must select an explicit dark SVG in README picture markup")
    for phrase in (
        "Bounded AI reasoning · deterministic policy authority",
        "DETERMINISTIC POLICY",
        "TRACEABLE EVIDENCE",
        "FAIL-CLOSED MUTATIONS",
        "Schema · execution · authorization contracts",
        "AUTHORIZATION BOUNDARY",
        "Visual evidence · explicit accessibility oracles",
        "AXE-CORE + KEYBOARD",
        "BASELINE GOVERNANCE",
    ):
        require(any(phrase in (ROOT/path).read_text(encoding="utf-8") for path in FLAGSHIP_SVGS), f"Reviewed flagship language missing: {phrase}")
    require(readme.count('ai-qa-automation/ci.yml?branch=main')==1, "AI flagship must expose exactly one scoped CI badge")
    require(readme.count('qa-automation-graphql/ci.yml?branch=main')==1 and readme.count('qa-automation-graphql/security.yml?branch=main')==1, "GraphQL flagship must expose CI + Security")
    require(readme.count('qa-automation-visual-and-accessibility-playwright-axe/ci.yml?branch=main')==1 and readme.count('qa-automation-visual-and-accessibility-playwright-axe/security.yml?branch=main')==1, "Visual/accessibility flagship must expose CI + Security")


def main() -> int:
    readme=README.read_text(encoding="utf-8")
    for retired in legacy.RETIRED_ASSETS:
        require(not (ROOT/retired).exists(), f"Retired asset must remain removed: {retired}")
        require(retired not in readme, f"README references retired asset: {retired}")
    require(legacy.HERO_IMAGE.is_file(), f"Profile hero image is missing: {legacy.HERO_REFERENCE}")
    hero_bytes=legacy.HERO_IMAGE.read_bytes()
    require(len(hero_bytes)==legacy.HERO_SIZE, f"Profile hero image size changed: expected {legacy.HERO_SIZE}, got {len(hero_bytes)}")
    require(hashlib.sha256(hero_bytes).hexdigest()==legacy.HERO_SHA256, "Profile hero image bytes differ from the reviewed original")
    require(readme.find(legacy.HERO_REFERENCE)<readme.find("Ƴunior Ƥortal"), "Hero image must appear before the profile name")
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
    legacy.validate_badges(readme); legacy.validate_thesis_headers(readme)
    for relative in legacy.IDENTITY_AND_PRINCIPLE_SVGS: legacy.safe_svg(ROOT/relative, relative)
    for relative in legacy.PRINCIPLE_BADGES:
        content=(ROOT/relative).read_text(encoding="utf-8")
        require('font-size="23"' in content and 'font-size="24"' not in content, f"Principle badge typography changed: {relative}")
    oracle=(ROOT/"assets/profile-badges/principle-oracle-discipline.svg").read_text(encoding="utf-8")
    require('width="210" height="54" viewBox="0 0 210 54"' in oracle, "Oracle Discipline must retain its 210px canvas")
    repro=(ROOT/"assets/profile-badges/principle-reproducibility-optics.svg").read_text(encoding="utf-8")
    require(">Reproducibility</text>" in repro and ">over Optics</text>" in repro, "Reproducibility principle wording changed")
    validate_flagships(readme); validate_references(readme)
    for ref in SPOTLIGHT_REFS:
        require(readme.count(ref)==1, f"Generated spotlight reference must occur exactly once: {ref}")
    require("deterministically each UTC day" in readme, "Daily deterministic spotlight policy must remain explicit")
    require("curated pool of substantive public QE frameworks" in readme, "Spotlight qualification pool wording changed")
    activity=readme.find('<h2 align="center">◉ Activity Metrics</h2>'); signal=readme.find('alt="GitHub activity signal field"'); systems=readme.find('<h2 align="center">◇ Selected Engineering Systems</h2>'); spotlight=readme.find('<h3 align="center">↻ Evidence Spotlight</h3>'); copyright_notice=readme.find("© 2026 Ƴunior Ƥortal")
    require(activity<signal<systems<spotlight<copyright_notice, "Selected systems and spotlight placement changed")
    footer='\n---\n\n<p align="center">\n<sub><strong>© 2026 Ƴunior Ƥortal. All rights reserved.</strong></sub>'
    require(readme.count(footer)==1, "A horizontal rule must exist immediately above the copyright footer")
    require("release-candidate.yml?branch=main" not in readme, "Profile must not present an RC workflow with no current main status")
    print("Profile v4 validation passed: established profile contracts remain intact; three explicit-theme flagship systems and two generated daily Evidence Spotlights are attributable, scoped, responsive, and fail-closed by validation.")
    return 0
if __name__ == "__main__": raise SystemExit(main())
