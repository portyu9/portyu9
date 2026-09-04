#!/usr/bin/env python3
"""Validate that profile capability badges link to substantive public evidence.

The profile's visible taxonomy is capability-oriented rather than tool-oriented. Every
badge therefore links to a public repository that directly demonstrates that capability,
and the link set collectively covers every substantive public QA framework currently
owned by portyu9. Placeholder/empty repositories are deliberately not treated as proof.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

EVIDENCE_LINKS = {
    "AI-Enabled QE": "https://github.com/portyu9/ai-qa-automation",
    "Web / UI": "https://github.com/portyu9/qa-automation-dotnet-selenium",
    "API": "https://github.com/portyu9/qa-automation-api-postman-newman",
    "GraphQL": "https://github.com/portyu9/qa-automation-graphql",
    "Mobile": "https://github.com/portyu9/qa-automation-mobile-appium",
    "CI/CD": "https://github.com/portyu9/qa-automation-ui-cypress",
    "Unit": "https://github.com/portyu9/qa-automation-python-pytest",
    "Component": "https://github.com/portyu9/qa-automation-node-supertest",
    "Integration": "https://github.com/portyu9/qa-automation-java-restassured",
    "Contract": "https://github.com/portyu9/qa-automation-node-supertest",
    "E2E": "https://github.com/portyu9/qa-automation-node-playwright",
    "Database / Persistence": "https://github.com/portyu9/qa-automation-python-pytest",
    "Visual Regression": "https://github.com/portyu9/qa-automation-visual-and-accessibility-playwright-axe",
    "Accessibility": "https://github.com/portyu9/qa-automation-visual-and-accessibility-playwright-axe",
    "Security": "https://github.com/portyu9/ai-qa-automation",
    "Performance": "https://github.com/portyu9/qa-automation-load-k6",
}

SUBSTANTIVE_PUBLIC_QE_REPOS = {
    "https://github.com/portyu9/ai-qa-automation",
    "https://github.com/portyu9/qa-automation-api-postman-newman",
    "https://github.com/portyu9/qa-automation-dotnet-selenium",
    "https://github.com/portyu9/qa-automation-graphql",
    "https://github.com/portyu9/qa-automation-java-restassured",
    "https://github.com/portyu9/qa-automation-load-k6",
    "https://github.com/portyu9/qa-automation-mobile-appium",
    "https://github.com/portyu9/qa-automation-node-playwright",
    "https://github.com/portyu9/qa-automation-node-supertest",
    "https://github.com/portyu9/qa-automation-python-pytest",
    "https://github.com/portyu9/qa-automation-ui-cypress",
    "https://github.com/portyu9/qa-automation-visual-and-accessibility-playwright-axe",
}

PLACEHOLDER_REPOS = {
    "https://github.com/portyu9/qa-automation-ai-agent-evals",
}


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    try:
        if not README.is_file():
            fail("README.md is missing")
        text = README.read_text(encoding="utf-8")

        if len(EVIDENCE_LINKS) != 16:
            fail("capability evidence map must cover exactly the 16 reviewed badges")

        linked_repos: set[str] = set()
        for label, href in EVIDENCE_LINKS.items():
            pattern = re.compile(
                rf'<a\s+href="{re.escape(href)}">\s*<picture>.*?'
                rf'<img\s+alt="{re.escape(label)}"\b.*?</picture>\s*</a>',
                re.I | re.S,
            )
            matches = pattern.findall(text)
            if len(matches) != 1:
                fail(f"capability badge must have exactly one reviewed evidence link: {label} -> {href}")
            linked_repos.add(href)

        missing_repos = sorted(SUBSTANTIVE_PUBLIC_QE_REPOS - linked_repos)
        if missing_repos:
            fail("substantive public QE repositories are not represented by badge evidence links: " + ", ".join(missing_repos))

        for repo in PLACEHOLDER_REPOS:
            if f'href="{repo}"' in text:
                fail(f"placeholder repository must not be presented as capability evidence: {repo}")

        print(
            "Capability evidence validation passed: all 16 reviewed badges are evidence-linked and the link set "
            "covers all 12 substantive public QE framework repositories without treating placeholders as proof."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
