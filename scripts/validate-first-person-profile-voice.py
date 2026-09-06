#!/usr/bin/env python3
"""Keep public-facing profile prose in first-person ownership voice."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MARKDOWN_PATHS = (
    ROOT / "README.md",
    ROOT / ".github" / "ATTESTATION.md",
    ROOT / ".github" / "GOVERNANCE.md",
    ROOT / ".github" / "REFRESH_CADENCE.md",
    ROOT / ".github" / "RULESETS.md",
    ROOT / ".github" / "THREAT_MODEL.md",
    ROOT / "assets" / "profile-badges" / "ASSET_POLICY.md",
)

FLAGSHIP_SVGS = tuple(sorted((ROOT / "assets" / "profile-systems").glob("qualification-*.svg")))

FIRST_PERSON_REQUIRED = {
    ROOT / ".github" / "ATTESTATION.md": (
        "My profile treats generated evidence as a supply-chain artifact rather than decorative output.",
        "My production profile workflow separates three authorities:",
        "represented by my profile",
    ),
    ROOT / ".github" / "GOVERNANCE.md": (
        "I treat my profile README",
        "represented by my profile",
        "during my profile evidence run",
    ),
    ROOT / ".github" / "REFRESH_CADENCE.md": (
        "My profile evidence pipeline has three refresh paths:",
        "My production push trigger covers the complete trusted `scripts/**` tree",
    ),
    ROOT / ".github" / "RULESETS.md": (
        "used for my repository",
    ),
    ROOT / ".github" / "THREAT_MODEL.md": (
        "my profile evidence system",
        "my public profile",
    ),
    ROOT / "assets" / "profile-badges" / "ASSET_POLICY.md": (
        "My profile hero is intentionally stored",
        "my active profile contract",
    ),
}

FORBIDDEN_MARKDOWN = (
    re.compile(r"\bthis profile\b", re.IGNORECASE),
    re.compile(r"\bthe profile\b", re.IGNORECASE),
    re.compile(r"\bthis repository\b", re.IGNORECASE),
    re.compile(r"\brepresented by the profile\b", re.IGNORECASE),
    re.compile(r"\bduring a profile evidence run\b", re.IGNORECASE),
)


def prose_only(markdown: str) -> str:
    """Remove code/URL surfaces before checking natural-language ownership phrasing."""
    text = re.sub(r"```.*?```", "", markdown, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", "", text)
    text = re.sub(r"https?://\S+", "", text)
    return text


def line_for(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def main() -> int:
    failures: list[str] = []

    for path in MARKDOWN_PATHS:
        if not path.is_file():
            failures.append(f"missing public prose file: {path.relative_to(ROOT)}")
            continue
        raw = path.read_text(encoding="utf-8")
        prose = prose_only(raw)
        for pattern in FORBIDDEN_MARKDOWN:
            for match in pattern.finditer(prose):
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_for(prose, match.start())}: "
                    f"detached ownership wording {match.group(0)!r}; use first-person ownership such as 'my profile', 'my repository', or 'I ...'"
                )
        for phrase in FIRST_PERSON_REQUIRED.get(path, ()):
            if phrase not in raw:
                failures.append(f"{path.relative_to(ROOT)}: missing required first-person wording: {phrase}")

    for path in FLAGSHIP_SVGS:
        raw = path.read_text(encoding="utf-8")
        desc_match = re.search(r"<desc\b[^>]*>(.*?)</desc>", raw, flags=re.DOTALL)
        if not desc_match:
            failures.append(f"{path.relative_to(ROOT)}: missing accessible <desc> copy")
            continue
        desc = desc_match.group(1)
        if "portfolio" in desc.lower() and "my portfolio" not in desc.lower():
            failures.append(
                f"{path.relative_to(ROOT)}: accessible portfolio description must identify ownership with 'my portfolio'"
            )
        if re.search(r"\bthe card is a portfolio summary\b", desc, flags=re.IGNORECASE):
            failures.append(
                f"{path.relative_to(ROOT)}: detached card description remains; describe the card as part of 'my portfolio'"
            )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print(
        "First-person profile voice contract passed: public Markdown ownership prose and flagship accessible descriptions are explicitly mine, while technical identifiers remain unchanged."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
