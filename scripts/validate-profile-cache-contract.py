#!/usr/bin/env python3
"""Validate cache-busting identities for mutable generated profile surfaces."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

SPOTLIGHT_TOKEN = "engineering-spotlight-v21-ledger-v1-20260905"
SIGNAL_FIELD_TOKEN = "signal-field-v214-evidence-id-20260905"

SPOTLIGHT = re.compile(
    r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/engineering-spotlight/"
    r"spotlight-[123]-(?:light|dark)\.svg\?v=([^\"'> ]+)"
)
SIGNAL_FIELD = re.compile(
    r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/profile-stats/profile/"
    r"signal-field-(?:wide|compact)-(?:light|dark)\.svg\?v=([^\"'> ]+)"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate() -> None:
    text = README.read_text(encoding="utf-8")
    spotlight = SPOTLIGHT.findall(text)
    signal = SIGNAL_FIELD.findall(text)

    require(len(spotlight) == 6, "README must reference exactly six generated Spotlight theme assets")
    require(len(signal) == 4, "README must reference exactly four generated Signal Field assets")
    require(set(spotlight) == {SPOTLIGHT_TOKEN}, "Spotlight cache token is stale or inconsistent across slots/themes")
    require(set(signal) == {SIGNAL_FIELD_TOKEN}, "Signal Field cache token is stale or inconsistent across layouts/themes")

    require("engineering-spotlight-v21-three-slots-20260905" not in text, "pre-Ledger Spotlight cache token remains in README")
    require("signal-field-v212-balance-20260903" not in text, "pre-v2.14 Signal Field cache token remains in README")

    # Mutable generated-branch surfaces must never be referenced without an explicit
    # cache identity. Immutable source-revision URLs elsewhere in the README do not
    # need query-based cache busting.
    generated_urls = re.findall(
        r"https://raw\.githubusercontent\.com/portyu9/portyu9/generated/[^\"'> ]+",
        text,
    )
    require(len(generated_urls) == 10, "generated profile asset URL inventory changed")
    require(all("?v=" in url for url in generated_urls), "mutable generated profile asset lacks an explicit cache identity")


def main() -> int:
    try:
        validate()
        print(
            "Profile cache contract passed: six Spotlight and four Signal Field generated assets "
            "use one current cache identity per surface family."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
