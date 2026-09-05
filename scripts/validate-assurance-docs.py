#!/usr/bin/env python3
"""Fail closed when governance/threat-model docs drift from the active trust graph."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
GOV = ROOT / ".github" / "GOVERNANCE.md"
THREAT = ROOT / ".github" / "THREAT_MODEL.md"

GOV_REQUIRED = (
    "Portfolio Evidence Ledger",
    "GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection",
    "exactly **11 subjects**",
    "spotlight-manifest.json",
    "frozen legacy verification contract",
    "profile-evidence-v2.schema.json",
    "predicateSchema",
    "validate-profile-cache-contract.py",
    "generate-read-only",
    "attest-validated-evidence",
    "publish-write-only",
    "id-token: write",
    "attestations: write",
    "does **not certify every software behavior**",
)

THREAT_REQUIRED = (
    "**Checkpoint:** 2026-09-05",
    "one Portfolio Evidence Ledger snapshot",
    "exactly 11 files",
    "Ledger-backed Spotlight projection",
    "frozen historical verification contract",
    "profile-evidence-v2.schema.json",
    "predicateSchema.digest",
    "Profile image cache boundary",
    "spotlight-manifest.json",
    "generated",
)

FORBIDDEN = (
    "Baseline: `main` after PR #65",
    "root is expected to contain only the generated Signal Field and Engineering Spotlight artifact trees",
    "revalidates both evidence sets",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    try:
        governance = GOV.read_text(encoding="utf-8")
        threat = THREAT.read_text(encoding="utf-8")
        for phrase in GOV_REQUIRED:
            require(phrase in governance, f"governance contract is missing current architecture phrase: {phrase}")
        for phrase in THREAT_REQUIRED:
            require(phrase in threat, f"threat model is missing current architecture phrase: {phrase}")
        joined = governance + "\n" + threat
        for phrase in FORBIDDEN:
            require(phrase not in joined, f"stale assurance statement remains: {phrase}")
        print("Assurance documentation contract passed: governance and threat model match the current evidence, schema, cache, and authority graph.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
