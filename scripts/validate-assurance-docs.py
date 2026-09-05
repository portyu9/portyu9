#!/usr/bin/env python3
"""Fail closed when governance/threat-model docs drift from the active trust graph."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
GOV = ROOT / ".github" / "GOVERNANCE.md"
THREAT = ROOT / ".github" / "THREAT_MODEL.md"

SEMANTICS = "execution-result-subject-binding-freshness-v1"

GOV_REQUIRED = (
    "Portfolio Evidence Ledger v2",
    "GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection",
    "exactly **11 subjects**",
    "spotlight-manifest.json",
    "frozen historical verification contract",
    "profile-evidence-v3.schema.json",
    "profile-evidence-v2.schema.json",
    "predicateSchema",
    "PL2-",
    SEMANTICS,
    "execution result",
    "subject binding",
    "freshness",
    "DIFFERENT_SUBJECT",
    "CURRENT_SUBJECT",
    "validate-profile-cache-contract.py",
    "generate-read-only",
    "attest-validated-evidence",
    "publish-write-only",
    "id-token: write",
    "attestations: write",
    "validate-ruleset-contract.py --live",
    "live GitHub control-plane",
    "admin-scope",
    "does **not certify every software behavior**",
)

THREAT_REQUIRED = (
    "**Checkpoint:** 2026-09-05",
    "one Portfolio Evidence Ledger snapshot",
    "exactly 11 files",
    "Ledger-backed Spotlight projection",
    "frozen historical verification contract",
    "profile-evidence-v3.schema.json",
    "profile-evidence-v2.schema.json",
    "predicateSchema.digest",
    "PL2-",
    SEMANTICS,
    "execution result",
    "subject binding",
    "freshness",
    "DIFFERENT_SUBJECT",
    "CURRENT_SUBJECT",
    "Profile image cache boundary",
    "validate-ruleset-contract.py --live",
    "live GitHub control-plane",
    "admin-scope",
    "redact",
    "spotlight-manifest.json",
    "generated",
)

FORBIDDEN = (
    "Baseline: `main` after PR #65",
    "root is expected to contain only the generated Signal Field and Engineering Spotlight artifact trees",
    "revalidates both evidence sets",
    "New production attestations use `profile-evidence-v2.schema.json`",
    "current issuance uses v2",
    "PL1-XXXXXXXXXXXXXXXX",
    "signal state, and UTC whole-day freshness",
    "audited separately from source-controlled validators",
    "inspect repository rulesets separately from source-controlled validation",
    "redacted bypass actors are empty",
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
        print(
            "Assurance documentation contract passed: governance and threat model match Ledger v2 orthogonal evidence semantics, "
            "predicate v3 issuance, historical schema immutability, cache boundaries, authority separation, live observable ruleset drift verification, "
            "and the explicit admin-scope bypass-actor audit boundary."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
