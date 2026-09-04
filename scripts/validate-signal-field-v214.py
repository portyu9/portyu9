#!/usr/bin/env python3
"""Finalize Signal Field v2.15 presentation and validate v2.14 Evidence ID semantics."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER_PATH = ROOT / "scripts/identify-signal-field-evidence.py"
PRESENTATION_PATH = ROOT / "scripts/polish-signal-field-evidence-v215.py"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identifier = load_module(IDENTIFIER_PATH, "signal_field_evidence_id")
presentation = load_module(PRESENTATION_PATH, "signal_field_v215")


def validate_directory(directory: Path) -> tuple[str, str]:
    # v2.15 is deliberately idempotent. Generation reaches this validator immediately
    # after v2.14 stamping, while attestation/publication boundaries re-run it on already
    # finalized artifacts. In both cases the same final bytes are validated.
    presentation.apply(directory)

    identities: list[tuple[str, str]] = []
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        attrs = identifier.root_attrs(text)
        evidence_id = attrs.get("data-evidence-id", "")
        digest = attrs.get("data-evidence-digest", "")
        if attrs.get("data-evidence-identity") != identifier.VERSION:
            raise ValueError(f"{filename}: v2.14 Evidence ID provenance missing")
        if attrs.get("data-evidence-id-schema") != identifier.SCHEMA:
            raise ValueError(f"{filename}: Evidence ID schema changed")
        if attrs.get("data-evidence-presentation") != presentation.VERSION:
            raise ValueError(f"{filename}: v2.15 evidence-presentation provenance missing")
        if not re.fullmatch(r"SF1-[0-9A-F]{16}", evidence_id):
            raise ValueError(f"{filename}: Evidence ID format is invalid")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"{filename}: Evidence digest format is invalid")
        identifier.validate_stamped(text, path, evidence_id, digest)
        presentation.validate(text, path)
        identities.append((evidence_id, digest))

    if len(set(identities)) != 1:
        raise ValueError("Signal Field responsive variants do not share one Evidence ID/digest")
    evidence_id, digest = identities[0]
    print(
        "Signal Field v2.14/v2.15 validation passed: four variants share one deterministic "
        f"semantic identity {evidence_id}, preserve full {digest}, and use the reviewed final presentation."
    )
    return evidence_id, digest


def self_test() -> None:
    identifier.self_test()
    presentation.self_test()
    print("Signal Field v2.14 Evidence ID + v2.15 presentation validator self-test passed")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test(); return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: validate-signal-field-v214.py <generated-directory> | --self-test")
        validate_directory(Path(sys.argv[1])); return 0
    except (OSError, ValueError, AssertionError, RuntimeError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
