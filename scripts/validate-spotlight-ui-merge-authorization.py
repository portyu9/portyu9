#!/usr/bin/env python3
"""Project item-11 ADR tails around the frozen item-10 Spotlight MAC proof."""
from __future__ import annotations

import spotlight_ui_merge_authorization_item10_core as core


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strip_adr_tail(workflow: str, label: str) -> str:
    marker = "  decision_receipt:\n"
    require(workflow.count(marker) == 1,
            f"{label} item-11 projection cannot isolate ADR preparer")
    start = workflow.index(marker)
    tail = workflow[start:]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            f"{label} item-11 projection cannot isolate ADR signer")
    return workflow[:start]


def main() -> int:
    try:
        for path in (core.SYNC, core.STATS, core.POLICY, core.BUILDER, core.BUILDER_CORE,
                     core.PREPARER, core.SCHEMA):
            require(path.is_file() and not path.is_symlink(),
                    f"Spotlight merge authorization input is missing or aliased: {path.relative_to(core.ROOT)}")

        sync = strip_adr_tail(core.SYNC.read_text(encoding="utf-8"), "Spotlight")
        stats = strip_adr_tail(core.STATS.read_text(encoding="utf-8"), "Profile Stats")
        policy = core.POLICY.read_text(encoding="utf-8")
        preparer = core.PREPARER.read_text(encoding="utf-8")
        builder = core.BUILDER.read_text(encoding="utf-8")
        builder_core = core.BUILDER_CORE.read_text(encoding="utf-8")

        legacy = core.project_item9(sync)
        core.item9.validate(legacy, stats, policy)
        core.item9.self_test(legacy, stats, policy)
        core.validate_preparer_script(preparer)
        core.validate_builder_script(builder, builder_core)
        core.validate_mac(sync)
        core.self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: item-11 ADR tails are projected away before the complete frozen item-10 proof; "
            "stale reconciliation still validates the exact full PR object, the read-only MAC preparer independently re-proves live state, "
            "the isolated OIDC signer attests only the deterministic certificate subject, and terminal merge binds canonical live provenance "
            "and the CLI's direct verified statement before expected-head mutation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=core.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
