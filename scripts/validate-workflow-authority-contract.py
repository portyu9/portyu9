#!/usr/bin/env python3
"""Adapt the item-11 workflow authority proof to the stabilized item-10 shell formatting."""
from __future__ import annotations

import workflow_authority_contract_item11_core as core


core.ITEM10_CANDIDATE_REPROOF = (
    '          test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"\n'
    '          gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content | '
    "tr -d '\\n' | base64 --decode > candidate-readme.md\n"
    '          test "$(sha256sum candidate-readme.md | cut -d\' \' -f1)" = "$README_SHA256_AFTER"\n'
)


def main() -> int:
    return core.main()


if __name__ == "__main__":
    raise SystemExit(main())
