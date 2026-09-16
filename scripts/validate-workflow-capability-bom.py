#!/usr/bin/env python3
"""Temporary read-only diagnostic for exact capability authorization tuple."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

BASE_SHA = "eb9e9c7254ea147521011515b95d6bee24db8682"
CANDIDATE_TREE_SHA = "b1edd853744eda7fe110cf6040e07ea9acd00130"


def main() -> int:
    base_root = Path("/tmp/codeql-autofix-auth-base")
    subprocess.run(["rm", "-rf", str(base_root)], check=True)
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", BASE_SHA], check=True)
    subprocess.run(["git", "worktree", "add", "--detach", str(base_root), BASE_SHA], check=True)
    sys.path.insert(0, str(base_root / "scripts"))

    import workflow_capability_admission as admission
    import workflow_capability_diff as capability_diff
    import workflow_capability_snapshot as snapshot
    import trusted_workflow_capability as trusted

    candidate_root = Path.cwd()
    base = snapshot.load_combined()
    candidate = trusted.compile_repository(candidate_root)
    diff = capability_diff.semantic_diff(base, candidate)
    diff = admission.protect_trusted_control(base, candidate, diff)
    diff = admission.protect_trusted_sources(candidate_root, CANDIDATE_TREE_SHA, diff)
    payload = {
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "expansionCount": len(diff["expansions"]),
        "reductionCount": len(diff["reductions"]),
        "trustedSourceKeys": [
            item.get("key") for item in diff["expansions"]
            if item.get("category") == "trusted-control-source"
        ],
        "candidateTcbSha256": sorted({
            item.get("after", {}).get("candidateTcbSha256")
            for item in diff["expansions"]
            if item.get("category") == "trusted-control-source" and isinstance(item.get("after"), dict)
        }),
    }
    print("AUTH_TUPLE=" + json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
