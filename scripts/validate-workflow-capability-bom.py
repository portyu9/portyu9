#!/usr/bin/env python3
"""Diagnostic: run exact current-main capability admission and emit its rejected tuple."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "fc5bcd9bf4b7fe998bb737c287fc023eae47a063"
CANDIDATE_TREE_SHA = "45a9aa54de39406c91d3c51e20de905d7918202e"
REPOSITORY = "https://github.com/portyu9/portyu9.git"

PROBE = r'''
import json
from pathlib import Path
import sys
base_root = Path(sys.argv[1]).resolve()
candidate_root = Path(sys.argv[2]).resolve()
candidate_tree_sha = sys.argv[3]
sys.path.insert(0, str(base_root / "scripts"))
import workflow_capability_admission as admission
import workflow_capability_authorization as authorization
import workflow_capability_diff as capability_diff
import workflow_capability_snapshot as snapshot
import trusted_workflow_capability as trusted
base = snapshot.load_combined()
ledger = admission.strict_json(admission.TRUSTED_LEDGER, "trusted capability authorization ledger")
authorization.validate_ledger(ledger)
candidate = trusted.compile_repository(candidate_root)
diff = capability_diff.semantic_diff(base, candidate)
diff = admission.protect_trusted_control(base, candidate, diff)
diff = admission.protect_trusted_sources(candidate_root, candidate_tree_sha, diff)
decision = authorization.authorize(diff, ledger)
print("FINAL_DEPENDABOT_AUTH_TUPLE=" + json.dumps({
    "allowed": decision["allowed"],
    "authorizationRequired": decision["authorizationRequired"],
    "authorizationId": decision["authorizationId"],
    "baseBomSha256": diff["baseBomSha256"],
    "candidateBomSha256": diff["candidateBomSha256"],
    "expansionSha256": diff["expansionSha256"],
    "expansionCount": len(diff["expansions"]),
    "reductionCount": len(diff["reductions"]),
}, sort_keys=True, separators=(",", ":")))
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="dependabot-auth-base-") as raw:
        base_root = Path(raw)
        subprocess.run(["git", "init", "-q", str(base_root)], check=True)
        subprocess.run(
            ["git", "-C", str(base_root), "fetch", "-q", "--depth=1", REPOSITORY, BASE_SHA],
            check=True,
        )
        subprocess.run(["git", "-C", str(base_root), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
        completed = subprocess.run(
            [sys.executable, "-c", PROBE, str(base_root), str(ROOT), CANDIDATE_TREE_SHA],
            check=False,
            text=True,
        )
        if completed.returncode != 0:
            raise SystemExit(completed.returncode)
    print("ERROR: diagnostic intentionally stops Profile Quality after emitting the exact tuple", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
