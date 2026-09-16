#!/usr/bin/env python3
"""Disposable unprotected diagnostic for exact prior-authorization digests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

import trusted_workflow_capability
import workflow_capability_diff
import workflow_capability_snapshot
import workflow_capability_tcb

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "2f369463ce6ccc9a029bce4210297a33bb064b14"
CONTROL_PATH = "scripts/codeql_autofix_controller.py"
BASE_URL = (
    "https://raw.githubusercontent.com/portyu9/portyu9/"
    f"{BASE_SHA}/{CONTROL_PATH}"
)


def main() -> int:
    base_bom = workflow_capability_snapshot.load_combined()
    candidate_bom = trusted_workflow_capability.compile_repository(ROOT)
    semantic = workflow_capability_diff.semantic_diff(base_bom, candidate_bom)
    if semantic["expansions"] or semantic["reductions"]:
        raise ValueError("diagnostic expected no semantic workflow capability change")

    with urlopen(BASE_URL, timeout=10) as response:
        base_source_sha256 = hashlib.sha256(response.read()).hexdigest()

    candidate_files = workflow_capability_tcb.protected_files(ROOT)
    candidate_source_sha256 = candidate_files[CONTROL_PATH]
    candidate_tcb_sha256 = workflow_capability_tcb.protected_digest(candidate_files)
    expansion = {
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": workflow_capability_tcb.CONTROL_WORKFLOW_ID,
        "key": CONTROL_PATH,
        "before": {"sha256": base_source_sha256},
        "after": {
            "sha256": candidate_source_sha256,
            "candidateTcbSha256": candidate_tcb_sha256,
        },
    }
    result = {
        "baseBomSha256": semantic["baseBomSha256"],
        "candidateBomSha256": semantic["candidateBomSha256"],
        "expansionSha256": workflow_capability_diff.digest([expansion]),
        "candidateTcbSha256": candidate_tcb_sha256,
        "baseSourceSha256": base_source_sha256,
        "candidateSourceSha256": candidate_source_sha256,
    }
    print("AUTHORIZATION_DIAGNOSTIC=" + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
