#!/usr/bin/env python3
"""Exercise real repository workflow corpus against trusted artifact release derivation.

Network-free. Candidate workflows are inert fixture data; all executable logic
comes from the checked-out reviewed test module and trusted compiler.
"""
from __future__ import annotations

import copy
from pathlib import Path
import shutil
import tempfile

import dependabot_artifact_reconciliation as reconciler
from action_identity_lock import load_action_lock

ROOT = Path(__file__).resolve().parents[1]


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def self_test() -> None:
    lock = load_action_lock(ROOT / reconciler.LOCK_PATH)
    for repo in sorted(reconciler.REPOSITORIES):
        action = repo
        before = dict(lock[action])
        after = dict(before)
        after["sha"] = "b" * 40
        after["tag"] = ("v7.0.2" if repo.endswith("upload-artifact") else "v8.0.2")
        after["tagRefSha"] = "b" * 40
        after["releaseId"] = before["releaseId"] + 1

        with tempfile.TemporaryDirectory(prefix="artifact-admission-fixture-") as tmp:
            candidate = Path(tmp)
            shutil.copytree(ROOT / ".github", candidate / ".github",
                            symlinks=False)
            changed: list[str] = []
            changed_uses = 0
            for path in sorted((candidate / ".github/workflows").glob("*.yml")):
                source = path.read_text(encoding="utf-8")
                prior = f"uses: {repo}@{before['sha']} # {before['tag']}"
                nxt = f"uses: {repo}@{after['sha']} # {after['tag']}"
                if prior not in source:
                    continue
                updated = source.replace(prior, nxt)
                changed_uses += source.count(prior)
                path.write_text(updated, encoding="utf-8")
                changed.append(path.relative_to(candidate).as_posix())
            require(changed and changed_uses >= len(changed),
                    "fixture did not advance every affected Action workflow")

            proof = {
                "classification": "allowed",
                "dependencyRepository": repo,
                "before": before, "after": after,
                "actions": [action], "files": sorted(changed),
            }
            derived = reconciler.derive(
                trusted_root=ROOT, candidate_root=candidate, proof=proof,
            )
            require(reconciler.LOCK_PATH in derived and
                    reconciler.BOM_PATH in derived and
                    reconciler.PRIVILEGED_IDENTITY in derived,
                    "real Action fixture lost required governance derivatives")
            require(reconciler.update_lock(
                (ROOT / reconciler.LOCK_PATH).read_text(encoding="utf-8"), proof,
            ) == derived[reconciler.LOCK_PATH],
                "real Action fixture lock update is not reproducible")
            require(all(name != next(iter(changed)) for name in derived),
                    "real Action fixture overwrote native Dependabot workflow pins")
            require(derived == reconciler.derive(
                trusted_root=ROOT, candidate_root=candidate, proof=proof,
            ), "real Action fixture derivation was not deterministic")
            try:
                reconciler.derive(
                    trusted_root=ROOT, candidate_root=candidate,
                    proof={**proof, "files": []},
                )
            except ValueError:
                pass
            else:
                raise ValueError("real Action fixture accepted an omitted changed-file list")


if __name__ == "__main__":
    self_test()
    print("Artifact release corpus regression: upload/download full atomic pin diff + derivative closure passed.")
