#!/usr/bin/env python3
"""Exercise real repository workflow corpus against trusted artifact release derivation.

Network-free. Candidate workflows are inert fixture data; all executable logic
comes from the checked-out reviewed test module and trusted compiler.
"""
from __future__ import annotations

import copy
from contextlib import chdir
import hashlib
import json
from pathlib import Path
import re
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
        # Derive a forward-only synthetic release from the current canonical
        # lock. The fixture must keep working after each genuine Dependabot
        # release is accepted; never pin its future version to today's release.
        current = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", before["tag"])
        require(current is not None,
                f"{repo}: fixture requires a stable three-component lock release")
        major, minor, patch = (int(part) for part in current.groups())
        after["tag"] = f"v{major}.{minor}.{patch + 1}"
        release_bytes = f"synthetic-artifact-release:{repo}:{after['tag']}".encode("utf-8")
        candidate_sha = hashlib.sha1(release_bytes).hexdigest()
        if candidate_sha == before["sha"]:
            candidate_sha = hashlib.sha1(release_bytes + b":collision").hexdigest()
        require(candidate_sha != before["sha"] and after["tag"] != before["tag"],
                f"{repo}: synthetic release must advance version and immutable identity")
        after["sha"] = candidate_sha
        after["tagRefSha"] = candidate_sha
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
            require(reconciler.SOURCE_EPOCH_PATH in derived,
                    "production Action update omitted the required Profile Stats source epoch")
            epoch = json.loads(derived[reconciler.SOURCE_EPOCH_PATH])
            accepted = json.loads((ROOT / reconciler.SOURCE_EPOCH_PATH).read_text(encoding="utf-8"))
            require(epoch["version"] == accepted["version"] and
                    epoch["algorithm"] == accepted["algorithm"] and
                    epoch["file_count"] == accepted["file_count"] and
                    epoch["closure_sha256"] != accepted["closure_sha256"],
                    "production Action update did not advance only the correct source epoch")
            base_workflows = {
                path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
                for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
            }
            candidate_workflows = {
                path.relative_to(candidate).as_posix(): path.read_text(encoding="utf-8")
                for path in sorted((candidate / ".github/workflows").glob("*.yml"))
            }
            projection = reconciler.update_profile_source_epoch(
                trusted_root=ROOT, base_workflows=base_workflows,
                candidate_workflows=candidate_workflows, derivatives=derived,
            )
            require(projection == derived[reconciler.SOURCE_EPOCH_PATH],
                    "source epoch was not a deterministic projection of canonical workflow and script bytes")
            require(all(name != next(iter(changed)) for name in derived),
                    "real Action fixture overwrote native Dependabot workflow pins")
            require(derived == reconciler.derive(
                trusted_root=ROOT, candidate_root=candidate, proof=proof,
            ), "real Action fixture derivation was not deterministic")
            # The production controller passes --base-root . from its checkout.
            # Re-execute the complete trusted-only derivation in that exact shape
            # for both upload and download releases; this must remain byte-identical
            # to an absolute trusted checkout after each future source change.
            with chdir(ROOT):
                relative_derived = reconciler.derive(
                    trusted_root=Path("."), candidate_root=candidate, proof=proof,
                )
            require(relative_derived == derived,
                    "production relative trusted-root derivation diverged from absolute root")
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
