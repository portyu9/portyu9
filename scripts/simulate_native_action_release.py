#!/usr/bin/env python3
"""Offline-only native Dependabot release candidate closure replay.

This simulation has no credentials, network transport, GitHub review, status
publication, branch updates or merge. It tests real admitted/derived data
from a disposable candidate, without changing any trusted controller source.
"""
from __future__ import annotations

from pathlib import Path
from action_identity_lock import repository_for_action
from dependabot_artifact_reconciliation import REPOSITORIES, require


def self_test() -> None:
    # No genuine new signed upstream version currently exists to create a
    # native Dependabot update. This offline integration fixture deliberately
    # mints NO real release, review, CI status or merge; instead it exercises
    # the same production native-actor, atomic lock/occurrence and derivation
    # functions on disposable, inert candidate tree bytes. Keep this apart
    # from first-attempt release-to-merge acceptance.
    import tempfile
    import shutil
    import dependabot_controller as controller
    from dependabot_pr_identity import fixture as pr_fixture
    base = Path(__file__).resolve().parents[1]
    lock = controller.load_action_lock(base / controller.ACTION_LOCK)
    for action_repository in sorted(REPOSITORIES):
        action_names = sorted(
            action for action in lock
            if repository_for_action(action) == action_repository
        )
        require(action_names and all(
            lock[name] == lock[action_names[0]] for name in action_names),
            "synthetic artifact candidate has divergent trusted pin baseline")
        previous = dict(lock[action_names[0]])
        fresh_sha = "b" * 40 if previous["sha"] != "b" * 40 else "c" * 40
        fresh_tag = "v999.0.0"
        require(previous["tag"] != fresh_tag,
                "synthetic artifact candidate is not a newer tag")
        fake_signed_release = {
            **previous,
            "releaseId": int(previous["releaseId"]) + 1,
            "tag": fresh_tag, "sha": fresh_sha,
            "tagRefSha": ("e" * 40 if fresh_sha != "e" * 40
                          else "f" * 40),
            "tagRefType": "tag",
        }
        with tempfile.TemporaryDirectory(
            prefix="dependabot-artifact-offline-"
        ) as disposable:
            fake_candidate = Path(disposable) / "candidate"
            shutil.copytree(base, fake_candidate, symlinks=True)
            replacements = 0
            for yaml_file in (fake_candidate / ".github/workflows").glob("*.yml"):
                original_yaml = yaml_file.read_text(encoding="utf-8")
                edited_yaml = original_yaml
                for action_name in action_names:
                    old_pin = (
                        f"{action_name}@{previous['sha']} "
                        f"# {previous['tag']}"
                    )
                    new_pin = (
                        f"{action_name}@{fresh_sha} "
                        f"# {fresh_tag}"
                    )
                    replacements += edited_yaml.count(old_pin)
                    edited_yaml = edited_yaml.replace(old_pin, new_pin)
                if edited_yaml != original_yaml:
                    yaml_file.write_text(edited_yaml, encoding="utf-8")
            require(replacements > 0,
                    "artifact simulation has no original Action uses occurrences")
            simulated_pr = pr_fixture()
            simulated_pr["head"]["sha"] = "d" * 40
            simulated_pr["head"]["ref"] = (
                f"dependabot/github_actions/{action_repository}-{fresh_tag}"
            )
            # A native PR claiming a different immutable commit can never
            # enter the simulated protected reconciliation, even if its title
            # or branch resembles the accepted native Dependabot namespace.
            mismatched = {
                **simulated_pr, "head": {
                    **simulated_pr["head"], "sha": "e" * 40,
                },
            }
            try:
                controller.probe(
                    pr=mismatched, expected_head_sha="d" * 40,
                    base_root=base, candidate_root=fake_candidate)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    "synthetic Dependabot PR spoofed an immutable head")
            proposal = controller.probe(
                pr=simulated_pr, expected_head_sha="d" * 40,
                base_root=base, candidate_root=fake_candidate)
            require(proposal["dependencyRepository"] == action_repository
                    and proposal["classification"] == "dependabot-artifact-probe",
                    "synthetic native Dependabot pin-only proposal was misclassified")
            admitted = controller.admit(
                pr=simulated_pr, expected_head_sha="d" * 40,
                base_root=base, candidate_root=fake_candidate,
                resolved_release=fake_signed_release)
            require(admitted["classification"] == "allowed"
                    and admitted["dependencyRepository"] == action_repository,
                    "synthetic native Dependabot signed release was not admitted")
            expected_derivatives = controller.derive_release_files(
                base_root=base, candidate_root=fake_candidate, proof=admitted)
            require(bool(expected_derivatives),
                    "synthetic artifact candidate has no canonical derivatives")
            controller.write_outputs(expected_derivatives, fake_candidate)
            diff_paths = sorted(set(admitted["files"]) | set(expected_derivatives))
            result = controller.validate_reconciled_candidate(
                base_root=base, candidate_root=fake_candidate,
                proof=admitted, changed_paths=diff_paths)
            require(result["classification"] == "dependabot-artifact-reconciled"
                    and result["dependencyRepository"] == action_repository,
                    "synthetic native release candidate did not converge")
            # Byte-level tampering is rejected by the actual final admission,
            # rather than a bespoke simulated policy.
            target_path = sorted(expected_derivatives)[0]
            output_file = fake_candidate / target_path
            output_file.write_text("tampered-release-derivative\n",
                                   encoding="utf-8")
            try:
                controller.validate_reconciled_candidate(
                    base_root=base, candidate_root=fake_candidate,
                    proof=admitted, changed_paths=diff_paths)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    "synthetic signed Action candidate admitted tampered "
                    + target_path)
            print(
                "OFFLINE Dependabot native release-to-reconciled-candidate "
                f"simulation PASS: {action_repository}, {replacements} "
                "atomic pin occurrences; no GitHub mutation")


    print("Dependabot offline artifact release-to-reconciled-candidate simulation: all 3 trusted Actions PASS")


if __name__ == "__main__":
    self_test()
