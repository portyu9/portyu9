# Repository ruleset control-plane contract

**Contract:** `.github/rulesets/repository-rulesets-v1.json`  
**Repository:** `portyu9/portyu9`

GitHub branch rulesets are repository control-plane state, not ordinary source files. This document records the exact intended protection semantics so a settings change cannot be mistaken for an unreviewed operational preference.

## Protect Main

`Protect Main` targets the default branch, is active, has no bypass actors, blocks deletion and non-fast-forward updates, requires pull requests, permits only merge commits, and requires these exact status contexts on the current head:

- `validate-contracts`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

The pull-request rule intentionally keeps `required_approving_review_count: 0` for a solo-maintainer repository. It must require `required_review_thread_resolution: true` so an unresolved review conversation cannot be bypassed merely because no second approving reviewer is configured.

`dismiss_stale_reviews_on_push`, code-owner review, and last-push approval remain disabled because they do not add a meaningful independent reviewer in the current ownership model and can create an artificial self-approval deadlock.

## Protect generated

`Protect generated` targets only `refs/heads/generated`, is active, has no bypass actors, and blocks deletion and non-fast-forward updates. It intentionally does not require pull requests or status checks because the reviewed `publish-write-only` job must be able to make normal fast-forward artifact commits after generation and attestation succeed.

## Verification

`python3 scripts/validate-ruleset-contract.py` validates the version-controlled contract and its fail-closed invariants without requiring administration access.

`python3 scripts/validate-ruleset-contract.py --live` additionally reads GitHub's repository rulesets and compares the control-plane state with the version-controlled target. `Profile quality / validate-contracts` executes this live form on every pull request and on relevant `main` pushes with only the workflow's read-only GitHub token. A live mismatch is therefore a **merge-blocking** governance defect rather than a separate manual observation.

The live comparison covers the exact ruleset inventory, targets, enforcement, bypass actors, `Protect Main` pull-request parameters, the strict five-check set, and the `Protect generated` rule inventory. It detects settings drift that cannot be represented by a repository source diff.

The connected mutation surface used for this repository may still lack GitHub administration authority. Source review can codify and verify the desired ruleset contract, but it must not claim a control-plane setting changed unless an authorized settings operation occurred and the live gate then returns success.
