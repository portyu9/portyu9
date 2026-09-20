# Repository ruleset control-plane contract

**Contract:** `.github/rulesets/repository-rulesets-v1.json`  
**Repository:** `portyu9/portyu9`

GitHub branch rulesets are repository control-plane state, not ordinary source files. This document records the exact intended protection semantics so a settings change cannot be mistaken for an unreviewed operational preference.

## Protect Main

`Protect Main` targets the default branch, is active, has no bypass actors, blocks deletion and non-fast-forward updates, requires pull requests, permits only merge commits, and requires these exact status contexts on the current head:

- `validate-contracts`
- `trusted-capability-admission`
- `trusted-governed-bot-review`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

All seven required status checks are additionally bound to the GitHub Actions app identity `integration_id: 15368`. Matching a context name is not sufficient: the live ruleset gate requires every required-check entry to carry that exact integration ID so a same-named status emitted by another integration cannot satisfy the reviewed merge contract.

`trusted-capability-admission` is the default-branch-trusted authority-expansion gate. It evaluates pull-request capability source as inert data using trusted base code and requires an exact prior default-branch authorization for any semantic capability expansion or protected admission-TCB expansion. It does not replace `validate-contracts`; the latter remains required for the broader repository validation surface.

`trusted-governed-bot-review` is the GitHub-native server merge gate for the exact marker-bound `portyu9` review contract. Ordinary human PRs complete it as deterministic not-applicable success. Dependabot GitHub Actions, CodeQL Autofix, and Spotlight PRs can complete it only after the exact v2 base/head marker-bound APPROVED review exists and no latest manual exact-head `CHANGES_REQUESTED` veto or revoked marker is active. The reviewer still uses the existing six/lane-specific pre-review gates, so the seventh context does not create a circular review dependency.

The pull-request rule intentionally keeps `required_approving_review_count: 0` for my solo-maintainer repository. It must require `required_review_thread_resolution: true` so an unresolved review conversation cannot be bypassed merely because no second approving reviewer is configured.

`dismiss_stale_reviews_on_push`, code-owner review, and last-push approval remain disabled because they do not add a meaningful independent reviewer in my current ownership model and can create an artificial self-approval deadlock.

## Protect generated

`Protect generated` targets only `refs/heads/generated`, is active, has no bypass actors, and blocks deletion and non-fast-forward updates. It intentionally does not require pull requests or status checks because my reviewed `publish-write-only` job must be able to make normal fast-forward artifact commits after generation and attestation succeed.

## Verification

`python3 scripts/validate-ruleset-contract.py` validates the version-controlled contract and its fail-closed invariants without requiring administration access.

`python3 scripts/validate-ruleset-contract.py --live` additionally reads GitHub's repository rulesets and compares every field observable to the read-only workflow identity with the version-controlled target. `Profile quality / validate-contracts` executes this live form on every pull request and on relevant `main` pushes. A mismatch in the observable control-plane surface is therefore a **merge-blocking** governance defect rather than a separate manual observation.

The required live comparison covers the exact ruleset inventory, targets, enforcement, `Protect Main` pull-request parameters, the strict seven-check set including each check's GitHub Actions integration identity, and the `Protect generated` rule inventory. If GitHub exposes `bypass_actors` to the workflow identity, a non-empty value also fails the gate.

The steady-state live contract accepts only the final seven-context set above. The historical six-context predecessor remains recorded in `.github/rulesets/ruleset-transitions-v1.json` solely for reconciliation provenance, receipt verification, and idempotent already-applied classification; it is not an accepted steady-state ruleset. No partial, substituted, extra, or predecessor context set is accepted by ordinary live validation.

GitHub currently redacts `bypass_actors` from both the short-lived read-only Actions token and the unauthenticated public API view. The validator does not interpret that omission as an empty list. Empty bypass actors remain locked as desired state in the source contract and as a separate **admin-scope** control-plane audit invariant. An administration-capable read must periodically confirm that invariant; the latest connected control-plane audit observed `bypass_actors: []` on both repository rulesets.

The unauthenticated public lookup is only a supplemental attempt to observe that already-documented admin-scope field. Hosted runners share public GitHub API quota with other traffic, so a proven public response of HTTP 403 with `X-RateLimit-Remaining: 0` leaves `bypass_actors` unobservable rather than failing an otherwise authenticated live control-plane comparison. That narrow condition is not interpreted as an empty bypass list; **all other public API failures remain merge-blocking**, and authenticated ruleset-read failures or any observable ruleset mismatch always fail closed.

The connected mutation surface used for my repository may still lack GitHub administration authority. Source review can codify and verify desired ruleset state, but it must not claim a control-plane setting changed unless an authorized settings operation occurred and the observable live gate plus any admin-scope invariant checks return the expected state.


## Read-only drift sentinel

`.github/workflows/ruleset-drift-sentinel.yml` is the GitHub-native, read-only drift sentinel for the repository ruleset control plane. It runs every six hours and may also be dispatched manually, but the detection job executes only for `portyu9/portyu9` on `refs/heads/main`.

The sentinel has only `contents: read`. It first reads the live `main` ref and requires it to equal the exact workflow source SHA, then executes the same fail-closed `validate-ruleset-contract.py --live` contract used by Profile Quality. It does not write repository settings, refs, pull requests, reviews, checks, workflow state, attestations, or artifacts, and it does not use `PORTYU9_BOT_REVIEW_TOKEN`.

This sentinel is detection only. Deliberate remediation is implemented separately by `.github/workflows/ruleset-reconciler.yml`. The reconciler wakes on ordinary accepted `main` pushes and retains `workflow_dispatch` only as a recovery path. Because GitHub suppresses recursive `push` workflow creation for merges performed with `GITHUB_TOKEN`, it also wakes on completed `workflow_run` events from only the exact trusted CodeQL Autofix controller, Dependabot controller, and Spotlight sync workflow name/path pairs. The read-only plan re-proves the exact repository, current `main`, and wake-source identity; a controller completion whose recorded head already equals current `main` exits as not-applicable before ruleset classification or any Administration secret access, while a controller completion spanning a `main` advance proceeds through the same exact reviewed predecessor/successor classification. The serialized, non-cancellable Administration job is entered only for the exact predecessor. When the exact successor is already live, applicable wakes stop before any admin token is minted or ruleset write is attempted. The workflow remains bound to one exact reviewed repository/ruleset/endpoint/method/predecessor/successor transition, uses the dedicated `ruleset-admin-identity` environment and repository-scoped GitHub App bootstrap secrets to mint a short-lived Administration-only installation token, and must never use `PORTYU9_BOT_REVIEW_TOKEN`.

Before mutation, the reconciler re-proves exact trusted `main`, App/installation/repository scope, token lifetime, and the exact administration-scope predecessor. It emits one reviewed PUT payload, immediately re-reads the ruleset, requires the exact successor, preserves a non-secret reconciliation receipt, and attests that receipt in a separate signer job. If the successor is already present, the serialized writer exits without a second ruleset mutation; an ambiguous write response is classified by readback rather than blindly retried.
