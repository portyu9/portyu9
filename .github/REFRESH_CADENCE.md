# Profile evidence refresh cadence

**Checkpoint:** 2026-09-10  
**Contract:** `profile-refresh-v2`

My profile evidence pipeline has three refresh paths:

- **push-triggered:** immediate when the reviewed production evidence source epoch or production workflow changes on `main`;
- **manual:** `workflow_dispatch` for an explicit operator refresh;
- **scheduled:** one best-effort opportunity per hour at minute **17**.

The scheduled path is deliberately a fallback. It is not the primary response to source changes, because relevant merges already trigger the same production workflow immediately.

## Push-trigger source closure

My production push trigger is intentionally narrow: `.github/workflows/profile-stats.yml` and `scripts/profile-stats-source-epoch-v1.json` are the only two invalidation tokens. The workflow token makes any change to the privileged execution graph self-invalidating. The second token is a content-addressed source epoch compiled from the complete reviewed production source closure.

`scripts/validate-profile-stats-trigger-contract.py` derives that production source closure from the versioned generation, Signal Field, validation-boundary, subject, and delegated-implementation authorities, plus the workflow's direct production script roots and the active attestation schema. The epoch records the exact closure size and one deterministic digest over every member identity. A production source change therefore cannot merge with a stale token: required Profile Quality recomputes the closure and fails closed until the source epoch is deliberately advanced in the same review.

This separates validation authority from publication authority. These validation-only changes do not trigger the privileged profile generation, attestation, publication, or downstream Spotlight transaction merely because they live under the scripts directory. They still run through required Profile Quality, CodeQL, and the other repository checks on their own pull request. Conversely, adding or changing a true production dependency without advancing the compiled epoch cannot satisfy the protected validation contract.

Workflow changes remain a direct trigger because the workflow itself is authority-bearing and is separately byte-locked. Predicate-schema changes are part of the compiled production epoch rather than a wildcard trigger. The result is fail-closed under-trigger protection without the previous over-trigger behavior that converted unrelated validator maintenance into a publishing event.

## Measurement that retired the five-minute request

The prior workflow requested `2-57/5 * * * *`. That cron expression was valid, but GitHub-hosted scheduled workflows are best-effort rather than an exact delivery timer. The five newest scheduled `Update profile stats` runs sampled during the 2026-09-05 audit arrived at approximately:

- 01:12 UTC
- 05:44 UTC
- 09:24 UTC
- 12:52 UTC
- 15:39 UTC

Those observed gaps were roughly **4h32m, 3h40m, 3h28m, and 2h47m**. A visible five-minute refresh claim therefore overstated what the hosted scheduler actually delivered.

The same sample also showed redundant work. On two consecutive stable-head scheduled runs, the pipeline still performed the full read-only generation/API collection path, then skipped predicate construction and attestation because the generated evidence was unchanged. Changed runs in the sample were associated with source revisions that already had a push-triggered refresh path.

The intermediate `profile-refresh-v1` contract requested two scheduled opportunities per hour at `17,47 * * * *`. The current v2 contract intentionally simplifies that fallback to one off-peak hourly opportunity. This is an operator policy choice, not a claim that GitHub historically delivered runs exactly once per hour.

## Current contract

The production schedule is:

```text
17 * * * *
```

This is a **best-effort hourly generation refresh**, not a one-hour delivery SLA. GitHub may delay scheduled workflows. Push-triggered and manual refreshes remain available independently of the schedule.

Final publishable Signal Field artifacts must encode all of the following:

- `data-generation-schedule="1-hour"`
- `data-generation-cadence-contract="profile-refresh-v2"`
- `data-current-day-highlight="phosphorescent-red-v1"`
- `data-contribution-headline-balance="responsive-v3"`
- contribution headline type at **37px wide / 31px compact**
- visible footer copy using `REFRESH · 1 HR`
- accessible copy stating `Generation refresh: every hour; execution and README cache propagation are best-effort.`
- one phosphorescent-red `#FF335F` outer ring marking the current/latest day while the tile fill remains the contribution-intensity color

`scripts/set-signal-field-refresh-cadence.py` owns this final refresh/current-day presentation contract. It is idempotent and must run after Signal Field evidence identity/presentation finalization and before `validate-generated-signal-field.py`.

## Boundary with evidence freshness

Generation refresh cadence and evidence freshness are different claims. The Portfolio Evidence Ledger keeps freshness as its own evidence dimension; an hourly scheduled fallback does not certify that every upstream GitHub observation is younger than one hour. Publication and attestation continue to enforce the existing live-evidence, subject-binding, digest, and semantic contracts.

## Change rule

Changing the cron, the push-trigger source boundary, the source-epoch compiler, the published refresh provenance, the current-day highlight contract, or the refresh-contract version is a governance change. My repository governance validator and Profile Quality integration must fail closed until the workflow, trigger validator, finalizer, validator, source epoch, cache identity, and this rationale agree.

## Independent Activity Metrics (proposed `independent-activity-v1`)

Activity Metrics and the strict-live portfolio-evidence set serve different freshness
purposes. The existing attested eleven-subject `generated` branch remains governed
by the hourly best-effort pipeline above: a missing exact-current-main CI/Security
execution must still block Ledger/Spotlight publication, and this historical
publication/receipt contract is not relaxed.

The new `activity-metrics.yml` workflow is **independent**: it gathers GitHub account
activity using the same pinned upstream generator and reviewed Signal Field pipeline,
validates its original four SVG subjects, and then projects exactly four cadence
presentation strings with a reversible equality proof. This changes the display
to `REFRESH · 5 MIN`, `data-generation-schedule="5-minutes"`, and
`data-generation-cadence-contract="independent-activity-v1"`. Measured evidence,
contributions, the latest-day ring, the desktop/mobile geometry, and Signal Field
Evidence IDs must not change. The separate source remains constrained to the four
responsive `profile-stats/profile/signal-field-*.svg` subjects.

`activity-metrics.yml` requests the shortest GitHub Actions cron interval,
`2/5 * * * *` (UTC; 02, 07, ..., 57 minutes). This is **not a freshness SLA**:
GitHub may delay or drop scheduled events, upstream profile APIs may cache values,
and raw.githubusercontent.com/README clients have their own caches. Only
successful, changed validated candidates advance the independent
`activity-metrics` branch; identical candidates are explicit no-ops.

The generator job has no repository write or OIDC permission. A separate signer
attests the four independently generated SVGs without content-write permission.
A terminal publisher can write the isolated `activity-metrics` branch only;
it cannot issue attestations. Its source-main freshness proof and Git
fast-forward semantics reject stale or conflicting publication. It never modifies
the legacy `generated` branch, its eleven-subject inventory, its Ledger, its
Spotlight visuals, or its immutable attestation/receipt history.
