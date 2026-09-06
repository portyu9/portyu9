# Profile evidence refresh cadence

**Checkpoint:** 2026-09-05  
**Contract:** `profile-refresh-v2`

The profile evidence pipeline has three refresh paths:

- **push-triggered:** immediate when reviewed production evidence code or workflow inputs change on `main`;
- **manual:** `workflow_dispatch` for an explicit operator refresh;
- **scheduled:** one best-effort opportunity per hour at minute **17**.

The scheduled path is deliberately a fallback. It is not the primary response to source changes, because relevant merges already trigger the same production workflow immediately.

## Push-trigger source closure

The production push trigger covers the complete trusted `scripts/**` tree rather than maintaining a per-script allowlist. This is intentionally broader than the runtime import graph: validator-only changes may cause an extra refresh, but new generators, renderers, registries, helpers, transformers, or validators cannot be introduced under `scripts/` without entering the immediate production refresh path on `main`.

Seven files are also named explicitly beneath the umbrella as review sentinels: three historical pipeline/refresh contract files and four profile-evidence subject-contract files. They are redundant with `scripts/**`; they do not carry source-coverage responsibility. The umbrella trigger is the fail-safe that ensures new production source modules cannot silently fall outside the immediate push-triggered refresh path.

Workflow, attestation documentation, and predicate-schema changes remain explicit non-script triggers because they live outside the trusted scripts tree. `scripts/validate-profile-stats-trigger-contract.py` locks this trigger shape in Profile Quality.

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
- visible footer copy using `REFRESH · 1 HR`
- accessible copy stating `Generation refresh: every hour; execution and README cache propagation are best-effort.`
- one phosphorescent-red `#FF335F` outer ring marking the current/latest day while the tile fill remains the contribution-intensity color

`scripts/set-signal-field-refresh-cadence.py` owns this final refresh/current-day presentation contract. It is idempotent and must run after Signal Field evidence identity/presentation finalization and before `validate-generated-signal-field.py`.

## Boundary with evidence freshness

Generation refresh cadence and evidence freshness are different claims. The Portfolio Evidence Ledger keeps freshness as its own evidence dimension; an hourly scheduled fallback does not certify that every upstream GitHub observation is younger than one hour. Publication and attestation continue to enforce the existing live-evidence, subject-binding, digest, and semantic contracts.

## Change rule

Changing the cron, the push-trigger source boundary, the published refresh provenance, the current-day highlight contract, or the refresh-contract version is a governance change. The repository governance validator and Profile Quality integration must fail closed until the workflow, trigger validator, finalizer, validator, cache identity, and this rationale agree.
