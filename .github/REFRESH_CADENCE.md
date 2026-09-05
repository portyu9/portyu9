# Profile evidence refresh cadence

**Checkpoint:** 2026-09-05  
**Contract:** `profile-refresh-v1`

The profile evidence pipeline has three refresh paths:

- **push-triggered:** immediate when reviewed production evidence code or workflow inputs change on `main`;
- **manual:** `workflow_dispatch` for an explicit operator refresh;
- **scheduled:** two best-effort opportunities per hour at minutes **17** and **47**.

The scheduled path is deliberately a fallback. It is not the primary response to source changes, because relevant merges already trigger the same production workflow immediately.

## Measurement that replaced the five-minute request

The prior workflow requested `2-57/5 * * * *`, but the five newest scheduled `Update profile stats` runs sampled during the 2026-09-05 audit arrived at approximately:

- 01:12 UTC
- 05:44 UTC
- 09:24 UTC
- 12:52 UTC
- 15:39 UTC

Those observed gaps were roughly **4h32m, 3h40m, 3h28m, and 2h47m**. A five-minute cron expression therefore overstated the freshness the hosted scheduler actually delivered.

The same sample also showed redundant work. On two consecutive stable-head scheduled runs, the pipeline still performed the full read-only generation/API collection path, then skipped predicate construction and attestation because the generated evidence was unchanged. Changed runs in the sample were associated with source revisions that already had a push-triggered refresh path.

## Current contract

The production schedule is:

```text
17,47 * * * *
```

This is a **best-effort 30-minute generation schedule**, not a 30-minute delivery SLA. GitHub may delay scheduled workflows. Push-triggered and manual refreshes remain available independently of the schedule.

Final publishable Signal Field artifacts must encode all of the following:

- `data-generation-schedule="30-minutes"`
- `data-generation-cadence-contract="profile-refresh-v1"`
- visible schedule copy using `30 MIN`
- accessible copy stating `Generation schedule: every 30 minutes; execution and README cache propagation are best-effort.`

`scripts/set-signal-field-refresh-cadence.py` owns this final schedule-only transformation. It is idempotent and must run after Signal Field evidence identity/presentation finalization and before `validate-generated-signal-field.py`.

## Boundary with evidence freshness

Generation cadence and evidence freshness are different claims. The Portfolio Evidence Ledger keeps freshness as its own evidence dimension; a 30-minute schedule does not certify that every upstream GitHub observation is younger than 30 minutes. Publication and attestation continue to enforce the existing live-evidence, subject-binding, digest, and semantic contracts.

## Change rule

Changing the cron, the published schedule provenance, or the cadence-contract version is a governance change. The repository governance validator and Profile Quality integration must fail closed until the workflow, finalizer, validator, and this rationale agree.