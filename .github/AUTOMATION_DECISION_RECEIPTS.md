# Automation Decision Receipt assurance supplement

**Checkpoint:** 2026-09-14  
**Repository:** `portyu9/portyu9`

This supplement documents the item-11 Automation Decision Receipt (ADR) trust boundary without redefining the frozen evidence-attestation, generated-publication receipt, or Spotlight Merge Authorization Certificate contracts.

## Contract and classification

The generic predicate contract is `.github/attestation/automation-decision-receipt-v1.schema.json`. A generic ADR is append-only evidence for a concrete semantic effect, not merely evidence that a workflow completed. Its transaction identity binds the exact repository, workflow/run ID and attempt, source epoch, short-lived lease/candidate identity, target identity, observed result, outcome, and timestamp required by the reviewed contract.

Receipt classification is explicit. Effects that issue an attestation about their own issuance are **self-attested** rather than generic ADRs. The existing `generated-publication-receipt-v1.schema.json` remains the specialized receipt for the actual generated publication and is not relabeled as a generic ADR.

For Profile Stats, profile-evidence attestation issuance is self-attested; generated publication remains covered by the specialized generated-publication receipt; generated-publication receipt issuance is self-attested; the accepted Spotlight workflow dispatch is the generic ADR semantic effect; and generic ADR attestation issuance is self-attested.

For Spotlight, actual stale cleanup is a generic ADR effect only when reconciliation produced a real reduction; candidate publication is generic and records `created` or exact `reused` outcome; only actual approval POST effects are generic; Merge Authorization Certificate issuance is self-attested; successful merge and candidate cleanup are generic semantic effects; and generic ADR attestation issuance is self-attested.

## Authority graph supplement

These rows extend the existing governance and threat-model authority tables. Permissions are compiled from `.github/automation-policy-v1.json`.

| Workflow / job | Effective job authority | Purpose |
| --- | --- | --- |
| Profile stats / `prepare-automation-decision-receipt-read-only` | `contents: read`, `actions: read` | independently re-prove the accepted fixed Spotlight workflow dispatch and build the generic ADR subject/predicate without mutation or signing authority |
| Profile stats / `attest-automation-decision-receipt-write-only` | `contents: read`, `id-token: write`, `attestations: write` | under the exact lease, digest-check and attest only the prepared generic ADR with no checkout, authored Python, Git, `gh`, content-write, or Actions-write surface |
| Spotlight link sync / `prepare-automation-decision-receipt-read-only` | `contents: read`, `pull-requests: read`, `actions: read` | on success or the reviewed always() recovery path, independently re-prove the durable subset of stale cleanup, candidate publication/reuse, actual approval POST, and merge/cleanup effects and build one ordered generic ADR journal |
| Spotlight link sync / `attest-automation-decision-receipt-write-only` | `contents: read`, `id-token: write`, `attestations: write` | under the exact lease, digest-check and attest only the prepared generic ADR; no repository mutation, Actions mutation, checkout, authored Python, Git, or `gh` execution is available |

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| Spotlight / `prepare-automation-decision-receipt-read-only` | `contents: read`, `pull-requests: read`, `actions: read` | independently re-prove durable semantic effects for the generic ADR, including the reviewed recovery path after a later transaction failure |
| Spotlight / `attest-automation-decision-receipt-write-only` | `contents: read`, `id-token: write`, `attestations: write` | sign only the prepared generic ADR after exact lease and digest proofs; it cannot perform or repair the receipted external effect |

## Recovery and completion semantics

Receipt preparation is independent read-only state reconstruction. Spotlight may enter it through an `always()` recovery path when a durable semantic effect already occurred but a later phase failed. The journal may therefore contain a valid ordered subset: stale cleanup only, candidate publication/reuse, publication plus actual approval POST effects, or the complete merge transaction. Missing effects are never invented to make a failed run appear complete.

A successful externally visible transaction is not fully successful until its required receipt provenance is emitted and attested. **Failed receipt signing** therefore leaves the transaction failed rather than silently converting an unreceipted side effect into success. When failure occurs after an external effect, the run remains failed; a recovery receipt may describe the independently re-proved durable effect where the reviewed recovery path is safe.

The ADR signer is deliberately tiny: `contents: read`, `id-token: write`, and `attestations: write` only. Repository-authored validation and state preparation execute in the separate read-only preparer. This separation keeps semantic observation, mutation authority, and OIDC signing authority independently auditable.
