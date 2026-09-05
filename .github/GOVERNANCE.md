# Repository governance contract

**Checkpoint:** 2026-09-05  
**Repository:** `portyu9/portyu9`

This repository treats the profile README, reviewed source assets, generated Signal Field, Engineering Spotlight, Portfolio Evidence Ledger, cache identities, and profile-evidence attestations as production artifacts. Version-controlled checks and GitHub repository settings must describe the same trust boundary.

## Main branch merge contract

`Protect Main` must require pull requests, block deletion and non-fast-forward updates, and require the branch to be current before merge. The exact merge-time status set is:

- `Profile quality / validate-contracts`
- `Profile quality / integration-pinned-upstream`
- `Dependency review / dependency-review`
- `CodeQL / analyze-python`
- `CodeQL / analyze-actions`

All five are required on the exact pull-request head. Repository ruleset settings are control-plane state rather than source files; version-controlled validators protect the executable half of the contract, while repository-setting audits verify the control-plane half.

## Dependency and external Action governance

`.github/dependabot.yml` is limited to reviewed GitHub Actions update discovery. Dependabot pull requests are not auto-merged and must pass the same five merge gates.

Every external `uses:` reference must execute an exact 40-character commit SHA. A same-line semantic release annotation is also required and is independently resolved by **Action release provenance** validation. The human release label and immutable executable SHA must identify the same upstream release before a merge can proceed.

`Dependency review / dependency-review` is the required pre-merge vulnerability gate. It runs read-only, uses no PR-comment or repository-write authority, and blocks reviewed severity/scope violations without becoming a hidden license-policy gate.

## Workflow authority firewall

The GitHub Actions surface is a **closed allowlist** of exactly four workflows:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`

The **Workflow authority firewall** locks workflow triggers, job inventory, workflow-level permissions, and job-level permissions. Read-only authority is the default. The only reviewed write-capable exceptions are:

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| CodeQL analysis | `security-events: write` | publish code-scanning results |
| Profile stats / `attest-validated-evidence` | `id-token: write`, `attestations: write` | mint and persist the profile evidence attestation |
| Profile stats / `publish-write-only` | `contents: write` | fast-forward validated artifacts to `generated` |

No job may combine repository-content write with OIDC/attestation authority. Privileged trigger families such as `pull_request_target`, `workflow_run`, `repository_dispatch`, or comment-driven execution remain unauthorized unless a deliberate governance change reviews the new trust boundary.

## Workflow shell safety

**Workflow shell safety** forbids `${{ ... }}` expression interpolation directly into `run:` **shell source**. Dynamic values must cross a non-shell field such as `env:`, `with:`, or `if:` and be treated as data by the resulting script. YAML forms that obscure the generated shell source are rejected.

This control limits command-source injection risk but does not replace normal quoting, input validation, path safety, or safe subprocess use in authored scripts.

## Profile Quality boundary

`Profile quality / validate-contracts` is read-only and runs the fail-closed repository contract suite, including Signal Field, Spotlight, Portfolio Ledger, attestation, dependency, Action provenance, authority, shell-safety, CodeQL, cache-identity, and repository governance checks.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed Signal Field generator, runs the full production transformation chain, performs the Signal Field artifact round trip with digest enforcement, then collects one live Portfolio Evidence Ledger snapshot and renders the Engineering Spotlight strictly from that validated snapshot. The read-only contract summary reports the resulting identities and authority map through `GITHUB_STEP_SUMMARY`.

## Single evidence snapshot contract

The **Portfolio Evidence Ledger** is the sole live GitHub evidence collection surface for the 13 reviewed QE systems during a profile evidence run.

The required data flow is:

`GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection`

The Spotlight renderer must not independently re-query GitHub for system evidence. Its three deterministic daily slots are selected from the nine rotating systems and must project the exact Ledger `subject_revision`, `evidence_contract`, and complete `signals` for each selected repository. The internal Spotlight manifest records the Ledger Evidence ID and full SHA-256 digest used for the projection.

This removes a temporal race in which two independently collected surfaces could describe different workflow state inside one run.

## Signal Field Evidence ID

The four Signal Field variants share one deterministic `signal-field-evidence-v1` identity when they encode the same measured evidence. The human handle is `SF1-` plus the first 64 bits of the canonical evidence SHA-256; the **full SHA-256** remains the verification identity carried in artifact provenance and the attestation predicate.

The short Signal Field Evidence ID is a correlation handle, not a substitute for full-digest verification.

## Generated asset cache contract

Mutable images served from the `generated` branch must carry an explicit cache identity in README URLs. All six Spotlight theme assets share one current Spotlight cache token and all four Signal Field assets share one current Signal Field cache token. `scripts/validate-profile-cache-contract.py` rejects missing, stale, or inconsistent family tokens.

Immutable source-revision URLs do not need query-based cache busting because the revision itself is the cache identity.

## Generation, attestation, and publication authority separation

`generate-read-only` receives `contents: read` only. Third-party generation code has neither repository-write nor attestation authority. It produces and validates three immutable evidence sets:

1. four Signal Field SVGs;
2. six Engineering Spotlight SVGs plus an internal validation manifest;
3. one Portfolio Evidence Ledger JSON document.

The public/attested subject set is exactly **11 subjects**: four Signal Field SVGs, six Spotlight SVGs, and one Portfolio Evidence Ledger JSON file. `spotlight-manifest.json` is internal validation metadata and must never be published or attested.

`attest-validated-evidence` runs on a fresh job boundary with `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It downloads the three immutable evidence sets, fails closed on artifact digest mismatch, revalidates Signal Field, Portfolio Ledger, and Ledger-backed Spotlight projection, builds the predicate, and only then invokes the pinned attestation Action.

`publish-write-only` depends on both generation and attestation. It receives `contents: write` but no OIDC or attestation authority. It downloads the same immutable evidence, revalidates it again, stages exactly the 11 public subjects, and pushes only to `generated`.

## Attestation schema versioning

Published predicate schema versions are immutable.

- `.github/attestation/profile-evidence-v1.schema.json` is a **frozen legacy verification contract** and must never change byte-for-byte.
- `.github/attestation/profile-evidence-v2.schema.json` is the current issuance contract.

New production attestations use v2. The predicate records a `predicateSchema` identity that binds the v2 schema URI and the exact SHA-256 digest of the schema bytes used by the builder. A semantic predicate change requires a new schema filename/version rather than mutation of an already published contract.

## Attestation claim boundary

The engineering attestation establishes provenance and repository-defined contract conformance for the exact 11 named subjects at the recorded source revision. It binds the Signal Field Evidence ID/digest, Portfolio Ledger ID/digest/system count, current predicate schema identity, validation inventories, and authority separation.

It does **not certify every software behavior** represented by the profile, replace underlying CI/security evidence, or expand the scope of any oracle.

Verification instructions and the current/legacy schema relationship are documented in `.github/ATTESTATION.md`.

## Generated branch

`generated` is an artifact branch, not a source branch. Its public root is expected to contain only:

- `profile-stats/profile/` with four Signal Field SVGs;
- `engineering-spotlight/` with six Spotlight SVGs;
- `portfolio-evidence/portfolio-evidence-ledger.json`.

The `Protect generated` ruleset should block branch **deletion** and **non-fast-forward** updates while permitting the reviewed GitHub Actions publisher to make normal fast-forward artifact commits. A pull-request requirement must not be added to this artifact branch unless the automation model is deliberately redesigned.

## Verification after material trust-boundary changes

Confirm all of the following before declaring a security/governance change complete:

1. the exact five required PR checks passed on the final head;
2. Action release provenance, Dependency Review, Workflow authority firewall, Workflow shell safety, and CodeQL contracts remain green;
3. the Signal Field artifact round trip fails closed on digest mismatch and revalidates downloaded bytes;
4. one Portfolio Ledger is collected and Spotlight is projected from that same validated Ledger;
5. generation remains read-only, attestation remains non-publishing, and publication remains non-signing;
6. the attestation subject set and generated public set are the same exact 11 subjects;
7. v1 schema bytes remain frozen and new predicates use v2 with `predicateSchema.digest`;
8. mutable generated README asset URLs pass the cache-identity contract;
9. for production-path changes, a real `Update profile stats` run succeeds through `generate-read-only → attest-validated-evidence → publish-write-only`;
10. repository rulesets are checked separately because settings-level controls cannot be guaranteed by repository files alone.

Any change that weakens these boundaries is a governance-contract change and must fail closed until deliberately reviewed.
