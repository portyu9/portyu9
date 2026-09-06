# Repository governance contract

**Checkpoint:** 2026-09-05  
**Repository:** `portyu9/portyu9`

I treat my profile README, reviewed source assets, generated Signal Field, Engineering Spotlight, Portfolio Evidence Ledger, cache identities, and profile-evidence attestations as production artifacts. Version-controlled checks and GitHub repository settings must describe the same trust boundary.

## Main branch merge contract

`Protect Main` must require pull requests, block deletion and non-fast-forward updates, and require the branch to be current before merge. The exact merge-time status set is:

- `Profile quality / validate-contracts`
- `Profile quality / integration-pinned-upstream`
- `Dependency review / dependency-review`
- `CodeQL / analyze-python`
- `CodeQL / analyze-actions`

All five are required on the exact pull-request head. Repository ruleset settings are control-plane state rather than source files, so `validate-contracts` executes `python3 scripts/validate-ruleset-contract.py --live` and compares every field exposed to the workflow's read-only identity with the checked-in desired state. A mismatch in that **live GitHub control-plane** surface is merge-blocking; the source contract does not claim a settings mutation occurred merely because desired state was edited.

GitHub does not expose `bypass_actors` to the short-lived read-only Actions token or unauthenticated public API. The live gate therefore never converts an omitted bypass field into an empty list. Zero bypass actors remain a source-locked and **admin-scope** audit invariant. The latest connected control-plane audit on 2026-09-05 observed no bypass actors on either ruleset.

The current `Protect Main` pull-request contract intentionally keeps zero required approving reviews for my solo-maintainer model while requiring review-thread resolution, allowing merge commits only, requiring the branch to be current, and enforcing the exact five status contexts above. The desired-state contract also requires no bypass actors.

## Dependency update automation

`.github/dependabot.yml` is the canonical GitHub Actions update-discovery policy. Dependabot proposes trust-boundary dependency changes but does not authorize them: Dependabot pull requests are **never auto-merged**, must pass the same five merge gates, and each dependency update remains a **separate pull request** so executable-identity changes stay attributable.

Every external `uses:` reference must execute an **exact commit SHA**. The reviewed trust boundary includes `actions/attest`, `actions/checkout`, artifact transport/setup actions, Dependency Review, CodeQL, and `shinpr/github-profile-stats`. Same-line semantic release annotations are independently resolved by Action release provenance validation; the release label and immutable executable SHA must identify the same upstream release.

Dependabot alerts and security-update settings are separate GitHub control-plane controls and should remain enabled where supported. GitHub does not provide the same vulnerability-alert semantics for every **SHA-pinned GitHub Actions** reference, so scheduled GitHub Actions update discovery remains an important independent signal rather than a replacement for exact pins or review.

## Action release provenance

`scripts/validate-action-release-provenance.py` binds each executable Action SHA to its **same-line** reviewed release annotation. Every external Action must therefore have both an immutable 40-character commit and an **exact semantic-version** label.

Release verification uses public `git ls-remote` and supports both lightweight and **annotated tags**; for an annotated tag the peeled commit is authoritative. The resolved release commit must equal the executable SHA. This live provenance check **does not replace** exact pinning, Dependency Review, Dependabot, least privilege, or source review.

## Dependency review gate

`.github/workflows/dependency-review.yml` provides the required `Dependency review / dependency-review` status on every pull request with **no path filters**. It runs with `contents: read`, blocks **moderate-or-higher** known vulnerabilities across **runtime, development, and unknown** scopes, and fails rather than silently warning.

The vulnerability gate intentionally does not become a hidden **license policy**. Dependabot updates remain **never auto-merged**; Dependency Review evaluates proposed dependency changes but does not authorize executable-identity changes by itself.

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
| Profile stats / `attest-validated-evidence` | `id-token: write`, `attestations: write` | mint and persist my profile evidence attestation |
| Profile stats / `publish-write-only` | `contents: write` | fast-forward validated artifacts to `generated` |

No job may combine repository-content write with OIDC/attestation authority. A **new workflow**, new job, trigger family, or token grant is a governance change. Privileged trigger families such as `pull_request_target`, `workflow_run`, `repository_dispatch`, or comment-driven execution remain unauthorized unless a deliberate governance change reviews the new trust boundary.

## Workflow shell safety

**Workflow shell safety** forbids `${{ ... }}` expression interpolation directly into `run:` **shell source**. Dynamic values must cross a non-shell field such as `env:`, `with:`, or `if:` and be treated as data by the resulting script. YAML forms that obscure the generated shell source are rejected.

This control limits command-source injection risk but does not replace normal quoting, input validation, path safety, or safe subprocess use in authored scripts.

## CodeQL security analysis

`.github/workflows/codeql.yml` runs isolated `analyze-python` and `analyze-actions` jobs for authored Python and **GitHub Actions workflows**. It has **no path filters**, runs on pull requests/main plus a **weekly** scan, and uses the `security-extended` query suite.

External CodeQL Actions execute at an **exact commit SHA**. Analysis receives only read authority plus `security-events: write` for SARIF publication. **CodeQL is not an attestation** and does not expand the meaning of generated evidence; it is an independent static-analysis control.

## Profile Quality boundary

`Profile quality / validate-contracts` is read-only and runs the fail-closed repository contract suite, including Signal Field, Spotlight, Portfolio Ledger, attestation, dependency, Action provenance, authority, shell-safety, CodeQL, cache-identity, repository governance, assurance-document, and ruleset checks. Its ruleset step validates the source-controlled target against every control-plane field visible to the read-only workflow identity; this is drift detection, not settings mutation authority. Admin-redacted bypass actors remain separately auditable rather than being guessed.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed Signal Field generator, runs the full production transformation chain, performs the Signal Field artifact round trip with digest enforcement, then collects one live Portfolio Evidence Ledger v2 snapshot and renders the Engineering Spotlight strictly from that validated snapshot. It also exercises the same canonical candidate validation boundary used by production before staging the exact publication subjects. The read-only contract summary reports the resulting identities, independent evidence dimensions, and authority map through `GITHUB_STEP_SUMMARY`.

## Canonical profile evidence validation boundary

`scripts/profile-evidence-validation-boundary-v1.json` is the versioned `profile-evidence-validation-boundary-v1` contract for downloaded candidate evidence. It owns the ordered validator scripts, their live-evidence flags, the validator identities recorded in the attestation predicate, and the `attest-validated-evidence` boundary name.

`scripts/validate-profile-evidence-boundary.py` is the only workflow entrypoint for full candidate revalidation after artifact transport. Both `attest-validated-evidence` and `publish-write-only` invoke it against their own downloaded copies. The predicate builder reads the same manifest through `profile_evidence_validation.py`, so the validator identities it records cannot drift independently from the commands production actually executes.

The immutable predicate v3 schema remains byte-for-byte frozen. `validate-profile-attestation-contract.py` requires its validator arrays and boundary constant to match this canonical manifest. A future semantic validator-set change that cannot satisfy the frozen schema therefore requires an explicit new predicate schema version rather than silent divergence.

This consolidation does not share artifacts across authority boundaries and does not move validation into a write-capable helper. The runner is read-only; attestation and publication still download separately, execute separately, and retain distinct permissions.

## Single evidence snapshot contract

The **Portfolio Evidence Ledger v2** is the sole live GitHub evidence collection surface for the 13 reviewed QE systems during my profile evidence run.

The required data flow is:

`GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection`

The Spotlight renderer must not independently re-query GitHub for system evidence. Its three deterministic daily slots are selected from the nine rotating systems and must project the exact Ledger `subject_revision`, `evidence_contract`, and complete evidence records for each selected repository. The internal Spotlight manifest records the Ledger Evidence ID and full SHA-256 digest used for the projection.

This removes a temporal race in which two independently collected surfaces could describe different workflow state inside one run.

## Orthogonal evidence semantics

Ledger v2 uses the immutable semantic identifier `execution-result-subject-binding-freshness-v1`. Every workflow observation keeps three independent dimensions:

- **execution result** records what the declared workflow/job/step scope concluded;
- **subject binding** records whether the observed run head equals the current `main` subject;
- **freshness** records timestamp availability and UTC whole-day age.

A run on a different revision must never have its observed execution result overwritten with a synthetic `STALE` result. `DIFFERENT_SUBJECT` is a binding fact, not a result. Likewise, `AGED` is a freshness fact, not a result or binding fact.

Separation does not weaken publication. `--require-live` still requires usable execution evidence, `CURRENT_SUBJECT` binding, usable freshness, and complete run provenance before Spotlight/Portfolio evidence can cross the attestation or publication boundary.

Ledger v2 uses a `PL2-` human correlation handle and full SHA-256 digest. Its `result_summary`, `binding_summary`, and `freshness_summary` remain separate; the v1 `signal_summary` conflation is forbidden in v2.

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

`attest-validated-evidence` runs on a fresh job boundary with `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It downloads the three immutable evidence sets, fails closed on artifact digest mismatch, executes the canonical candidate validation boundary, builds the predicate, and only then invokes the pinned attestation Action.

`publish-write-only` depends on both generation and attestation. It receives `contents: write` but no OIDC or attestation authority. It downloads the same immutable evidence, independently executes the same canonical candidate validation boundary, stages exactly the 11 public subjects, and pushes only to `generated`.

## Attestation schema versioning

Published predicate schema versions are immutable.

- `.github/attestation/profile-evidence-v1.schema.json` is a **frozen legacy verification contract**.
- `.github/attestation/profile-evidence-v2.schema.json` is also a **frozen historical verification contract** for the prior Ledger v1 / `PL1-` semantics.
- `.github/attestation/profile-evidence-v3.schema.json` is the current issuance contract.

New production attestations use v3. The predicate records a `predicateSchema` identity that binds the v3 schema URI and exact SHA-256 digest of the schema bytes used by the builder. Predicate v3 additionally binds `portfolioEvidenceLedger.version = portfolio-evidence-ledger-v2` and `portfolioEvidenceLedger.semantics = execution-result-subject-binding-freshness-v1`. A future semantic predicate change requires a new schema filename/version rather than mutation of any published contract.

## Attestation claim boundary

The engineering attestation establishes provenance and repository-defined contract conformance for the exact 11 named subjects at the recorded source revision. It binds the Signal Field Evidence ID/digest, Portfolio Ledger v2 ID/digest/system count/semantics, current predicate schema identity, validation inventories, and authority separation.

It does **not certify every software behavior** represented by my profile, replace underlying CI/security evidence, or expand the scope of any oracle.

Verification instructions and the current/historical schema relationship are documented in `.github/ATTESTATION.md`.

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
4. one Portfolio Ledger v2 is collected and Spotlight is projected from that same validated Ledger;
5. the canonical `profile-evidence-validation-boundary-v1` contract is exercised by Profile Quality integration, attestation, and publication and its predicate identities still match the frozen current schema;
6. execution result, subject binding, and freshness remain independent across Ledger, Spotlight, summary, and attestation semantics;
7. generation remains read-only, attestation remains non-publishing, and publication remains non-signing;
8. the attestation subject set and generated public set are the same exact 11 subjects;
9. v1 and v2 predicate schema bytes remain frozen and new predicates use v3 with `predicateSchema.digest`;
10. mutable generated README asset URLs pass the cache-identity contract;
11. for production-path changes, a real `Update profile stats` run succeeds through `generate-read-only → attest-validated-evidence → publish-write-only`;
12. `validate-ruleset-contract.py --live` passes inside the required Profile Quality gate for every observable ruleset field, while an administration-capable audit separately confirms the source-locked no-bypass invariant when GitHub redacts that field from the workflow identity.

Any change that weakens these boundaries is a governance-contract change and must fail closed until deliberately reviewed.