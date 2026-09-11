# Repository governance contract

**Checkpoint:** 2026-09-10  
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

GitHub does not expose `bypass_actors` to the short-lived read-only Actions token or unauthenticated public API. The live gate therefore never converts an omitted bypass field into an empty list. Zero bypass actors remain a source-locked and **admin-scope** audit invariant. The latest connected control-plane audit observed no bypass actors on either ruleset.

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

The GitHub Actions surface is a **closed allowlist** of exactly five workflows:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`
- `spotlight-link-sync.yml`

The **Workflow authority firewall** locks workflow triggers, job inventory, workflow-level permissions, and job-level permissions. Read-only authority is the default. Both autonomous transaction workflows mint a **short-lived mutation lease** before any write-capable job may act; the 30-minute lease binds the exact repository/workflow/run/source/candidate transaction and is independent of scheduling. The reviewed Spotlight control plane also includes explicit stale-state reconciliation plus read-only admission/quarantine boundaries before its constructive mutation jobs:

| Workflow / job | Effective job authority | Purpose |
| --- | --- | --- |
| CodeQL analysis | `security-events: write` | publish code-scanning results |
| Profile stats / `mint-mutation-lease-read-only` | `actions: read` | validate the exact current Actions run, re-prove the live generated base, and mint the hash-bound 30-minute transaction capability |
| Profile stats / `attest-write-only` | `id-token: write`, `attestations: write` | consume only digest-checked reviewed artifacts/predicate and mint my profile evidence attestation after exact lease/predicate proofs |
| Profile stats / `publish-write-only` | `contents: write` | verify one sealed publication candidate and fast-forward that exact commit to `generated` under the exact lease |
| Profile stats / `dispatch-spotlight-link-sync` | `actions: write only` | after successful publication, dispatch only the fixed Spotlight reconciliation workflow on `main` under the exact lease; no checkout/content/PR/signing authority |
| Spotlight link sync / `plan-direct-links-read-only` | `contents: read` | reconstruct the exact validated published projection and emit a hash-bound README plan without mutation |
| Spotlight link sync / `mint-mutation-lease-read-only` | `actions: read` | validate the exact current Actions run and mint the hash-bound 30-minute source/candidate transaction capability |
| Spotlight link sync / `reconcile-stale-candidates-write` | `contents: write`, `pull-requests: write` | monotonically remove only stale, fully revalidated automation PR/ref residue while preserving the current deterministic candidate and all young candidates, under the exact lease |
| Spotlight link sync / `mutation-budget-read-only` | `actions: read` | count immutable exact-source-epoch changed-plan attempt artifacts and fail closed on incomplete or ambiguous history |
| Spotlight link sync / `mutation-budget-quarantine-read-only` | `contents: read` | emit diagnostic-only quarantine output after a successful exhausted budget decision; no GitHub CLI/API mutation surface |
| Spotlight link sync / `propose-readme-only-write` | `contents: write`, `pull-requests: write` | create or reuse only the deterministic immutable README candidate and open its exact PR after positive admission and exact lease proof |
| Spotlight link sync / `approve-bot-pr-checks-only` | `contents: read`, `actions: write` | prove `main` is still the reviewed base and the exact head is one README-only commit over it, bind runs to canonical workflows, then approve only those exact workflow runs when required under the exact lease |
| Spotlight link sync / `merge-readme-only-terminal-write` | `contents: write`, `pull-requests: read`, `checks: read` | revalidate and merge only the exact one-file README PR after the five GitHub-Actions checks succeed, the planned generated snapshot is still current, and the exact lease remains valid |

`prepare-attestation-read-only` is deliberately outside the write-capable exceptions. It has `contents: read` only, downloads the three immutable evidence sets, executes the canonical validation boundary, computes the scheduled delta, builds the v3 predicate, and uploads exactly one short-lived predicate artifact. It has no OIDC/attestation-write authority.

`stage-publication-read-only` is also outside the write-capable exceptions. It has `contents: read` only, performs the independent publication revalidation/staging work, creates the local artifact commit without repository push authority, and seals that exact commit into a digest-transported **sealed Git bundle** for the terminal publisher.

The lease contract is owned by Automation Policy IR rather than shell convention. Each `mint-mutation-lease-read-only` job has `actions: read` only and seals repository name/id, workflow path/ref/SHA, run id/attempt, base SHA, deterministic candidate ID, issuance, and expiry into one SHA-256 capability identity. Every write-capable job is in the policy's complete `boundJobs` set and independently reconstructs that identity before side effects. Its policy-owned **minimum remaining lifetime** must be at least that job's literal hard timeout, so a job cannot enter with a capability that is allowed to expire during its maximum execution window. The lease supplements, rather than replaces, freshness checks, item-7 non-cancellable terminal serialization, Spotlight mutation-budget admission, immutable-candidate topology, and exact check/run provenance.

No job may combine repository-content write with OIDC/attestation authority. `attest-write-only` has no checkout, setup-Python, repository-authored Python, Git, `gh`, or token-bearing alternate mutation client. Its only authored shell is exactly two reviewed read-only proofs: the short-lived mutation lease identity/lifetime proof and the downloaded predicate SHA-256 proof; it otherwise contains four digest-checked artifact downloads plus one pinned `actions/attest`. The Spotlight synchronization jobs split read-only planning, lease minting, **stale-only monotone reconciliation**, **source-epoch mutation budget** admission, **diagnostic-only quarantine**, content/PR mutation, Actions approval, and check-gated merge authority so no single bot step receives all capabilities. The post-publication dispatcher is separate again: it has `actions: write only`, depends on successful publication and the exact lease, checks out no repository content, and cannot itself mutate a branch or PR. A **new workflow**, new job, trigger family, or token grant is a governance change. Privileged trigger families such as `pull_request_target`, `workflow_run`, `repository_dispatch`, or comment-driven execution remain unauthorized unless a deliberate governance change reviews the new trust boundary.

## Spotlight direct-link synchronization

The three Evidence Spotlight subjects rotate deterministically, while `README.md` is protected source and `Protect Main` has no bypass actors. My profile therefore does **not** weaken `main`, route clicks through an issue, or let a scheduled job push directly to the protected branch.

Each published Spotlight snapshot uses flagship-style interaction: the whole card links directly to the selected repository, and the external CI / SECURITY Shields link directly to that repository's named `ci.yml` / `security.yml` workflow. All six light/dark card image URLs in the guarded block are pinned to one immutable `generated` commit SHA. The image bytes and their three repository/six workflow hrefs therefore change atomically when one reviewed README commit lands; a mutable card can never rotate ahead of a static link.

`plan-direct-links-read-only` checks out trusted `main` and `generated` without persisted credentials, revalidates the published Portfolio Evidence Ledger, deterministically reconstructs the Spotlight projection from that Ledger, and byte-compares all six regenerated cards with the published snapshot. Only then does `scripts/spotlight_profile_links.py` render a complete proposed README and a hash-bound plan. The planning job has `contents: read` only. A changed plan is uploaded under an immutable one-day artifact name content-addressed by the exact `(main SHA, generated SHA)` source epoch.

`mint-mutation-lease-read-only` follows planning in the serialized terminal phase. With only `actions: read`, it binds the current run/attempt, exact workflow identity, planned `main` base, and deterministic `(main SHA, generated SHA, proposed README digest)` candidate to a 30-minute lease. Reconciliation, proposal, approval, and merge must all prove that exact capability and retain enough minimum remaining lifetime to cover their complete job timeout before mutation authority is usable.

`reconcile-stale-candidates-write` is transaction-adjacent maintenance rather than a constructive transaction phase. After the read-only plan seals the current source/generated/README identity and the lease is minted, the reconciler derives the one current deterministic candidate branch, lists only the `automation/spotlight-links/<64-hex>` namespace, and fails closed if that namespace exceeds the reviewed bound or contains malformed refs. The current deterministic candidate is always preserved. A different candidate is mutation-eligible only after a 30-minute stale floor and after re-proving the bot author/committer identity, one parent, one README-only commit topology, and—when an open PR exists—the exact GitHub Actions bot/title/body/base/head/repository/non-maintainer-mutable PR identity. Its only mutations are closing that exact stale PR and deleting that exact stale ref, followed by a zero-ref proof. It cannot create or move refs, create PRs, approve workflow runs, or merge, so cleanup remains monotone-reductive even when constructive mutation is quarantined.

`mutation-budget-read-only` executes before any **constructive** branch, pull-request, approval, or merge mutation. With `actions: read` only, it queries the exact epoch artifact history, proves the response is complete within the reviewed single page, rejects mismatched repository/head provenance, and requires exactly one attempt token for the current workflow run. The initial changed-plan attempt plus one retry are admitted in the artifact window. A third attempt yields `allowed=false` rather than constructive mutation authority. `mutation-budget-quarantine-read-only` then emits a read-only diagnostic summary and fails visibly; it has no explicit GitHub CLI token/API mutation surface. Incomplete or ambiguous history fails in the budget job before proposal and does not route through quarantine as an authorization substitute. Stale-only reconciliation remains independent so quarantine cannot preserve abandoned authority indefinitely.

`propose-readme-only-write` downloads only the exact source-epoch digest-verified plan, requires the recorded base SHA to still be the exact `main` tip, verifies the before/after README hashes, derives `automation/spotlight-links/<sha256(main SHA, generated SHA, proposed README digest)>`, and either reuses that exact immutable ref or constructs and validates the one-parent README-only commit before creating the ref once. The candidate ref is never force-reset or moved. The job then opens or reuses the exact non-maintainer-mutable PR for that immutable head. It never writes directly to `main`, and its job predicate additionally requires the exact short-lived mutation lease, positive mutation-budget admission, and successful stale-state reconciliation.

GitHub may place workflow runs created by an automation-authored pull request into an approval-required state. Approval is itself execution authority, so `approve-bot-pr-checks-only` receives `contents: read` plus `actions: write` and fails closed before using the latter. It first proves the exact short-lived mutation lease and requires `main` itself to remain the recorded base SHA. It then compares the exact proposed head against that recorded base and requires one README-only commit, zero behind commits, the exact merge base, and one modified file named `README.md`. It also requires the planned **generated evidence head** to remain current. Finally, it resolves `codeql.yml`, `dependency-review.yml`, and `profile-quality.yml` from the repository's **canonical default-branch workflow** paths and requires the observed run `workflow_id` values to match those identities before any `/approve` call. Within one reconciliation, it records workflow-run IDs after an approval request and will not POST approval twice for the same run while status converges.

`merge-readme-only-terminal-write` starts only after the exact short-lived mutation lease, positive mutation-budget admission, stale-state reconciliation, proposal success, and the Actions-only approval/wait job succeeds. It receives `contents: write`, `pull-requests: read`, and `checks: read`; it does not receive PR-write or Actions authority. It revalidates the exact PR head, current `main` base, current `generated` evidence SHA, one-file `README.md` closure, and the exact successful five-check snapshot bound to the sealed workflow-run/check-suite identities. Immediately before the expected-head merge request it rechecks both mutable roots. After a successful merge it re-fetches the merged PR, binds the returned merge SHA to `main`, then uses matching-ref cardinality to prove the exact consumed candidate is absent or still points to the reviewed head; if present it deletes only that exact immutable ref and proves zero exact refs remain. The normal `Protect Main` ruleset remains the final server-side arbiter; the synchronization workflow has no bypass actor and uses merge-commit semantics.

The `Update profile stats` workflow no longer relies on cron ordering to make Spotlight links converge after publication. After `publish-write-only` succeeds, a dedicated **post-publication** `dispatch-spotlight-link-sync` job with `actions: write only` dispatches the fixed `spotlight-link-sync.yml` workflow on `main`. The synchronizer's hourly schedule remains an eventual-consistency recovery path for transient dispatch/scheduler failures, not an ordering guarantee. The dispatcher proves the same Profile Stats short-lived mutation lease, has no checkout, content-write, pull-request, OIDC, attestation, check-read, or security-event authority.

The synchronization workflow is presentation/navigation automation only. It does not change Spotlight selection, Portfolio Ledger evidence, generated evidence bytes, the eleven-subject attestation set, attestation authority, or publication authority.

## Workflow shell safety

**Workflow shell safety** forbids `${{ ... }}` expression interpolation directly into `run:` **shell source**. Dynamic values must cross a non-shell field such as `env:`, `with:`, or `if:` and be treated as data by the resulting script. YAML forms that obscure the generated shell source are rejected. Token-authorized shell jobs also reject command-name aliases, indirect execution wrappers, alternate runner-resident interpreters/network clients, and unauthorized Git execution.

This control limits command-source injection risk but does not replace normal quoting, input validation, path safety, or safe subprocess use in authored scripts.

## CodeQL security analysis

`.github/workflows/codeql.yml` runs isolated `analyze-python` and `analyze-actions` jobs for authored Python and **GitHub Actions workflows**. It has **no path filters**, runs on pull requests/main plus a **weekly** scan, and uses the `security-extended` query suite.

External CodeQL Actions execute at an **exact commit SHA**. Analysis receives only read authority plus `security-events: write` for SARIF publication. **CodeQL is not an attestation** and does not expand the meaning of generated evidence; it is an independent static-analysis control.

## Profile Quality boundary

`Profile quality / validate-contracts` is read-only and runs the fail-closed repository contract suite, including Signal Field, Spotlight, Portfolio Ledger, attestation, dependency, Action provenance, authority, shell-safety, CodeQL, cache-identity, repository governance, assurance-document, and ruleset checks. Its ruleset step validates the source-controlled target against every control-plane field visible to the read-only workflow identity; this is drift detection, not settings mutation authority. Admin-redacted bypass actors remain separately auditable rather than being guessed.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed Signal Field generator, runs the full production transformation chain, performs the Signal Field artifact round trip with digest enforcement, then collects one live Portfolio Evidence Ledger v2 snapshot and renders the Engineering Spotlight strictly from that validated snapshot. It also exercises the same canonical candidate validation boundary used by production before staging the exact publication subjects. The read-only contract summary reports the resulting identities, independent evidence dimensions, and authority map through `GITHUB_STEP_SUMMARY`.

## Canonical profile evidence validation boundary

`scripts/profile-evidence-validation-boundary-v1.json` is the versioned `profile-evidence-validation-boundary-v1` contract for downloaded candidate evidence. It owns the ordered validator scripts, their live-evidence flags, the validator identities recorded in the attestation predicate, and the frozen semantic `attest-validated-evidence` boundary name.

`scripts/validate-profile-evidence-boundary.py` is the only workflow entrypoint for full candidate revalidation after artifact transport. Both `prepare-attestation-read-only` and `stage-publication-read-only` invoke it against independently downloaded copies. The predicate builder reads the same manifest through `profile_evidence_validation.py`, so the validator identities it records cannot drift independently from the commands production actually executes. `attest-write-only` executes no authored validator; `publish-write-only` executes no authored Python. The immutable predicate v3 schema remains byte-for-byte frozen, so the semantic `attest-validated-evidence` name remains stable even though signing authority is now a distinct terminal job.

This consolidation does not share mutable working directories across authority boundaries. Attestation preparation and publication staging download the generated evidence independently and execute the candidate validation boundary separately; terminal attestation receives only digest-checked evidence plus the reviewed predicate, and the write-capable publisher receives only the digest-checked sealed Git bundle produced after read-only staging.

## Single evidence snapshot contract

The **Portfolio Evidence Ledger v2** is the sole live GitHub evidence collection surface for the 13 reviewed QE systems during my profile evidence run.

The required data flow is:

`GitHub evidence → Portfolio Evidence Ledger → validated Engineering Spotlight projection`

The Spotlight renderer must not independently re-query GitHub for system evidence. Its three deterministic daily slots are selected from the nine rotating systems and must project the exact Ledger `subject_revision`, `evidence_contract`, and complete evidence records for each selected repository. The internal Spotlight manifest records the Ledger Evidence ID and full SHA-256 digest used for the projection.

This removes a temporal race in which two independently collected surfaces could describe different workflow state inside one run.

## Orthogonal evidence semantics

Ledger v2 uses the immutable semantic identifier `execution-result-subject-binding-freshness-v1`. Every workflow observation keeps three independent dimensions: **execution result**, **subject binding**, and **freshness**. A run on a different revision must never have its observed execution result overwritten with a synthetic `STALE` result. `DIFFERENT_SUBJECT` is a binding fact, not a result. `AGED` is a freshness fact, not a result or binding fact.

Separation does not weaken publication. `--require-live` still requires usable execution evidence, `CURRENT_SUBJECT` binding, usable freshness, and complete run provenance before Spotlight/Portfolio evidence can cross the attestation or publication boundary. Ledger v2 uses a `PL2-` human correlation handle and full SHA-256 digest. Its `result_summary`, `binding_summary`, and `freshness_summary` remain separate.

## Signal Field Evidence ID

The four Signal Field variants share one deterministic `signal-field-evidence-v1` identity when they encode the same measured evidence. The human handle is `SF1-` plus the first 64 bits of the canonical evidence SHA-256; the **full SHA-256** remains the verification identity carried in artifact provenance and the attestation predicate.

## Generated asset cache contract

Mutable images served from the `generated` branch must carry an explicit cache identity in README URLs. The four Signal Field assets share one current Signal Field cache token. Evidence Spotlight uses a stronger atomic presentation contract: all six theme assets in my profile README are pinned to one immutable generated commit SHA. `scripts/validate-profile-cache-contract.py` rejects mixed Spotlight SHAs, mutable Spotlight URLs, and stale or inconsistent Signal Field tokens.

## Generation, attestation, and publication authority separation

`generate-read-only` receives `contents: read` only. Third-party generation code has neither repository-write nor attestation authority. It produces and validates three immutable evidence sets: four Signal Field SVGs; six Engineering Spotlight SVGs plus internal validation metadata; and one Portfolio Evidence Ledger JSON document. The public/attested subject set is exactly **11 subjects**. `spotlight-manifest.json` is internal validation metadata and must never be published or attested.

`prepare-attestation-read-only` runs on a fresh read-only job boundary. It downloads the three immutable evidence sets, fails closed on artifact digest mismatch, executes the canonical candidate validation boundary, computes scheduled delta state, builds the predicate, and uploads exactly one `profile-evidence-attestation-predicate` artifact. It has no `id-token: write` or `attestations: write` authority.

`mint-mutation-lease-read-only` then receives `actions: read` only. It validates the exact current Profile Stats Actions run and re-proves the live `generated` ref before minting a 30-minute SHA-256 capability over repository/workflow/run identity, the exact `main` base, the generated base, reviewed predicate digest, issuance, and expiry. All three Profile Stats writers independently verify this short-lived mutation lease and their policy-owned minimum remaining lifetime before side effects.

`attest-write-only` receives `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It contains exactly four digest-checked artifact downloads (three evidence sets plus the reviewed predicate), exactly two reviewed read-only shell proofs (mutation lease identity/lifetime and predicate SHA-256), and one pinned `actions/attest` step. It has no checkout, no setup-python, no repository-authored Python, and no Git/`gh`/alternate network mutation client.

`stage-publication-read-only` depends on generation, attestation preparation, the lease mint, and terminal attestation but receives `contents: read` only. It independently downloads the same three immutable evidence sets with digest enforcement, executes the canonical candidate validation boundary, checks out `generated` without persisted credentials, requires that checked-out generated base to equal the leased generated SHA, stages exactly the 11 public subjects, runs the staged-publication validators, creates the local bot commit, verifies its one-parent relationship to the observed generated head, and seals that exact candidate into a verified Git bundle. It has no repository push authority.

`publish-write-only` depends on successful publication staging plus the exact lease and receives `contents: write` but no OIDC or attestation authority. It has no checkout step, no Python setup, and no authored Python. If staging reports no change it succeeds without mutation. Otherwise it independently verifies the short-lived mutation lease, downloads only the digest-checked sealed Git bundle, reconstructs the local candidate from that bundle, verifies the expected candidate/base SHAs, one-parent ancestry, exact 11-file `100644` tree, bot commit identity, clean worktree, credential-free local Git configuration, and fixed repository origin, then exposes the job token only to the final exact `HEAD:generated` push. If `generated` moved after staging, normal Git fast-forward semantics plus the `Protect generated` non-fast-forward rule reject the stale candidate rather than overwrite newer evidence.

The post-publication `dispatch-spotlight-link-sync` job depends on `publish-write-only` plus the exact Profile Stats lease and receives `actions: write only`. It independently verifies the lease, performs no checkout, and executes no authored Python. Its sole mutation is an Actions API dispatch of `.github/workflows/spotlight-link-sync.yml` with `ref=main`, so publication authority and README-reconciliation authority remain separate.

## Attestation schema versioning

Published predicate schema versions are immutable. `.github/attestation/profile-evidence-v1.schema.json` is a **frozen legacy verification contract**. `.github/attestation/profile-evidence-v2.schema.json` is a **frozen historical verification contract** for prior Ledger v1 / `PL1-` semantics. `.github/attestation/profile-evidence-v3.schema.json` is the current issuance contract. New production attestations use v3 and record `predicateSchema.digest`; a future semantic predicate change requires a new schema filename/version rather than mutation of any published contract.

## Attestation claim boundary

The engineering attestation establishes provenance and repository-defined contract conformance for the exact 11 named subjects at the recorded source revision. It binds the Signal Field Evidence ID/digest, Portfolio Ledger v2 ID/digest/system count/semantics, current predicate schema identity, validation inventories, and authority separation. It does **not certify every software behavior** represented by my profile, replace underlying CI/security evidence, or expand the scope of any oracle.

Verification instructions and the current/historical schema relationship are documented in `.github/ATTESTATION.md`.

## Generated branch

`generated` is an artifact branch, not a source branch. Its public root is expected to contain only `profile-stats/profile/` with four Signal Field SVGs, `engineering-spotlight/` with six Spotlight SVGs, and `portfolio-evidence/portfolio-evidence-ledger.json`. The `Protect generated` ruleset should block branch **deletion** and **non-fast-forward** updates while permitting the reviewed GitHub Actions publisher to make normal fast-forward artifact commits.

## Verification after material trust-boundary changes

Confirm all of the following before declaring a security/governance change complete:

1. the exact five required PR checks passed on the final head;
2. Action release provenance, Dependency Review, Workflow authority firewall, Workflow shell safety, and CodeQL contracts remain green;
3. the Signal Field artifact round trip fails closed on digest mismatch and revalidates downloaded bytes;
4. one Portfolio Ledger v2 is collected and Spotlight is projected from that same validated Ledger;
5. the canonical `profile-evidence-validation-boundary-v1` contract is exercised by Profile Quality integration, `prepare-attestation-read-only`, and `stage-publication-read-only`, while its frozen `attest-validated-evidence` predicate identity still matches v3;
6. execution result, subject binding, and freshness remain independent across Ledger, Spotlight, summary, and attestation semantics;
7. each autonomous workflow mints a 30-minute `mint-mutation-lease-read-only` capability with `actions: read` only, every write-capable job is lease-bound, and each policy-owned minimum remaining lifetime covers that job's hard timeout;
8. generation and attestation preparation remain read-only, `attest-write-only` contains exactly two reviewed read-only proof shells plus four digest-checked downloads and pinned `actions/attest`, publication staging remains read-only/non-signing, terminal publication contains no checkout/Python/authored validation, and the post-publication dispatcher remains `actions: write only` with no checkout/content/PR/signing authority;
9. the attestation subject set and generated public set are the same exact 11 subjects;
10. v1 and v2 predicate schema bytes remain frozen and new predicates use v3 with `predicateSchema.digest`;
11. mutable Signal Field README URLs pass the cache-identity contract and all six Spotlight README URLs bind one immutable generated snapshot SHA;
12. the Spotlight reconciler may only close/delete stale fully revalidated automation residue while preserving the current deterministic candidate; reconciler/proposal/approval/merge must prove the exact short-lived mutation lease; constructive proposal must separately pass the exact source-epoch mutation budget, exhausted successful decisions route only to diagnostic-only quarantine, proposal remains one immutable README-only commit, approval-required runs bind to canonical default-branch workflow identities, and approval/merge reject movement of either `main` or the planned generated evidence head;
13. for production-path changes, a real `Update profile stats` run succeeds through `generate-read-only → prepare-attestation-read-only → mint-mutation-lease-read-only → attest-write-only → stage-publication-read-only → publish-write-only → dispatch-spotlight-link-sync`, and the dispatched reconciliation either deterministically no-ops or produces a single guarded README-only PR;
14. `validate-ruleset-contract.py --live` passes inside the required Profile Quality gate for every observable ruleset field, while an administration-capable audit separately confirms the source-locked no-bypass invariant when GitHub redacts that field from the workflow identity.

Any change that weakens these boundaries is a governance-contract change and must fail closed until deliberately reviewed.