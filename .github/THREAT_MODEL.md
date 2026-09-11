# Security threat model and control inventory

**Checkpoint:** 2026-09-10  
**Repository:** `portyu9/portyu9`

This document records the current trust graph, enforced repository controls, accepted residual risk, and verification points for my profile evidence system. It is an assurance checkpoint, not a runtime permission grant.

## Security objective

Protect the integrity, attribution, and bounded meaning of my public profile and generated evidence while keeping data collection, authored validation, workflow mutation, signing, and publication authority separated.

The architecture is intended to ensure that:

1. unreviewed source changes cannot reach `main` without the exact required merge gates;
2. third-party generation code cannot write repository content or mint attestations;
3. **one Portfolio Evidence Ledger snapshot** is the live system-evidence source for each run;
4. the **Ledger-backed Spotlight projection** cannot silently describe evidence collected at a different moment;
5. **execution result**, **subject binding**, and **freshness** remain independent evidence dimensions;
6. generated evidence is validated before transport, after transport, before attestation preparation, and before publication;
7. repository-authored validation/predicate code cannot execute with OIDC/attestation-write authority;
8. the signer cannot publish repository content and the publisher cannot mint the attestation on which publication depends;
9. public generated subjects exactly equal attested subjects;
10. published predicate schemas cannot be retroactively redefined;
11. mutable generated profile image URLs carry explicit reviewed cache identities;
12. every ruleset field observable to the read-only workflow identity must match source-controlled intent before the required Profile Quality gate passes, while admin-redacted bypass actors remain separately audited;
13. new workflows, local Actions, trigger families, jobs, and write-capable token grants fail closed unless they enter the reviewed authority model first;
14. a pathological Spotlight reconciliation cannot constructively mutate indefinitely for one exact source epoch: a read-only source-epoch mutation budget precedes candidate/PR creation, workflow approval, and merge while exhausted epochs enter diagnostic-only quarantine;
15. interrupted Spotlight transactions converge toward a clean fixed point through a separately modeled reductive reconciliation capability that may only close a stale validated bot PR and delete its exact stale immutable candidate ref after a **30-minute stale floor**.

## Protected assets

| Asset | Security property |
| --- | --- |
| `main` source and README | protected, attributable change history through exact merge gates |
| Workflow definitions | closed workflow/job/trigger/permission inventory |
| External Actions | exact immutable commit identities with reviewed semantic release provenance |
| Local Actions | forbidden until a dedicated reviewed local-action contract exists |
| Four Signal Field SVGs | validated evidence semantics and one deterministic Evidence ID/digest |
| Portfolio Evidence Ledger v2 | one 13-system evidence snapshot with independent result, binding, freshness, and run provenance |
| Six Engineering Spotlight SVGs | deterministic Ledger-backed projection of the same validated snapshot |
| Signal Field Evidence ID / digest | stable correlation plus full-digest verification identity |
| Portfolio Ledger `PL2-` ID / digest | stable snapshot correlation plus full-digest verification identity |
| Profile evidence attestation | provenance and repository-defined contract-conformance statement |
| v1/v2 predicate schemas | frozen historical verification contract surfaces |
| v3 predicate schema | current issuance semantics with `predicateSchema.digest` and Ledger v2 binding |
| `generated` branch | exact artifact-only public evidence history |
| README generated-asset cache identities | presentation identity aligned with current generated evidence |
| Repository ruleset control plane | observable live enforcement must match reviewed desired state |
| GitHub Actions token capabilities | separated read, Actions-read admission, reductive cleanup, Actions-mutation, PR/content mutation, signing, and publication authority |
| Spotlight mutation-attempt artifacts | one-day immutable exact `(main SHA, generated SHA)` attempt tokens used only for fail-closed constructive mutation admission |
| Spotlight candidate refs/PRs | immutable content-addressed transaction state; stale residue may be reduced only after exact topology/identity and age proofs |

## Trust boundaries

### 1. Pull request boundary

Source changes reach `main` through five exact required status contexts: `validate-contracts`, `integration-pinned-upstream`, `dependency-review`, `analyze-actions`, and `analyze-python`.

`Protect Main` blocks deletion and non-fast-forward updates, requires pull requests, allows merge commits only, requires review-thread resolution, and requires the branch to be current. `validate-contracts` executes `python3 scripts/validate-ruleset-contract.py --live`, comparing source intent with the **live GitHub control-plane**.

The short-lived read-only Actions identity can encounter GitHub API views that **redact** `bypass_actors`. The validator never converts omission into an empty list. No bypass actors therefore remains a source-locked **admin-scope** invariant and an administration-capable connected audit requirement when required CI cannot observe it.

### 2. Read-only Profile Quality boundary

`Profile quality / validate-contracts` and `Profile quality / integration-pinned-upstream` receive `contents: read` only. The first executes fail-closed source/live governance contracts; the second exercises the pinned upstream generator, authored evidence-generation pipeline, artifact transport, live Ledger collection, Ledger-backed Spotlight rendering, publication subject staging, and read-only assurance summary.

### 3. Dependency and Action boundary

Every external `uses:` reference executes at a reviewed 40-character commit SHA. Same-line semantic release annotations are independently resolved against the public upstream repository and must identify the same executable commit.

**Local/composite `uses: ./...` execution is currently forbidden** by the Action provenance contract because local Actions would otherwise create an execution surface outside the canonical external identity lock. Introducing one requires a deliberate governance change and a separately reviewed local-action contract.

Dependency Review is a required pull-request vulnerability gate. Dependabot discovers GitHub Actions updates but does not authorize them.

### 4. Workflow authority boundary

The GitHub Actions surface is a closed allowlist of **exactly five workflows**:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`
- `spotlight-link-sync.yml`

Read-only is the default. Spotlight planning, reductive reconciliation, source-epoch admission, quarantine, proposal, approval, and terminal merge are explicit separate jobs so the authority graph itself is inspectable:

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| CodeQL / `analyze` | `security-events: write` | publish code-scanning results |
| Profile stats / `attest-write-only` | `id-token: write`, `attestations: write` | consume digest-checked reviewed evidence/predicate and mint the attestation |
| Profile stats / `publish-write-only` | `contents: write` | push only the already sealed generated publication commit |
| Profile stats / `dispatch-spotlight-link-sync` | `actions: write` | dispatch only the fixed Spotlight reconciliation workflow after publication |
| Spotlight / `plan-direct-links-read-only` | `contents: read` | reconstruct and validate the exact published projection before any mutation |
| Spotlight / `reconcile-stale-candidates-write` | `contents: write`, `pull-requests: write` | close/delete only stale fully revalidated immutable bot candidates; never create/update candidates, approve runs, or merge |
| Spotlight / `mutation-budget-read-only` | `actions: read` | prove the complete exact-source-epoch changed-plan artifact history and decide whether constructive mutation remains admissible |
| Spotlight / `mutation-budget-quarantine-read-only` | `contents: read` | emit diagnostic-only quarantine output for an exhausted successful budget decision without GitHub mutation/API authority |
| Spotlight / `propose-readme-only-write` | `contents: write`, `pull-requests: write` | create or exact-reuse one content-addressed immutable README-only candidate and its PR after reconciliation plus positive budget admission |
| Spotlight / `approve-bot-pr-checks-only` | `contents: read`, `actions: write` | approve only exact canonical required workflow runs after fail-closed source/head/file checks and de-duplicate approval requests |
| Spotlight / `merge-readme-only-terminal-write` | `contents: write`, `pull-requests: read`, `checks: read` | revalidate and merge only the exact README-only head after the five required checks succeed and mutable roots remain bound |

`prepare-attestation-read-only` and `stage-publication-read-only` deliberately remain read-only. No job combines repository-content write with OIDC/attestation authority. More importantly, `attest-write-only` contains no checkout, no setup-python, no `run:` step, and no repository-authored shell/Python at all.

The Spotlight graph similarly prevents authority collapse. `reconcile-stale-candidates-write` has no checkout/Python, no Actions/check authority, and a closed monotone-reductive API surface: after exact namespace, bot identity, one-parent/one-README topology, PR identity, and stale-age proofs it may close one stale bot PR and delete its exact stale ref. `mutation-budget-read-only` can observe only Actions history; it cannot mutate repository content, PRs, or workflow runs. `mutation-budget-quarantine-read-only` can only report and fail. The terminal merger can write repository contents through the expected-head merge endpoint but can only read PR/check metadata and has no Actions authority.

### 5. Shell/data boundary

GitHub expressions are forbidden inside `run:` shell source. Dynamic values must cross reviewed non-shell fields such as `env:`, `with:`, or `if:`. Token-authorized shell jobs—including the reconciler—additionally reject command-name aliases, indirect execution wrappers, alternate runner-resident interpreters/network clients, and unauthorized Git execution.

### 6. Generation boundary

`generate-read-only` executes with `contents: read` only and has neither repository-write nor attestation authority. It generates/transforms/validates the four Signal Field variants, collects one 13-system Portfolio Evidence Ledger v2, projects three rotating systems into six Spotlight SVGs, and uploads three immutable transport sets. The production Spotlight renderer performs no second system-evidence query.

### 7. Orthogonal evidence boundary

Portfolio Evidence Ledger v2 uses `execution-result-subject-binding-freshness-v1` semantics. Each evidence record independently carries **execution result**, **subject binding**, and **freshness**.

A successful run on another revision remains `PASSING` in execution result while becoming `DIFFERENT_SUBJECT` in binding. `AGED` is a freshness fact, not a result. Live publication remains stricter: `--require-live` requires usable execution evidence, `CURRENT_SUBJECT` binding, available freshness, and complete run provenance before evidence crosses the attestation/publication boundary.

### 8. Artifact transport boundary

Reviewed SHA-pinned upload/download Actions move immutable evidence between authority-isolated jobs. `digest-mismatch: error` fails closed where configured. Transport success is not authorization; read-only downstream preparation/staging jobs independently revalidate what they consume.

Spotlight changed-plan artifacts have a separate authority purpose: their immutable one-day names contain the exact source `main` and `generated` SHAs. `mutation-budget-read-only` treats them as attempt tokens, not as authorization by themselves. It accepts the history only when `total_count` equals the returned page length, the set fits the reviewed one-page bound, every artifact belongs to the exact repository/source epoch, and exactly one artifact belongs to the current run. Ambiguous or incomplete history fails before any constructive mutation-capable job can start.

### 9. Attestation boundary

`prepare-attestation-read-only` receives `contents: read` only. It independently downloads the three evidence sets, enforces transport digests, runs the canonical `profile-evidence-validation-boundary-v1`, computes scheduled-delta state, builds the v3 predicate, and uploads one reviewed `profile-evidence-attestation-predicate` artifact. It cannot request an OIDC identity or write an attestation.

`attest-write-only` receives `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It contains **exactly four digest-checked downloads**—three evidence sets plus the reviewed predicate—and one pinned `actions/attest`. It executes no repository-authored shell/Python and has no Git/gh/curl/wget mutation path.

The public/attested subject set is **exactly 11 files**: four Signal Field SVGs, six Spotlight SVGs, and one Portfolio Evidence Ledger JSON document. `spotlight-manifest.json` is internal validation metadata and is neither published nor attested.

The canonical validation manifest retains the frozen semantic boundary identity `attest-validated-evidence`; that string is predicate semantics, not the terminal job name.

### 10. Predicate-schema boundary

`.github/attestation/profile-evidence-v1.schema.json` and `.github/attestation/profile-evidence-v2.schema.json` are each a **frozen historical verification contract**. New production attestations use `profile-evidence-v3.schema.json`, whose predicate carries `predicateSchema.digest`, the Ledger `PL2-` identity, and `execution-result-subject-binding-freshness-v1` semantics. Future semantic predicate changes require a new schema filename/version rather than mutation of a published schema.

### 11. Publication boundary

`stage-publication-read-only` depends on validated generation, read-only attestation preparation, and successful terminal attestation. It downloads independent candidate copies, runs the canonical validation boundary again, stages the exact 11 public subjects, excludes internal metadata, creates the local generated commit, and seals that commit in a digest-transported Git bundle.

`publish-write-only` receives `contents: write` but no OIDC/attestation authority and does not execute authored Python or a source checkout. It verifies the sealed candidate's Git identity, ancestry, exact tree paths, fixed origin, and expected base/head identities, then performs the one terminal fast-forward push to `generated`.

### 12. Spotlight reconciliation boundary

`dispatch-spotlight-link-sync` has only `actions: write` and dispatches the fixed reconciliation workflow after successful publication. The synchronizer's planning job is read-only and uploads a changed plan under an exact source-epoch artifact name.

`reconcile-stale-candidates-write` runs after a successful plan as a transaction-adjacent maintenance capability, not as one of the current transaction's `propose → approve → mutate → verify → terminalize` phases. It first re-proves the planned `main` and `generated` roots, derives the exact current content-addressed candidate when a change is planned, and preserves that candidate for immutable retry reuse. It bounds the candidate namespace, rejects malformed refs, and applies a **30-minute stale floor** before examining any other candidate for cleanup. Every stale cleanup candidate must re-prove one parent, exact GitHub Actions bot author/committer/message identity, exactly one commit over its parent, and exactly one modified `README.md`. If an open PR exists it must additionally be the exact automation-authored, non-maintainer-mutable PR for that branch/head. Only then may the job close that stale PR and delete that exact stale ref. It has no POST/PUT candidate-creation, Actions approval, or merge authority; unknown or malformed residue fails closed rather than being deleted.

Independently, `mutation-budget-read-only` uses `actions: read` to enforce the **source-epoch mutation budget** before constructive candidate/PR creation, workflow approval, or merge. For one exact `(main SHA, generated SHA)` epoch, the first changed-plan attempt and at most one retry are admitted while the one-day attempt artifacts remain live. A third changed-plan attempt yields `allowed=false`; `mutation-budget-quarantine-read-only` enters **diagnostic-only quarantine**, writes a job summary, and fails without a GitHub API mutation token surface. Quarantine does not re-enable constructive mutation, but reductive reconciliation remains available so stale authority can still converge away. If history is incomplete or malformed, the budget job itself fails closed and no constructive mutation job is authorized.

After successful reconciliation and positive admission, `propose-readme-only-write` may create or reuse only the exact content-addressed immutable candidate branch and its README-only PR. `approve-bot-pr-checks-only` revalidates both source roots and the one-commit README-only topology, binds the three canonical default-branch workflow identities, and locally de-duplicates each `/approve` mutation while waiting for success. `merge-readme-only-terminal-write` receives `contents: write`, `pull-requests: read`, and `checks: read` only. It revalidates the exact PR head, `main` base, `generated` snapshot, one-file README diff, and five required checks immediately before the expected-head merge. After a successful merge it uses matching-ref cardinality to accept zero or one exact consumed candidate ref, verifies any remaining exact ref still targets the reviewed head, deletes it, and proves absence. Candidate refs are never moved.

### 13. Generated branch boundary

`generated` is an artifact branch, not a second source branch. Its public tree is restricted to four Signal Field SVGs under `profile-stats/profile/`, six Spotlight SVGs under `engineering-spotlight/`, and `portfolio-evidence/portfolio-evidence-ledger.json`. `Protect generated` blocks deletion and non-fast-forward updates while allowing the reviewed publisher's normal fast-forward commit.

### 14. Profile image cache boundary

The **Profile image cache boundary** is presentation/version hygiene, not evidence provenance. Signal Field mutable generated URLs use an explicit reviewed family cache token. Spotlight image URLs are stronger: all six light/dark URLs are pinned to one immutable generated commit SHA so visual identity and README navigation move atomically.

### 15. Ruleset drift boundary

`.github/rulesets/repository-rulesets-v1.json` is the reviewed desired state for `Protect Main` and `Protect generated`. `validate-ruleset-contract.py --live` fails when observable live ruleset inventory, targets, enforcement, pull-request parameters, required-status bindings, or generated-branch protections differ from source-controlled intent. If GitHub redacts `bypass_actors`, omission is never inferred to mean empty.

## Detection and prevention matrix

| Threat / failure mode | Primary control | Secondary control | Residual |
| --- | --- | --- | --- |
| Unvalidated source merged to `main` | five exact required checks + `Protect Main` | no source-side bypass path | validator/control-plane defects remain possible |
| Observable ruleset drift | required live ruleset comparison | source desired-state contract | admin-redacted fields require privileged audit |
| Known vulnerable dependency introduced | Dependency Review | Dependabot discovery | unknown/novel vulnerabilities remain possible |
| Floating/mislabeled external Action | exact SHA pin | release-label → SHA provenance | reviewed upstream may itself be flawed |
| Unreviewed local Action executes | local `uses: ./...` prohibition | workflow source review + CodeQL Actions | future local-action model needs its own closure |
| New workflow receives authority | exact five-workflow allowlist | governed workflow byte identity | validator defects remain possible |
| Event data becomes shell source | shell-safety firewall | CodeQL Actions analysis | authored scripts still require safe data handling |
| Third-party generator writes/signs | generation read-only/non-signing | terminal authority isolation | platform compromise out of scope |
| Authored predicate code abuses OIDC | predicate/validation runs only in `prepare-attestation-read-only` | `attest-write-only` has no `run:`/checkout/Python | malicious pinned platform Action remains in TCB |
| Artifact corrupted in transport | digest mismatch fails closed | downstream semantic validation | GitHub artifact service remains in TCB |
| Public files differ from attested files | exact 11-subject closure | staged tree checks | authored path-contract defects remain possible |
| Historical predicate semantics change | frozen schema bytes + v3 | `predicateSchema.digest` | verifier must select intended schema version |
| Signer publishes arbitrary content | signer lacks `contents: write` | separate sealed publisher | platform compromise out of scope |
| Publisher forges attestation | publisher lacks OIDC/attestation authority | publication waits for signer | platform credential compromise out of scope |
| Repeated Spotlight constructive reconciliation loops mutate one source epoch | two-attempt exact-epoch mutation budget | read-only diagnostic quarantine + approval de-duplication | artifact-history availability can conservatively block mutation |
| Interrupted Spotlight candidate/PR residue persists | stale-only reductive reconciliation after exact topology/identity proof | 30-minute stale floor + current-candidate preservation | malformed residue intentionally blocks cleanup for manual investigation |
| Force-push/delete generated history | `Protect generated` | artifact-only exact tree | authorized fast-forward publisher remains powerful |
| Evidence claim overstates assurance | bounded predicate claim | governance/threat-model documentation | human interpretation risk remains |

## Trusted computing base

The design trusts the GitHub platform and hosted runners, reviewed immutable Action commits, repository validators/generators, GitHub evidence semantics returned by the API, GitHub Actions artifact-history semantics used by the mutation budget, GitHub ref/PR metadata used by stale reconciliation, and repository rulesets/token behavior.

## Accepted residual risks

- A zero-day or malicious behavior in a reviewed pinned dependency may evade Dependency Review and CodeQL.
- An upstream release tag move/deletion can cause fail-closed CI availability loss.
- A compromised GitHub-hosted runner or GitHub control plane is outside repository-level mitigation.
- `attest-write-only` intentionally holds OIDC/attestation authority; safety depends on exact Action identity, digest-checked input transport, zero authored shell/code, and GitHub's attestation implementation.
- `publish-write-only` intentionally holds `contents: write`; safety depends on source protection, authority isolation, sealed-candidate verification, and exact terminal push closure.
- Spotlight reconciliation/proposal/approval/merge jobs intentionally hold narrow mutation capabilities; safety depends on the reconciler's reductive stale-only closure, positive source-epoch budget admission for constructive mutation, exact branch/file/head/workflow/check predicates, and the server-side no-bypass Main ruleset.
- Spotlight stale reconciliation intentionally refuses to delete malformed/ambiguous candidates and preserves the current deterministic candidate plus candidates younger than 30 minutes; this can cause conservative availability/cleanup delay rather than destructive guessing.
- Spotlight mutation admission intentionally depends on GitHub artifact-history availability and completeness. Ambiguous, incomplete, malformed, or unavailable history causes fail-closed availability loss rather than permitting additional mutations.
- Attestation proves provenance and repository-defined contract conformance, not universal behavioral correctness.
- Public GitHub API/network outages can block live evidence refresh or live ruleset verification; integrity is preferred over availability.
- Settings can drift between Profile Quality executions, and admin-redacted bypass actors require periodic administration-capable audit rather than silent inference.

## Verification checklist

After a material workflow, evidence, or governance change:

1. confirm the exact five required PR checks succeeded on the final head;
2. confirm workflow authority contains exactly five reviewed workflows and no unreviewed local Action surface;
3. confirm Action provenance, Dependency Review, authority, shell-safety, cache, CodeQL, assurance-doc, and ruleset validators pass;
4. confirm `validate-ruleset-contract.py --live` matched every observable ruleset field and did not interpret redacted bypass actors as empty;
5. confirm one Portfolio Ledger v2 is collected before Spotlight and Spotlight validates against that exact Ledger;
6. confirm result, binding, and freshness stay independent and live publication requires `CURRENT_SUBJECT`;
7. confirm the public and attested subject sets remain the same exact 11 files;
8. confirm historical schema bytes remain frozen and current issuance uses v3 with `predicateSchema.digest`;
9. confirm generation has no write/signing authority and `prepare-attestation-read-only` has no OIDC/attestation authority;
10. confirm `attest-write-only` contains exactly four digest-checked downloads plus one pinned `actions/attest`, with no checkout/setup-python/`run:`/authored Python;
11. confirm `stage-publication-read-only` remains read-only, publication has no signing authority, and the exact seven-job Spotlight graph keeps planning → reductive reconciliation plus source-epoch mutation budget → diagnostic-only quarantine/proposal → approval → terminal merge authority separated;
12. confirm the reconciler preserves the current deterministic candidate, applies the 30-minute stale floor, and can only close/delete stale fully revalidated immutable candidates while constructive mutations remain budget-gated;
13. confirm a real production `Update profile stats` run succeeds after production-path changes;
14. confirm `generated` contains only the four Signal Field SVGs, six Spotlight SVGs, and Portfolio Ledger JSON;
15. confirm generated README images pass the cache-identity contract.

## Change policy

Update this threat model whenever the **trust graph, evidence graph, publication set, signing semantics, workflow authority, or control-plane assumptions** change. Routine copy or visual changes do not require a threat-model revision unless they alter one of those boundaries.
