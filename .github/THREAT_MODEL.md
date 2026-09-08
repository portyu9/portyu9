# Security threat model and control inventory

**Checkpoint:** 2026-09-08  
**Repository:** `portyu9/portyu9`

This document records the current trust graph, enforced repository controls, accepted residual risk, and verification points for my profile evidence system. It is an assurance checkpoint, not a runtime permission grant.

## Security objective

Protect the integrity, attribution, and bounded meaning of my public profile and generated evidence while keeping data collection, workflow mutation, signing, and publication authority separated.

The architecture is intended to ensure that:

1. unreviewed source changes cannot reach `main` without the exact required merge gates;
2. third-party generation code cannot write repository content or mint attestations;
3. **one Portfolio Evidence Ledger snapshot** is the live system-evidence source for each run;
4. the Ledger-backed Spotlight projection cannot silently describe evidence collected at a different moment;
5. execution result, subject binding, and freshness remain independent evidence dimensions;
6. generated evidence is validated before transport, after transport, before attestation, and before publication;
7. the signer cannot publish repository content and the publisher cannot mint the attestation on which publication depends;
8. public generated subjects exactly equal attested subjects;
9. published predicate schemas cannot be retroactively redefined;
10. mutable generated profile image URLs carry explicit reviewed cache identities;
11. every ruleset field observable to the read-only workflow identity must match source-controlled intent before the required Profile Quality gate passes, while admin-redacted bypass actors remain a separately audited invariant;
12. new workflows, local Actions, trigger families, jobs, and write-capable token grants fail closed unless they enter the reviewed authority model first.

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
| GitHub Actions token capabilities | separated read, Actions-mutation, PR/content mutation, signing, and publication authority |

## Trust boundaries

### 1. Pull request boundary

Source changes reach `main` through pull requests gated by five exact status contexts:

- `validate-contracts`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

`Protect Main` blocks deletion and non-fast-forward updates, requires pull requests, allows merge commits only, requires review-thread resolution, and requires the branch to be current. `validate-contracts` executes `python3 scripts/validate-ruleset-contract.py --live`, comparing the source contract with the **live GitHub control-plane**.

The short-lived read-only Actions identity can encounter GitHub API views that redact `bypass_actors`. The validator never converts omission into an empty list. No bypass actors therefore remains a source-locked **admin-scope** invariant and an administration-capable connected audit requirement when the required CI identity cannot observe it.

### 2. Read-only Profile Quality boundary

`Profile quality / validate-contracts` and `Profile quality / integration-pinned-upstream` receive `contents: read` only. The first executes fail-closed source and live governance contracts; the second exercises the actual pinned upstream generator, the authored evidence-generation pipeline, artifact transport, live Ledger collection, Ledger-backed Spotlight rendering, publication subject staging, and read-only assurance summary.

The integration job is evidence that the reviewed production logic runs under the same read-only trust boundary before a source change can merge. It receives no repository-content, PR, Actions-mutation, OIDC, attestation, or security-event write permission.

### 3. Dependency and Action boundary

Every external `uses:` reference executes at a reviewed 40-character commit SHA. Same-line semantic release annotations are independently resolved against the public upstream repository and must identify the same executable commit.

Local/composite `uses: ./...` execution is currently forbidden by the Action provenance contract because local Actions would otherwise create an execution surface outside the canonical external identity lock. Introducing one requires a deliberate governance change and a separately reviewed local-action contract.

Dependency Review is a required pull-request vulnerability gate. Dependabot discovers GitHub Actions updates but does not authorize them. Executable trust changes remain explicit source changes and must pass all five required checks.

### 4. Workflow authority boundary

The GitHub Actions surface is a closed allowlist of **exactly five workflows**:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`
- `spotlight-link-sync.yml`

The canonical workflow-authority validator locks each workflow's trigger set, job inventory, workflow-level permissions, and job-level permissions. Read-only is the default. Reviewed write-capable exceptions are split by terminal purpose:

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| CodeQL / `analyze` | `security-events: write` | publish code-scanning results |
| Profile stats / `attest-validated-evidence` | `id-token: write`, `attestations: write` | mint the profile evidence attestation without repository write |
| Profile stats / `publish-write-only` | `contents: write` | push only the already sealed generated publication commit |
| Profile stats / `dispatch-spotlight-link-sync` | `actions: write` | dispatch only the fixed Spotlight reconciliation workflow after publication |
| Spotlight link sync / `propose-readme-only-write` | `contents: write`, `pull-requests: write` | update the fixed automation branch and create/update its README-only PR |
| Spotlight link sync / `approve-bot-pr-checks-only` | `contents: read`, `actions: write` | approve only exact canonical required workflow runs after fail-closed head/base/file checks |
| Spotlight link sync / `merge-readme-only-after-required-checks` | `contents: write`, `pull-requests: write`, `checks: read` | merge only the exact README-only head after the five required GitHub Actions checks succeed and mutable roots remain bound |

`stage-publication-read-only` deliberately remains read-only. It performs semantic revalidation and seals the exact generated Git commit into the publication bundle before any job receives repository write permission.

No job combines repository-content write with OIDC/attestation authority. No Spotlight bot job combines content/PR mutation, Actions approval, and merge-check inspection in one authority scope. New workflows, jobs, trigger families, and write grants are governance changes rather than implicitly trusted extensions.

### 5. Shell/data boundary

GitHub expressions are forbidden inside `run:` shell source. Dynamic values must cross reviewed non-shell fields such as `env:`, `with:`, or `if:`. This prevents direct expression-to-shell-source injection but does not replace quoting, input validation, URL/path validation, or safe subprocess behavior inside authored scripts.

### 6. Generation boundary

`generate-read-only` executes with `contents: read` only and has neither repository-write nor attestation authority. Its evidence flow is:

1. generate, transform, and validate four Signal Field variants;
2. collect and validate one 13-system Portfolio Evidence Ledger v2;
3. deterministically select three rotating systems for the Ledger UTC date;
4. project exact Ledger subject revisions, evidence contracts, execution results, subject bindings, freshness, and run provenance into six light/dark Spotlight SVGs;
5. upload three immutable transport sets.

The production Spotlight renderer performs no second system-evidence query.

### 7. Orthogonal evidence boundary

Portfolio Evidence Ledger v2 uses `execution-result-subject-binding-freshness-v1` semantics. Each evidence record carries three independent dimensions:

- **execution result** — what the declared workflow/job/step scope concluded;
- **subject binding** — whether the observed run head equals the current `main` subject;
- **freshness** — timestamp availability and UTC whole-day age.

A successful run on another revision remains `PASSING` in execution result while becoming `DIFFERENT_SUBJECT` in binding; the result must not be rewritten to a synthetic stale state. `AGED` is a freshness fact, not an execution result or binding.

The live publication contract remains stricter than descriptive semantics: `--require-live` is intended to require a usable execution result, `CURRENT_SUBJECT` binding, available freshness, and complete run provenance before evidence is allowed across the attestation/publication boundary.

### 8. Artifact transport boundary

Reviewed SHA-pinned upload/download Actions move immutable evidence between authority-isolated jobs. Digest mismatch fails closed where configured. Transport success is not authorization: downstream jobs independently revalidate the content they consume.

### 9. Attestation boundary

`attest-validated-evidence` receives `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It independently downloads the evidence sets, enforces transport digests, runs the canonical validation boundary, builds the predicate, and only then invokes the pinned attestation Action.

The public/attested subject set is **exactly 11 files**: four Signal Field SVGs, six Spotlight SVGs, and one Portfolio Evidence Ledger JSON document. `spotlight-manifest.json` is internal validation metadata and is neither published nor attested.

### 10. Predicate-schema boundary

`.github/attestation/profile-evidence-v1.schema.json` and `.github/attestation/profile-evidence-v2.schema.json` are each a **frozen historical verification contract**. New production attestations use `profile-evidence-v3.schema.json`, whose predicate carries `predicateSchema.digest` for the exact schema bytes plus the Ledger `PL2-` identity and `execution-result-subject-binding-freshness-v1` semantics.

Future predicate semantic changes require a new schema filename/version rather than mutation of a published schema.

### 11. Publication boundary

`stage-publication-read-only` depends on validated generation and attestation, downloads independent candidate copies, runs the canonical validation boundary again, stages the exact 11 public subjects, excludes internal metadata, creates the local generated commit, and seals that commit in a digest-transported Git bundle.

`publish-write-only` receives `contents: write` but no OIDC/attestation authority and does not execute authored Python or a source checkout. It verifies the sealed candidate's Git identity, ancestry, exact tree paths, fixed origin, and expected base/head identities, then performs the one terminal fast-forward push to `generated`.

### 12. Spotlight reconciliation boundary

`dispatch-spotlight-link-sync` has only `actions: write` and dispatches the fixed reconciliation workflow after successful publication. The synchronizer's planning job is read-only. PR proposal, Actions approval, and final merge authority are deliberately separated into different jobs.

Scheduled and post-publication bot dispatches may plan, propose, and approve exact workflow runs, but they cannot reach the final UI merge authority. `merge-readme-only-after-required-checks` is additionally gated by explicit manual `workflow_dispatch` authorization and revalidates the exact PR head, `main` base, `generated` snapshot, one-file README diff, and five required checks immediately before merge.

### 13. Generated branch boundary

`generated` is an artifact branch, not a second source branch. Its public tree is restricted to four Signal Field SVGs under `profile-stats/profile/`, six Spotlight SVGs under `engineering-spotlight/`, and `portfolio-evidence/portfolio-evidence-ledger.json`.

`Protect generated` blocks deletion and non-fast-forward updates while allowing the reviewed publisher's normal fast-forward commit.

### 14. Profile image cache boundary

The **Profile image cache boundary** is presentation/version hygiene, not evidence provenance. Signal Field mutable generated URLs use an explicit reviewed family cache token. Spotlight image URLs are stronger: all six light/dark URLs are pinned to one immutable generated commit SHA so visual identity and README navigation move atomically when a reviewed link change merges.

### 15. Ruleset drift boundary

`.github/rulesets/repository-rulesets-v1.json` is the reviewed desired state for `Protect Main` and `Protect generated`. `validate-ruleset-contract.py --live` fails when observable live ruleset inventory, targets, enforcement, pull-request parameters, required-status bindings, or generated-branch protections differ from source-controlled intent.

If GitHub redacts `bypass_actors`, the validator emits an explicit notice and never infers that a missing value is empty. That blind spot remains an admin-scope audit invariant.

## Detection and prevention matrix

| Threat / failure mode | Primary control | Secondary control | Residual |
| --- | --- | --- | --- |
| Unvalidated source merged to `main` | five exact required status checks + `Protect Main` | no source-side bypass path | validator/control-plane defects remain possible |
| Observable ruleset drift | required live ruleset comparison | source-controlled desired-state contract | admin-redacted fields require privileged audit; drift may occur between executions |
| Known vulnerable dependency introduced | Dependency Review | Dependabot discovery | unknown/novel vulnerabilities remain possible |
| Floating or mislabeled external Action | exact SHA pin | live release-label → SHA provenance | reviewed pinned upstream code may itself be flawed |
| Unreviewed local Action executes | local `uses: ./...` prohibition | workflow source review + CodeQL Actions | a future deliberate local-action model must add its own closure |
| New workflow receives unreviewed authority | exact five-workflow authority allowlist | CodeQL Actions analysis | validator defects remain possible |
| Event data becomes shell source | shell-safety firewall | CodeQL Actions analysis | authored scripts still require safe data handling |
| Third-party generator writes or signs | generation is read-only/non-signing | isolated signer/publisher | platform/validator correctness remains trusted |
| Ledger and Spotlight describe different live moments | one live Portfolio Ledger collection | exact projection equality validation | GitHub API semantics are trusted input |
| Execution result overwritten by revision mismatch | orthogonal result/binding fields | validators forbid legacy conflated `signal` in Ledger v2 | authored semantic bugs remain possible |
| Selected Spotlight data diverges from Ledger | full record equality + current-subject live gate | repeated attestation/publication validation | renderer/validator defects remain possible |
| Artifact corrupted in transport | digest mismatch fails closed | downstream semantic validation | GitHub artifact service remains in the TCB |
| Public files differ from attested files | exact 11-subject staging/attestation closure | internal-manifest exclusion and tree checks | authored path-contract defects remain possible |
| Historical predicate semantics change | frozen schema bytes + versioned v3 | `predicateSchema.digest` | verifier must select intended schema version |
| Signer publishes arbitrary content | signer lacks `contents: write` | separate sealed publisher | platform compromise is out of scope |
| Publisher forges attestation | publisher lacks OIDC/attestation authority | publication depends on signer | platform credential compromise is out of scope |
| Bot broadens UI merge authority | explicit manual opt-in + exact-head five-check proof | authority-separated proposal/approval/merge jobs | GitHub platform compromise remains out of scope |
| Force-push/delete generated history | `Protect generated` | artifact-only exact tree | authorized fast-forward publisher remains powerful |
| Stale profile imagery | explicit cache/SHA identity | cache-contract validator | external intermediary refresh timing is not fully controllable |
| Evidence claim overstates assurance | bounded predicate claim | governance/threat-model documentation | human interpretation risk remains |

## Trusted computing base

The design trusts the GitHub platform and hosted runners, reviewed immutable Action commits, repository validators/generators, GitHub evidence semantics returned by the API, and the repository control-plane settings that enforce rulesets and workflow token behavior.

## Accepted residual risks

- A zero-day or malicious behavior in a reviewed pinned dependency may evade Dependency Review and CodeQL.
- An upstream release tag move/deletion can cause fail-closed CI availability loss.
- A compromised GitHub-hosted runner or GitHub control plane is outside repository-level mitigation.
- `publish-write-only` intentionally holds `contents: write`; safety depends on source protection, authority isolation, sealed-candidate verification, and exact terminal push closure.
- Spotlight proposal/approval/merge jobs intentionally hold narrow mutation capabilities; safety depends on their exact branch/file/head/workflow/check predicates and the server-side no-bypass Main ruleset.
- Attestation proves provenance and repository-defined contract conformance, not universal behavioral correctness.
- Public GitHub API/network outages can block live evidence refresh or live ruleset verification; integrity is preferred over availability.
- Mutable-image caches cannot be forced to refresh every intermediary immediately; the repository controls cache identity, not third-party cache timing.
- Settings can drift between Profile Quality executions, and admin-redacted bypass actors require periodic administration-capable control-plane audit rather than silent inference.

## Verification checklist

After a material workflow, evidence, or governance change:

1. confirm the exact five required PR checks succeeded on the final head;
2. confirm the workflow authority inventory contains exactly the five reviewed workflows and no unreviewed local Action surface;
3. confirm Action provenance, Dependency Review, authority, shell-safety, cache, CodeQL, assurance-doc, and ruleset validators pass;
4. confirm `validate-ruleset-contract.py --live` matched every observable ruleset field and did not interpret redacted bypass actors as empty;
5. confirm an administration-capable ruleset read verifies the no-bypass invariant where required CI cannot observe it;
6. confirm one Portfolio Ledger v2 is collected before Spotlight and the Spotlight projection validates against that exact Ledger;
7. confirm result, binding, and freshness stay independent and live publication requires `CURRENT_SUBJECT`;
8. confirm the public and attested subject sets remain the same exact 11 files;
9. confirm historical schema bytes remain frozen and current issuance uses v3 with `predicateSchema.digest`;
10. confirm generation has no write/signing authority, attestation has no repository write, staging remains read-only, and publication has no signing authority;
11. confirm dispatcher/proposer/approver/merger authority remains separated and UI merge still requires explicit manual authorization;
12. confirm a real production `Update profile stats` run succeeds after production-path changes;
13. confirm `generated` contains only the four Signal Field SVGs, six Spotlight SVGs, and Portfolio Ledger JSON;
14. confirm generated README images pass the cache-identity contract.

## Change policy

Update this threat model whenever the **trust graph, evidence graph, publication set, signing semantics, workflow authority, or control-plane assumptions** change. Routine copy or visual changes do not require a threat-model revision unless they alter one of those boundaries.
