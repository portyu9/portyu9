# Security threat model and control inventory

**Checkpoint:** 2026-09-05  
**Repository:** `portyu9/portyu9`

This document records the current trust graph, enforced repository controls, accepted residual risk, and verification points for my profile evidence system. It is an assurance checkpoint, not a new runtime permission grant.

## Security objective

Protect the integrity, attribution, and bounded meaning of my public profile and its generated evidence while keeping data collection, signing, and publication authority separate.

The architecture is intended to ensure that:

1. unreviewed source changes cannot reach `main` without the required merge gates;
2. third-party generation code cannot write repository content or mint attestations;
3. **one Portfolio Evidence Ledger snapshot** is the live system-evidence source for a run;
4. Spotlight cannot silently describe evidence collected at a different moment from its Ledger;
5. execution result, subject binding, and freshness are distinct facts and cannot overwrite one another;
6. generated evidence is validated before transport, after transport, before attestation, and before publication;
7. the signer cannot publish repository content and the publisher cannot mint the attestation on which publication depends;
8. public generated subjects exactly equal attested subjects;
9. published predicate schemas cannot be retroactively redefined;
10. mutable generated profile image URLs carry explicit, reviewed cache identities;
11. every ruleset field observable to the read-only workflow identity must match source-controlled intent before the required Profile Quality gate passes, while admin-redacted bypass actors remain a separately audited invariant rather than an assumed value.

## Protected assets

| Asset | Security property |
| --- | --- |
| `main` source and README | reviewed integrity and attributable change history |
| Workflow definitions | least privilege, immutable dependencies, controlled triggers and shell inputs |
| Four Signal Field SVGs | validated evidence semantics and one deterministic Evidence ID/digest |
| Portfolio Evidence Ledger v2 | one 13-system live evidence snapshot with exact result, binding, freshness, and run provenance |
| Six Engineering Spotlight SVGs | deterministic Ledger-backed Spotlight projection of the same validated snapshot |
| Signal Field Evidence ID / digest | stable correlation plus full-digest verification identity |
| Portfolio Ledger `PL2-` ID / digest | stable snapshot correlation plus full-digest verification identity |
| Profile evidence attestation | provenance and repository-defined contract-conformance statement |
| v1/v2 predicate schemas | frozen historical verification contracts |
| v3 predicate schema | current issuance semantics with `predicateSchema.digest` and Ledger v2 binding |
| `generated` branch | exact artifact-only public evidence history |
| README generated-asset cache tokens | cache identity aligned with current visual surface contract |
| Repository ruleset control plane | observable live enforcement must match reviewed desired state; admin-redacted fields remain explicit audit invariants |
| GitHub Actions token capabilities | separation of read, signing, and publication authority |

## Trust boundaries

### 1. Pull request boundary

Source changes reach `main` through pull requests gated by these five exact status contexts:

- `validate-contracts`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

`Protect Main` must block deletion and non-fast-forward updates, require pull requests, allow only merge commits, require review-thread resolution, and require the branch to be current. The required `validate-contracts` job runs `python3 scripts/validate-ruleset-contract.py --live`, so the exact ruleset inventory, targets, enforcement, pull-request parameters, required-status contract, and generated-branch rule inventory are compared with the **live GitHub control-plane** before merge.

GitHub redacts `bypass_actors` from the short-lived read-only Actions token and unauthenticated public API. The gate therefore does not interpret omission as empty. No bypass actors remains a source-locked, **admin-scope** invariant; the latest connected control-plane audit on 2026-09-05 observed `bypass_actors: []` for both rulesets.

### 2. Read-only Profile Quality boundary

`Profile quality / validate-contracts` receives `contents: read` and executes fail-closed source contracts, including profile assets, cache identities, Signal Field, Portfolio Ledger v2, Ledger-backed Spotlight projection, attestation, dependency provenance, workflow authority, shell safety, CodeQL governance, assurance documentation, repository governance, and source-plus-live observable ruleset verification. The ruleset API read uses the workflow's read-only GitHub token and grants no settings mutation authority.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed upstream Signal Field generator, applies the production transformation chain, performs an artifact upload/download round trip with digest enforcement, collects one live Portfolio Evidence Ledger v2, renders Spotlight from that Ledger without a second live evidence collection pass, and emits a read-only `GITHUB_STEP_SUMMARY`.

### 3. Dependency and Action boundary

Every external `uses:` reference executes at a reviewed 40-character commit SHA. The same-line semantic release annotation is resolved independently against the upstream repository and must identify the same executable commit.

Dependency Review is a required pull-request vulnerability gate. Dependabot discovers GitHub Actions updates but does not authorize them; trust changes remain explicit source changes and must pass the complete gate set.

### 4. Workflow authority boundary

The GitHub Actions surface is a closed allowlist of exactly four workflows: `codeql.yml`, `dependency-review.yml`, `profile-quality.yml`, and `profile-stats.yml`.

Read-only is the default. Reviewed write-capable exceptions are limited to CodeQL `security-events: write`, Profile stats `attest-validated-evidence` with `id-token: write` + `attestations: write`, and Profile stats `publish-write-only` with `contents: write`. No job combines repository-content write with OIDC/attestation authority.

### 5. Shell/data boundary

GitHub expressions are forbidden inside `run:` shell source. Dynamic values must cross reviewed non-shell fields such as `env:`, `with:`, or `if:`. This prevents direct expression-to-shell-source injection but does not replace input validation, quoting, path safety, or safe subprocess use inside authored scripts.

### 6. Generation boundary

`generate-read-only` executes with `contents: read` only. It has neither `contents: write`, `id-token: write`, nor `attestations: write`.

Its evidence flow is:

1. generate/transform/validate four Signal Field variants;
2. collect and validate one 13-system Portfolio Evidence Ledger v2;
3. deterministically select three rotating systems for the Ledger UTC date;
4. project exact Ledger subject revisions, evidence contracts, execution results, subject bindings, freshness, and run provenance into six light/dark Spotlight SVGs;
5. upload three immutable transport sets.

The Spotlight generator must not independently query GitHub for system evidence when operating in the production path.

### 7. Orthogonal evidence boundary

Portfolio Evidence Ledger v2 uses the semantics identifier `execution-result-subject-binding-freshness-v1`.

Each evidence record contains three independent dimensions:

- **execution result** — the observed workflow/job/step conclusion;
- **subject binding** — whether the run head equals the current `main` subject;
- **freshness** — timestamp availability and UTC whole-day age.

The principal failure mode addressed here is semantic conflation. A successful run on a different commit must remain `PASSING` in the result dimension while separately becoming `DIFFERENT_SUBJECT` in binding. It must not be rewritten to a synthetic `STALE` result. Likewise, `AGED` belongs only to freshness.

Fail-closed live publication is preserved: `--require-live` requires a usable execution result, `CURRENT_SUBJECT` binding, available freshness, and complete run provenance. Separation improves attribution without broadening what may be attested or published.

### 8. Artifact transport boundary

Reviewed SHA-pinned upload/download Actions transport immutable evidence between jobs. Digest mismatch fails closed at the PR round trip, attestation boundary, and publication boundary where configured. Transport success is not treated as authorization or semantic validity; downstream jobs revalidate the content they consume.

### 9. Attestation boundary

`attest-validated-evidence` receives `contents: read`, `id-token: write`, and `attestations: write`, but not repository-content write permission.

It downloads the three immutable evidence sets, fails closed on digest mismatch, revalidates Signal Field, Portfolio Ledger v2, and the exact Ledger-backed Spotlight projection, builds my profile predicate, and only then invokes the pinned attestation Action.

The public/attested subject set is **exactly 11 files**: four Signal Field SVGs, six Spotlight SVGs, and one Portfolio Evidence Ledger JSON document. `spotlight-manifest.json` is internal validation metadata and must not be published or attested.

### 10. Predicate-schema boundary

`.github/attestation/profile-evidence-v1.schema.json` and `.github/attestation/profile-evidence-v2.schema.json` are each a **frozen historical verification contract**. Byte changes to either fail closed.

New production attestations use `profile-evidence-v3.schema.json`. Predicate v3 carries `predicateSchema.id` plus `predicateSchema.digest`, the full SHA-256 digest of the exact schema bytes used by the builder. It additionally binds `portfolio-evidence-ledger-v2`, `PL2-` identity format, system count 13, and `execution-result-subject-binding-freshness-v1`. Future semantic changes require a new schema filename/version rather than mutation of v1, v2, or v3.

### 11. Publication boundary

`publish-write-only` depends on generation and attestation. It receives `contents: write`, but no OIDC or attestation authority. It downloads the same immutable evidence, revalidates the evidence and Ledger-backed Spotlight binding again, stages exactly the 11 public subjects, proves the Spotlight manifest is absent from publication, and pushes a normal fast-forward commit to `generated`.

### 12. Generated branch boundary

`generated` is an artifact branch, not a second source branch. Its public tree is restricted to four Signal Field SVGs under `profile-stats/profile/`, six Spotlight SVGs under `engineering-spotlight/`, and `portfolio-evidence/portfolio-evidence-ledger.json`.

`Protect generated` should block deletion and non-fast-forward updates while permitting the reviewed publisher's normal fast-forward commits.

### 13. Profile image cache boundary

The README references mutable `generated`-branch images through explicit family cache identities. Six Spotlight URLs must share one current Spotlight token and four Signal Field URLs must share one current Signal Field token.

The **Profile image cache boundary** is presentation/version hygiene; it does not replace evidence provenance or attestation. Missing, stale, or inconsistent tokens fail Profile Quality.

### 14. Ruleset drift boundary

`.github/rulesets/repository-rulesets-v1.json` is the reviewed desired state for `Protect Main` and `Protect generated`. `validate-ruleset-contract.py --live` reads the current repository rulesets and fails when any observable ruleset inventory, target, enforcement, pull-request parameter, required-status contract, or generated-branch protection differs. If GitHub exposes `bypass_actors`, a non-empty value also fails.

When `bypass_actors` is redacted, the validator emits an explicit notice and does not treat the missing field as empty. That blind spot remains an admin-scope control-plane audit invariant. This still closes the broader prior observability gap while preserving an honest distinction between what required CI proves and what an administration-capable audit must verify.

## Detection and prevention matrix

| Threat / failure mode | Primary control | Secondary control | Residual |
| --- | --- | --- | --- |
| Unvalidated source merged to `main` | five required status checks + `Protect Main` | no source-side bypass path | validator/control-plane defects remain possible |
| Observable ruleset settings drift from reviewed intent | required live ruleset comparison | source-controlled desired-state contract | admin-redacted bypass actors require separate privileged audit; drift can exist between executions |
| Known vulnerable dependency introduced | Dependency Review | Dependabot discovery | unknown/novel vulnerabilities remain possible |
| Floating or mislabeled external Action | exact SHA pin | live release-label → SHA provenance | pinned upstream code may itself be flawed |
| New workflow receives unreviewed authority | closed workflow authority allowlist | CodeQL Actions analysis | validator defects remain possible |
| Event data becomes shell source | shell-safety firewall | CodeQL Actions analysis | authored scripts still require safe data handling |
| Third-party generator writes or signs | generation is read-only and non-signing | isolated signer/publisher | validator correctness is part of TCB |
| Ledger and Spotlight describe different live moments | one live Portfolio Ledger collection | exact projection equality validation | GitHub data semantics at collection time are trusted input |
| Execution result overwritten by revision mismatch | orthogonal result/binding fields | validators forbid legacy conflated `signal` in Ledger v2 | authored semantic bugs remain possible |
| Freshness confused with execution state | explicit freshness dimension | separate freshness summary + projection checks | chosen age policy remains repository-defined |
| Selected Spotlight data diverges from Ledger | full subject/contract/result/binding/freshness equality | revalidation at attestation/publication | renderer/validator implementation defects remain possible |
| Artifact corrupted in transport | digest mismatch fails closed | downstream semantic validation | GitHub artifact service is part of TCB |
| Public files differ from attested files | exact 11-subject staging/attestation closure | manifest exclusion + file-count checks | authored path-contract defects remain possible |
| Historical predicate semantics silently change | frozen v1/v2 bytes + versioned v3 | `predicateSchema.digest` | verifier must choose the intended schema version |
| Signer publishes arbitrary content | signer lacks `contents: write` | separate publisher | platform compromise is out of scope |
| Publisher forges attestation | publisher lacks OIDC/attestation authority | publication depends on signer | platform credential compromise is out of scope |
| Force-push/delete generated history | `Protect generated` | artifact-only staging | authorized fast-forward publisher remains powerful |
| Stale profile imagery after renderer changes | explicit family cache tokens | cache-contract validator | intermediary cache refresh timing is not fully controllable |
| Evidence claim overstates assurance | bounded predicate claim | governance/threat-model documentation | human interpretation risk remains |

## Trusted computing base

The design still trusts GitHub platform/hosted runners, reviewed immutable Action commits, repository validators/generators, GitHub evidence semantics returned by the API at collection time, and repository control-plane settings such as rulesets.

## Accepted residual risks

- A zero-day or malicious behavior in a reviewed pinned dependency may evade Dependency Review and CodeQL.
- An upstream release tag move/deletion can cause fail-closed CI availability loss.
- A compromised GitHub-hosted runner or control plane is outside repository-level mitigation.
- `publish-write-only` intentionally holds `contents: write`; safety depends on source protection, authority isolation, attestation dependency, and repeated validation.
- Attestation proves provenance and repository-defined contract conformance, not universal behavioral correctness.
- Public GitHub API/network outages can block live evidence refresh or the live ruleset gate; integrity takes priority over availability.
- Mutable-image cache invalidation cannot force every intermediary to refresh instantly; my repository controls cache identity, not external cache implementation.
- Settings-level controls can drift between Profile Quality executions. In addition, `bypass_actors` is not observable to the required read-only workflow identity, so that no-bypass invariant depends on periodic administration-capable control-plane audit rather than silent inference.

## Verification checklist

After a material workflow, evidence, or governance change:

1. confirm the exact five required PR checks succeeded on the final head;
2. confirm Action provenance, Dependency Review, authority, shell-safety, cache, ruleset, and CodeQL validators pass;
3. confirm `validate-ruleset-contract.py --live` matched every observable checked-in ruleset field to the live GitHub control-plane and did not interpret redacted bypass actors as empty;
4. confirm an administration-capable ruleset read verifies the source-locked no-bypass invariant when that field is redacted from required CI;
5. confirm one Portfolio Ledger v2 is collected before Spotlight and the Spotlight projection validates against that exact Ledger;
6. confirm result, binding, and freshness stay independent across Ledger, Spotlight metadata, read-only summary, and predicate semantics;
7. confirm the public and attested subject sets remain the same exact 11 files;
8. confirm v1/v2 schema bytes remain frozen and current issuance uses v3 with `predicateSchema.digest`;
9. confirm generation has no write/signing authority, attestation has no repository write, and publication has no signing authority;
10. confirm a real production `Update profile stats` run succeeds after production-path changes;
11. confirm `generated` contains only the four Signal Field SVGs, six Spotlight SVGs, and Portfolio Ledger JSON;
12. confirm generated README images pass the cache-identity contract.

## Change policy

Update this threat model whenever the **trust graph, evidence graph, publication set, signing semantics, or control-plane assumptions** change. Routine copy or visual changes do not require a threat-model revision unless they alter one of those boundaries.