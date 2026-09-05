# Security threat model and control inventory

**Checkpoint:** 2026-09-05  
**Repository:** `portyu9/portyu9`  
**Baseline:** `main` after PR #83 (`80f08c6103e1da50e655681c57842df06b60f094`)

This document records the current trust graph, enforced repository controls, accepted residual risk, and verification points for the profile evidence system. It is an assurance checkpoint, not a new runtime permission grant.

## Security objective

Protect the integrity, attribution, and bounded meaning of the public profile and its generated evidence while keeping data collection, signing, and publication authority separate.

The architecture is intended to ensure that:

1. unreviewed source changes cannot reach `main` without the required merge gates;
2. third-party generation code cannot write repository content or mint attestations;
3. one Portfolio Evidence Ledger snapshot is the live system-evidence source for a run;
4. Spotlight cannot silently describe evidence collected at a different moment from its Ledger;
5. generated evidence is validated before transport, after transport, before attestation, and before publication;
6. the signer cannot publish repository content;
7. the publisher cannot mint the attestation on which publication depends;
8. public generated subjects exactly equal attested subjects;
9. published predicate schemas cannot be retroactively redefined;
10. mutable generated profile image URLs carry explicit, reviewed cache identities.

## Protected assets

| Asset | Security property |
| --- | --- |
| `main` source and README | reviewed integrity and attributable change history |
| Workflow definitions | least privilege, immutable dependencies, controlled triggers and shell inputs |
| Four Signal Field SVGs | validated evidence semantics and one deterministic Evidence ID/digest |
| Portfolio Evidence Ledger | one 13-system live evidence snapshot with exact system/run provenance |
| Six Engineering Spotlight SVGs | deterministic projection of the same validated Ledger snapshot |
| Signal Field Evidence ID / digest | stable correlation plus full-digest verification identity |
| Portfolio Ledger Evidence ID / digest | stable snapshot correlation plus full-digest verification identity |
| Profile evidence attestation | provenance and repository-defined contract-conformance statement |
| v1/v2 predicate schemas | immutable verification history and explicit current issuance semantics |
| `generated` branch | exact artifact-only public evidence history |
| README generated-asset cache tokens | cache identity aligned with current visual/evidence surface contract |
| GitHub Actions token capabilities | separation of read, signing, and publication authority |

## Trust boundaries

### 1. Pull request boundary

Source changes reach `main` through pull requests gated by these five exact status contexts:

- `validate-contracts`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

`Protect Main` is expected to block deletion and non-fast-forward updates and require the branch to be current. Review-count, conversation-resolution, and other ruleset details are GitHub control-plane settings and must be inspected separately from source-controlled validators.

### 2. Read-only Profile Quality boundary

`Profile quality / validate-contracts` receives `contents: read` and executes fail-closed source contracts, including profile assets, cache identities, Signal Field, Portfolio Ledger, Ledger-backed Spotlight projection, attestation, dependency provenance, workflow authority, shell safety, CodeQL governance, and repository governance.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed upstream Signal Field generator, applies the production transformation chain, performs an artifact upload/download round trip with digest enforcement, collects one live Portfolio Evidence Ledger, renders Spotlight from that Ledger without a second live evidence collection pass, and emits a read-only `GITHUB_STEP_SUMMARY`.

### 3. Dependency and Action boundary

Every external `uses:` reference executes at a reviewed 40-character commit SHA. The same-line semantic release annotation is resolved independently against the upstream repository and must identify the same executable commit.

Dependency Review is a required pull-request vulnerability gate. Dependabot discovers GitHub Actions updates but does not authorize them; trust changes remain explicit source changes and must pass the complete gate set.

### 4. Workflow authority boundary

The GitHub Actions surface is a closed allowlist of exactly four workflows:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`

Read-only is the default. Reviewed write-capable exceptions are limited to:

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| CodeQL analysis | `security-events: write` | publish code-scanning results |
| Profile stats / `attest-validated-evidence` | `id-token: write`, `attestations: write` | create profile-evidence attestation |
| Profile stats / `publish-write-only` | `contents: write` | fast-forward validated artifacts to `generated` |

No job combines repository-content write with OIDC/attestation authority.

### 5. Shell/data boundary

GitHub expressions are forbidden inside `run:` shell source. Dynamic values must cross reviewed non-shell fields such as `env:`, `with:`, or `if:`. The shell-safety validator rejects ambiguous YAML forms that obscure the generated command source.

This prevents direct expression-to-shell-source injection but does not replace input validation, quoting, path safety, or safe subprocess use inside authored scripts.

### 6. Generation boundary

`generate-read-only` executes with `contents: read` only. It has neither `contents: write`, `id-token: write`, nor `attestations: write`.

Its evidence flow is:

1. generate/transform/validate four Signal Field variants;
2. collect and validate one 13-system Portfolio Evidence Ledger;
3. deterministically select three rotating systems for the Ledger UTC date;
4. project exact Ledger subject revisions, evidence contracts, and full signal records into six light/dark Spotlight SVGs;
5. upload three immutable transport sets.

The Spotlight generator must not independently query GitHub for system evidence when operating in the production path.

### 7. Artifact transport boundary

Reviewed SHA-pinned upload/download Actions transport immutable evidence between jobs. Digest mismatch fails closed at the PR round trip, attestation boundary, and publication boundary where configured.

Transport success is not treated as authorization or semantic validity. Downstream jobs revalidate the content they consume.

### 8. Attestation boundary

`attest-validated-evidence` receives `contents: read`, `id-token: write`, and `attestations: write`, but not repository-content write permission.

It downloads the three immutable evidence sets, fails closed on digest mismatch, revalidates Signal Field, Portfolio Ledger, and the exact Ledger-backed Spotlight projection, builds the profile predicate, and only then invokes the pinned attestation Action.

The public/attested subject set is exactly 11 files:

- four Signal Field SVGs;
- six Spotlight SVGs;
- one Portfolio Evidence Ledger JSON document.

`spotlight-manifest.json` is internal validation metadata. It must not be published or attested.

### 9. Predicate-schema boundary

`.github/attestation/profile-evidence-v1.schema.json` is a frozen historical verification contract. Byte changes to v1 fail closed.

New production attestations use `profile-evidence-v2.schema.json`. The v2 predicate carries `predicateSchema.id` plus a full SHA-256 digest of the exact schema bytes used by the builder. Future semantic changes require a new schema filename/version rather than mutation of v1 or v2.

### 10. Publication boundary

`publish-write-only` depends on generation and attestation. It receives `contents: write`, but no OIDC or attestation authority.

It downloads the same immutable evidence, revalidates the evidence and Ledger-backed Spotlight binding again, stages exactly the 11 public subjects, proves the Spotlight manifest is absent from publication, and pushes a normal fast-forward commit to `generated`.

### 11. Generated branch boundary

`generated` is an artifact branch, not a second source branch. Its public tree is restricted to:

- `profile-stats/profile/` — four Signal Field SVGs;
- `engineering-spotlight/` — six Spotlight SVGs;
- `portfolio-evidence/portfolio-evidence-ledger.json` — one Ledger JSON file.

`Protect generated` should block deletion and non-fast-forward updates while permitting the reviewed publisher's normal fast-forward commits.

### 12. Profile image cache boundary

The README references mutable `generated`-branch images through explicit family cache identities. Six Spotlight URLs must share one current Spotlight token and four Signal Field URLs must share one current Signal Field token.

The cache contract is presentation/version hygiene; it does not replace evidence provenance or attestation. Missing, stale, or inconsistent tokens fail Profile Quality.

## Detection and prevention matrix

| Threat / failure mode | Primary control | Secondary control | Residual |
| --- | --- | --- | --- |
| Unvalidated source merged to `main` | five required status checks + `Protect Main` | no source-side bypass path | validator/control-plane defects remain possible |
| Known vulnerable dependency introduced | Dependency Review | Dependabot discovery | unknown/novel vulnerabilities remain possible |
| Floating or mislabeled external Action | exact SHA pin | live release-label → SHA provenance | pinned upstream code may itself be flawed |
| New workflow receives unreviewed authority | closed workflow authority allowlist | CodeQL Actions analysis | validator defects remain possible |
| Event data becomes shell source | shell-safety firewall | CodeQL Actions analysis | authored scripts still require safe data handling |
| Third-party generator writes repository content | generation is `contents: read` only | separate publication job | malicious candidate output still relies on validators |
| Third-party generator signs its own output | no OIDC/attestation authority in generation | fresh attestation job revalidates | validator correctness is part of TCB |
| Ledger and Spotlight describe different live moments | one live Portfolio Ledger collection | exact projection equality validation | GitHub data semantics at collection time are trusted input |
| Selected Spotlight data diverges from Ledger | full subject/contract/signal equality checks | revalidation at attestation/publication | renderer/validator implementation defects remain possible |
| Artifact corrupted in transport | digest mismatch fails closed | downstream semantic validation | GitHub artifact service is part of TCB |
| Public files differ from attested files | exact 11-subject staging/attestation closure | manifest exclusion + file-count checks | authored path-contract defects remain possible |
| Historical predicate semantics silently change | frozen v1 bytes + versioned v2 | `predicateSchema.digest` | verifier must choose the intended schema version |
| Signer publishes arbitrary content | signer lacks `contents: write` | separate publisher | platform compromise is out of scope |
| Publisher forges attestation | publisher lacks OIDC/attestation authority | publication depends on signer | platform credential compromise is out of scope |
| Force-push/delete generated history | `Protect generated` | artifact-only staging | authorized fast-forward publisher remains powerful |
| Stale profile imagery after renderer changes | explicit family cache tokens | cache-contract validator | intermediary cache refresh timing is not fully controllable |
| Evidence claim overstates assurance | bounded predicate claim | governance/threat-model documentation | human interpretation risk remains |

## Trusted computing base

The design reduces authority but still trusts:

1. **GitHub platform and hosted runners** for job isolation, token issuance, artifact storage, OIDC, attestations, API behavior, and rulesets.
2. **Reviewed immutable Action commits**. Pinning prevents later movement but does not prove the pinned implementation is safe.
3. **Repository validators and generators**. They are security-sensitive authored code and can contain defects.
4. **GitHub evidence semantics** returned by the API at collection time.
5. **Repository control-plane settings** such as rulesets, which must be inspected separately from source-controlled contracts.

## Accepted residual risks

- A zero-day or malicious behavior in a reviewed pinned dependency may evade Dependency Review and CodeQL.
- An upstream release tag move/deletion can cause fail-closed CI availability loss.
- A compromised GitHub-hosted runner or control plane is outside repository-level mitigation.
- `publish-write-only` intentionally holds `contents: write`; safety depends on source protection, authority isolation, attestation dependency, and repeated validation.
- Attestation proves provenance and repository-defined contract conformance, not universal behavioral correctness.
- Public GitHub API/network outages can block live evidence refresh; integrity takes priority over availability.
- Mutable-image cache invalidation cannot force every intermediary to refresh instantly; the repository controls cache identity, not external cache implementation.
- Settings-level controls can drift without a source diff and therefore require periodic control-plane verification.

## Verification checklist

After a material workflow, evidence, or governance change:

1. confirm the exact five required PR checks succeeded on the final head;
2. confirm Action provenance, Dependency Review, authority, shell-safety, cache, and CodeQL validators pass;
3. confirm one Portfolio Ledger is collected before Spotlight and the Spotlight projection validates against that exact Ledger;
4. confirm the public and attested subject sets remain the same exact 11 files;
5. confirm v1 schema bytes remain frozen and current issuance uses v2 with `predicateSchema.digest`;
6. confirm generation has no write/signing authority, attestation has no repository write, and publication has no signing authority;
7. confirm a real production `Update profile stats` run succeeds after production-path changes;
8. confirm `generated` contains only the four Signal Field SVGs, six Spotlight SVGs, and Portfolio Ledger JSON;
9. confirm generated README images pass the cache-identity contract;
10. inspect repository rulesets separately from source-controlled validation.

## Change policy

Update this threat model whenever the **trust graph, evidence graph, publication set, signing semantics, or control-plane assumptions** change. Routine copy or visual changes do not require a threat-model revision unless they alter one of those boundaries.
