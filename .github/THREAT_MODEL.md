# Security threat model and control inventory

**Checkpoint:** 2026-09-04  
**Repository:** `portyu9/portyu9`  
**Baseline:** `main` after PR #65 (`ce5dcf4e1d884c38236f0ef369e3d89afba11faa`)

This document is an assurance checkpoint, not a new runtime control. It records the current trust boundaries, enforced controls, residual risks, and verification points for the profile repository after completion of the planned roadmap and post-roadmap hardening.

## Security objective

Protect the integrity and attribution of the public profile and its generated evidence while keeping automation authority narrowly separated.

The repository is designed so that:

1. unreviewed source changes cannot reach `main` without all required gates;
2. third-party generation code cannot write repository content or mint attestations;
3. generated evidence is validated before transport, after transport, before attestation, and before publication;
4. the signer cannot publish repository content;
5. the publisher cannot mint the attestation on which publication depends;
6. external Actions execute only at reviewed immutable commits whose release labels are independently resolved;
7. new workflow authority, triggers, jobs, or direct expression-to-shell paths fail closed;
8. the `generated` branch remains an artifact branch rather than a second source branch.

## Protected assets

| Asset | Security property |
| --- | --- |
| `main` source and profile README | reviewed integrity and attributable change history |
| Workflow definitions | least privilege, immutable dependencies, controlled triggers and shell inputs |
| Signal Field SVG set | validated evidence semantics, shared deterministic Evidence ID, artifact integrity |
| Engineering Spotlight SVG set | scoped live evidence, validated safe SVG structure and provenance |
| Signal Field Evidence ID / full evidence digest | stable correlation between equivalent render variants and signed evidence |
| Artifact attestation | provenance and repository-defined contract-conformance statement |
| `generated` branch | artifact-only publication history with no force-push/deletion path |
| GitHub Actions token capabilities | separation of read, signing, and publication authority |

## Trust boundaries

### 1. Pull request boundary

All source changes enter `main` through pull requests. `Protect Main` is active, has no bypass actors, blocks branch deletion and non-fast-forward updates, requires the branch to be current, and requires these five exact status contexts:

- `validate-contracts`
- `integration-pinned-upstream`
- `dependency-review`
- `analyze-actions`
- `analyze-python`

The ruleset currently requires **zero approving reviews**. This is an intentional solo-maintainer operating choice; automated gates are enforced, while human review remains process rather than a GitHub review-count requirement.

Repository auto-merge is disabled. Completed source branches are deleted after merge.

### 2. PR validation boundary

`Profile quality / validate-contracts` is read-only and executes the repository's fail-closed contracts, including:

- profile/visual contracts;
- Signal Field generation and semantic contracts;
- Engineering Spotlight validation;
- attestation-boundary validation;
- capability-evidence validation;
- Dependabot governance;
- action release provenance;
- Dependency Review governance;
- workflow authority firewall;
- workflow shell-safety firewall;
- CodeQL governance;
- repository meta-governance.

`Profile quality / integration-pinned-upstream` is also read-only. It executes the exact reviewed third-party generator, runs the complete transformation chain, performs an upload/download artifact round trip, fails on artifact digest mismatch, revalidates the downloaded bytes, and exercises the live Engineering Spotlight evidence path.

### 3. Dependency and Action boundary

Every external `uses:` reference must execute an exact 40-character commit SHA.

Profile Quality separately resolves the same-line `# vX.Y.Z` release annotation against the public upstream repository and requires the resolved release commit to equal the executable SHA. Both lightweight and annotated tags are supported.

The current workflow inventory contains eight unique external repository/release identities:

- `actions/attest@v4.2.2`
- `actions/checkout@v7.0.1`
- `actions/dependency-review-action@v5.0.0`
- `actions/download-artifact@v8.0.1`
- `actions/setup-python@v7.0.0`
- `actions/upload-artifact@v7.0.1`
- `github/codeql-action@v4.37.9`
- `shinpr/github-profile-stats@v0.2.0`

Dependabot discovers GitHub Actions updates weekly and keeps each dependency independently reviewable. Bot-driven auto-merge is intentionally forbidden. A new action SHA is not trusted merely because Dependabot proposed it: reviewed SHA contracts must be deliberately updated and the full gate set must pass.

Dependency graph, Dependabot alerts, and Dependabot security updates were enabled as repository settings during this hardening checkpoint.

### 4. Workflow authority boundary

The GitHub Actions surface is a closed allowlist containing exactly four workflows:

- `codeql.yml`
- `dependency-review.yml`
- `profile-quality.yml`
- `profile-stats.yml`

The authority firewall locks each workflow's trigger inventory, job inventory, workflow-level permissions, and job-level permissions.

Read-only is the default. The only reviewed write-capable token exceptions are:

| Workflow / job | Additional authority | Purpose |
| --- | --- | --- |
| CodeQL / analysis | `security-events: write` | publish code-scanning results |
| Profile stats / `attest-validated-evidence` | `id-token: write`, `attestations: write` | mint and persist artifact attestation |
| Profile stats / `publish-write-only` | `contents: write` | fast-forward validated artifacts to `generated` |

No current job combines repository-content write with OIDC/attestation authority.

Privileged trigger families such as `pull_request_target`, `workflow_run`, `repository_dispatch`, and comment-driven execution are not currently authorized.

### 5. Shell/data boundary

GitHub expressions are forbidden inside every `run:` shell body.

The shell-safety firewall currently scans all workflow shell steps and requires dynamic values to cross non-shell fields such as `env:`, `with:`, or `if:`. YAML aliases, anchors, tags, quoted whole-command scalars, and non-canonical `run:` forms that would obscure the generated shell source are rejected.

This prevents event-controlled values such as PR titles, branch names, issue bodies, or matrix/context data from becoming shell source through direct `${{ ... }}` interpolation.

Normal shell hygiene still applies after data enters through `env:`: variables should be quoted and authored scripts must validate values according to their own contracts.

### 6. Read-only generation boundary

`generate-read-only` executes the third-party Signal Field generator with `contents: read` only.

It has neither:

- `contents: write`;
- `id-token: write`;
- `attestations: write`.

Candidate Signal Field and Engineering Spotlight artifacts are transformed and validated before upload. The generation job uploads immutable evidence sets but cannot publish them to a repository branch and cannot sign them.

### 7. Artifact transport boundary

Artifact transport uses reviewed SHA-pinned upload/download actions.

Downloads at the PR round-trip, attestation boundary, and publication boundary use `digest-mismatch: error` where applicable. Downloaded Signal Field bytes are revalidated rather than trusted solely because an artifact transfer succeeded.

The artifact mechanism is a transport boundary, not an authorization boundary: downstream jobs still independently validate the artifact content they consume.

### 8. Attestation boundary

`attest-validated-evidence` runs as a separate job with a fresh job token and no repository-content write permission.

It downloads the immutable evidence, fails closed on digest mismatch, revalidates Signal Field and Engineering Spotlight contracts, builds the repository-defined predicate, and only then executes the pinned `actions/attest` identity.

The attestation binds the generated evidence and Signal Field Evidence ID/digest to the recorded source revision and repository-defined conformance claim.

The attestation does **not** certify every software behavior represented by the profile and does not replace underlying CI/security evidence.

### 9. Publication boundary

`publish-write-only` depends on both generation and attestation.

It receives `contents: write` but receives neither OIDC nor attestation authority. It downloads and revalidates the immutable artifact set again, stages only generated artifact trees, and pushes a normal fast-forward commit to `generated`.

The publisher therefore cannot create the attestation whose successful completion gates publication.

### 10. Generated branch boundary

`Protect generated` is active for `refs/heads/generated` and blocks:

- branch deletion;
- non-fast-forward updates.

It intentionally does not require pull requests, because the reviewed publisher performs normal fast-forward artifact publication.

At this checkpoint the repository branch inventory is only:

- `main`;
- `generated`.

## Detection and prevention matrix

| Threat / failure mode | Primary control | Secondary control | Residual |
| --- | --- | --- | --- |
| Unvalidated source merged to `main` | strict five-check `Protect Main` ruleset | no bypass actors | automated checks can still have defects |
| Known vulnerable dependency introduced in a PR | required Dependency Review | Dependabot alerts/security updates | unknown/novel vulnerabilities remain possible |
| Stale GitHub Action dependency | weekly Dependabot | manual review + exact SHA contracts | update discovery depends on GitHub/Dependabot availability |
| Floating or silently changed Action reference | exact SHA pin validator | release tag → SHA provenance check | pinned code may itself be malicious or flawed |
| Upstream release tag moved/deleted | live release provenance check | immutable executable SHA remains unchanged | can cause fail-closed CI availability loss |
| New workflow silently receives write authority | closed workflow authority allowlist | CodeQL Actions analysis | validator defects remain possible |
| Dangerous trigger added | trigger allowlist | CodeQL Actions analysis | deliberate governance changes still require sound review |
| Event text injected into shell source | workflow shell-safety firewall | CodeQL Actions analysis | authored scripts must still validate/quote data |
| Third-party generator writes repository content | generation job has `contents: read` only | separate publisher job | generator can still produce malicious candidate output |
| Third-party generator signs its own output | no OIDC/attestation authority in generation | fresh attestation job revalidates | validator correctness is part of TCB |
| Artifact corrupted in transport | digest mismatch fails closed | downstream semantic revalidation | GitHub artifact service is part of TCB |
| Signer publishes arbitrary repository content | signer lacks `contents: write` | publisher is separate job | GitHub platform compromise is out of scope |
| Publisher forges attestation | publisher lacks OIDC/attestation authority | publication depends on attestation job | platform-level credential compromise is out of scope |
| Force-push/delete generated evidence history | `Protect generated` | artifact-only staging contract | normal authorized fast-forward publisher remains powerful |
| Static vulnerability in Python/workflows | CodeQL `security-extended` for Python + Actions | repository-specific validators | CodeQL is not exhaustive |
| Evidence variants diverge semantically | deterministic Signal Field Evidence ID/full digest | v2.14/final artifact validators | upstream API correctness is trusted input |
| Evidence claim overstates assurance | explicit predicate/attestation claim boundary | governance documentation | human interpretation risk remains |

## Trusted computing base

The design intentionally reduces authority but does not eliminate all trust. The following remain part of the trusted computing base or external assumptions:

1. **GitHub platform and hosted runners.** Runner provisioning, job-token isolation, artifact storage, OIDC, attestations, branch rulesets, and GitHub API behavior are trusted platform services.
2. **Reviewed immutable Action commits.** Pinning prevents later movement but cannot make intentionally malicious code safe. Review, release provenance, least privilege, Dependency Review, and CodeQL reduce—not eliminate—this risk.
3. **Repository validators.** The fail-closed validators are security-sensitive authored code. CodeQL and adversarial self-tests provide defense in depth, but validator implementation errors remain possible.
4. **GitHub data semantics.** Profile metrics and evidence depend on GitHub API data being available and semantically correct for the queries performed.
5. **Solo-maintainer authorization.** `Protect Main` does not require an approving review. Deliberate human authorization of dependency trust changes is a maintained process requirement rather than a separate-person approval guarantee.

## Accepted residual risks

The following are accepted at this checkpoint rather than hidden as implied guarantees:

- A zero-day or malicious behavior in a reviewed pinned dependency may not be detected by Dependency Review or CodeQL.
- An upstream tag deletion/move can intentionally or accidentally create a CI denial of service because release provenance fails closed.
- A compromised GitHub-hosted runner or GitHub control plane is outside the repository-level threat model.
- The publication job intentionally holds `contents: write` and can fast-forward `generated`; its safety depends on protected source, job authority isolation, and repeated artifact validation.
- The attestation proves provenance and repository-defined contract conformance, not universal behavioral correctness.
- Public GitHub API/network outages can prevent live validation or scheduled evidence refreshes; availability is secondary to fail-closed integrity.
- Shell safety prevents expression-to-source injection but does not replace ordinary input validation, quoting, path safety, or secure subprocess usage inside Python/shell code.
- Security settings that live only in GitHub's control plane cannot be guaranteed by repository files alone and should be periodically compared with this document.

## Verification checklist

Use this checklist after a material workflow/security change:

1. Confirm `main` has only the intended source changes and the PR head is current.
2. Confirm all five required PR checks succeeded on the exact head.
3. Confirm `Protect Main` still has no bypass actors and still requires the five named contexts.
4. Confirm `Protect generated` still blocks deletion and non-fast-forward updates.
5. Confirm workflow inventory remains exactly the reviewed four workflows.
6. Confirm all external actions are exact-SHA pinned and release-provenance verification passes.
7. Confirm workflow authority and shell-safety validators pass.
8. Confirm PR integration completes artifact upload → download → digest enforcement → revalidation.
9. For production-path changes, confirm a real `Update profile stats` run succeeds through `generate-read-only → attest-validated-evidence → publish-write-only`.
10. Confirm branch hygiene returns to only `main` and `generated` after merge.

## Change policy

This threat model should change when the **trust graph** changes—not for routine profile copy, styling, or evidence-refresh changes.

Revisit it when adding or changing any of the following:

- workflow/job inventory or trigger families;
- token permissions or secrets;
- external Action repositories;
- package ecosystems or build systems;
- attestation predicate/identity model;
- artifact transport/storage mechanism;
- generated-branch publication model;
- branch rulesets or required status checks;
- new external evidence sources;
- a new trust boundary, signer, publisher, or deployment destination.

The desired operating posture after this checkpoint is to stop adding security machinery speculatively. New controls should be introduced only for a concrete threat, demonstrated gap, platform change, or new repository capability.
