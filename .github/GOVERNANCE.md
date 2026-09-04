# Repository governance contract

This profile repository treats its README, reviewed visual assets, generated Signal Field, Engineering Spotlight, Signal Field Evidence ID, and evidence attestations as production artifacts. Version-controlled workflow checks and GitHub repository settings are expected to enforce the same evidence boundary.

## Main branch

The active `Protect Main` ruleset must continue to require pull requests and block deletion and non-fast-forward updates. Before a pull request is merged, the two Profile Quality jobs, the Dependency Review job, and both CodeQL analysis jobs must succeed on the exact pull-request head:

- `Profile quality / validate-contracts`
- `Profile quality / integration-pinned-upstream`
- `Dependency review / dependency-review`
- `CodeQL / analyze-python`
- `CodeQL / analyze-actions`

All five checks should be configured as **required status checks** in the `Protect Main` GitHub ruleset. That requirement is a repository setting rather than a file in this branch; this document records the intended setting so it cannot be mistaken for optional process.

The integration check intentionally executes the exact SHA-pinned upstream Signal Field generator using read-only repository permissions and runs the complete production transformation chain without publishing.

## Dependency update automation

`.github/dependabot.yml` is the version-controlled Dependabot contract for this repository. Because this repository currently has no application package manifest, scheduled version updates are limited to the `github-actions` ecosystem at repository root. Dependabot runs weekly on Monday morning in `America/New_York`, with a bounded open-pull-request limit of ten. The configuration is intentionally canonical: adding another ecosystem, target branch, ignore/allow rule, registry, grouping rule, or other behavior is a governance change rather than silent configuration drift.

Every external workflow dependency must remain pinned to an **exact commit SHA**. Human-readable release tags in same-line comments are documentation that Dependabot can keep synchronized; execution authority comes only from the immutable commit identifier. The dependency validator discovers every `.github/workflows/*.yml` and `.yaml` file, including future workflows, and rejects floating tags/branches or unsupported external action forms.

Dependency updates remain individually reviewable: each action is expected in a **separate pull request** rather than a broad owner-level group. Shared ownership does not imply shared blast radius. `actions/attest` executes at the OIDC/attestation boundary, `actions/checkout` also participates in the write-only publication path, upload/download actions transport immutable evidence, setup actions control the execution environment, the Dependency Review action is a merge-time supply-chain gate, and the third-party `shinpr/github-profile-stats` generator materially affects generated evidence. Keeping these updates separate preserves attributable review and makes the exact SHA-contract change explicit for one dependency at a time.

Dependabot pull requests are **never auto-merged**. They must pass `Profile quality / validate-contracts`, `Profile quality / integration-pinned-upstream`, `Dependency review / dependency-review`, `CodeQL / analyze-python`, and `CodeQL / analyze-actions` on the exact proposed head and receive deliberate review. Existing governance validators intentionally pin the currently reviewed trust-boundary SHAs, so an action update should fail closed until the corresponding reviewed SHA contract is deliberately updated in the same pull request. This is intentional friction: the bot discovers an update, but a human authorizes the new executable identity.

Dependabot alerts and Dependabot security updates are repository settings distinct from this scheduled version-update file and should be enabled where supported. GitHub currently does not generate Dependabot vulnerability alerts for **SHA-pinned GitHub Actions** references, so scheduled GitHub Actions version updates remain the primary automated discovery channel for these immutable pins. Security settings still matter for any supported present or future dependency-graph entries and should remain enabled independently of version updates.

Neither scheduled nor security dependency updates may weaken workflow permissions, bypass attestation/generation/publication authority separation, target the `generated` artifact branch, expand the scope of any evidence claim, or introduce an auto-merge workflow with repository-write authority.

## Dependency review gate

`.github/workflows/dependency-review.yml` is the version-controlled pre-merge vulnerability gate for dependency changes. It runs the single stable `Dependency review / dependency-review` status on every pull request and intentionally uses **no path filters**, so workflow/action or future package-manifest changes cannot create an unreviewed dependency path.

The gate blocks **moderate-or-higher** known vulnerabilities across `runtime, development, and unknown` dependency scopes. All three scopes are covered deliberately because GitHub Actions and future dependency sources should not escape review due to scope classification. Vulnerability checking is enabled and `warn-only` behavior is forbidden.

Dependency Review is intentionally not a repository **license policy**. License checking is disabled so this security gate cannot silently reject a change based on an unreviewed licensing rule. A future license policy must be introduced as its own explicit governance decision rather than hidden inside vulnerability review.

The workflow and `actions/dependency-review-action` must remain pinned to exact commit SHAs. Workflow and job permissions remain `contents: read`; checkout credentials are not persisted, PR comments are disabled, and the gate must not receive `pull-requests: write`, repository-content write, OIDC, attestation, Actions-mutation, package-write, or security-event write authority.

The Dependency Review status is a merge-time supply-chain signal and should be required by `Protect Main` as `dependency-review`. It complements Dependabot: Dependabot discovers newer versions over time, while Dependency Review evaluates dependency changes introduced by each pull request before they reach `main`.

## CodeQL security analysis

`.github/workflows/codeql.yml` is the version-controlled static-analysis boundary for both authored Python and the repository's GitHub Actions workflows. It runs isolated `analyze-python` and `analyze-actions` jobs on every pull request, every push to `main`, manual dispatch, and a weekly scheduled scan. The workflow intentionally uses **no path filters** so changes to workflow/configuration or helper code cannot create an unscanned merge path.

GitHub recommends one CodeQL language per analysis, so the workflow uses a non-fail-fast language matrix containing exactly `python` and `actions`. Each language uses its native no-build analysis path, runs the `security-extended` query suite, and publishes results under a stable per-language SARIF category. No `autobuild` step is permitted because neither reviewed language requires one.

The workflow and its `github/codeql-action` dependencies must remain pinned to an **exact commit SHA** and are governed by Dependabot plus `scripts/validate-codeql-contract.py`.

The workflow default token remains `contents: read`. Each language-analysis job receives only `contents: read` plus `security-events: write`, which is required to publish code-scanning results. It must not receive `contents: write`, `pull-requests: write`, `id-token: write`, `attestations: write`, or other mutation/signing authority. Checkout credentials are not persisted.

The two CodeQL statuses are merge-time security signals and should be required by `Protect Main` as `analyze-python` and `analyze-actions`. Scheduled scans provide defense against newly added queries or newly recognized vulnerability patterns even when repository source is unchanged.

CodeQL is not an attestation and does not certify generated profile evidence, repository behavior, or every possible security property. It is an independent static-analysis control whose findings complement, but do not expand, the repository's evidence and attestation claims.

## Generated branch

The `generated` branch is an artifact branch, not a source branch. Its root is expected to contain only the generated Signal Field and Engineering Spotlight artifact trees. Publishing is performed only by the `publish-write-only` GitHub Actions job after a separately executed read-only generation job has succeeded, the immutable artifact set has been revalidated, and the attestation gate has completed.

The `generated` branch should have a GitHub ruleset that blocks **deletion** and **non-fast-forward** updates while still permitting the normal fast-forward pushes performed by GitHub Actions. Do not add a pull-request requirement that would break the automated publisher unless GitHub Actions is explicitly configured as an appropriate bypass actor.

## Signal Field Evidence ID

The four Signal Field variants must share one deterministic `signal-field-evidence-v1` identity when they encode the same measured evidence. The human correlation handle is `SF1-` plus the first 64 bits of the canonical evidence SHA-256 digest; the complete digest remains in SVG provenance and in the signed profile-evidence attestation predicate.

The identity is derived from measured evidence semantics, not rendered SVG bytes, so light/dark and wide/compact presentation differences cannot create distinct identities for the same evidence. Conversely, a change to measured profile totals, headline metrics, the 30-day date/count/level sequence, activity telemetry, or source semantics must change the canonical digest.

The short Evidence ID is not itself a cryptographic verification mechanism. Verification depends on the full SHA-256 evidence digest plus the artifact attestation.

## Authority separation

Third-party generation code must not receive repository write or attestation authority.

`generate-read-only` may read GitHub data and produce candidate artifacts with `contents: read` only. It has neither `contents: write`, `id-token: write`, nor `attestations: write`.

`attest-validated-evidence` is a separate trust-boundary job. It downloads the immutable generated artifacts into a fresh runner, revalidates both evidence sets, and may mint a short-lived OIDC identity and persist a GitHub artifact attestation. It receives `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. The reviewed `actions/attest` dependency must remain pinned to an exact commit SHA.

`publish-write-only` may publish only the immutable artifact set passed from generation after the attestation job succeeds. It receives `contents: write` but no OIDC or attestation authority, and revalidates the downloaded artifacts again at the publication boundary.

This separation prevents the third-party generator from signing its own output and prevents the publisher from creating the attestation on which publication depends.

## Attestation claim boundary

The engineering attestation establishes artifact provenance and repository-defined contract conformance for the named generated SVG subjects at the recorded source revision. It does not certify every software behavior represented by the profile, replace underlying CI/security evidence, or expand the scope of any oracle.

The predicate schema and verification instructions are version controlled in `.github/attestation/profile-evidence-v1.schema.json` and `.github/ATTESTATION.md`.

Any workflow edit that removes the named generation/attestation/publication jobs, pinned runtimes/actions, authority separation, Signal Field Evidence ID contract, final artifact validation, attestation gate, artifact-only generated-branch staging, governed Dependency Review, or governed CodeQL analysis is a governance-contract change and must fail Profile Quality until deliberately reviewed.
