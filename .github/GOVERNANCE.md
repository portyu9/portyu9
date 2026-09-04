# Repository governance contract

This profile repository treats its README, reviewed visual assets, generated Signal Field, Engineering Spotlight, Signal Field Evidence ID, and evidence attestations as production artifacts. Version-controlled workflow checks and GitHub repository settings are expected to enforce the same evidence boundary.

## Main branch

The active `Protect Main` ruleset must continue to require pull requests and block deletion and non-fast-forward updates. Before a pull request is merged, both Profile Quality jobs must succeed on the exact pull-request head:

- `Profile quality / validate-contracts`
- `Profile quality / integration-pinned-upstream`

These two checks should also be configured as **required status checks** in the `Protect Main` GitHub ruleset. That requirement is a repository setting rather than a file in this branch; this document records the intended setting so it cannot be mistaken for optional process.

The integration check intentionally executes the exact SHA-pinned upstream Signal Field generator using read-only repository permissions and runs the complete production transformation chain without publishing.

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

Any workflow edit that removes the named generation/attestation/publication jobs, pinned runtimes/actions, authority separation, Signal Field Evidence ID contract, final artifact validation, attestation gate, or artifact-only generated-branch staging is a governance-contract change and must fail Profile Quality until deliberately reviewed.
