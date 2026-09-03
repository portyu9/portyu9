# Repository governance contract

This profile repository treats its README, reviewed visual assets, and generated Signal Field as production artifacts. Version-controlled workflow checks and GitHub repository settings are expected to enforce the same evidence boundary.

## Main branch

The active `Protect Main` ruleset must continue to require pull requests and block deletion and non-fast-forward updates. Before a pull request is merged, both Profile Quality jobs must succeed on the exact pull-request head:

- `Profile quality / validate-contracts`
- `Profile quality / integration-pinned-upstream`

These two checks should also be configured as **required status checks** in the `Protect Main` GitHub ruleset. That requirement is a repository setting rather than a file in this branch; this document records the intended setting so it cannot be mistaken for optional process.

The integration check intentionally executes the exact SHA-pinned upstream Signal Field generator using read-only repository permissions and runs the complete production transformation chain without publishing.

## Generated branch

The `generated` branch is an artifact branch, not a source branch. Its root is expected to contain only the generated Signal Field artifact tree. Publishing is performed only by the `publish-write-only` GitHub Actions job after a separately executed read-only generation job has succeeded and the downloaded SVG set has been revalidated.

The `generated` branch should have a GitHub ruleset that blocks **deletion** and **non-fast-forward** updates while still permitting the normal fast-forward pushes performed by GitHub Actions. Do not add a pull-request requirement that would break the automated publisher unless GitHub Actions is explicitly configured as an appropriate bypass actor.

## Authority separation

Third-party generation code must not receive repository write authority. `generate-read-only` may read GitHub data and produce candidate artifacts. `publish-write-only` may publish only the immutable artifact set passed from that job and revalidated at its trust boundary.

Any workflow edit that removes these job names, pinned runtimes/actions, read/write separation, final artifact validation, or artifact-only generated-branch staging is a governance-contract change and must fail Profile Quality until deliberately reviewed.
