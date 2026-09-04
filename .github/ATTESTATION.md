# Engineering attestation contract

This profile treats generated evidence as a supply-chain artifact rather than decorative output.

The production profile workflow separates three authorities:

1. `generate-read-only` collects GitHub evidence and applies repository-defined transformation and validation contracts with `contents: read` only.
2. `attest-validated-evidence` downloads the immutable validated artifacts into a fresh job, revalidates them, and creates a GitHub artifact attestation using a short-lived Sigstore-backed workflow identity. This job has `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission.
3. `publish-write-only` may update only the generated artifact branch after generation and attestation have both succeeded. It revalidates the downloaded artifact set again before staging and publication.

The third-party Signal Field generator therefore never receives repository write or attestation authority, and the publication job never creates the attestation it relies on.

## Attested subjects

One attestation covers the eight SVG files that make up the generated profile-evidence set:

- `profile-stats/profile/signal-field-wide-light.svg`
- `profile-stats/profile/signal-field-wide-dark.svg`
- `profile-stats/profile/signal-field-compact-light.svg`
- `profile-stats/profile/signal-field-compact-dark.svg`
- `engineering-spotlight/spotlight-1-light.svg`
- `engineering-spotlight/spotlight-1-dark.svg`
- `engineering-spotlight/spotlight-2-light.svg`
- `engineering-spotlight/spotlight-2-dark.svg`

The custom predicate type is:

`https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json`

The predicate records the exact source revision, workflow/run identity, published subject paths, validators, and the authority separation under which the evidence was produced.

## Claim boundary

The attestation establishes that the named generated artifacts passed the repository-defined validators at the recorded source revision before publication and that GitHub can verify the workflow identity that issued the attestation.

It does **not** certify every software behavior represented by the profile, replace the underlying CI/security evidence, or expand the scope of any oracle. The attestation is a provenance and contract-conformance claim, not universal certification.

## Verification

After downloading one of the generated SVG subjects, verify it with the GitHub CLI:

```bash
gh attestation verify <artifact.svg> \
  --repo portyu9/portyu9 \
  --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json
```

A successful verification binds the artifact digest to the GitHub Actions workflow identity that created the attestation. The predicate should then be inspected for `sourceRevision`, validation scope, subject set, and authority boundary before making any broader inference.
