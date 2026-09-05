# Engineering attestation contract

This profile treats generated evidence as a supply-chain artifact rather than decorative output.

The production profile workflow separates three authorities:

1. `generate-read-only` collects GitHub evidence and applies repository-defined transformation and validation contracts with `contents: read` only.
2. `attest-validated-evidence` downloads the immutable validated artifacts into a fresh job, revalidates them, and creates a GitHub artifact attestation using a short-lived Sigstore-backed workflow identity. This job has `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission.
3. `publish-write-only` may update only the generated artifact branch after generation and attestation have both succeeded. It revalidates the downloaded artifact set again before staging and publication.

The third-party Signal Field generator therefore never receives repository write or attestation authority, and the publication job never creates the attestation it relies on.

## Attested subjects

One attestation covers the eleven files that make up the generated profile-evidence set: ten SVG presentation subjects plus the machine-readable Portfolio Evidence Ledger.

- `profile-stats/profile/signal-field-wide-light.svg`
- `profile-stats/profile/signal-field-wide-dark.svg`
- `profile-stats/profile/signal-field-compact-light.svg`
- `profile-stats/profile/signal-field-compact-dark.svg`
- `engineering-spotlight/spotlight-1-light.svg`
- `engineering-spotlight/spotlight-1-dark.svg`
- `engineering-spotlight/spotlight-2-light.svg`
- `engineering-spotlight/spotlight-2-dark.svg`
- `engineering-spotlight/spotlight-3-light.svg`
- `engineering-spotlight/spotlight-3-dark.svg`
- `portfolio-evidence/portfolio-evidence-ledger.json`

`engineering-spotlight/spotlight-manifest.json` is internal generation/validation metadata. It remains inside the immutable workflow artifact long enough for the Spotlight validator to prove manifest/SVG provenance agreement, but it is deliberately excluded from the public `generated` branch. The published generated evidence set is therefore exactly the same eleven subjects named by the attestation contract.

The custom predicate type is:

`https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json`

The predicate records the exact source revision, workflow/run identity, published subject paths, validators, Signal Field Evidence ID, Portfolio Evidence Ledger identity, and the authority separation under which the evidence was produced.

## Signal Field Evidence ID

Every generated Signal Field variant carries the same deterministic **Signal Field Evidence ID** in the form `SF1-XXXXXXXXXXXXXXXX` plus the complete SHA-256 evidence digest.

The ID uses the `signal-field-evidence-v1` canonical evidence schema. It is derived from measured evidence semantics rather than SVG bytes: exact profile contribution period/total, headline metrics, the measured 30-day date/count/level sequence, activity telemetry, and source/timezone/intensity semantics. Light/dark and wide/compact presentation differences therefore share one identity when they represent the same evidence.

The short visible ID is the first 64 bits of the complete canonical SHA-256 digest. The full digest remains in each SVG's provenance and is copied into the signed attestation predicate as `signalFieldEvidence.digest`. Verification should use the complete digest and attestation; the short ID is a human correlation handle, not a replacement for cryptographic verification.

## Portfolio Evidence Ledger

The **Portfolio Evidence Ledger** is the machine-readable evidence surface for all **13 reviewed systems**: four permanent Selected Engineering Systems and nine systems eligible for Evidence Spotlight rotation.

Each ledger entry records the repository's current `main` revision, permanent/rotating classification, explicit evidence contract, exact workflow and run provenance, signal state, and UTC whole-day freshness. Agent Evaluation / TEVV retains its specialized job-and-step evidence model rather than being flattened into a generic workflow status.

Every generated ledger carries a deterministic Portfolio Evidence ID in the form `PL1-XXXXXXXXXXXXXXXX` plus the full canonical SHA-256 digest. The predicate records that identity as `portfolioEvidenceLedger.id` and `portfolioEvidenceLedger.digest`, along with the exact 13-system count. The ledger is published at `portfolio-evidence/portfolio-evidence-ledger.json` on the generated artifact branch.

As with the Signal Field ID, the short `PL1-` handle is for correlation. The complete digest and GitHub attestation are the cryptographic verification surfaces.

## Claim boundary

The attestation establishes that the named generated artifacts passed the repository-defined validators at the recorded source revision before publication and that GitHub can verify the workflow identity that issued the attestation.

It does **not** certify every software behavior represented by the profile, replace the underlying CI/security evidence, or expand the scope of any oracle. The attestation is a provenance and contract-conformance claim, not universal certification.

## Verification

After downloading any generated subject, verify it with the GitHub CLI. For an SVG:

```bash
gh attestation verify <artifact.svg> \
  --repo portyu9/portyu9 \
  --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json
```

The Portfolio Evidence Ledger can be verified the same way:

```bash
gh attestation verify portfolio-evidence-ledger.json \
  --repo portyu9/portyu9 \
  --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json
```

A successful verification binds the artifact digest to the GitHub Actions workflow identity that created the attestation. The predicate should then be inspected for `sourceRevision`, `signalFieldEvidence.id`, `signalFieldEvidence.digest`, `portfolioEvidenceLedger.id`, `portfolioEvidenceLedger.digest`, validation scope, subject set, and authority boundary before making any broader inference.
