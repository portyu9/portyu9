# Engineering attestation contract

This profile treats generated evidence as a supply-chain artifact rather than decorative output.

The production profile workflow separates three authorities:

1. `generate-read-only` collects GitHub evidence and applies repository-defined transformation and validation contracts with `contents: read` only.
2. `attest-validated-evidence` downloads the immutable validated artifacts into a fresh job, revalidates them, and creates a GitHub artifact attestation using a short-lived Sigstore-backed workflow identity. This job has `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission.
3. `publish-write-only` may update only the generated artifact branch after generation and attestation have both succeeded. It revalidates the downloaded artifact set again before staging and publication.

The third-party Signal Field generator therefore never receives repository write or attestation authority, and the publication job never creates the attestation it relies on.

## Predicate schema versioning

Current attestations use the immutable **v3** predicate type:

`https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json`

`profile-evidence-v3.schema.json` fixes the exact eleven published subject paths, exact validator sets, authority strings, claim boundary, Portfolio Evidence Ledger v2 identity, and its explicit evidence semantics. Every v3 predicate records `predicateSchema.id` plus `predicateSchema.digest`, the SHA-256 digest of the exact schema bytes used by the builder.

All issued predicate schema versions are **frozen byte-for-byte**, including the currently issued v3 contract:

- `profile-evidence-v3.schema.json` is the current immutable contract for Portfolio Evidence Ledger v2 and the exact eleven-subject set.
- `profile-evidence-v2.schema.json` verifies the prior Portfolio Evidence Ledger v1 / `PL1-` contract.
- `profile-evidence-v1.schema.json` verifies the original historical predicate contract.

Production no longer issues v1 or v2 predicates. A published predicate schema is never edited to describe a later contract; any semantic change requires a new schema version and predicate type.

Historical predicate types:

- `https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v2.schema.json`
- `https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json`

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

The canonical source for that inventory is `scripts/profile-evidence-subjects-v1.json`. Its `profile-evidence-subjects-v1` contract defines the exact published paths, the three evidence groups, the attestation patterns that must resolve only to those paths, and the internal-only Spotlight manifest. The predicate builder derives `subjectSet.publishedPaths` from this contract rather than maintaining another subject list.

`validate-profile-evidence-subjects.py` closes the remaining boundaries: it requires the frozen v3 schema array to equal the canonical contract, requires the production `actions/attest` patterns to resolve to the same paths, validates the downloaded candidate inventories before attestation and publication, and verifies that the staged `generated` tree contains exactly those eleven files. `stage-profile-evidence.py` uses the same contract for scheduled-delta comparison and final publication staging, eliminating independent shell copies and manual file counts.

`engineering-spotlight/spotlight-manifest.json` is internal generation/validation metadata. It remains inside the immutable workflow artifact long enough for the Spotlight validator to prove manifest/SVG provenance agreement, but it is deliberately excluded from the public `generated` branch and from the attestation glob. The published generated evidence set is therefore **exactly the same eleven subjects** named by the attestation contract.

The v3 predicate records the exact source revision, workflow/run identity, predicate-schema identity/digest, published subject paths, validators, Signal Field Evidence ID, Portfolio Evidence Ledger v2 identity and evidence semantics, and the authority separation under which the evidence was produced.

## Signal Field Evidence ID

Every generated Signal Field variant carries the same deterministic **Signal Field Evidence ID** in the form `SF1-XXXXXXXXXXXXXXXX` plus the complete SHA-256 evidence digest.

The ID uses the `signal-field-evidence-v1` canonical evidence schema. It is derived from measured evidence semantics rather than SVG bytes: exact profile contribution period/total, headline metrics, the measured 30-day date/count/level sequence, activity telemetry, and source/timezone/intensity semantics. Light/dark and wide/compact presentation differences therefore share one identity when they represent the same evidence.

The short visible ID is the first 64 bits of the complete canonical SHA-256 digest. The full digest remains in each SVG's provenance and is copied into the signed attestation predicate as `signalFieldEvidence.digest`. Verification should use the complete digest and attestation; the short ID is a human correlation handle, not a replacement for cryptographic verification.

## Portfolio Evidence Ledger v2

The **Portfolio Evidence Ledger v2** is the machine-readable evidence surface for all **13 reviewed systems**: four permanent Selected Engineering Systems and nine systems eligible for Evidence Spotlight rotation.

Ledger v2 uses the explicit evidence semantics identifier:

`execution-result-subject-binding-freshness-v1`

Each evidence record separates three independent facts:

- **execution result** — what the named workflow/job/step scope actually concluded (`PASSING`, `FAILING`, `RUNNING`, and other bounded result states);
- **subject binding** — whether that run head is the current `main` subject (`CURRENT_SUBJECT`, `DIFFERENT_SUBJECT`, or an explicit unavailable state);
- **freshness** — whether a usable UTC timestamp exists and its whole-day age (`SAME_DAY`, `AGED`, or an explicit unavailable/synthetic state).

A successful run on a different revision therefore remains a successful execution result while separately carrying `DIFFERENT_SUBJECT`. Binding mismatch no longer destroys or rewrites the observed result as `STALE`. Publication still fails closed under `--require-live` unless the evidence is bound to the current subject; separation improves attribution without weakening the current-main trust boundary.

Agent Evaluation / TEVV retains its specialized job-and-step evidence model rather than being flattened into a generic workflow status. Engineering Spotlight performs no second live evidence collection: it projects the exact Ledger v2 subject, contract, result, binding, freshness, and run provenance for the three deterministic rotating slots.

Every generated Ledger v2 carries a deterministic Portfolio Evidence ID in the form `PL2-XXXXXXXXXXXXXXXX` plus the full canonical SHA-256 digest. The v3 predicate records that identity as `portfolioEvidenceLedger.id` and `portfolioEvidenceLedger.digest`, binds `portfolioEvidenceLedger.semantics` to `execution-result-subject-binding-freshness-v1`, and records the exact 13-system count. The ledger is published at `portfolio-evidence/portfolio-evidence-ledger.json` on the generated artifact branch.

As with the Signal Field ID, the short `PL2-` handle is for correlation. The complete digest and GitHub attestation are the cryptographic verification surfaces.

## Claim boundary

The attestation establishes that the named generated artifacts passed the repository-defined validators at the recorded source revision before publication and that GitHub can verify the workflow identity that issued the attestation.

It does **not** certify every software behavior represented by the profile, replace the underlying CI/security evidence, or expand the scope of any oracle. The attestation is a provenance and contract-conformance claim, **not universal certification**.

## Verification

After downloading any newly generated subject, verify it with the GitHub CLI using the current v3 predicate type. For an SVG:

```bash
gh attestation verify <artifact.svg> \
  --repo portyu9/portyu9 \
  --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json
```

The Portfolio Evidence Ledger can be verified the same way:

```bash
gh attestation verify portfolio-evidence-ledger.json \
  --repo portyu9/portyu9 \
  --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json
```

A successful verification binds the artifact digest to the GitHub Actions workflow identity that created the attestation. For v3, inspect `sourceRevision`, `predicateSchema.id`, `predicateSchema.digest`, `signalFieldEvidence.id`, `signalFieldEvidence.digest`, `portfolioEvidenceLedger.version`, `portfolioEvidenceLedger.semantics`, `portfolioEvidenceLedger.id`, `portfolioEvidenceLedger.digest`, validation scope, subject set, and authority boundary before making any broader inference. The recorded `predicateSchema.digest` should equal the SHA-256 digest of the immutable v3 schema bytes used for that run.

Historical v1 and v2 attestations remain verifiable with their frozen predicate types. The existence of those legacy verification paths does not authorize new v1/v2 attestations or edits to either historical schema.
