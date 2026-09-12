# Engineering attestation contract

My profile treats generated evidence as a supply-chain artifact rather than decorative output.

My production profile workflow separates seven relevant authorities:

1. `generate-read-only` collects GitHub evidence and applies repository-defined transformation and validation contracts with `contents: read` only.
2. `prepare-attestation-read-only` downloads the immutable validated artifacts into a fresh read-only job, revalidates them, computes the scheduled-delta decision, builds the reviewed predicate, and uploads that predicate as a short-lived workflow artifact. It has `contents: read` only and no OIDC or attestation-write authority.
3. `attest-write-only` owns the short-lived Sigstore-backed evidence-signing authority. It has `contents: read`, `id-token: write`, and `attestations: write`, but no repository-content write permission. It performs only four digest-checked `actions/download-artifact` transports and one pinned `actions/attest` invocation: no checkout, no setup-python, no repository-authored shell, no repository-authored Python, and no alternate GitHub/network client.
4. `stage-publication-read-only` independently downloads and revalidates the evidence, constructs the exact generated-tree candidate, and seals that candidate into one Git bundle with `contents: read` only.
5. `publish-write-only` may update only the generated artifact branch after generation, read-only attestation preparation, terminal evidence attestation, and publication staging have all succeeded. It has no OIDC or attestation-write authority. After the push it re-proves that remote `generated` equals the exact candidate and emits the actual published commit, parent, and source identities.
6. `prepare-publication-receipt-read-only` independently re-proves the actual published `generated` commit and its one parent, bot commit identity, live remote head, source revision, lease/candidate identity, and reviewed evidence predicate. It computes SHA-256 over the canonical Git commit object bytes and builds one deterministic post-publication receipt predicate with `contents: read` only.
7. `attest-publication-receipt-write-only` owns only the second OIDC/attestation capability. It has `contents: read`, `id-token: write`, and `attestations: write`, no repository-content or Actions-write permission, and signs the canonical Git-object SHA-256 only after digest-checking the prepared receipt predicate.

The third-party Signal Field generator therefore never receives repository write or attestation authority. Repository-authored validation/predicate code never executes in either OIDC-capable signer, and `publish-write-only` never receives OIDC/attestation authority. Post-publication Spotlight reconciliation remains a separate Actions-write-only dispatcher and cannot run until `attest-publication-receipt-write-only` succeeds under the same short-lived transaction lease.

## Predicate schema versioning

Current evidence attestations use the immutable **v3** predicate type:

`https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json`

`profile-evidence-v3.schema.json` fixes the exact eleven published subject paths, exact validator sets, authority strings, claim boundary, Portfolio Evidence Ledger v2 identity, and its explicit evidence semantics. Every v3 predicate records `predicateSchema.id` plus `predicateSchema.digest`, the SHA-256 digest of the exact schema bytes used by the builder.

All issued evidence-predicate schema versions are **frozen byte-for-byte**, including the currently issued v3 contract:

- `profile-evidence-v3.schema.json` is the current immutable contract for Portfolio Evidence Ledger v2 and the exact eleven-subject set.
- `profile-evidence-v2.schema.json` verifies the prior Portfolio Evidence Ledger v1 / `PL1-` contract.
- `profile-evidence-v1.schema.json` verifies the original historical predicate contract.

Production no longer issues v1 or v2 evidence predicates. A published evidence-predicate schema is never edited to describe a later contract; any semantic change requires a new schema version and predicate type.

Historical evidence-predicate types:

- `https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v2.schema.json`
- `https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json`

## Post-publication generated commit receipt

The pre-publication v3 evidence attestation proves the reviewed evidence inputs and validation contract. The separate post-publication receipt proves which Git commit actually became the `generated` head after the terminal push succeeded. Its predicate type is:

`https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/generated-publication-receipt-v1.schema.json`

`generated-publication-receipt-v1.schema.json` is fail-closed around repository/workflow identity, source epoch, transaction identity, publication topology, the exact eleven-subject evidence set, and the bounded receipt claim. `scripts/build-generated-publication-receipt.py` derives the subject inventory from `profile-evidence-subjects-v1` and rejects a profile predicate whose published paths do not equal that canonical contract.

The receipt is intentionally about the **actual published Git commit**, not a staged candidate or GitHub API JSON serialization. `prepare-publication-receipt-read-only` checks that the checked-out commit equals the publisher's emitted commit SHA, has exactly one parent equal to the sealed publication base, retains the reviewed bot author/committer/message identity, and is still the live remote `generated` head. It then reconstructs the canonical Git object as `commit <payload-size>\0<payload>`, proves the repository-native SHA-1 Git OID over those exact bytes, and computes the independent SHA-256 subject digest over the same canonical Git object.

The deterministic receipt predicate binds:

- the native published commit SHA and exact parent SHA;
- the canonical Git-object SHA-256 used as the custom attestation subject digest;
- exact source `main` SHA plus `profile-stats-source-epoch-v1` algorithm, file count, and closure SHA-256;
- exact workflow run ID and run attempt;
- exact short-lived mutation lease ID and deterministic Profile Stats candidate ID;
- the reviewed profile-evidence predicate SHA-256;
- `profile-evidence-subjects-v1` plus SHA-256 for each of the exact eleven published subjects; and
- its own receipt-schema identity and SHA-256.

Publication and receipt signing remain deliberately separated. `publish-write-only` has `contents: write` but no OIDC/attestation authority. `prepare-publication-receipt-read-only` has only `contents: read`. `attest-publication-receipt-write-only` has OIDC/attestation authority but no `contents: write`, Actions-write, checkout, setup-Python, repository-authored Python, Git, or `gh` surface. It consumes one digest-checked receipt artifact and invokes the already-reviewed pinned `actions/attest` custom-attestation mode with subject name `portyu9/portyu9:generated@<commit-sha>` and subject digest `sha256:<canonical-git-object-sha256>`.

The receipt does not grant promotion or merge authority and is not an Automation Decision Receipt. It is a post-publication provenance receipt for the actual generated commit. Spotlight dispatch is downstream of successful receipt signing so a publication that cannot be receipted does not automatically advance into README promotion.

## Attested subjects

One evidence attestation covers the eleven files that make up the generated profile-evidence set: ten SVG presentation subjects plus the machine-readable Portfolio Evidence Ledger.

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

The canonical source for that inventory is `scripts/profile-evidence-subjects-v1.json`. Its `profile-evidence-subjects-v1` contract defines the exact published paths, the three evidence groups, the attestation patterns that must resolve only to those paths, and the internal-only Spotlight manifest. The evidence-predicate builder derives `subjectSet.publishedPaths` from this contract rather than maintaining another subject list; the post-publication receipt builder derives its per-subject receipt records from the same contract.

`validate-profile-evidence-subjects.py` closes the remaining subject boundaries: it requires the frozen v3 schema array to equal the canonical contract, requires the production evidence `actions/attest` patterns to resolve to the same paths, validates candidate inventories, and verifies that the staged `generated` tree contains exactly those eleven files. `stage-profile-evidence.py` uses the same contract for scheduled-delta comparison and final publication staging, eliminating independent shell copies and manual file counts.

## Canonical validation boundary

`scripts/profile-evidence-validation-boundary-v1.json` is the versioned `profile-evidence-validation-boundary-v1` contract for candidate evidence revalidation. It owns the exact read-only validator order, live-evidence flags, predicate validator identities, and the frozen semantic boundary name `attest-validated-evidence`. That boundary string remains part of the immutable v3 evidence-predicate contract even though evidence-attestation workflow authority is split into `prepare-attestation-read-only` and `attest-write-only`. `profile_evidence_validation.py` loads the contract, and `validate-profile-evidence-boundary.py` executes its six ordered stages.

Both `prepare-attestation-read-only` and `stage-publication-read-only` invoke `validate-profile-evidence-boundary.py` instead of maintaining separate copies of Signal Field, Portfolio Ledger, Spotlight, and subject-closure commands. The v3 evidence-predicate builder derives its `validation.signalField`, `validation.engineeringSpotlight`, `validation.portfolioEvidenceLedger`, and `validation.boundary` values from the same contract. The immutable v3 schema bytes remain unchanged; the attestation contract validator requires the frozen schema's validator arrays to equal the canonical boundary contract.

The terminal `attest-write-only` job does not re-run repository-authored validators. It consumes the already reviewed evidence predicate plus the same three immutable evidence artifacts through four independent digest-checked workflow-artifact downloads, then invokes only pinned `actions/attest`. This deliberately separates predicate/subject computation from the OIDC capability that can issue the evidence attestation.

This does not weaken publication validation. `stage-publication-read-only` independently downloads and revalidates the same evidence before constructing the exact generated candidate, while publication cannot begin until `attest-write-only` succeeds. After publication, the separate receipt boundary independently binds the actual pushed commit back to the same reviewed evidence predicate, source epoch, transaction lease/candidate, and exact eleven-subject inventory before Spotlight dispatch can proceed.

`engineering-spotlight/spotlight-manifest.json` is internal generation/validation metadata. It remains inside the immutable workflow artifact long enough for the Spotlight validator to prove manifest/SVG provenance agreement, but it is deliberately excluded from the public `generated` branch and from the evidence-attestation glob. The published generated evidence set is therefore **exactly the same eleven subjects** named by the evidence-attestation and post-publication receipt contracts.

The v3 evidence predicate records the exact source revision, workflow/run identity, predicate-schema identity/digest, published subject paths, validators, Signal Field Evidence ID, Portfolio Evidence Ledger v2 identity and evidence semantics, and the authority separation under which the evidence was produced. The receipt predicate then binds those reviewed semantics to the actual published commit object without claiming a new validation result.

## Signal Field Evidence ID

Every generated Signal Field variant carries the same deterministic **Signal Field Evidence ID** in the form `SF1-XXXXXXXXXXXXXXXX` plus the complete SHA-256 evidence digest.

The ID uses the `signal-field-evidence-v1` canonical evidence schema. It is derived from measured evidence semantics rather than SVG bytes: exact profile contribution period/total, headline metrics, the measured 30-day date/count/level sequence, activity telemetry, and source/timezone/intensity semantics. Light/dark and wide/compact presentation differences therefore share one identity when they represent the same evidence.

The short visible ID is the first 64 bits of the complete canonical SHA-256 digest. The full digest remains in each SVG's provenance and is copied into the signed evidence-attestation predicate as `signalFieldEvidence.digest`. Verification should use the complete digest and attestation; the short ID is a human correlation handle, not a replacement for cryptographic verification.

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

Every generated Ledger v2 carries a deterministic Portfolio Evidence ID in the form `PL2-XXXXXXXXXXXXXXXX` plus the full canonical SHA-256 digest. The v3 evidence predicate records that identity as `portfolioEvidenceLedger.id` and `portfolioEvidenceLedger.digest`, binds `portfolioEvidenceLedger.semantics` to `execution-result-subject-binding-freshness-v1`, and records the exact 13-system count. The ledger is published at `portfolio-evidence/portfolio-evidence-ledger.json` on the generated artifact branch.

As with the Signal Field ID, the short `PL2-` handle is for correlation. The complete digest and GitHub evidence attestation are the cryptographic verification surfaces; the publication receipt adds a separate cryptographic binding from that reviewed evidence identity to the actual generated Git commit.

## Claim boundary

The evidence attestation establishes that the named generated artifacts passed my repository-defined validators at the recorded source revision before publication and that GitHub can verify the workflow identity that issued the attestation. The post-publication receipt separately establishes that the actual `generated` Git commit/parent and canonical Git-object digest were bound to that reviewed evidence/source-epoch/transaction identity after publication.

Neither attestation **certifies every software behavior** represented by my profile, replaces the underlying CI/security evidence, or expands the scope of any oracle. The evidence attestation is a provenance and contract-conformance claim, **not universal certification**. The publication receipt is a provenance binding, not a second validation result or merge authorization.

## Verification

After downloading any newly generated evidence subject, verify it with the GitHub CLI using the current v3 evidence-predicate type. For an SVG:

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

A successful evidence verification binds the artifact digest to the GitHub Actions workflow identity that created the attestation. For v3, inspect `sourceRevision`, `predicateSchema.id`, `predicateSchema.digest`, `signalFieldEvidence.id`, `signalFieldEvidence.digest`, `portfolioEvidenceLedger.version`, `portfolioEvidenceLedger.semantics`, `portfolioEvidenceLedger.id`, `portfolioEvidenceLedger.digest`, validation scope, subject set, and authority boundary before making any broader inference. The recorded `predicateSchema.digest` should equal the SHA-256 digest of the immutable v3 schema bytes used for that run.

The post-publication receipt is a custom attestation whose subject name identifies `generated@<commit-sha>` and whose subject digest is the SHA-256 of the canonical Git object, not the SHA-1 Git OID. When inspecting that receipt, verify the `generated-publication-receipt-v1.schema.json` predicate type and correlate `publication.commitSha`, `publication.parentSha`, `publication.gitObjectSha256`, `source.revision`, `source.epoch.closureSha256`, `transaction.leaseId`, `transaction.candidateId`, `run.id`, `run.attempt`, `evidence.profileEvidencePredicateSha256`, and every per-subject digest before treating it as the publication receipt for that generated commit.

Historical v1 and v2 evidence attestations remain verifiable with their frozen predicate types. The existence of those legacy verification paths does not authorize new v1/v2 evidence attestations or edits to either historical schema.
