# Latest approved profile art must be what the profile rotation serves

## Invariant

When the owner approves a banner upgrade **and** requests deployment,
**merging review artwork is not deployment**. The accepted content-addressed
production catalog, guarded Spotlight selector, exact source pinning, and
separately approved **README-only bot publication** must complete. After
publishing, read the three actual banner paths in `main/README.md` and
verify all three bytes against the currently approved manifest. Do not report
the version as live before the last verification.

This revision corrects the repeated confusion where Lagrange Tides V2 and
V3 existed only under `assets/profile-banners/review/`, while slot 4 still
selected accepted V1 in the production four-day rotation.

## Accepted source lineage

- Tides V1 PR #1777: desktop `be373e0a4b601ae4f136797e2ddb96ea519d8f36`,
  mobile `34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1`, bottom
  `8b8719635237cc9bbb785bd2dc20d38479a0a009`.
- Tides V2 PR #1783 merged as
  `943e0d9870e16fe0cf9820314ad78a065dc8ca49`: desktop
  `87507b866caf359a6c3edfc76c06ad97f539ddc5`, mobile
  `e7234689af9d29767fc8f6f1b7c0b9cddb14f874`, bottom
  `57aae2dd4919fc9ffdf848dd85eb4d0bcc659bf4`.
- Tides V3 owner-approved PR #1784 merged as
  `d6af2dc0201fe962c17a35931404f092a002fb3e`: desktop
  `ef87051144ccb9717e451045b4cb015e614e2360`, mobile
  `d382ff8e113aaccda0c1a43a1ea729302d5a994c`, bottom
  `30ba13c09b9cae8dacd7d1a1543f8ce557341bc6`.
- All approved V1 and review V2/V3 art are preserved under separate
  immutable paths. **No older content is destructively overwritten**.
  Selecting latest V3 replaces the production *reference*, not accepted
  historical source data.

## New production choice

- The **four-day epoch remains 2026-10-12 UTC**:
  slots 1 Quantum Apex V2, 2 Fractal Iris, 3 Chronohedron,
  4 **Lagrange Tides V3**. Slots 5-8 remain reserved.
- New immutable `scripts/approved-banner-rotation-v6.json` pins the
  exact three V3 Git blobs via
  `assets/profile-banners/approved/04-lagrange-tides-v3-kinetic-*.svg`.
  Accepted v3/v4/v5 catalogs remain *unaltered*. In particular, old v5
  catalogs can still prove already-published v6 README markers where
  slot 4 shows V1.
- `scripts/approved_banner_rotation.py` now selects latest V3 under
  **v7 marker**, while verifying all previously accepted v3/v4/v5/**v6**
  markers under their own historically pinned manifest. The same UTC
  day may be upgraded from slot 4 V1 to V3 atomically and idempotently,
  without bypassing rollback prevention or rewriting unrelated README.
- `scripts/spotlight_profile_links.py` pins the exact helper and **all
  four** historical/current approved catalogs before execution.
- `--check` validates exact blobs, accessible SVG XML, no remote
  resources, 16 spline-interpolated shape morphs, 17+ moving photons,
  11+ translations, proper moving depth-weave, reduced-motion and
  bounded filters for V3. `--self-test` verifies day/slot schedule,
  legacy replay, same-day v6 to v7 update, atomic three-surface output,
  rollback prevention and idempotency.

## Human acceptance and autonomous verification contract

The requested **"always apply latest version"** means an owner-approved
production promotion must never silently stop after merely merging a
review/gallery PR. The current catalog has explicit versioned source blobs
and has to be reauthorized for *every future art version*. The rotation
must never adopt an unapproved source by dynamic filename matching,
mutable `latest` aliases, newest-commit detection or unsecured workflow
shortcuts. This keeps the existing capability-admission governance intact.

Publication is verified only when the *merged main* README's
`<!-- banner-rotation:v7 ... -->` marker and all three image paths
correspond to the chosen slot from `approved-banner-rotation-v6.json`.
For October 19 UTC (slot 4), that means V3 for desktop/mobile/bottom;
October 20 UTC rotates to Quantum Apex V2 as before. Daily selector may
publish the following day if CI/governance extends across midnight.

## Protection, order, provenance

No direct main push, no modifying signed `generated`, no bypassing code
reviews, no permission expansion or unauthorized push. First freeze the
feature candidate HEAD/tree and measure its protected semantic expansion
using trusted accepted main on a read-only diagnostic PR. Obtain a
separate prior authorization ledger PR with exact observed expansion
fingerprint, merge authorization after required checks, integrate
authorized main into the feature without changing protected source bytes,
then merge feature after required checks. Finally allow ordinary governed
Spotlight bot to propose, approve and merge its **README-only** change.

At the lineage preflight, accepted main was
`d6af2dc0201fe962c17a35931404f092a002fb3e`. Exactly zero open
PRs; only main and independent signed
`generated@1140b616437ab94d9f7fb1d6a1795b3bd396961a`.
Historic unmerged #1637 `2e0ade0a1a073a824d77ebb599d89db453dd51d6`
and #1641 `d9ab4446aefc27b71662ba0aeee8aee2355e4438`
remain preserved, not silently promoted. Existing open Dependabot
zero-touch issue #1659 is independent; sensitive GHAS alert access is
not exposed by this connector.
