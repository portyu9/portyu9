# Four-slot profile banner activation: accepted Quantum Apex V2 + Lagrange Tides V1

**Production deployment is subject to prior GitHub capability authorization, green
required checks, governed bot review, and an independently merged README-only
Spotlight publisher PR. The feature PR alone does not make images live.**

## What is genuinely accepted, what is merely present on main?

Quantum Apex **V2** was accepted as non-deploying artwork via #1772 and merged
`97699f02d6d4fd67148e4f612f7abbabd48174cc`. Source images are exact:
`f7cf024a8343f9904f63c314d5bc72f87e5049f7`,
`256a5315728bc0778d941df24ba3b860f5a67f3a`, and
`61419a4e18f055ca8843071402f37e9868812e5a`.
Earlier #1773 deployed **V1** in slot 1; thus V2 existed on main but *did
not appear on the live profile*. This PR corrects that explicit disparity.

Slot 4 Lagrange Tides V1 was accepted in #1777 and merged
`4d6eb6a8c79fd4c35b1eed375494c91a0d4bd176`; complete SVG blobs:
`be373e0a4b601ae4f136797e2ddb96ea519d8f36`,
`34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1`, and
`8b8719635237cc9bbb785bd2dc20d38479a0a009`.
Those images were not live before this proposed deployment.

## New exact-hash schedule

The eight-slot schema persists. Only slots 1–4 are approved; slots 5–8
remain reserved, never implicitly activated.

| Slot | Design | New state | Source |
| --- | --- | --- | --- |
| 1 | **Quantum Apex V2 — Luminous Singularity** | Approved | Exact six-figure reviewed SVGS via #1772 |
| 2 | Fractal Iris | Approved, unchanged | Previous immutable catalog |
| 3 | Chronohedron | Approved, unchanged | Previous immutable catalog |
| 4 | **Lagrange Tides V1** | Approved | Exact independently approved SVGS via #1777 |
| 5–8 | Reserved | Reserved | No artwork scheduled |

The existing UTC epoch **2026-10-12** is preserved. The selector uses
`(utc_day - epoch).days % 4`, without ad-hoc calendar special-cases.
The expected deterministic cycle is:

| UTC date | Slot | Visual |
| --- | --- | --- |
| October 19, 2026 | 4 | Lagrange Tides V1 |
| October 20, 2026 | 1 | Quantum Apex V2 |
| October 21, 2026 | 2 | Fractal Iris |
| October 22, 2026 | 3 | Chronohedron |
| October 23, 2026 | 4 | Lagrange Tides V1 |

GitHub's scheduled publisher runs eventually, not guaranteed at midnight;
the visible profile can lag due to review, CI, merger, cache or schedule.

## Exact source, replay and immutable lineage

- `scripts/approved-banner-rotation-v5.json` holds the new four-slot
  catalog and six immutable hashes. Never modify historical
  `scripts/approved-banner-rotation-v3.json` or `v4.json`.
- `scripts/approved_banner_rotation.py` now emits v6 README markers and
  accepts the old **v3**, **v4**, and **v5** markers only if they exactly match
  the corresponding immutable old schedule and complete three-surface assets.
  Any malformed marker/path pair, non-monotone UTC-day update, missing source
  asset, content hash drift, or unapproved slot must fail closed.
- `scripts/spotlight_profile_links.py` pins the source blob for the new
  selector as well as *all three* old and new approved catalogs **before
  executing/importing the selector**.
- New approved SVG files are byte-identical copies of the accepted review
  files and do not delete or overwrite V1 or the original crown/horizon.
- SVG validation checks exact title, description, role, responsive canvas,
  reduced-motion fallback, deterministic material texture, local resource
  references and no external active content. Independent existing Fractal
  Iris / Chronohedron validation is untouched.
- The critical business invariants are enforced in selector self-tests:
  strict four-slot day-by-day sequence; old v3/v4/v5 rollback-safe replay;
  October 19 slot 4; October 20 slot 1; subsequent cycle; positive idempotency;
  rejection of unauthorized archived artwork; all three surfaces always
  switch atomically; Spotlight card block stays untouched.

## Required approval workflow

The trusted Spotlight renderer is protected source. **No direct merge until
a separate read-only exact commit+tree measurement and accepted
authorization-ledger PR exist.** The new production feature PR must remain
frozen for that authorization fingerprint, then merge accepted ledger
main through a normal merge commit without changing any measured candidate
file. GitHub required checks must then pass against that final head.
The ordinary publisher's subsequent bot PR must modify only README and
be independently approved/attested and merged. Direct edits to README/main
or bypass of review/rulesets are forbidden.

A separate `automation/spotlight-links/` bot PR (#1778) was open at
the lineage preflight because the new UTC day had begun. It is a valid
old three-slot README-only publication; its content must be preserved
in main or reconciled through the immutable old-version marker parser,
**never overwritten or force-closed merely to accelerate this rollout**.

## Branch provenance and salvage

Accepted main at feature branch creation:
`4d6eb6a8c79fd4c35b1eed375494c91a0d4bd176`.
Signed `generated` head:
`1140b616437ab94d9f7fb1d6a1795b3bd396961a` untouched.
Closed unmerged #1637 at
`2e0ade0a1a073a824d77ebb599d89db453dd51d6` and #1641 at
`d9ab4446aefc27b71662ba0aeee8aee2355e4438` remain archival and
are **not** quietly adopted. The unrelated open Dependabot automation
issue #1659 remains out of scope; GHAS alert-level introspection is
unavailable to the current connector.
