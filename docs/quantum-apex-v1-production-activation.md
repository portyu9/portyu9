# Production activation: accepted Quantum Apex Photonic Depth V1

**Status:** Proposed owner-requested production activation. The guarded Spotlight
publisher must be authorized and must publish a README-only bot PR before the
GitHub profile reflects the new triplet. This document is not publication evidence.

## Why merging PR #1771 did not change the profile

PR #1771 merged three *review* SVGs and an assurance script without changing
production pinning or `README.md`. Today (2026-10-18 UTC), the accepted
`<!-- banner-rotation:v4 ... slot=1 slug=01-original-quantum-apex -->`
marker explicitly selects the original 2026-10-12 SVGs. As expected, the
old protected renderer could not activate the review assets.

## Exact new production images

| Surface | Approved V1 path | Git blob |
| --- | --- | --- |
| Wide hero | `assets/profile-banners/approved/01-quantum-apex-photonic-depth-top.svg` | `4d783a9f32cc747e50db36312f8ae6d1894403f2` |
| Compact hero | `assets/profile-banners/approved/01-quantum-apex-photonic-depth-top-compact.svg` | `39f6298bfece3ef19ec8496a907869b7cecb2f59` |
| Closing evidence horizon | `assets/profile-banners/approved/01-quantum-apex-photonic-depth-bottom.svg` | `47c5b6cfce89a0ae1497749f1c5ef129f58739d5` |

The three SVGs are **byte-for-byte identical** to the V1 assets accepted in PR #1771;
their source files in `assets/profile-banners/review/` remain unchanged.

## Gate and rotation

- The new `scripts/approved-banner-rotation-v4.json` has the same eight-slot
  layout and the same date anchor as the previous `v3` catalog.
- Slot 1 becomes **01-photonic-depth**. Slots 2 (Fractal Iris) and 3
  (Chronohedron) and their immutable blobs stay unchanged; slots 4–8
  stay **reserved and unscheduled**.
- The selector emits **v5** README date markers. It explicitly recognizes
  legacy v3 and v4 date markers, proves them using the separately pinned,
  unchanged historical `scripts/approved-banner-rotation-v3.json`, and
  migrates them without day rollback or mismatched art.
- On the UTC day 2026-10-18, slot 1 is V1. On 2026-10-19, slot 2 is
  Fractal Iris; on 2026-10-20, slot 3 is Chronohedron; 2026-10-21
  returns to V1, then repeats every three UTC days.
- The daily sync is **best-effort**, not an exact midnight SLA.
  GitHub caches can delay browser visibility after the bot merges.
- The original `assets/profile-banners/quantum-apex-signal-crown-hero.svg`,
  `...-hero-compact.svg`, and `elite-evidence-horizon-bottom.svg` remain
  untouched, protected by the archived historical helper and blob hashes.
- V2 in **PR #1772** is strictly review-only and must remain **open/unmerged**.

## Guardrails for deployment

Only the existing protected Spotlight automation may publish the atomic
README-only candidate after the separately measured capability expansion
is authorized and merged. No direct `main` push, manual date-marker rewrite,
self-merge, ruleset bypass, workflow/permission change, or replacement of
the original assets is permitted. The active selector and manifests are
byte-for-byte pinned by the trusted Spotlight renderer.

Acceptance requires: the feature branch's selector self-test, actual
published README marker `banner-rotation:v5`, exactly three matching V1
approved asset URLs, an automatically reviewed/merged bot PR, and
browser-level observation. Passing source/CI checks alone is **not** proof
that the live profile has changed.
