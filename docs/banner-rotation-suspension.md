# Profile banner rotation — reviewed artwork gate (2026-10-13)

This updates the historical October 13 **original-only suspension** to a
content-addressed, explicitly approved **eight-slot** UTC rotation. The
original-only hold remains the fallback for unapproved work.

## Slot map and source of truth

The canonical, immutable gate is `scripts/approved-banner-rotation-v3.json`.
The read-only `scripts/approved_banner_rotation.py` verifies every approved
asset's exact Git blob SHA, checks responsive SVG and reduced-motion contracts,
enforces a single HTML hero and footer image per surface, and rejects malformed
README markers and any unapproved asset path.

| Slot | State | Rendered artwork |
| --- | --- | --- |
| 1 | Approved | Original Quantum Apex desktop/mobile and Evidence Horizon footer |
| 2 | Approved | Fractal Iris desktop/mobile/closing horizon, **without under-iris shadow** |
| 3–8 | Reserved | Original triplet only, until reviewed artwork is approved per slot |

Slot 1 begins **2026-10-12 UTC**, slot 2 is **2026-10-13 UTC**, and each
subsequent UTC day advances one slot (modulo eight). This makes slot 2 a
fixed, predictable eight-day recurrence. Reserved slots deliberately fall
back to the original artwork and cannot use archived experimental themes.

The approved Fractal Iris is rendered as **three self-contained SVGs**
under `assets/profile-banners/approved/`, each with the exact same real
motion and light-response system, with viewports adapted to its destination:

- `02-fractal-iris-top.svg`: 1280×258 desktop hero.
- `02-fractal-iris-top-compact.svg`: center-cropped 640×196 mobile hero.
- `02-fractal-iris-bottom.svg`: centered/cropped 1280×150 footer.

The previous seven experimental daily themes and all 21 prior SVGs in
`assets/profile-banners/daily/` are **preserved for historical review**,
not automatically promoted into this new approval catalog. The former
`scripts/banner_rotation.py`, V1/V2 manifests, code and tests remain
archival validation tools and are **not production publishers**.

## Protected atomic publication

The only production daily writer is the existing guarded Spotlight README
automation. Its content-addressed source delegate now verifies the separate
V3 helper and catalog as well as the archived V2 helper, then derives the
current calendar day in UTC, validates the current README marker and all
three referenced images, and proposes exactly one monotonic, replay-safe
`README.md` candidate with a matching day/slot/slug marker.

The Spotlight workflow's independent exact-head branch/PR/commit/readme
authorization, standing bot approval and required CI gates remain in force.
Manual content mutation that bypasses those controls is **not authorized**.
Before merging any protected publisher source change, the exact trusted-source
capability expansion must receive a separately merged prior ledger
authorization. The bot can merge only its own content-addressed README-only
candidate. No direct main push, workflow permission expansion, or bypass is
introduced.

## Assurance and quality gate

`python3 scripts/approved_banner_rotation.py --check` validates pinned
original and Fractal Iris blobs; `--self-test` checks slot continuity,
archive fallback, leap/year boundaries, replay safety, and malicious
unapproved asset rejection. `scripts/validate-profile-v4.py` executes both
historical archive checks and the new approved-only checks.

Real GitHub rendering on desktop and mobile, image loading, footer crop and
browser playback remain separate visual checks. The accepted Fractal Iris
experiment and the seven archived concept assets are never deleted.
