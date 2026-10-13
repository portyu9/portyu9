# Chronohedron — concept 3 · living four-phosphor optical reactor

**Status: experimental owner visual review only.** This artwork is not approved for production and is not part of the eight-slot profile rotation. Slot 3 still falls back to the original artwork. This page documents the **current** design, not obsolete intermediate halo compositions.

## Review the real animated SVGs

| Surface | Viewport | Animation |
| --- | --- | --- |
| Wide desktop hero | 1280 × 258 | [Open actual SVG](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-top.svg) |
| Mobile hero | 640 × 196 center-crop | [Open actual SVG](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-top-compact.svg) |
| Footer horizon | 1280 × 150 | [Open actual SVG](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-bottom.svg) |

### Desktop reference

![Real Chronohedron wide SVG](previews/chronohedron-top.svg)

### Mobile crop

![Real Chronohedron compact SVG](previews/chronohedron-top-compact.svg)

### Footer crop

![Real Chronohedron footer SVG](previews/chronohedron-bottom.svg)

GitHub PR diff thumbnails are static and can show an earlier commit or stale cached frame. Use the immutable GitHub commit or current raw SVG links to review the current geometry and live motion in a browser. Source verification is not a measured-browser-FPS claim.

## Precise fixes following the user's screenshot

**The broad pale elliptical halo is removed—not merely faded.** The original huge rings were first reduced, but the screenshot showed they remained visually unacceptable. The current files remove both root-wide ovals, both internal decorative halo ovals, and their unused `night`, `haloIce` and `haloMagenta` gradient definitions. This retains the independent moving atmospheric plasma banks and active reactor without a giant translucent donut.

**All four sides of every banner are solid black, never transparent.** The outermost SVG declares `style="background-color:black"` and contains a literal opaque `<rect x="0" y="0" width="1280" height="258" fill="black" data-opaque-banner-backdrop="true"/>` underneath every visual group. It covers the complete native wide canvas; the cropped mobile and footer viewboxes fall within the same rect. No transparent gradient is used as a substitute for the background. A regression checker pins both the backing color and the paint order.

**The unnecessary yellow fading vertical swirl has been deleted**, along with the older purposeless set of fifteen center stripes. Instead, the four prism-cut reactor membranes brighten and subtly move on the exact phase and duration of the arriving profile-colored light. This replaces the hollow black central cutout with an energy-responsive cavity.

## The canonical four-color profile contract

The sole profile color source is `scripts/phosphor-lines-signal-field-v2.py` → `HEADER_COLORS["dark"]`. The scene must use **exactly**:

| Color | Canonical hex |
| --- | --- |
| Green | `#00FBCC` |
| Magenta | `#FF4DE1` |
| Violet | `#8C7CFF` |
| Cyan | `#28D7FF` |

Pure black is allowed **only** as the unlit canvas/neutral material negative space. No yellow, gold, orange, warm white, or other chromatic pigment. The validator reads the production Python theme definition via AST literal parsing and checks every SVG paint literal against that source—no duplicated hardcoded palette list in the artwork checker.

## The physics-inspired animation systems

- **Atmosphere:** Six independent, softly feathered plasma banks breathe and shift in a staggered, smooth, closed trajectory. These clouds survive the removal of the oversized halos.
- **Photonic delivery:** Fourteen traveling light-route highlights enter the reactor through actual Bézier guide geometry. Each tip and its supporting bloom follow the same normalized `pathLength="1000"` and seamless full-period `stroke-dashoffset` loop, not hard positional resets.
- **Beam-to-glass response:** Fourteen individual contact sites on the receptor facets illuminate as their corresponding supply lanes arrive, matching the exact incoming line period and phase.
- **Profile spectrum:** The four canonical phosphors each have moving routes along prismatic facet boundaries. Their color-specific impact caustics, incoming charge bundles and the four central glass membranes are linked to the same light routes rather than independently blinking.
- **Optical material:** The crystal contains clipped moving face sheens, static bounded dielectric microfracture, fine specular grain, mild chromatic separation, nested mechanical cages and localized moving contact glints. Filter definitions are static; blur/noise parameters do **not** animate.
- **Accessibility:** Every moving architecture, atmosphere, optical reflection and glass-impact group has a static counterpart for `prefers-reduced-motion: reduce`.

The three current SVGs have the **same actual art geometry**, with only viewbox, accessible title and surface metadata differing. Each is approximately 175 KB and contains 48 unique internal identifiers, 408 resolved paint references, 50 transform animations, and 118 other vector/brightness animations. High animation counts are structural facts, not proof of attractive or smooth playback.

## Regression assurance and release gate

Run `python3 experiments/validate_chronohedron_svg.py` to check responsive source parity, exact profile-only paint values, unique SVG IDs and reference validity, the exact timing of the four-phase reactor membranes, closed movement loops, matched reduced-motion fallbacks, bounded static noise, and the explicit **opaque black background/no pale halo** contract.

The source audit verifies structural SVG contracts but **does not establish native Firefox/LibreWolf/Safari/browser frame pacing**. To accept concept 3, the user must visually approve the actual desktop, mobile and footer animations first. **Do not merge this PR or enroll it in slot 3 yet.** The production profile, the approved Fractal Iris in slot 2, original banners, publisher and generated evidence branch are outside this experimental PR.


## Chronohedron VI — crystalline optics only (post-owner rejection of metal claws)

On the same non-draft, unmerged PR branch, the prior metallic/exoskeleton layer was entirely reverted first, with all five files restored to the exact original pre-hybrid Git blob SHAs from `baf74920431ebf336c9835aae36e33579d14ac07`. This alternative builds *inside* the original 188px-wide crystal silhouette: subdued polarized silica-glass planes, narrow beveled caustic reflections, internal fracture seams and four phase-matched internal illumination routes. All added visible geometry is clipped to the existing crystal outline. The luminous core, existing live membranes and 14 external feed/impact mechanisms remain unchanged; no new outer gimbals, bolts, clamps, giant ovals, or silhouette growth. The internal routes use the original four-phosphor source periods and phases with identical static counterparts. The under-185KB source budget and identical-scene, viewport-specific crop contract remain. Browser-rendered mobile/desktop/footer visual acceptance and live FPS measurements are outstanding. **No merge, no production rotation changes, no original Quantum Apex / Fractal Iris changes.**
