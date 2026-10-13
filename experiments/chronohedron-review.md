# Chronohedron — concept 3 kinetic crystal reactor

**Status: NEW VISUAL STUDY ONLY. Not approved or active in the profile's daily eight-slot rotation.** Its intended target is a future, separately authorized slot 3 only after owner visual acceptance. The current real slot 3 remains reserved and renders original Quantum Apex.

This visual is not a recolor, clone or reskin of the Fractal Iris. Its main silhouette is a transparent, deeply faceted six-sided suspended crystal around a glowing photonic energy cavity. Both sides are architectural optical waveguide arrays funneling through the crystal and across narrow cyan/magenta grazing reflections. Independent polyhedral cages and layered inner faceting create a 3D-like parallax without turbulent filters or disruptive resets.

## Inspect actual committed SVG artwork

### Wide desktop — 1280 × 258

![Chronohedron wide crystalline reactor](previews/chronohedron-top.svg)

[Open actual SVG / raw browser playback](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-top.svg)

### Mobile center crop — 640 × 196

![Chronohedron compact](previews/chronohedron-top-compact.svg)

[Open actual compact SVG / raw browser playback](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-top-compact.svg)

### Footer horizon — 1280 × 150

![Chronohedron horizon](previews/chronohedron-bottom.svg)

[Open actual footer SVG / raw browser playback](https://raw.githubusercontent.com/portyu9/portyu9/feature/chronohedron-crystal-reactor-study-20261013/experiments/previews/chronohedron-bottom.svg)

GitHub's Markdown image proxy may freeze an SVG's SMIL animation. Open the raw link in an ordinary browser to assess real motion, lighting, device behavior and perceived depth.

## Volumetric light-response revision (2026-10-13)

The first Chronohedron pilot looked **static, low-contrast and synthetic**, despite using many geometry paths. The original 14 motion groups moved by only a few pixels, light did not physically traverse any circuitry, the glass did not brighten in response to its energy source, and there was almost no atmospheric depth. This PR now contains an actual **second-pass experimental animation**, rather than an aesthetic adjective applied to the original pilot.

**The main observable improvements:**

- **Living plasma volumes:** six large but feathered, independently breathing cyan and profile magenta vapor banks, each moving on an asymmetric 22–37-second loop; their gradients are static, while only vector opacity and translation change.
- **Physically directional energy transport:** **14 optical supply routes** entering the reactor from the left and right, each with a soft aura stroke and bright core. Both components traverse the same Bézier path with a shared phase using a normalized `pathLength="1000"`, `stroke-dasharray="12 988"`, and the exact closed 0→−1000 linear dash offset. The path is continuous; the source is not flickered on/off randomly.
- **Energy has consequences:** fourteen small optical landing sites on the glass **flash as the corresponding beam arrives**. Their colors, exact durations and negative phase offsets are copied from the incident blue/magenta energy channels. A delayed-peak envelope lights the facet near the end of each smooth guide traversal, then fades before the next arrival. These are causally synchronized light responses, not an unrelated sparkle loop. Static contact glints remain in reduced-motion mode.
- **A luminous central reactor:** dual cyan and magenta heartbeats illuminate the cavity with distinct 9- and 11-second optical rhythms. There is real glowing radial structure instead of a single dark flat polygon.
- **Spectrally layered dielectric glass:** beyond the moving faceted reflections, a small bounded **static** two-octave dielectric microstructure produces nonuniform refractive material grain inside the crystal, while blue/magenta subpixel-offset shell edges mimic subtle chromatic splitting. The noise seed and frequency are pinned by the regression checker, and no time-varying blur or turbulence parameters are permitted.
- **True glass behavior:** six shifting, clipped color-dispersing facet sheens, added dielectric grain inside the transparent body, and ten tiny independently phased grazing caustics tracing the outer facets. Their motion does not spin the entire artwork.
- **Subtle engineering depth:** preserves the original 104 crystal facets, 14 existing eased mechanical/waveguide loops, original environmental perspective, orthogonal cage and lens anatomy. Rather than deleting those details, the new layers make them meaningfully visible.
- **No heavy animated filter:** two new **static** local bloom kernels and static optical gradients are reused. No animated turbulence frequency, blur radius or displacement values, no Javascript, no network dependencies. The beam paths do animate vector dash offset; browser/device frame pacing still requires genuine playback evaluation.

The previous four-color pass had **42 closed transform loops** (14 pilot + 24 new moving groups), **14 continuously transporting energy routes** (28 synchronized core/bloom stroke-dash-offset animations), **14 phase-locked guide-to-glass impact reactions**, **25 geometry-mirrored reduced-motion optical groups**, and **14 independent static contact glints**. On `prefers-reduced-motion: reduce`, all new motion is hidden and substituted by its static counterpart without losing the glass detail. The earlier source was about **155 KB per view**, with identical artwork in all three responsive viewports. The accepted original Fractal Iris is a separate production artifact and is not modified here.

### What was verified, and what was not

The earlier four-color source audit passed; this latest revision increases it to **50** unique IDs, **397** paint references and **46** closed spline transforms, normalized 14 periodic light circuits and 14 co-timed glass contact reactions, identical normalized scene content across three crops, and motion/still group counts. The Python checker `python3 experiments/validate_chronohedron_svg.py` has been expanded to assert all these structural contracts, including phase coupling and no malformed or unapproved payloads. Independent browser-level 30/60 FPS measurements and your visual acceptance have **not** been performed or claimed.

## Fourth pass — reactive faceted chamber and controlled atmosphere

The owner-provided GitHub SVG screenshot exposed a serious composition issue: an enormous pale-looking ellipse dominated the hero and a near-black hollow center made the reactor look inert. The separate yellow central stroke had already been removed on the prior four-phosphor pass. This revision repairs the **remaining architectural cause** rather than simply adding more particles.

- **Replace the hollow center:** The old opaque-black inner polygon and its fifteen faint, curved, decorative stripes are gone. A prism-cut illuminated chamber now reveals energetic cyan/green/violet/magenta facets instead of an empty void.
- **Bind all four reactor membranes to incoming energy:** Green `8.6s/-1.8s`, cyan `12.6s/-4.6s`, violet `10.4s/-3.1s`, magenta `15.2s/-6.2s`. Each membrane's position and optical brightness pulse match its associated existing perimeter feed *exactly*, with closed cubic easing. Each has identical static source geometry for reduced-motion rendering.
- **Constrain the old ellipse:** The two former wide, fully intense halo ellipses (radii `340/280`) are now narrower (`248/215`) and restrained to `0.29/0.24` group opacity, allowing the fully drawn reactor to be the focal point. The six separately animated atmospheric plumes and their nuanced four-color glow remain.
- **Exact palette still enforced:** Only `#00FBCC`, `#FF4DE1`, `#8C7CFF`, `#28D7FF` as chromatic paints, with black reserved for unlit negative space. No amber, yellow, white, or unrelated RGB tones.
- **Regression controls:** The SVG now has 46 closed transform animations (42 existing + 4 reactor membranes) and 94 other animation elements, 50 unique IDs, and 397 resolved internal SVG paint references. Three complete responsive SVGs share the **exact same source body** with only viewport/title distinctions; each is about **159 KB**. A validator specifically fails on the old giant halos, black hollow cutout, or missing/cross-wired reactor membranes.

No rendering frame-rate benchmark or side-by-side real-browser photographic evidence was available; this is an implementation and source-structure result pending visual signoff. Still **no production enrollment** of concept 3.

## Profile-theme-only color and optical motion correction (owner review)

**Canonical profile theme source:** `scripts/phosphor-lines-signal-field-v2.py` → `HEADER_COLORS["dark"]`. The art has exactly these four chromatic values:

| Phosphor | Canonical profile color | Use in concept 3 |
| --- | --- | --- |
| Green | `#00FBCC` | Inbound luminous energy, faceted injections, edge caustics |
| Magenta | `#FF4DE1` | Reactive glass emissions and counterbalancing plasma |
| Violet | `#8C7CFF` | Refractive spectral facets, atmosphere, perimeter transmissions |
| Cyan | `#28D7FF` | Glass optics, transport circuits and the reactor core |

Black is used only as an unlit neutral background/negative space. **No yellow, orange, gold, white decorative pigment, or off-theme chromatic gradients remain.** This is enforced by the Python validator, which reads the actual palette from the production theme definition without executing it. The existing static dielectric texture matrix now outputs the canonical cyan color, rather than a separate approximate blue. All three SVG variants are sourced from identical art and differ only in viewport and accessibility title.

**Removed:** The yellow fading vertical swirl at the absolute center was specifically the `M641 79 Q661 108 648 132 T635 176` stroke inside the older dual-color reactor heartbeat, duplicated in its reduced-motion fallback. Both occurrences have been deleted; the central reactor retains luminous breathing/glass dispersion but no purposeless central ribbon.

**Added:** Four fast, internally routed `pathLength=1000` facet transmissions (one in each exact theme color), with matched soft bloom and sharp energized heads, continuous `stroke-dashoffset` loops and matching reduced-motion artwork. Four coordinated refractive caustic groups now respond along the crystal edges with the same phase and duration as their energy circuits, using smooth closed transforms and opacity envelopes. Total animation contracts now cover **42 spline transforms**, fourteen incoming energy channels, four additional chromatic facet channels, fourteen arrival reactions, four spectral edge responses and full static reduced-motion parity. The baseline atmospheric volumes, mechanical cage articulation, dielectric grain and large core breathing system remain; the design is still an experimental concept, not accepted artwork.

## Assurance and isolation

Run `python3 experiments/validate_chronohedron_svg.py` to validate unique SVG IDs, balanced XML, matching geometry among all three crops, density thresholds, accessible titles and descriptions, **46** seamlessly closed transform loops, 14 traveling light circuits, 25 original additional paired static fallbacks and four new reactor membrane fallbacks, zero external payloads and constrained geometry size.

**Approval gate:** This PR must stay open and unmerged until you approve the actual visual. No changes to the already approved Fractal Iris files, original Quantum Apex/Evidence Horizon assets, the eight-day selector, the generated evidence branch or the production README are permitted from this lane.
