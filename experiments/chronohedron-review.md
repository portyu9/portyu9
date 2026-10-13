# Chronohedron — concept 3 kinetic crystal reactor

**Status: NEW VISUAL STUDY ONLY. Not approved or active in the profile's daily eight-slot rotation.** Its intended target is a future, separately authorized slot 3 only after owner visual acceptance. The current real slot 3 remains reserved and renders original Quantum Apex.

This visual is not a recolor, clone or reskin of the Fractal Iris. Its main silhouette is a transparent, deeply faceted six-sided suspended crystal around a glowing photonic energy cavity. Both sides are architectural optical waveguide arrays funneling through the crystal and across narrow cyan/amber grazing reflections. Independent polyhedral cages and layered inner faceting create a 3D-like parallax without turbulent filters or disruptive resets.

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

- **Living plasma volumes:** six large but feathered, independently breathing cyan and champagne-amber vapor banks, each moving on an asymmetric 22–37-second loop; their gradients are static, while only vector opacity and translation change.
- **Physically directional energy transport:** **14 optical supply routes** entering the reactor from the left and right, each with a soft aura stroke and bright core. Both components traverse the same Bézier path with a shared phase using a normalized `pathLength="1000"`, `stroke-dasharray="12 988"`, and the exact closed 0→−1000 linear dash offset. The path is continuous; the source is not flickered on/off randomly.
- **Energy has consequences:** fourteen small optical landing sites on the glass **flash as the corresponding beam arrives**. Their colors, exact durations and negative phase offsets are copied from the incident blue/amber energy channels. A delayed-peak envelope lights the facet near the end of each smooth guide traversal, then fades before the next arrival. These are causally synchronized light responses, not an unrelated sparkle loop. Static contact glints remain in reduced-motion mode.
- **A luminous central reactor:** dual cyan and amber heartbeats illuminate the cavity with distinct 9- and 11-second optical rhythms. There is real glowing radial structure instead of a single dark flat polygon.
- **True glass behavior:** six shifting, clipped color-dispersing facet sheens, added dielectric grain inside the transparent body, and ten tiny independently phased grazing caustics tracing the outer facets. Their motion does not spin the entire artwork.
- **Subtle engineering depth:** preserves the original 104 crystal facets, 14 existing eased mechanical/waveguide loops, original environmental perspective, orthogonal cage and lens anatomy. Rather than deleting those details, the new layers make them meaningfully visible.
- **No heavy animated filter:** two new **static** local bloom kernels and static optical gradients are reused. No animated turbulence frequency, blur radius or displacement values, no Javascript, no network dependencies. The beam paths do animate vector dash offset; browser/device frame pacing still requires genuine playback evaluation.

This revision has **38 closed transform loops** (14 pilot + 24 new moving groups), **14 continuously transporting energy routes** (28 synchronized core/bloom stroke-dash-offset animations), **14 phase-locked guide-to-glass impact reactions**, **25 geometry-mirrored reduced-motion optical groups**, and **14 independent static contact glints**. On `prefers-reduced-motion: reduce`, all new motion is hidden and substituted by its static counterpart without losing the glass detail. The SVG source is about **132 KB per view**, with identical artwork in all three responsive viewports. The accepted original Fractal Iris is a separate production artifact and is not modified here.

### What was verified, and what was not

A direct source audit of the **actual committed** desktop/mobile/footer SVGs passed: 37 unique internal identifiers, resolved paint references, correct nested SVG tags, closed 38 spline transforms, normalized 14 periodic light circuits and 14 co-timed glass contact reactions, identical normalized scene content across three crops, and motion/still group counts. The Python checker `python3 experiments/validate_chronohedron_svg.py` has been expanded to assert all these structural contracts, including phase coupling and no malformed or unapproved payloads. Independent browser-level 30/60 FPS measurements and your visual acceptance have **not** been performed or claimed.

## Assurance and isolation

Run `python3 experiments/validate_chronohedron_svg.py` to validate unique SVG IDs, balanced XML, matching geometry among all three crops, density thresholds, accessible titles and descriptions, 38 seamlessly closed transform loops, 14 traveling light circuits, 25 additional paired static fallbacks, zero external payloads and constrained geometry size.

**Approval gate:** This PR must stay open and unmerged until you approve the actual visual. No changes to the already approved Fractal Iris files, original Quantum Apex/Evidence Horizon assets, the eight-day selector, the generated evidence branch or the production README are permitted from this lane.
