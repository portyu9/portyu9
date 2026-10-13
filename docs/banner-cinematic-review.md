# Cinematic seven-theme visual review

The images below link to **actual proposed SVG files**, not illustrative concepts. Production's original Quantum Apex/Evidence Horizon trio, eight-day schedule, catalog, README and protected publishing code remain untouched. **Review appearance before merge.**

## Orbital Relay

Interferometric orbit observatory with ion filaments and parallax phase rings.

**Wide top**

![Orbital Relay desktop](../assets/profile-banners/daily/01-orbital-relay-top.svg)

**Compact top**

![Orbital Relay mobile](../assets/profile-banners/daily/01-orbital-relay-top-compact.svg)

**Bottom**

![Orbital Relay closing horizon](../assets/profile-banners/daily/01-orbital-relay-bottom.svg)

## Prism Vault

Refractive crystalline chamber with deep faceting and animated optical scans.

**Wide top**

![Prism Vault desktop](../assets/profile-banners/daily/02-prism-vault-top.svg)

**Compact top**

![Prism Vault mobile](../assets/profile-banners/daily/02-prism-vault-top-compact.svg)

**Bottom**

![Prism Vault closing horizon](../assets/profile-banners/daily/02-prism-vault-bottom.svg)

## Neural Weave

High-density synaptic pathways, propagating impulses and luminous network nodes.

**Wide top**

![Neural Weave desktop](../assets/profile-banners/daily/03-neural-weave-top.svg)

**Compact top**

![Neural Weave mobile](../assets/profile-banners/daily/03-neural-weave-top-compact.svg)

**Bottom**

![Neural Weave closing horizon](../assets/profile-banners/daily/03-neural-weave-bottom.svg)

## Spectral Tides

Coherent interference bands, flowing ribbons and spectral signal trails.

**Wide top**

![Spectral Tides desktop](../assets/profile-banners/daily/04-spectral-tides-top.svg)

**Compact top**

![Spectral Tides mobile](../assets/profile-banners/daily/04-spectral-tides-top-compact.svg)

**Bottom**

![Spectral Tides closing horizon](../assets/profile-banners/daily/04-spectral-tides-bottom.svg)

## Fractal Iris

Curved plasma filaments around a dark, luminous energy aperture.

**Wide top**

![Fractal Iris desktop](../assets/profile-banners/daily/05-fractal-iris-top.svg)

**Compact top**

![Fractal Iris mobile](../assets/profile-banners/daily/05-fractal-iris-top-compact.svg)

**Bottom**

![Fractal Iris closing horizon](../assets/profile-banners/daily/05-fractal-iris-bottom.svg)

## Circuit Basilica

Architectural vanishing-point circuitry with traveling photonic packets.

**Wide top**

![Circuit Basilica desktop](../assets/profile-banners/daily/06-circuit-basilica-top.svg)

**Compact top**

![Circuit Basilica mobile](../assets/profile-banners/daily/06-circuit-basilica-top-compact.svg)

**Bottom**

![Circuit Basilica closing horizon](../assets/profile-banners/daily/06-circuit-basilica-bottom.svg)

## Singularity Mesh

Warped spacetime field around a glowing gravitational accretion torus.

**Wide top**

![Singularity Mesh desktop](../assets/profile-banners/daily/07-singularity-mesh-top.svg)

**Compact top**

![Singularity Mesh mobile](../assets/profile-banners/daily/07-singularity-mesh-top-compact.svg)

**Bottom**

![Singularity Mesh closing horizon](../assets/profile-banners/daily/07-singularity-mesh-bottom.svg)

## Review criteria

All 21 assets are deterministic and bounded to fewer than 30 KB each; no raster image, external resources, or embedded scripting. Only three accent animations over full static artwork per variant, with `prefers-reduced-motion` fallback and no whole-banner blur filters. Verify with `node scripts/generate-cinematic-banners.js --check` and `python3 scripts/banner_rotation.py --self-test` / `--check`. Also run full required PR CI. Real browser screenshots, GitHub-hosted animation playback, and frame-time benchmarks must be approved separately; source correctness alone is insufficient.
