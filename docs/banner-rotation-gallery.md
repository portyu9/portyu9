# Seven-day kinetic crown + evidence-horizon gallery

**Implementation branch:** `feature/seven-day-animated-banner-cycle-20261012` · **Source PR:** [#1632](https://github.com/portyu9/portyu9/pull/1632). This gallery is for review while the production publication path remains gated.

Each of the seven themes is a designed **triplet**, not a recoloring: wide desktop crown (`1280×258` viewBox), simplified compact mobile crown (`640×196`), and matching closing horizon (`1280×150`). All artworks are self-contained vector XML with SMIL motion, `prefers-reduced-motion` static fallbacks, low-kilobyte payloads, and the established aqua / magenta / green brand family.

**Selection invariant:** `floor(UTC unix seconds / 86400) modulo 7`. One UTC day chooses **one** scene for all three images. No per-visitor JavaScript, randomized selection, mutable index state, or local timezone assumptions.

**Publishing safety:** GitHub README rendering cannot inspect the date from embedded SVGs. The read-only `scripts/banner_rotation.py` computes a bounded, replay-safe README proposal; a separately authorized reviewer/merge workflow must apply it. This feature is **not production-active while #1632 remains open**. The existing signed `generated` evidence branch and the current top/footer assets must remain untouched until authorized integration.

## 01 · Orbital Relay

Interlocking phase-space rings, synchronized aperture signals.

**Wide crown**

![Orbital Relay wide](../assets/profile-banners/daily/01-orbital-relay-top.svg)

**Mobile crown**

![Orbital Relay compact](../assets/profile-banners/daily/01-orbital-relay-top-compact.svg)

**Closing horizon**

![Orbital Relay horizon](../assets/profile-banners/daily/01-orbital-relay-bottom.svg)

## 02 · Prism Vault

Nested trapezoidal perspective and optical depth lattice.

**Wide crown**

![Prism Vault wide](../assets/profile-banners/daily/02-prism-vault-top.svg)

**Mobile crown**

![Prism Vault compact](../assets/profile-banners/daily/02-prism-vault-top-compact.svg)

**Closing horizon**

![Prism Vault horizon](../assets/profile-banners/daily/02-prism-vault-bottom.svg)

## 03 · Neural Weave

Connected attribution nodes with pulsing evidence synapses.

**Wide crown**

![Neural Weave wide](../assets/profile-banners/daily/03-neural-weave-top.svg)

**Mobile crown**

![Neural Weave compact](../assets/profile-banners/daily/03-neural-weave-top-compact.svg)

**Closing horizon**

![Neural Weave horizon](../assets/profile-banners/daily/03-neural-weave-bottom.svg)

## 04 · Spectral Tides

Layered interference waves, spectrometer trace energy.

**Wide crown**

![Spectral Tides wide](../assets/profile-banners/daily/04-spectral-tides-top.svg)

**Mobile crown**

![Spectral Tides compact](../assets/profile-banners/daily/04-spectral-tides-top-compact.svg)

**Closing horizon**

![Spectral Tides horizon](../assets/profile-banners/daily/04-spectral-tides-bottom.svg)

## 05 · Fractal Iris

Radial crystalline blades around a rotating verification iris.

**Wide crown**

![Fractal Iris wide](../assets/profile-banners/daily/05-fractal-iris-top.svg)

**Mobile crown**

![Fractal Iris compact](../assets/profile-banners/daily/05-fractal-iris-top-compact.svg)

**Closing horizon**

![Fractal Iris horizon](../assets/profile-banners/daily/05-fractal-iris-bottom.svg)

## 06 · Circuit Basilica

Mirrored photonic circuitry and architectural port geometry.

**Wide crown**

![Circuit Basilica wide](../assets/profile-banners/daily/06-circuit-basilica-top.svg)

**Mobile crown**

![Circuit Basilica compact](../assets/profile-banners/daily/06-circuit-basilica-top-compact.svg)

**Closing horizon**

![Circuit Basilica horizon](../assets/profile-banners/daily/06-circuit-basilica-bottom.svg)

## 07 · Singularity Mesh

Warped gravitational field lines and an event horizon core.

**Wide crown**

![Singularity Mesh wide](../assets/profile-banners/daily/07-singularity-mesh-top.svg)

**Mobile crown**

![Singularity Mesh compact](../assets/profile-banners/daily/07-singularity-mesh-top-compact.svg)

**Closing horizon**

![Singularity Mesh horizon](../assets/profile-banners/daily/07-singularity-mesh-bottom.svg)

## Safety and rollout gates

- Preserve the canonical current README while the daily publisher is not yet authorized and validated.
- Reuse the existing governed, exact-head reviewed README-only Spotlight synchronization lane **only after** a separate prior authorization for its protected source, and expand its candidate semantics intentionally rather than smuggling unreviewed writes into the current channel. Alternatively provision a new narrowly bounded, authorized daily README lane with independent checks and no direct-main write.
- At every UTC calendar transition, validate the same scene slug in the top desktop, mobile compact, and bottom references; reject stale day/date rollback, duplicate/malformed markers, external image/script resource URLs, and unchecked animated payload growth.
- Retain a deterministic, identity-pinned candidate, full required CI, review, authorization receipt, and an auditable merged PR for the daily update; no silent self-merge or secrets in public SVGs.
- GitHub's scheduled Actions delivery is best-effort rather than an exact second-level clock. Document retries and delayed-run convergence; never claim an exactly midnight live switch without a 00:00 service-level guarantee.
- Test Safari, Firefox/LibreWolf, Android Chrome and mobile Safari at representative widths, plus light/dark and prefers-reduced-motion. CI validates structure and assets but does not substitute for these pixel-level captures.

### Local review commands

```bash
python3 scripts/banner_rotation.py --self-test
python3 scripts/banner_rotation.py --check
python3 scripts/banner_rotation.py --select --date 2026-10-12
python3 scripts/banner_rotation.py --propose --date 2026-10-12 > /tmp/banner-readme-proposal.md
python3 scripts/validate-profile-v4.py
```

The `--propose` command emits a candidate to stdout, **never writes README.md**. The emitted proposal is not an authorization to bypass protected review.
