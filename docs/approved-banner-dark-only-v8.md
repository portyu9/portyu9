# Approved Banner Rotation v8: Dark-Only Presentation

Status: Proposed (protected change)
Date: 2026-10-23

## Finding

The accepted four-slot UTC rotation has **no separate light SVG files**. The
Luminous Singularity triplet and Lagrange Tides V3 triplet each embedded
`prefers-color-scheme: light` CSS that selectively reduced glow, facets,
fog, scattering and fine-line opacity on light clients. Fractal Iris and
Chronohedron already had no color-scheme conditional rules.

## Decision

Introduce six new, content-addressed `*-dark-only.svg` assets from accepted
Quantum Apex V2 and Lagrange Tides V3, removing only light-mode media
blocks. Preserve the originals byte-for-byte in the immutable v6 catalog and
all review archives. Existing Fractal Iris and Chronohedron are unchanged.
All twelve active SVG surfaces prohibit color-scheme media queries, while
retaining SMIL animation, geometry, filter IDs, color palettes, dimensions,
title/description, mobile variants and `prefers-reduced-motion` behavior.

The new `approved-banner-rotation-v7.json` is a versioned artifact catalog;
the README publication marker advances from v7 to v8. The UTC epoch
2026-10-12, 86400-second period, order [1,2,3,4], reserved slots [5..8],
three-surface atomicity and original-only history are unchanged. Prior v7
README states remain verifiable against the exact immutable original v6
catalog and become valid inputs to the v8 publisher. The source emits no
unreviewed light-specific alternatives.

## Threat and regression boundary

- Verify exact Git blob identities for new six SVGs and the immutable
  original six; reject any theme-specific light CSS in active assets.
- Fail closed on legacy marker or asset mismatch and partial triplet
  replacement.
- Never edit unrelated badges, generated ledger, activity metrics,
  Spotlight receipts, or upstream test signals.
- Keep the reviewed bounded publisher and its protected PR admission.
  If trusted-source capability expands, demand exact prior authorization
  before release. Maintain current least-privilege source and checks.

The accepted original images remain accessible in Git history and as approved
assets. Dark-only files are new derivatives; no original artwork was deleted.
