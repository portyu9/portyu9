# Profile asset policy

My profile hero is intentionally stored at `quality-engineering-automation-systems.png` as a reviewed, size-bounded PNG fallback.

## Current optimized fallback

- Canvas: `1280 × 854`
- Size: `1,472,916` bytes (1.473 MB decimal / 1.405 MiB)
- SHA-256: `d840734c78ec59f3c53644330bc2166c51e1bb5eb8e768595035a37767eb5452`
- Git blob: `8415380b255d8f24a1c2152a029e50b69c91ec3d`

This is a roughly 50% payload reduction from the previous reviewed `1535 × 1024`, `2,947,658`-byte fallback. The candidate was produced from that exact prior image with Lanczos downscaling, metadata stripping, and PNG compression; it was not redrawn or regenerated.

The isolated measurement run `37142059806` compared bounded candidates before replacement. The selected 1280px candidate was `1,472,916` bytes and measured PSNR `33.3112 dB` after deterministic restoration to the former canvas for comparison. Manual visual inspection confirmed that the hero composition, text, and primary detail remain readable at README hero scale. The finalizer then required the exact measured candidate SHA-256, byte count, and `1280 × 854` geometry before replacing the fallback.

## Current optimized animated source

The active README source is now `quality-engineering-automation-systems-nebula-portal-animated-v2-optimized.svg`. The animation/vector shell is unchanged; only the embedded raster base and cache identity changed.

The previous active SVG was `2,727,295` bytes. Its single embedded `4605 × 3072` WebP was `2,024,838` bytes across 14,146,560 decoded pixels, and its base64 text accounted for 98.99% of the SVG source. The animation markup itself was only about 27.5 KB.

Isolated measurement run `37810174181` used the pinned GitHub runner's Chromium 154 canvas/WebP encoder to compare bounded candidates against that exact embedded base on the canonical `1535 × 1024` comparison canvas. The selected candidate is:

- Embedded WebP: `2560 × 1708`
- WebP bytes: `372,702`
- WebP SHA-256: `fcb9d112ff3447ef1671e58be169051ddde0dd83016b88386cf4a3f2e39c7824`
- Comparison PSNR: `37.115736 dB`
- Final self-contained SVG: `524,447` bytes
- Final SVG SHA-256: `b7a6bb60e85e6304a2e561849174bd305ed73d25848e886ea83df753baa7a5d3`
- Git blob: `6621e4d74a8caf1fb52683df83f5418e167fe009`

That cuts the complete SVG payload by 80.77%, the embedded WebP bytes by 81.59%, and embedded decoded pixels by 69.09%. The reviewed animation inventory remains exactly 86 `<animate>`, 22 `<animateTransform>`, and 14 `<animateMotion>` elements (122 total), including the existing reduced-motion behavior and atmospheric/glow filter system. A normalized vector/animation-shell digest is pinned separately so raster optimization cannot silently mutate motion geometry.

The new filename is intentional cache hygiene: the oversized `quality-engineering-automation-systems-nebula-portal-animated-v2.svg` identity is retired and must remain absent rather than relying on GitHub README image-cache invalidation.

The earlier UUID-style filename was removed without recompression and must remain retired. Any later hero optimization or animated-source re-embedding must be isolated, visually verified, and repinned with its own exact checksum and geometry contract.

Retired v1 nameplate and pre-responsive table-header assets are not part of my active profile contract and must remain absent.
