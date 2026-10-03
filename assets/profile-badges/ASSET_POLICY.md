# Profile asset policy

My profile hero is intentionally stored at `quality-engineering-automation-systems.png` as a reviewed, size-bounded PNG fallback.

## Current optimized fallback

- Canvas: `1280 × 854`
- Size: `1,472,916` bytes (1.473 MB decimal / 1.405 MiB)
- SHA-256: `d840734c78ec59f3c53644330bc2166c51e1bb5eb8e768595035a37767eb5452`
- Git blob: `8415380b255d8f24a1c2152a029e50b69c91ec3d`

This is a roughly 50% payload reduction from the previous reviewed `1535 × 1024`, `2,947,658`-byte fallback. The candidate was produced from that exact prior image with Lanczos downscaling, metadata stripping, and PNG compression; it was not redrawn or regenerated.

The isolated measurement run `37142059806` compared bounded candidates before replacement. The selected 1280px candidate was `1,472,916` bytes and measured PSNR `33.3112 dB` after deterministic restoration to the former canvas for comparison. Manual visual inspection confirmed that the hero composition, text, and primary detail remain readable at README hero scale. The finalizer then required the exact measured candidate SHA-256, byte count, and `1280 × 854` geometry before replacing the fallback.

The active README source remains `quality-engineering-automation-systems-nebula-portal-animated-v2.svg`; that self-contained animation still carries its previously reviewed embedded base. This optimization intentionally changes only the PNG fallback requested here and does not silently rewrite the animated source.

The earlier UUID-style filename was removed without recompression and must remain retired. Any later hero optimization or animated-source re-embedding must be isolated, visually verified, and repinned with its own exact checksum and geometry contract.

Retired v1 nameplate and pre-responsive table-header assets are not part of my active profile contract and must remain absent.
