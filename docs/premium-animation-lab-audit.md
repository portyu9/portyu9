# Frame-based plasma experimental asset audit

- Accepted production base: `6dec4e6f5d31c2bad7a28714661cc090ce43208e`; same feature branch `feature/premium-plasma-iris-lab-20261012`; original rejected candidate head `8723667a2eb7c0acfa1d49e81df872e970ed676e`.
- Exact generator Git blob: `7322707676baf6aca23abd1508c527a94d0c495e`; locally reproduced hashes matched connector-generated GIF blobs.
- Desktop: Git blob `f06fec45b9deaf1280347eb7caca515e5634c999`, 448 × 90, 20 frames, 637896 bytes.
- Mobile: Git blob `2ce1e25f91de4a7580a49b2e0a9112cbc755525f`, 420 × 128, 20 frames, 881188 bytes.
- Footer: Git blob `fe3bc5c3da26cec28b572e89f532e0f412fb1f19`, 448 × 52, 20 frames, 348976 bytes.
- All GIFs decoded through Pillow at first and mid-animation frames locally. Animate full pixel field; no stroke-dash loop.
- Original three banner blob SHA identities preserved: desktop `cba6be419ca838ada1accd02b714cd99fdd06664`, mobile `7a9b12381c15fe6811e57af07a5569b15354c219`, footer `de437b518adae0a8a501d4c6693b8a6b987576a2`.
- Production and eight-theme rotation untouched. No new branch. No merge.
- Open bot PRs and security-related open issues: none during initial preflight, though private Security alert inventory is unavailable.
- Still needed: aesthetic signoff, Firefox/LibreWolf and mobile viewing, performance/compression and reduced-motion alternative.
