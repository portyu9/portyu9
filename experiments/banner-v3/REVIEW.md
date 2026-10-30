# Four animated banner families — visual review only

**No activation or production merge is authorized.** All approved legacy and current slots remain byte-for-byte unchanged; the daily rotation is unaffected.

| Family | Wide (1280 × 258) | Compact (640 × 196) | Footer (1280 × 150) |
|---|---|---|---|
| Living Plasma | ![Living Plasma desktop](assets/05-living-plasma-top.svg) | ![Living Plasma mobile](assets/05-living-plasma-top-compact.svg) | ![Living Plasma footer](assets/05-living-plasma-bottom.svg) |
| Cybernetic Cathedral | ![Cybernetic Cathedral desktop](assets/06-cybernetic-cathedral-top.svg) | ![Cybernetic Cathedral mobile](assets/06-cybernetic-cathedral-top-compact.svg) | ![Cybernetic Cathedral footer](assets/06-cybernetic-cathedral-bottom.svg) |
| Quantum Interference | ![Quantum Interference desktop](assets/07-quantum-interference-top.svg) | ![Quantum Interference mobile](assets/07-quantum-interference-top-compact.svg) | ![Quantum Interference footer](assets/07-quantum-interference-bottom.svg) |
| Celestial Singularity | ![Celestial Singularity desktop](assets/08-celestial-singularity-top.svg) | ![Celestial Singularity mobile](assets/08-celestial-singularity-top-compact.svg) | ![Celestial Singularity footer](assets/08-celestial-singularity-bottom.svg) |

## Verification

1. `python3 experiments/banner-v3/generate.py --check` validates that the 12 files match their deterministic generator byte-for-byte, each is well-formed and scriptless, no external references, path-density thresholds and size limits hold.
2. Optional actual Chromium and Pillow regression test, `python3 experiments/banner-v3/verify_motion.py --family 05` (repeat for 06–08) or `--family all`, checks every SVG's significant raster-frame difference over 900 ms, network request count zero, and reduced-motion mode static. These are **local tests only**, not protected GitHub required checks.
3. **2026-10-30 local Chromium evidence: all 12/12 pass normal motion and reduced-motion tests.** Motion deltas: Living Plasma bottom 45.77%, mobile 39.58%, desktop 32.63%; Cybernetic Cathedral 31.41%, 27.13%, 27.60%; Quantum Interference 35.53%, 34.04%, 31.26%; Celestial Singularity 8.17%, 16.17%, 12.89%. Variation across runs is expected because phases are sampled at elapsed time. All reduced-motion comparisons yielded zero changed pixels.
4. GitHub README visual appearance in Safari/LibreWolf/mobile and actual hardware frame pacing have **not** been certified by these screenshots. Owner visual quality approval is still required.

## Production boundaries

- No files in `assets/profile-banners/approved`, no approved catalog, no README, workflows, generated evidence or delegated source contracts changed.
- This is a standalone **review** experiment. Do not merge this PR or activate additional slots without owner acceptance and a separately protected production activation PR.
