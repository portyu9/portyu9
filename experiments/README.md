# Fractal Iris — offline cinematic render study (not approved)

This is the first **isolated, deliberately unshipped** attempt to replace geometric SVG animation with evolving volumetric raster texture. It is neither a claim of physical accuracy nor a finished state-of-the-art treatment. Production remains pinned to original Quantum Apex/Evidence Horizon. The seven daily SVG triplets are preserved unchanged.

## Frame renderer

Requires Python 3.11+ plus Pillow, NumPy and OpenCV (headless). Run after installing these packages in a local isolated environment:

```bash
python3 experiments/fractal_iris_pilot.py --self-test
python3 experiments/fractal_iris_pilot.py --output /tmp/iris-review.webp
python3 experiments/fractal_iris_pilot.py --output /tmp/iris-keyframe.png
```

The isolated study uses transported multiscale stochastic turbulence, a nonlinear emission/density field, evolving aperture corona, spatially layered bloom and a bounded filmic curve. Source frame count, animation duration, output dimensions, and no-overwrite behavior are bounded. Reduced-motion content can use the generated static PNG.

## Acceptance gate before any production or reactivation

1. **Visual:** compare actual moving frames with the approved original Quantum Apex desktop and compact art. A merely animated contour/wireframe is a failed iteration. Review at desktop and narrow mobile aspect ratios and footer proportions, including reduced motion.
2. **Runtime:** verify GitHub README image playback behavior, first-view loading, transferred bytes, decoded memory, mobile frame cadence, and motion/cross-browser behavior. Report measured results, not theoretical guarantees.
3. **Security:** no README publisher changes, no external loads, no hidden script, no automatic merge of artwork, and no rotation reactivation without a separate explicit PR and owner signoff.
4. **Coverage:** when the first render is genuinely approved, build six separately directed scenes (Orbital Relay, Prism Vault, Neural Weave, Spectral Tides, Circuit Basilica, Singularity Mesh) and distinct desktop/mobile/footer compositions.

Current study is **not accepted artwork**. Keep this PR available for code iteration and review, but do not merge or deploy unfinished imagery.
