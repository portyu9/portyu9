# Fractal Iris — offline cinematic render study (not approved)

This is the first **isolated, deliberately unshipped** attempt to replace geometric SVG animation with evolving volumetric raster texture. It is neither a claim of physical accuracy nor a finished state-of-the-art treatment. Production remains pinned to original Quantum Apex/Evidence Horizon. The seven daily SVG triplets are preserved unchanged.

## GitHub-hosted animated SVG preview

**[Open the actual Fractal Iris animated SVG in GitHub](previews/fractal-iris-animated.svg)** · **[Open the raw SVG animation](https://raw.githubusercontent.com/portyu9/portyu9/feature/volumetric-iris-render-study-20261013/experiments/previews/fractal-iris-animated.svg)**

![Fractal Iris animation review — evolving procedural plasma texture and glow](previews/fractal-iris-animated.svg)

The preview above is the **actual committed animated SVG**, not a sandbox link or a mockup. If GitHub's Markdown image proxy shows a static frame, open the raw link in your browser to review motion. This is a separate **SVG-native filter and turbulence study**, not an exact conversion of the Python WebP renderer below. Visual/performance approval is outstanding; SVG turbulence can be expensive on slower browsers. **This preview is not included in README.md and cannot enter the production rotation.**

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

## Initial visual evaluation (not acceptance)

Locally rendered study sample: 960 × 194, 32 frames, 112 ms per frame (~3.58 seconds), animated WebP approximately 273 KB. It introduces evolving gas texture rather than simply animating geometrical line drawings, but its central aperture and magenta cloud field are **still too schematic to qualify as the final cinematic design**. The model is artistically provisional. No actual GitHub animation playback, browser frame-time, memory, or mobile/compact/footer verification has been performed. The next iteration must materially improve material realism, dimensional atmosphere, and scene composition before product integration.
