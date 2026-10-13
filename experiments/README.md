# Fractal Iris — offline cinematic render study (not approved)

This is the first **isolated, deliberately unshipped** attempt to replace geometric SVG animation with evolving volumetric raster texture. It is neither a claim of physical accuracy nor a finished state-of-the-art treatment. Production remains pinned to original Quantum Apex/Evidence Horizon. The seven daily SVG triplets are preserved unchanged.

## GitHub-hosted animated SVG preview

**[Open the actual Fractal Iris animated SVG in GitHub](previews/fractal-iris-animated.svg)** · **[Open the raw SVG animation](https://raw.githubusercontent.com/portyu9/portyu9/feature/volumetric-iris-render-study-20261013/experiments/previews/fractal-iris-animated.svg)**

![Fractal Iris animation review — evolving procedural plasma texture and glow](previews/fractal-iris-animated.svg)

The preview above is the **actual committed animated SVG**, not a sandbox link or a mockup. If GitHub's Markdown image proxy shows a static frame, open the raw link in your browser to review motion. This is a separate **SVG-native filter and turbulence study**, not an exact conversion of the Python WebP renderer below. Visual/performance approval is outstanding; SVG turbulence can be expensive on slower browsers. **This preview is not included in README.md and cannot enter the production rotation.**

## Motion + central-aperture revision (October 13)

This is the **actual committed [revision of the animated SVG](previews/fractal-iris-animated.svg)**. Use [the raw SVG in a browser](https://raw.githubusercontent.com/portyu9/portyu9/feature/volumetric-iris-render-study-20261013/experiments/previews/fractal-iris-animated.svg) if GitHub's image proxy shows only a still frame.

The first SVG had four animation changes to turbulence/displacement filters, a large rotating group containing roughly 165 long, detailed filament paths, and oversized native raster dimensions of 3840 × 774 for a 1280 × 258 composition. These are plausible sources of visible timing discontinuities and costly repaint, and have been removed. The turbulence/displacement supply **static texture**, and the underlying 165 filament paths stay in place rather than forcing full-path rotation. **Motion is restored to the atmosphere and filaments:** two unfiltered nebula emission fronts drift slowly over 19- and 23-second closed cubic-eased loops, and 14 filament highlight strands stream continuously via linear, repeat-exact `stroke-dashoffset` cycles (14–22 seconds). Their dash pattern totals 162 units and resets after advancing exactly 162 units, avoiding a phase discontinuity. Three small optical groups continue uninterrupted linear rotation (53, 71 and 96 seconds), with matching static fallback geometry. All atmosphere/filament motion is hidden under `prefers-reduced-motion`, leaving the original static textured art visible. The intrinsic SVG dimensions are now 1280 × 258, a **9× lower raster-pixel request**.

The central focal point is no longer a single black oval: it is a dimensional iris of sixteen refractive aperture blades, 18 inner shutter petals, graduated dielectric rings, static grain, iridescent bevels, optical glints and a deeply recessed black center. All new content is **outside the production rotation**.

### Regression contract

Run `python3 experiments/validate_iris_svg.py` to verify no animated SVG filter parameters, bounded linear optical transforms, seamless eased nebula drift, continuous 162-unit filament dash phase loops, self-contained references, reduced-motion fallbacks and a bounded asset payload. The script verifies **structure, not frame rate or artistic quality**. Browser-based moving-frame and memory tests, particularly Firefox/LibreWolf and mobile browsers, remain required before approving motion quality. Do not describe this as proven 60 FPS until it has been observed and measured.

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
