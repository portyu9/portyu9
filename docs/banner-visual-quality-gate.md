# Animated banner browser-evidence gate

This utility renders **actual repository SVGs** for visual review. It is not an artistic scoring algorithm, a native protected GitHub check, or an assertion that GitHub's image proxy, Safari, LibreWolf, and physical phones render identically.

## Scope and invariants

- **Approved mode** reads the current `approved-banner-rotation-v7.json` manifest and verifies Git blob identities for all **four** approved desktop/compact/footer triplets. Reserved slots 5–8 are never promoted by the tool.
- **Review mode** reads exactly complete triplets named `05-...` through `08-...` from an explicitly selected directory. It does **not** assume that rejected or unmerged experimental artwork is approved.
- Screenshots and a JSON evidence report are written **only outside the repository**, by default to `/tmp/portyu9-banner-review`; no README, catalog, SVG source, workflow, secret, authorization ledger, generated branch, or protected-ref mutation.
- All inputs must parse as SVG with dimensions, accessible title/description and a reduced-motion rule. Reject active/external SVG elements, nonlocal resource schemes, and network requests observed by the browser.
- Normal-motion and reduced-motion frames are each sampled twice. Normal frames must show at least 0.1% materially changed pixels; reduced-motion frames must remain pixel-identical. This is a motion *smoke test*, not a frame-pacing or perceptual-quality certificate.

## Run against exact approved art

Requirements: Python 3.11+, `playwright`, `Pillow`, and an installed browser binary. For example, in a disposable Python environment:

```sh
python3 -m pip install playwright Pillow
python3 -m playwright install chromium
python3 experiments/banner_visual_quality_gate.py --mode approved --browser chromium --out /tmp/portyu9-banner-approved
```

On systems with Chromium already installed, add `--executable /usr/bin/chromium`. The script also supports `--browser firefox` and `--browser webkit` where those Playwright engines are available; browser availability is **not** assumed.

## Run against a new **unapproved** review collection

```sh
python3 experiments/banner_visual_quality_gate.py \
  --mode review \
  --review-dir experiments/banner-v4/assets \
  --browser chromium \
  --out /tmp/portyu9-banner-candidate
```

For each family the output includes a labeled contact sheet combining its wide top, mobile-compact top, and footer, along with normal-motion and reduced-motion PNGs and `render-report.json` containing source SHA-256, rendered dimensions, changed-pixel fractions and explicit `human_visual_approval: false` and `github_or_real_device_certification: false`.

## Approval checklist (human judgment, not code inference)

Review actual rendered frames (and motion) for focal hierarchy, density at the real aspect ratio, depth/lighting, contrast, negative space, visual differentiation between families, and whether a compact 640px composition genuinely works rather than merely shrinking a 1280px one. Compare against the four **approved** originals as the quality floor. Verify in GitHub's own README rendering, Safari, a Firefox-based browser including LibreWolf, and physical mobile devices before claiming cross-browser fidelity. Approve separately before any production-art or rotation change.

**Lineage / non-salvage:** The earlier 12-SVG visual candidate PR #1980 was explicitly closed without merging and its head branch deleted on 2026-10-30. Its final commit `be272c9c0227c3b102650d37759b9b0b29c93c52` remains an archival reference, with unique generator blob `eb4267ae0e661bf632eb36d38f6703f4a82f72cb` and browser-verifier blob `0c0df16f35598f80f40b3733a37b34cd76a7b17d`. The **testing idea** is salvaged into this independent, approved-catalog-aware tool; no art assets or production permissions are copied or activated. Original Quantum Apex/Evidence Horizon content-addressed blobs `cba6be419ca838ada1accd02b714cd99fdd06664`, `7a9b12381c15fe6811e57af07a5569b15354c219`, `de437b518adae0a8a501d4c6693b8a6b987576a2` remain untouched.

The 2026-10-30 source preflight used accepted `main=b0895a90939ca5fed4eadd884794466fc863ad0e`, zero open PRs, and existing separate `generated` and `activity-metrics` branches. Neither independent branch is modified. Historical #1637 artwork was also closed unmerged and is not implicitly accepted.
