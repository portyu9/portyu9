#!/usr/bin/env python3
"""Offline-only experimental Fractal Iris raster study, NOT a production banner.

Requires numpy, opencv-python-headless, and Pillow. Generates self-contained
animated WebP or static PNG without changing the README or production rotation.
Not physically accurate; visual signoff on actual moving frames is required.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import math
from pathlib import Path
import sys

import cv2
import numpy as np
from PIL import Image


@lru_cache(maxsize=64)
def noise_layer(w: int, h: int, nx: int, ny: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    grid = rng.random((ny, nx), dtype=np.float32)
    return cv2.resize(grid, (w, h), interpolation=cv2.INTER_CUBIC).astype(np.float32)


def render_frame(w: int, h: int, t: float) -> Image.Image:
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    x, y = (xx - w * .5) / h, (yy - h * .515) / h
    aspect = w / h
    radius = np.hypot(x * .98, y * 1.26) + 1e-6
    theta = np.arctan2(y * 1.26, x * .98)
    phase = 2 * math.pi * t
    spin = .2 * np.cos(phase) - .17 * np.sin(phase)
    angle = theta + spin / (.7 + radius) * 2.2
    transported_x, transported_y = np.cos(angle) * radius, np.sin(angle) * radius
    dx = (.1 * np.sin(transported_y * 9 + phase) +
          .06 * np.cos(transported_x * 5 - phase)) * h
    dy = (.09 * np.cos(transported_x * 11 - phase) +
          .05 * np.sin(transported_y * 7 + phase)) * h
    map_x = np.float32(np.clip(xx + dx, 0, w - 1))
    map_y = np.float32(np.clip(yy + dy, 0, h - 1))
    fractional = np.zeros((h, w), np.float32)
    ridge = np.zeros_like(fractional)
    for octave, scale in enumerate((4, 8, 15, 26, 48, 86)):
        weight = 1 / (1 + octave * .63)
        layer = noise_layer(w, h, max(4, int(scale * aspect)), scale, 800 + octave)
        transported = cv2.remap(layer, map_x, map_y, cv2.INTER_LINEAR,
                                borderMode=cv2.BORDER_REFLECT)
        fractional += (transported - .5) * weight
        ridge += (1 - np.abs(2 * transported - 1)) * weight
    fractional /= 2.7
    ridge /= 3.1

    heat = np.clip(.6 + 3.2 * fractional, 0, 1.5)
    envelope = np.exp(-((radius - .57 - .11 * fractional) / .31)**2)
    cloud = np.clip((heat - .12) * 3, 0, 3)**1.65 * envelope
    pockets = np.clip(ridge * 2 - .35, 0, 1.8) * envelope
    plasma = cloud * (.30 + .7 * np.clip(.5 + np.cos(theta * 7 + phase) * .3 +
                                          fractional * 3, 0, 1))
    shear = np.clip(.5 + fractional * 8, 0, 2)
    corona = np.exp(-((radius - .355 - .017 * fractional) / .075)**2)
    wings = np.exp(-((y - .12 * np.sin(x * 2.4 + phase + fractional * 5)) / .32)**2)
    nebula = wings * np.clip(.45 + fractional * 5 + ridge * .8, 0, 2.2)

    # All additive layers are radiance, processed with spatially multiscale bloom.
    radiance = np.zeros((h, w, 3), np.float32)
    radiance[:] = (.003, .006, .024)
    radiance += (nebula * .21)[..., None] * (.07, .13, .54)
    radiance += (cloud * .75)[..., None] * (.54, .05, .39)
    radiance += (pockets * .6)[..., None] * (.19, .11, .51)
    radiance += (plasma * .60)[..., None] * (.71, .06, .59)
    radiance += (shear * cloud * .22)[..., None] * (.04, .82, 1.2)
    radiance += (corona * .38)[..., None] * (.78, .09, .66)
    spark = np.clip((fractional - .05) * 15, 0, 5)**2 * np.clip(ridge - .6, 0, .9)
    radiance += (spark * envelope * .5)[..., None] * (1.2, .54, .39)

    aperture = np.clip((radius - .27) / .125, 0, 1)**1.4
    radiance *= aperture[..., None]
    inner_rim = np.exp(-((radius - .310) / .02)**2)
    radiance += (inner_rim * .23)[..., None] * (.4, .13, .54)
    radiance += cv2.GaussianBlur(radiance, (0, 0), 2.5) * .25
    radiance += cv2.GaussianBlur(radiance, (0, 0), 12) * .47
    radiance += cv2.GaussianBlur(radiance, (0, 0), 29) * .37
    radiance *= np.clip((radius - .25) / .055, 0, 1)[..., None]
    # Filmic shoulder; avoid neon highlight hard clipping.
    radiance = np.maximum(radiance, 0)
    radiance = np.clip(radiance / (radiance + .42), 0, 1)**.86
    return Image.fromarray(np.uint8(radiance * 255), mode="RGB")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, help="Output .webp or .png")
    p.add_argument("--width", type=int, default=960)
    p.add_argument("--height", type=int, default=194)
    p.add_argument("--frames", type=int, default=32)
    p.add_argument("--duration-ms", type=int, default=112)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        a = np.asarray(render_frame(256, 52, 0))
        b = np.asarray(render_frame(256, 52, .25))
        z = np.asarray(render_frame(256, 52, 1))
        assert a.shape == (52, 256, 3)
        assert np.mean(np.abs(a.astype(np.float32) -
                              b.astype(np.float32))) > 1.0, "no effective motion"
        assert np.array_equal(a, z), "timeline is not exactly loop-periodic"
        print("Volumetric Iris study: periodic motion, RGB frames and temporal variation passed")
        return 0
    if not args.output or args.output.suffix.lower() not in (".png", ".webp"):
        p.error("--output must name a PNG or animated WebP")
    if not (128 <= args.width <= 1280 and 64 <= args.height <= 258 and
            4 <= args.frames <= 48 and 50 <= args.duration_ms <= 200):
        p.error("size, frame count or duration exceeds bounded study budget")
    if args.output.exists():
        p.error("refusing to overwrite an existing visual review artifact")
    frames = [render_frame(args.width, args.height, i / args.frames)
              for i in range(args.frames)]
    if args.output.suffix.lower() == ".png":
        frames[0].save(args.output)
    else:
        frames[0].save(args.output, format="WEBP", save_all=True,
                       append_images=frames[1:], duration=args.duration_ms,
                       loop=0, quality=80, method=5)
    print(f"Experimental render {args.output}: {args.frames} source frames; "
          f"{args.output.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
