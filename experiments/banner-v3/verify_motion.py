#!/usr/bin/env python3
"""Read-only browser smoke test for the four SVG review families.

Optional dependencies: local chromium, playwright, Pillow.
Usage: python experiments/banner-v3/verify_motion.py --family 05
       python experiments/banner-v3/verify_motion.py --family all
Never edits the reviewed assets, trusted workflows, README, or approved catalog.
"""
from __future__ import annotations
import argparse
import asyncio
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import sys
from PIL import Image, ImageChops
from playwright.async_api import async_playwright

ROOT=Path(__file__).resolve().parent
ASSETS=ROOT/"assets"

def diff_fraction(a:bytes,b:bytes)->float:
    before=Image.open(BytesIO(a)).convert("RGB")
    after=Image.open(BytesIO(b)).convert("RGB")
    if before.size != after.size:
        raise ValueError("SVG screenshots changed dimensions")
    delta=ImageChops.difference(before,after).convert("L")
    return sum(v>10 for v in delta.get_flattened_data())/(delta.width*delta.height)

async def verify(family:str)->None:
    subprocess.run([sys.executable,str(ROOT/"generate.py"),"--check"],check=True,capture_output=True)
    assets=sorted(ASSETS.glob(f"{family}-*.svg")) if family!="all" else sorted(ASSETS.glob("0[5-8]-*.svg"))
    if len(assets)!=(12 if family=="all" else 3):
        raise ValueError("Missing triplet assets")
    binary=shutil.which("chromium") or shutil.which("google-chrome")
    if not binary:
        raise RuntimeError("Chromium executable required")
    async with async_playwright() as playwright:
        browser=await playwright.chromium.launch(executable_path=binary,args=["--no-sandbox"])
        try:
            for source in assets:
                payload=source.read_text(encoding="utf8")
                urls=[]
                context=await browser.new_context(reduced_motion="no-preference",color_scheme="dark",viewport={"width":1280,"height":300})
                page=await context.new_page()
                page.on("request",lambda request:urls.append(request.url))
                await page.set_content(payload,wait_until="load")
                scene=await page.locator("svg").get_attribute("data-scene")
                if not scene or scene not in source.name:
                    raise ValueError(f"Unrecognized SVG scene: {source.name}")
                await page.wait_for_timeout(400)
                first=await page.locator("svg").screenshot()
                await page.wait_for_timeout(900)
                second=await page.locator("svg").screenshot()
                fraction=diff_fraction(first,second)
                if fraction<0.002 or urls:
                    raise ValueError(f"Motion failed or network observed: {source.name} {fraction:.3%} {urls}")
                await context.close()
                reduced=await browser.new_context(reduced_motion="reduce",color_scheme="dark",viewport={"width":1280,"height":300})
                page=await reduced.new_page()
                await page.set_content(payload,wait_until="load")
                visibility=await page.evaluate("""() => {
                    const moving=document.querySelector('.motion');
                    const still=document.querySelector('.still');
                    return [getComputedStyle(moving).display,getComputedStyle(still).display];
                }""")
                if visibility[0]!="none" or visibility[1]=="none":
                    raise ValueError(f"Reduced-motion fallback unavailable: {source.name}")
                await page.wait_for_timeout(350)
                still0=await page.locator("svg").screenshot()
                await page.wait_for_timeout(900)
                still1=await page.locator("svg").screenshot()
                if diff_fraction(still0,still1)!=0:
                    raise ValueError(f"Reduced-motion SVG changed: {source.name}")
                await reduced.close()
                print(f"PASS {source.name}: {fraction:.2%} moving; reduced-motion static")
        finally:
            await browser.close()
    print(f"PASS {len(assets)}/{len(assets)} motion/reduced-motion browser tests")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--family",choices=("all","05","06","07","08"),default="all")
    asyncio.run(verify(parser.parse_args().family))
