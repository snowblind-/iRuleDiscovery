#!/usr/bin/env python3
"""
Retake only the ai_analysis screenshot with cache disabled.
Run from repo root: python3 retake_ai_screenshot.py
"""
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

VIEWER = (Path(__file__).parent / "irule_output" / "irule_viewer.html").resolve().as_uri()
DOCS   = Path(__file__).parent / "docs"


async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-application-cache", "--disable-cache"])
        # Fresh user-data-dir every run so nothing is cached
        ctx = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            bypass_csp=True,
        )
        await ctx.route("**/*", lambda route: route.continue_())

        page = await ctx.new_page()

        # Force reload with cache disabled
        await page.set_extra_http_headers({"Cache-Control": "no-cache, no-store"})

        print(f"Loading viewer (cache disabled) …")
        await page.goto(VIEWER, wait_until="networkidle")
        await asyncio.sleep(2)

        # Verify we have the new UI (no AI button)
        ai_btn_visible = await page.locator("#search-ai-btn").is_visible() if await page.locator("#search-ai-btn").count() > 0 else False
        print(f"  Old AI button present: {ai_btn_visible}  (should be False)")

        # Switch to Force Graph
        await page.click("#tab-force")
        await asyncio.sleep(4)

        # Walk iRule nodes for one with real AI content
        irule_nodes = page.locator(".node.irule circle")
        n = await irule_nodes.count()
        print(f"  Found {n} iRule nodes")

        for i in range(n):
            await irule_nodes.nth(i).click()
            await asyncio.sleep(0.5)

            ai_div = page.locator("#ai-divider")
            if not await ai_div.is_visible():
                continue

            cls = await ai_div.get_attribute("class") or ""
            if "collapsed" in cls:
                await ai_div.click()
                await asyncio.sleep(0.3)

            label_text = await page.locator("#ai-label").inner_text()
            if "No analysis" in label_text:
                continue

            # Expand AI pane to 320px so content is visible
            await page.evaluate("""
                const pane = document.getElementById('ai-pane');
                pane.style.flex = 'none';
                pane.style.height = '320px';
                pane.style.display = 'block';
            """)
            await asyncio.sleep(0.3)

            path = str(DOCS / "screenshot_ai_analysis.png")
            await page.screenshot(path=path, full_page=False)
            rule = await page.locator("#rule-name-display").inner_text()
            print(f"  Saved → {path}")
            print(f"  iRule: {rule}  |  AI: {label_text}")
            break

        await browser.close()


asyncio.run(main())
