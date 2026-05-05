#!/usr/bin/env python3
"""
Regenerate docs/screenshot_*.png from the current demo viewer.
Requires: pip install playwright && python3 -m playwright install chromium

Run from repo root:
    python3 generate_demo.py
    python3 take_screenshots.py
"""
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

VIEWER = (Path(__file__).parent / "irule_output" / "irule_viewer.html").resolve().as_uri()
DOCS   = Path(__file__).parent / "docs"
DOCS.mkdir(exist_ok=True)

W, H = 1440, 900


async def shot(page, name: str):
    path = str(DOCS / f"screenshot_{name}.png")
    await page.screenshot(path=path, full_page=False)
    print(f"  saved → {path}")


async def js_click(page, selector: str):
    """Click via JS so viewport position doesn't matter (works on SVG nodes)."""
    await page.evaluate(f"""
        (() => {{
            const el = document.querySelector('{selector}');
            if (el) el.dispatchEvent(new MouseEvent('click', {{bubbles: true, cancelable: true}}));
        }})()
    """)


async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx     = await browser.new_context(viewport={"width": W, "height": H})
        page    = await ctx.new_page()

        print(f"Loading viewer …")
        await page.goto(VIEWER, wait_until="networkidle")
        await asyncio.sleep(2)

        # ── 1. Device Fleet ───────────────────────────────────────────────────
        print("1. fleet")
        await shot(page, "fleet")

        # ── 2. Fleet filtered ─────────────────────────────────────────────────
        print("2. fleet_filtered")
        search = page.locator("#search-input")
        await search.fill("rate")
        await asyncio.sleep(0.8)
        await shot(page, "fleet_filtered")
        await search.fill("")
        await asyncio.sleep(0.4)

        # ── 3. Force Graph ────────────────────────────────────────────────────
        print("3. force_graph  (waiting 5s for sim to settle)")
        await page.locator("#tab-force").click()
        await asyncio.sleep(5)   # let D3 sim cool down
        await shot(page, "force_graph")

        # ── 4. Force Graph — device selected (JS click, bypasses viewport) ────
        print("4. force_selected")
        await js_click(page, ".node.device circle")
        await asyncio.sleep(0.8)
        await shot(page, "force_selected")
        # Deselect by clicking the SVG background
        await js_click(page, "svg#svg")
        await asyncio.sleep(0.3)

        # ── 5. Force Graph — text filter ──────────────────────────────────────
        print("5. force_filtered")
        await search.fill("jwt")
        await asyncio.sleep(0.8)
        await shot(page, "force_filtered")
        await search.fill("")
        await asyncio.sleep(0.4)

        # ── 6. iRule source + AI analysis ─────────────────────────────────────
        print("6. ai_analysis")
        # JS-click every iRule node until the AI divider appears with real content
        irule_count = await page.locator(".node.irule circle").count()
        for i in range(irule_count):
            await page.evaluate(f"""
                (() => {{
                    const nodes = document.querySelectorAll('.node.irule circle');
                    if (nodes[{i}]) nodes[{i}].dispatchEvent(
                        new MouseEvent('click', {{bubbles: true, cancelable: true}}));
                }})()
            """)
            await asyncio.sleep(0.5)

            ai_div = page.locator("#ai-divider")
            if not await ai_div.is_visible():
                continue

            label = await page.locator("#ai-label").inner_text()
            if "No analysis" in label:
                continue

            # Ensure AI pane is expanded and tall enough to show content
            await page.evaluate("""
                const d = document.getElementById('ai-divider');
                const p = document.getElementById('ai-pane');
                if (d && d.classList.contains('collapsed')) d.click();
                if (p) { p.style.flex = 'none'; p.style.height = '310px'; p.style.display = 'block'; }
            """)
            await asyncio.sleep(0.3)
            await shot(page, "ai_analysis")
            print(f"     label: {label}")
            break

        # ── 7. ServiceNow flyout ──────────────────────────────────────────────
        print("7. snow_cve / snow_panel")
        snow_div = page.locator("#snow-section-divider")
        found_snow = False
        for i in range(irule_count):
            await page.evaluate(f"""
                (() => {{
                    const nodes = document.querySelectorAll('.node.irule circle');
                    if (nodes[{i}]) nodes[{i}].dispatchEvent(
                        new MouseEvent('click', {{bubbles: true, cancelable: true}}));
                }})()
            """)
            await asyncio.sleep(0.5)
            if await snow_div.is_visible():
                await snow_div.click()
                await asyncio.sleep(0.7)
                await shot(page, "snow_cve")
                await shot(page, "snow_panel")
                await page.locator("#snow-flyout-close").click()
                await asyncio.sleep(0.3)
                found_snow = True
                break
        if not found_snow:
            print("  (no SNow iRule visible in force graph — skipping)")

        # ── 8. Sankey ─────────────────────────────────────────────────────────
        print("8. sankey")
        await page.locator("#tab-sankey").click()
        await asyncio.sleep(2)
        await shot(page, "sankey")

        # ── 9. Sankey filtered ────────────────────────────────────────────────
        print("9. sankey_filtered")
        await search.fill("geo")
        await asyncio.sleep(0.8)
        await shot(page, "sankey_filtered")
        await search.fill("")

        await browser.close()
        print("\nDone — all screenshots saved to docs/")


asyncio.run(main())
