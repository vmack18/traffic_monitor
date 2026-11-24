#!/usr/bin/env python3
"""Capture a screenshot of the Traffic Guard dashboard."""
import os
import sys
import time
from playwright.sync_api import sync_playwright

URL = os.environ.get("DASH_URL", "http://127.0.0.1:3000/")
OUT = os.environ.get("SHOT_OUT", "docs/dashboard.png")
CHROME = "/root/.cache/ms-playwright/chromium-1217/chrome-linux64/chrome"


def main() -> int:
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with sync_playwright() as p:
        launch_kwargs = {"headless": True, "args": ["--no-sandbox"]}
        if os.path.exists(CHROME):
            launch_kwargs["executable_path"] = CHROME
        browser = p.chromium.launch(**launch_kwargs)
        page = browser.new_page(viewport={"width": 1600, "height": 1000},
                                device_scale_factor=2)
        page.goto(URL, wait_until="networkidle", timeout=30000)
        # Let the WebSocket deliver several snapshots so the chart fills in.
        time.sleep(9)
        page.screenshot(path=OUT, full_page=True)
        print(f"saved {OUT} ({os.path.getsize(OUT)} bytes)")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
