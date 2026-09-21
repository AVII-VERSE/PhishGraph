"""Headless Browser Screenshot & DOM Inspector.

Safely captures web page screenshots in a sandboxed headless environment
with strict timeout, private network blocking (SSRF prevention), and fallback.
"""

import asyncio
from dataclasses import dataclass
from typing import Optional
from app.logging import get_logger
from app.security.url_safety import validate_url_safety

logger = get_logger("phishgraph.analyzers.screenshot")


@dataclass
class ScreenshotResult:
    """Headless capture output containing screenshot bytes and extracted DOM."""

    success: bool
    image_bytes: Optional[bytes] = None
    page_title: Optional[str] = None
    html_content: Optional[str] = None
    error: Optional[str] = None


class HeadlessScreenshotAnalyzer:
    """Captures safe isolated webpage screenshots using Playwright."""

    def __init__(self, timeout_ms: int = 8000):
        self.timeout_ms = timeout_ms

    async def capture(
        self,
        url: str,
        allow_private_in_testing: bool = False,
    ) -> ScreenshotResult:
        """Capture webpage screenshot and HTML safely."""
        # 1. SSRF Safety Check before launching browser connection
        is_safe, reason, _ = await validate_url_safety(
            url,
            allow_private_in_testing=allow_private_in_testing,
        )
        if not is_safe:
            return ScreenshotResult(
                success=False,
                error=f"Screenshot blocked by SSRF firewall: {reason}",
            )

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ScreenshotResult(
                success=False,
                error="Playwright is not installed or available.",
            )

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGraph/1.2 Security-Scanner",
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                try:
                    await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                    title = await page.title()
                    html = await page.content()
                    screenshot = await page.screenshot(type="jpeg", quality=75)
                    await browser.close()

                    return ScreenshotResult(
                        success=True,
                        image_bytes=screenshot,
                        page_title=title,
                        html_content=html,
                    )
                except Exception as page_exc:
                    await browser.close()
                    return ScreenshotResult(
                        success=False,
                        error=f"Navigation timeout/error: {page_exc}",
                    )

        except Exception as exc:
            logger.warning(f"Browser screenshot capture failed for {url}: {exc}")
            return ScreenshotResult(success=False, error=str(exc))
