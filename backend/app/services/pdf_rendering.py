"""Playwright-based PDF rendering for the React report templates.

This intentionally avoids manual PDF layout engines (e.g. reportlab for layout)
and prints a dedicated report route with full CSS/gradient/shadow support.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import date
from typing import Literal, Optional
from urllib.parse import urlencode

from app.core.config import settings

logger = logging.getLogger(__name__)

ReportKind = Literal["executive", "technical"]


def _frontend_base_url() -> str:
    # Prefer an explicit config; fall back to local Vite dev server.
    return (getattr(settings, "frontend_base_url", "") or "http://localhost:5173").rstrip("/")


def build_report_url(
    *,
    kind: ReportKind,
    profile_id: int,
    start_date: date,
    end_date: date,
) -> str:
    base = _frontend_base_url()
    path = f"/reports/{kind}/{profile_id}"
    qs = urlencode(
        {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }
    )
    return f"{base}{path}?{qs}"


async def render_report_pdf(
    *,
    kind: ReportKind,
    profile_id: int,
    start_date: date,
    end_date: date,
    auth_token: Optional[str] = None,
) -> bytes:
    """Render the report route into a pixel-accurate PDF."""
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "Playwright is not installed. Add it to the backend environment and run "
            "`python -m playwright install chromium`."
        ) from exc

    url = build_report_url(kind=kind, profile_id=profile_id, start_date=start_date, end_date=end_date)
    logger.info("Rendering report PDF via Playwright: %s", url)

    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox"])
        try:
            context = await browser.new_context()
            if auth_token:
                # The SPA uses localStorage to attach auth headers via the API client.
                await context.add_init_script(
                    f"window.localStorage.setItem('sentinelix_token', {auth_token!r});"
                )
            page = await context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=120_000)
            # Ensure fonts/layout settle.
            await page.wait_for_timeout(250)
            pdf = await page.pdf(
                format="A4",
                print_background=True,
                prefer_css_page_size=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"},
            )
            return pdf
        finally:
            await browser.close()


def render_report_pdf_sync(**kwargs) -> bytes:
    """Sync wrapper for non-async callers."""
    return asyncio.run(render_report_pdf(**kwargs))

