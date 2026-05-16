"""Shodan-backed live threat telemetry service with 24h cache."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.cve import CVE
from app.schemas.cve import TelemetryPoint, TelemetryResponse

logger = logging.getLogger(__name__)


def _obfuscate_ip(ip: str | None) -> str:
    if not ip:
        return "0.0.0.0"
    if ":" in ip:  # IPv6 — keep first 2 segments
        parts = ip.split(":")
        return ":".join(parts[:2] + ["x"] * max(0, len(parts) - 2))
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return f"{parts[0]}.{parts[1]}.x.x"


class ShodanService:
    """Wraps the synchronous shodan client behind a cached async API."""

    def __init__(self) -> None:
        self._cache_payload: TelemetryResponse | None = None
        self._cache_expiry: float = 0.0
        self._lock = asyncio.Lock()
        self._api_key = settings.shodan_api_key or os.getenv("SHODAN_API_KEY")

    async def get_telemetry(self, db: AsyncSession) -> TelemetryResponse:
        now = time.time()
        if self._cache_payload and now < self._cache_expiry:
            return self._cache_payload.model_copy(update={"cached": True})

        async with self._lock:
            if self._cache_payload and time.time() < self._cache_expiry:
                return self._cache_payload.model_copy(update={"cached": True})

            top = await self._top_kev_cves(db, limit=10)
            points, source, note = await self._gather_points(top)

            payload = TelemetryResponse(
                generated_at=datetime.now(tz=timezone.utc),
                cached=False,
                source=source,
                note=note,
                points=points,
            )
            self._cache_payload = payload
            self._cache_expiry = time.time() + settings.telemetry_cache_ttl_seconds
            return payload

    async def _top_kev_cves(self, db: AsyncSession, limit: int = 10) -> list[CVE]:
        stmt = (
            select(CVE)
            .where(CVE.is_kev.is_(True))
            .order_by(CVE.cvss_v3_score.desc().nullslast())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def _gather_points(
        self, cves: list[CVE]
    ) -> tuple[list[TelemetryPoint], str, str | None]:
        if not cves:
            return [], "empty", "No CISA KEV CVEs in the database yet. Run a KEV ingest."

        if not self._api_key:
            logger.info("SHODAN_API_KEY not set — returning synthetic telemetry")
            return (
                self._synthetic_points(cves),
                "synthetic",
                "SHODAN_API_KEY not configured; showing representative geo distribution.",
            )

        try:
            import shodan  # type: ignore
        except ImportError:  # pragma: no cover
            logger.warning("shodan client not installed; using synthetic telemetry")
            return self._synthetic_points(cves), "synthetic", "shodan client not installed"

        api = shodan.Shodan(self._api_key)
        loop = asyncio.get_running_loop()
        points: list[TelemetryPoint] = []
        last_error: str | None = None

        for cve in cves:
            try:
                results = await loop.run_in_executor(
                    None, lambda c=cve: api.search(f"vuln:{c.cve_id}", limit=20)
                )
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                logger.warning("Shodan query failed for %s: %s", cve.cve_id, exc)
                continue

            for match in results.get("matches", [])[:20]:
                location = match.get("location") or {}
                lat = location.get("latitude")
                lon = location.get("longitude")
                if lat is None or lon is None:
                    continue
                points.append(
                    TelemetryPoint(
                        cve_id=cve.cve_id,
                        cvss_v3_score=cve.cvss_v3_score,
                        cvss_v3_severity=cve.cvss_v3_severity,
                        is_kev=cve.is_kev,
                        kev_vulnerability_name=cve.kev_vulnerability_name,
                        ip_obfuscated=_obfuscate_ip(match.get("ip_str")),
                        latitude=float(lat),
                        longitude=float(lon),
                        country=location.get("country_name"),
                        city=location.get("city"),
                        org=match.get("org"),
                    )
                )
            await asyncio.sleep(1.0)  # be polite to Shodan

        if points:
            return points, "shodan", None
        note = (
            f"Shodan live search unavailable ({last_error or 'no matches'}); showing "
            "representative points. A Shodan paid membership is required for the `vuln:` filter."
        )
        return self._synthetic_points(cves), "synthetic", note

    def _synthetic_points(self, cves: list[CVE]) -> list[TelemetryPoint]:
        """Fallback when Shodan is unavailable. Produces a deterministic but
        naturally-scattered spread of points (no straight-line artefacts) so
        the threat map looks like real telemetry in dev/demo."""
        import hashlib

        sample_locations = [
            ("United States", "Ashburn", 39.0438, -77.4874, "Equinix"),
            ("United States", "San Jose", 37.3382, -121.8863, "AWS"),
            ("Germany", "Frankfurt", 50.1109, 8.6821, "Hetzner"),
            ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Leaseweb"),
            ("Singapore", "Singapore", 1.3521, 103.8198, "AWS"),
            ("Japan", "Tokyo", 35.6895, 139.6917, "NTT"),
            ("Brazil", "São Paulo", -23.5505, -46.6333, "Telefônica"),
            ("United Kingdom", "London", 51.5074, -0.1278, "BT"),
            ("Australia", "Sydney", -33.8688, 151.2093, "Telstra"),
            ("India", "Mumbai", 19.0760, 72.8777, "Reliance"),
            ("Canada", "Toronto", 43.6532, -79.3832, "Bell"),
            ("France", "Paris", 48.8566, 2.3522, "OVH"),
        ]

        def _jitter(seed: str, span: float = 6.0) -> tuple[float, float]:
            """Return (dLat, dLon) seeded from a string, in degrees."""
            digest = hashlib.md5(seed.encode("utf-8")).digest()
            dx = (digest[0] - 128) / 128 * span
            dy = (digest[1] - 128) / 128 * span
            return dx, dy

        points: list[TelemetryPoint] = []
        for idx, cve in enumerate(cves):
            for j, (country, city, lat, lon, org) in enumerate(sample_locations):
                dlat, dlon = _jitter(f"{cve.cve_id}-{j}", span=4.0)
                points.append(
                    TelemetryPoint(
                        cve_id=cve.cve_id,
                        cvss_v3_score=cve.cvss_v3_score,
                        cvss_v3_severity=cve.cvss_v3_severity,
                        is_kev=cve.is_kev,
                        kev_vulnerability_name=cve.kev_vulnerability_name,
                        ip_obfuscated=f"{(idx * 17 + j) % 223 + 10}.{(j * 11 + idx) % 254}.x.x",
                        latitude=round(lat + dlat, 4),
                        longitude=round(lon + dlon, 4),
                        country=country,
                        city=city,
                        org=org,
                    )
                )
        return points


_service_instance: ShodanService | None = None


def get_shodan_service() -> ShodanService:
    global _service_instance
    if _service_instance is None:
        _service_instance = ShodanService()
    return _service_instance
