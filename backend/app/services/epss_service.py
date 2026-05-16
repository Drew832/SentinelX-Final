"""EPSS enrichment (FIRST) with lightweight caching."""
from __future__ import annotations

import logging
from typing import Dict, Optional

import httpx
from cachetools import TTLCache

logger = logging.getLogger(__name__)

_cache: TTLCache[str, float] = TTLCache(maxsize=50_000, ttl=24 * 3600)


async def get_epss_score(cve_id: str) -> Optional[float]:
    key = (cve_id or "").strip().upper()
    if not key:
        return None
    if key in _cache:
        return _cache[key]

    url = "https://api.first.org/data/v1/epss"
    params = {"cve": key}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        items = data.get("data") or []
        if not items:
            return None
        score = float(items[0].get("epss"))
        _cache[key] = score
        return score
    except Exception as exc:  # noqa: BLE001
        logger.warning("EPSS lookup failed for %s: %s", key, exc)
        return None


async def get_epss_scores(cve_ids: list[str], limit: int = 200) -> Dict[str, float]:
    unique = []
    seen = set()
    for c in cve_ids:
        k = (c or "").strip().upper()
        if not k or k in seen:
            continue
        seen.add(k)
        unique.append(k)
        if len(unique) >= limit:
            break

    out: Dict[str, float] = {}
    # Run in small parallel batches to keep latency down.
    import asyncio

    sem = asyncio.Semaphore(8)

    async def _one(cid: str):
        async with sem:
            s = await get_epss_score(cid)
            if isinstance(s, float):
                out[cid] = s

    await asyncio.gather(*[_one(cid) for cid in unique])
    return out

