"""Centralised LLM gateway.

Every backend AI feature funnels through ``ai_complete()`` so we have
a single point of control for:

  * Provider selection (Anthropic Claude first, OpenAI as a graceful
    fallback for legacy installs).
  * Per-call timeouts.
  * Bounded exponential-backoff retries (network errors and 5xx only —
    deterministic errors like 400/401/403 fail fast).
  * A tiny in-process response cache so duplicate prompts within
    ``DEFAULT_TTL`` seconds are answered instantly. This is what keeps
    the report and policy endpoints responsive when several operators
    refresh the same view in succession.
  * Structured logging so a failed AI call always tells us exactly
    which provider and prompt fingerprint it was.

Callers receive a structured result rather than a raw string. The
caller decides how to render it — never crashes the request when the
LLM is unavailable.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# Public types
# ---------------------------------------------------------------


@dataclass
class AiResult:
    """Outcome of a single AI completion.

    Attributes:
        text: The generated text (empty if ``ok`` is False).
        model: The provider/model string actually used, or ``"none"``
            when no provider is configured.
        ok: Whether the call succeeded. ``False`` means callers should
            fall back to their deterministic local behaviour.
        cached: True when the response was served from the in-process
            cache instead of hitting the upstream API.
        error: Human-readable error reason when ``ok`` is False.
    """

    text: str
    model: str
    ok: bool
    cached: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------
# Cache
# ---------------------------------------------------------------


DEFAULT_TTL = 300  # 5 min; long enough to dedupe rapid-refresh loops.


class _TTLCache:
    """Tiny lock-free TTL cache. Good enough for sub-1k entries."""

    def __init__(self, max_entries: int = 256) -> None:
        self._store: dict[str, tuple[float, AiResult]] = {}
        self._max = max_entries

    def get(self, key: str) -> Optional[AiResult]:
        item = self._store.get(key)
        if not item:
            return None
        expires_at, value = item
        if expires_at < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: AiResult, ttl: int) -> None:
        if len(self._store) >= self._max:
            # Evict the soonest-to-expire entry; cheap and predictable.
            oldest = min(self._store.items(), key=lambda kv: kv[1][0])
            self._store.pop(oldest[0], None)
        self._store[key] = (time.time() + ttl, value)

    def clear(self) -> None:
        self._store.clear()


_cache = _TTLCache()


def _cache_key(provider: str, system: str, user: str, model: str) -> str:
    h = hashlib.sha256()
    h.update(provider.encode())
    h.update(b"\x00")
    h.update(model.encode())
    h.update(b"\x00")
    h.update(system.encode())
    h.update(b"\x00")
    h.update(user.encode())
    return h.hexdigest()


# ---------------------------------------------------------------
# Provider calls
# ---------------------------------------------------------------


async def _with_retry(
    fn: Callable[[], Awaitable[httpx.Response]],
    *,
    label: str,
    retries: int = 2,
    base_delay: float = 0.6,
) -> httpx.Response:
    """Retry transient failures (network, 5xx, 429) with capped backoff."""
    last_exc: Optional[BaseException] = None
    for attempt in range(retries + 1):
        try:
            resp = await fn()
            # 429 and 5xx → retryable; everything else returns as-is so the
            # caller can decide how loud to be about it.
            if resp.status_code < 500 and resp.status_code != 429:
                return resp
            if attempt == retries:
                return resp
            logger.warning(
                "AI %s returned %s, retrying (%d/%d)",
                label, resp.status_code, attempt + 1, retries,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt == retries:
                raise
            logger.warning(
                "AI %s network error (%s), retrying (%d/%d)",
                label, exc, attempt + 1, retries,
            )
        await asyncio.sleep(base_delay * (2 ** attempt))
    if last_exc:
        raise last_exc  # pragma: no cover (loop always returns or raises)
    raise RuntimeError("retry loop exhausted without a response")


async def _call_anthropic(
    system: str,
    user: str,
    *,
    max_tokens: int,
    temperature: float,
    timeout: float,
) -> str:
    headers = {
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": settings.anthropic_model,
        "max_tokens": max_tokens,
        "system": system,
        "temperature": temperature,
        "messages": [{"role": "user", "content": user}],
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await _with_retry(
            lambda: client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            ),
            label="anthropic",
        )
    resp.raise_for_status()
    data = resp.json()
    parts = data.get("content", [])
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()


async def _call_openai(
    system: str,
    user: str,
    *,
    max_tokens: int,
    temperature: float,
    timeout: float,
) -> str:
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await _with_retry(
            lambda: client.post(
                f"{settings.openai_base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            ),
            label="openai",
        )
    resp.raise_for_status()
    data = resp.json()
    return (data["choices"][0]["message"]["content"] or "").strip()


# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------


async def ai_complete(
    *,
    system: str,
    user: str,
    max_tokens: int = 900,
    temperature: float = 0.2,
    timeout: float = 30.0,
    cache_ttl: int = DEFAULT_TTL,
    label: str = "generic",
) -> AiResult:
    """Run a single LLM completion through the gateway.

    Returns an :class:`AiResult` rather than raising — callers should
    inspect ``result.ok`` and fall back to local content when it's
    False. ``timeout`` is the total wall-clock budget for the call
    (each attempt gets the full budget; with at most 2 retries that's
    a 3× upper bound, but the cumulative retry sleeps stay below 2s).
    """
    # Provider selection — Claude wins when both are set.
    if settings.anthropic_api_key:
        provider = "anthropic"
        model = settings.anthropic_model
    elif settings.openai_api_key:
        provider = "openai"
        model = settings.openai_model
    else:
        return AiResult(text="", model="none", ok=False, error="no_provider")

    key = _cache_key(provider, system, user, model)
    cached = _cache.get(key)
    if cached:
        return AiResult(
            text=cached.text,
            model=cached.model,
            ok=cached.ok,
            cached=True,
            error=cached.error,
        )

    try:
        if provider == "anthropic":
            text = await _call_anthropic(
                system, user,
                max_tokens=max_tokens, temperature=temperature, timeout=timeout,
            )
        else:
            text = await _call_openai(
                system, user,
                max_tokens=max_tokens, temperature=temperature, timeout=timeout,
            )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "AI %s (%s) HTTP %s: %s",
            label, provider, exc.response.status_code,
            exc.response.text[:200],
        )
        return AiResult(text="", model=model, ok=False, error=f"http_{exc.response.status_code}")
    except (httpx.TimeoutException, httpx.NetworkError) as exc:
        logger.warning("AI %s (%s) network: %s", label, provider, exc)
        return AiResult(text="", model=model, ok=False, error="timeout")
    except Exception as exc:  # noqa: BLE001
        logger.exception("AI %s (%s) unexpected failure", label, provider)
        return AiResult(text="", model=model, ok=False, error=str(exc)[:120])

    if not text:
        return AiResult(text="", model=model, ok=False, error="empty_response")

    result = AiResult(text=text, model=model, ok=True)
    _cache.set(key, result, cache_ttl)
    return result


def clear_cache() -> None:
    """Wipe the in-process AI cache. Useful in tests or admin tooling."""
    _cache.clear()


def has_provider() -> bool:
    return bool(settings.anthropic_api_key or settings.openai_api_key)


def active_model() -> str:
    if settings.anthropic_api_key:
        return settings.anthropic_model
    if settings.openai_api_key:
        return settings.openai_model
    return "none"
