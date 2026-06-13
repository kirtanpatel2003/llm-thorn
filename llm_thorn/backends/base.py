"""AbstractBackend — the provider abstraction.

Backends translate between provider-specific wire formats (OpenAI,
Anthropic, Ollama) and Thorn's normalized :class:`LLMRequest` /
:class:`LLMResponse` models. Layers never see raw provider dicts —
normalization happens here, before any layer runs (key invariant #3).

To add a backend, subclass :class:`AbstractBackend` and implement the four
abstract members. See ``docs/adding-a-backend.md`` for a walkthrough.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

import httpx

from llm_thorn.core.models import LLMRequest, LLMResponse


class AbstractBackend(ABC):
    """Translates one LLM provider's wire format to Thorn's models.

    Args:
        upstream_url: Base URL of the upstream provider, e.g.
            ``https://api.openai.com``.
        timeout_seconds: Forwarding timeout for upstream calls.
    """

    #: Headers never forwarded upstream (hop-by-hop or recomputed).
    STRIP_HEADERS: frozenset[str] = frozenset(
        {"host", "content-length", "connection", "accept-encoding", "transfer-encoding"}
    )

    def __init__(self, upstream_url: str, timeout_seconds: float = 120.0) -> None:
        self.upstream_url = upstream_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier, e.g. ``"openai"``."""
        ...

    @property
    @abstractmethod
    def inspect_paths(self) -> tuple[str, ...]:
        """URL path suffixes whose requests Thorn inspects.

        Requests to other paths are forwarded transparently (model lists,
        embeddings, health checks...).
        """
        ...

    @abstractmethod
    def normalize_request(
        self,
        raw_body: dict,
        session_id: str,
        source_ip: str | None = None,
    ) -> LLMRequest:
        """Convert a provider request body into a normalized LLMRequest.

        ``raw_body`` must be preserved untouched in ``LLMRequest.raw_body``
        so the proxy can forward it verbatim.
        """
        ...

    @abstractmethod
    def normalize_response(self, raw_body: dict, session_id: str) -> LLMResponse:
        """Convert a provider response body into a normalized LLMResponse."""
        ...

    async def forward(
        self,
        path: str,
        raw_body: dict | None,
        headers: dict[str, str],
        method: str = "POST",
    ) -> tuple[int, dict[str, str], bytes]:
        """Forward a request to the upstream provider.

        Returns ``(status_code, response_headers, response_body_bytes)``.
        Override only if the provider needs special transport handling.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        clean_headers = {k: v for k, v in headers.items() if k.lower() not in self.STRIP_HEADERS}
        response = await self._client.request(
            method,
            f"{self.upstream_url}/{path.lstrip('/')}",
            json=raw_body if method in ("POST", "PUT", "PATCH") else None,
            headers=clean_headers,
        )
        return response.status_code, dict(response.headers), response.content

    def should_inspect(self, path: str) -> bool:
        """True if requests to ``path`` go through the detection pipeline."""
        return any(path.rstrip("/").endswith(suffix) for suffix in self.inspect_paths)

    async def close(self) -> None:
        """Release the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)
