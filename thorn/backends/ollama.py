"""Ollama backend — guard locally hosted models.

Inspects Ollama's ``/api/chat`` endpoint. ``/api/generate`` (raw prompt
completion) is normalized as a single-message conversation.
"""

from __future__ import annotations

from thorn.backends.base import AbstractBackend
from thorn.core.models import LLMRequest, LLMResponse


class OllamaBackend(AbstractBackend):
    """Backend for a local or remote Ollama server."""

    @property
    def name(self) -> str:
        """Backend identifier."""
        return "ollama"

    @property
    def inspect_paths(self) -> tuple[str, ...]:
        """Chat and generate endpoints are inspected."""
        return ("/api/chat", "/api/generate")

    def normalize_request(
        self,
        raw_body: dict,
        session_id: str,
        source_ip: str | None = None,
    ) -> LLMRequest:
        """Normalize an Ollama chat or generate request body."""
        if "messages" in raw_body:
            messages = list(raw_body.get("messages", []))
        else:  # /api/generate: single prompt, optional system
            messages = []
            system = raw_body.get("system")
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": raw_body.get("prompt", "")})

        return LLMRequest(
            session_id=session_id,
            messages=messages,
            model=str(raw_body.get("model", "unknown")),
            raw_body=raw_body,
            timestamp=self._now(),
            source_ip=source_ip,
        )

    def normalize_response(self, raw_body: dict, session_id: str) -> LLMResponse:
        """Extract assistant text from an Ollama chat or generate response."""
        content = ""
        if "message" in raw_body:  # /api/chat
            content = raw_body.get("message", {}).get("content", "")
        elif "response" in raw_body:  # /api/generate
            content = raw_body.get("response", "")
        return LLMResponse(
            session_id=session_id,
            content=content,
            raw_body=raw_body,
            timestamp=self._now(),
        )
