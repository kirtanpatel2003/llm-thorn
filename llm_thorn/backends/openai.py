"""OpenAI backend — also covers every OpenAI-compatible endpoint.

Works with api.openai.com, Azure OpenAI (chat completions route), and the
many providers that speak the OpenAI wire format (Together, Groq, vLLM,
LiteLLM, OpenRouter...). Point ``--upstream`` at any of them.
"""

from __future__ import annotations

from llm_thorn.backends.base import AbstractBackend
from llm_thorn.core.models import LLMRequest, LLMResponse


class OpenAIBackend(AbstractBackend):
    """Backend for OpenAI and OpenAI-compatible chat completion APIs."""

    @property
    def name(self) -> str:
        """Backend identifier."""
        return "openai"

    @property
    def inspect_paths(self) -> tuple[str, ...]:
        """Chat completions are inspected; everything else passes through."""
        return ("/chat/completions", "/completions", "/responses")

    def normalize_request(
        self,
        raw_body: dict,
        session_id: str,
        source_ip: str | None = None,
    ) -> LLMRequest:
        """Normalize an OpenAI chat completions request body."""
        return LLMRequest(
            session_id=session_id,
            messages=list(raw_body.get("messages", [])),
            model=str(raw_body.get("model", "unknown")),
            raw_body=raw_body,
            timestamp=self._now(),
            source_ip=source_ip,
        )

    def normalize_response(self, raw_body: dict, session_id: str) -> LLMResponse:
        """Extract assistant text from an OpenAI chat completions response."""
        content = ""
        choices = raw_body.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            raw_content = message.get("content")
            if isinstance(raw_content, str):
                content = raw_content
            elif isinstance(raw_content, list):  # content-part responses
                content = " ".join(
                    part.get("text", "")
                    for part in raw_content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
        return LLMResponse(
            session_id=session_id,
            content=content,
            raw_body=raw_body,
            timestamp=self._now(),
        )
