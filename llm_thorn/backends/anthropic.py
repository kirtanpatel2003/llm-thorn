"""Anthropic backend — native Messages API support.

Anthropic's wire format differs from OpenAI's in two ways that matter to
Thorn: the system prompt is a top-level ``system`` parameter (not a message),
and response content is a list of typed blocks. Normalization folds the
system parameter into the message list so layers (e.g. the output layer's
system-prompt-leak detection) see a uniform shape.
"""

from __future__ import annotations

from llm_thorn.backends.base import AbstractBackend
from llm_thorn.core.models import LLMRequest, LLMResponse


class AnthropicBackend(AbstractBackend):
    """Backend for the Anthropic Messages API (api.anthropic.com)."""

    @property
    def name(self) -> str:
        """Backend identifier."""
        return "anthropic"

    @property
    def inspect_paths(self) -> tuple[str, ...]:
        """The Messages API is inspected; everything else passes through."""
        return ("/messages",)

    def normalize_request(
        self,
        raw_body: dict,
        session_id: str,
        source_ip: str | None = None,
    ) -> LLMRequest:
        """Normalize an Anthropic Messages request body.

        The top-level ``system`` parameter becomes a leading system message
        so all layers see OpenAI-shaped message lists.
        """
        messages: list[dict] = []
        system = raw_body.get("system")
        if isinstance(system, str) and system:
            messages.append({"role": "system", "content": system})
        elif isinstance(system, list):  # system content blocks
            text = " ".join(
                block.get("text", "")
                for block in system
                if isinstance(block, dict) and block.get("type") == "text"
            )
            if text:
                messages.append({"role": "system", "content": text})

        for message in raw_body.get("messages", []):
            content = message.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                )
            messages.append({"role": message.get("role", "user"), "content": content})

        return LLMRequest(
            session_id=session_id,
            messages=messages,
            model=str(raw_body.get("model", "unknown")),
            raw_body=raw_body,
            timestamp=self._now(),
            source_ip=source_ip,
        )

    def normalize_response(self, raw_body: dict, session_id: str) -> LLMResponse:
        """Extract assistant text from an Anthropic Messages response."""
        content = " ".join(
            block.get("text", "")
            for block in raw_body.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        )
        return LLMResponse(
            session_id=session_id,
            content=content,
            raw_body=raw_body,
            timestamp=self._now(),
        )
