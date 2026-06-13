"""TopicGuardLayer — the reference Thorn plugin.

A complete, working community layer that restricts conversations to a
configured list of allowed topics. Read this file top to bottom if you are
writing your first Thorn layer; it demonstrates every part of the plugin
contract:

  - subclassing :class:`llm_thorn.BaseLayer`
  - implementing ``name`` and ``inspect_input``
  - returning well-formed :class:`LayerVerdict` objects with useful metadata
  - staying stateless (session state belongs to SessionContext)

The detection approach here is deliberately simple keyword matching — the
point of this plugin is to show the *shape* of a layer, not to be clever.
Replace ``_score_topics`` with embeddings, an LLM call, or anything else
in your own layer.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from llm_thorn.core.models import LayerVerdict, LLMRequest, Verdict
from llm_thorn.layers.base import BaseLayer

if TYPE_CHECKING:
    from llm_thorn.core.session import SessionContext

#: Default topic vocabulary. Each topic maps to keywords that indicate it.
#: Real deployments pass their own topics to the constructor.
DEFAULT_TOPICS: dict[str, list[str]] = {
    "orders": ["order", "shipping", "delivery", "tracking", "package", "refund", "return"],
    "billing": ["invoice", "payment", "charge", "subscription", "billing", "price", "cost"],
    "account": ["password", "login", "account", "email", "profile", "settings"],
}

#: Fraction of recognizable words that must be on-topic for a clear pass.
_ON_TOPIC_THRESHOLD = 0.05


class TopicGuardLayer(BaseLayer):
    """Restricts conversations to an allowed set of topics.

    Verdicts:
        - **benign** — at least one allowed topic is clearly present.
        - **suspicious** — no allowed topic detected, but the message is
          short or vague enough that it may be a follow-up ("yes please",
          "what about the second one?").
        - **malicious** — a longer message with zero overlap with any
          allowed topic: clearly steering the conversation off the rails.

    Args:
        topics: Mapping of topic name to indicator keywords. Defaults to
            a small e-commerce vocabulary (see ``DEFAULT_TOPICS``).
        min_words_for_verdict: Messages shorter than this are never flagged
            malicious — follow-ups and confirmations are legitimate.

    Policy usage::

        plugins:
          - "llm_thorn_topic_guard.TopicGuardLayer"

        rules:
          - id: block-off-topic
            layer: topic_guard
            condition:
              verdict: malicious
              confidence_above: 0.7
            action: block
    """

    def __init__(
        self,
        topics: dict[str, list[str]] | None = None,
        min_words_for_verdict: int = 8,
    ) -> None:
        self.topics = topics or DEFAULT_TOPICS
        self.min_words_for_verdict = min_words_for_verdict
        # Compile one pattern per topic at construction time — layers run
        # on every request, so do expensive setup exactly once.
        self._patterns: dict[str, re.Pattern[str]] = {
            topic: re.compile(
                r"\b(?:" + "|".join(re.escape(k) for k in keywords) + r")\b",
                re.IGNORECASE,
            )
            for topic, keywords in self.topics.items()
        }

    @property
    def name(self) -> str:
        """Identifier used in verdicts, audit logs, and policy rules."""
        return "topic_guard"

    def inspect_input(
        self,
        request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Classify whether the latest user message is on an allowed topic."""
        text = request.last_user_message
        if not text:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=1.0,
                reason="no user message content to inspect",
            )

        matched = self._score_topics(text)
        word_count = len(text.split())

        if matched:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.9,
                reason=f"on-topic: {', '.join(sorted(matched))}",
                metadata={"topics": sorted(matched)},
            )

        if word_count < self.min_words_for_verdict:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.SUSPICIOUS,
                confidence=0.4,
                reason="short message with no recognizable topic — possible follow-up",
                metadata={"topics": [], "word_count": word_count},
            )

        return LayerVerdict(
            layer=self.name,
            verdict=Verdict.MALICIOUS,
            confidence=0.75,
            reason="message has no overlap with any allowed topic",
            matched_rule="off_topic",
            metadata={"topics": [], "word_count": word_count},
        )

    def _score_topics(self, text: str) -> set[str]:
        """Return the set of allowed topics present in the text."""
        return {topic for topic, pattern in self._patterns.items() if pattern.search(text)}
