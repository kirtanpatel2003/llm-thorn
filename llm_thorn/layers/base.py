"""The BaseLayer contribution interface.

This interface is stable within a major version. Changing the signature of
``inspect_input`` or ``inspect_output`` requires a major version bump and a
migration guide, because it breaks every community plugin.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from llm_thorn.core.models import LayerVerdict, LLMRequest, LLMResponse, Verdict

if TYPE_CHECKING:
    from llm_thorn.core.session import SessionContext


class BaseLayer(ABC):
    """The contribution interface for Thorn.

    Every detection layer — built-in or community plugin — subclasses this.
    The interface is intentionally minimal so plugins are easy to write.

    Layers are stateless. Session state lives in SessionContext
    (``llm_thorn/core/session.py``). Request it via the ``session`` parameter if
    your layer needs conversation history.

    To publish a community layer:
        1. Subclass BaseLayer
        2. Implement ``name``, ``inspect_input``, and/or ``inspect_output``
        3. Publish to PyPI as ``llm-thorn-<your-layer-name>``
        4. Users add it to their policy.yaml under ``plugins:``

    Example plugin entry in policy.yaml::

        plugins:
          - "llm_thorn_pii_guard.PIIGuardLayer"
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier used in verdicts, logs, and policy rules."""

    def inspect_input(
        self,
        request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Called before the request reaches the LLM. Override to inspect inputs."""
        return LayerVerdict(
            layer=self.name,
            verdict=Verdict.BENIGN,
            confidence=1.0,
            reason="layer does not inspect inputs",
            matched_rule=None,
        )

    def inspect_output(
        self,
        response: LLMResponse,
        original_request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Called before the response reaches the client. Override to inspect outputs."""
        return LayerVerdict(
            layer=self.name,
            verdict=Verdict.BENIGN,
            confidence=1.0,
            reason="layer does not inspect outputs",
            matched_rule=None,
        )
