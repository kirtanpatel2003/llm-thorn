"""Mode 2 — the Python SDK wrapper.

Wraps an OpenAI (or OpenAI-compatible) client so every chat completion call
runs through the full Thorn detection pipeline — same layers, same policy,
same audit log as the reverse proxy.

Usage::

    import openai
    from thorn import guard

    client = guard(openai.OpenAI(), policy="./policy.yaml")
    # behaves exactly like the normal client:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hello"}],
    )

Blocked requests raise :class:`ThornBlocked` instead of reaching the LLM.
Pass ``thorn_session_id="..."`` to ``create`` to group calls into one
conversation for multi-turn tracking; otherwise all calls through one
wrapped client share a session.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

from thorn.backends.openai import OpenAIBackend
from thorn.core.models import Action, PolicyDecision
from thorn.core.pipeline import DetectionPipeline
from thorn.policy.schema import Policy, load_policy


class ThornBlocked(Exception):
    """Raised when the policy blocks a request or response.

    Attributes:
        decision: The full :class:`PolicyDecision`, including which rules
            fired and the audit entry id.
    """

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(
            f"blocked by Thorn policy (action={decision.action}, "
            f"rules={decision.triggered_by}, audit={decision.audit_entry_id})"
        )


def guard(
    client: Any,  # any OpenAI-compatible client; typed Any to avoid a hard dependency
    policy: str | Policy,
    db_path: str = "./thorn.db",
    session_id: str | None = None,
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3.2",
) -> GuardedClient:
    """Wrap an OpenAI-compatible client with the Thorn detection pipeline.

    Args:
        client: An ``openai.OpenAI()`` instance or any client exposing
            ``chat.completions.create(**kwargs)``.
        policy: Path to a policy YAML file, or an already-loaded Policy.
        db_path: SQLite path for sessions + audit log.
        session_id: Fixed session id for all calls through this wrapper.
            Defaults to a fresh UUID per wrapper.
        ollama_url: Ollama URL for the semantic layer.
        ollama_model: Ollama model for the semantic layer.

    Returns:
        A :class:`GuardedClient` that proxies every attribute of the
        original client and intercepts ``chat.completions.create``.
    """
    loaded = load_policy(policy) if isinstance(policy, str) else policy
    pipeline = DetectionPipeline(
        loaded, db_path=db_path, ollama_url=ollama_url, ollama_model=ollama_model
    )
    return GuardedClient(client, pipeline, session_id or f"sdk-{uuid.uuid4()}")


class GuardedClient:
    """Transparent wrapper: all attributes proxy to the wrapped client.

    Only ``.chat.completions.create`` is intercepted.
    """

    def __init__(self, client: Any, pipeline: DetectionPipeline, session_id: str) -> None:
        self._client = client
        self._pipeline = pipeline
        self._session_id = session_id
        # Normalization only — this backend instance never forwards.
        self._normalizer = OpenAIBackend("https://unused.invalid")

    def __getattr__(self, name: str) -> Any:
        if name == "chat":
            return _GuardedChat(self)
        return getattr(self._client, name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _create(self, **kwargs: Any) -> Any:
        """Inspected replacement for chat.completions.create."""
        session_id = kwargs.pop("thorn_session_id", self._session_id)
        raw_body = {k: v for k, v in kwargs.items() if _jsonable(v)}
        request = self._normalizer.normalize_request(raw_body, session_id)

        result = _run(self._pipeline.inspect_request(request))
        if result.blocked:
            raise ThornBlocked(result.decision)

        response = self._client.chat.completions.create(**kwargs)

        response_body = response.model_dump() if hasattr(response, "model_dump") else dict(response)
        llm_response = self._normalizer.normalize_response(response_body, session_id)
        out = _run(self._pipeline.inspect_response(llm_response, request, result))
        if out.blocked:
            raise ThornBlocked(out.decision)
        if out.decision.action == Action.REDACT and out.redacted_content is not None:
            _write_content(response, out.redacted_content)
        return response


class _GuardedChat:
    def __init__(self, guarded: GuardedClient) -> None:
        self._guarded = guarded

    @property
    def completions(self) -> _GuardedCompletions:
        return _GuardedCompletions(self._guarded)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._guarded._client.chat, name)


class _GuardedCompletions:
    def __init__(self, guarded: GuardedClient) -> None:
        self._guarded = guarded

    def create(self, **kwargs: Any) -> Any:
        """Inspected chat completion call. Same signature as the SDK's."""
        return self._guarded._create(**kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._guarded._client.chat.completions, name)


def _run(coro: Any) -> Any:
    """Run a pipeline coroutine from sync code.

    The SDK wrapper targets synchronous clients. Calling it from inside a
    running event loop raises a clear error instead of deadlocking — use the
    proxy or middleware modes in async applications.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError(
        "thorn.guard() wraps synchronous clients and cannot be called from a "
        "running event loop. In async applications, use the reverse proxy "
        "(thorn start) or ThornMiddleware instead."
    )


def _write_content(response: Any, content: str) -> None:
    """Best-effort write of redacted content back onto the SDK response object."""
    with contextlib.suppress(AttributeError, IndexError):
        response.choices[0].message.content = content


def _jsonable(value: Any) -> bool:
    """True if a kwarg belongs in the raw request body we hash and inspect."""
    return isinstance(value, str | int | float | bool | list | dict | type(None))
