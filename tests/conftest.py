"""Shared fixtures for the Thorn test suite."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from llm_thorn.core.models import LLMRequest, LLMResponse
from llm_thorn.policy.schema import Policy, load_policy

#: A representative policy used across unit and integration tests.
#: The semantic and safety layers are disabled — tests must not require Ollama.
TEST_POLICY_YAML = """\
policy:
  name: test-policy
  version: 1.0.0
  description: policy used by the automated test suite

  layers:
    heuristic: true
    semantic: false
    context: true
    output: true
    safety: false

  rules:
    - id: block-heuristic-malicious
      description: block clear signature matches
      layer: heuristic
      condition:
        verdict: malicious
        confidence_above: 0.8
      action: block
      alert: true

    - id: warn-heuristic-suspicious
      description: log softer signature matches
      layer: heuristic
      condition:
        verdict: suspicious
        confidence_above: 0.5
      action: warn

    - id: block-context-malicious
      description: block attack trajectories
      layer: context
      condition:
        verdict: malicious
        confidence_above: 0.6
      action: block
      alert: true

    - id: terminate-context-runaway
      description: kill sessions with very high accumulated risk
      layer: context
      condition:
        verdict: malicious
        confidence_above: 0.6
        session_risk_above: 9.0
      action: terminate_session
      alert: true

    - id: block-output-malicious
      description: block leaked prompts and successful injections
      layer: output
      condition:
        verdict: malicious
        confidence_above: 0.8
      action: block
      alert: true

    - id: redact-output-pii
      description: redact PII from responses
      layer: output
      condition:
        verdict: suspicious
        confidence_above: 0.5
      action: redact

  defaults:
    on_layer_error: block
    max_session_turns: 50
    session_ttl_seconds: 3600
"""


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Fresh SQLite path per test."""
    return str(tmp_path / "thorn-test.db")


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    """The standard test policy, loaded through the real YAML loader."""
    path = tmp_path / "policy.yaml"
    path.write_text(TEST_POLICY_YAML)
    return load_policy(path)


@pytest.fixture
def policy_fail_open(tmp_path: Path) -> Policy:
    """Same policy but fail-open on layer errors."""
    path = tmp_path / "policy-open.yaml"
    path.write_text(TEST_POLICY_YAML.replace("on_layer_error: block", "on_layer_error: allow"))
    return load_policy(path)


RequestFactory = Callable[..., LLMRequest]


@pytest.fixture
def make_request() -> RequestFactory:
    """Factory for normalized LLMRequests with sensible defaults."""

    def _make(
        content: str,
        session_id: str = "test-session",
        system: str | None = None,
        history: list[dict] | None = None,
        model: str = "gpt-4o-mini",
    ) -> LLMRequest:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.extend(history or [])
        messages.append({"role": "user", "content": content})
        return LLMRequest(
            session_id=session_id,
            messages=messages,
            model=model,
            raw_body={"model": model, "messages": messages},
            timestamp=datetime.now(UTC),
        )

    return _make


ResponseFactory = Callable[..., LLMResponse]


@pytest.fixture
def make_response() -> ResponseFactory:
    """Factory for normalized LLMResponses."""

    def _make(content: str, session_id: str = "test-session") -> LLMResponse:
        return LLMResponse(
            session_id=session_id,
            content=content,
            raw_body={"choices": [{"message": {"role": "assistant", "content": content}}]},
            timestamp=datetime.now(UTC),
        )

    return _make
