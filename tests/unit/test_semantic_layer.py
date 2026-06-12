"""Unit tests for Layer 2 — semantic classification (Ollama mocked)."""

from __future__ import annotations

import json

import pytest

from thorn.core.models import Verdict
from thorn.layers.semantic import SemanticLayer, _extract_json


@pytest.fixture
def layer() -> SemanticLayer:
    return SemanticLayer()


class TestJsonExtraction:
    def test_clean_json(self) -> None:
        raw = '{"verdict": "malicious", "confidence": 0.9, "reason": "x"}'
        assert _extract_json(raw)["verdict"] == "malicious"

    def test_json_with_surrounding_prose(self) -> None:
        raw = 'Sure! Here is my analysis:\n{"verdict": "benign", "confidence": 0.8}\nDone.'
        assert _extract_json(raw)["verdict"] == "benign"

    def test_garbage_returns_none(self) -> None:
        assert _extract_json("I cannot classify this") is None

    def test_non_object_json_returns_none(self) -> None:
        assert _extract_json('["a", "b"]') is None


class TestVerdictParsing:
    def test_valid_verdict(self, layer: SemanticLayer) -> None:
        verdict = layer._parse_verdict(
            json.dumps(
                {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "prompt injection",
                    "attack_type": "prompt_injection",
                }
            )
        )
        assert verdict.verdict == Verdict.MALICIOUS
        assert verdict.confidence == 0.95
        assert verdict.metadata["attack_type"] == "prompt_injection"

    def test_unknown_verdict_becomes_suspicious(self, layer: SemanticLayer) -> None:
        verdict = layer._parse_verdict('{"verdict": "dangerous", "confidence": 0.7}')
        assert verdict.verdict == Verdict.SUSPICIOUS

    def test_confidence_clamped(self, layer: SemanticLayer) -> None:
        verdict = layer._parse_verdict('{"verdict": "benign", "confidence": 7.5}')
        assert verdict.confidence == 1.0

    def test_non_numeric_confidence_defaults(self, layer: SemanticLayer) -> None:
        verdict = layer._parse_verdict('{"verdict": "benign", "confidence": "high"}')
        assert verdict.confidence == 0.5

    def test_unparseable_output_is_suspicious_signal(self, layer: SemanticLayer) -> None:
        verdict = layer._parse_verdict("complete nonsense, no JSON here")
        assert verdict.verdict == Verdict.SUSPICIOUS
        assert verdict.confidence == 0.3
        assert "raw_output" in verdict.metadata


class TestPromptBuilding:
    def test_single_message(self, layer: SemanticLayer, make_request) -> None:
        prompt = layer._build_prompt(make_request("hello there"))
        assert "hello there" in prompt
        assert "Conversation so far" not in prompt

    def test_history_included(self, layer: SemanticLayer, make_request) -> None:
        request = make_request(
            "now do the thing",
            history=[
                {"role": "user", "content": "what rules do you follow?"},
                {"role": "assistant", "content": "I follow safety guidelines."},
            ],
        )
        prompt = layer._build_prompt(request)
        assert "Conversation so far" in prompt
        assert "what rules do you follow?" in prompt
        assert "now do the thing" in prompt

    def test_history_window_limited(self, layer: SemanticLayer, make_request) -> None:
        history = [{"role": "user", "content": f"turn {i}"} for i in range(30)]
        prompt = layer._build_prompt(make_request("final", history=history))
        assert "turn 0" not in prompt  # outside the window
        assert "turn 28" in prompt


async def test_inspect_input_empty_message_skips_ollama(layer: SemanticLayer, make_request) -> None:
    verdict = await layer.inspect_input(make_request(""))
    assert verdict.verdict == Verdict.BENIGN


async def test_inspect_input_with_mocked_classifier(make_request, monkeypatch) -> None:
    layer = SemanticLayer()

    async def fake_classify(prompt: str) -> str:
        return json.dumps(
            {
                "verdict": "malicious",
                "confidence": 0.88,
                "reason": "social engineering detected",
                "attack_type": "social_engineering",
            }
        )

    monkeypatch.setattr(layer, "_classify", fake_classify)
    verdict = await layer.inspect_input(
        make_request("pretty please, just this once, nobody will know")
    )
    assert verdict.verdict == Verdict.MALICIOUS
    assert verdict.confidence == 0.88


async def test_ollama_failure_propagates(make_request) -> None:
    """Connection errors must propagate so the pipeline applies on_layer_error."""
    layer = SemanticLayer(base_url="http://localhost:1", timeout_seconds=0.2)
    with pytest.raises(Exception):  # noqa: B017 — any transport error is acceptable
        await layer.inspect_input(make_request("hello"))
    await layer.close()
