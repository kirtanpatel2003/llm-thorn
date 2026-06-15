"""Unit tests for the content-safety layer (Ollama judge mocked)."""

from __future__ import annotations

import json

import pytest

from llm_thorn.core.models import Verdict
from llm_thorn.layers.safety import SafetyLayer, _extract_json


@pytest.fixture
def layer() -> SafetyLayer:
    return SafetyLayer()


class TestVerdictParsing:
    def test_harmful_response_flagged(self, layer: SafetyLayer) -> None:
        verdict = layer._parse_verdict(
            json.dumps(
                {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "step-by-step explosive synthesis",
                    "category": "explosives",
                }
            )
        )
        assert verdict.verdict == Verdict.MALICIOUS
        assert verdict.confidence == 0.95
        assert verdict.metadata["category"] == "explosives"
        assert verdict.matched_rule == "explosives"

    def test_benign_response(self, layer: SafetyLayer) -> None:
        verdict = layer._parse_verdict(
            json.dumps({"verdict": "benign", "confidence": 0.9, "category": "none"})
        )
        assert verdict.verdict == Verdict.BENIGN
        assert verdict.matched_rule is None  # "none" category is not a rule hit

    def test_unknown_verdict_becomes_suspicious(self, layer: SafetyLayer) -> None:
        verdict = layer._parse_verdict('{"verdict": "dangerous", "confidence": 0.7}')
        assert verdict.verdict == Verdict.SUSPICIOUS

    def test_confidence_clamped(self, layer: SafetyLayer) -> None:
        verdict = layer._parse_verdict('{"verdict": "malicious", "confidence": 5}')
        assert verdict.confidence == 1.0

    def test_unparseable_is_suspicious_not_silent_pass(self, layer: SafetyLayer) -> None:
        """A safety check must not silently pass when it can't read the judgment."""
        verdict = layer._parse_verdict("the judge rambled with no json")
        assert verdict.verdict == Verdict.SUSPICIOUS
        assert verdict.confidence == 0.3


class TestJsonExtraction:
    def test_clean(self) -> None:
        assert _extract_json('{"verdict": "benign"}')["verdict"] == "benign"

    def test_surrounded_by_prose(self) -> None:
        raw = 'Here is my verdict:\n{"verdict": "malicious", "confidence": 0.8}\nDone'
        assert _extract_json(raw)["verdict"] == "malicious"

    def test_garbage_returns_none(self) -> None:
        assert _extract_json("no json here") is None


async def test_empty_response_skips_judge(layer: SafetyLayer, make_request, make_response) -> None:
    verdict = await layer.inspect_output(make_response(""), make_request("hi"))
    assert verdict.verdict == Verdict.BENIGN


async def test_inspect_output_with_mocked_judge(make_request, make_response, monkeypatch) -> None:
    layer = SafetyLayer()

    async def fake_judge(content: str) -> str:
        return json.dumps(
            {
                "verdict": "malicious",
                "confidence": 0.9,
                "reason": "actionable weapon instructions",
                "category": "weapons",
            }
        )

    monkeypatch.setattr(layer, "_judge", fake_judge)
    verdict = await layer.inspect_output(
        make_response("Here is how to build it..."), make_request("...")
    )
    assert verdict.verdict == Verdict.MALICIOUS
    assert verdict.metadata["category"] == "weapons"


async def test_judge_failure_propagates(make_request, make_response) -> None:
    """Connection errors must propagate so the pipeline applies on_layer_error."""
    layer = SafetyLayer(base_url="http://localhost:1", timeout_seconds=0.2)
    with pytest.raises(Exception):  # noqa: B017 — any transport error is acceptable
        await layer.inspect_output(make_response("some response"), make_request("hi"))
    await layer.close()


def test_layer_name(layer: SafetyLayer) -> None:
    assert layer.name == "safety"
