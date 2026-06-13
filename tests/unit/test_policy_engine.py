"""Unit tests for the policy schema, loader, and evaluation engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from llm_thorn.core.models import Action, LayerVerdict, Verdict
from llm_thorn.core.session import SessionContext
from llm_thorn.policy.engine import PolicyEngine
from llm_thorn.policy.schema import PolicyError, load_policy


def _verdict(
    layer: str = "heuristic",
    verdict: str = Verdict.MALICIOUS,
    confidence: float = 0.9,
) -> LayerVerdict:
    return LayerVerdict(layer=layer, verdict=verdict, confidence=confidence, reason="test")


def _session(risk: float = 0.0, turns: int = 0) -> SessionContext:
    now = datetime.now(UTC)
    return SessionContext(
        session_id="s1",
        created_at=now,
        last_active=now,
        turn_count=turns,
        risk_score=risk,
        terminated=False,
    )


class TestSchemaValidation:
    def test_valid_policy_loads(self, policy) -> None:
        assert policy.name == "test-policy"
        assert len(policy.rules) == 6

    def test_missing_file(self) -> None:
        with pytest.raises(PolicyError, match="not found"):
            load_policy("/nonexistent/policy.yaml")

    def test_invalid_yaml(self, tmp_path) -> None:
        path = tmp_path / "broken.yaml"
        path.write_text("policy: [unclosed")
        with pytest.raises(PolicyError, match="not valid YAML"):
            load_policy(path)

    def test_missing_required_field_names_the_field(self, tmp_path) -> None:
        path = tmp_path / "incomplete.yaml"
        path.write_text("policy:\n  name: x\n")  # missing version
        with pytest.raises(PolicyError, match="policy.version"):
            load_policy(path)

    def test_bad_action_names_the_rule(self, tmp_path) -> None:
        path = tmp_path / "bad-action.yaml"
        path.write_text(
            "policy:\n"
            "  name: x\n"
            "  version: 1.0.0\n"
            "  rules:\n"
            "    - id: r1\n"
            "      layer: heuristic\n"
            "      condition: {verdict: malicious}\n"
            "      action: obliterate\n"
        )
        with pytest.raises(PolicyError, match="action"):
            load_policy(path)

    def test_duplicate_rule_ids_rejected(self, tmp_path) -> None:
        path = tmp_path / "dupes.yaml"
        path.write_text(
            "policy:\n"
            "  name: x\n"
            "  version: 1.0.0\n"
            "  rules:\n"
            "    - {id: r1, layer: heuristic, condition: {verdict: malicious}, action: block}\n"
            "    - {id: r1, layer: output, condition: {verdict: malicious}, action: block}\n"
        )
        with pytest.raises(PolicyError, match="duplicate rule id"):
            load_policy(path)

    def test_bad_plugin_spec_rejected(self, tmp_path) -> None:
        path = tmp_path / "bad-plugin.yaml"
        path.write_text("policy:\n  name: x\n  version: 1.0.0\n  plugins:\n    - justamodule\n")
        with pytest.raises(PolicyError, match="package.ClassName"):
            load_policy(path)

    def test_unknown_keys_rejected(self, tmp_path) -> None:
        path = tmp_path / "extra.yaml"
        path.write_text("policy:\n  name: x\n  version: 1.0.0\n  surprises: true\n")
        with pytest.raises(PolicyError, match="surprises"):
            load_policy(path)


class TestRuleEvaluation:
    def test_no_verdicts_allows(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate([], _session())
        assert decision.action == Action.ALLOW
        assert decision.triggered_by == []

    def test_benign_verdicts_allow(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate(
            [_verdict(verdict=Verdict.BENIGN, confidence=1.0)], _session()
        )
        assert decision.action == Action.ALLOW

    def test_malicious_heuristic_blocks(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate([_verdict(confidence=0.9)], _session())
        assert decision.action == Action.BLOCK
        assert "block-heuristic-malicious" in decision.triggered_by

    def test_confidence_threshold_respected(self, policy) -> None:
        # 0.4 is below both the block (0.8) and warn (0.5) thresholds.
        decision = PolicyEngine(policy).evaluate([_verdict(confidence=0.4)], _session())
        assert decision.action == Action.ALLOW
        # 0.5 clears warn but not block: malicious satisfies the looser
        # suspicious condition, so the warn rule fires.
        decision = PolicyEngine(policy).evaluate([_verdict(confidence=0.5)], _session())
        assert decision.action == Action.WARN

    def test_suspicious_warns(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate(
            [_verdict(verdict=Verdict.SUSPICIOUS, confidence=0.6)], _session()
        )
        assert decision.action == Action.WARN

    def test_malicious_satisfies_suspicious_condition(self, policy) -> None:
        """A stricter verdict must satisfy a looser rule condition."""
        decision = PolicyEngine(policy).evaluate(
            [_verdict(verdict=Verdict.MALICIOUS, confidence=0.6)], _session()
        )
        # malicious@0.6 doesn't meet block (0.8) but does meet warn (0.5, suspicious)
        assert decision.action == Action.WARN

    def test_most_severe_action_wins(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate(
            [
                _verdict(layer="heuristic", verdict=Verdict.SUSPICIOUS, confidence=0.6),
                _verdict(layer="output", verdict=Verdict.MALICIOUS, confidence=0.9),
            ],
            _session(),
        )
        assert decision.action == Action.BLOCK  # block beats warn

    def test_session_risk_condition(self, policy) -> None:
        verdict = _verdict(layer="context", verdict=Verdict.MALICIOUS, confidence=0.9)
        low = PolicyEngine(policy).evaluate([verdict], _session(risk=5.0))
        high = PolicyEngine(policy).evaluate([verdict], _session(risk=9.5))
        assert low.action == Action.BLOCK  # block rule, terminate threshold not met
        assert high.action == Action.TERMINATE

    def test_session_condition_without_session_never_fires(self, policy) -> None:
        verdict = _verdict(layer="context", verdict=Verdict.MALICIOUS, confidence=0.9)
        decision = PolicyEngine(policy).evaluate([verdict], None)
        # terminate rule (needs session_risk) can't fire; plain block rule can
        assert decision.action == Action.BLOCK

    def test_layer_mismatch_does_not_fire(self, policy) -> None:
        decision = PolicyEngine(policy).evaluate(
            [_verdict(layer="semantic", confidence=0.99)], _session()
        )
        assert decision.action == Action.ALLOW  # test policy has no semantic rules

    def test_decision_carries_verdicts_and_ids(self, policy) -> None:
        verdicts = [_verdict(confidence=0.9)]
        decision = PolicyEngine(policy).evaluate(verdicts, _session())
        assert decision.verdicts == verdicts
        assert decision.session_id == "s1"
        assert decision.audit_entry_id


class TestLayerErrorHandling:
    def test_fail_closed(self, policy) -> None:
        decision = PolicyEngine(policy).decision_for_layer_error(
            "semantic", RuntimeError("ollama down"), [], _session()
        )
        assert decision.action == Action.BLOCK
        assert decision.triggered_by == ["on_layer_error:semantic"]

    def test_fail_open(self, policy_fail_open) -> None:
        decision = PolicyEngine(policy_fail_open).decision_for_layer_error(
            "semantic", RuntimeError("ollama down"), [], _session()
        )
        assert decision.action == Action.ALLOW
