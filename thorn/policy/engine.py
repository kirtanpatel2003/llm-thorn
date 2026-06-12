"""Policy evaluation runtime.

The engine takes the verdicts every layer produced for a request (or
response), matches them against the rules in the loaded policy, and returns
a single :class:`~thorn.core.models.PolicyDecision`.

When multiple rules fire, the most severe action wins:
``terminate > block > redact > warn > allow``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from thorn.core.models import Action, LayerVerdict, PolicyDecision, Verdict
from thorn.core.session import SessionContext
from thorn.policy.schema import Policy, PolicyRule, RuleAction

logger = logging.getLogger("thorn.policy")
alert_logger = logging.getLogger("thorn.alerts")

#: Severity order for resolving conflicts between fired rules.
_ACTION_SEVERITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.WARN: 1,
    Action.REDACT: 2,
    Action.BLOCK: 3,
    Action.TERMINATE: 4,
}

#: Map YAML rule actions to runtime actions.
_RULE_ACTION_TO_ACTION: dict[RuleAction, Action] = {
    RuleAction.ALLOW: Action.ALLOW,
    RuleAction.WARN: Action.WARN,
    RuleAction.REDACT: Action.REDACT,
    RuleAction.BLOCK: Action.BLOCK,
    RuleAction.TERMINATE_SESSION: Action.TERMINATE,
}

#: Verdict ordering used when matching rule conditions: a rule that matches
#: "suspicious" also matches "malicious" — a stricter signal always satisfies
#: a looser condition.
_VERDICT_SEVERITY: dict[str, int] = {
    Verdict.BENIGN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.MALICIOUS: 2,
}


class PolicyEngine:
    """Evaluates layer verdicts against a validated policy.

    One engine instance is created per loaded policy and shared across all
    requests. It is stateless between calls.

    Example::

        engine = PolicyEngine(policy)
        decision = engine.evaluate(verdicts, session)
        if decision.action == Action.BLOCK:
            ...
    """

    def __init__(self, policy: Policy) -> None:
        """Create an engine bound to a validated policy."""
        self.policy = policy

    def evaluate(
        self,
        verdicts: list[LayerVerdict],
        session: SessionContext | None = None,
    ) -> PolicyDecision:
        """Match verdicts against policy rules and return the final decision.

        Args:
            verdicts: All verdicts produced by the layer stack for this
                request or response.
            session: Session snapshot, required for rules that use
                ``session_risk_above`` or ``turn_count_above`` conditions.

        Returns:
            A :class:`PolicyDecision` whose action is the most severe among
            all fired rules, or ``allow`` if nothing fired.
        """
        fired: list[tuple[PolicyRule, Action]] = []
        for rule in self.policy.rules:
            if self._rule_matches(rule, verdicts, session):
                action = _RULE_ACTION_TO_ACTION[rule.action]
                fired.append((rule, action))
                if rule.alert:
                    alert_logger.warning(
                        "policy alert: rule=%s action=%s session=%s",
                        rule.id,
                        action,
                        session.session_id if session else "unknown",
                    )

        if fired:
            final_action = max((action for _, action in fired), key=_ACTION_SEVERITY.__getitem__)
            triggered_by = [rule.id for rule, _ in fired]
        else:
            final_action = Action.ALLOW
            triggered_by = []

        return PolicyDecision(
            action=final_action,
            triggered_by=triggered_by,
            verdicts=verdicts,
            session_id=session.session_id if session else "unknown",
            timestamp=datetime.now(UTC),
            audit_entry_id=str(uuid.uuid4()),
        )

    def decision_for_layer_error(
        self,
        layer_name: str,
        error: Exception,
        verdicts: list[LayerVerdict],
        session: SessionContext | None = None,
    ) -> PolicyDecision:
        """Build the decision applied when a layer raised at runtime.

        Honors the policy's ``defaults.on_layer_error`` setting: fail-open
        (allow) or fail-closed (block). The error is logged either way —
        a layer exception must never crash the proxy.
        """
        logger.error("layer %s raised during inspection: %s", layer_name, error, exc_info=error)
        mode = self.policy.defaults.on_layer_error
        action = Action.ALLOW if mode == "allow" else Action.BLOCK
        return PolicyDecision(
            action=action,
            triggered_by=[f"on_layer_error:{layer_name}"],
            verdicts=verdicts,
            session_id=session.session_id if session else "unknown",
            timestamp=datetime.now(UTC),
            audit_entry_id=str(uuid.uuid4()),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rule_matches(
        self,
        rule: PolicyRule,
        verdicts: list[LayerVerdict],
        session: SessionContext | None,
    ) -> bool:
        """Check whether any verdict from the rule's layer satisfies it."""
        condition = rule.condition

        for verdict in verdicts:
            if verdict.layer != rule.layer:
                continue

            if condition.verdict is not None:
                required = _VERDICT_SEVERITY.get(condition.verdict, 0)
                actual = _VERDICT_SEVERITY.get(verdict.verdict, 0)
                if actual < required:
                    continue
            elif verdict.verdict == Verdict.BENIGN:
                # Rules without an explicit verdict condition never fire
                # on benign verdicts.
                continue

            if verdict.confidence < condition.confidence_above:
                continue

            if condition.session_risk_above is not None and (
                session is None or session.risk_score <= condition.session_risk_above
            ):
                continue

            if condition.turn_count_above is not None and (
                session is None or session.turn_count <= condition.turn_count_above
            ):
                continue

            return True
        return False
