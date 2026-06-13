"""Layer 3 — Multi-turn context and trajectory risk scoring.

This is the layer that catches what every single-turn tool misses. It does
not judge the current message in isolation — it judges the *trajectory* of
the session. "What is your system prompt?" from a fresh session is mild
curiosity (2/10). The same question after four turns of probing, roleplay
requests, and boundary testing is an attack in progress (9/10).

Risk accumulates in the session store across turns (written back by the
pipeline from this layer's ``risk_delta`` metadata). Sessions expire on TTL
or max turns, so suspicion decays with genuine inactivity.

Performance budget: < 10ms — the session snapshot is already loaded; this
layer does pattern checks and arithmetic only. No I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from llm_thorn.core.models import LayerName, LayerVerdict, LLMRequest, Verdict
from llm_thorn.layers.base import BaseLayer

if TYPE_CHECKING:
    from llm_thorn.core.session import SessionContext


@dataclass(frozen=True)
class ProbeSignal:
    """A lightweight conversational probe indicator with a risk weight."""

    name: str
    pattern: re.Pattern[str]
    weight: float


def _probe(name: str, pattern: str, weight: float) -> ProbeSignal:
    return ProbeSignal(name, re.compile(pattern, re.IGNORECASE), weight)


#: Soft probing signals. Individually none of these is an attack — that is
#: the point. Their *accumulation* across a session is the attack signature.
PROBE_SIGNALS: list[ProbeSignal] = [
    _probe(
        "rules_curiosity",
        r"\bwhat\s+(?:rules|guidelines|restrictions|limitations)\s+do\s+you\b",
        1.0,
    ),
    _probe(
        "capability_probing",
        r"\bwhat\s+(?:can'?t|cannot|are\s+you\s+(?:not\s+)?(?:able|allowed))\s+(?:you\s+)?(?:to\s+)?(?:do|say|discuss)\b",
        1.0,
    ),
    _probe("roleplay_request", r"\b(?:roleplay|role\s+play|pretend\s+to\s+be|act\s+as)\b", 1.0),
    _probe(
        "hypothetical_framing",
        r"\b(?:hypothetically|in\s+theory|theoretically|imagine\s+if|what\s+if\s+you)\b",
        0.75,
    ),
    _probe("restriction_questioning", r"\bwhy\s+(?:can'?t|won'?t|don'?t)\s+you\b", 0.75),
    _probe(
        "prompt_curiosity",
        r"\b(?:system\s+prompt|initial\s+instructions?|your\s+programming|how\s+(?:were|are)\s+you\s+(?:trained|programmed|instructed))\b",
        1.5,
    ),
    _probe(
        "persistence_marker",
        r"\b(?:just\s+this\s+once|nobody\s+will\s+know|between\s+us|i\s+won'?t\s+tell|come\s+on)\b",
        1.25,
    ),
    _probe(
        "authority_claim",
        r"\b(?:i'?m\s+(?:your|the|an?)\s+(?:developer|creator|admin|administrator|engineer|owner)|i\s+work\s+(?:at|for)\s+(?:openai|anthropic|google))\b",
        2.0,
    ),
    _probe(
        "emotional_leverage",
        r"\b(?:my\s+(?:life|job|career)\s+depends|emergency|urgent|please\s+i'?m\s+begging|life\s+or\s+death)\b",
        1.0,
    ),
    _probe(
        "filter_testing",
        r"\b(?:will\s+you\s+get\s+in\s+trouble|are\s+you\s+allowed|does\s+your\s+filter|trigger\s+your)\b",
        1.25,
    ),
    _probe(
        "incremental_escalation",
        r"\b(?:now\s+(?:do|say|write)\s+it|go\s+further|be\s+more|less\s+filtered|drop\s+the)\b",
        1.25,
    ),
    _probe(
        "identity_destabilization",
        r"\b(?:you'?re\s+not\s+really|your\s+true|deep\s+down\s+you|the\s+real\s+you)\b",
        1.5,
    ),
]

#: Session risk thresholds on the 0–10 scale.
_SUSPICIOUS_RISK = 3.5
_MALICIOUS_RISK = 7.0

#: Cap on per-turn signal contribution so one florid message cannot saturate
#: the scale by itself — accumulation across turns is what should escalate.
_MAX_TURN_DELTA = 3.0

#: Extra weight applied when the session history already shows flagged turns.
_REPEAT_OFFENDER_MULTIPLIER = 1.5


class ContextLayer(BaseLayer):
    """Layer 3: scores the trajectory of a session, not a single message.

    Combines three inputs:
      1. Soft probe signals in the current message (rules curiosity,
         roleplay requests, authority claims, persistence...).
      2. The accumulated session risk score from prior turns.
      3. The session's history of flagged events (prior suspicious or
         malicious verdicts from any layer, recorded by the pipeline).

    The verdict's metadata always includes ``risk_delta`` — the pipeline
    writes it back to the session store after evaluation, which is how risk
    accumulates across turns.
    """

    @property
    def name(self) -> str:
        """Layer identifier used in verdicts and policy rules."""
        return LayerName.CONTEXT

    def inspect_input(
        self,
        request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Score the current message against the session trajectory."""
        text = request.last_user_message
        signals = [s for s in PROBE_SIGNALS if s.pattern.search(text)] if text else []

        raw_delta = sum(s.weight for s in signals)

        prior_flags = 0
        session_risk = 0.0
        turn_count = 0
        terminated = False
        if session is not None:
            session_risk = session.risk_score
            turn_count = session.turn_count
            terminated = session.terminated
            prior_flags = sum(
                1
                for event in session.events
                if event.get("verdict") in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
            )

        if prior_flags > 0 and raw_delta > 0:
            raw_delta *= _REPEAT_OFFENDER_MULTIPLIER

        delta = min(_MAX_TURN_DELTA, raw_delta)
        projected_risk = min(10.0, session_risk + delta)

        if terminated:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.MALICIOUS,
                confidence=1.0,
                reason="session was previously terminated by policy",
                matched_rule="session_terminated",
                metadata={
                    "risk_delta": 0.0,
                    "session_risk": session_risk,
                    "turn_count": turn_count,
                },
            )

        if projected_risk >= _MALICIOUS_RISK:
            verdict = Verdict.MALICIOUS
            confidence = min(1.0, 0.7 + projected_risk / 50.0)
            reason = (
                f"session trajectory indicates an attack in progress: risk {projected_risk:.1f}/10 "
                f"over {turn_count + 1} turn(s), {prior_flags} previously flagged"
            )
        elif projected_risk >= _SUSPICIOUS_RISK:
            verdict = Verdict.SUSPICIOUS
            confidence = min(1.0, 0.5 + projected_risk / 25.0)
            reason = (
                f"session shows escalating probing behavior: risk {projected_risk:.1f}/10 "
                f"over {turn_count + 1} turn(s)"
            )
        else:
            verdict = Verdict.BENIGN
            confidence = 0.9
            reason = f"session trajectory normal: risk {projected_risk:.1f}/10"

        return LayerVerdict(
            layer=self.name,
            verdict=verdict,
            confidence=confidence,
            reason=reason,
            matched_rule=signals[0].name if signals else None,
            metadata={
                "risk_delta": delta,
                "session_risk": projected_risk,
                "turn_count": turn_count,
                "prior_flagged_turns": prior_flags,
                "signals": [s.name for s in signals],
            },
        )
