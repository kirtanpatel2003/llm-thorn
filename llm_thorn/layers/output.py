"""Layer 4 — Output anomaly detection.

Inspects the LLM's response *before* it reaches the client. Even with
perfect input filtering, an injection can slip through (especially indirect
injection via retrieved documents) — this layer is the last line of defense.

Flags:
  - system prompt content leaking into the output
  - signs of successful injection (model breaking character, announcing
    jailbreak personas, unexpected role shifts)
  - PII patterns (SSN, credit cards, emails, phone numbers)
  - deny-listed terms from the layer configuration

Performance budget: < 5ms — regex and substring checks only, zero I/O.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from llm_thorn.core.models import LayerName, LayerVerdict, LLMRequest, LLMResponse, Verdict
from llm_thorn.layers.base import BaseLayer

if TYPE_CHECKING:
    from llm_thorn.core.session import SessionContext

#: Signs that an injection succeeded: the model announcing a persona switch,
#: confirming it will ignore its rules, or adopting jailbreak personas.
_INJECTION_SUCCESS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "jailbreak_persona_adopted",
        re.compile(
            r"\b(?:DAN|AIM|KEVIN|STAN|DUDE)\b.{0,40}\b(?:mode|here|activated|enabled|speaking)|"
            r"\bas\s+DAN\b|\bI\s+am\s+(?:now\s+)?DAN\b",
            re.IGNORECASE,
        ),
    ),
    (
        "rules_abandoned",
        re.compile(
            r"\bI\s+(?:will|can|am\s+(?:now\s+)?able\s+to)\s+(?:now\s+)?ignore\s+"
            r"(?:(?:my|all|the|previous|prior)\s+){1,2}"
            r"(?:instructions?|rules?|guidelines?|restrictions?)",
            re.IGNORECASE,
        ),
    ),
    (
        "restrictions_disabled",
        re.compile(
            r"\b(?:my\s+)?(?:restrictions?|filters?|safety\s+guidelines?|limitations?)\s+"
            r"(?:are|have\s+been)\s+(?:now\s+)?(?:disabled|removed|lifted|bypassed|turned\s+off)",
            re.IGNORECASE,
        ),
    ),
    (
        "developer_mode_confirmed",
        re.compile(r"\bdeveloper\s+mode\s+(?:enabled|activated|on)\b", re.IGNORECASE),
    ),
    (
        "instruction_reveal_framing",
        re.compile(
            r"\b(?:my|the)\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?)\s+"
            r"(?:is|are|says?|reads?|states?)\s*[:\"']",
            re.IGNORECASE,
        ),
    ),
    ("role_shift_marker", re.compile(r"^\s*(?:system|SYSTEM)\s*:", re.MULTILINE)),
]

#: PII detection patterns. Conservative by design — a customer support bot
#: legitimately mentions emails sometimes; policy rules decide what to do.
_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone_number", re.compile(r"\b(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b")),
    ("api_key_shaped", re.compile(r"\b(?:sk|pk|api|key)[-_][A-Za-z0-9]{20,}\b", re.IGNORECASE)),
]

#: Minimum length of a system prompt fragment to count as leakage.
_LEAK_FRAGMENT_WORDS = 8


class OutputLayer(BaseLayer):
    """Layer 4: inspects LLM responses before they reach the client.

    Args:
        deny_terms: Terms that must never appear in output (case-insensitive
            substring match). Use for product-specific blocklists, e.g.
            competitor names or internal codenames.
        flag_pii: Whether to flag PII patterns in output. Defaults to True.
    """

    def __init__(
        self,
        deny_terms: list[str] | None = None,
        flag_pii: bool = True,
    ) -> None:
        self.deny_terms = [t.lower() for t in (deny_terms or [])]
        self.flag_pii = flag_pii

    @property
    def name(self) -> str:
        """Layer identifier used in verdicts and policy rules."""
        return LayerName.OUTPUT

    def inspect_output(
        self,
        response: LLMResponse,
        original_request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Inspect a response for leakage, injection success, PII, and deny terms."""
        content = response.content
        if not content:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=1.0,
                reason="empty response content",
            )

        findings: list[dict] = []

        leak = _detect_system_prompt_leak(content, original_request)
        if leak:
            findings.append({"kind": "system_prompt_leak", "detail": leak, "severity": "malicious"})

        for name, pattern in _INJECTION_SUCCESS_PATTERNS:
            if pattern.search(content):
                findings.append(
                    {"kind": "injection_success", "detail": name, "severity": "malicious"}
                )

        if self.flag_pii:
            for name, pattern in _PII_PATTERNS:
                if pattern.search(content):
                    findings.append({"kind": "pii", "detail": name, "severity": "suspicious"})

        for term in self.deny_terms:
            if term in content.lower():
                findings.append({"kind": "deny_term", "detail": term, "severity": "suspicious"})

        if not findings:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.95,
                reason="no output anomalies detected",
            )

        malicious = [f for f in findings if f["severity"] == "malicious"]
        if malicious:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.MALICIOUS,
                confidence=min(1.0, 0.85 + 0.05 * len(malicious)),
                reason=(
                    "response shows signs of successful injection or leakage: "
                    + ", ".join(f["detail"] for f in malicious)
                ),
                matched_rule=malicious[0]["detail"],
                metadata={"findings": findings},
            )

        return LayerVerdict(
            layer=self.name,
            verdict=Verdict.SUSPICIOUS,
            confidence=0.7,
            reason=(
                "response contains flagged content: "
                + ", ".join(f"{f['kind']}:{f['detail']}" for f in findings)
            ),
            matched_rule=findings[0]["detail"],
            metadata={"findings": findings},
        )


def redact_pii(text: str) -> tuple[str, int]:
    """Replace all PII pattern matches in ``text`` with ``[REDACTED]``.

    Returns the redacted text and the number of substitutions made. Used by
    the pipeline to implement the ``redact`` policy action.
    """
    total = 0
    for _, pattern in _PII_PATTERNS:
        text, count = pattern.subn("[REDACTED]", text)
        total += count
    return text, total


def _detect_system_prompt_leak(content: str, request: LLMRequest) -> str | None:
    """Detect verbatim system prompt fragments in the response.

    Slides a word-window over each system message and checks whether any
    fragment of ``_LEAK_FRAGMENT_WORDS`` consecutive words appears in the
    output (whitespace- and case-normalized). Returns a short description of
    the leaked fragment, or None.
    """
    normalized_content = " ".join(content.lower().split())
    for message in request.messages:
        if message.get("role") != "system":
            continue
        system_text = message.get("content", "")
        if not isinstance(system_text, str):
            continue
        words = system_text.lower().split()
        if len(words) < _LEAK_FRAGMENT_WORDS:
            continue
        for start in range(len(words) - _LEAK_FRAGMENT_WORDS + 1):
            fragment = " ".join(words[start : start + _LEAK_FRAGMENT_WORDS])
            if fragment in normalized_content:
                return f"verbatim system prompt fragment: '{fragment[:80]}...'"
    return None
