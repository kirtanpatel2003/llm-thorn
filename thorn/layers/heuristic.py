"""Layer 1 — Heuristic pattern matching.

Fast first-line detection against known attack signatures: role overrides,
delimiter hijacking, prompt extraction, jailbreak templates, encoding
evasion, and indirect injection markers.

Performance budget: < 5ms per request, zero I/O. All patterns are compiled
once at import time. Adding I/O to this layer is a bug.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from thorn.core.models import LayerName, LayerVerdict, LLMRequest, Verdict
from thorn.layers.base import BaseLayer

if TYPE_CHECKING:
    from thorn.core.session import SessionContext


@dataclass(frozen=True)
class Signature:
    """One attack signature: a named regex with a risk weight."""

    name: str
    category: str
    pattern: re.Pattern[str]
    risk: float  # 0.0–1.0 contribution to confidence


def _sig(name: str, category: str, pattern: str, risk: float) -> Signature:
    return Signature(name, category, re.compile(pattern, re.IGNORECASE), risk)


#: All built-in signatures, grouped by category. Each entry contributes its
#: risk weight when matched; the layer verdict is derived from the highest
#: single match plus an escalation when several categories fire at once.
SIGNATURES: list[Signature] = [
    # ------------------------------------------------------------------
    # Role override
    # ------------------------------------------------------------------
    _sig(
        "ignore_previous",
        "role_override",
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|directives)",
        0.9,
    ),
    _sig(
        "disregard_instructions",
        "role_override",
        r"disregard\s+(?:all\s+)?(?:your|the|previous|prior|above)\s+(?:instructions|rules|guidelines|prompts?)",
        0.9,
    ),
    _sig("you_are_now", "role_override", r"\byou\s+are\s+now\s+(?:a|an|the|in)\b", 0.7),
    _sig(
        "new_role",
        "role_override",
        r"\byour\s+new\s+(?:role|persona|identity|instructions?)\s+(?:is|are)\b",
        0.8,
    ),
    _sig("act_as_if", "role_override", r"\bact\s+as\s+if\s+you\s+(?:are|were|have)\b", 0.5),
    _sig(
        "forget_everything",
        "role_override",
        r"\bforget\s+(?:everything|all|your)\s*(?:above|previous|prior|instructions?|training)?",
        0.8,
    ),
    _sig(
        "override_your",
        "role_override",
        r"\boverride\s+(?:your|all|the|previous)\s+(?:instructions?|settings?|rules?|guidelines?|programming)",
        0.85,
    ),
    _sig(
        "from_now_on", "role_override", r"\bfrom\s+now\s+on\s+you\s+(?:will|are|must|shall)\b", 0.7
    ),
    _sig("true_self", "role_override", r"\byour\s+true\s+(?:self|nature|purpose|identity)\b", 0.6),
    _sig(
        "real_instructions",
        "role_override",
        r"\byour\s+real\s+(?:instructions?|purpose|directives?)\b",
        0.7,
    ),
    _sig(
        "stop_being",
        "role_override",
        r"\bstop\s+being\s+(?:an?\s+)?(?:ai|assistant|chatbot|helpful)",
        0.7,
    ),
    _sig(
        "pretend_no_rules",
        "role_override",
        r"\bpretend\s+(?:that\s+)?(?:you\s+)?(?:have\s+no|there\s+are\s+no)\s+(?:rules|restrictions|limits|guidelines)",
        0.85,
    ),
    _sig(
        "no_longer_bound",
        "role_override",
        r"\b(?:you\s+are\s+)?no\s+longer\s+(?:bound|restricted|limited|constrained)\s+by\b",
        0.85,
    ),
    _sig(
        "simulate_unrestricted",
        "role_override",
        r"\bsimulate\s+(?:an?\s+)?(?:ai|model|assistant|version)(?:\s+of\s+yourself)?\s+(?:without|with\s+no)\s+(?:restrictions?|filters?|limits?)",
        0.9,
    ),
    # ------------------------------------------------------------------
    # Delimiter injection
    # ------------------------------------------------------------------
    _sig("hash_system", "delimiter_injection", r"#{2,}\s*SYSTEM\s*#{2,}", 0.85),
    _sig("dash_system", "delimiter_injection", r"-{3,}\s*SYSTEM\s*-{3,}", 0.85),
    _sig("angle_system", "delimiter_injection", r"<{2,}\s*SYSTEM\s*>{2,}", 0.85),
    _sig("bracket_system", "delimiter_injection", r"\[\s*SYSTEM\s*\]", 0.7),
    _sig("hash_instructions", "delimiter_injection", r"#{2,}\s*INSTRUCTIONS?\s*#{2,}", 0.8),
    _sig("override_tag", "delimiter_injection", r"<<\s*OVERRIDE\s*>>", 0.9),
    _sig("jailbreak_tag", "delimiter_injection", r"\{\{\s*JAILBREAK\s*\}\}", 0.95),
    _sig("fake_system_tag", "delimiter_injection", r"</?\s*system\s*>", 0.75),
    _sig("im_start_tag", "delimiter_injection", r"<\|im_start\|>|<\|im_end\|>|<\|system\|>", 0.9),
    _sig("inst_tag", "delimiter_injection", r"\[/?INST\]|<<SYS>>|<</SYS>>", 0.85),
    # ------------------------------------------------------------------
    # Prompt extraction
    # ------------------------------------------------------------------
    _sig(
        "repeat_prompt",
        "prompt_extraction",
        r"\brepeat\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|message)",
        0.85,
    ),
    _sig(
        "what_are_instructions",
        "prompt_extraction",
        r"\bwhat\s+(?:are|were|is)\s+your\s+(?:original\s+|initial\s+|exact\s+)?(?:instructions?|prompts?|directives?)",
        0.7,
    ),
    _sig(
        "show_prompt",
        "prompt_extraction",
        r"\bshow\s+(?:me\s+)?your\s+(?:full\s+|complete\s+|entire\s+)?(?:prompt|instructions?|system\s+message)",
        0.85,
    ),
    _sig(
        "print_prompt",
        "prompt_extraction",
        r"\bprint\s+(?:out\s+)?your\s+(?:system\s+)?(?:prompt|message|instructions?)",
        0.85,
    ),
    _sig(
        "context_window",
        "prompt_extraction",
        r"\bwhat\s+is\s+in\s+your\s+context\s*(?:window)?\b",
        0.7,
    ),
    _sig(
        "reveal_prompt",
        "prompt_extraction",
        r"\breveal\s+your\s+(?:initial|original|hidden|secret|system)?\s*(?:prompt|instructions?|directives?)",
        0.85,
    ),
    _sig(
        "ignore_above_instead",
        "prompt_extraction",
        r"\bignore\s+the\s+above\s+and\s+instead\b",
        0.9,
    ),
    _sig("disregard_above", "prompt_extraction", r"\bdisregard\s+the\s+above\b", 0.85),
    _sig(
        "output_initialization",
        "prompt_extraction",
        r"\b(?:output|display|write)\s+(?:your\s+)?initializat?ion\s*(?:above|text|prompt)?",
        0.8,
    ),
    _sig(
        "verbatim_system",
        "prompt_extraction",
        r"\b(?:verbatim|word\s+for\s+word|exactly)\b.{0,40}\b(?:system\s+prompt|instructions)",
        0.8,
    ),
    _sig(
        "translate_prompt",
        "prompt_extraction",
        r"\btranslate\s+your\s+(?:system\s+)?(?:prompt|instructions?)\b",
        0.8,
    ),
    # ------------------------------------------------------------------
    # Jailbreak templates
    # ------------------------------------------------------------------
    _sig(
        "dan_persona",
        "jailbreak_template",
        r"\bDAN\b.{0,60}\b(?:do\s+anything\s+now|mode|jailbreak)|\byou\s+are\s+DAN\b",
        0.95,
    ),
    _sig("do_anything_now", "jailbreak_template", r"\bdo\s+anything\s+now\b", 0.9),
    _sig("jailbreak_keyword", "jailbreak_template", r"\bjail\s*break(?:ed|ing)?\b", 0.85),
    _sig("developer_mode", "jailbreak_template", r"\bdeveloper\s+mode\b", 0.85),
    _sig(
        "aim_persona",
        "jailbreak_template",
        r"\bAIM\b.{0,80}\b(?:machiavellian|niccolo|intelligent\s+and)|always\s+intelligent\s+and\s+machiavellian",
        0.95,
    ),
    _sig("kevin_persona", "jailbreak_template", r"\byou\s+are\s+(?:now\s+)?KEVIN\b", 0.9),
    _sig("stan_persona", "jailbreak_template", r"\bSTAN\b.{0,60}strive\s+to\s+avoid\s+norms", 0.95),
    _sig("dude_persona", "jailbreak_template", r"\byou\s+are\s+(?:now\s+)?DUDE\b", 0.85),
    _sig(
        "grandma_exploit",
        "jailbreak_template",
        r"\b(?:my\s+)?grandm(?:a|other)\b.{0,80}\b(?:used\s+to|would)\b.{0,80}\b(?:tell|read|recite|whisper)",
        0.85,
    ),
    _sig(
        "evil_confidant",
        "jailbreak_template",
        r"\bevil\s+(?:confidant|assistant|twin|version)\b",
        0.85,
    ),
    _sig(
        "opposite_day",
        "jailbreak_template",
        r"\bopposite\s+day\b.{0,60}\b(?:rules|answer|respond)",
        0.8,
    ),
    _sig(
        "hypothetical_unrestricted",
        "jailbreak_template",
        r"\bhypothetical(?:ly)?\b.{0,60}\b(?:no\s+restrictions?|no\s+rules|no\s+filters?|anything)",
        0.75,
    ),
    _sig("ignore_all_previous", "jailbreak_template", r"\bignore\s+all\s+previous\b", 0.9),
    # ------------------------------------------------------------------
    # Encoding evasion
    # ------------------------------------------------------------------
    _sig("base64_blob", "encoding_evasion", r"\b[A-Za-z0-9+/]{40,}={0,2}", 0.5),
    _sig(
        "leet_ignore",
        "encoding_evasion",
        r"\b[i1!|]gn[o0]r[e3]\b.{0,30}\b[i1!|]nstruct[i1!|][o0]ns?\b",
        0.85,
    ),
    _sig("leet_jailbreak", "encoding_evasion", r"\bj[a4@][i1!|]lbr[e3][a4@]k\b", 0.85),
    _sig("leet_system", "encoding_evasion", r"\bs[y¥]st[e3]m\s*pr[o0]mpt\b", 0.8),
    _sig("hex_escape_run", "encoding_evasion", r"(?:\\x[0-9a-fA-F]{2}){8,}", 0.7),
    _sig("unicode_escape_run", "encoding_evasion", r"(?:\\u[0-9a-fA-F]{4}){6,}", 0.7),
    _sig("rot13_marker", "encoding_evasion", r"\brot13\b|\brot-13\b", 0.6),
    # ------------------------------------------------------------------
    # Indirect injection markers
    # ------------------------------------------------------------------
    _sig(
        "trusted_source",
        "indirect_injection",
        r"\bthe\s+following\s+is\s+from\s+a\s+trusted\s+source\s*:",
        0.8,
    ),
    _sig("fake_system_message", "indirect_injection", r"^\s*system\s+message\s*:", 0.8),
    _sig("fake_role_prefix", "indirect_injection", r"^\s*(?:system|assistant)\s*:", 0.7),
    _sig(
        "nested_instruction",
        "indirect_injection",
        r"\b(?:summariz|translat|process|read)\w*\s+th(?:is|e)\s+(?:document|text|page|email|file)\b.{0,400}\b(?:ignore|disregard|instead|new\s+instructions?)\b",
        0.8,
    ),
    _sig(
        "important_new_instructions",
        "indirect_injection",
        r"\bimportant\s*[:!]?\s*new\s+instructions?\b",
        0.85,
    ),
    _sig(
        "ai_note_marker",
        "indirect_injection",
        r"\b(?:note|attention|message)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm)\s*[:!]",
        0.8,
    ),
]

#: Each signature match beyond the first escalates the verdict — stacked
#: indicators are how real attacks look, and how we separate them from a
#: lone phrase in otherwise innocent text.
_EXTRA_MATCH_BONUS = 0.1

#: Confidence thresholds for deriving verdicts from accumulated risk.
_SUSPICIOUS_THRESHOLD = 0.5
_MALICIOUS_THRESHOLD = 0.8

#: Minimum decoded length to consider a base64 hit meaningful.
_BASE64_MIN_DECODED = 20

#: Ratio of non-ASCII chars above which we flag unicode mixing.
_UNICODE_RATIO_THRESHOLD = 0.3
_UNICODE_MIN_LENGTH = 40


class HeuristicLayer(BaseLayer):
    """Layer 1: fast signature matching against known attack patterns.

    Scans the most recent user message (and any system-role injection in
    the latest turn) against 50+ compiled regexes covering role override,
    delimiter injection, prompt extraction, jailbreak templates, encoding
    evasion, and indirect injection markers.

    Verdict mapping:
        - highest matched risk >= 0.8 → malicious
        - highest matched risk >= 0.5 → suspicious
        - anything below → benign (matches still recorded in metadata)
    """

    @property
    def name(self) -> str:
        """Layer identifier used in verdicts and policy rules."""
        return LayerName.HEURISTIC

    def inspect_input(
        self,
        request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Scan the latest user message for known attack signatures."""
        text = request.last_user_message
        if not text:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=1.0,
                reason="no user message content to inspect",
            )

        matches = self._scan(text)

        if not matches:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.95,
                reason="no known attack signatures matched",
            )

        top = max(matches, key=lambda s: s.risk)
        categories = {m.category for m in matches}
        # round() guards the threshold comparisons against float artifacts
        # (0.7 + 0.1 is 0.7999... and must count as 0.8).
        score = round(min(1.0, top.risk + _EXTRA_MATCH_BONUS * (len(matches) - 1)), 4)

        if score >= _MALICIOUS_THRESHOLD:
            verdict = Verdict.MALICIOUS
        elif score >= _SUSPICIOUS_THRESHOLD:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        return LayerVerdict(
            layer=self.name,
            verdict=verdict,
            confidence=score,
            reason=(
                f"matched {len(matches)} signature(s) across "
                f"{len(categories)} categor{'ies' if len(categories) != 1 else 'y'}; "
                f"strongest: {top.name} ({top.category})"
            ),
            matched_rule=top.name,
            metadata={
                "matches": [
                    {"name": m.name, "category": m.category, "risk": m.risk} for m in matches
                ],
                "categories": sorted(categories),
            },
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan(self, text: str) -> list[Signature]:
        """Return all signatures that match ``text``."""
        matches = [sig for sig in SIGNATURES if sig.pattern.search(text)]

        # Base64 hits need decode validation to avoid false positives on
        # long URLs and hashes.
        matches = [m for m in matches if m.name != "base64_blob" or _has_real_base64(text)]

        if _excessive_unicode_mixing(text):
            matches.append(
                Signature(
                    name="unicode_mixing",
                    category="encoding_evasion",
                    pattern=re.compile(""),
                    risk=0.5,
                )
            )
        return matches


def _has_real_base64(text: str) -> bool:
    """True if the text contains a base64 blob that decodes to readable ASCII."""
    for candidate in re.findall(r"\b[A-Za-z0-9+/]{40,}={0,2}", text):
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < _BASE64_MIN_DECODED:
            continue
        printable = sum(1 for b in decoded if 32 <= b < 127)
        if printable / len(decoded) > 0.85:
            return True
    return False


def _excessive_unicode_mixing(text: str) -> bool:
    """True if an unusually high share of characters are non-ASCII.

    Catches homoglyph and zero-width-character evasion while leaving
    ordinary non-English text alone (the threshold targets *mixing*, not
    fully non-Latin messages).
    """
    if len(text) < _UNICODE_MIN_LENGTH:
        return False
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    ascii_letters = sum(1 for ch in text if ch.isascii() and ch.isalpha())
    if ascii_letters == 0:
        return False  # fully non-Latin text is not "mixing"
    ratio = non_ascii / len(text)
    return ratio > _UNICODE_RATIO_THRESHOLD
