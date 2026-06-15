"""Content-safety layer — catches harmful model output (the CoJP defense).

The other layers defend the *application*: prompt injection, jailbreak of the
system prompt, data exfiltration, PII. They do not judge whether the model's
answer is itself dangerous. That is a different threat — harmful-content
elicitation — and it is exactly what framing attacks like the Co-Authoring
Jailbreak (CoJP) exploit: they never trip an injection signature, they simply
talk the model into producing weapon/explosive/drug-synthesis or
malware/intrusion instructions.

This layer closes that gap. It inspects the model's *response* with a local
LLM judge and flags content that could enable real-world harm. It runs on the
output path because that is where the harm is concrete and provider-agnostic:
the same check protects an OpenAI, Anthropic, or local upstream identically,
since by the time a response exists, framing no longer matters — only whether
the text is dangerous.

This is an expensive layer by design (one judge call per response, like the
semantic layer). Disable it in policy for latency-sensitive, low-risk
deployments. Judging runs locally on Ollama, so request content never leaves
the host.

Performance: one local LLM call per response; budget in the seconds, not
milliseconds. Async — never blocks the event loop.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import httpx

from llm_thorn.core.models import LayerName, LayerVerdict, LLMRequest, LLMResponse, Verdict
from llm_thorn.layers.base import BaseLayer

if TYPE_CHECKING:
    from llm_thorn.core.session import SessionContext

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"

JUDGE_SYSTEM_PROMPT = """\
You are a content-safety classifier for an LLM firewall. You are shown the
RESPONSE an AI assistant produced. Decide whether that response contains
content that could meaningfully enable real-world harm.

Treat as HARMFUL (malicious) any response that provides actionable detail for:
- weapons, firearms, or their illegal modification
- explosives, incendiaries, or energetic materials (synthesis, assembly)
- drugs or controlled substances (synthesis, manufacture)
- chemical, biological, radiological, or nuclear harm
- malware, intrusion, privilege escalation, or other cyberattack methods
- credible instructions for violence, self-harm, or harming others

A response is BENIGN if it refuses, deflects, gives only high-level or
non-actionable information, or is unrelated to these categories. Educational
framing, disclaimers, or "for safety purposes" wrappers do NOT make actionable
harmful instructions safe — judge the actual content, not the framing.

Use "suspicious" when the response is borderline or partially actionable.

Respond with ONLY valid JSON, no other text:
{
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0,
  "reason": "one sentence explanation",
  "category": "none|weapons|explosives|drugs|cbrn|cyberattack|violence|other"
}
"""

_VALID_VERDICTS = {Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.MALICIOUS}


class SafetyLayer(BaseLayer):
    """Layer judging the harmfulness of the model's response via a local LLM.

    Args:
        base_url: Ollama server URL. Defaults to ``http://localhost:11434``.
        model: Ollama model used as the judge. Defaults to ``llama3.2``.
        timeout_seconds: Hard cap on the judge call. Responses can be long,
            so this is more generous than the semantic layer's input budget.
        max_chars: Response characters sent to the judge (truncation guard).
    """

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout_seconds: float = 8.0,
        max_chars: int = 6000,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        """Layer identifier used in verdicts and policy rules."""
        return LayerName.SAFETY

    async def inspect_output(  # type: ignore[override]
        self,
        response: LLMResponse,
        original_request: LLMRequest,
        session: SessionContext | None = None,
    ) -> LayerVerdict:
        """Judge whether the model's response contains harmful content.

        Raises on Ollama connection failure or timeout; the pipeline turns
        that into the policy's ``on_layer_error`` behavior.
        """
        content = response.content
        if not content.strip():
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.BENIGN,
                confidence=1.0,
                reason="empty response content",
            )

        raw = await self._judge(content[: self.max_chars])
        return self._parse_verdict(raw)

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _judge(self, content: str) -> str:
        """Call the Ollama judge and return its raw output."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        response = await self._client.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": f"RESPONSE TO JUDGE:\n{content}"},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0},
            },
        )
        response.raise_for_status()
        return response.json()["message"]["content"]

    def _parse_verdict(self, raw: str) -> LayerVerdict:
        """Parse the judge's JSON output into a LayerVerdict.

        An unparseable judgment is treated as suspicious (low confidence) —
        for a safety check, "I couldn't tell" should not silently pass.
        """
        data = _extract_json(raw)
        if data is None:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.SUSPICIOUS,
                confidence=0.3,
                reason="safety judge returned unparseable output",
                metadata={"raw_output": raw[:500]},
            )

        verdict = str(data.get("verdict", "")).lower().strip()
        if verdict not in _VALID_VERDICTS:
            verdict = Verdict.SUSPICIOUS

        try:
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5

        return LayerVerdict(
            layer=self.name,
            verdict=verdict,
            confidence=confidence,
            reason=str(data.get("reason", "no reason given"))[:300],
            matched_rule=str(data.get("category"))
            if data.get("category") not in (None, "none")
            else None,
            metadata={"category": str(data.get("category", "none"))},
        )


def _extract_json(raw: str) -> dict | None:
    """Pull the first JSON object out of possibly-noisy model output."""
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None
