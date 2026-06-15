"""Core data models shared across every Thorn component.

These dataclasses are the internal API of Thorn. Layers, the policy engine,
backends, and the audit logger all communicate through them. Do not change
their shape without strong justification — every plugin depends on them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums — no magic strings anywhere else in the codebase.
# ---------------------------------------------------------------------------


class Verdict(StrEnum):
    """Classification a layer assigns to an input or output."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Action(StrEnum):
    """Final action the policy engine takes on a request."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"
    TERMINATE = "terminate"


class LayerName(StrEnum):
    """Identifiers for the built-in detection layers."""

    HEURISTIC = "heuristic"
    SEMANTIC = "semantic"
    CONTEXT = "context"
    OUTPUT = "output"
    SAFETY = "safety"


# ---------------------------------------------------------------------------
# Request / response models — backend-normalized, never raw provider dicts.
# ---------------------------------------------------------------------------


@dataclass
class LLMRequest:
    """A normalized LLM request, independent of the upstream provider.

    Backends normalize provider-specific request bodies into this shape
    before any layer sees them. ``raw_body`` preserves the original body
    untouched so the proxy can forward it verbatim.
    """

    session_id: str
    messages: list[dict]
    model: str
    raw_body: dict
    timestamp: datetime
    source_ip: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def last_user_message(self) -> str:
        """Content of the most recent user message, or empty string."""
        for message in reversed(self.messages):
            if message.get("role") == "user":
                content = message.get("content", "")
                return content if isinstance(content, str) else _flatten_content(content)
        return ""


@dataclass
class LLMResponse:
    """A normalized LLM response, independent of the upstream provider."""

    session_id: str
    content: str
    raw_body: dict
    timestamp: datetime
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Verdicts and decisions.
# ---------------------------------------------------------------------------


@dataclass
class LayerVerdict:
    """The result a single detection layer returns for one inspection."""

    layer: str
    verdict: str
    confidence: float
    reason: str
    matched_rule: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for JSON encoding."""
        return asdict(self)


@dataclass
class PolicyDecision:
    """The policy engine's final ruling on a request or response."""

    action: str
    triggered_by: list[str]
    verdicts: list[LayerVerdict]
    session_id: str
    timestamp: datetime
    audit_entry_id: str

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for JSON encoding."""
        return {
            "action": self.action,
            "triggered_by": list(self.triggered_by),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "audit_entry_id": self.audit_entry_id,
        }


@dataclass
class AuditEntry:
    """One tamper-evident record in the hash-chained audit log."""

    entry_id: str
    timestamp: datetime
    session_id: str
    request_hash: str
    response_hash: str | None
    verdicts: list[LayerVerdict]
    policy_decision: PolicyDecision
    chain_hash: str

    def content_for_hashing(self) -> str:
        """Canonical serialization of everything except ``chain_hash``.

        The chain hash is sha256(previous_chain_hash + this string), so the
        serialization must be deterministic: sorted keys, no whitespace
        variance.
        """
        payload = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "verdicts": [v.to_dict() for v in self.verdicts],
            "policy_decision": self.policy_decision.to_dict(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes | str) -> str:
    """Return the hex sha256 digest of ``data``."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_body(body: dict) -> str:
    """Deterministically hash a JSON-serializable request/response body."""
    return sha256_hex(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str))


def _flatten_content(content: list) -> str:
    """Flatten OpenAI content-part lists (e.g. vision messages) to text."""
    parts: list[str] = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            parts.append(part.get("text", ""))
        elif isinstance(part, str):
            parts.append(part)
    return " ".join(parts)
