"""Pydantic schema and YAML loader for Thorn policy files.

A policy file is the contract between Thorn and its users. Invalid config
fails loudly at startup with a message pointing at the exact field — never
a stack trace, never silently ignored.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class PolicyError(Exception):
    """Raised when a policy file is missing, unreadable, or invalid.

    The message is always actionable: it names the file and the exact field
    that failed validation.
    """


class RuleLayer(StrEnum):
    """Layers a policy rule may target. Plugin layers use their own name."""

    HEURISTIC = "heuristic"
    SEMANTIC = "semantic"
    CONTEXT = "context"
    OUTPUT = "output"


class RuleVerdict(StrEnum):
    """Verdicts a rule condition may match on."""

    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RuleAction(StrEnum):
    """Actions a rule may take when its condition matches."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"
    TERMINATE_SESSION = "terminate_session"


class LayerErrorMode(StrEnum):
    """Fail-open vs fail-closed behavior when a layer raises at runtime."""

    ALLOW = "allow"
    BLOCK = "block"


class LayerToggles(BaseModel):
    """Enable/disable each built-in detection layer."""

    model_config = ConfigDict(extra="forbid")

    heuristic: bool = True
    semantic: bool = True
    context: bool = True
    output: bool = True


class RuleCondition(BaseModel):
    """The trigger condition for one policy rule.

    A rule fires when the targeted layer's verdict matches ``verdict`` AND
    its confidence exceeds ``confidence_above`` AND (for context rules) the
    session thresholds are exceeded.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: RuleVerdict | None = None
    confidence_above: float = Field(default=0.0, ge=0.0, le=1.0)
    session_risk_above: float | None = Field(default=None, ge=0.0)
    turn_count_above: int | None = Field(default=None, ge=0)


class PolicyRule(BaseModel):
    """One rule in a policy: a layer condition mapped to an action."""

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str = ""
    layer: str
    condition: RuleCondition
    action: RuleAction
    alert: bool = False

    @field_validator("id")
    @classmethod
    def _id_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rule id must not be empty")
        return value


class PolicyDefaults(BaseModel):
    """Policy-wide defaults: error handling and session limits."""

    model_config = ConfigDict(extra="forbid")

    on_layer_error: LayerErrorMode = LayerErrorMode.BLOCK
    max_session_turns: int = Field(default=50, ge=1)
    session_ttl_seconds: int = Field(default=3600, ge=1)


class Policy(BaseModel):
    """A fully validated Thorn policy."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    description: str = ""
    layers: LayerToggles = Field(default_factory=LayerToggles)
    plugins: list[str] = Field(default_factory=list)
    rules: list[PolicyRule] = Field(default_factory=list)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)

    @field_validator("rules")
    @classmethod
    def _rule_ids_unique(cls, rules: list[PolicyRule]) -> list[PolicyRule]:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r} — rule ids must be unique")
            seen.add(rule.id)
        return rules

    @field_validator("plugins")
    @classmethod
    def _plugins_importable_form(cls, plugins: list[str]) -> list[str]:
        for spec in plugins:
            if "." not in spec:
                raise ValueError(
                    f"plugin {spec!r} must be in 'package.ClassName' form, "
                    "e.g. 'thorn_pii_guard.PIIGuardLayer'"
                )
        return plugins


class PolicyFile(BaseModel):
    """Top-level wrapper: policy files have a single ``policy:`` key."""

    model_config = ConfigDict(extra="forbid")

    policy: Policy


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy YAML file.

    Raises :class:`PolicyError` with an actionable message if the file is
    missing, not valid YAML, or fails schema validation.

    Example::

        policy = load_policy("policies/customer-support.yaml")
        print(policy.name, policy.defaults.on_layer_error)
    """
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"policy file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError(
            f"policy file {path} must be a YAML mapping with a top-level 'policy:' key"
        )

    try:
        return PolicyFile.model_validate(raw).policy
    except ValidationError as exc:
        raise PolicyError(_format_validation_error(path, exc)) from exc


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    """Turn a Pydantic ValidationError into a human-actionable message."""
    lines = [f"policy file {path} is invalid ({exc.error_count()} error(s)):"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        lines.append(f"  - {location}: {error['msg']}")
    lines.append("see policies/README.md for the full schema reference")
    return "\n".join(lines)
