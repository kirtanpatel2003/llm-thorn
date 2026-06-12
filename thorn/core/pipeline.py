"""The shared detection pipeline.

All three integration modes (reverse proxy, SDK wrapper, ASGI middleware)
run this exact pipeline. That is what guarantees the key invariant: identical
inputs produce identical audit logs regardless of integration mode.

Flow per request:

    1. Load (or create) the session snapshot.
    2. Run all enabled input layers; collect verdicts. A layer exception is
       caught here and converted into the policy's ``on_layer_error``
       behavior — it never crashes the caller.
    3. Evaluate the policy → input decision.
    4. Record the turn against the session (risk accumulation).
    5. If blocked/terminated: write the audit entry, return the decision.
    6. Caller forwards to the LLM, then calls ``inspect_response``.
    7. Run output layers, re-evaluate policy over all verdicts.
    8. Write the audit entry — always before the response goes to the client.
"""

from __future__ import annotations

import importlib
import inspect
import logging

from thorn.core.audit import AuditLog
from thorn.core.models import (
    Action,
    LayerVerdict,
    LLMRequest,
    LLMResponse,
    PolicyDecision,
    Verdict,
    hash_body,
)
from thorn.core.session import SessionContext, SessionStore
from thorn.layers.base import BaseLayer
from thorn.layers.context import ContextLayer
from thorn.layers.heuristic import HeuristicLayer
from thorn.layers.output import OutputLayer, redact_pii
from thorn.layers.semantic import SemanticLayer
from thorn.policy.engine import PolicyEngine
from thorn.policy.schema import LayerErrorMode, Policy, PolicyError

logger = logging.getLogger("thorn.pipeline")

#: Risk contributed to the session score by non-context layer verdicts.
_VERDICT_RISK_CONTRIBUTION: dict[str, float] = {
    Verdict.BENIGN: 0.0,
    Verdict.SUSPICIOUS: 1.5,
    Verdict.MALICIOUS: 3.0,
}


class LayerLoadError(PolicyError):
    """Raised at startup when a plugin layer cannot be imported."""


class InspectionResult:
    """Bundle returned by pipeline inspection calls.

    Attributes:
        decision: The policy decision for this stage.
        verdicts: All verdicts collected so far (input + output).
        session: The session snapshot used for evaluation.
        blocked: True when the action is block or terminate.
        redacted_content: When the action is ``redact`` on an output
            inspection, the response content with PII removed; else None.
    """

    def __init__(
        self,
        decision: PolicyDecision,
        verdicts: list[LayerVerdict],
        session: SessionContext,
        redacted_content: str | None = None,
    ) -> None:
        self.decision = decision
        self.verdicts = verdicts
        self.session = session
        self.redacted_content = redacted_content

    @property
    def blocked(self) -> bool:
        """True if the request/response must not proceed."""
        return self.decision.action in (Action.BLOCK, Action.TERMINATE)


class DetectionPipeline:
    """Runs the full Thorn detection stack for one deployment.

    One pipeline instance is created per process and shared across requests.

    Args:
        policy: A validated policy (from :func:`thorn.policy.load_policy`).
        db_path: SQLite path for both session state and the audit log.
        ollama_url: Base URL for the semantic layer's Ollama instance.
        ollama_model: Model name for the semantic layer.

    Example::

        pipeline = DetectionPipeline(load_policy("policy.yaml"))
        result = await pipeline.inspect_request(request)
        if result.blocked:
            return blocked_response(result.decision)
    """

    def __init__(
        self,
        policy: Policy,
        db_path: str = "./thorn.db",
        ollama_url: str = "http://localhost:11434",
        ollama_model: str = "llama3.2",
    ) -> None:
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.sessions = SessionStore(
            db_path,
            ttl_seconds=policy.defaults.session_ttl_seconds,
            max_turns=policy.defaults.max_session_turns,
        )
        self.audit = AuditLog(db_path)

        self.input_layers: list[BaseLayer] = []
        self.output_layers: list[BaseLayer] = []
        if policy.layers.heuristic:
            self.input_layers.append(HeuristicLayer())
        if policy.layers.semantic:
            self.input_layers.append(SemanticLayer(base_url=ollama_url, model=ollama_model))
        if policy.layers.context:
            self.input_layers.append(ContextLayer())
        if policy.layers.output:
            self.output_layers.append(OutputLayer())

        for spec in policy.plugins:
            plugin = _load_plugin(spec)
            self.input_layers.append(plugin)
            self.output_layers.append(plugin)

    # ------------------------------------------------------------------
    # Input path
    # ------------------------------------------------------------------

    async def inspect_request(self, request: LLMRequest) -> InspectionResult:
        """Run all input layers and the policy engine over a request.

        Never raises for layer failures — those are converted to the
        policy's ``on_layer_error`` behavior. If the result is blocking,
        the audit entry has already been written when this returns.
        """
        session = self.sessions.get_or_create(request.session_id)
        verdicts, error = await self._run_input_layers(request, session)

        if error is not None and self.policy.defaults.on_layer_error == LayerErrorMode.BLOCK:
            decision = self.engine.decision_for_layer_error(*error, verdicts, session)
        else:
            decision = self.engine.evaluate(verdicts, session)

        self._record_turn(request.session_id, verdicts)

        if decision.action == Action.TERMINATE:
            self.sessions.terminate(request.session_id)

        if decision.action in (Action.BLOCK, Action.TERMINATE):
            self._write_audit(request, None, verdicts, decision)

        return InspectionResult(decision, verdicts, session)

    # ------------------------------------------------------------------
    # Output path
    # ------------------------------------------------------------------

    async def inspect_response(
        self,
        response: LLMResponse,
        request: LLMRequest,
        prior: InspectionResult,
    ) -> InspectionResult:
        """Run output layers, re-evaluate policy, and write the audit entry.

        Must be called exactly once per forwarded request. The audit entry
        is always written here — before the caller returns anything to the
        client (key invariant #2).
        """
        verdicts = list(prior.verdicts)
        error: tuple[str, Exception] | None = None

        for layer in self.output_layers:
            try:
                verdict = layer.inspect_output(response, request, prior.session)
                if inspect.isawaitable(verdict):
                    verdict = await verdict
                verdicts.append(verdict)
            except Exception as exc:  # noqa: BLE001 — invariant: never crash
                logger.exception("output layer %s failed", layer.name)
                error = (layer.name, exc)

        if error is not None and self.policy.defaults.on_layer_error == LayerErrorMode.BLOCK:
            decision = self.engine.decision_for_layer_error(*error, verdicts, prior.session)
        else:
            decision = self.engine.evaluate(verdicts, prior.session)

        if decision.action == Action.TERMINATE:
            self.sessions.terminate(request.session_id)

        redacted: str | None = None
        if decision.action == Action.REDACT:
            redacted, count = redact_pii(response.content)
            logger.info("redacted %d PII match(es) from response", count)

        self._write_audit(request, response, verdicts, decision)
        return InspectionResult(decision, verdicts, prior.session, redacted_content=redacted)

    async def close(self) -> None:
        """Release database connections and HTTP clients."""
        for layer in self.input_layers:
            if isinstance(layer, SemanticLayer):
                await layer.close()
        self.sessions.close()
        self.audit.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_input_layers(
        self,
        request: LLMRequest,
        session: SessionContext,
    ) -> tuple[list[LayerVerdict], tuple[str, Exception] | None]:
        """Run input layers, awaiting async ones. Returns (verdicts, first_error)."""
        verdicts: list[LayerVerdict] = []
        error: tuple[str, Exception] | None = None
        for layer in self.input_layers:
            try:
                verdict = layer.inspect_input(request, session)
                if inspect.isawaitable(verdict):
                    verdict = await verdict
                verdicts.append(verdict)
            except Exception as exc:  # noqa: BLE001 — invariant: never crash
                logger.exception("input layer %s failed", layer.name)
                if error is None:
                    error = (layer.name, exc)
        return verdicts, error

    def _record_turn(self, session_id: str, verdicts: list[LayerVerdict]) -> None:
        """Accumulate session risk from this turn's verdicts."""
        delta = 0.0
        worst: LayerVerdict | None = None
        for verdict in verdicts:
            if verdict.layer == "context":
                delta += float(verdict.metadata.get("risk_delta", 0.0))
            else:
                delta += _VERDICT_RISK_CONTRIBUTION.get(verdict.verdict, 0.0)
            if worst is None or _severity(verdict) > _severity(worst):
                worst = verdict
        event = None
        if worst is not None and worst.verdict != Verdict.BENIGN:
            event = {
                "verdict": worst.verdict,
                "layer": worst.layer,
                "rule": worst.matched_rule,
            }
        self.sessions.record_turn(session_id, risk_delta=delta, event=event)

    def _write_audit(
        self,
        request: LLMRequest,
        response: LLMResponse | None,
        verdicts: list[LayerVerdict],
        decision: PolicyDecision,
    ) -> None:
        """Append the audit entry for this interaction."""
        self.audit.append(
            session_id=request.session_id,
            request_hash=hash_body(request.raw_body),
            response_hash=hash_body(response.raw_body) if response else None,
            verdicts=verdicts,
            policy_decision=decision,
            entry_id=decision.audit_entry_id,
        )


def _severity(verdict: LayerVerdict) -> int:
    order = {Verdict.BENIGN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}
    return order.get(verdict.verdict, 0)


def _load_plugin(spec: str) -> BaseLayer:
    """Import and instantiate a plugin layer from 'package.ClassName' form.

    Raises :class:`LayerLoadError` with an actionable message if the module
    is missing, the class does not exist, or it is not a BaseLayer.
    """
    module_path, _, class_name = spec.rpartition(".")
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise LayerLoadError(
            f"cannot import plugin module {module_path!r} (from plugin spec {spec!r}): {exc}. "
            f"Is the package installed? Try: pip install {module_path.split('.')[0]}"
        ) from exc
    try:
        cls = getattr(module, class_name)
    except AttributeError as exc:
        raise LayerLoadError(
            f"module {module_path!r} has no class {class_name!r} (from plugin spec {spec!r})"
        ) from exc
    instance = cls()
    if not isinstance(instance, BaseLayer):
        raise LayerLoadError(
            f"plugin {spec!r} does not subclass thorn.BaseLayer — "
            "every Thorn layer must inherit from BaseLayer"
        )
    return instance
