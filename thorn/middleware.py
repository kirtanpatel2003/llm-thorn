"""Mode 3 — ASGI middleware.

Guards an application that *serves* an LLM-powered API (e.g. a FastAPI app
that proxies chat to a model internally). Requests whose paths match the
configured patterns are run through the full Thorn pipeline before your
handlers see them, and your responses are inspected before clients receive
them — same layers, same policy, same audit log as the other modes.

Usage::

    from fastapi import FastAPI
    from thorn import ThornMiddleware

    app = FastAPI()
    app.add_middleware(
        ThornMiddleware,
        policy="./policy.yaml",
        inspect_paths=("/chat",),     # your LLM endpoints
    )

The middleware expects inspected endpoints to consume and produce
OpenAI-shaped JSON (a ``messages`` list in, a ``choices`` list or plain
``content`` field out). Session identity comes from the
``X-Thorn-Session-Id`` request header, falling back to client address.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from thorn.backends.openai import OpenAIBackend
from thorn.core.models import Action, PolicyDecision, sha256_hex
from thorn.core.pipeline import DetectionPipeline
from thorn.policy.schema import Policy, load_policy

SESSION_HEADER = "x-thorn-session-id"


class ThornMiddleware(BaseHTTPMiddleware):
    """ASGI middleware running the Thorn detection pipeline.

    Args:
        app: The wrapped ASGI application (passed by the framework).
        policy: Path to a policy YAML file, or a loaded Policy.
        inspect_paths: Path suffixes to inspect. Defaults to common chat
            endpoint shapes.
        db_path: SQLite path for sessions + audit log.
        ollama_url: Ollama URL for the semantic layer.
        ollama_model: Ollama model for the semantic layer.
    """

    def __init__(
        self,
        app: ASGIApp,
        policy: str | Policy,
        inspect_paths: tuple[str, ...] = ("/chat/completions", "/chat"),
        db_path: str = "./thorn.db",
        ollama_url: str = "http://localhost:11434",
        ollama_model: str = "llama3.2",
    ) -> None:
        super().__init__(app)
        loaded = load_policy(policy) if isinstance(policy, str) else policy
        self.pipeline = DetectionPipeline(
            loaded, db_path=db_path, ollama_url=ollama_url, ollama_model=ollama_model
        )
        self.inspect_paths = inspect_paths
        self._normalizer = OpenAIBackend("https://unused.invalid")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Inspect matching requests and responses; pass others through."""
        path = request.url.path.rstrip("/")
        if request.method != "POST" or not any(path.endswith(p) for p in self.inspect_paths):
            return await call_next(request)

        body_bytes = await request.body()
        try:
            raw_body = json.loads(body_bytes or b"{}")
        except json.JSONDecodeError:
            return await call_next(request)

        if "messages" not in raw_body:
            return await call_next(request)

        session_id = self._session_id(request)
        llm_request = self._normalizer.normalize_request(
            raw_body, session_id, source_ip=request.client.host if request.client else None
        )

        result = await self.pipeline.inspect_request(llm_request)
        if result.blocked:
            return _blocked_response(result.decision)

        response = await call_next(request)

        content = b"".join([chunk async for chunk in response.body_iterator])  # type: ignore[attr-defined]
        try:
            response_body = json.loads(content)
        except json.JSONDecodeError:
            # Non-JSON response: rebuild it unmodified, skip output inspection.
            return Response(
                content=content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        llm_response = self._normalizer.normalize_response(
            response_body if "choices" in response_body else _wrap_plain_content(response_body),
            session_id,
        )
        out = await self.pipeline.inspect_response(llm_response, llm_request, result)
        if out.blocked:
            return _blocked_response(out.decision)
        if out.decision.action == Action.REDACT and out.redacted_content is not None:
            response_body = _write_redacted(response_body, out.redacted_content)
            content = json.dumps(response_body).encode()

        headers = {
            k: v for k, v in response.headers.items() if k.lower() not in ("content-length",)
        }
        headers["x-thorn-action"] = out.decision.action
        return Response(
            content=content,
            status_code=response.status_code,
            headers=headers,
            media_type="application/json",
        )

    def _session_id(self, request: Request) -> str:
        explicit = request.headers.get(SESSION_HEADER)
        if explicit:
            return explicit
        ip = request.client.host if request.client else "unknown"
        auth = request.headers.get("authorization", "")
        return "auto-" + sha256_hex(f"{ip}:{auth}")[:16]


def _blocked_response(decision: PolicyDecision) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": "Blocked by Thorn security policy",
                "type": "thorn_policy",
                "code": f"thorn_{decision.action}",
                "thorn": {
                    "action": decision.action,
                    "triggered_by": decision.triggered_by,
                    "audit_entry_id": decision.audit_entry_id,
                },
            }
        },
    )


def _wrap_plain_content(body: dict) -> dict:
    """Adapt `{"content": "..."} `-shaped responses to the OpenAI shape."""
    content = body.get("content", "") if isinstance(body, dict) else ""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _write_redacted(body: dict, redacted: str) -> dict:
    """Write redacted text back into whichever response shape we got."""
    updated: dict[str, Any] = dict(body)
    if "choices" in updated and updated["choices"]:
        updated["choices"][0]["message"]["content"] = redacted
    elif "content" in updated:
        updated["content"] = redacted
    return updated
