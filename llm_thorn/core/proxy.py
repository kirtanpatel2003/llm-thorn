"""Mode 1 — the Thorn reverse proxy.

Sits between any client and any LLM API with zero code change downstream:
the client just points its base URL at Thorn. Every chat completion request
runs through the full detection pipeline; everything else (model lists,
embeddings...) is forwarded transparently.

Session identity: clients should send an ``X-LLM-Thorn-Session-Id`` header for
precise multi-turn tracking. Without it, Thorn falls back to a stable hash
of the caller's credentials + source IP, which still groups one client's
turns together.

Streaming is not supported in v0.1 — streaming requests get a clear 400
rather than silently degraded behavior.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from llm_thorn.backends.base import AbstractBackend
from llm_thorn.core.models import Action, PolicyDecision, sha256_hex
from llm_thorn.core.pipeline import DetectionPipeline
from llm_thorn.policy.schema import Policy

logger = logging.getLogger("llm_thorn.proxy")

#: Header a client sets to identify its conversation session.
SESSION_HEADER = "x-llm-thorn-session-id"

#: Largest request body Thorn will buffer and inspect. Bigger inspected bodies
#: are rejected with 413 instead of being read into memory — a basic guard
#: against memory exhaustion. Non-inspected paths (embeddings, model lists…)
#: forward through untouched and are not subject to this limit.
MAX_INSPECTED_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB


def create_app(
    policy: Policy,
    backend: AbstractBackend,
    db_path: str = "./llm-thorn.db",
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3.2",
) -> FastAPI:
    """Build the reverse proxy ASGI app.

    Args:
        policy: A validated policy.
        backend: The provider backend to forward to.
        db_path: SQLite path for sessions + audit log.
        ollama_url: Ollama URL for the semantic layer (not the upstream).
        ollama_model: Ollama model for the semantic layer.

    Example::

        from llm_thorn.policy import load_policy
        from llm_thorn.backends import OpenAIBackend
        app = create_app(load_policy("policy.yaml"),
                         OpenAIBackend("https://api.openai.com"))
    """
    pipeline = DetectionPipeline(
        policy, db_path=db_path, ollama_url=ollama_url, ollama_model=ollama_model
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await pipeline.close()
        await backend.close()

    app = FastAPI(title="Thorn", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.pipeline = pipeline
    app.state.backend = backend

    @app.get("/llm-thorn/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "policy": policy.name,
            "policy_version": policy.version,
            "backend": backend.name,
        }

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def proxy(path: str, request: Request) -> Response:
        if request.method != "POST" or not backend.should_inspect(path):
            return await _passthrough(backend, path, request)

        body_bytes = await request.body()
        if len(body_bytes) > MAX_INSPECTED_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content=_error_body(
                    f"request body exceeds the {MAX_INSPECTED_BODY_BYTES}-byte inspection limit",
                    "request_too_large",
                ),
            )

        try:
            raw_body = json.loads(body_bytes or b"{}")
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content=_error_body("request body is not valid JSON", "invalid_request"),
            )

        if raw_body.get("stream"):
            return JSONResponse(
                status_code=400,
                content=_error_body(
                    "streaming is not supported by Thorn v0.1 — set stream=false",
                    "streaming_unsupported",
                ),
            )

        session_id = _session_id(request)
        llm_request = backend.normalize_request(
            raw_body, session_id, source_ip=request.client.host if request.client else None
        )

        # --- Input inspection -----------------------------------------
        result = await app.state.pipeline.inspect_request(llm_request)
        if result.blocked:
            return _blocked_response(result.decision)

        # --- Forward upstream -------------------------------------------
        status, headers, body_bytes = await backend.forward(path, raw_body, dict(request.headers))
        if status >= 400:
            # Upstream rejected it; pass the error through untouched.
            return Response(
                content=body_bytes,
                status_code=status,
                media_type=headers.get("content-type", "application/json"),
            )

        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            logger.warning("upstream returned non-JSON body; passing through uninspected")
            return Response(
                content=body_bytes,
                status_code=status,
                media_type=headers.get("content-type", "application/json"),
            )

        llm_response = backend.normalize_response(response_body, session_id)

        # --- Output inspection (audit entry written inside) -----------
        out = await app.state.pipeline.inspect_response(llm_response, llm_request, result)
        if out.blocked:
            return _blocked_response(out.decision)
        if out.decision.action == Action.REDACT and out.redacted_content is not None:
            response_body = _apply_redaction(response_body, out.redacted_content, backend)
            body_bytes = json.dumps(response_body).encode()

        response_headers = {"x-llm-thorn-action": out.decision.action}
        if out.decision.action == Action.WARN:
            response_headers["x-llm-thorn-warning"] = ",".join(out.decision.triggered_by)

        return Response(
            content=body_bytes,
            status_code=status,
            media_type="application/json",
            headers=response_headers,
        )

    return app


async def _passthrough(backend: AbstractBackend, path: str, request: Request) -> Response:
    """Forward a non-inspected request verbatim."""
    body: dict | None = None
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            body = None
    status, headers, content = await backend.forward(
        path, body, dict(request.headers), method=request.method
    )
    return Response(
        content=content,
        status_code=status,
        media_type=headers.get("content-type", "application/json"),
    )


def _session_id(request: Request) -> str:
    """Derive the session id: explicit header, else stable client hash."""
    explicit = request.headers.get(SESSION_HEADER)
    if explicit:
        return explicit
    auth = request.headers.get("authorization", "") or request.headers.get("x-api-key", "")
    ip = request.client.host if request.client else "unknown"
    return "auto-" + sha256_hex(f"{ip}:{auth}")[:16]


def _blocked_response(decision: PolicyDecision) -> JSONResponse:
    """Build the 403 returned when policy blocks a request or response."""
    message = (
        "Request blocked by Thorn security policy"
        if decision.action == Action.BLOCK
        else "Session terminated by Thorn security policy"
    )
    body = _error_body(message, f"llm_thorn_{decision.action}")
    body["error"]["llm_thorn"] = {
        "action": decision.action,
        "triggered_by": decision.triggered_by,
        "audit_entry_id": decision.audit_entry_id,
    }
    return JSONResponse(status_code=403, content=body)


def _error_body(message: str, code: str) -> dict:
    """OpenAI-style error envelope so SDK clients fail cleanly."""
    return {"error": {"message": message, "type": "llm_thorn_policy", "code": code}}


def _apply_redaction(response_body: dict, redacted_content: str, backend: AbstractBackend) -> dict:
    """Write redacted text back into the provider's response shape."""
    body = dict(response_body)
    if backend.name == "openai" and body.get("choices"):
        body["choices"][0]["message"]["content"] = redacted_content
    elif backend.name == "anthropic" and body.get("content"):
        body["content"] = [{"type": "text", "text": redacted_content}]
    elif backend.name == "ollama":
        if "message" in body:
            body["message"]["content"] = redacted_content
        elif "response" in body:
            body["response"] = redacted_content
    return body
