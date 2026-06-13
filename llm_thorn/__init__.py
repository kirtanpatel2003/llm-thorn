"""Thorn — runtime semantic security layer for LLM-powered applications.

Thorn sits between any client and any LLM, understands intent (not just
syntax), tracks conversation context across turns, enforces a YAML-defined
policy, and produces a cryptographically tamper-evident audit log of every
interaction.

Public API::

    from llm_thorn import guard, ThornMiddleware, BaseLayer

    # Mode 2 — SDK wrapper
    client = guard(openai.OpenAI(), policy="./policy.yaml")

    # Mode 3 — ASGI middleware
    app.add_middleware(ThornMiddleware, policy="./policy.yaml")

Mode 1 (reverse proxy) is started from the CLI: ``llm-thorn start --policy ...``.
"""

from llm_thorn.layers.base import BaseLayer

__version__ = "0.1.0"


def __getattr__(name: str) -> object:
    # Lazy imports keep `import llm_thorn` fast and avoid pulling FastAPI/httpx
    # into processes that only need BaseLayer (e.g. plugin test suites).
    if name == "guard":
        from llm_thorn.sdk import guard

        return guard
    if name == "ThornMiddleware":
        from llm_thorn.middleware import ThornMiddleware

        return ThornMiddleware
    raise AttributeError(f"module 'llm_thorn' has no attribute {name!r}")


__all__ = ["BaseLayer", "ThornMiddleware", "__version__", "guard"]
