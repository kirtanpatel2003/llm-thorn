"""LLM provider backends: normalization and forwarding."""

from llm_thorn.backends.anthropic import AnthropicBackend
from llm_thorn.backends.base import AbstractBackend
from llm_thorn.backends.ollama import OllamaBackend
from llm_thorn.backends.openai import OpenAIBackend

#: Registry used by the CLI's ``--backend`` flag.
BACKENDS: dict[str, type[AbstractBackend]] = {
    "openai": OpenAIBackend,
    "anthropic": AnthropicBackend,
    "ollama": OllamaBackend,
}

__all__ = [
    "BACKENDS",
    "AbstractBackend",
    "AnthropicBackend",
    "OllamaBackend",
    "OpenAIBackend",
]
