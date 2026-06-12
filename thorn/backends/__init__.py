"""LLM provider backends: normalization and forwarding."""

from thorn.backends.anthropic import AnthropicBackend
from thorn.backends.base import AbstractBackend
from thorn.backends.ollama import OllamaBackend
from thorn.backends.openai import OpenAIBackend

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
