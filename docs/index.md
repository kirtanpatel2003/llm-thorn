# Thorn Documentation

Thorn is a runtime semantic security layer for LLM-powered applications: a
reverse proxy / SDK wrapper / ASGI middleware that inspects every request to
and response from any LLM with four detection layers, enforces a YAML
policy, and writes a hash-chained, tamper-evident audit log.

## Start here

- **[Quickstart](quickstart.md)** — from zero to a running, attack-blocking
  proxy in five minutes.
- **[Architecture](architecture.md)** — how the four layers, policy engine,
  session store, and audit chain fit together.

## Reference

- **[Policy reference](policy-reference.md)** — every YAML field: type,
  default, semantics, examples.
- **Backends** — provider-specific setup:
  - [OpenAI & compatible endpoints](backends/openai.md)
  - [Anthropic](backends/anthropic.md)
  - [Ollama](backends/ollama.md)

## Extending Thorn

- **[Writing a layer](writing-a-layer.md)** — the plugin system, step by
  step, with a complete working example.
- **[Adding a backend](adding-a-backend.md)** — bring Thorn to a new LLM
  provider.
- **[Policy templates](../policies/README.md)** — ready-made policies and
  how to contribute one.

## Project

- [README](../README.md) — overview, comparison, benchmarks.
- [CONTRIBUTING](../CONTRIBUTING.md) — dev setup, code style, PR checklist.
- [CHANGELOG](../CHANGELOG.md) — release history.
