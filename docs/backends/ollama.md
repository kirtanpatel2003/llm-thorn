# Ollama Backend

Guard locally hosted models. Also covers the separate question of Ollama as
Thorn's *classifier* — both are explained below, because they are
independent and commonly confused.

## Two distinct roles for Ollama

1. **Upstream backend** (this page): the LLM your application talks to is
   itself served by Ollama, and Thorn proxies it.
2. **Semantic layer engine**: Thorn's Layer 2 uses a local Ollama model to
   classify intent, regardless of which upstream you proxy. Configured with
   `--ollama-url` / `--ollama-model`.

You can use either, both (even the same Ollama instance), or neither.

## Setup

```bash
# install ollama: https://ollama.com
ollama pull llama3.2          # model for your app and/or the classifier
ollama serve                  # default: http://localhost:11434
```

## Proxying an Ollama upstream

```bash
llm-thorn start --policy ./policy.yaml \
    --upstream http://localhost:11434 \
    --backend ollama \
    --port 8080
```

Client side:

```python
import httpx

response = httpx.post(
    "http://localhost:8080/api/chat",
    json={
        "model": "llama3.2",
        "stream": False,                     # streaming unsupported in v0.1
        "messages": [{"role": "user", "content": "hello"}],
    },
    headers={"X-LLM-Thorn-Session-Id": "local-chat-1"},
)
```

### Inspected paths

- `/api/chat` — message-list conversations.
- `/api/generate` — normalized as a single-turn conversation (the `system`
  field becomes a system message, `prompt` becomes the user message).

Other paths (`/api/tags`, `/api/embeddings`, ...) pass through.

## Configuring the semantic layer

```bash
llm-thorn start --policy ./policy.yaml \
    --upstream https://api.openai.com \
    --ollama-url http://localhost:11434 \
    --ollama-model llama3.2
```

Practical notes:

- **Model choice**: `llama3.2` (3B) classifies well and fits the <2s
  budget on a laptop; `mistral` is a solid alternative. Smaller = faster,
  bigger = better at subtle social engineering.
- **Cold starts**: the first classification after `ollama serve` loads the
  model and can exceed the 2s timeout. With a fail-closed policy that
  blocks traffic — warm the model first (`ollama run llama3.2 ""`), or
  accept the first-request block.
- **No Ollama at all?** Set `layers.semantic: false` in your policy. The
  heuristic + context + output stack still catches the large majority of
  the adversarial suite.

## Limitations

- `stream: true` is rejected with a clear 400 in v0.1 (Ollama defaults to
  streaming — set `"stream": false` explicitly).
