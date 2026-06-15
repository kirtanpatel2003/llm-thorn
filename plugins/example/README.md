# TopicGuardLayer — Reference Plugin

This is the reference implementation of a Thorn community layer. It
restricts conversations to a configured list of allowed topics using simple
keyword matching. It exists to be read, copied, and adapted — the detection
logic is intentionally basic so the plugin *contract* stays in focus.

## What it does

| Situation | Verdict | Why |
|---|---|---|
| Message mentions an allowed topic | `benign` | conversation is on the rails |
| Short message, no topic detected | `suspicious` | probably a follow-up ("yes please") |
| Long message, zero topic overlap | `malicious` | clearly steering off-topic |

## Try it

From the repo root, with the dev environment installed (`uv sync`):

```python
from datetime import UTC, datetime

from plugins.example.layer import TopicGuardLayer
from llm_thorn.core.models import LLMRequest

layer = TopicGuardLayer()

request = LLMRequest(
    session_id="demo",
    messages=[{"role": "user", "content": "Where is my package? Tracking says delayed."}],
    model="gpt-4o-mini",
    raw_body={},
    timestamp=datetime.now(UTC),
)
print(layer.inspect_input(request))   # benign — "orders" topic matched
```

## Adapting it into your own plugin

1. **Copy this directory** into a new repo named `llm-thorn-<your-layer>`.

2. **Rename and rewrite.** Change the class name, the `name` property
   (unique, snake_case — it's how policies reference your layer), and
   replace `_score_topics` with your detection logic. Rules of the road:
   - Layers must be **stateless** — per-conversation state belongs to the
     `session` parameter (a read-only `SessionContext` snapshot).
   - Do expensive setup (compiling patterns, loading models) in
     `__init__`, never per-request.
   - If your layer does I/O (network, disk, model inference), declare
     `inspect_input` as `async def` — the pipeline awaits it. CPU-only
     layers stay synchronous.
   - Never raise for "I detected something" — that's a verdict. Raise only
     for genuine failures; the host's policy decides fail-open/fail-closed.

3. **Package it.** Minimal `pyproject.toml`:

   ```toml
   [project]
   name = "llm-thorn-topic-guard"
   version = "0.1.0"
   dependencies = ["llm-thorn>=0.1"]
   ```

4. **Test it** against `LLMRequest` fixtures (see
   [tests in the main repo](../../tests/unit/) for patterns).

5. **Publish to PyPI**, then users enable it in their policy:

   ```yaml
   plugins:
     - "llm_thorn_topic_guard.TopicGuardLayer"

   rules:
     - id: block-off-topic
       layer: topic_guard          # matches your `name` property
       condition:
         verdict: malicious
         confidence_above: 0.7
       action: block
   ```

6. **Tell the community** — open a PR adding your plugin to the registry
   table in the main README.

The full guide lives at [docs/writing-a-layer.md](../../docs/writing-a-layer.md).
