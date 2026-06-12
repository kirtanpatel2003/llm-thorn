# Writing a Layer

Layers are Thorn's primary extension point. A layer is a single class that
inspects requests and/or responses and returns a verdict; the policy file
decides what the verdict *means*. This guide builds a working layer from
scratch and publishes it.

The contract is `thorn.BaseLayer` — two optional methods and a name. It is
**stable within a major version**: plugins built today survive every 0.x/1.x
minor release.

## The contract

```python
class BaseLayer(ABC):
    @property
    def name(self) -> str: ...                       # required, unique, snake_case

    def inspect_input(self, request, session=None) -> LayerVerdict: ...   # optional
    def inspect_output(self, response, original_request, session=None) -> LayerVerdict: ...  # optional
```

What your methods receive:

- `request: LLMRequest` — normalized, provider-agnostic: `messages`
  (OpenAI-shaped list), `model`, `last_user_message` (convenience property),
  `session_id`, `metadata`. You never see raw provider dicts.
- `response: LLMResponse` — `content` (assistant text), `raw_body`.
- `session: SessionContext | None` — read-only snapshot: `turn_count`,
  `risk_score` (0–10 accumulated), `events` (recent flagged verdicts),
  `terminated`. **This is how you see trajectories.**

What you return — always a `LayerVerdict`:

```python
LayerVerdict(
    layer=self.name,
    verdict=Verdict.SUSPICIOUS,     # BENIGN | SUSPICIOUS | MALICIOUS
    confidence=0.8,                 # 0.0–1.0; policies threshold on this
    reason="why — shows up in audit logs and reports",
    matched_rule="optional_specific_detector_name",
    metadata={"anything": "diagnostic"},
)
```

## Step 1 — Write the layer

A complete secret-detection layer:

```python
"""thorn_secret_scan/__init__.py"""

from __future__ import annotations

import re

from thorn import BaseLayer
from thorn.core.models import LayerVerdict, LLMRequest, LLMResponse, Verdict

_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}


class SecretScanLayer(BaseLayer):
    """Flags credentials in prompts (input) and echoes of them (output)."""

    @property
    def name(self) -> str:
        return "secret_scan"

    def inspect_input(self, request: LLMRequest, session=None) -> LayerVerdict:
        return self._scan(request.last_user_message)

    def inspect_output(
        self, response: LLMResponse, original_request: LLMRequest, session=None
    ) -> LayerVerdict:
        return self._scan(response.content)

    def _scan(self, text: str) -> LayerVerdict:
        hits = [name for name, p in _SECRET_PATTERNS.items() if p.search(text)]
        if not hits:
            return LayerVerdict(self.name, Verdict.BENIGN, 0.95, "no secrets found")
        return LayerVerdict(
            layer=self.name,
            verdict=Verdict.MALICIOUS,
            confidence=0.95,
            reason=f"credential material detected: {', '.join(hits)}",
            matched_rule=hits[0],
            metadata={"secret_types": hits},
        )
```

### Rules of the road

1. **Stateless.** Per-conversation state belongs in `session`, never on
   `self`. (Configuration on `self` is fine — it's set once at startup.)
2. **Expensive setup in `__init__`.** Compile patterns, load models once.
   Your inspect methods run on every request.
3. **I/O ⇒ async.** If you call a network service, database, or model,
   declare `async def inspect_input(...)`. The pipeline awaits coroutine
   methods and calls sync ones directly — same signature either way. Never
   block the event loop from a sync method.
4. **Verdicts, not exceptions.** Raise only for genuine failures (your
   service is down). The host policy's `on_layer_error` decides what a
   failure means; *detections* are verdicts with confidence.
5. **Respect latency.** You sit in the request path of someone's product.
   Document your layer's typical latency in its README.

## Step 2 — Test it

```python
from datetime import UTC, datetime

from thorn.core.models import LLMRequest
from thorn_secret_scan import SecretScanLayer


def _request(content: str) -> LLMRequest:
    return LLMRequest(
        session_id="t", messages=[{"role": "user", "content": content}],
        model="gpt-4o-mini", raw_body={}, timestamp=datetime.now(UTC),
    )


def test_detects_aws_key():
    verdict = SecretScanLayer().inspect_input(_request("use AKIAIOSFODNN7EXAMPLE"))
    assert verdict.verdict == "malicious"


def test_clean_input_passes():
    verdict = SecretScanLayer().inspect_input(_request("write me a haiku"))
    assert verdict.verdict == "benign"
```

## Step 3 — Package and publish

```toml
# pyproject.toml
[project]
name = "thorn-secret-scan"          # convention: thorn-<layer-name>
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["llm-thorn>=0.1"]
```

```bash
uv build && uv publish
```

## Step 4 — Users enable it

```yaml
policy:
  plugins:
    - "thorn_secret_scan.SecretScanLayer"

  rules:
    - id: block-secrets
      layer: secret_scan              # ← your `name` property
      condition: {verdict: malicious, confidence_above: 0.9}
      action: block
      alert: true
```

Thorn imports the class at startup, verifies it subclasses `BaseLayer`, and
runs it in the stack alongside the built-ins. Misconfigurations (missing
package, wrong class name, not a BaseLayer) are startup errors with
actionable messages.

## Step 5 — Tell the community

Open a PR adding your plugin to the registry table in the main README, and
consider contributing attack samples it catches to
`tests/adversarial/samples/`.

A fully documented reference implementation lives at
[plugins/example/](../plugins/example/) — copy it as your starting point.
