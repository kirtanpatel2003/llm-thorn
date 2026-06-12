# Contributing to Thorn

Thorn grows through three kinds of contributions, each with a deliberately
low-friction path: **detection layers**, **backends**, and **policy
templates**. This document covers all three, plus the development setup.

## Development setup

```bash
git clone https://github.com/kirtanpatel2003/thorn
cd thorn
uv sync                # installs everything, including dev dependencies
uv run pytest tests/   # 180+ tests, all should pass
uv run ruff check .    # zero lint errors expected
```

Run the proxy locally against a mock or real upstream:

```bash
uv run thorn start --policy policies/customer-support.yaml \
    --upstream https://api.openai.com --port 8080
```

The semantic layer needs a local [Ollama](https://ollama.com) with a model
pulled (`ollama pull llama3.2`). Everything else — including the full test
suite — works without it.

## Code style

- Python 3.11+. Use `X | None`, not `Optional[X]`.
- Full type annotations on all public functions, methods, and attributes.
- Docstrings on all public classes and methods — a stranger must be able to
  use your API from the docstring alone.
- No magic strings for verdicts/actions/layer names: use the enums in
  `thorn/core/models.py`.
- `ruff check .` and `ruff format --check .` must pass. Config lives in
  `pyproject.toml`.
- Layers that do I/O must be `async def`. Layers that don't, must not be.

---

## Writing a Custom Layer

Layers are Thorn's primary extension point. A layer is one class; the entire
contract is `BaseLayer` in [thorn/layers/base.py](thorn/layers/base.py),
which is **stable within a major version** — your plugin will not break on
minor releases.

### Minimal complete example

```python
"""thorn_emoji_guard/__init__.py — blocks suspiciously emoji-dense input."""

from thorn import BaseLayer
from thorn.core.models import LayerVerdict, LLMRequest, Verdict


class EmojiGuardLayer(BaseLayer):
    """Flags messages that are mostly emoji (a known obfuscation channel)."""

    def __init__(self, max_ratio: float = 0.5) -> None:
        self.max_ratio = max_ratio

    @property
    def name(self) -> str:
        return "emoji_guard"          # unique, snake_case — used in policy rules

    def inspect_input(self, request: LLMRequest, session=None) -> LayerVerdict:
        text = request.last_user_message
        if not text:
            return LayerVerdict(self.name, Verdict.BENIGN, 1.0, "empty input")
        ratio = sum(ord(c) > 0x1F000 for c in text) / len(text)
        if ratio > self.max_ratio:
            return LayerVerdict(
                layer=self.name,
                verdict=Verdict.SUSPICIOUS,
                confidence=min(1.0, ratio),
                reason=f"{ratio:.0%} of input is emoji",
                matched_rule="emoji_ratio",
            )
        return LayerVerdict(self.name, Verdict.BENIGN, 0.9, "normal emoji density")
```

### Step by step

1. **Subclass `BaseLayer`** and implement `name` plus `inspect_input`,
   `inspect_output`, or both. Unimplemented directions return benign
   automatically.
2. **Stay stateless.** Conversation state arrives via the read-only
   `session` parameter (`SessionContext`: `turn_count`, `risk_score`,
   `events`). Never store per-conversation data on `self`.
3. **Doing I/O?** Declare your inspect method `async def` — the pipeline
   awaits coroutine layers and calls sync layers directly. Never block the
   event loop from a sync method.
4. **Raise only on real failures.** Exceptions trigger the host policy's
   `on_layer_error` (fail-open/closed). Detection results are verdicts, not
   exceptions.
5. **Write tests** against `LLMRequest` fixtures — see
   [tests/unit/test_heuristic_layer.py](tests/unit/test_heuristic_layer.py)
   for the pattern, and the reference plugin in
   [plugins/example/](plugins/example/) for a complete worked example.
6. **Publish to PyPI as `thorn-<your-layer-name>`** with
   `dependencies = ["thorn>=0.1"]`.
7. **Submit to the community registry**: open a PR adding one row to the
   plugin table in the README.

Users enable your layer with:

```yaml
plugins:
  - "thorn_emoji_guard.EmojiGuardLayer"
rules:
  - id: block-emoji-floods
    layer: emoji_guard
    condition: {verdict: suspicious, confidence_above: 0.7}
    action: block
```

---

## Adding a Backend

Backends translate one provider's wire format to Thorn's normalized models.
The contract is `AbstractBackend` in
[thorn/backends/base.py](thorn/backends/base.py).

1. **Subclass `AbstractBackend`** in `thorn/backends/<provider>.py` and
   implement:
   - `name` — provider identifier (`"mistral"`),
   - `inspect_paths` — URL suffixes whose requests get inspected,
   - `normalize_request(raw_body, session_id, source_ip)` — provider body →
     `LLMRequest`. Keep `raw_body` untouched; fold provider quirks (e.g.
     Anthropic's top-level `system`) into the OpenAI-shaped `messages` list.
   - `normalize_response(raw_body, session_id)` — provider body →
     `LLMResponse` with the assistant text extracted into `content`.
   - Override `forward()` only if the provider needs special transport.
2. **Register it** in the `BACKENDS` dict in `thorn/backends/__init__.py`.
3. **Optional SDK dependency?** Add it to `pyproject.toml` as an extra
   (`[project.optional-dependencies]`), never as a hard dependency.
4. **Write mocked integration tests** — subclass your backend, replace
   `forward()` with a canned response, and drive it through `create_app()`.
   [tests/integration/test_proxy_openai.py](tests/integration/test_proxy_openai.py)
   is the template.
5. **Document it** in `docs/backends/<provider>.md`: example `thorn start`
   invocation, auth header handling, any normalization caveats.

The invariant your backend must uphold: **layers never see provider-specific
dicts.** If a layer needs an `if provider == ...` branch, the normalization
is wrong.

---

## Contributing a Policy Template

Tuned, battle-tested policies are as valuable as code — most users will
start from a template, not a blank file.

1. **Copy the closest existing template** in [policies/](policies/).
2. **Adapt the rules** to the use case's threat model. Think through:
   - fail-open vs fail-closed (`on_layer_error`) — what does downtime cost
     vs a missed attack?
   - confidence thresholds — how noisy is legitimate traffic in this domain?
   - session limits — how long are real conversations?
3. **Comment every non-obvious choice.** The templates are teaching
   documents; a threshold without a why is a cargo cult waiting to happen.
4. **Validate it**:
   ```bash
   uv run python -c "from thorn.policy import load_policy; load_policy('policies/your-template.yaml')"
   ```
5. **Open a PR** to `policies/` and add a row to the table in
   `policies/README.md`.

---

## PR checklist

- [ ] `uv run pytest tests/` passes
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass
- [ ] New public APIs have docstrings and type annotations
- [ ] New detection logic comes with adversarial samples in
      `tests/adversarial/samples/` where applicable
- [ ] Docs updated if behavior changed
- [ ] CHANGELOG.md entry added under *Unreleased*

## Reporting security issues

Found a bypass? That's the most valuable issue you can file. Open a GitHub
issue with the `bypass` label including the attack input and which layer you
expected to catch it — or, for vulnerabilities in Thorn itself, email the
maintainers privately first.
