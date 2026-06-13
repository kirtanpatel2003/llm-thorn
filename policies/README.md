# Policy Templates

A Thorn policy is a YAML file that declares which detection layers run, what
conditions trigger rules, and what happens when they fire. Policies are the
contract between Thorn and your application — they are validated at startup
and invalid policies fail loudly with the exact field that's wrong.

## Templates in this directory

| Template | Use case | Error mode | Notable choices |
|---|---|---|---|
| [customer-support.yaml](customer-support.yaml) | Customer-facing support bots | fail-open | PII redacted, not blocked; uptime first |
| [healthcare.yaml](healthcare.yaml) | Healthcare assistants | fail-closed | Lowest thresholds; PHI in output blocks outright |
| [fintech.yaml](fintech.yaml) | Financial services | fail-closed | 20-turn session cap; financial PII blocks + alerts |
| [coding-assistant.yaml](coding-assistant.yaml) | Code assistants | fail-open | Highest thresholds; secrets redacted from output |

Use one directly:

```bash
llm-thorn start --policy policies/customer-support.yaml --upstream https://api.openai.com
```

Or copy one as a starting point and adapt the rules.

## Schema overview

```yaml
policy:
  name: my-policy            # required
  version: 1.0.0             # required, semver
  description: what and why  # optional

  layers:                    # all default to true
    heuristic: true          # Layer 1 — pattern matching, <5ms
    semantic: true           # Layer 2 — Ollama intent classifier, <2s
    context: true            # Layer 3 — multi-turn risk scoring, <10ms
    output: true             # Layer 4 — response inspection, <5ms

  plugins:                   # community layers, loaded at startup
    - "llm_thorn_pii_guard.PIIGuardLayer"

  rules:
    - id: unique-rule-id     # required, unique within the policy
      description: optional human explanation
      layer: heuristic       # which layer's verdict this rule reads
      condition:
        verdict: malicious   # fires on this verdict or stricter
        confidence_above: 0.8
        session_risk_above: 5.0   # context rules only
        turn_count_above: 3       # context rules only
      action: block          # allow | warn | block | redact | terminate_session
      alert: true            # also emit to the llm_thorn.alerts logger

  defaults:
    on_layer_error: block    # block = fail-closed, allow = fail-open
    max_session_turns: 50    # session resets after this many turns
    session_ttl_seconds: 3600
```

The full field-by-field reference lives in
[docs/policy-reference.md](../docs/policy-reference.md).

## How rules evaluate

1. Every enabled layer produces a verdict (`benign` / `suspicious` /
   `malicious` + confidence) for each request and response.
2. Each rule is checked against the verdicts from its layer. A `suspicious`
   condition is also satisfied by a `malicious` verdict — stricter signals
   satisfy looser conditions.
3. If several rules fire, the most severe action wins:
   `terminate_session > block > redact > warn > allow`.
4. If nothing fires, the request is allowed.

## Choosing fail-open vs fail-closed

`on_layer_error` decides what happens when a layer crashes or times out at
runtime (e.g. Ollama is down):

- **`allow` (fail-open)** — the remaining layers still run; the request
  proceeds if they pass. Choose this when downtime costs more than the
  marginal risk: support bots, developer tools.
- **`block` (fail-closed)** — requests are rejected until the stack is
  healthy. Choose this when a missed attack costs more than downtime:
  healthcare, finance, anything with regulated data.

## Contributing a template

Real-world tuned policies are one of the most valuable contributions to
Thorn. Copy the closest existing template, adapt it, comment every
non-obvious threshold, and open a PR. See
[CONTRIBUTING.md](../CONTRIBUTING.md#contributing-a-policy-template).
