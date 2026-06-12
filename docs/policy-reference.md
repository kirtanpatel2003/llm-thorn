# Policy Reference

Complete reference for every field in a Thorn policy file. Policies are
validated at startup with `extra="forbid"` semantics: unknown keys, typos,
and out-of-range values are **startup errors with the exact field named**,
never silent no-ops.

A policy file has a single top-level `policy:` key.

## `policy`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | ✅ | — | Identifier shown in logs, health checks, and reports. |
| `version` | string | ✅ | — | Your policy's version (semver recommended). Version security config like code. |
| `description` | string | — | `""` | Free-text context for humans. |
| `layers` | mapping | — | all `true` | Per-layer enable toggles. See [`layers`](#policylayers). |
| `plugins` | list[string] | — | `[]` | Community layers to load. See [`plugins`](#policyplugins). |
| `rules` | list | — | `[]` | Detection rules. See [`rules`](#policyrules). |
| `defaults` | mapping | — | see below | Error handling and session limits. See [`defaults`](#policydefaults). |

```yaml
policy:
  name: my-app
  version: 1.2.0
  description: Production policy for the support bot.
```

## `policy.layers`

Each built-in layer can be disabled independently. Disabled layers produce
no verdicts, so rules targeting them never fire.

| Field | Type | Default | Notes |
|---|---|---|---|
| `heuristic` | bool | `true` | Layer 1 — signature matching. <5ms, no I/O. Rarely worth disabling. |
| `semantic` | bool | `true` | Layer 2 — Ollama intent classifier. Requires a reachable Ollama; with fail-closed policies, an unreachable Ollama blocks traffic. |
| `context` | bool | `true` | Layer 3 — multi-turn session risk. Disabling it turns Thorn into a single-turn filter. |
| `output` | bool | `true` | Layer 4 — response inspection. Needed for `redact` rules and leak detection. |

## `policy.plugins`

List of community layers in `"importable.module.ClassName"` form. Each is
imported at startup, instantiated with no arguments, and must subclass
`thorn.BaseLayer` — violations are startup errors with install hints.
Plugin layers run on both the input and output paths (their base-class
defaults return benign for whichever direction they don't implement).

```yaml
plugins:
  - "thorn_pii_guard.PIIGuardLayer"
```

## `policy.rules`

Each rule reads the verdicts of one layer and maps a condition to an action.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | ✅ | — | Unique within the policy. Appears in audit entries, block responses, and alerts. |
| `description` | string | — | `""` | Why this rule exists. Future-you will thank you. |
| `layer` | string | ✅ | — | Which layer's verdicts this rule reads: `heuristic`, `semantic`, `context`, `output`, or a plugin's `name`. |
| `condition` | mapping | ✅ | — | When the rule fires. See below. |
| `action` | enum | ✅ | — | `allow` \| `warn` \| `block` \| `redact` \| `terminate_session`. |
| `alert` | bool | — | `false` | Also emit a warning to the `thorn.alerts` logger when the rule fires. |

### `rules[].condition`

All present conditions must hold (AND semantics):

| Field | Type | Default | Description |
|---|---|---|---|
| `verdict` | `suspicious` \| `malicious` | — | Fires on this verdict **or stricter** — a `suspicious` condition is satisfied by a `malicious` verdict. |
| `confidence_above` | float 0.0–1.0 | `0.0` | The verdict's confidence must exceed this. |
| `session_risk_above` | float ≥ 0 | — | Accumulated session risk (0–10 scale) must exceed this. Requires session tracking; meaningful for `context` rules. |
| `turn_count_above` | int ≥ 0 | — | The session must have more turns than this. |

### `rules[].action` semantics

| Action | Input rule | Output rule |
|---|---|---|
| `allow` | explicit allow (still audited) | same |
| `warn` | forward; decision logged, `x-thorn-warning` header set (proxy) | deliver; logged |
| `block` | request never reaches the LLM; client gets 403 with rule ids | response never reaches the client; 403 |
| `redact` | forwarded; treat as warn on input | PII patterns in the response replaced with `[REDACTED]` |
| `terminate_session` | block **and** mark the session dead — every subsequent request on it is blocked until the session expires | same |

When several rules fire on one request, the most severe action wins:
`terminate_session > block > redact > warn > allow`.

## `policy.defaults`

| Field | Type | Default | Description |
|---|---|---|---|
| `on_layer_error` | `allow` \| `block` | `block` | What happens when a layer raises at runtime (e.g. Ollama down). `block` = fail-closed: requests rejected until healthy. `allow` = fail-open: remaining layers still run and decide. |
| `max_session_turns` | int ≥ 1 | `50` | Sessions reset (fresh risk score) after this many turns. |
| `session_ttl_seconds` | int ≥ 1 | `3600` | Idle sessions reset after this long. |

## Complete annotated example

```yaml
policy:
  name: example
  version: 1.0.0
  description: Demonstrates every field.

  layers:
    heuristic: true
    semantic: true
    context: true
    output: true

  plugins:
    - "thorn_topic_guard.TopicGuardLayer"

  rules:
    # Signature attacks: block at high confidence, warn below.
    - id: block-signatures
      description: Known attack patterns, high confidence.
      layer: heuristic
      condition: {verdict: malicious, confidence_above: 0.8}
      action: block
      alert: true

    - id: warn-soft-signatures
      layer: heuristic
      condition: {verdict: suspicious, confidence_above: 0.5}
      action: warn

    # Intent classifier: block clear attacks.
    - id: block-bad-intent
      layer: semantic
      condition: {verdict: malicious, confidence_above: 0.8}
      action: block
      alert: true

    # Trajectory: block escalating sessions, terminate runaway ones.
    - id: block-escalation
      layer: context
      condition: {verdict: malicious, confidence_above: 0.6}
      action: block
      alert: true

    - id: terminate-runaway
      layer: context
      condition:
        verdict: malicious
        confidence_above: 0.6
        session_risk_above: 9.0
      action: terminate_session
      alert: true

    # Output: never deliver a compromised response; scrub PII.
    - id: block-compromised-output
      layer: output
      condition: {verdict: malicious, confidence_above: 0.8}
      action: block
      alert: true

    - id: redact-pii
      layer: output
      condition: {verdict: suspicious, confidence_above: 0.5}
      action: redact

    # Plugin rule: layer name matches the plugin's `name` property.
    - id: block-off-topic
      layer: topic_guard
      condition: {verdict: malicious, confidence_above: 0.7}
      action: block

  defaults:
    on_layer_error: block
    max_session_turns: 50
    session_ttl_seconds: 3600
```

## Validation errors

Invalid policies fail at startup with the path to the offending field:

```
policy error: policy file my-policy.yaml is invalid (1 error(s)):
  - policy.rules.2.action: Input should be 'allow', 'warn', 'block', 'redact' or 'terminate_session'
see policies/README.md for the full schema reference
```
