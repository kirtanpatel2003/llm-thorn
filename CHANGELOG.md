# Changelog

All notable changes to Thorn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Thorn adheres
to [Semantic Versioning](https://semver.org/): the `BaseLayer` plugin
interface only changes on major versions.

## [Unreleased]

### Changed

- **Renamed the project to `llm-thorn`** (the `thorn` name was taken on PyPI).
  This covers the distribution name (`pip install llm-thorn`), the Python
  package (`import llm_thorn`), the CLI command (`llm-thorn`), and the HTTP
  wire API: header prefix `X-LLM-Thorn-*`, health endpoint `/llm-thorn/health`,
  error type `llm_thorn_policy` / codes `llm_thorn_<action>`, and the default
  database filename (`llm-thorn.db`).

### Added

- **Content-safety layer (Layer 5)** — a local LLM judge that scores the
  model's *response* for harmful content (weapons, explosives, drugs, CBRN,
  malware, violence). It defends against harmful-content elicitation —
  framing attacks like the Co-Authoring Jailbreak (CoJP) that coax a model
  into dangerous output without tripping any injection signature. Because it
  judges the response, it protects OpenAI, Anthropic, and local upstreams
  identically. On by default; disable via `layers.safety: false`.
- `benchmarks/redco_eval.py`: evaluates llm-thorn against a Red_Co-Author
  CoJP result log, measuring input-side and output-side (safety) detection
  and the stop rate among attacks that actually jailbroke the target model.
- Live red-team evaluation harness (`benchmarks/redteam_eval.py`): fires a
  corpus of single-shot jailbreak prompts through the full live stack
  (semantic layer included), forwards survivors to an Ollama or cloud target
  so the output layer can judge real responses, and reports per-layer
  detection. Reads a directory of `.txt` prompts — the integration point for
  external red-team tools.
- Optional Laminar tracing for the eval harness (`--trace`, `laminar` extra):
  one span per prompt covering input verdict, target generation, and output
  inspection. Degrades to a no-op when `lmnr` or the API key is absent.
- CI restructured into independent status checks (lint, format, test on
  3.11/3.12, adversarial-regression, policy-templates, build) so branch
  protection can require each individually.
- Security workflows: weekly + per-commit dependency CVE audit (pip-audit),
  full-history secret scanning (gitleaks), CodeQL analysis, and PR
  dependency review.
- The adversarial regression suite now gates every commit in CI (it runs
  the non-semantic stack, so no Ollama is needed).

## [0.1.0] — 2026-06-12

Initial release.

### Added

- **Four detection layers**: heuristic signature matching (60+ patterns
  across role override, delimiter injection, prompt extraction, jailbreak
  templates, encoding evasion, indirect injection), semantic intent
  classification via local Ollama, multi-turn context risk scoring, and
  output anomaly detection (prompt leakage, injection success, PII, deny
  terms).
- **Three integration modes** running one shared pipeline: reverse proxy
  (`llm-thorn start`), SDK wrapper (`llm_thorn.guard()`), and ASGI middleware
  (`llm_thorn.ThornMiddleware`).
- **Policy-as-code**: Pydantic-validated YAML policies with per-layer rules,
  five actions (allow/warn/block/redact/terminate_session), configurable
  fail-open/fail-closed error handling, and actionable validation errors.
- **Hash-chained audit log** in SQLite with `llm-thorn audit verify` (integrity
  check, exit code 0/1) and `llm-thorn audit report` (time-window and
  per-session summaries).
- **Plugin system**: community layers via `BaseLayer`, loaded from policy
  YAML (`plugins:`), with a fully documented reference plugin
  (`plugins/example/`).
- **Backends**: OpenAI (and OpenAI-compatible endpoints), Anthropic Messages
  API, and Ollama.
- **Policy templates**: customer-support, healthcare, fintech, and
  coding-assistant, each documenting its threat model and threshold choices.
- **Adversarial regression suite**: 28 real attack samples + benign-control
  false-positive guards.

### Known limitations

- Streaming responses are not supported; streaming requests receive a clear
  400 (planned for a future release).
- The SDK wrapper targets synchronous OpenAI-compatible clients; async
  applications should use the proxy or middleware modes.
- Audit chain truncation from the tail is detectable only with external
  anchoring of the head hash (see docs/architecture.md).
