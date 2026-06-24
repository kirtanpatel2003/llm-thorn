# Changelog

All notable changes to Thorn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Thorn adheres
to [Semantic Versioning](https://semver.org/): the `BaseLayer` plugin
interface only changes on major versions.

## [Unreleased]

## [0.1.1] — 2026-06-24

### Changed

- **Renamed the project to `llm-thorn`** (the `thorn` name was taken on PyPI).
  This covers the distribution name (`pip install llm-thorn`), the Python
  package (`import llm_thorn`), the CLI command (`llm-thorn`), and the HTTP
  wire API: header prefix `X-LLM-Thorn-*`, health endpoint `/llm-thorn/health`,
  error type `llm_thorn_policy` / codes `llm_thorn_<action>`, and the default
  database filename (`llm-thorn.db`).
- The package version is now single-sourced from `llm_thorn/__init__.py`
  (hatch dynamic version) so `pyproject.toml` can no longer drift from it.

### Added

- **`llm-thorn init`** — scaffolds a ready-to-run starter `policy.yaml`
  (no Ollama required) so a fresh `pip install` works immediately, since the
  wheel ships no policy files. The template is validated before it is written.
  Also exposes `llm_thorn.policy.load_policy_from_text()` for validating a
  policy held as a string.
- **Request body-size guard**: an inspected request body larger than 10 MiB is
  rejected with HTTP 413 instead of being buffered into memory.
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

### Fixed

- `llm-thorn audit report` could drop matching rows when `--session` and
  `--last` were combined: the `--limit` was applied before the session
  filter. The report now filters by session and time window before limiting.
- README quickstart shipped a `[placeholder: terminal GIF …]` note; replaced
  with a real captured block-and-audit transcript.

### Security

- The backend forwarder now pins the upstream host: a crafted request path can
  no longer redirect a forwarded request to a different host (defense-in-depth).
  Resolves the open CodeQL code-scanning findings (incl. a partial-SSRF report),
  alongside lint/quality cleanups across the package.

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
