# Changelog

All notable changes to Thorn are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Thorn adheres
to [Semantic Versioning](https://semver.org/): the `BaseLayer` plugin
interface only changes on major versions.

## [Unreleased]

### Added

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
  (`thorn start`), SDK wrapper (`thorn.guard()`), and ASGI middleware
  (`thorn.ThornMiddleware`).
- **Policy-as-code**: Pydantic-validated YAML policies with per-layer rules,
  five actions (allow/warn/block/redact/terminate_session), configurable
  fail-open/fail-closed error handling, and actionable validation errors.
- **Hash-chained audit log** in SQLite with `thorn audit verify` (integrity
  check, exit code 0/1) and `thorn audit report` (time-window and
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
