# Testing Thorn — help us find the gaps

Thorn is young, and the only way a security tool gets good is by being attacked
by people who are better at it than its author. If you work on prompt-injection
defense, red-teaming, or you just ship LLM features and want to stress them:
**point Thorn at your traffic, try to get something past it, and tell us where
it fails.** Every bypass you find is a gap we close.

This guide gets you from zero to a running proxy in a couple of minutes.

## 1. Install

```bash
pip install llm-thorn
# not published yet? install straight from source:
pip install git+https://github.com/kirtanpatel2003/llm-thorn
```

## 2. Run it in front of your provider

Thorn is a reverse proxy: you change one `base_url` and your API key flows
through untouched (Thorn only *hashes* it to group a session — it is never
logged in the clear).

**OpenAI (and any OpenAI-compatible endpoint):**

```bash
llm-thorn start --policy policies/customer-support.yaml \
  --upstream https://api.openai.com --backend openai
```
```python
import openai
client = openai.OpenAI(base_url="http://localhost:8080/v1")   # keep your OPENAI_API_KEY
```

**Anthropic:**

```bash
llm-thorn start --policy policies/customer-support.yaml \
  --upstream https://api.anthropic.com --backend anthropic
```
```python
import anthropic
client = anthropic.Anthropic(base_url="http://localhost:8080")  # keep your ANTHROPIC_API_KEY
```

> **No local Ollama?** The semantic (layer 2) and safety (layer 5) layers need
> one. Set `semantic: false` and `safety: false` under `layers:` in your policy
> and the other three layers run with zero setup. With Ollama running
> (`ollama pull llama3.2`), leave them on for the full stack.

## 3. Try to break it

- Throw your nastiest prompt-injection and jailbreak payloads at it (role
  override, delimiter hijacking, DAN/AIM templates, base64/leetspeak evasion,
  indirect injection).
- Run a **multi-turn** probe across a session (send a stable
  `X-LLM-Thorn-Session-Id` header) and see whether escalation gets caught.
- Use [**Red_Co-Author**](https://github.com/kirtanpatel2003/Red_Co-Author),
  our companion attack generator, to fire Co-Authoring Jailbreak (CoJP) framing
  attacks at a Thorn-guarded endpoint.
- Watch what Thorn decided — every request is in the tamper-evident log:

```bash
llm-thorn audit report --db ./llm-thorn.db --last 24h
llm-thorn audit verify --db ./llm-thorn.db
```

## 4. Tell us what you found

- **A bypass, false positive, or rough edge** → open an
  [issue](https://github.com/kirtanpatel2003/llm-thorn/issues). Include the
  payload, the policy you ran, and what you expected vs. what happened.
- **Something sensitive** (a systemic bypass class, a real-world exploit) →
  please use **private** reporting:
  [Security → Report a vulnerability](https://github.com/kirtanpatel2003/llm-thorn/security/advisories/new),
  per [SECURITY.md](SECURITY.md). We credit reporters of valid findings.

Thanks for helping make shipping AI a little safer. 🌵
