# OpenAI Backend

The default backend. Covers api.openai.com **and every OpenAI-compatible
endpoint** — Azure OpenAI (chat completions route), Together, Groq,
OpenRouter, vLLM, LiteLLM, LM Studio, and anything else speaking the OpenAI
wire format.

## Usage

```bash
# OpenAI itself
thorn start --policy ./policy.yaml --upstream https://api.openai.com

# Any OpenAI-compatible provider — same backend, different upstream
thorn start --policy ./policy.yaml --upstream https://api.groq.com/openai
thorn start --policy ./policy.yaml --upstream http://localhost:8000   # vLLM
```

Client side, change only the base URL:

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    # api_key stays exactly as before — Thorn forwards your Authorization
    # header to the upstream untouched and never stores it.
)
```

## Inspected paths

Requests to paths ending in these suffixes run through the detection
pipeline:

- `/chat/completions`
- `/completions`
- `/responses`

Everything else (`/models`, `/embeddings`, `/files`, ...) is forwarded
verbatim with no inspection and no audit entry.

## Sessions

Send `X-Thorn-Session-Id` per conversation for precise multi-turn tracking:

```python
client.chat.completions.create(
    model="gpt-4o-mini",
    messages=messages,
    extra_headers={"X-Thorn-Session-Id": f"user-{user_id}-chat-{chat_id}"},
)
```

Without it, turns are grouped by a stable hash of client credentials +
source IP.

## Normalization notes

- `messages` is already Thorn's canonical shape — passthrough.
- Vision/content-part messages: text parts are flattened for inspection;
  the original body is forwarded untouched.
- Response text is read from `choices[0].message.content` (string or
  content-part list).

## Limitations

- `stream: true` requests are rejected with a clear 400 in v0.1 — set
  `stream: false`. Streaming inspection is on the roadmap.
- Function/tool-call arguments in responses are not yet inspected as text.
