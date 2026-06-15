# Anthropic Backend

Native support for the Anthropic Messages API (`api.anthropic.com`).

## Usage

```bash
llm-thorn start --policy ./policy.yaml \
    --upstream https://api.anthropic.com \
    --backend anthropic
```

Client side:

```python
import anthropic

client = anthropic.Anthropic(
    base_url="http://localhost:8080",
    # x-api-key and anthropic-version headers are forwarded untouched.
)

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system="You are a support assistant for Acme.",
    messages=[{"role": "user", "content": "hello"}],
    extra_headers={"X-LLM-Thorn-Session-Id": "user-42-chat-7"},
)
```

## Inspected paths

- `/messages` (i.e. `/v1/messages`)

Other paths are forwarded verbatim.

## Normalization notes

Anthropic's wire format differs from OpenAI's in two ways Thorn absorbs:

1. **`system` is a top-level parameter, not a message.** The backend folds
   it into a leading `{"role": "system"}` message in the normalized view,
   so Layer 4's system-prompt-leak detection works identically to OpenAI.
   String and content-block forms of `system` are both handled.
2. **Content is a list of typed blocks.** Text blocks are flattened to
   plain text for inspection (both in requests and responses). The original
   body is forwarded byte-for-byte.

Blocked requests return Thorn's standard 403 error envelope; the Anthropic
SDK surfaces it as a `PermissionDeniedError`.

## Limitations

- `stream: true` is rejected with a clear 400 in v0.1.
- Tool-use blocks in responses are not yet inspected as text.
