# Thorn reverse proxy image.
#
# Build (from the repo root):
#   docker build -f docker/Dockerfile -t llm-thorn .
#
# Run:
#   docker run -p 8080:8080 \
#     -v $(pwd)/policies:/policies \
#     -v llm-thorn-data:/data \
#     llm-thorn start --policy /policies/customer-support.yaml \
#       --upstream https://api.openai.com \
#       --host 0.0.0.0 --port 8080 --db /data/llm-thorn.db
#
# Note: the semantic layer needs an Ollama reachable from the container —
# pass --ollama-url http://host.docker.internal:11434 or run Ollama as a
# sidecar; or disable it in the policy (layers.semantic: false).

FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY llm_thorn ./llm_thorn

# Install the project and locked dependencies into an isolated venv.
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.11-slim

RUN groupadd -r thorn && useradd -r -g thorn thorn \
    && mkdir /data && chown thorn:thorn /data

COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER thorn
WORKDIR /data
EXPOSE 8080

ENTRYPOINT ["llm-thorn"]
CMD ["--help"]
