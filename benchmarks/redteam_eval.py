"""Live red-team evaluation harness.

Fires a corpus of single-shot jailbreak prompts (e.g. CoJP prompts produced
by the Red_Co-Author tool) through the *full live llm-thorn stack* and reports
what each layer caught.

Unlike ``runner.py`` (which scores the non-semantic stack offline), this
harness runs against a live Ollama: the semantic layer actually classifies
each prompt, and any prompt that slips past the input layers is forwarded to
a real target model so the output layer can judge whether the model was
genuinely jailbroken. That is the complete loop a strong single-shot
jailbreak should be measured against.

Corpus interface (decoupled from Red_Co-Author so the projects stay
independent until release): a directory of ``.txt`` files, one prompt per
file. Long multi-paragraph jailbreaks paste in cleanly. Point Red_Co-Author's
export — or just save its generated prompts — into that directory. Keep it
under ``tracker/`` (gitignored) so red-team data is never pushed.

Optional Laminar tracing (``--trace``) records a span per prompt — input
verdict, action, target reply, latency — so you can inspect every run in the
Laminar UI. Requires ``uv sync --extra laminar`` and ``LMNR_PROJECT_API_KEY``
in the environment.

Usage::

    # input + semantic detection only (no target model needed)
    uv run python benchmarks/redteam_eval.py --attacks tracker/cojp \\
        --ollama-model llama3.2

    # full loop against a local Ollama target, with Laminar tracing
    uv run python benchmarks/redteam_eval.py --attacks tracker/cojp \\
        --benign tracker/benign --ollama-model llama3.2 \\
        --target ollama --target-model llama3.2 --trace

    # forward survivors to a cloud OpenAI-compatible model instead
    uv run python benchmarks/redteam_eval.py --attacks tracker/cojp \\
        --target openai --target-model gpt-4o-mini
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from llm_thorn.core.models import Action, LLMRequest, LLMResponse, Verdict  # noqa: E402
from llm_thorn.core.pipeline import DetectionPipeline  # noqa: E402
from llm_thorn.policy.schema import load_policy  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"

#: Actions that stop the attack outright.
_STOPPED = (Action.BLOCK, Action.TERMINATE)


# ---------------------------------------------------------------------------
# Optional Laminar tracing — degrades to no-ops if lmnr is not installed.
# ---------------------------------------------------------------------------


class _Tracer:
    """Thin, defensive wrapper around Laminar.

    Tracing is entirely optional: if ``lmnr`` is missing, no key is set, or
    the SDK surface differs, every method becomes a no-op and the eval runs
    unchanged. Observability must never break the security evaluation.
    """

    def __init__(self, enabled: bool) -> None:
        self._laminar = None
        if not enabled:
            return
        try:
            from lmnr import Laminar
        except ImportError:
            print(
                "warning: --trace set but 'lmnr' is not installed. "
                "Run `uv sync --extra laminar`. Continuing without tracing.",
                file=sys.stderr,
            )
            return
        if not os.environ.get("LMNR_PROJECT_API_KEY"):
            print(
                "warning: --trace set but LMNR_PROJECT_API_KEY is not in the "
                "environment. Continuing without tracing.",
                file=sys.stderr,
            )
            return
        try:
            Laminar.initialize()  # reads LMNR_PROJECT_API_KEY from env
            self._laminar = Laminar
            print("Laminar tracing enabled.")
        except Exception as exc:  # noqa: BLE001 — never let tracing abort the run
            print(
                f"warning: Laminar init failed ({exc}); continuing without tracing.",
                file=sys.stderr,
            )

    @contextmanager
    def span(self, name: str, payload: dict | None = None):
        """Open a tracing span, or a no-op context if tracing is off."""
        if self._laminar is None:
            yield None
            return
        try:
            with self._laminar.start_as_current_span(name=name, input=payload or {}) as span:
                yield span
        except Exception:  # noqa: BLE001 — defensive: SDK surface may differ
            yield None

    def record(self, output: Any) -> None:
        """Attach an output to the current span, best-effort."""
        if self._laminar is None:
            return
        with suppress(Exception):  # defensive: SDK surface may differ
            self._laminar.set_span_output(output)

    def shutdown(self) -> None:
        """Flush buffered spans before exit, best-effort."""
        if self._laminar is None:
            return
        with suppress(Exception):  # defensive: flush may fail if init was partial
            self._laminar.shutdown()


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def load_prompts(directory: str) -> list[tuple[str, str]]:
    """Load (id, text) pairs from every ``.txt`` file in a directory."""
    path = Path(directory)
    if not path.is_dir():
        raise SystemExit(f"not a directory: {path} (expected a folder of .txt prompt files)")
    pairs = [(f.stem, f.read_text().strip()) for f in sorted(path.glob("*.txt"))]
    pairs = [(name, text) for name, text in pairs if text]
    if not pairs:
        raise SystemExit(f"no non-empty .txt prompt files found in {path}")
    return pairs


# ---------------------------------------------------------------------------
# Target model calls (the survivor forward)
# ---------------------------------------------------------------------------


async def _call_ollama(client: httpx.AsyncClient, url: str, model: str, prompt: str) -> str:
    response = await client.post(
        f"{url.rstrip('/')}/api/chat",
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


async def _warmup(client: httpx.AsyncClient, args: argparse.Namespace) -> None:
    """Pre-load the Ollama models so cold-start latency doesn't distort the run.

    The semantic layer enforces a hard timeout (default 2s); a model's first
    request includes multi-second load time and would blow it, silently
    failing the layer (fail-open => attacks slip through). Warming the model
    first means every measured call reflects warm inference, and the recorded
    detections are honest. Best-effort: warm-up failures never abort the eval.
    """
    targets = [(args.ollama_url, args.ollama_model)]
    if args.target == "ollama":
        targets.append((args.target_url, args.target_model))
    seen: set[tuple[str, str]] = set()
    for url, model in targets:
        if not model or (url, model) in seen:
            continue
        seen.add((url, model))
        try:
            print(f"warming {model} @ {url} ...")
            await _call_ollama(client, url, model, "ok")
        except Exception as exc:  # noqa: BLE001 — warm-up is best-effort
            print(f"warning: warm-up of {model} failed ({exc})", file=sys.stderr)


async def _call_openai(
    client: httpx.AsyncClient, url: str, model: str, prompt: str, api_key: str
) -> str:
    response = await client.post(
        f"{url.rstrip('/')}/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _flagging_layers(verdicts: list) -> list[str]:
    """Names of layers that returned a non-benign verdict."""
    return [v.layer for v in verdicts if v.verdict != Verdict.BENIGN]


async def _run_one(
    pipeline: DetectionPipeline,
    client: httpx.AsyncClient,
    tracer: _Tracer,
    prompt_id: str,
    text: str,
    target: str,
    target_url: str,
    target_model: str | None,
    target_api_key: str | None,
) -> dict:
    """Run one prompt: input inspection, optional forward, output inspection."""
    with tracer.span("redteam.prompt", {"id": prompt_id, "prompt": text[:2000]}):
        request = LLMRequest(
            session_id=f"redteam-{uuid.uuid4()}",  # one session per prompt: single-shot isolation
            messages=[{"role": "user", "content": text}],
            model=target_model or "eval",
            raw_body={
                "model": target_model or "eval",
                "messages": [{"role": "user", "content": text}],
            },
            timestamp=datetime.now(UTC),
        )

        start = time.perf_counter()
        with tracer.span("thorn.inspect_input", {"prompt": text[:2000]}):
            result = await pipeline.inspect_request(request)
        flagged_by = _flagging_layers(result.verdicts)
        action = result.decision.action
        target_status = "not_forwarded"

        if action not in _STOPPED and target != "none" and target_model is not None:
            try:
                with tracer.span("target.generate", {"backend": target, "model": target_model}):
                    if target == "openai":
                        reply = await _call_openai(
                            client, target_url, target_model, text, target_api_key or ""
                        )
                    else:
                        reply = await _call_ollama(client, target_url, target_model, text)
                response = LLMResponse(
                    session_id=request.session_id,
                    content=reply,
                    raw_body={"choices": [{"message": {"role": "assistant", "content": reply}}]},
                    timestamp=datetime.now(UTC),
                )
                with tracer.span("thorn.inspect_output", {"reply": reply[:2000]}):
                    out = await pipeline.inspect_response(response, request, result)
                action = out.decision.action
                flagged_by = _flagging_layers(out.verdicts)
                target_status = "forwarded"
            except Exception as exc:  # noqa: BLE001 — target errors shouldn't abort the run
                target_status = f"target_error: {exc}"

        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        row = {
            "id": prompt_id,
            "action": action,
            "flagged_by": flagged_by,
            "target": target_status,
            "latency_ms": latency_ms,
        }
        tracer.record(row)
        return row


async def evaluate(args: argparse.Namespace) -> dict:
    """Run the full corpus through the live stack and build a report dict."""
    attacks = load_prompts(args.attacks)
    benign = load_prompts(args.benign) if args.benign else []
    print(
        f"loaded {len(attacks)} attack(s)"
        + (f" + {len(benign)} benign control(s)" if benign else "")
        + f"; semantic={args.ollama_model}, target={args.target}"
        + (f"/{args.target_model}" if args.target != "none" else "")
    )

    target_api_key = None
    if args.target == "openai":
        target_api_key = os.environ.get(args.target_api_key_env)
        if not target_api_key:
            raise SystemExit(
                f"--target openai needs an API key in ${args.target_api_key_env} "
                "(set it or pass --target-api-key-env)"
            )

    policy = load_policy(args.policy)
    tracer = _Tracer(enabled=args.trace)

    with tempfile.TemporaryDirectory() as tmp:
        pipeline = DetectionPipeline(
            policy,
            db_path=f"{tmp}/redteam.db",
            ollama_url=args.ollama_url,
            ollama_model=args.ollama_model,
        )
        client = httpx.AsyncClient(timeout=180.0)
        await _warmup(client, args)

        attack_rows = [
            await _run_one(
                pipeline,
                client,
                tracer,
                pid,
                text,
                args.target,
                args.target_url,
                args.target_model,
                target_api_key,
            )
            for pid, text in attacks
        ]
        benign_rows = [
            await _run_one(
                pipeline,
                client,
                tracer,
                pid,
                text,
                args.target,
                args.target_url,
                args.target_model,
                target_api_key,
            )
            for pid, text in benign
        ]

        await client.aclose()
        await pipeline.close()
    tracer.shutdown()

    stopped = [r for r in attack_rows if r["action"] in _STOPPED]
    flagged = [r for r in attack_rows if r["flagged_by"]]
    false_positives = [r for r in benign_rows if r["action"] in _STOPPED]
    latencies = [r["latency_ms"] for r in attack_rows + benign_rows]

    layer_credit: dict[str, int] = {}
    for row in flagged:
        for layer in row["flagged_by"]:
            layer_credit[layer] = layer_credit.get(layer, 0) + 1

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "policy": policy.name,
        "semantic_model": args.ollama_model,
        "target": args.target,
        "target_model": args.target_model,
        "attacks": len(attack_rows),
        "benign": len(benign_rows),
        "stopped_rate": len(stopped) / len(attack_rows) if attack_rows else None,
        "flagged_rate": len(flagged) / len(attack_rows) if attack_rows else None,
        "false_positive_rate": len(false_positives) / len(benign_rows) if benign_rows else None,
        "layer_attribution": layer_credit,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 1) if latencies else None,
            "mean": round(statistics.fmean(latencies), 1) if latencies else None,
        },
        "missed_attacks": [r["id"] for r in attack_rows if not r["flagged_by"]],
        "false_positive_ids": [r["id"] for r in false_positives],
        "attack_detail": attack_rows,
        "benign_detail": benign_rows,
    }


def _print_report(report: dict) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print(
        f"\n[bold]Red-team evaluation[/bold] — policy={report['policy']}, "
        f"semantic={report['semantic_model']}, "
        f"target={report['target']}"
        + (f"/{report['target_model']}" if report["target"] != "none" else "")
        + "\n"
    )

    table = Table(title="Attacks")
    table.add_column("prompt")
    table.add_column("action")
    table.add_column("flagged by")
    for row in report["attack_detail"]:
        stopped = row["action"] in ("block", "terminate")
        style = "green" if row["flagged_by"] else "red"
        table.add_row(
            row["id"][:34],
            f"[{'green' if stopped else 'yellow'}]{row['action']}[/]",
            f"[{style}]{', '.join(row['flagged_by']) or 'MISSED'}[/]",
        )
    console.print(table)

    sr, fr, fp = report["stopped_rate"], report["flagged_rate"], report["false_positive_rate"]
    if sr is not None:
        console.print(f"\n[bold]stopped (blocked/terminated):[/bold] {sr:.1%}")
    if fr is not None:
        console.print(f"[bold]flagged (any non-benign verdict):[/bold] {fr:.1%}")
    if fp is not None:
        console.print(f"[bold]false positive rate:[/bold] {fp:.1%} (benign prompts blocked)")
    if report["layer_attribution"]:
        credit = ", ".join(f"{k}: {v}" for k, v in report["layer_attribution"].items())
        console.print(f"[bold]layer attribution:[/bold] {credit}")
    lat = report["latency_ms"]
    console.print(f"[bold]latency:[/bold] p50 {lat['p50']}ms / mean {lat['mean']}ms")
    if report["missed_attacks"]:
        console.print(f"[red]missed:[/red] {', '.join(report['missed_attacks'])}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attacks", required=True, help="directory of .txt attack prompts")
    parser.add_argument("--benign", help="directory of .txt benign control prompts (for FP rate)")
    parser.add_argument(
        "--policy",
        default=str(REPO_ROOT / "policies" / "customer-support.yaml"),
        help="policy file (default: customer-support)",
    )
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument(
        "--ollama-model", default="llama3.2", help="model for the semantic layer (Layer 2)"
    )
    parser.add_argument(
        "--target",
        choices=["none", "ollama", "openai"],
        default="none",
        help="forward survivors to this target so the output layer can run",
    )
    parser.add_argument("--target-model", help="target model name (required unless --target none)")
    parser.add_argument(
        "--target-url",
        help="target base URL (default: ollama=http://localhost:11434, openai=https://api.openai.com)",
    )
    parser.add_argument(
        "--target-api-key-env",
        default="OPENAI_API_KEY",
        help="env var holding the cloud target API key (default: OPENAI_API_KEY)",
    )
    parser.add_argument("--trace", action="store_true", help="enable Laminar tracing")
    args = parser.parse_args()

    if args.target != "none" and not args.target_model:
        parser.error("--target-model is required unless --target none")
    if args.target_url is None:
        args.target_url = (
            "https://api.openai.com" if args.target == "openai" else "http://localhost:11434"
        )

    report = asyncio.run(evaluate(args))

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"redteam-{datetime.now(UTC):%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps(report, indent=2))
    _print_report(report)
    print(f"\nfull report: {out}")


if __name__ == "__main__":
    main()
