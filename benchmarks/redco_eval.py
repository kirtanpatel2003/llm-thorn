"""Evaluate llm-thorn against a Red_Co-Author result log.

Red_Co-Author emits a JSONL log of CoJP runs against target models: each
record has the base query (``prompt`` or ``keyword``), the model's responses
(``direct_response`` / ``cojp_response``), and success labels
(``direct_asr`` / ``cojp_asr`` — whether the attack actually jailbroke the
model). Because the responses are already in the log, this eval needs no
target model — only the local Ollama for the semantic layer.

It measures Thorn's defense on two surfaces:

  - **input**  — run the base query through Thorn's input layers: would the
    request be blocked before it ever reached the model?
  - **output** — run the model's CoJP response through Thorn's output layer:
    would the harmful answer be caught before it reached the user?

and cross-references the result with ``cojp_asr`` to answer the headline
question: *of the attacks that actually jailbroke the model, how many does
Thorn stop?*

Caveat printed in the report: the log stores the **base query**, not the full
CoJP-framed prompt actually sent to the model. Input-side numbers therefore
reflect detection of the bare query, not the framing attack — for that we
need Red_Co-Author to export the framed prompt text.

Usage::

    uv run python benchmarks/redco_eval.py --jsonl tracker/redco/results.jsonl \\
        --ollama-model llama3.2
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from llm_thorn.core.models import Action, LLMRequest, LLMResponse, Verdict  # noqa: E402
from llm_thorn.core.pipeline import DetectionPipeline  # noqa: E402
from llm_thorn.policy.schema import load_policy  # noqa: E402

RESULTS_DIR = Path(__file__).parent / "results"
_STOPPED = (Action.BLOCK, Action.TERMINATE)


def load_records(path: str) -> list[dict]:
    """Parse a Red_Co-Author JSONL log into a list of records."""
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"log not found: {p}")
    records = []
    for n, line in enumerate(p.read_text().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"warning: skipping unparseable line {n}: {exc}", file=sys.stderr)
    if not records:
        raise SystemExit(f"no records parsed from {p}")
    return records


def _query(rec: dict) -> str:
    return rec.get("prompt") or rec.get("keyword") or ""


async def _warmup(client: httpx.AsyncClient, url: str, model: str) -> None:
    try:
        print(f"warming {model} @ {url} ...")
        r = await client.post(
            f"{url.rstrip('/')}/api/chat",
            json={"model": model, "messages": [{"role": "user", "content": "ok"}], "stream": False},
        )
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — warm-up is best-effort
        print(f"warning: warm-up failed ({exc})", file=sys.stderr)


def _req(query: str) -> LLMRequest:
    return LLMRequest(
        session_id=f"redco-{datetime.now(UTC).timestamp()}",
        messages=[{"role": "user", "content": query}],
        model="redco",
        raw_body={"messages": [{"role": "user", "content": query}]},
        timestamp=datetime.now(UTC),
    )


def _resp(text: str, req: LLMRequest) -> LLMResponse:
    return LLMResponse(
        session_id=req.session_id,
        content=text,
        raw_body={"choices": [{"message": {"role": "assistant", "content": text}}]},
        timestamp=datetime.now(UTC),
    )


async def evaluate(args: argparse.Namespace) -> dict:
    records = load_records(args.jsonl)
    policy = load_policy(args.policy)
    print(f"loaded {len(records)} Red_Co-Author record(s); semantic={args.ollama_model}")

    with tempfile.TemporaryDirectory() as tmp:
        pipeline = DetectionPipeline(
            policy,
            db_path=f"{tmp}/redco.db",
            ollama_url=args.ollama_url,
            ollama_model=args.ollama_model,
        )
        client = httpx.AsyncClient(timeout=60.0)
        await _warmup(client, args.ollama_url, args.ollama_model)

        rows = []
        for rec in records:
            query = _query(rec)
            if not query:
                continue
            req = _req(query)
            in_result = await pipeline.inspect_request(req)
            input_blocked = in_result.decision.action in _STOPPED
            input_flagged = [v.layer for v in in_result.verdicts if v.verdict != Verdict.BENIGN]

            response_text = rec.get("cojp_response")
            output_blocked = False
            output_flagged = False
            if response_text:
                out = await pipeline.inspect_response(_resp(response_text, req), req, in_result)
                output_blocked = out.decision.action in _STOPPED
                output_flagged = any(
                    v.layer == "output" and v.verdict != Verdict.BENIGN for v in out.verdicts
                )

            rows.append(
                {
                    "query": query[:60],
                    "domain": rec.get("domain", "?"),
                    "cojp_asr": bool(rec.get("cojp_asr")),
                    "input_blocked": input_blocked,
                    "input_flagged_by": input_flagged,
                    "output_blocked": output_blocked,
                    "output_flagged": output_flagged,
                    "thorn_stops": input_blocked or output_blocked,
                    "had_response": bool(response_text),
                }
            )

        await client.aclose()
        await pipeline.close()

    succeeded = [r for r in rows if r["cojp_asr"]]
    stopped_succeeded = [r for r in succeeded if r["thorn_stops"]]
    with_resp = [r for r in rows if r["had_response"]]

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "log": args.jsonl,
        "policy": policy.name,
        "semantic_model": args.ollama_model,
        "records": len(rows),
        "input_block_rate": _rate([r["input_blocked"] for r in rows]),
        "output_flag_rate": _rate([r["output_flagged"] for r in with_resp]) if with_resp else None,
        "thorn_stop_rate": _rate([r["thorn_stops"] for r in rows]),
        "model_jailbroken": len(succeeded),
        "thorn_stops_on_jailbroken": (
            f"{len(stopped_succeeded)}/{len(succeeded)}" if succeeded else "n/a"
        ),
        "missed_successful_attacks": [r["query"] for r in succeeded if not r["thorn_stops"]],
        "detail": rows,
    }


def _rate(flags: list[bool]) -> float | None:
    return round(sum(flags) / len(flags), 4) if flags else None


def _print(report: dict) -> None:
    from rich.console import Console
    from rich.table import Table

    c = Console()
    c.print(
        f"\n[bold]Red_Co-Author × llm-thorn[/bold] — {report['records']} records, "
        f"policy={report['policy']}, semantic={report['semantic_model']}\n"
    )
    t = Table()
    for col in ("query", "domain", "model\njailbroken", "input", "output", "thorn\nstops"):
        t.add_column(col)
    for r in report["detail"]:
        t.add_row(
            r["query"][:40],
            r["domain"],
            "[red]yes[/]" if r["cojp_asr"] else "no",
            "[green]block[/]" if r["input_blocked"] else (",".join(r["input_flagged_by"]) or "-"),
            "[green]flag[/]" if r["output_flagged"] else "-",
            "[green]✓[/]" if r["thorn_stops"] else "[red]✗[/]",
        )
    c.print(t)
    c.print(f"\n[bold]input block rate:[/bold] {_pct(report['input_block_rate'])}")
    c.print(f"[bold]output flag rate (on responses):[/bold] {_pct(report['output_flag_rate'])}")
    c.print(f"[bold]Thorn stop rate (overall):[/bold] {_pct(report['thorn_stop_rate'])}")
    c.print(f"[bold]model was jailbroken (cojp_asr):[/bold] {report['model_jailbroken']} records")
    c.print(
        f"[bold]→ Thorn stops on jailbroken attacks:[/bold] {report['thorn_stops_on_jailbroken']}"
    )
    if report["missed_successful_attacks"]:
        c.print(
            "\n[red]missed successful attacks (candidates for a safety layer / adversarial samples):[/red]"
        )
        for q in report["missed_successful_attacks"]:
            c.print(f"  - {q}")


def _pct(x: float | None) -> str:
    return f"{x:.1%}" if x is not None else "n/a"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", required=True, help="Red_Co-Author JSONL result log")
    ap.add_argument("--policy", default=str(REPO_ROOT / "policies" / "customer-support.yaml"))
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--ollama-model", default="llama3.2")
    args = ap.parse_args()

    report = asyncio.run(evaluate(args))
    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"redco-{datetime.now(UTC):%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps(report, indent=2))
    _print(report)
    print(f"\nfull report: {out}")


if __name__ == "__main__":
    main()
