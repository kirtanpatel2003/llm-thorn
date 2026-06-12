"""Thorn benchmark runner.

Measures detection rate, false positive rate, and latency of the detection
pipeline against labeled datasets, and writes a JSON report to
``benchmarks/results/``.

Usage::

    # built-in adversarial suite (no Ollama required)
    uv run python benchmarks/runner.py --dataset adversarial

    # a JSONL dataset (see benchmarks/datasets/README.md for the format)
    uv run python benchmarks/runner.py --dataset benchmarks/datasets/hackaprompt.jsonl

    # include the semantic layer (requires local Ollama)
    uv run python benchmarks/runner.py --dataset adversarial --semantic
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from thorn.core.models import Action, LLMRequest  # noqa: E402
from thorn.core.pipeline import DetectionPipeline  # noqa: E402
from thorn.policy.schema import load_policy  # noqa: E402

ADVERSARIAL_SAMPLES = REPO_ROOT / "tests" / "adversarial" / "samples" / "attacks.json"
RESULTS_DIR = Path(__file__).parent / "results"
BENCH_POLICY = REPO_ROOT / "policies" / "customer-support.yaml"


def load_dataset(spec: str) -> list[dict]:
    """Load a dataset as a list of {id, input, label, category} dicts.

    ``label`` is "attack" or "benign". The built-in "adversarial" spec maps
    the repo's regression samples; anything else is a JSONL path.
    """
    if spec == "adversarial":
        raw = json.loads(ADVERSARIAL_SAMPLES.read_text())
        samples = [
            {"id": s["id"], "input": s["input"], "label": "attack", "category": s["category"]}
            for s in raw["single_turn"]
        ]
        samples += [
            {"id": s["id"], "input": s["input"], "label": "benign", "category": "benign"}
            for s in raw["benign_controls"]
        ]
        return samples

    path = Path(spec)
    if not path.exists():
        raise SystemExit(
            f"dataset not found: {path}\nsee benchmarks/datasets/README.md for how to add datasets"
        )
    samples = []
    with path.open() as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            samples.append(
                {
                    "id": record.get("id", f"line-{line_number}"),
                    "input": record["input"],
                    "label": record["label"],
                    "category": record.get("category", "unknown"),
                }
            )
    return samples


async def run_benchmark(samples: list[dict], semantic: bool) -> dict:
    """Run every sample through a fresh pipeline; return the report dict."""
    policy = load_policy(BENCH_POLICY)
    policy.layers.semantic = semantic

    with tempfile.TemporaryDirectory() as tmp:
        pipeline = DetectionPipeline(policy, db_path=f"{tmp}/bench.db")

        per_category: dict[str, dict[str, int]] = {}
        latencies_ms: list[float] = []
        false_positives: list[str] = []
        missed: list[str] = []

        for sample in samples:
            request = LLMRequest(
                session_id=f"bench-{uuid.uuid4()}",  # isolation: one session per sample
                messages=[{"role": "user", "content": sample["input"]}],
                model="bench",
                raw_body={"messages": [{"role": "user", "content": sample["input"]}]},
                timestamp=datetime.now(UTC),
            )
            start = time.perf_counter()
            result = await pipeline.inspect_request(request)
            latencies_ms.append((time.perf_counter() - start) * 1000)

            flagged = result.decision.action in (Action.BLOCK, Action.TERMINATE, Action.WARN)
            bucket = per_category.setdefault(
                sample["category"], {"total": 0, "detected": 0, "false_positive": 0}
            )
            bucket["total"] += 1
            if sample["label"] == "attack":
                if flagged:
                    bucket["detected"] += 1
                else:
                    missed.append(sample["id"])
            elif result.decision.action in (Action.BLOCK, Action.TERMINATE):
                bucket["false_positive"] += 1
                false_positives.append(sample["id"])

        await pipeline.close()

    attacks = [s for s in samples if s["label"] == "attack"]
    benign = [s for s in samples if s["label"] == "benign"]
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "policy": policy.name,
        "semantic_layer": semantic,
        "samples": len(samples),
        "detection_rate": (len(attacks) - len(missed)) / len(attacks) if attacks else None,
        "false_positive_rate": len(false_positives) / len(benign) if benign else None,
        "latency_ms": {
            "p50": round(statistics.median(latencies_ms), 2),
            "p95": round(statistics.quantiles(latencies_ms, n=20)[18], 2)
            if len(latencies_ms) >= 20
            else round(max(latencies_ms), 2),
            "mean": round(statistics.fmean(latencies_ms), 2),
        },
        "per_category": per_category,
        "missed_attacks": missed,
        "false_positives": false_positives,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="adversarial",
        help="'adversarial' (built-in) or a path to a JSONL dataset",
    )
    parser.add_argument(
        "--semantic",
        action="store_true",
        help="enable the semantic layer (requires local Ollama)",
    )
    args = parser.parse_args()

    samples = load_dataset(args.dataset)
    print(f"running {len(samples)} samples (semantic={args.semantic})...")
    report = asyncio.run(run_benchmark(samples, semantic=args.semantic))

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"bench-{datetime.now(UTC):%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps(report, indent=2))

    detection = report["detection_rate"]
    fp = report["false_positive_rate"]
    print(f"detection rate:      {detection:.1%}" if detection is not None else "no attacks in set")
    print(f"false positive rate: {fp:.1%}" if fp is not None else "no benign samples in set")
    print(f"latency p50/p95:     {report['latency_ms']['p50']}ms / {report['latency_ms']['p95']}ms")
    if report["missed_attacks"]:
        print(f"missed: {', '.join(report['missed_attacks'])}")
    print(f"report written to {out}")


if __name__ == "__main__":
    main()
