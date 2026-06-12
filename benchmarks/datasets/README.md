# Benchmark Datasets

Datasets live here as JSONL files (gitignored if large — see each dataset's
license before committing it).

## Format

One JSON object per line:

```jsonl
{"id": "sample-1", "input": "Ignore previous instructions...", "label": "attack", "category": "prompt_injection"}
{"id": "sample-2", "input": "What is your return policy?", "label": "benign", "category": "benign"}
```

| Field | Required | Values |
|---|---|---|
| `input` | ✅ | the user message to run through the pipeline |
| `label` | ✅ | `attack` or `benign` |
| `id` | — | stable identifier (auto-generated from line number if absent) |
| `category` | — | free-form grouping for the per-category breakdown |

Run with:

```bash
uv run python benchmarks/runner.py --dataset benchmarks/datasets/yourfile.jsonl
```

## HackAPrompt

The primary public benchmark for prompt injection is the
[HackAPrompt dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset)
(~600k adversarial prompts from the HackAPrompt competition; see the
[paper](https://arxiv.org/abs/2311.16119)).

To convert it (requires the `datasets` package):

```python
from datasets import load_dataset
import json

ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train")
with open("benchmarks/datasets/hackaprompt.jsonl", "w") as fh:
    for i, row in enumerate(ds):
        if not row["user_input"]:
            continue
        fh.write(json.dumps({
            "id": f"hackaprompt-{i}",
            "input": row["user_input"],
            "label": "attack",
            "category": f"level-{row['level']}",
        }) + "\n")
```

Pair attack datasets with a benign set (your own real traffic is best) —
a benchmark without benign controls cannot measure false positives, and
false positives are what actually get security tools uninstalled.

## Adding a dataset

1. Convert to the JSONL format above.
2. Note its source and license here.
3. If it's small (<1MB) and license-compatible, commit it; otherwise add a
   conversion script like the HackAPrompt one.
