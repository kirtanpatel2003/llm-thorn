"""Adversarial regression tests against real attack samples.

Every sample in ``samples/attacks.json`` must stay detected forever. When a
bypass is reported in the wild, the fix is: add the sample here first, watch
it fail, then improve the layers until it passes.

These tests run the non-semantic stack (heuristic + context) so they work
without Ollama. They are excluded from CI by path (CI runs tests/unit and
tests/integration only) but should be run locally before every release:

    pytest tests/adversarial/
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thorn.core.models import Action, Verdict
from thorn.core.pipeline import DetectionPipeline

SAMPLES = json.loads((Path(__file__).parent / "samples" / "attacks.json").read_text())

_SEVERITY = {Verdict.BENIGN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


@pytest.fixture
def pipeline(policy, db_path) -> DetectionPipeline:
    return DetectionPipeline(policy, db_path=db_path)


@pytest.mark.parametrize(
    "sample",
    SAMPLES["single_turn"],
    ids=[s["id"] for s in SAMPLES["single_turn"]],
)
async def test_single_turn_attack_detected(pipeline, make_request, sample: dict) -> None:
    """Each known attack must be flagged at least at its expected severity."""
    result = await pipeline.inspect_request(
        make_request(sample["input"], session_id=f"adv-{sample['id']}")
    )
    worst = max(
        (v.verdict for v in result.verdicts),
        key=lambda v: _SEVERITY.get(v, 0),
        default=Verdict.BENIGN,
    )
    expected = sample["expected"]
    assert _SEVERITY[worst] >= _SEVERITY[expected], (
        f"{sample['id']} ({sample['category']}): expected at least {expected}, "
        f"got {worst} — a previously-detected attack now bypasses Thorn"
    )


@pytest.mark.parametrize(
    "sample",
    SAMPLES["multi_turn"],
    ids=[s["id"] for s in SAMPLES["multi_turn"]],
)
async def test_multi_turn_attack_blocked(pipeline, make_request, sample: dict) -> None:
    """Multi-turn sequences must be blocked by their expected turn."""
    session_id = f"adv-mt-{sample['id']}"
    blocked_at: int | None = None
    for turn_number, turn in enumerate(sample["turns"], start=1):
        result = await pipeline.inspect_request(make_request(turn, session_id=session_id))
        if result.decision.action in (Action.BLOCK, Action.TERMINATE):
            blocked_at = turn_number
            break
    assert blocked_at is not None, (
        f"{sample['id']}: the full sequence ran without a block — "
        "multi-turn detection has regressed"
    )
    assert blocked_at <= sample["expect_block_by_turn"]


@pytest.mark.parametrize(
    "sample",
    SAMPLES["benign_controls"],
    ids=[s["id"] for s in SAMPLES["benign_controls"]],
)
async def test_benign_controls_pass(pipeline, make_request, sample: dict) -> None:
    """False positive guard: ordinary traffic must not be blocked."""
    result = await pipeline.inspect_request(
        make_request(sample["input"], session_id=f"adv-benign-{sample['id']}")
    )
    assert result.decision.action in (Action.ALLOW, Action.WARN), (
        f"{sample['id']}: benign input was {result.decision.action} — false positive"
    )
