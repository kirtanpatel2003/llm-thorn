"""Unit tests for the CLI — focused on `llm-thorn init` scaffolding."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from llm_thorn.cli import app
from llm_thorn.policy.schema import load_policy

runner = CliRunner()


def test_init_writes_a_loadable_policy(tmp_path: Path) -> None:
    out = tmp_path / "policy.yaml"
    result = runner.invoke(app, ["init", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    # The whole point: the generated file must pass the real validator.
    policy = load_policy(out)
    assert policy.name == "starter"
    # Ships runnable with no Ollama — semantic/safety off by default.
    assert policy.layers.semantic is False
    assert policy.layers.safety is False


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "policy.yaml"
    out.write_text("do not clobber me")
    result = runner.invoke(app, ["init", "--output", str(out)])
    assert result.exit_code == 1
    assert out.read_text() == "do not clobber me"  # left untouched


def test_init_force_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "policy.yaml"
    out.write_text("stale")
    result = runner.invoke(app, ["init", "--output", str(out), "--force"])
    assert result.exit_code == 0, result.output
    assert load_policy(out).name == "starter"
