## What this PR does

<!-- One paragraph. Link related issues. -->

## Type of change

- [ ] Bug fix
- [ ] New detection capability (layer / signatures / signals)
- [ ] New backend
- [ ] Policy template
- [ ] Docs
- [ ] Other

## Checklist

- [ ] `uv run pytest tests/` passes
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass
- [ ] New public APIs have docstrings and full type annotations
- [ ] New detection logic includes adversarial samples in
      `tests/adversarial/samples/` (attacks it catches + benign controls
      it doesn't flag)
- [ ] Performance budgets respected (L1/L4 < 5ms, L3 < 10ms — no I/O in
      sync layers)
- [ ] `BaseLayer` / `AbstractBackend` signatures unchanged (breaking them
      requires a major version discussion first)
- [ ] CHANGELOG.md updated under *Unreleased*
