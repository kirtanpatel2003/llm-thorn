---
name: New layer / bypass report
about: Propose a detection layer, or report an attack that bypasses Thorn
labels: layer
---

<!-- Bypass reports are the most valuable issues we receive. -->

## Type

- [ ] Bypass: an attack Thorn should catch but doesn't
- [ ] New built-in layer proposal
- [ ] Community plugin announcement (link your repo!)

## For bypasses: the attack

```
# the exact input(s) — for multi-turn, list each turn in order
```

- Which layer did you expect to catch it?
- Verdicts Thorn actually produced (from `thorn audit report` or logs):
- Policy template used:

## For layer proposals: what it detects

<!-- The threat, the detection approach, expected latency, and whether it
     needs I/O (=> async). Note: detection logic usually starts life as a
     community plugin (thorn-<name> on PyPI) and gets promoted to built-in
     if it proves broadly useful. -->
