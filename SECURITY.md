# Security Policy

Thorn is a security tool, so we hold ourselves to the standard we ask of
others: clear disclosure paths, fast triage, and honest communication about
limitations.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest release) | ✅ |
| older | ❌ — upgrade to the latest release |

## Reporting a vulnerability

**For vulnerabilities in Thorn itself** (anything that could compromise a
deployment: auth bypass in the proxy, audit-chain forgery, policy-engine
logic errors, injection into Thorn's own components):

1. **Do not open a public issue.**
2. Use GitHub's private vulnerability reporting:
   [Security → Report a vulnerability](https://github.com/kirtanpatel2003/thorn/security/advisories/new).
3. Include: affected version, reproduction steps, and impact assessment.

You will get an acknowledgment within **72 hours** and a triage verdict
within **7 days**. We coordinate disclosure timing with you; our default is
publishing a GitHub Security Advisory with the fix release.

## Detection bypasses are different

A prompt/jailbreak that slips past the detection layers is **not** a
vulnerability in this sense — it is expected, ongoing cat-and-mouse, and we
handle it in public so the whole community benefits:

- Open a regular issue with the **bypass** label
  ([template](.github/ISSUE_TEMPLATE/new_layer.md)), including the exact
  input(s) and which layer you expected to catch it.
- Even better: submit a PR adding the sample to
  `tests/adversarial/samples/attacks.json` — every confirmed bypass becomes
  a permanent regression test.

Use private reporting only if the bypass exposes a *systemic* flaw (e.g. a
class of encoding that blinds an entire layer) that attackers could weaponize
at scale before a fix ships.

## Scope notes for deployers

Honest statements about what Thorn does and does not protect, so your threat
model is accurate:

- Thorn reduces risk; it is **defense in depth, not a guarantee**. No
  detection stack catches every attack.
- The audit chain detects modification, deletion, and reordering of entries
  — but truncation from the tail is only detectable if you anchor the head
  hash externally (see [docs/architecture.md](docs/architecture.md)).
- The proxy adds no authentication between client and Thorn in v0.1; deploy
  it on a trusted network segment.
- Streaming responses are rejected, not inspected, in v0.1.

## Hall of fame

Reporters of valid vulnerabilities and novel bypass classes are credited in
release notes (unless you prefer anonymity).
