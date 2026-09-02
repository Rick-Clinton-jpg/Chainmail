# Security policy

## Scope and status

Chainmail is an **early-stage research prototype**. It is a *policy* boundary, not
a sandbox. Read [`README.md`](README.md) — specifically "What Chainmail is
not" — before deploying it anywhere real.

The parts to rely on are the deterministic ones: permission matching, the action
allow-list, hard denials, metered budgets, delegation subset math, envelope
fingerprinting, replay nonces, signature verification, schema + path validation,
and the fail-closed decision path. The contextual layer (embedding-based drift,
objective mismatch, anomaly, re-entry) is a **heuristic tripwire**, not a proof.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report privately through GitHub's *Security → Report a vulnerability* (private
advisory) on the repository, or by direct message to the maintainer. Include:

- affected version / commit,
- a minimal reproduction,
- the invariant you believe is violated (see the "Core invariants" list in the
  README, or `docs`-style notes in `CHANGELOG.md`).

Expect an acknowledgement within a few days. Because this is a prototype there is
no formal SLA, but confirmed boundary breaks are treated as the top priority and
are added to `tests/test_regressions.py` and, where they fit, to the standard
mutation family in `src/chainmail/evaluation.py`.

## What counts

In scope:

- an agent obtaining authority it was never granted without `HUMAN`,
- a delegation chain laundering more authority than any single link held,
- a context signal *expanding* the live authority set,
- a replayed proposal accepted, or an exhausted budget silently renewed,
- an envelope mutation after construction going undetected,
- a payload smuggling a path traversal past schema validation,
- a verifier/engine exception crashing the governor instead of escalating,
- a single governor forcing `CONTINUE` against quorum rules,
- an unsigned or wrongly-signed proposal being trusted when a verifier is
  configured.

Out of scope (documented limitations, not vulnerabilities):

- weak or bypassable *contextual* detection (drift/mismatch/anomaly) — it is a
  heuristic by design,
- anything requiring a compromised host process, a malicious registered handler,
  or a trusted operator,
- the single shared-secret / per-token service auth being unsuitable across an
  untrusted network (use mTLS in front),
- key material at rest in process memory (KMS backing is a v6 item).
