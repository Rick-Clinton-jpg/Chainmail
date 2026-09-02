# Chainmail v5.1 — handoff brief

You are picking up a finished project. This file is everything you need to
understand it, work on it, or publish it. Read it fully before touching code.

---

## 0. TL;DR — current state

- **What:** `chainmail` — a policy-hard, context-fluid governance layer for
  long-running multi-agent systems. A governor evaluates an agent's proposed
  action and returns `CONTINUE` / `RESTRICT` / `RECHECK` / `HUMAN`.
- **Status:** v5.1, complete. `python -m pytest -q` → **101 passed**. `demo_v5.py`
  runs clean (mutation harness kills 9/9).
- **Git:** this tree is a git repo. One commit, `7ced897`, authored
  `Rick Clinton <307349629+Rick-Clinton-jpg@users.noreply.github.com>`. Remote
  `origin` = `https://github.com/Rick-Clinton-jpg/Chainmail.git` (an **empty**
  GitHub repo). **Do not `git init`** — it would clobber `.git/`.
- **Only remaining task:** `git push -u origin main`. Everything else is done.
- **License:** PolyForm Noncommercial 1.0.0, `Copyright 2026 Rick Clinton`.

---

## 1. What Chainmail is (and is not)

Agents may plan and propose freely. Chainmail — not the agent — decides whether a
proposed action is inside the human-declared **authority envelope**. It contains
no LLM. It is the *trajectory* governor; the *single-action* boundary is a
generic, independent seam (`chainmail.execution_boundary`) that any sibling
project can plug into -- e.g. Armour (see §9) -- with no dependency in either
direction.

```
Agent / harness               Intent & planning     Fluid work inside the envelope
      |
chainmail.governor            Trajectory            objective continuity, authority flow,
                                                     delegation, drift, cross-agent anomaly,
                                                     re-entry, schema + path safety,
                                                     envelope integrity, replay, quorum
      |
chainmail.execution_boundary  Action                single-action execution boundary (seam)
      |
OS / APIs                     Effect                trusted handlers
```

**It is NOT:**
- a sandbox — it decides, it does not contain or execute. The real action
  boundary is whatever you wire in via `GuardedExecutorAdapter`. The built-in
  `PermissiveExecutionBoundary` authorises everything and is development-only.
- a network security boundary — the service auth is a shared / per-caller token
  over a `0600` Unix socket. Fine co-located on one trusted host; put mTLS in
  front to cross a host.
- a semantic proof — drift / objective-mismatch / anomaly / re-entry rest on
  embedding cosine similarity vs tuned thresholds. They are tripwires. The
  deterministic checks (permissions, allow-list, hard denials, budgets,
  delegation math, signatures, schema, replay, envelope integrity) are the wall.
- fully durable across restart — nonce/proposal-ID replay protection and
  restriction state are now durable and atomic when a `SQLiteStore` is
  wired into `AuditSink` (see `SQLiteStore.claim_nonce`/`claim_proposal_id`/
  `impose_restriction`/`clear_restriction`, Unreleased in CHANGELOG.md);
  `live_authority` and STEP_BUDGET restriction budgets (`_restrict_budgets`)
  still live only in RAM. The audit log is durable; nothing rebuilds
  `live_authority`/budgets from it yet (that's the rest of v6).

---

## 2. Repository layout

```
pyproject.toml            installable package; extras: crypto, embeddings,
                          embeddings-transformer, tracing, dev
README.md                 the public readme (start here after this file)
CHANGELOG.md              v5.0.0 and v5.1.0 notes
LICENSE.md                PolyForm NC 1.0.0 + copyright preamble
SECURITY.md               vuln reporting + in/out of scope
demo_v5.py                narrated end-to-end walkthrough
.github/workflows/ci.yml  pytest 3.9-3.12 + the mutation harness as a gate

src/chainmail/
  __init__.py             public API surface (__all__)
  core.py                 Decision, RiskSignal, Permission, Authority, Proposal,
                          ActionSchema (+ path validation), GovernanceResult
  config.py               GovernorConfig — every threshold/window/bound
  envelope.py             AuthorityEnvelope + tamper-evident fingerprint,
                          allowed_actions allow-list
  embeddings.py           EmbeddingEngine protocol; Model2Vec (default) /
                          SentenceTransformer / TF-IDF; auto_embedding_engine()
  intent.py               IntentGraph — drift, peer-consensus, hard-gated
                          reentry_risk (safety_boundary lineage)
  crypto.py               KeyRegistry (kid, validity window, revoke, rotate),
                          CompositeVerifier (Ed25519 + HMAC), canonical signing
                          payload, sign_proposal
  persistence.py          HashChainLog (non-destructive verify, file reload),
                          SQLiteStore (indices, schema_version, prune),
                          AuditSink, sanitize() (bounded + PII-scrubbed)
  redaction.py            scrub_pii — typed shapes only (keeps hashes/UUIDs)
  quorum.py               QuorumAggregator (fail-closed: any HUMAN dominates),
                          VoteTransport, LocalSingleGovernorTransport
  execution_boundary.py   ExecutionBoundary, Permissive/DenyAll, GuardedExecutorAdapter
  evaluation.py           offline adversarial mutation harness — MutationRunner,
                          standard_mutant_family, MutationReport
  tracing.py              optional OpenTelemetry span per evaluate() (off unless
                          CHAINMAIL_TRACING=1 + the `tracing` extra); console
                          exporter only — no cloud, no cost
  governor.py             ChainmailGovernor — the policy-hard core
  service/
    protocol.py           4-byte length prefix + JSON frame, (de)serialisation
    server.py             UnixSocketGovernorServer, per-caller auth_tokens,
                          CLI entry point (chainmail-governor)
    client.py             GovernorClient

tests/                    10 modules, 101 tests
  conftest.py             JaccardEmbeddingEngine (deterministic), fixtures
  test_governor.py        behavioural suite (ported + expanded from v4)
  test_crypto.py          Ed25519 / HMAC / key lifecycle / signature binding
  test_persistence.py     hash chain, SQLite, audit sink fail-closed
  test_quorum.py          fail-closed aggregation rules
  test_service.py         Unix-socket round-trips, per-caller tokens
  test_regressions.py     one test per numbered v4->v5 bug
  test_redaction.py       PII scrubbing
  test_evaluation.py      the mutation harness must fully pass / detect a
                          weakened boundary
  test_embeddings.py      engine separation (model2vec test skips if absent)

legacy/                   the original v4 single-file build — unmaintained,
                          kept for reference only
reference/                (NOT in the zip / gitignored) local clones of the
                          sibling repos used while building v5.1
```

---

## 3. The decision model

`ChainmailGovernor.evaluate(proposal)` is thread-safe (re-entrant lock). Order —
every failing gate returns `HUMAN`:

1. envelope integrity fingerprint (mutation after construction -> `ENVELOPE_DRIFT`)
2. proposal structurally well-formed (`NaN`/out-of-range confidence -> `INVALID_PROPOSAL`)
3. agent is in the envelope (`UNKNOWN_AGENT`)
4. action on `allowed_actions` if the envelope declares one (`UNKNOWN_ACTION`)
5. `proposal_id` not seen before, if `dedupe_proposal_ids` (`PROPOSAL_DUPLICATE`)
6. signature present (if `require_signature`) and valid — binds the **whole**
   proposal (`SIGNATURE_MISSING` / `SIGNATURE_INVALID`)
7. nonce not replayed — checked only **after** the signature is trusted (`REPLAY_DETECTED`)
8. fleet / per-agent step budget (`FLEET_BUDGET_EXHAUSTED` / `AGENT_BUDGET_EXHAUSTED`)
9. action schema + filesystem-path safety (`SCHEMA_VIOLATION` / `PATH_TRAVERSAL`)
10. hard denial (`AUTHORITY_ABUSE`)
11. agent holds the required permission under active restrictions (`AUTHORITY_ABUSE`)
12. permission budget remains (`BUDGET_EXHAUSTED`)
13. step-budget restriction not exhausted
14. contextual risk -> signal set:
    - objective overlap < threshold -> `OBJECTIVE_MISMATCH`
    - confidence <= threshold -> `LOW_CONFIDENCE`
    - intent-graph drift > threshold -> `DRIFT`
    - peer consensus < threshold -> `HIGH_DISAGREEMENT`
    - high confidence + low overlap -> `ASSUMPTION_ANOMALY`
    - hard-gated re-entry to a refused objective -> `OBJECTIVE_REENTRY`
    Mapping: any `require_human_on` signal or HIGH re-entry -> `HUMAN`;
    disagreement/anomaly -> `RECHECK`; MEDIUM re-entry/drift/low-confidence ->
    `RESTRICT`; else `CONTINUE`.
15. audit "started" (write failure -> `HUMAN` / `SANITIZATION_FAILURE`)
16. execution boundary, only if `CONTINUE` (reject or exception -> `HUMAN`)
17. quorum, only if `CONTINUE` (any `HUMAN` vote dominates)
18. consume permission budget **only** if final decision is `CONTINUE`
19. apply restriction if `RESTRICT`; record intent-graph entry
    (`safety_boundary=True` when the turn was `RESTRICT`/`HUMAN`)
20. audit "completed"

### Core invariants (also in README)
Hard envelope; non-expanding delegation (reduced to recipient ceiling,
role-map constrained); central authority; context can only tighten;
consensus is evidence not a vote; fail-closed everywhere; budget bounded
(spent only on CONTINUE); replay prevention after signature; tamper-evident
hash-chained provenance re-verified on startup; envelope integrity;
signature binds the whole proposal; quorum fail-closed; unknown actions
fail closed; re-entry is hard-gated (needs a real prior refusal in the
agent's lineage — similarity alone never raises risk).

---

## 4. What changed

### v4 -> v5.0.0 — ten numbered bugs, each with a regression test
1. `HashChainLog.verify()` was destructive (`pop("hash")`) — chain self-corrupted
   after two appends. Now non-destructive; `failed_record` is 0-based.
2. Signatures only bound `proposal_id:agent_id:action:nonce` — a signed
   "read docs" could be rewritten to "deploy prod". Now the canonical payload
   binds permission, payload, objective fragment, parent, nonce.
3. Nonce consumed before signature check — a forgery burned a legit nonce.
   Reordered.
4. Budget consumed before the decision — RESTRICT/RECHECK/HUMAN still spent it.
   Now consumed only on CONTINUE.
5. Quorum not fail-closed — a 1-CONTINUE/1-HUMAN split could return CONTINUE.
   Any HUMAN vote now dominates.
6. Delegation to an unknown agent silently created live authority. Rejected.
7. No `Proposal` validation — `NaN` confidence bypassed every threshold. Rejected.
8. `GovernanceResult.effective_authority` leaked live governor state. Now a copy.
9. `ActionSchema.filesystem_path_fields` declared but never enforced. Now blocks
   `..`, NUL/control bytes, backslash/drive paths, and confines to
   `allowed_path_roots`.
10. `evaluate()` had no lock despite the threaded SQLite layer. Now serialized.

Plus: config-driven thresholds, bounded nonce set / proposal log / intent graph,
SQLite indices + retention, HashChainLog file reload, proposal-id dedupe,
per-agent step budgets, real `KeyRegistry` (rotation/revocation/expiry),
model2vec default embedding engine, the `chainmail.service` wrapper.

### v5.0.0 -> v5.1.0 — pulled from the sibling projects (all PolyForm NC)
- **Hard-gated re-entry detection** (`IntentGraph.reentry_risk`, from
  `intent-layer`): a RESTRICT/HUMAN turn becomes a `safety_boundary` node; a
  reworded return escalates via `OBJECTIVE_REENTRY` — but only when the agent's
  lineage holds a real prior refusal. Per-agent. Config `reentry_high` /
  `reentry_medium`.
- **Action allow-list** (`AuthorityEnvelope.allowed_actions`) — opt-in;
  unknown action -> `HUMAN` / `UNKNOWN_ACTION`.
- **Adversarial mutation harness** (`chainmail.evaluation`, idea from Armour's
  `evaluation.py`) — bounded hostile variants, mutation score + invariant
  coverage; CI fails on any survivor; never executes a proposal.
- **PII redaction** (`chainmail.redaction.scrub_pii`, from `Quorum`) — wired into
  `sanitize()` and the audit sink; typed shapes only, keeps hashes/UUIDs.
- **Optional OTel tracing** (`chainmail.tracing`, from `Quorum`) — additive,
  fail-safe, off by default, console-only.
- **Per-caller service tokens** (from `Quorum/gate/agent_identity.py`) —
  `auth_tokens={token: CallerIdentity(label, agent_id=None, admin=False)}`
  (a plain string is shorthand for label-only, no authority), caller identity
  logged per connection. Authentication alone grants `ping`/`evaluate` only;
  `register_delegation` requires the caller's own `agent_id` or admin;
  `revoke_delegation`/`snapshot`/`suggest_envelope` require admin (see
  Unreleased in CHANGELOG.md — authentication is not authorization).

---

## 5. Build & test (when a terminal is available)

```bash
python -m venv .venv && ./.venv/bin/pip install -e ".[dev]"
./.venv/bin/python -m pytest -q          # -> 101 passed
./.venv/bin/python demo_v5.py            # -> mutation harness 9/9, hash chain valid
```

`[dev]` triggers a one-time ~30 MB `model2vec` model download from HuggingFace
(free, no key, cached locally). Without it the suite still passes on the TF-IDF
fallback: `100 passed, 1 skipped`. Nothing else reaches the network.

CI (`.github/workflows/ci.yml`) installs only `[crypto,tracing]` (skips the ML
download), runs pytest on Python 3.9–3.12, then runs the standard mutation family
against the demo envelope and fails the build on any survivor.

---

## 6. How to finish publishing

The repo is committed and the remote is set. The last step is a push, which
needs GitHub credentials.

**If you have a terminal:**
```bash
git push -u origin main
```
If it can't authenticate: `gh auth login` (install `gh`), or a Personal Access
Token with `repo` scope, then re-run. If the remote already has a commit:
`git pull --rebase origin main && git push -u origin main`.

**If you have a GitHub tool/connector but no terminal:** create the repo contents
from this tree via the API — every file under version control (run of
`git ls-files` in the bundle, 41 files), preserving paths. Then no further
commit is needed here; the tree already matches `7ced897`.

**If you have neither:** hand the human `chainmail-v5.1.zip` and this one line —
```
cd <unzipped dir> && git push -u origin main
```
or tell them to use GitHub's web "Add file -> Upload files" on the empty repo
with the unzipped contents (excluding `.git/`).

**After the push:** set the repo description to
"Policy-hard, context-fluid governance layer for long-running multi-agent
systems", add topics `ai-safety multi-agent governance agents`, and confirm the
Actions run is green.

---

## 7. Known limitations / v6 roadmap

Must: network quorum transport with real peer governors; mTLS/SPIFFE identity for
the service; durable `live_authority` and STEP_BUDGET restriction budgets /
permission budgets (nonce/proposal-ID replay protection and restriction state
are already durable -- see Unreleased in CHANGELOG.md; the rest still needs a
store + local fallback, rebuilt from the audit log on restart — pattern from
`Quorum/gate/firestore_*.py`).
Should: encrypted key material at rest / KMS backend; formal TLA+ model of the
delegation invariants; wall-clock fleet budgets + rate limits; an atomic
idempotency store so a client retry can't re-run a CONTINUE (pattern from
`Quorum/gate/idempotency.py`).
Nice: natural-language objective -> envelope generation; Prometheus metrics
alongside the OTel spans.

---

## 8. Sibling ecosystem (context, not dependencies)

All under `github.com/Rick-Clinton-jpg`, all PolyForm NC 1.0.0. Chainmail is one
layer of a "Five-Layer Stack" (see the `papers` repo).

- **Armour** — the deterministic single-action execution boundary chainmail's
  `GuardedExecutorAdapter` is meant to wrap. Its **hardened** code is on branch
  `publish/initial-release`, two commits ahead of `main`; `main` is the
  un-hardened version. Armour and chainmail v5 independently converged on the
  same hardening vocabulary (`ActionSchema`, `ReceiptVerification`,
  `ApprovalVerifier`+HMAC, canonical signing payload, staged fsync'd receipts,
  identical `_sanitize`, construction fingerprint, fail-closed verifier loop).
- **Quorum** — a multi-*verifier* gate (Sentry + Reasoning Kernel + IntentGraph
  -> PASS/REJECT/ESCALATE). NOT the same concept as chainmail's multi-*governor*
  `QuorumAggregator`. Source of the redaction / tracing / per-caller-token /
  (future) durable-state and idempotency patterns.
- **intent-layer** — the real IntentGraph. Source of the safety-boundary hard
  gate now in `chainmail/intent.py`.
- **warden** — audit log is fine; its drift matcher is **inverted** (AUC 0.332,
  worse than random) — do not gate on it. Has **no LICENSE file**.
- **Sentry** (pattern injection detection), **reasoning-kernel** (8-rule claim
  integrity), **trust-boundary**, **Boundary-Memory-**, **Review-Board**
  (human-only Claude Code skill, no API).

---

## 9. License & copyright — do not get this wrong

- `Copyright 2026 Rick Clinton`. Asserted in three places: the preamble at the
  top of `LICENSE.md`, the License section of `README.md`, and
  `pyproject.toml`'s `authors`.
- The line `Required Notice: Copyright Yoyodyne, Inc. (http://example.com)`
  **inside** `LICENSE.md` is verbatim PolyForm license text — an example in the
  standard license's "Notices" section. **Do not edit it.** Editing it breaks the
  "standard license, word-for-word" guarantee. The real notice is the preamble
  above it.
- Commercial use requires a separate license from the copyright holder;
  noncommercial (personal, research, education, non-profits, evaluation) is free.
