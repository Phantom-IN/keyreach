<!--
Thanks for contributing to keyreach! 🔑

This checklist is real — it is what reviewers check against, and most items map
to a CI guardrail. Please fill it in rather than deleting it.

⚠️ Before you open this PR: run `git diff` over every file you touched and
   confirm no real API key, cassette secret, or personal account identifier is
   in the diff. A key committed to git history is compromised permanently.
-->

## What & why

<!-- What does this change, and why? Keep it short but concrete. -->

## Roadmap item & governing doc

<!-- REQUIRED. Every PR traces to a roadmap item and to the doc that governs the
     decision — that's what keeps decisions auditable. -->

- **Implements roadmap item:** <!-- e.g. R0.7 — Scoring -->
- **Follows:** <!-- e.g. implementation_plan.md §7 and plan.md §6 -->
- **Closes:** <!-- #issue -->

## Type of change

- [ ] `feat` — new capability (provider, flag, report format)
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `chore` — maintenance, deps, release
- [ ] `test` — tests or fixtures
- [ ] `ci` — workflows or guardrail checks
- [ ] `refactor` — restructuring, no behavior change
- [ ] **Breaking change** (marked `!` in the commit and with a `BREAKING CHANGE:`
      footer)

---

## The hard rules

Every box must be ticked or explicitly justified. These are enforced by CI once
roadmap item **R0.9** lands; until then they're on the author and reviewer.

### 🚫 No AI/LLM

- [ ] **No AI/LLM SDK, dependency, model call, or model API endpoint added
      anywhere.** No "smart" heuristic that isn't a written rule.
- [ ] Anything undecidable by a rule is emitted as `AccessLevel.UNKNOWN`, never
      guessed.
- [ ] The `ai_ban` check is untouched or strengthened — **never weakened**.

> keyreach handles live secrets: sending one to a model would itself be a
> credential leak. This rule has no exceptions. (`plan.md` §1)

### 🎲 Determinism

- [ ] Same key + same recorded responses ⇒ **byte-identical** report (modulo the
      injected timestamp).
- [ ] No unseeded randomness, no dependence on dict/set iteration order, no
      ad-hoc wall-clock reads.
- [ ] Output paths sort by explicit, stable keys. No `set` iteration in output.
- [ ] Timestamps come from the engine-injected `generated_at` only.
- [ ] Golden snapshots and `test_determinism.py` pass (updated deliberately, with
      the diff explained below, if they changed).

### 🔒 Read-only & masked

- [ ] All new probes are **non-destructive** — no writes, deletes, or spend.
- [ ] No non-idempotent method added without explicit annotation **and** a
      justification here (the HTTP layer default-denies POST/PUT/PATCH/DELETE).
- [ ] Keys are **masked** in all output, logs, evidence, and fixtures unless
      `--unmask` is passed.
- [ ] Redaction assertions added or updated for any output/evidence path touched.
- [ ] Provider code goes through **`ProbeContext`** — no direct
      `httpx`/`socket`/`requests` import under `providers/`.
- [ ] No exploitation, privilege-escalation, or lateral-movement capability
      added.

### ⚖️ Licensing & credit

- [ ] **No AGPL/GPL code copied.** (Copyleft prior art is studied and
      re-implemented from public API docs only.)
- [ ] Every reused source's license was **verified from its own upstream
      repository**, not from a summary or package index.
- [ ] Reused code/data is attributed in [`NOTICE`](../NOTICE) and
      [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md), with the full
      license text.
- [ ] [`CREDITS.md`](../CREDITS.md) updated, and any provider derived from prior
      art carries an **inline credit header**.

### 📚 Docs in sync

- [ ] The document that **owns** this decision is updated **in this same PR**
      (`plan.md` for product/scope/safety, `implementation_plan.md` for technical
      structure, `CLAUDE.md` if a rule or convention changed).
- [ ] [`ROADMAP.md`](../ROADMAP.md) checkbox ticked if this completes an item.
- [ ] [`CHANGELOG.md`](../CHANGELOG.md) updated under `Unreleased` if the change
      is user-visible.
- [ ] `README.md` updated if install/usage/coverage changed.

---

## Testing

- [ ] `ruff check . && black --check . && mypy keyreach` passes
- [ ] `pytest -q --cov=keyreach` passes
- [ ] New/changed providers ship **both** a valid and an invalid/expired fixture
- [ ] **No real key is in any committed fixture** — recorded with a throwaway key
      and scrubbed, and I read the cassette diff myself
- [ ] Scoring changes cover every affected band boundary in `test_scoring.py`

**How I verified this:**

<!-- Commands run, cassettes recorded, manual checks. If goldens changed,
     explain exactly why the output legitimately changed. -->

## Screenshots / output

<!-- For report or CLI changes, paste the before/after — MASKED. -->

## Notes for reviewers

<!-- Anything tricky, deliberately deferred, or worth arguing about. If a
     provider API drifted and you updated a cassette, say so here. -->
