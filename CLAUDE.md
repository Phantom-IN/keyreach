# CLAUDE.md

Working guide for Claude Code (and any agent) contributing to **keyreach**. Read this before making changes.

---

## Repo docs & how to use them

Three planning docs live together in the repo **root**: `plan.md`, `implementation_plan.md`, and this file (`CLAUDE.md`). They are the source of truth — treat them as authoritative over your own assumptions, and keep them in sync when behavior or structure changes.

- **`plan.md` — the product plan (what & why).** Consult it for anything about scope, goals, non-goals, provider coverage, the severity model's *intent*, report contents, safety/ethics policy, licensing, and credits. When a decision is about *whether* keyreach should do something, or *what* it should produce, `plan.md` governs. Do not put implementation detail here.
- **`implementation_plan.md` — the technical blueprint (how).** Consult it for codebase structure, the `Provider`/`Capability` interfaces, the detection/engine/HTTP/scoring internals, the declarative probe format, testing strategy, CI guardrails, the CLI spec, and build phases. When a decision is about *how* to build or where code goes, `implementation_plan.md` governs.
- **`CLAUDE.md` — the working rules (this file).** The always-on operating manual: hard rules, conventions, commands, and the definition of done for a change.

**How to work with them:**
1. Before starting a task, read this file, then skim the relevant section of `plan.md` (for product/scope questions) or `implementation_plan.md` (for technical questions).
2. If the two disagree, `plan.md` wins on product/scope/safety and `implementation_plan.md` wins on technical structure. If they genuinely conflict, stop and flag it rather than guessing.
3. When you change behavior, interfaces, scope, or structure, update the doc that owns that decision **in the same PR**, and update this file if a rule or convention changed. Never let code and docs drift.
4. Cite the doc you're following in your reasoning/PR description (e.g. "per `implementation_plan.md` §4, providers return a stably-sorted `list[Capability]`") so decisions stay traceable.

---

## What keyreach is

A deterministic, rule-based CLI that takes an already-exposed API key (cloud, AI/LLM, payment, comms, dev-tool, database, or SaaS), figures out **what that key can access** via read-only probes, computes a severity (Info→Critical), and produces a disclosure-ready security report. It is **not** a secret scanner (it doesn't hunt for keys) and **not** an exploitation framework.

Pipeline: `detect → validate → enumerate → score → report`.

---

## Hard rules (never violate)

1. **No AI/LLM. Anywhere. Ever.** keyreach must contain zero AI/LLM calls and zero AI/LLM SDK dependencies. Everything is rule-based. Reasons: it handles live secrets (sending one to a model would be a leak), findings must be reproducible, and every verdict must be auditable to a concrete rule. If a capability can't be decided by a rule, emit `AccessLevel.UNKNOWN` — never guess with a model or fuzzy heuristic. The `ai_ban` CI check enforces this; do not weaken it.
2. **Deterministic output.** Same key + same recorded provider responses ⇒ byte-identical report (except the injected timestamp). No unseeded randomness, no reliance on dict/set ordering, no ad-hoc wall-clock reads. Sort by explicit keys before output.
3. **Read-only by default.** Probes must be non-destructive. No writes, deletes, or spend. The HTTP layer default-denies non-idempotent methods. Anything aggressive is off by default, explicitly flagged, and warned.
4. **Mask secrets by default.** Keys are masked in all output, logs, evidence, and recorded fixtures unless `--unmask` is passed. Never commit a real key or an unscrubbed cassette.
5. **License discipline.** This repo is permissively licensed (Apache-2.0 recommended). **Never copy AGPL/GPL code** (e.g. TruffleHog) — study behavior and re-implement from public API docs only. Reuse MIT/Apache/BSD/CC-BY sources only, with attribution in `NOTICE`/`THIRD_PARTY_LICENSES.md` and `CREDITS.md`. Verify every third-party license from its repo before reusing anything.
6. **Plugins don't touch the network directly.** Provider code must go through `ProbeContext` (the recordable, rate-limited, redacting client). Direct `httpx`/`socket`/`requests` imports under `providers/` fail CI (`network_isolation` check).

---

## Architecture at a glance

```
DETECT (pure rules) → PROVIDER PLUGIN (detect/validate/enumerate)
                          │ uses ProbeContext (shared HTTP: rate-limit, record/replay, redact, read-only guard)
                          ▼
                    list[Capability] → SCORING (pure) → REPORT (terminal/md/html/json)
```

Plugins **declare** probes; the **engine executes** them. All I/O and nondeterminism control live in the engine, not the plugins.

---

## Where things live

- `keyreach/core/models.py` — `Capability`, `Identity`, `ValidationResult`, `Report` (pydantic).
- `keyreach/core/provider.py` — `Provider` base class.
- `keyreach/core/detect.py` — deterministic pattern + entropy detection.
- `keyreach/core/engine.py` — orchestration, concurrency, stable ordering.
- `keyreach/core/http.py` — the only place sockets are opened; rate-limit, record/replay, redaction, read-only guard.
- `keyreach/core/scoring.py` — pure severity function + rationale.
- `keyreach/core/probes.py` — runner for declarative YAML probes.
- `keyreach/providers/*` — one file (or YAML) per provider.
- `keyreach/patterns/detection_rules.yml` — detection rules written from vendor docs (nothing copied; see `CREDITS.md`).
- `keyreach/report/build.py` — `EngineResult` → `Report`. Pure; `generated_at` is a parameter, never read here.
- `keyreach/report/render.py` — terminal / JSON / Markdown renderers; `templates/`; `report.schema.json`.
- `tests/fixtures/` — recorded cassettes (no real keys); `tests/golden/` — snapshot reports, regenerated with `python -m tests.regenerate_goldens`.

---

## How to add a provider

1. Create `keyreach/providers/<name>.py` (or `.yml` for simple cases).
2. Implement:
   - `detect(key)` — pure, high-confidence structural match; add a pattern to `detection_rules.yml` if needed.
   - `validate(key, ctx)` — cheapest read-only liveness + identity call.
   - `enumerate(key, ctx)` — read-only probes; each match returns a `Capability` with `access`, `detail`, `evidence`, `risk_weight`, and the `data_sensitive`/`incurs_cost`/`restricted` flags set correctly (these drive severity — see `core/scoring.py` for the exact rules). Return a stably-sorted list.
     - `data_sensitive` and `incurs_cost` raise the band; on a **single** capability, either one combined with `write`/`admin` is what makes a finding Critical. Set `restricted` when a referrer/IP/app restriction appears to block real use — it lowers the band by one, but only when it holds for every capability.
     - Use `AccessLevel.UNKNOWN` when no rule can decide. It is scored as undetermined, never as harmless, and never as a write. Guessing `read` to make a report look tidier understates real impact.
   - metadata: `name`, `category`, `docs_url`, `rotation_guide_url`, and `credit` (upstream project, if derived).
     - `name` must be **lowercase and unique** — it is both the registry key and the literal value `--provider` matches.
     - `category` must be one of the **closed set** enforced by `core/registry.py`: `cloud`, `ai`, `payment`, `comms`, `email`, `devtools`, `database`, `monitoring`, `auth`, `generic`. It drives the v0.1 "≥10 providers across ≥4 categories" measure, so a typo would quietly inflate coverage. Call `validate_provider()` in your plugin's test to catch this before the registry does.
3. Record fixtures for a **valid** and an **invalid/expired** key response; scrub secrets.
4. Add tests: detection, provider behavior, and update golden snapshots.
5. If derived from prior art (e.g. the Google plugin from gmapsapiscanner), add an inline credit header and an entry in `CREDITS.md`.

Aim: a new provider in ~30 minutes. Keep probes minimal (OpSec) and read-only.

---

## Conventions

- Python 3.11+, typed. `ruff` + `black` + `mypy` must pass.
- pydantic v2 models for all structured data; never pass around raw dicts for capabilities/reports.
- Async probes via `httpx` **through `ProbeContext` only**.
- Deterministic sorting before any output. No `set` iteration in output paths.
- Evidence strings are masked and read-only; include the request and a benign response summary that proves the capability.
- Timestamps: use the engine-injected `generated_at`; never call the clock directly in report code.

---

## Commands

```
# setup
pipx install -e .            # or: pip install -e '.[dev]'

# quality gates (run before every commit)
# `mypy keyreach tests` is what pre-commit and CI run — the tests are typed too,
# and `mypy keyreach` alone will pass on code that fails the hook.
ruff check . && black --check . && mypy keyreach tests
pytest -q --cov=keyreach

# regenerate checked-in artifacts (both fail the suite when stale)
python -m keyreach.report.schema --write   # report.schema.json
python -m tests.regenerate_goldens         # tests/golden/*

# run locally against a throwaway key — R1.5 wires these up
keyreach <KEY>
keyreach <KEY> --report md -o out.md
keyreach <KEY> --json
```

Do not run keyreach against keys you don't own or aren't authorized to test.

---

## Testing rules

- **No live keys in CI** — everything uses cassettes in `tests/fixtures/`.
- Cover every scoring band boundary in `test_scoring.py`.
- `test_determinism.py` must stay green: double-run byte-equality + golden snapshots (timestamp fixed).
- Add redaction assertions whenever you touch output/evidence paths.
- When a provider's API changes, update the cassette and golden files in the same PR and note the drift.
- **Never write a key-shaped literal in source, even a fake one.** Compose test samples from parts (`"sk_" + "live_" + body`). A single literal matches keyreach's own detector *and* GitHub push protection, which blocks the push and offers only a click-through "allow this secret" link — never use it. `tests/test_repo_hygiene.py` catches this before the commit exists; do not narrow the file list it scans.

---

## What NOT to do

- ❌ Add any AI/LLM SDK, call any model, or route key/response data to a third party. (Probing the key's *own* provider endpoints read-only is the only external traffic allowed.)
- ❌ Introduce randomness, time-dependent logic (outside injected timestamp), or order-dependent output.
- ❌ Make write/delete/spend calls, or add exploitation/privesc/lateral-movement features.
- ❌ Print full keys by default, or commit real secrets/unscrubbed fixtures.
- ❌ Copy AGPL/GPL source, or reuse anything without verifying its license and adding attribution.
- ❌ Let provider plugins open sockets or import `httpx` directly.

---

## Definition of done for a change

- Lint, format, types, and tests pass, including `ai_ban`, `network_isolation`, `read_only`, and schema-drift checks.
- New/changed providers ship valid + invalid fixtures and updated goldens.
- Output stays deterministic and masked.
- Any reused code/data is license-verified and credited.
- Docs updated if behavior or interfaces changed.
