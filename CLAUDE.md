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

1. **No AI/LLM. Anywhere. Ever.** keyreach must contain zero AI/LLM calls and zero AI/LLM SDK dependencies. Everything is rule-based. Reasons: it handles live secrets (sending one to a model would be a leak), findings must be reproducible, and every verdict must be auditable to a concrete rule. If a capability can't be decided by a rule, emit `AccessLevel.UNKNOWN` — never guess with a model or fuzzy heuristic. The `ai_ban` guardrail enforces this; do not weaken it.
   - **The line, precisely.** keyreach *probes* AI providers — that is the product — so naming `api.openai.com` and calling its read-only endpoints is fine. Asking a model to do anything is not. `ai_ban` therefore bans SDKs and imports outright, and bans **inference endpoints** (the chat-completions path, `:generateContent`, …) rather than provider hostnames. See `plan.md` §1.
   - **Endpoint paths in `ai_ban` carry no API version.** Provider plugins compose URLs from a base constant, so the banned string never appears version-qualified on the line that matters. This was found in R1.2 by planting `f"{API}/chat/completions"` and watching the check pass. Do not "tidy" the fragments by re-adding `/v1`.
   - **What the rule costs, and the answer to it.** keyreach can never confirm that an AI key can run inference or spend, so AI capabilities do not set `incurs_cost` and their `detail` says inference was not tested. Reporting less than the truth is the correct side to err on. The exception is a *documented* vendor access model — Anthropic states its Console admin keys carry no selectable scopes, so an Admin API read establishes the matching write and is recorded as `admin`. OpenAI's admin keys are scoped per resource, so the identical finding there is `read`. Cite the vendor sentence when you claim more than you probed.
2. **Deterministic output.** Same key + same recorded provider responses ⇒ byte-identical report (except the injected timestamp). No unseeded randomness, no reliance on dict/set ordering, no ad-hoc wall-clock reads. Sort by explicit keys before output.
3. **Read-only by default.** Probes must be non-destructive. No writes, deletes, or spend. The HTTP layer default-denies non-idempotent methods. Anything aggressive is off by default, explicitly flagged, and warned.
4. **Mask secrets by default.** Keys are masked in all output, logs, evidence, and recorded fixtures unless `--unmask` is passed. Never commit a real key or an unscrubbed cassette.
5. **License discipline.** This repo is permissively licensed (Apache-2.0 recommended). **Never copy AGPL/GPL code** (e.g. TruffleHog) — study behavior and re-implement from public API docs only. Reuse MIT/Apache/BSD/CC-BY sources only, with attribution in `NOTICE`/`THIRD_PARTY_LICENSES.md` and `CREDITS.md`. Verify every third-party license from its repo before reusing anything.
6. **Plugins don't touch the network directly.** Provider code must go through `ProbeContext` (the recordable, rate-limited, redacting client). Direct `httpx`/`socket`/`requests` imports under `providers/` fail CI (`network_isolation` check), including deferred and `importlib` imports, and including the fixture provider packages under `tests/`.
7. **Guardrails are tested, not trusted.** Rules 1, 3, 4 and 6 are enforced by `tools/guardrails/`, run by CI, by pre-commit, and by `pytest`. Every one has a test that *plants the violation it exists to catch* — because in R0.6 ruff's `banned-api` rule was found to have been silently inert since R0.2 while three pull requests claimed it was enforcing, and in R0.8 a secret scan reported a clean repository it had never actually read. Adding a check without a failing-case test repeats that. Weakening one is not a refactor; it is a change to what keyreach promises.

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
- `keyreach/core/http.py` — the only place sockets are opened; rate-limit, record/replay, redaction, read-only guard, and a per-run cache so a repeated idempotent GET costs one request (R1.4). Never assume two identical probes reach the network twice.
- `keyreach/core/scoring.py` — pure severity function + rationale.
- `keyreach/core/probes.py` — runner for declarative YAML probes.
- `keyreach/providers/*` — one file (or YAML) per provider. Ten as of v0.1: `google.py`, `aws.py` (cloud); `openai.py`, `anthropic.py` (ai); `stripe.py`, `razorpay.py` (payment); `slack.py`, `twilio.py`, `telegram.py` (comms); `github.py` (devtools). Every one shares a probe-table shape and **none share code**. R1.4 asked whether that abstraction is real and answered no; R1.6 added six more providers without touching `keyreach/core/`, which is the evidence. The genuine shared abstraction is the declarative probe runner scheduled as **R2.8**.
- `keyreach/patterns/detection_rules.yml` — detection rules written from vendor docs (nothing copied; see `CREDITS.md`).
- `keyreach/report/build.py` — `EngineResult` → `Report`. Pure; `generated_at` is a parameter, never read here.
- `keyreach/report/render.py` — terminal / JSON / Markdown renderers; `templates/`; `report.schema.json`.
- `tests/fixtures/` — recorded cassettes (no real keys); `tests/golden/` — snapshot reports, regenerated with `python -m tests.regenerate_goldens`.
- `tools/guardrails/` — `workflows`, `ai_ban`, `network_isolation`, `read_only`, `no_secrets`. Dev tooling, not shipped. Run with `python -m tools.guardrails`.

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
4. Add tests: detection, provider behavior, and update golden snapshots. `tests/test_provider_contract.py` already holds every registered plugin to the shared contract — metadata, `detect` purity, probe-table hygiene, attribution, and the `ProbeContext` surface — so your own test module only has to cover what is *specific* to your provider. If a contract test fails, fix the provider; do not weaken the contract.
5. If derived from prior art (e.g. the Google plugin from gmapsapiscanner), add an inline credit header and an entry in `CREDITS.md`.

Aim: a new provider in ~30 minutes. Keep probes minimal (OpSec) and read-only.

### Two things R1.6 found, which the next provider will meet again

- **`ai_ban`'s endpoint list matches case-sensitively, and that is load-bearing.**
  Twilio's message resource is `/Messages.json`; the banned inference path is the
  same word in lower case. `tests/test_guardrails.py` pins both directions, so
  "make the match case-insensitive" fails rather than silently breaking
  `keyreach/providers/twilio.py`. The check also scans *prose in source files* —
  it fired on the Twilio module docstring that was explaining this very point,
  which is the check working. Describe a banned path; do not spell it.
- **A cassette URL is the redacted URL.** When a credential appears in the
  request path (Telegram's token, Twilio's Account SID), redaction runs *after*
  the URL is built, so the recorded form carries the literal `<key>` placeholder.
  Do not generate a fixture by putting `<key>` through a URL builder: `httpx`
  percent-encodes the angle brackets, and the resulting cassette never matches at
  replay. Build with a real-looking value and substitute afterwards.

---

## Conventions

- Python 3.11+, typed. `ruff` + `black` + `mypy` must pass.
- pydantic v2 models for all structured data; never pass around raw dicts for capabilities/reports.
- Async probes via `httpx` **through `ProbeContext` only**.
- Deterministic sorting before any output. No `set` iteration in output paths.
- **A plugin never reads the clock.** The one exception is `ctx.now()`, added in R1.3 for AWS SigV4, which refuses a request whose timestamp is stale. It is sanctioned only for request signing: anything it returns that reaches a capability, a severity or a report is a bug. `Engine(clock=...)` injects it so tests can pin it.
- **Split a composite credential? Register the parts.** `ctx.protect(part)` adds a secret to the redactor. Seeding with the whole pasted string does not mask a response echoing back one half — `iam:ListAccessKeys` returns exactly that.
- **Anything noisy goes behind `ctx.aggressive`**, which defaults to false and is surfaced as `--aggressive` (R1.5). Mark the capabilities it produces so a reader can tell which findings cost a sweep. Read-only is not the same as quiet.
- Evidence strings are masked and read-only; include the request and a benign response summary that proves the capability.
- Timestamps: use the engine-injected `generated_at`; never call the clock directly in report code.

---

## Commands

```
# setup
pipx install -e .            # or: pip install -e '.[dev]'

# quality gates (run before every commit) — CI runs exactly these
# `tests` and `tools` are typed too; `mypy keyreach` alone passes on code the
# pre-commit hook and CI both reject.
ruff check . && black --check . && mypy keyreach tests tools
pytest -q --cov=keyreach --cov=tools     # coverage must be 100%

# the hard rules (implementation_plan.md §11) — also a pre-commit hook
python -m tools.guardrails                 # all five
python -m tools.guardrails read_only       # or one by name

# regenerate checked-in artifacts (CI fails on drift; --check is what it runs)
python -m keyreach.report.schema --write   # report.schema.json
python -m tests.regenerate_goldens         # tests/golden/*

# run locally against a throwaway key
keyreach <KEY>                       # terminal report; banner on stderr
keyreach <KEY> --report md -o out.md
keyreach <KEY> --json --quiet        # stdout is only the report
keyreach -f keys.txt --fail-on high  # batch; exit 2 at or above the band
```

Do not run keyreach against keys you don't own or aren't authorized to test.

---

## Testing rules

- **No live keys in CI** — everything uses cassettes in `tests/fixtures/`.
- Cover every scoring band boundary in `test_scoring.py`.
- `test_determinism.py` must stay green: double-run byte-equality + golden snapshots (timestamp fixed).
- Add redaction assertions whenever you touch output/evidence paths.
- **Never assert on raw terminal output.** `rich` colours and wraps according to what it infers about the environment — and it styles a flag's leading hyphen separately, so `"--version" in output` is false whenever colour is on. GitHub Actions sets `CI=true`, which turns colour on, so an assertion like that passes on every developer machine and fails only in CI. Strip styling and collapse whitespace first (`tests/test_cli.py::readable`), and pin colour and width on the runner.
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

- Lint, format, types, and tests pass, including the `workflows`, `ai_ban`, `network_isolation`, `read_only` and `no_secrets` guardrails and both drift checks (`report.schema.json`, `tests/golden/`). All of these run in CI as of R0.9 — `python -m tools.guardrails` runs them locally, and `pre-commit install` runs them on every commit.
- Coverage stays at 100% across `keyreach` and `tools`. An uncovered line is a deliberate, argued `pragma: no cover`, not an oversight.
- Any new guardrail ships a test that plants the violation it catches (hard rule 7).
- New/changed providers ship valid + invalid fixtures and updated goldens.
- Output stays deterministic and masked.
- Any reused code/data is license-verified and credited.
- Docs updated if behavior or interfaces changed.
