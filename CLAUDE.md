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
- `keyreach/providers/*` — one file (or YAML) per provider. Thirty-one as of R2.6 (`datadog`, `sentry`, `newrelic`, `grafana` added): `google.py`, `aws.py` (cloud); `openai.py`, `anthropic.py` (ai); `stripe.py`, `razorpay.py`, `paystack.py`, `paypal.py` (payment); `slack.py`, `twilio.py`, `telegram.py`, `discord.py`, `zoom.py` (comms); `sendgrid.py`, `mailgun.py`, `postmark.py`, `resend.py`, `mailchimp.py` (email); `github.py`, `gitlab.py`, `bitbucket.py`, `npm.py`, `dockerhub.py` (devtools); `mongodb.py`, `supabase.py`, `redis.py`, `pinecone.py` (database); `datadog.py`, `sentry.py`, `newrelic.py`, `grafana.py` (monitoring). Every one shares a probe-table shape and **none share code**. R1.4 asked whether that abstraction is real and answered no; R1.6 added six more providers without touching `keyreach/core/`, R2.3 added five, R2.4 four, R2.5 four and R2.6 four — six consecutive items, none of which needed an interface change. The genuine shared abstraction is the declarative probe runner scheduled as **R2.8**.
  - **`pypi` is a detection rule with no plugin, on purpose.** PyPI's only token-accepting endpoint is a package upload, so no plugin can exist without performing a write. Do not add one. See `plan.md` §5.2 and `tests/test_detect.py::test_pypi_is_detected_and_deliberately_has_no_plugin`.
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

### Three things R2.6 found

- **A composite credential's two halves are not always useless apart.** Every
  prior composite (PayPal, Zoom, MongoDB Atlas) exchanges its parts together
  for one OAuth token; a lone half authenticates nothing. Datadog's own docs
  split "write needs an API key" from "read needs both", so a bare API key
  genuinely validates on its own via `GET /api/v2/validate`. Do not assume the
  next composite credential is useless in pieces just because the last three
  were — check what the vendor's own docs say each half is *for*.
- **`read_only_post` earns its cleanest justification yet from GraphQL.**
  PayPal, Zoom, Docker Hub and MongoDB Atlas all needed it because the *only*
  way to authenticate was a POST. New Relic's NerdGraph needs it because the
  *only* way to read anything at all is a POST — GraphQL has no GET form for
  a query. Send exactly the query New Relic's own docs show verbatim
  (`{ requestContext { userId apiKey } }`); do not assemble a richer one from
  field names seen only in third-party tooling.
- **The "detection rule, no plugin" pattern PyPI established does not
  generalise to every write-only credential.** Sentry's DSN is exactly as
  write-only as PyPI's token and just as distinctively shaped, but it gets
  **neither** a rule nor a plugin: `keyreach/providers/sentry.py` already
  exists for Sentry's auth tokens, so a DSN detection rule would hand that
  plugin a live, working credential it would then report "invalid" for not
  being an auth token. Before reusing PyPI's pattern, check whether the same
  provider name is already claimed by a better credential.

### Three things R2.5 found

- **Check the vendor treats the string as authorisation before writing a
  provider at all.** Firebase publishes that its API key "only identifies your
  Firebase project and app" and that "none of the Firebase-related APIs use an
  API key as authorization". A string that authorises nothing has no capability
  map and no honest severity, so keyreach ships no `firebase` provider. This is
  a third failure mode next to undetectable (R2.3) and un-enumerable (R2.4);
  `plan.md` §5.2 keeps all three apart.
- **Read the roadmap name narrowly and say what you actually covered.** "Redis"
  cannot mean a Redis server: that credential is spoken over RESP on port 6379,
  and keyreach's whole I/O layer is HTTP. The plugin covers Redis Cloud's
  control plane and its docstring says so, rather than letting the provider name
  imply a database probe that never happens.
- **A credential may carry its own routing, and decoding it is not a probe.**
  A Supabase legacy key is a JWT whose `ref` claim names the project host and
  whose `role` claim names what it can do. Decoding is pure, offline and
  deterministic — one base64url decode, no signature check, because keyreach is
  reading a claim out of a credential its holder already has rather than
  trusting a token. Do **not** turn that into a detection rule: a regex over
  three base64 segments claims every JWT ever pasted at keyreach.

### Three things R2.4 found

- **Re-verify every rule you touch, including the ones you are not changing.**
  R2.4 opened by opening the `source:` URL of all three devtools rules that
  already existed. One was sound, one was **correct but cited to a page that no
  longer supports it** (GitLab moved its prefix table), and one was
  **unsupportable anywhere** and was withdrawn (npm). A `source` that does not
  support its rule is worth nothing — re-verification is the only thing the
  field is for. Two withdrawals in two items is a trend, not a coincidence.
- **A vendor's OpenAPI specification is a primary source, and is sometimes the
  only one.** Docker Hub's prose token pages publish no format; its published
  specification examples `dckr_pat_…` and `dckr_oat_…` in the request and
  response schemas. Check the machine-readable spec before concluding a vendor
  publishes nothing — Bitbucket's and Docker's both answered questions their
  prose did not, including which endpoints are **deprecated**, which is worth
  avoiding in a probe table.
- **Detection and enumeration fail independently.** Undetectable means no rule
  can be written; un-enumerable means no read-only probe exists. PyPI is the
  second: format documented, rule sound, and its only token-accepting endpoint
  is a package upload. It ships as a rule with **no plugin**. Do not "fix" that
  by adding one that posts.

### Three things R2.3 found

- **A detection rule can stop being verifiable, and then it must go.**
  keyreach shipped a Mailgun rule from R0.5 whose source page no longer
  documents any key format. The rule still matched real keys; it had not become
  wrong. But nobody could re-verify it, which is the single thing
  `detection_rules.yml` promises, so it was **withdrawn** and `mailgun` set
  `detectable = False`. Before adding *or keeping* a rule, open its `source:`
  URL and check the page still says what the rule claims. If it does not, the
  rule goes and the provider is reached with `--provider`. Do not re-source a
  rule to a page that merely mentions the vendor.
- **Say what the API says, not what the docs say, when they differ.** Resend
  documents `403` for an invalid key and returns `400`; it documents `401` for a
  key that is *live and restricted to sending*. The ordinary reading of 401
  would retire a working credential. Branch on the vendor's error **name** where
  there is one — that is a contract — and treat the status as corroboration.
  This is the fourth item running where the defect surfaced by exercising the
  real API rather than by reading about it.
- **`ai_ban` will eventually cost a real probe, and the answer is to pay it.**
  Postmark's outbound-mail search sits under the same lowercase path as an
  inference endpoint, and `ai_ban` matches sub-resources on purpose so that
  Anthropic's message-batches path is caught. Nothing in a line of source
  separates the two — only the host does, and the check bans paths rather than
  hosts deliberately. The probe was dropped and a different endpoint carries the
  finding. Do not compose the URL from fragments to slip past the check: that is
  exactly the hole R1.2 found by planting `f"{API}/chat/completions"`.

### Three things R2.1 found

- **A provider with no publishable credential format sets `detectable = False`.**
  It is never a detection candidate, and `--provider <name>` is how a user
  reaches it — the report already records that as the operator's assertion. Use
  it only when the vendor publishes nothing to write a rule *from*, and say so
  in the module docstring; `tests/test_provider_contract.py` requires every
  provider to be reachable one way or the other. This is not a shortcut past
  writing a detection rule.
- **`read_only_post` responses are cached per run, keyed on the request body.**
  A provider that must POST to authenticate (PayPal's token exchange) gets one
  request, not one per pipeline stage. If you add a `read_only_post` probe, make
  sure two calls with the same URL and body really are the same request.
- **Two vendors can document the same prefix.** Stripe and Paystack both use
  `sk_live_`/`sk_test_`. Do not narrow either rule to "fix" it — that invents a
  fact the vendor has not stated. Both fire, the engine probes both, and the one
  that authenticates wins, at a cost of one wasted request. Say so in the
  rejection note, so a user who sees "X rejected this key" does not conclude the
  key is dead.

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
