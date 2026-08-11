# keyreach roadmap

> keyreach roadmap. Built in public: each item is a feature branch → PR →
> squash-merge into `main`. Phases and acceptance criteria trace to
> [`implementation_plan.md`](implementation_plan.md) (§ references) and
> [`plan.md`](plan.md). Checkboxes track progress.

**How to use this file:** open a tracking issue for an item before starting it,
branch with the item's branch name, and tick the box in the pull request that
completes it. One roadmap item per pull request where practical. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full workflow.

---

## Phase 0 — Foundations

- [x] **R0.1 — Base OSS structure** *(first commit)* — governance, docs, templates, roadmap, hygiene CI. No source code. *Done when:* repo has all governance/docs files and a clean initial commit on `main`.
- [x] **R0.2 — Project scaffold** `feat/r0.2-project-scaffold` — `pyproject.toml` (Apache-2.0, Python 3.11+, deps per `implementation_plan.md` §1, **no AI/LLM deps**), empty `keyreach/` package, Typer CLI entrypoint with `--help`/`--version` only, `pre-commit` config (ruff/black/mypy), pytest harness. *Done when:* `pipx install -e .` works and `keyreach --help` prints; lint/type/test scaffolding runs green with zero real logic. *Also landed:* the `keyreach` name reserved on PyPI (`0.1.0.dev0` placeholder) and `.github/workflows/publish.yml` — token-free publishing via PyPI Trusted Publishing, pulled forward from R1.6 so the name could be held without storing a long-lived API token.
- [x] **R0.3 — Core data models** `feat/r0.3-core-models` — pydantic `Capability`, `Identity`, `ValidationResult`, `Report` (`implementation_plan.md` §4); generate and check in `report.schema.json`; unit tests. *Done when:* models validate and schema is generated deterministically. *Also landed:* the `Severity` enum with an explicit band ordering, and `keyreach/report/schema.py` with a `--check` mode that R0.9 wires in as the schema-drift job.
- [x] **R0.4 — Provider base + registry** `feat/r0.4-provider-registry` — `Provider` base class and deterministic registry/discovery (`implementation_plan.md` §4); tests with a dummy provider. *Done when:* registry loads providers in stable order. *Also landed:* a closed provider-category set with a public `validate_provider()`, and an empty `ProbeContext` protocol that R0.6 fills in without changing any provider signature.
- [x] **R0.5 — Detection layer** `feat/r0.5-detection` — pattern loader, high-confidence prefix matching + deterministic entropy fallback (`implementation_plan.md` §5); table-driven tests. *Done when:* sample keys map to expected providers/confidence deterministically. **Scope change:** this item originally read "seeded with an **attributed** subset of secrets-patterns-db (CC-BY, update `NOTICE`/`THIRD_PARTY_LICENSES.md`)". Verifying that license from the upstream repository showed it is **CC-BY-SA-4.0** (not CC-BY) and that the database self-declares AGPL TruffleHog content with no per-rule provenance — so **nothing was copied**. Patterns are written from vendor documentation, each citing its source URL; `NOTICE`, `THIRD_PARTY_LICENSES.md`, `CREDITS.md` and `plan.md` §5.2 were corrected to record the finding.
- [x] **R0.6 — Engine + HTTP layer** `feat/r0.6-engine-http` — async, rate-limited, **recordable** (record/replay), **redacting**, **read-only-guarded** client + `ProbeContext` (`implementation_plan.md` §6); tests via cassettes. *Done when:* probes run only through `ProbeContext`; non-idempotent methods default-denied; keys masked in recordings. *Also fixed:* ruff's `TID` rules were never in the `select` list, so the `banned-api` block added in R0.2 had been silently inert — the direct-`httpx` ban now actually fires, which is the edit-time half of the `network_isolation` check due in R0.9.
- [x] **R0.7 — Scoring** `feat/r0.7-scoring` — pure, rule-based severity function + rationale (`implementation_plan.md` §7, `plan.md` §6); tests covering every band boundary. *Done when:* identical capability sets always produce identical band + rationale. *Scope change:* §7 sketched the Critical test as `(admin or write) and (data or cost)` evaluated across the whole capability set, which rates a key Critical when one capability writes to something harmless and a *different* one reads something sensitive. Critical now requires a **single** capability that is both; §7 was corrected and gained §7.1. *Also landed:* `Capability.restricted`, the explicit restriction flag §7 always specified but the model did not carry, and the one-band downgrade rule it drives.
- [x] **R0.8 — Reporting** `feat/r0.8-reporting` — terminal + JSON + Markdown renderers, Jinja2 templates, injected timestamp, golden-file + double-run determinism tests (`implementation_plan.md` §9). *Done when:* same inputs reproduce byte-identical reports (modulo timestamp). *Also landed:* `keyreach/report/build.py` (the `EngineResult` → `Report` assembly the plan implied but never named), `Report.notes` so R0.6's collected probe errors reach the reader, a three-valued status (`valid` / `not valid` / **`not probed`**) so an unidentified secret is not reported as rejected, and the removal of `respx` and `syrupy` — declared in R0.2, never used. The CLI is deliberately untouched; `--report`/`--json` belong to **R1.5**.
- [x] **R0.9 — CI guardrails** `feat/r0.9-ci-guardrails` — GitHub Actions: `ai_ban`, `network_isolation`, `read_only`, schema-drift checks, pytest+coverage, ruff/black/mypy (`implementation_plan.md` §11). *Done when:* a PR that adds an AI SDK, a direct socket in `providers/`, or a non-idempotent probe fails CI — **verified by planting all three**, in `tests/test_guardrails.py` and by hand. *Scope change:* §11 said to "grep source for known model API hostnames", which would have made **R1.1 and R1.2 impossible** — enumerating what an exposed Gemini or OpenAI key can reach means naming those hosts. `ai_ban` bans *inference endpoints* instead; §11 gained a §11.1 and `plan.md` §1 now states the line in product terms. *Also landed:* a fourth guardrail (`no_secrets`, promoted from R0.8's test), a 100% coverage floor over `keyreach` and `tools`, a golden-report drift check alongside the schema one, a 3.11/3.12/3.13 test matrix, a wheel-install job that exercises the package from outside the source tree, and a single `ci` anchor job so branch protection needs one required check.

**Phase 0 is complete.** The pipeline, the report formats, and the guardrails that enforce the hard rules all exist. What does not exist is a single provider plugin — so keyreach still cannot analyse a real key. That is **R1.1**.

## Phase 1 — Archetype providers & MVP (v0.1)

- [x] **R1.1 — Google `AIza` provider** `feat/r1.1-google-aiza-provider` — enumerate Maps/Places/Geocode/Roads/**Gemini** read-only (blueprint + credit: gmapsapiscanner, license verified **MIT**); four fixtures; inline credit header. *Done when:* a test `AIza` key yields a capability map incl. any Gemini exposure, scored with rationale. **keyreach can now analyse a real key.** *Scope change:* **FCM is deliberately not probed** — the only known probe for a legacy FCM server key is to *send a message*, which is a write that would push a notification to a real device, outside `plan.md` §11; legacy FCM was decommissioned in 2024 regardless. *Also landed:* `plan.md` §11 gains a rule for **billable read probes** (the Maps Platform meters reads, so establishing a Maps capability costs the key's owner a fraction of a cent — accepted narrowly, and always flagged `incurs_cost`), and the rule that keyreach reports Gemini *reachability* without claiming inference, since Google key restrictions can be scoped to individual methods.
- [x] **R1.2 — OpenAI/Anthropic provider** `feat/r1.2-ai-provider` — identity + model list + billing/tier, read-only; fixtures. *Done when:* AI-key identity/scope enumerated deterministically. **Two plugins, not one** — `openai` and `anthropic` are separate files with separate auth schemes and error vocabularies, which is what makes them the honest test of the plugin contract that **R1.4** checks. *Also landed:* each provider's keys are split into **two families with disjoint endpoint sets** (an `sk-admin-` / `sk-ant-admin` key reaches the administration API and no model; every other key is the reverse), so a key costs two to four requests rather than every probe in the table. *Scope change:* "billing/tier" is reachable only with an administration key — both vendors moved spend data behind one — so it is enumerated for that family and is not, and cannot be, part of an ordinary key's capability map. *Also fixed:* `ai_ban` matched **version-qualified** inference paths, so it could not see `f"{API}/chat/completions"` — the form every provider plugin here actually writes. Found by planting it; the paths are now version-independent with a boundary match, and `tests/test_guardrails.py` plants both the miss and a near-miss that must not fire.
**Phase 1 is three providers in.** `google`, `openai` and `anthropic` cover two
categories; neither AI plugin required a single change to `keyreach/core/`,
which is the acceptance test **R1.4** exists to confirm.

- [ ] **R1.3 — AWS provider** `feat/r1.3-aws-provider` — `sts get-caller-identity` + read-only permission inference; aggressive enumeration **opt-in and flagged**; fixtures. *Done when:* default run is minimal/read-only; aggressive mode gated.
- [ ] **R1.4 — Interface acceptance checkpoint** `chore/r1.4-interface-review` — verify the Phase-0 acceptance test: adding the third provider touched only its own file + fixture. *Done when:* confirmed, or the interface is refactored until true.
- [ ] **R1.5 — CLI UX** `feat/r1.5-cli-ux` — batch input (`-f` / stdin), `--provider`, `--no-enumerate`, `--delay`, `--unmask`, `--fail-on`, fixed exit codes (`implementation_plan.md` §12).
- [ ] **R1.6 — v0.1 release** `chore/r1.6-release-0.1` — reach ≥10 providers across ≥4 categories (cloud, AI, payment, comms); README usage; CHANGELOG; tag `v0.1.0`; PyPI publish workflow *(already landed in R0.2 — this item just uses it)*. *Done when:* `pipx install keyreach` (or test index) works end-to-end.

## Phase 2 — Breadth & depth

- [ ] **R2.1 — Payment providers** `feat/r2.1-payment` — Stripe, PayPal, Razorpay, Square (read-only; correct `incurs_cost`/`data_sensitive` flags).
- [ ] **R2.2 — Comms providers** `feat/r2.2-comms` — Slack, Twilio, Discord, Telegram.
- [ ] **R2.3 — Email/marketing** `feat/r2.3-email` — SendGrid, Mailgun, Postmark, Resend, Mailchimp.
- [ ] **R2.4 — Dev/source/CI** `feat/r2.4-devtools` — GitHub, GitLab, npm, PyPI, Docker Hub.
- [ ] **R2.5 — Databases/data infra** `feat/r2.5-databases` — MongoDB Atlas, Supabase, Firebase, Redis, Pinecone.
- [ ] **R2.6 — Monitoring/observability** `feat/r2.6-monitoring` — Datadog, Sentry, New Relic, Grafana.
- [ ] **R2.7 — Generic bearer/JWT inspector** `feat/r2.7-generic-jwt` — decode/validate claims deterministically; user-directed generic bearer probe.
- [ ] **R2.8 — Declarative YAML probes** `feat/r2.8-yaml-probes` — probe runner + migrate simple providers to YAML (`implementation_plan.md` §8).
- [ ] **R2.9 — HTML reports** `feat/r2.9-html-report` — disclosure-ready HTML template.
- [ ] **R2.10 — Drift-canary CI** `feat/r2.10-drift-canary` — scheduled workflow detecting provider API drift; auto-opens issues (`implementation_plan.md` §10).

## Phase 3 — Ecosystem

- [ ] **R3.1 — Scanner ingestion** `feat/r3.1-scanner-ingest` — consume TruffleHog/gitleaks/Nosey Parker output (they find, keyreach analyzes + reports).
- [ ] **R3.2 — GitHub Action** `feat/r3.2-github-action` — run keyreach in CI with `--fail-on` gating.
- [ ] **R3.3 — Provider registry & docs site** `feat/r3.3-docs-site` — curated provider list + contributor docs.

## Cross-cutting (ongoing, every PR)

- Determinism preserved (no AI/LLM, no unseeded randomness/order/time dependence).
- Read-only by default; keys masked; no exploitation features.
- Third-party licenses verified and credited; `NOTICE`/`CREDITS.md` kept current.
- Docs updated in the same PR as the behavior/interface they describe.
