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
- [ ] **R0.7 — Scoring** `feat/r0.7-scoring` — pure, rule-based severity function + rationale (`implementation_plan.md` §7, `plan.md` §6); tests covering every band boundary. *Done when:* identical capability sets always produce identical band + rationale.
- [ ] **R0.8 — Reporting** `feat/r0.8-reporting` — terminal + JSON + Markdown renderers, Jinja2 templates, injected timestamp, golden-file + double-run determinism tests (`implementation_plan.md` §9). *Done when:* same inputs reproduce byte-identical reports (modulo timestamp).
- [ ] **R0.9 — CI guardrails** `feat/r0.9-ci-guardrails` — GitHub Actions: `ai_ban`, `network_isolation`, `read_only`, schema-drift checks, pytest+coverage, ruff/black/mypy (`implementation_plan.md` §11). *Done when:* a PR that adds an AI SDK, a direct socket in `providers/`, or a non-idempotent probe fails CI.

## Phase 1 — Archetype providers & MVP (v0.1)

- [ ] **R1.1 — Google `AIza` provider** `feat/r1.1-google-aiza-provider` — enumerate Maps/Places/Geocode/Roads/FCM/**Gemini** read-only (blueprint + credit: gmapsapiscanner); valid + invalid fixtures; inline credit header. *Done when:* a test `AIza` key yields a capability map incl. any Gemini exposure, scored with rationale.
- [ ] **R1.2 — OpenAI/Anthropic provider** `feat/r1.2-ai-provider` — identity + model list + billing/tier, read-only; fixtures. *Done when:* AI-key identity/scope enumerated deterministically.
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
