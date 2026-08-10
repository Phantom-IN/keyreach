# Contributing to keyreach

Thanks for wanting to help. keyreach is being **built in public**: every feature
lands as its own roadmap item, on its own branch, through its own pull request,
so anyone can audit how the tool came to be. This document explains how to work
inside that process.

Before anything else, please read the three planning documents — they are the
source of truth, and pull requests are reviewed against them:

| Document | Owns decisions about |
| --- | --- |
| [`plan.md`](plan.md) | **Product** — scope, goals, non-goals, provider coverage, the *intent* of the severity model, report contents, safety/ethics, licensing. |
| [`implementation_plan.md`](implementation_plan.md) | **Technical** — codebase structure, interfaces, engine/HTTP/scoring internals, probe format, testing, CI guardrails, CLI spec. |
| [`CLAUDE.md`](CLAUDE.md) | **Working rules** — the always-on operating manual: hard rules, conventions, commands, definition of done. |

If two documents disagree: `plan.md` wins on product/scope/safety,
`implementation_plan.md` wins on technical structure. If they genuinely
conflict, **stop and open an issue** rather than guessing.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## The hard rules

These are non-negotiable. A pull request that breaks one of them will not be
merged, no matter how good the rest of it is. Most are enforced by CI once the
guardrails land in roadmap item **R0.9**.

1. **No AI/LLM. Anywhere. Ever.** Zero AI/LLM calls, zero AI/LLM SDK
   dependencies. Everything is rule-based. keyreach handles live secrets
   (sending one to a model would be a leak), findings must be reproducible, and
   every verdict must be auditable to a concrete rule. If a capability can't be
   decided by a rule, emit `AccessLevel.UNKNOWN` — never guess with a model or a
   fuzzy heuristic. The `ai_ban` CI check enforces this; do not weaken it.
   *(keyreach may **probe** an AI provider's endpoints with the user's key —
   that is the product. It must never **import their SDK to call a model**.)*
2. **Deterministic output.** Same key + same recorded provider responses ⇒
   byte-identical report (except the injected timestamp). No unseeded
   randomness, no reliance on dict/set iteration order, no ad-hoc wall-clock
   reads. Sort by explicit keys before output.
3. **Read-only by default.** Probes must be non-destructive: no writes, deletes,
   or spend. The HTTP layer default-denies non-idempotent methods. Anything
   aggressive is off by default, explicitly flagged, and warned.
4. **Mask secrets by default.** Keys are masked in all output, logs, evidence,
   and recorded fixtures unless `--unmask` is passed. **Never commit a real key
   or an unscrubbed cassette.**
5. **License discipline.** keyreach is Apache-2.0. **Never copy AGPL/GPL code**
   (e.g. TruffleHog) — study behavior and re-implement from public API docs
   only. Reuse MIT/Apache/BSD/CC-BY sources only, with attribution in
   [`NOTICE`](NOTICE) / [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) and
   [`CREDITS.md`](CREDITS.md). **Verify every third-party license from its own
   repository** before reusing anything.
6. **Plugins don't touch the network directly.** Provider code goes through
   `ProbeContext` (the recordable, rate-limited, redacting client). Direct
   `httpx`/`socket`/`requests` imports under `providers/` fail the
   `network_isolation` CI check.

And the corresponding **do nots**:

- ❌ No exploitation, privilege-escalation, or lateral-movement features.
  keyreach is a scoping-and-reporting tool.
- ❌ No time-dependent logic outside the injected timestamp.
- ❌ No printing full keys by default.
- ❌ No secret-scanning features (crawling repos/buckets to *find* keys) — that
  is an explicit non-goal, see [`plan.md`](plan.md) §4.

---

## Development setup

> **Code arrives in R0.2.** As of the first commit this repository contains
> governance, docs, and the roadmap only — there is no `pyproject.toml`, no
> `keyreach/` package, and no test suite yet. The setup below describes what
> will exist once roadmap item **R0.2 — Project scaffold** merges. Until then,
> contributions are documentation, roadmap, and process work.

Planned stack ([`implementation_plan.md`](implementation_plan.md) §1): Python
3.11+, Typer, httpx, rich, pydantic v2, Jinja2, PyYAML, pytest + respx +
syrupy. **No AI/LLM dependencies, by design.**

```bash
# clone
git clone https://github.com/Phantom-IN/keyreach.git
cd keyreach

# install for development (available after R0.2)
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pre-commit install

# quality gates — run these before every commit (available after R0.2)
ruff check . && black --check . && mypy keyreach
pytest -q --cov=keyreach

# run locally against a throwaway key you own (available after R1.x)
keyreach <KEY>
keyreach <KEY> --report md -o out.md
keyreach <KEY> --json
```

**Never run keyreach against keys you don't own or aren't authorized to test.**
See [`SECURITY.md`](SECURITY.md).

---

## The build-in-public workflow

Everything after the initial commit happens on a feature branch. **Nothing is
committed directly to `main`.** History is never rewritten — no force-pushes to
`main`, ever.

### 1. Open a tracking issue

Before starting a roadmap item, open an issue for it. This is part of building in
public: it makes the work visible, avoids duplicated effort, and gives people a
place to weigh in before the code exists. Reference the roadmap ID in the title,
e.g. `R1.1 — Google AIza provider`.

For work that isn't on the roadmap, open a bug report, feature request, or
new-provider issue first (templates are in
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/)) so scope can be agreed
before you invest time.

### 2. Branch

Branch off up-to-date `main`, named for the roadmap item:

```
feat/<roadmap-id>-<slug>
```

Examples, straight from [`ROADMAP.md`](ROADMAP.md):

```
feat/r0.2-project-scaffold
feat/r0.6-engine-http
feat/r1.1-google-aiza-provider
```

Use the prefix that matches the work: `feat/…` for features, `fix/…` for bug
fixes, `docs/…` for documentation, `chore/…` for maintenance and releases,
`ci/…` for pipeline changes, `test/…` for test-only work, `refactor/…` for
restructuring.

```bash
git checkout main && git pull
git checkout -b feat/r0.2-project-scaffold
```

### 3. Commit — Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short imperative summary>

<optional body — what changed and why, wrapped at 72 chars>

<optional footer — Refs: #123 / BREAKING CHANGE: ...>
```

Allowed types:

| Type | Use for |
| --- | --- |
| `feat` | A new capability: a provider, a CLI flag, a report format. |
| `fix` | A bug fix. |
| `docs` | Documentation only — including `plan.md` / `ROADMAP.md` / this file. |
| `chore` | Maintenance, dependency bumps, releases, repo housekeeping. |
| `test` | Adding or correcting tests and fixtures. |
| `ci` | CI workflows and guardrail checks. |
| `refactor` | Restructuring with no behavior change. |

Rules: imperative mood ("add", not "added"); lower-case summary; no trailing
period; keep the summary under ~72 characters. A breaking interface change gets
a `!` after the type (`feat!:`) and a `BREAKING CHANGE:` footer. Scope the
provider where it helps: `feat(google): enumerate Gemini Files API`.

Examples:

```
feat(scoring): add deterministic severity bands with rationale
fix(http): mask key in recorded cassette request URLs
docs(roadmap): tick R0.3 and note schema generation
ci: add ai_ban denylist check for LLM SDK imports
test(google): add invalid-key cassette for AIza provider
```

### 4. Open a pull request

- **One roadmap item per pull request** where practical. If an item genuinely
  needs splitting, say so in the description and link the sibling PRs.
- Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) — it is
  a real checklist, not a formality.
- **Link the roadmap item and the governing doc section** you are implementing,
  e.g. "Implements R0.7; follows `implementation_plan.md` §7 and `plan.md` §6."
  Citing the doc you followed keeps decisions traceable.
- **Keep code and docs in sync in the same PR.** If you change behavior, scope,
  interfaces, or structure, update the document that owns that decision *in the
  same pull request*, and update [`CLAUDE.md`](CLAUDE.md) if a rule or convention
  changed. Code and docs must never drift. A PR that changes behavior without
  updating its owning doc is incomplete.
- Tick the roadmap checkbox in [`ROADMAP.md`](ROADMAP.md) as part of the PR that
  completes the item.
- Add an entry to [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased` for anything
  user-visible.
- Mark it **draft** while you're still working — early drafts are welcome and
  very much in the spirit of building in public.

### 5. Merge

Pull requests are **squash-merged** into `main`, so `main` keeps one clean commit
per roadmap item. The squash commit message must itself be a valid Conventional
Commit. Delete the branch after merge.

---

## Adding a provider

Adding a provider should take about 30 minutes. The authoritative checklist is
in [`CLAUDE.md`](CLAUDE.md) ("How to add a provider"), with the interface
contract in [`implementation_plan.md`](implementation_plan.md) §4 and the
declarative YAML probe format in §8. In outline:

1. Create `keyreach/providers/<name>.py` (or `.yml` for simple cases).
2. Implement the contract:
   - **`detect(key)`** — pure, high-confidence structural match. Add a pattern to
     `detection_rules.yml` if needed.
   - **`validate(key, ctx)`** — the cheapest read-only liveness + identity call.
   - **`enumerate(key, ctx)`** — read-only probes. Each match returns a
     `Capability` with `access`, `detail`, `evidence`, `risk_weight`, and the
     `data_sensitive` / `incurs_cost` flags set correctly — **those flags drive
     severity, so getting them right matters more than anything else in the
     file.** Return a stably-sorted list.
   - **Metadata** — `name`, `category`, `docs_url`, `rotation_guide_url`, and
     `credit` (the upstream project, if derived from one).
3. Record fixtures for **both** a valid and an invalid/expired key response, and
   **scrub every secret** before committing.
4. Add tests: detection, provider behavior, and updated golden snapshots.
5. If derived from prior art (e.g. the Google plugin from gmapsapiscanner), add
   an inline credit header in the file and an entry in
   [`CREDITS.md`](CREDITS.md) — plus [`NOTICE`](NOTICE) /
   [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) if code or data is
   actually reused.

**Keep probes minimal.** Every probe is authentication traffic and a log entry on
someone's production service. Probe the fewest endpoints that prove the
capability.

Proposing a provider you don't want to build yourself? Use the
[new provider issue template](.github/ISSUE_TEMPLATE/new_provider.md).

---

## Conventions

- Python 3.11+, fully typed. `ruff` + `black` + `mypy` must pass.
- pydantic v2 models for all structured data — never pass raw dicts around for
  capabilities or reports.
- Async probes via `httpx`, **through `ProbeContext` only**.
- Deterministic sorting before any output. No `set` iteration in output paths.
- Evidence strings are masked and read-only: include the request and a benign
  response summary that *proves* the capability.
- Timestamps: use the engine-injected `generated_at`. Never call the clock
  directly in report code.

## Testing rules

- **No live keys in CI** — everything runs off cassettes in `tests/fixtures/`.
- Cover every scoring band boundary in `test_scoring.py`.
- `test_determinism.py` must stay green: double-run byte-equality plus golden
  snapshots, with the timestamp fixed.
- Add redaction assertions whenever you touch an output or evidence path.
- When a provider's API changes, update the cassette and the golden files in the
  same PR, and note the drift in the description.

## Definition of done

A change is done when:

- [ ] Lint, format, types, and tests pass — including the `ai_ban`,
      `network_isolation`, `read_only`, and schema-drift checks.
- [ ] New or changed providers ship **valid and invalid fixtures** and updated
      goldens.
- [ ] Output stays **deterministic and masked**.
- [ ] Any reused code or data is **license-verified and credited**.
- [ ] Docs are updated if behavior or interfaces changed.

## Reporting security issues

Do **not** open a public issue for a vulnerability in keyreach itself. Follow the
coordinated disclosure process in [`SECURITY.md`](SECURITY.md).

## License of contributions

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the project.
