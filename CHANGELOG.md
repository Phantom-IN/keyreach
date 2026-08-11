# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

keyreach is built in public: each entry below corresponds to a roadmap item in
[`ROADMAP.md`](ROADMAP.md) that landed via its own pull request. Add an entry
under `Unreleased` in the same pull request as any user-visible change.

## [Unreleased]

### Added

- Base open-source repository structure (roadmap item **R0.1**): Apache-2.0
  `LICENSE`, `NOTICE`, `CREDITS.md`, `THIRD_PARTY_LICENSES.md`, `README.md`,
  `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, this
  changelog, `.gitignore`, GitHub issue and pull request templates, and a
  hygiene-only CI workflow.
- Project scaffold (roadmap item **R0.2**): `pyproject.toml` (Apache-2.0,
  Python 3.11+, hatchling, the stack fixed in `implementation_plan.md` §1 and
  **no AI/LLM dependencies**), the `keyreach` package with a PEP 561 `py.typed`
  marker, and the `keyreach` console script.
- `keyreach --help` and `keyreach --version`. Deliberately nothing else: the
  pipeline behind the CLI is built one roadmap item at a time, and the full
  flag surface is specified in `implementation_plan.md` §12 for **R1.5**.
- Test harness (pytest) covering the CLI scaffold and the packaging metadata,
  including a guard that no AI/LLM SDK appears in any declared dependency
  group. The full `ai_ban` source-and-dependency scan remains **R0.9**.
- Developer tooling: `.pre-commit-config.yaml` (ruff, black, mypy, markdownlint,
  plus `detect-private-key` to catch un-scrubbed cassettes before they become
  permanent git history) and a checked-in `.markdownlint-cli2.jsonc` shared by
  pre-commit, CI, and local runs.
- `keyreach` reserved on PyPI with a `0.1.0.dev0` placeholder. `pip install
  keyreach` deliberately resolves nothing — pip skips pre-releases by default —
  so the name is held without shipping a tool that cannot do anything yet. The
  first real release is `0.1.0`, roadmap item **R1.6**.
- `.github/workflows/publish.yml` — tag-triggered PyPI publishing via **Trusted
  Publishing (OIDC)**, so no long-lived API token is stored in the repository,
  in an environment secret, or on a maintainer's machine. Pulled forward from
  R1.6. It refuses to publish if the git tag does not match `__version__`, or if
  the test suite fails.

- Core data models (roadmap item **R0.3**) in `keyreach/core/models.py`:
  `Capability`, `Identity`, `ValidationResult` and `Report`, plus the
  `AccessLevel` and `Severity` enums. Every model is frozen and rejects unknown
  fields, `Report.capabilities` is sorted on construction so a concurrent probe
  order can never reach the output, and `Report.generated_at` must be
  timezone-aware.
- `Severity.rank` and explicit comparison operators, giving the bands a fixed
  order for `--fail-on` (**R1.5**). Without them `StrEnum` would compare
  lexicographically, making `Severity.HIGH > Severity.CRITICAL` true.
- `keyreach/report/report.schema.json` — the published JSON Schema for `--json`
  output, generated from the models and shipped inside the package. Carries a
  `schema_version` so consumers can branch on the contract version.
- `keyreach/report/schema.py`, which generates that schema:
  `python -m keyreach.report.schema --write` regenerates it and `--check` exits
  non-zero when it is stale. The `--check` assertion runs under `pytest` today;
  **R0.9** wires it in as the CI schema-drift job.

- The provider plugin contract (roadmap item **R0.4**) in
  `keyreach/core/provider.py`: `Provider` is an abstract base class with
  `detect`, `validate` and `enumerate`, plus the `name` / `category` /
  `docs_url` / `rotation_guide_url` / `credit` metadata. Abstract on purpose —
  a plugin missing a method fails when the registry loads it, not halfway
  through probing a live key.
- `keyreach/core/registry.py` — deterministic plugin discovery. Module names are
  sorted before import (`pkgutil` walks a package in filesystem order, which
  varies by platform), and providers are returned sorted by name. Detection
  candidates rank by descending confidence then name, so equally-confident
  providers never swap places between runs.
- Registry guardrails: provider names must be lowercase and unique, categories
  are a closed set, only classes defined in the scanned module are registered,
  underscore-prefixed modules are treated as shared helpers, and a `detect()`
  return value that is non-numeric, boolean or outside `0.0`–`1.0` is rejected
  at the boundary. `validate_provider()` is public so plugin authors can assert
  their own metadata in their own tests.
- `keyreach/providers/` — the plugin package, empty until **R1.1** adds the
  Google `AIza` archetype.

- Detection layer (roadmap item **R0.5**) in `keyreach/core/detect.py`: anchored
  structural matching against `keyreach/patterns/detection_rules.yml`, followed
  by a deterministic Shannon-entropy fallback for tokens no rule claims. Both
  stages are pure functions of the key, and results rank by confidence then
  provider then rule id, so repeated runs are identical.
- 20 detection rules covering 15 providers across cloud, AI, payment, comms,
  email and dev-platform categories. Every rule is anchored and cites the vendor
  documentation URL its format came from.
- `shannon_entropy()` and `looks_like_secret()`. The entropy stage runs only
  behind shape gates — minimum length, credential charset, path/URL rejection,
  and a required digit and letter — because raw entropy rates English prose
  above a hex digest and would otherwise report every sentence in a codebase.
  It never names a provider, since that signal cannot.

- Engine and HTTP layer (roadmap item **R0.6**). `keyreach/core/http.py` is the
  only module in keyreach that opens a socket: it holds the async, rate-limited,
  recordable, redacting, read-only-guarded client and the `ProbeContext` that
  provider plugins are handed. `keyreach/core/engine.py` orchestrates
  detect → validate → enumerate and guarantees stable ordering.
- The read-only guard. `GET`/`HEAD`/`OPTIONS` are allowed; `POST` requires an
  explicit `read_only_post=True` for RPC-style APIs whose read endpoints need
  it; `PUT`, `PATCH` and `DELETE` have no code path at all. The guard runs
  before any socket work, so a denied request never reaches the transport.
- Redaction of keys in URLs, headers, request and response bodies, evidence
  strings and cassettes — including percent-encoded forms, and with credential
  headers dropped wholesale rather than pattern-matched.
- Cassette record/replay. Replay constructs no HTTP client at all, so tests and
  CI can never need a live key. Recordings substitute a fixed `<key>`
  placeholder, which is what lets one cassette replay against any key and makes
  committed fixtures safe.
- A bounded, deterministic retry schedule (fixed, never jittered) and a
  `--delay` pacing lock that deliberately serialises probes when set.

- Severity scoring (roadmap item **R0.7**) in `keyreach/core/scoring.py`:
  `score(capabilities)` returns a `ScoreResult` carrying the band and the
  rationale for it. Pure — no clock, no network, no provider name, no model — so
  the same capability set always produces the same band and the same rationale,
  and a triager can re-derive the verdict rather than take it on trust. Wired
  into the pipeline as `EngineResult.score`.
- Named banding constants (`MEDIUM_RISK_WEIGHT`, `LOW_RISK_WEIGHT`,
  `BROAD_SERVICE_COUNT`, `MAX_CITED_CAPABILITIES`) rather than inlined numbers.
  Each is a published verdict boundary, and `tests/test_scoring.py` pins both
  sides of every threshold so retuning one is a reviewed change and not a silent
  reclassification of findings already filed.
- `Capability.restricted` — the explicit referrer/IP/app restriction flag
  `implementation_plan.md` §7 always specified but the model did not carry. When
  it holds for *every* confirmed capability it lowers the band by exactly one,
  never below Info: keyreach can observe that a restriction appears to be in
  force but cannot prove it holds, and such restrictions are routinely bypassed
  by sending the header the check expects.
- `AccessLevel.UNKNOWN` scores as undetermined rather than harmless. It can
  never satisfy the privileged-access test — keyreach does not claim a write it
  did not confirm — but it counts toward breadth and risk weight and always adds
  a rationale line saying the band may understate real impact.

### Changed

- **ruff's `TID` rules are now selected.** The `banned-api` block added in R0.2
  — which forbids importing `httpx`, `requests` or `socket` outside
  `keyreach/core/http.py` — had never been enforced, because `TID` was missing
  from the `select` list and ruff applies configuration only for selected rules.
  The direct-`httpx` ban now actually fires. This is the edit-time half of the
  `network_isolation` guardrail due in **R0.9**.
- **Detection patterns are written from vendor documentation, not seeded from
  secrets-patterns-db.** The plan assumed that database was CC-BY-4.0 and could
  be subset with attribution. Verifying the license from the upstream repository
  before reuse showed it is **CC-BY-SA-4.0** — ShareAlike, which keyreach may not
  reuse — and that its README self-declares AGPL TruffleHog content with no
  per-rule provenance, making the affected entries impossible to exclude. Nothing
  was copied. `plan.md` §5.2, `implementation_plan.md` §5, `NOTICE`,
  `THIRD_PARTY_LICENSES.md` and `CREDITS.md` were all corrected to record the
  finding and its reasoning.
- The CI workflow no longer generates its markdownlint config inline; it reads
  the checked-in `.markdownlint-cli2.jsonc`. CI remains hygiene-only —
  ruff/black/mypy/pytest are wired into it in **R0.9**, which owns the pipeline.
- `implementation_plan.md` §4 now reflects the models as built: `StrEnum` rather
  than `(str, Enum)`, `Identity.extra` typed `dict[str, str]`, and the frozen /
  closed-schema / sorting / timezone rules recorded as binding on every provider
  plugin. It also documents `Provider` as an ABC, the `ProbeContext` placeholder,
  and gains §4.1 covering the registry.
- `CLAUDE.md`'s "How to add a provider" checklist now states the lowercase-name
  and closed-category rules the registry enforces, and the `restricted` flag
  alongside `data_sensitive` and `incurs_cost`.
- **The Critical band now requires a single capability to be both privileged and
  valuable.** `implementation_plan.md` §7 sketched the test as
  `(admin or write) and (data or cost)` evaluated across the whole capability
  set, which rates a key Critical when one capability can write to something
  harmless and a *different* capability can read something sensitive. Neither is
  "write access to sensitive data" (`plan.md` §6), and a Critical filed on that
  basis would not survive triage. §7 was corrected and gained a §7.1 recording
  this and the other scoring decisions as built.

### Deprecated

- *Nothing yet.*

### Removed

- *Nothing yet.*

### Fixed

- *Nothing yet.*

### Security

- *Nothing yet.*

---

No releases yet. The first release, `v0.1.0`, is roadmap item **R1.6** and ships
once keyreach covers ≥10 providers across ≥4 categories (cloud, AI, payment,
comms). See [`ROADMAP.md`](ROADMAP.md).

<!-- Link definitions are added here as releases are tagged, e.g.:
[Unreleased]: https://github.com/Phantom-IN/keyreach/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Phantom-IN/keyreach/releases/tag/v0.1.0
-->
