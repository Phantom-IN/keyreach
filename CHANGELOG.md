# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

keyreach is built in public: each entry below corresponds to a roadmap item in
[`ROADMAP.md`](ROADMAP.md) that landed via its own pull request. Add an entry
under `Unreleased` in the same pull request as any user-visible change.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-12

The first release. Ten providers across five categories, a CLI, and the three
guarantees — deterministic, read-only, no AI/LLM — enforced by CI rather than
asserted. Everything below landed across roadmap items **R0.1**–**R1.6**, each
in its own pull request.

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

- Reporting (roadmap item **R0.8**). `keyreach/report/build.py` assembles a
  `Report` from an `EngineResult` — title, band, one-line impact, rationale,
  capability map with evidence, and remediation — and
  `keyreach/report/render.py` renders one to **terminal text, JSON or
  Markdown**. HTML remains **R2.9**.
- `Report.notes` — what could not be determined. R0.6 collects probe errors
  precisely so a report can distinguish "no capability" from "could not
  determine"; without this field a run where three probes failed rendered
  identically to one where three probes found nothing.
- A three-valued status: `valid`, `not valid`, and **`not probed`**. A secret
  whose provider keyreach could not identify was never tested, and reporting it
  as "not valid" would assert that a provider refused it — a stronger and
  different claim.
- Golden reports under `tests/golden/` — three end-to-end scenarios (live key,
  dead key, unidentified secret) in all three formats, generated by replaying
  committed cassettes. Regenerate with `python -m tests.regenerate_goldens`, a
  separate entrypoint from `pytest` so a snapshot can never rewrite itself.
  The Markdown goldens are linted by keyreach's own markdownlint configuration.
- `tests/test_determinism.py` — double-run byte equality across the whole
  pipeline in every format, plus a test that the *only* difference between two
  renders of one run is the timestamp.
- `tests/test_repo_hygiene.py` — keyreach's own detector run over every file a
  commit could carry, so a secret-shaped test sample fails locally instead of
  being rejected by GitHub push protection, whose only offered remedy is a
  click-through "allow this secret" link. It enumerates **tracked and
  untracked-but-not-ignored** files: an earlier ad-hoc version used
  `git ls-files`, which lists tracked files only and therefore skipped every
  newly added file in a pull request. A planted-secret test pins that.

- CI guardrails (roadmap item **R0.9**) in `tools/guardrails/`, completing
  **Phase 0**. Five checks — `workflows`, `ai_ban`, `network_isolation`,
  `read_only` and `no_secrets` — each a Python module exposing `check()`, so one implementation
  runs as a CI job, as a pre-commit hook, and under `pytest`. Run them with
  `python -m tools.guardrails`. Not shipped in the wheel: installing keyreach
  gets you a key analyser, not a linter.
- **Every guardrail is tested by planting the violation it exists to catch.**
  `tests/test_guardrails.py` adds an AI SDK, a direct socket under `providers/`,
  and a non-idempotent probe, and asserts each is caught — R0.9's acceptance
  criterion, stated as a failure and verified as one. Negative controls too: a
  check that rejects valid code gets switched off.
- `ai_ban` walks the AST, so an import inside a function body is caught, and it
  resolves `importlib.import_module("openai")`, which no import-based linter
  sees. It reads every declared dependency group, not just runtime.
- `network_isolation` is an **independent implementation**, not a wrapper around
  ruff's `banned-api` rule. A test proves it by planting a dynamic import,
  running ruff over it — which passes cleanly — and asserting this check still
  rejects it. The provider fixture packages under `tests/` are held to the same
  rule as real plugins.
- `read_only` rejects `put`/`patch`/`delete` outright, `post` without
  `read_only_post=True`, and any `request()` call in plugin code; it also scans
  declarative YAML probes, which AST scanning cannot see.
- A **100% coverage floor** over `keyreach` and `tools`, a **3.11/3.12/3.13**
  test matrix (every version the classifiers claim), a golden-report drift check
  alongside the schema one, a `package` job that installs the built wheel into a
  clean environment and exercises it from outside the source tree, and a single
  `ci` anchor job so branch protection needs one required check rather than
  eight.
- `workflows` — the CI definition must itself parse before it can gate
  anything. Added after R0.9's first push failed with a single annotation and no
  jobs at all: `ci.yml` used `join(needs.*.result, " ")`, and GitHub's
  expression language has no double-quoted string literal, so the whole file was
  rejected. Nothing in the repository could have caught it, because everything
  that would have runs *inside* the workflow that failed to parse. This check
  runs as a pre-commit hook, which is the only place that breaks the
  circularity. It also rejects a `needs:` naming a job that does not exist — a
  typo that parses cleanly and then never gates anything.
- `python -m tests.regenerate_goldens --check` — the verify half, mirroring
  `python -m keyreach.report.schema --check`. Both checked-in artifacts are
  generated from code, so both are verified the same way.

- **The Google `AIza` provider** (roadmap item **R1.1**) in
  `keyreach/providers/google.py` — the first real plugin, and the point at which
  keyreach can analyse a key. Six read-only probes: Gemini Files, Gemini Cached
  Content, Gemini Models, Places, Geocoding and Roads. Blueprint credit
  **gmapsapiscanner** (Ozgur Alp), license verified **MIT** from the upstream
  repository; no code copied, every endpoint written from Google's own
  documentation with each probe citing its source page.
- Recovery of the **GCP project number** from a `SERVICE_DISABLED` error, read
  from the structured `metadata.consumer` field rather than scraped from
  localised prose. An exposed key that names its own project tells the recipient
  which project to audit.
- Validation that distinguishes *rejected* from *restricted* from *not enabled*.
  Only `API_KEY_INVALID` means the key is not a key; a referrer or IP
  restriction, or a disabled API, means a **live** key whose capability map is a
  lower bound. Collapsing those into "invalid" would under-report an exposure.
- Four committed cassettes — live key, invalid key, restriction-blocked key, and
  the classic Maps-only key — constructed from Google's published response
  shapes rather than recorded from a live key, which keyreach's own rules
  forbid holding.

- **The OpenAI and Anthropic providers** (roadmap item **R1.2**) in
  `keyreach/providers/openai.py` and `keyreach/providers/anthropic.py` — two
  plugins rather than one, because the two vendors share nothing but a `sk-`
  prefix: different auth headers, different error vocabularies, different
  administration models. No prior art; every endpoint, header and error code was
  written from the vendor's own documentation, with each probe citing its page.
- **Key families.** Each vendor issues two credentials behind one prefix: an
  administration key (`sk-admin-`, `sk-ant-admin`) reaches the organization API
  and no model at all, and every other key is the reverse. Both plugins select
  the endpoint set from the documented prefix and probe only that, so a key
  costs two to four requests instead of every probe in the table (`plan.md`
  §11). Validation reuses the family's cheapest probe, so a live key costs one
  request there, not two.
- Identity for both: OpenAI's organization is read from the `openai-organization`
  response header on the liveness check, and Anthropic's from
  `/v1/organizations/me`. Neither vendor offers a free "who am I" endpoint, so
  neither costs an extra request.
- **Billing and tier**, for administration keys only — OpenAI's organization
  costs endpoint and Anthropic's cost report. Both take a fixed window constant
  rather than a relative one: reading the clock for a start time would give two
  runs of the same key different request URLs and a report that cannot be
  reproduced.
- Validation that distinguishes *rejected* from *out of credit* from *rate
  limited*. An OpenAI quota failure is proof of a **live** key — OpenAI only
  knows whose quota to check once it has accepted the credential — and reporting
  it as invalid would retire a key that starts working again the moment the
  account is topped up.
- Six committed cassettes — live platform key, invalid key and live
  administration key for each vendor — constructed from published response
  shapes rather than recorded from a live key, which keyreach's own rules forbid
  holding.
- An `openai-admin-key` detection rule, and `admin-` added to the generic
  OpenAI rule's negative lookahead so one key still yields one candidate. An
  admin key reaches a completely different endpoint set, so calling it "an
  OpenAI API key" would describe the wrong exposure to whoever reads the report.

- **The AWS provider** (roadmap item **R1.3**) in `keyreach/providers/aws.py`.
  Blueprint credit **enumerate-iam** (Andrés Riancho), license verified
  **GPL-3.0** from the upstream repository — copyleft, so nothing could be
  copied and nothing was. Every endpoint, API version and error code was written
  from AWS's own documentation, each probe citing its source page.
- **SigV4 request signing**, implemented from AWS's published specification.
  Verified against **botocore**, AWS's own reference implementation, in a
  throwaway environment: all twelve probes signed identically for both long-term
  and temporary credentials, 24 comparisons. Four of those vectors are pinned in
  `tests/test_provider_aws.py` so CI checks the signer without AWS's SDK
  installed; botocore is not a keyreach dependency and no code was taken from it.
- **Composite credentials.** AWS is the first credential that is not one string —
  nothing can be signed without the secret access key — so keyreach accepts a
  colon-joined `AKIA…:<secret>`, or `ASIA…:<secret>:<session token>` for
  temporary credentials. A bare access key ID is still detected and reported;
  validation says which half is missing rather than reporting the credential as
  dead.
- **Six default probes, all about the credential itself**: STS caller identity,
  the caller's IAM user, its access keys, the account alias, the account IAM
  summary, and the S3 bucket list.
- **An opt-in aggressive sweep** across IAM users and roles, EC2, RDS, SNS and
  SQS, gated on `ProbeContext.aggressive` and off by default. Every capability
  it produces says "found by opt-in aggressive enumeration", so a reader can
  tell which findings cost a sweep. Every aggressive probe is still read-only —
  the distinction is quiet versus loud, not read versus write.
- **Root credentials are reported as `ADMIN`.** AWS documents that the root user
  has complete access to every resource and that no IAM policy can constrain it,
  so an ARN ending `:root` establishes administrative access by the vendor's own
  access model rather than by inference. Every other AWS capability is `READ`:
  reading IAM does not establish writing it.
- Three `ProbeContext` hooks AWS required: `now()` (a UTC clock for SigV4
  timestamps, injectable via `Engine(clock=...)`), `protect()` (registers a
  composite credential's parts with the redactor, because `iam:ListAccessKeys`
  echoes back the access key ID alone), and `aggressive`.
- An `aws-credential-pair` detection rule for the joined form.

- **A provider conformance suite** (roadmap item **R1.4**) in
  `tests/test_provider_contract.py`: the plugin contract asserted against every
  registered provider, parametrised over the live registry so a plugin added
  later is held to it without anyone remembering. It pins metadata, `detect`
  purity and strictness, probe-table hygiene, that every provider has a
  detection rule, that a provider setting `credit` actually appears in
  `CREDITS.md` **and** in its own source — attribution is a hard rule and
  nothing checked it until now — and the exact public surface of
  `ProbeContext`, so widening it again is an edit to a reviewed list rather
  than a member nobody discusses.
- **`ProbeClient.requests_made`** — how many requests actually left, as opposed
  to being served from cache. `plan.md` §11 asks for minimal probe counts; this
  is the number that claim is about.

- **The CLI** (roadmap item **R1.5**) — keyreach is usable from a terminal.
  `keyreach KEY` runs the whole pipeline and prints a report; `-f keys.txt` and
  `-f -` take a batch from a file or stdin; `--report terminal|json|md`, `--json`
  and `-o PATH` choose and place the output; `--provider`, `--no-enumerate`,
  `--aggressive`, `--delay 500ms`, `--unmask`, `--fail-on BAND` and `--quiet`
  do what `implementation_plan.md` §12 says they do.
- **An ASCII startup banner** on stderr, carrying the version, the three
  guarantees, and the authorized-use reminder `plan.md` §11 asks for. Plain
  ASCII deliberately: box-drawing characters become mojibake over ssh, in a
  Windows console, and in CI log viewers. `--quiet` suppresses it, and
  `--version` never prints it, because release tooling parses that.
- **stdout carries only the report.** The banner, the aggressive-mode warning,
  the unmask warning and every error go to stderr, so `keyreach KEY --json | jq`
  works and `keyreach KEY --report md > finding.md` writes a file containing
  nothing but the finding.
- **Fixed exit codes**: `0` clean, `2` a finding at or above `--fail-on`, `1`
  anything went wrong. `2` means a finding and nothing else.
- **`Engine(force_provider=...)`**, behind `--provider`. The run records in
  `Report.notes` that detection was overridden — a capability map produced that
  way rests on the operator's claim rather than on a rule, and a reader cannot
  otherwise tell the two apart.

- **Six more providers (roadmap item **R1.6**), taking keyreach to 10 across 5
  categories** — the v0.1 coverage measure, met:
  - **`stripe`** (payment) — account, balance, charges, customers, payment
    intents, payouts and subscriptions. The first provider whose verdict can be
    **Critical from a single read**, because Stripe publishes the sentence that
    justifies it: a secret key "has unrestricted permissions on all Stripe
    APIs", while a restricted key has "permissions you control". Same probe,
    same response, two prefixes, two verdicts. A `sk_test_` key is a weaker
    finding than `sk_live_` for the same documented reason — sandbox payments
    are not processed and sandbox objects are simulated.
  - **`razorpay`** (payment) — payments, orders, customers, settlements, over a
    colon-joined `key_id:key_secret`. Only the secret half is registered for
    redaction, because Razorpay documents that "only the Key Id is visible on
    the Dashboard"; masking the key id would delete the one fact telling a
    recipient which key to revoke.
  - **`slack`** (comms) — workspace, members, channels, files. Slack answers
    `200 OK` with `{"ok": false, "error": "invalid_auth"}`, so the HTTP status
    is not the verdict, and `missing_scope` is treated as a clean negative
    rather than a failure.
  - **`twilio`** (comms) — account and tier, balance, message log, call log,
    phone numbers, over a colon-joined `AccountSid:AuthToken`.
  - **`telegram`** (comms) — bot identity, webhook target, commands. Carries the
    only capability in keyreach derived from a *response field* rather than from
    a probe succeeding: `getMe` reporting `can_read_all_group_messages`, which
    Telegram documents as privacy mode being disabled, means the bot receives
    every message in every group it belongs to.
  - **`github`** (devtools) — account, private repositories, organizations,
    email addresses, gists. The first provider that reports a **write without
    performing one**: GitHub documents `X-OAuth-Scopes` as listing a token's
    grants, so `repo` yields `write` on repositories — while the same token's
    organization capability stays `read`, because `repo` grants nothing there.
- **The v0.1 coverage measure is asserted, not counted.**
  `tests/test_provider_contract.py` now fails the build if the registry holds
  fewer than ten providers, or fewer than four categories, or is missing any of
  cloud / AI / payment / comms. The number had been published in three documents
  since R0.1 with nothing checking it.
- **Detection rules** for Razorpay key ids and key pairs, and for the Twilio
  `AccountSid:AuthToken` pair, each citing the vendor page it was written from.

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

- `Report.generated_at` now serializes as `2026-01-01T12:00:00+00:00` in JSON
  rather than `...Z`. pydantic spells a UTC datetime one way and
  `datetime.isoformat()` — which the Markdown and terminal renderers call —
  spells it another. Both are valid RFC 3339, but two spellings of one instant
  across keyreach's own three formats makes a JSON report and a Markdown report
  of the same run look like they disagree.
- `implementation_plan.md` §9 gains a §9.1 recording the reporting layer as
  built, including why `generated_at` is a parameter of `build_report` rather
  than something the engine stamps: `EngineResult` stays timestamp-free, so
  every stage below the CLI is a pure function of its inputs and the clock is
  read exactly once, at the outermost boundary.
- `plan.md` §7 gains a tenth required report content ("what could not be
  determined") and a note on what a report must not claim.
- **`ai_ban` bans model-inference endpoints, not provider hostnames.**
  `implementation_plan.md` §11 said to "grep source for known model API
  hostnames too". That rule would have made roadmap items **R1.1 and R1.2
  impossible**: enumerating what an exposed Gemini or OpenAI key can reach *is*
  keyreach's product, and doing it means writing `https://api.openai.com/v1/models`
  into a provider plugin. The distinction that matters is not which host is
  named but what is asked of it — listing models is a read-only capability
  probe, `POST /v1/chat/completions` is inference. `plan.md` §1 now states this
  in product terms and §11 gained a §11.1.
- **`ai_ban`'s inference-endpoint paths are now version-independent.** They read
  `/v1/chat/completions` until R1.2, which made the check blind to the
  convention every provider plugin in this repository follows: a plugin declares
  `API = "https://api.openai.com/v1"` and composes probes from it, so the line
  that would call a model reads `f"{API}/chat/completions"` and contains no
  version at all. Found by planting exactly that line while building R1.2 and
  watching `ai_ban` report a clean repository — the third time a check here has
  been believed to work and did not (`CLAUDE.md` hard rule 7). Matching now uses
  a trailing boundary so `/complete` does not also fire on a path ending
  `/completed`, and `tests/test_guardrails.py` plants both the miss and that
  near-miss.
- **keyreach reports AI-key *reachability*, never inference or spend.** Both AI
  plugins leave `incurs_cost` unset on every capability. Confirming that a key
  can spend means calling a model, which `plan.md` §1 forbids, and neither
  vendor's key format implies the permission: OpenAI project keys carry
  per-endpoint scopes, so a "Read Only" key lists models and is refused
  everything else. This under-reports the common case on purpose; the
  alternative is asserting a capability keyreach did not confirm. `plan.md` §1
  now states this consequence alongside the rule that produces it.
- **The same probe shape yields opposite access levels for the two vendors, and
  both are sourced.** Anthropic documents that Claude Console admin keys "do not
  have selectable scopes; every key carries full access to all endpoints that
  accept Admin API keys" — which include removing members — so an Admin API read
  establishes the matching write by the vendor's own access model, and those
  capabilities are recorded as `admin`. OpenAI admin keys *do* carry per-resource
  scopes (`users.read` is separate from `users.write`), so the identical finding
  there is recorded as `read`. Neither is a judgement about which vendor is
  riskier.
- **A provider may now see a clock, for request signing only.** `plan.md` §1
  forbids time-dependent *verdicts*, and R1.3 is the first item where a
  credential cannot be used at all without a timestamp: AWS SigV4 refuses a
  request whose clock is minutes stale. `ctx.now()` is the one sanctioned route,
  the engine owns it so a test can pin it, and because AWS signs in a header
  rather than the query string the timestamp never enters a cassette key.
  `tests/test_provider_aws.py` runs the same cassette under clocks five years
  apart and asserts byte-identical output.
- **`plan.md` §11's aggressive-mode clause stopped being hypothetical.** It read
  "if ever added"; the gate now exists, defaults off, and has something behind
  it. §11 also gains the composite-credential masking rule.
- **`implementation_plan.md` §12 gains `--aggressive`** and a note on the AWS
  credential format, which is the first CLI input that is not a single token.
- **`enumerate-iam`'s license is recorded as GPL-3.0**, verified from upstream.
  It was previously listed only as a "methodology and design reference" with no
  license noted. This is the mirror image of R1.1's gmapsapiscanner finding: that
  one was MIT, so reuse *would* have been allowed and "nothing was copied" was a
  choice; this one is copyleft, so the same sentence is load-bearing.
  `CREDITS.md` and `THIRD_PARTY_LICENSES.md` now say which is which.
- **The console script points at `keyreach.cli.run`, not at the typer app.**
  Click exits `2` on a malformed command line, and keyreach's `2` means "a
  finding at or above `--fail-on`" — the same number for "your CI config has a
  typo" and "this key is Critical", in the one place these codes are read by a
  machine. `run` is a total mapping from whatever click exited with onto the
  three documented codes. It is built on the exit code rather than on exception
  types because **typer vendors its own copy of click**, so
  `except click.UsageError` imported from the real package names a class that is
  never raised and catches nothing — which is how the first implementation was
  written, and it looked correct.
- **`plan.md` §11's first-run reminder exists.** It had been a requirement with
  nowhere to live until there was a CLI to put it in.
- The CI workflow no longer runs hygiene checks only. It now gates every pull
  request on the four guardrails, ruff/black/mypy, tests with a coverage floor,
  both drift checks, and a wheel-install check — the gates that had been running
  on author and reviewer discipline since R0.2.

- **`__version__` is `0.1.0`**, replacing the `0.1.0.dev0` placeholder that held
  the PyPI name from R0.2 and deliberately resolved to nothing. Releasing is
  tag-driven: `.github/workflows/publish.yml` refuses to publish when the git
  tag does not match this string.
- **`ai_ban`'s endpoint matching is documented as case-sensitive**, and pinned
  in both directions by a planted test. Twilio's message resource is
  `/Messages.json`; the banned inference path is the same word in lower case.
  What had been an incidental property of how the check was written is now the
  only thing separating a legitimate provider plugin from a failing build, so
  "make the match case-insensitive" now fails loudly instead of quietly breaking
  `keyreach/providers/twilio.py`.

### Deprecated

- *Nothing yet.*

### Removed

- **`respx` and `syrupy` dev dependencies.** Both were declared in R0.2 and
  never imported. R0.6 built its own cassette format — JSON keyed by redacted
  URL, replaying without constructing an HTTP client at all — and R0.8 checked
  golden reports in as plain files so a reviewer reads the actual report in the
  pull-request diff. Unused dependencies in a security tool are licenses to
  re-verify and installs to trust for no benefit, and they invite a second way
  to do a job that already has one.

- **`plan.md` §11 now covers billable read probes.** "No spend" was written for
  writes, sends and purchases. The Maps Platform meters *reads* and has no free
  metadata endpoint, so establishing that an exposed key can call the Geocoding
  API costs its owner a fraction of a cent. The rule now states the four
  conditions under which that is acceptable — trivial and bounded, no free
  equivalent, otherwise unestablishable, and billed to the person the report is
  for — and requires `incurs_cost` on every metered probe.
- **`CREDITS.md` and `THIRD_PARTY_LICENSES.md`: gmapsapiscanner is MIT.** It had
  been recorded as "verify license before reuse". Verified from the upstream
  repository: MIT, which would permit reuse with attribution. Nothing was copied
  even so, and both files now say which of those two facts is which.
- `implementation_plan.md` §3 names the provider `google.py` rather than
  `google_aiza.py` — the registry key is `google`, and the file should match what
  `--provider` accepts.

### Fixed

- **CLI help assertions that only held on a developer's machine.** Two tests
  from R0.2 asserted `"--version" in result.output`. `rich` styles the leading
  hyphen of a flag as its own span, so with colour on the help contains
  `\x1b[1;36m-\x1b[0m\x1b[1;36m-version\x1b[0m` — in which the literal
  `--version` does not occur. Whether colour is on depends on whether `rich`
  believes it is writing to a terminal, and GitHub Actions sets `CI=true`, which
  makes it believe so. The assertions therefore passed everywhere they had ever
  been run and failed on the first CI run that executed them, which was R0.9's.
  Tests now normalise help output (styling stripped, wrapping collapsed) and the
  runner pins colour and width; a regression test forces colour on and asserts
  the guarantees still reach the reader.

- **Every provider was fetching its validation endpoint twice** (found by
  **R1.4**). Each plugin makes its cheapest capability probe double as the
  liveness check, and each said so in a comment claiming this cost "one request,
  not two". Counting the requests showed all four issuing it once in `validate`
  and again in `enumerate` — a wasted request per run against somebody's
  production service, which is exactly what `plan.md` §11 exists to limit.
  `ProbeClient` now answers a repeated idempotent request from a per-run cache,
  keyed as a cassette is. Fixing it there rather than by threading the
  validation response into `enumerate` leaves the `Provider` signature untouched
  and fixes it for providers not written yet. Google 7→6 requests, OpenAI 5→4,
  Anthropic 3→2, AWS 7→6 (12→11 with `--aggressive`), with identical
  capabilities in every case. A test bans the wording so the reasoning cannot
  come back.
- **`httpx.URL(url, params=None)` clears the query string** rather than leaving
  it alone, so a probe URL carrying its own `?a=b` would have been sent without
  it. No shipped provider passes a pre-built query, so nothing was mis-sent —
  the next one to try would have been, silently. Found because three
  deliberately distinct URLs collapsed into one while measuring request counts.

### Security

- No advisories. Recorded here because a security tool's first release should
  say so explicitly: keyreach ships **no exploitation capability**, makes no
  write, delete or spend call, masks keys in all output by default, and contains
  no AI/LLM dependency or model call anywhere. Each of those is enforced by a
  guardrail that has a test planting the violation it exists to catch, and all
  of them run in CI and in `pre-commit`. See [`SECURITY.md`](SECURITY.md) for
  the authorized-use policy and how to report a vulnerability in keyreach
  itself.

---

`v0.1.0` is the first release, and closes Phase 1. Phase 2 widens provider
coverage and adds the declarative probe format, HTML reports, and the drift
canary that watches for vendors changing the endpoints these plugins depend on.
See [`ROADMAP.md`](ROADMAP.md).

[Unreleased]: https://github.com/Phantom-IN/keyreach/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Phantom-IN/keyreach/releases/tag/v0.1.0
