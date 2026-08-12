# keyreach — Implementation Plan

> Technical companion to `plan.md`. This document covers *how* keyreach is built: architecture, codebase structure, interfaces, determinism enforcement, testing, and build phases. Read `plan.md` first for product context and `CLAUDE.md` for the working rules while coding.

---

## 0. The determinism mandate (engineering constraints)

`plan.md` §1 requires keyreach to be fully deterministic and free of any AI/LLM calls. In engineering terms this means:

1. **No AI/LLM dependencies.** No SDK, HTTP client, or code path that sends data to a model. This is enforced by a CI check that fails the build if known LLM SDKs/endpoints appear in dependencies or source (`ai_ban` check, §11).
2. **No unseeded nondeterminism in verdicts.** No `random` in detection/enumeration/scoring, no dependence on dict/set iteration order, no wall-clock-dependent logic except the single report timestamp (which is injected, not read ad hoc, so it can be fixed in tests).
3. **Stable ordering everywhere.** Providers, capabilities, and report sections are sorted by explicit, stable keys before output.
4. **Pure verdict functions.** Detection, scoring, and report rendering are pure functions of their inputs. All network I/O is isolated in the engine's HTTP layer and is fully mockable.
5. **Reproducible output.** Same key + same recorded provider responses ⇒ byte-identical report (modulo the injected timestamp). A golden-file test enforces this.
6. **`unknown`, never guessed.** If a rule can't decide a capability, it is emitted as `AccessLevel.UNKNOWN` — the tool never infers via a model or fuzzy heuristic that isn't a written rule.

---

## 1. Tech stack

**Recommended language: Python 3.11+** — lowest barrier for community-contributed provider plugins and declarative (YAML) probes.

| Concern | Choice | Notes |
|---|---|---|
| CLI | **Typer** (Click under the hood) | Declarative commands/flags, good `--help`. |
| HTTP | **httpx** (async) | Concurrent read-only probes; single injectable client. |
| Terminal output | **rich** | Tables, colour, panels. |
| Models/validation | **pydantic v2** | Typed `Capability`/`Report` objects, JSON schema export. |
| Templating | **Jinja2** | Markdown/HTML report templates. |
| Detection patterns | **PyYAML** | Load the detection rule set (written from vendor docs — see §5 and `plan.md` §5.2). |
| Tests | **pytest** | Cassette record/replay and golden snapshots are both built in-tree (§6.1, §9.1) — respx and syrupy were declared in R0.2, never used, and removed in R0.8. |
| Packaging | **pyproject.toml**, **pipx**, PyPI | `keyreach` console script. |

**Alternative: Go** — only if a single static binary is a hard distribution requirement. Keeps the same architecture; raises the plugin-contribution barrier. Decision recorded in `plan.md` §14.

**Explicitly *not* dependencies:** any LLM/AI SDK (openai, anthropic-sdk-as-a-dependency, google-generativeai, etc.). Note the irony to avoid: keyreach *probes* these providers' endpoints with a user-supplied key, but it must never *import their SDKs to call a model*. Probes are plain `httpx` requests.

---

## 2. Architecture

```
   key(s)
     │
     ▼
┌───────────┐   deterministic pattern + entropy rules
│  DETECT   │──────────────────────────────────────────┐
└───────────┘                                           │
     │ provider id + confidence                         │
     ▼                                                   │
┌────────────────────┐        ┌──────────────────────────────┐
│  PROVIDER PLUGIN    │        │  ENGINE SERVICES (shared)     │
│  detect()           │        │  • async HTTP (rate-limited,  │
│  validate()         │◀──────▶│    recordable, redacting)     │
│  enumerate()        │        │  • retry/backoff (bounded)    │
│  metadata           │        │  • fixture record/replay      │
└────────────────────┘        └──────────────────────────────┘
     │ list[Capability]
     ▼
┌───────────┐   pure, rule-based
│  SCORING  │──────────────► severity band + rationale
└───────────┘
     │
     ▼
┌───────────┐   Jinja2 templates + pydantic → JSON
│  REPORT   │──────────────► terminal / markdown / html / json
└───────────┘
```

Plugins never touch the network directly. They **declare** probes (endpoint, method, headers, match rules); the engine **executes** them through the shared HTTP layer. This is what makes mocking, rate-limiting, redaction, and determinism enforceable in one place.

---

## 3. Repository structure

```
keyreach/
├── README.md
├── plan.md
├── implementation_plan.md
├── CLAUDE.md
├── LICENSE                         # Apache-2.0 (recommended)
├── NOTICE
├── CREDITS.md
├── THIRD_PARTY_LICENSES.md
├── CONTRIBUTING.md
├── SECURITY.md                     # responsible-use + coordinated disclosure
├── pyproject.toml
├── keyreach/
│   ├── __init__.py
│   ├── cli.py                      # Typer entrypoint
│   ├── core/
│   │   ├── models.py               # pydantic: Capability, Identity, ValidationResult, Report
│   │   ├── provider.py             # Provider base class (§4)
│   │   ├── registry.py             # plugin discovery/loading (deterministic order)
│   │   ├── detect.py               # pattern + entropy detection (§5)
│   │   ├── engine.py               # orchestration, concurrency, ordering
│   │   ├── http.py                 # rate-limited, recordable, redacting client (§6)
│   │   ├── scoring.py              # pure severity model (§7)
│   │   └── probes.py               # declarative YAML probe runner (§8)
│   ├── providers/
│   │   ├── google.py               # archetype 1  (credit: gmapsapiscanner, MIT)
│   │   ├── openai.py               # archetype 2  (no prior art; two key families)
│   │   ├── anthropic.py            # archetype 2b (no prior art; two key families)
│   │   ├── aws.py                  # archetype 3  (SigV4; blueprint: enumerate-iam, GPL — not copied)
│   │   ├── stripe.py               # payment      (access level from a documented key prefix)
│   │   ├── razorpay.py             # payment      (composite key_id:key_secret)
│   │   ├── slack.py                # comms        (200 OK can mean failure; `ok` is the verdict)
│   │   ├── twilio.py               # comms        (composite AccountSid:AuthToken, SID in the path)
│   │   ├── telegram.py             # comms        (token in the path; one capability from a response field)
│   │   ├── github.py               # devtools     (write proved from the X-OAuth-Scopes header)
│   │   └── ...                     # breadth per plan.md §8
│   ├── patterns/
│   │   └── detection_rules.yml     # written from vendor docs; nothing copied (§5)
│   └── report/
│       ├── render.py
│       ├── schema.py               # generates report.schema.json from the models
│       ├── report.schema.json      # generated from pydantic; checked in
│       └── templates/
│           ├── report.md.j2
│           └── report.html.j2
├── tests/
│   ├── fixtures/                   # recorded HTTP cassettes (NO real keys)
│   ├── golden/                     # snapshot reports for determinism tests
│   ├── test_detect.py
│   ├── test_scoring.py
│   ├── test_provider_*.py
│   └── test_determinism.py
├── tools/                          # dev tooling; NOT shipped in the wheel
│   └── guardrails/                 # workflows, ai_ban, network_isolation,
│                                   # read_only, no_secrets (§11.1)
│                                   # — run by CI, pre-commit and pytest
└── .github/workflows/
    ├── ci.yml                      # lint, types, tests, coverage, ai_ban check
    └── drift-canary.yml            # scheduled: detect provider API drift
```

---

## 4. Provider plugin contract

`keyreach/core/models.py`:

```python
from enum import StrEnum
from pydantic import BaseModel

class AccessLevel(StrEnum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    UNKNOWN = "unknown"

class Severity(StrEnum):            # plan.md §6 bands; .rank gives the ordering
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Capability(BaseModel):
    service: str                 # "Gemini Files API", "S3", "Stripe Charges"
    access: AccessLevel
    detail: str                  # "Can list uploaded files"
    evidence: str                # masked request + benign response summary (PROOF)
    risk_weight: int             # 0-100 base risk for this capability (plugin-declared)
    data_sensitive: bool = False # reaches private/user data?
    incurs_cost: bool = False    # can spend money / send messages?
    restricted: bool = False     # referrer/IP/app restriction appears to block use (§7)
    resource_ref: str | None = None
    poc: str | None = None       # safe, read-only PoC for the report

class Identity(BaseModel):
    account: str | None = None
    owner: str | None = None
    plan_or_tier: str | None = None
    extra: dict[str, str] = {}

class ValidationResult(BaseModel):
    valid: bool
    identity: Identity | None = None
    note: str = ""

class Report(BaseModel):            # contents fixed by plan.md §7; see §9
    ...
```

**Notes on the implementation (landed in R0.3).** These are decisions the sketch
above does not capture, recorded here because they are binding on every provider
plugin:

- **`StrEnum`, not `(str, Enum)`.** Python 3.11+ only. Under `(str, Enum)`,
  `str(AccessLevel.READ)` yields `"AccessLevel.READ"` rather than `"read"`,
  which would surface in rendered reports.
- **`Severity` ordering is explicit.** `Severity.rank` (0–4) defines the band
  order, and the comparison operators are overridden to use it. Inherited `str`
  comparison is lexicographic — under which `"high" > "critical"` — so
  `--fail-on` (§12, R1.5) would otherwise produce wrong exit codes.
- **All models are frozen and `extra="forbid"`.** A `Capability` cannot be
  edited after scoring has weighed it, and a mistyped field in a provider plugin
  or a YAML probe fails loudly instead of being silently dropped.
- **`Identity.extra` is `dict[str, str]`**, not a bare `dict`. Mixed value types
  serialize inconsistently; convert at the provider boundary.
- **`Report.capabilities` is sorted on construction** by
  `(service, access, detail)`. Probes complete concurrently (§6), so arrival
  order is not reproducible and no caller can be trusted to remember to sort.
- **`Report.generated_at` must be timezone-aware.** A naive datetime serializes
  without an offset, so the same run on two machines produces two different
  reports.
- **`Report.schema_version`** (currently `"1.0"`) lets a consumer of `--json`
  branch on the contract version. Bumped on any breaking shape change.

`keyreach/core/provider.py`:

```python
class Provider(ABC):
    name: str                    # "google", "openai", "aws", "stripe", ...
    category: str                # "cloud" | "ai" | "payment" | "comms" | ...
    docs_url: str
    rotation_guide_url: str | None = None
    credit: str | None = None    # upstream project this plugin derives from

    @abstractmethod
    def detect(self, key: str) -> float:
        """Pure. Confidence 0.0-1.0 that `key` belongs to this provider."""

    @abstractmethod
    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Cheapest read-only liveness + identity check."""

    @abstractmethod
    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Read-only probes mapping full scope. Must return a stably-sorted list."""
```

`ProbeContext` exposes only the sanctioned, recordable HTTP surface (`ctx.get(...)`, `ctx.post(...)`) plus config (delay, timeouts). Plugins must not import `httpx` or open sockets directly — CI forbids it (§11).

**Notes on the implementation (landed in R0.4).**

- **`Provider` is an ABC**, not a base class raising `NotImplementedError`. A plugin missing `enumerate` fails when the registry loads it, rather than halfway through probing a live key.
- **`ProbeContext` is currently an empty `Protocol`** declared in `core/provider.py`. R0.6 owns its real surface, and defines the concrete rate-limited/recording/redacting client in `core/http.py`. Declaring it now — rather than leaving the parameter untyped — means R0.6 can fill in `get`/`post` without touching a single provider signature. Being structurally empty it currently accepts any object; that is a known, temporary gap.
- **`detect()` returning `0.0` means "not mine".** The registry treats any positive confidence as a candidate worth probing, and probing the wrong provider is wasted authentication traffic against somebody's production service.

### 4.1 Registry (`keyreach/core/registry.py`)

`ProviderRegistry` scans a package for concrete `Provider` subclasses. It is parameterised by package name, so tests build registries over fixture packages instead of mutating global state; `default_registry` is the shared instance over `keyreach.providers`.

Two ordering rules keep discovery deterministic:

- **Module names are sorted before import.** `pkgutil` walks a package in filesystem order, which varies by platform and checkout.
- **Results are ordered by an explicit key.** Providers sort by `name`; detection candidates sort by descending confidence then `name`, per §5.

Also enforced:

- **Category is a closed set** — `cloud`, `ai`, `payment`, `comms`, `email`, `devtools`, `database`, `monitoring`, `auth`, `generic`. Category drives the v0.1 "≥10 providers across ≥4 categories" measure (`plan.md` §13), so a typo'd category would quietly inflate coverage. `validate_provider()` is public so plugin authors can assert their own metadata in their own tests.
- **Names must be lowercase and unique.** The name is both the registry key and the literal `--provider` value.
- **Ownership is by definition site.** Only classes whose `__module__` matches the scanned module are registered, so a provider importing another's class for reuse does not register it twice.
- **Underscore-prefixed modules are skipped**, and are the place for shared helpers.
- **`detect()`'s return value is validated at the boundary** — rejected if non-numeric, boolean (a `bool` is an `int` in Python and would rank as `1.0`), or outside `0.0`–`1.0`.

---

### 4.2 Interface acceptance checkpoint (roadmap R1.4)

Phase 0's promise was that **adding a provider touches only its own file and its fixtures**. R1.4 checked it against what actually happened, rather than against how it felt:

| Item | Provider files | Core files | Other |
| --- | --- | --- | --- |
| R1.1 Google | `google.py`, 4 fixtures, its test | none | `test_registry.py` (a test whose premise — "no plugins yet" — had expired) |
| R1.2 OpenAI + Anthropic | 2 plugins, 6 fixtures, 2 tests | none | a detection rule; an `ai_ban` **bug fix** the item exposed |
| R1.3 AWS | `aws.py`, 3 fixtures, its test | **`http.py`, `engine.py`** | a detection rule |

**The promise held twice and failed once.** The verdict is that the interface was *incomplete*, not *wrong*: all three members AWS added are generic, and AWS was merely the first provider to need them.

- **`ctx.now()`** — needed by any provider that signs requests, not only AWS. Azure SAS, GCP service-account JWTs and every HMAC-signed vendor API carry a timestamp.
- **`ctx.protect()`** — needed by any *composite* credential. Twilio's is literally `AccountSid:AuthToken` and is due in **R2.2**; MongoDB Atlas, Mailgun and Docker Hub are the same shape.
- **`ctx.aggressive`** — `plan.md` §11 required this from the beginning ("any aggressive mode is off by default, explicitly flagged"). It had simply never had anything to gate.

The test for "generic" is whether a *named, already-planned* provider needs it — not whether one can be imagined. All three pass that test.

**The probe tables are deliberately not abstracted.** Four `enumerate` methods share a shape — gather, zip, build `Capability`, sort — and differ in exactly the places that carry the reasoning: how a request is authenticated (query parameter, bearer header, `x-api-key`, SigV4), how success is decided (an HTTP status, or a Maps body saying `REQUEST_DENIED` inside a 200), which access level is justified, and whether a capability may come from a documented vendor rule rather than a probe at all. An abstraction over that needs one callback per difference, which is the same code with indirection added, and it would displace the comments that justify each decision. The real shared abstraction is the **declarative probe runner** already specified in §8 and scheduled as **R2.8**; building half of it now means building it twice.

What R1.4 built instead is `tests/test_provider_contract.py`: the contract asserted against every registered plugin, parametrised over the live registry so a plugin added later is held to it without anyone remembering. It pins metadata, `detect` purity and strictness, probe-table hygiene, that every provider has a detection rule, that a credited provider appears in `CREDITS.md` **and** in its own source, and the exact public surface of `ProbeContext` — so widening that surface again is an edit to a list somebody reviews, not a member that appears in a provider pull request and is never discussed.

**Two defects the checkpoint found by measuring instead of reading.**

1. **Every provider fetched its validation endpoint twice.** Each plugin makes its cheapest capability probe double as the liveness check, and each said in a comment that this cost "one request, not two". Counting them showed all four issuing it once in `validate` and again in `enumerate` — a whole wasted request per run against somebody's production service, which is precisely what `plan.md` §11 exists to limit. Fixed in `ProbeClient` with a per-run cache over idempotent requests rather than by threading the validation response into `enumerate`: the `Provider` signature stays untouched and every future provider gets the fix for free. `ProbeClient.requests_made` now counts what actually left, so the §11 claim is measurable rather than asserted.

2. **`httpx.URL(url, params=None)` clears the query string** rather than leaving it alone, so a probe URL carrying its own `?a=b` would have been sent without it. No shipped provider passes a pre-built query, so nothing was mis-sent — but the next one to try would have been, silently. Found because three deliberately distinct URLs collapsed into one during the request-count measurement.

Both are the argument for having a checkpoint at all: neither was visible in review, and both fell out of counting.

---

## 5. Detection layer

Two deterministic stages, in fixed order:

1. **High-confidence structural match** — unique prefixes/formats: `sk-ant-` (Anthropic), `sk-` (OpenAI), `AKIA`/`ASIA` (AWS), `AIza` (Google), `xox[bap]-` (Slack), `ghp_`/`gho_`/`github_pat_` (GitHub), `sk_live_`/`sk_test_`/`rk_` (Stripe), `SG.` (SendGrid), `AC…`+token (Twilio), etc. Returns high confidence.
2. **Entropy + context fallback** — for generic tokens, a deterministic Shannon-entropy threshold plus surrounding-context hints (learned from detect-secrets' approach, re-implemented). Never a model.

Patterns are loaded from `patterns/detection_rules.yml`. In "unknown" mode, all `detect()` run and results are ranked by (confidence, then provider name) for stable ordering. Ambiguity (e.g. a bare `AIza`) is resolved at the **enumerate** stage, not here.

**Pattern provenance (settled in R0.5).** This section originally read "seeded from secrets-patterns-db (CC-BY-4.0, attributed in `NOTICE`)". Verifying that license from the upstream repository showed it is **CC-BY-SA-4.0**, and that the database self-declares the inclusion of AGPL TruffleHog data without per-rule provenance — see `plan.md` §5.2 for the full finding. Patterns are therefore written from **vendor documentation**, and every rule carries a `source` URL so it can be re-verified. `gitleaks` (MIT) remains a behavioural cross-check with nothing copied.

**Notes on the implementation (landed in R0.5).**

- Rules are **anchored** (`^...$`). keyreach receives one key, not a corpus, so an unanchored pattern matching a key embedded in a longer string is a false positive rather than a feature.
- Rules load **sorted by `id`**, so reordering the YAML cannot change behaviour, and ids must be unique because they break ranking ties.
- Overlapping prefixes are disambiguated **in the pattern**, not by rule order: the OpenAI rule uses a negative lookahead to exclude `sk-ant-` (Anthropic) and OpenAI's own more specific prefixes. Relying on iteration order would make correctness depend on file layout.
- A malformed regex or duplicate id fails at **load time**, not mid-scan.
- **Entropy stage.** Shannon entropy alone is a poor detector — English prose scores *higher* than a hex digest — so it runs behind gates that first establish token shape: minimum length 20, a credential charset, rejection of path/URL shapes, and a required digit and letter. It runs only when no structural rule matched, always yields `provider=None` (it cannot attribute), and carries a flat low confidence because the signal says "looks like a secret", never whose.

---

## 6. Engine & HTTP layer

- **Concurrency:** probes within a provider run concurrently (bounded semaphore), but results are re-sorted into a deterministic order before scoring/reporting.
- **Rate limiting / delay:** global `--delay` and a bounded, deterministic retry/backoff (fixed schedule, not jittered — jitter would break reproducibility; if backoff is needed use a fixed sequence).
- **Record/replay:** the HTTP client supports a cassette mode so every provider ships fixtures and CI never needs live keys.
- **Redaction:** the client masks the key in any logged/recorded request and in evidence strings by default. Full key only surfaces with `--unmask`.
- **Read-only guard:** the client refuses non-idempotent methods (POST/PUT/PATCH/DELETE) unless a probe is explicitly annotated `read_only_post=True` for providers whose *read* endpoints require POST (e.g. some RPC-style APIs), and even then the probe must be reviewed. Default-deny.

### 6.1 Notes on the implementation (landed in R0.6)

`keyreach/core/http.py` holds `mask_key`, `Redactor`, `ProbeResponse`, `Cassette`, `ProbeClient` and `ProbeContext`. `keyreach/core/engine.py` holds `Engine`, which produces an `EngineResult` (not yet a `Report` — that is R0.8).

- **Redaction substitutes a fixed placeholder `<key>`, not the display mask.** `mask_key` preserves the first four and last three characters, which is right for a report header where a recipient wants to identify *which* key — but it makes every derived string key-specific, so a cassette recorded with one key would never replay against another. Committed fixtures would then only work for whoever recorded them. `mask_key` is therefore used for `Report.key_fingerprint` only; everything else — URLs, headers, bodies, cassettes, evidence — gets the constant.
- **Credential headers are dropped wholesale**, not pattern-replaced. The redactor only knows the key under test; a second bearer token or a session cookie has no registered secret and would otherwise survive into a committed cassette.
- **Header names are lower-cased and sorted.** Servers disagree about casing, so preserving it would make a provider's header lookup depend on which server answered.
- **Cassettes** are JSON, keyed by `(method, redacted URL)`, written sorted with no timestamp. Duplicate keys are rejected: read-only probes are idempotent, so two answers for one request means the recording is wrong. A valid key and an invalid key need **separate cassettes**, because redaction maps both to the same recorded URL.
- **Replay opens no socket at all** — no `httpx.AsyncClient` is constructed in replay mode. Not opening a socket is a stronger guarantee than intending not to use one.
- **A provider that raises degrades only its own outcome.** Errors are collected onto `ProviderOutcome.errors` so a report can distinguish "no capability" from "could not determine".
- **Probe breadth is capped** (`MAX_PROVIDERS_PROBED`). Detection can return several candidates for an ambiguous prefix; probing all of them is authentication traffic against services the key almost certainly does not belong to.
- **`ProbeResponse.json_body()`**, not `json()` — `BaseModel.json` is pydantic's own deprecated serializer, and overriding it would make the same call mean two different things.
- **Three hooks were added in R1.3**, all because AWS is the first credential that does not fit the single-bearer-token shape. Each is on `ProbeContext`, so nondeterminism control stays in the engine and a plugin only consumes it:
  - **`ctx.now()`** — a UTC clock, injectable on `Engine(clock=...)`. AWS SigV4 refuses a request whose timestamp is minutes stale, so there is no way to authenticate without one. This is not a determinism violation for the same reason pacing is not: `plan.md` §1 forbids time-dependent *verdicts*, and a signature timestamp reaches a request header and stops there. Because AWS signs in the `Authorization` header rather than the query string, the timestamp never enters a cassette key either — a fixture recorded once replays forever. `tests/test_provider_aws.py` proves the point by running the same cassette under clocks five years apart and asserting byte-identical output.
  - **`ctx.protect(secret)`** — registers a further secret with the redactor. A composite credential (`AKIA…:secret:token`) is seeded whole, which would not mask a response echoing back only the access key ID, and `iam:ListAccessKeys` does exactly that.
  - **`ctx.aggressive`** — set from `Engine(aggressive=False)`, surfaced as `--aggressive` in R1.5. Off by default, always (`plan.md` §11).
- **A plugin still must not read the clock itself.** `ctx.now()` is the one sanctioned route and exists for request signing; anything it returns reaching a capability, a severity or a report is a bug.
- **Idempotent requests are answered once per run** (R1.4). `ProbeClient` caches `GET`/`HEAD`/`OPTIONS` responses keyed exactly as a cassette is, `(method, redacted URL)`. This is sound for the reason the cassette layer already assumes — keyreach's probes are idempotent reads, so two identical requests in one run must give the same answer, and `Cassette.load` rejects a recording that says otherwise. `read_only_post` probes are **not** cached: POST is a read there by argument and review, not by HTTP semantics. `ProbeClient.requests_made` counts what actually left, so `plan.md` §11's "minimal probe counts" is a measurable claim rather than an asserted one; R1.5 can show it to the user.

---

## 7. Scoring implementation

Pure function: `score(capabilities: Sequence[Capability]) -> ScoreResult`, holding the band and the rationale for it. Deterministic, with no threshold pulled from anything but the capability fields. `keyreach/core/scoring.py`; `ScoreResult` lives there rather than in `models.py`, because it is an internal handoff and not part of the published report schema — `Report.severity` and `Report.severity_rationale` are the schema, and `ScoreResult`'s fields are named to match so R0.8 copies them across without translating.

```python
def _band(signals: _Signals) -> Severity:
    if signals.privileged_and_valuable:          # per capability, see below
        return Severity.CRITICAL
    if signals.data_sensitive or signals.incurs_cost or signals.privileged:
        return Severity.HIGH
    if (signals.worst_risk_weight >= MEDIUM_RISK_WEIGHT
            or signals.breadth >= BROAD_SERVICE_COUNT):
        return Severity.MEDIUM
    if signals.worst_risk_weight >= LOW_RISK_WEIGHT:
        return Severity.LOW
    return Severity.INFO
```

Constants are named, never inlined: `MEDIUM_RISK_WEIGHT = 50`, `LOW_RISK_WEIGHT = 20`, `BROAD_SERVICE_COUNT = 4`, `MAX_CITED_CAPABILITIES = 5`. Each is a published verdict boundary, so retuning one is a visible, reviewed change.

### 7.1 Notes on the implementation (landed in R0.7)

- **The Critical test applies to one capability, not to the set.** This section previously sketched it as `(admin or write) and (data or cost)` evaluated with separate `any()` calls across all capabilities — which rates a key Critical when one capability writes to something harmless and a *different* capability reads something sensitive. Neither of those is "write access to sensitive data" (`plan.md` §6), and a Critical filed on that basis falls apart as soon as a triager reads the capability map beside it. Critical now requires a **single** capability that is both privileged and valuable. The High test is unchanged, because each of its disjuncts is a single field and `any()` over the set is the correct reading.
- **`AccessLevel.UNKNOWN` never satisfies the privileged test.** keyreach cannot claim a write it did not confirm, so an undetermined access level cannot reach Critical. It still counts toward breadth and risk weight, and it always adds a rationale line stating the band may understate real impact — "not determined" is not "harmless" (`core/models.py`).
- **Restrictions downgrade by exactly one band, and only when every capability is restricted.** `Capability.restricted` is the explicit flag §4 now carries. A referrer check on one of five reachable services does not shrink the blast radius, so a partial restriction changes nothing. And keyreach observes only that a restriction *appears* to be in force — HTTP referrer and IP restrictions are routinely bypassed by sending the header the check expects, which is why `plan.md` §6 places "restricted-but-bypassable" at Medium rather than dismissing it. Collapsing a live payment key to Info on the strength of a spoofable header would be the worst error this function could make. The downgrade never underflows below Info.
- **The rationale cites each capability once, under the strongest reason that applies.** Otherwise a Stripe charge capability appears on three lines — privileged-and-valuable, spending, and write — and one finding reads as three.
- **The risk-weight line is emitted only when weight actually reached the band.** A breadth-driven Medium citing "0/100" would argue against its own verdict. Checked against the threshold rather than inferred from the band, because the band reaching the rationale builder is the one *after* any restriction downgrade.
- **Citations are bounded** at `MAX_CITED_CAPABILITIES` and taken in `sort_key` order, so the truncation is reproducible and a key with sixty capabilities does not produce a sixty-item sentence. The full list is in the capability map beside it.
- **`Engine`/`EngineResult.score` is a property, not a stored field.** Scoring is pure, so recomputing it can never disagree with the capabilities it derives from, whereas a stored band could be left stale.

Every band boundary is covered by a table-driven test (`tests/test_scoring.py`) so tuning never silently changes verdicts, along with input-order independence and repeated-run equality — R0.7's acceptance criterion.

---

## 8. Declarative probe format (optional but preferred)

To lower contribution cost and keep probes auditable, simple providers can be expressed as YAML rather than Python, executed by `core/probes.py`:

```yaml
# providers/google_aiza.yml  (illustrative)
service: "Gemini Files API"
request:
  method: GET
  url: "https://generativelanguage.googleapis.com/v1beta/files?key={KEY}"
match:
  success:
    status: 200
  capability:
    access: read
    detail: "Can list files uploaded to the Gemini project"
    risk_weight: 70
    data_sensitive: true
    incurs_cost: true
    poc: 'curl "https://generativelanguage.googleapis.com/v1beta/files?key=<KEY>"'
```

The runner substitutes `{KEY}`, executes via the shared recordable client, and emits a `Capability` on match. Complex logic (chained calls, identity parsing) falls back to Python plugins. Match rules are strict and rule-based — status codes, header presence, JSON field presence — never model-judged.

---

## 9. Reporting implementation

- pydantic `Report` model → `report.schema.json` (checked in; regenerated in CI and diffed). Generated by `keyreach/report/schema.py`: `python -m keyreach.report.schema --write` regenerates it, `--check` exits non-zero when it is stale. Schema descriptions come from `Field(description=...)` and each model's `json_schema_extra`, never from class docstrings — a published contract should not carry internal `plan.md` cross-references, and decoupling them stops a reworded docstring from looking like a breaking schema change.
- Jinja2 templates for Markdown and HTML; a `rich`-rendered terminal view.
- The only nondeterministic field is `generated_at`, injected at the outermost boundary and overridable in tests (fixed to a constant) so golden-file snapshots are stable.
- `test_determinism.py` runs a provider against fixtures twice and asserts byte-identical reports (timestamp fixed), and snapshot-compares against `tests/golden/`.

### 9.1 Notes on the implementation (landed in R0.8)

`keyreach/report/build.py` assembles a `Report` from an `EngineResult`; `keyreach/report/render.py` renders one to terminal text, JSON or Markdown. HTML remains R2.9 — the Jinja loader already selects autoescaping by extension, so the HTML template will be escaped without anyone having to remember.

- **`generated_at` is a parameter of `build_report`, not something the engine stamps.** §9 previously said "injected via the engine". Passing it in instead keeps `EngineResult` timestamp-free — which is what lets `test_engine.py` assert double-run equality on the engine's own output — and makes every stage below the CLI a pure function of its inputs. The clock is read exactly once, at the outermost boundary, by the CLI in R1.5.
- **`Report.notes` is new.** R0.6 collects probe errors specifically so a report can distinguish "no capability" from "could not determine", and `plan.md` §7's nine contents had nowhere to put them. Without this field, a run where three probes failed renders identically to one where three probes found nothing.
- **Status has three values, not two.** `ValidationResult.valid` is a bool, so a key nothing was ever asked about is indistinguishable from one a provider rejected. Those are different claims to put in front of a security team, so `render.status_label` reports `valid` / `not valid` / `not probed`, the last keyed on the report naming provider `unknown`.
- **A live provider outranks a more confident dead one.** Detection guesses; a provider that answered knows. Ties fall back to the engine's ordering (confidence, then name).
- **The timestamp is spelled one way everywhere.** pydantic renders a UTC datetime as `…Z` while `datetime.isoformat()` gives `…+00:00`; a field serializer on `Report` pins the second so a JSON report and a Markdown report of the same run cannot look like they disagree.
- **Terminal width is a parameter and colour is off by default.** `rich` otherwise wraps to `COLUMNS`, which would render the same finding differently on two machines. Plain output additionally has trailing whitespace stripped — `rich` pads table cells, and the repo's `trailing-whitespace` hook would rewrite any golden file containing that padding. Coloured output is left alone, because a trailing run of spaces is what paints a background style.
- **Goldens are plain checked-in files**, not a snapshot library: a reviewer reads the actual report in the pull-request diff. `tests/golden/*.md` is linted by the repo's own markdownlint configuration, so the disclosure artifact is valid Markdown. Regenerate with `python -m tests.regenerate_goldens` — deliberately a separate entrypoint, mirroring `python -m keyreach.report.schema --write`, so `pytest` can never rewrite its own expectation.
- **JSON is validated by round-tripping through `Report`** rather than against `report.schema.json` with a JSON Schema library. The schema is generated from that model and pinned by the drift check, so the chain is already closed — and a security tool should not take a dependency it does not need.

---

## 10. Testing strategy

- **No live keys in CI.** All provider tests use recorded cassettes in `tests/fixtures/`. Document a maintainer flow to record new cassettes with throwaway keys, with an automated scrub step that strips real secrets before commit.
- **Detection tests:** table-driven sample keys → expected provider + confidence band.
- **Scoring tests:** capability sets → expected band + rationale, covering every boundary.
- **Provider tests:** each provider validated against its cassette for both valid and invalid/expired key responses.
- **Redaction tests:** assert keys never appear unmasked in output/evidence without `--unmask`.
- **Determinism tests:** golden snapshots + double-run byte-equality.
- **Drift-canary (`drift-canary.yml`, scheduled):** probe a small set of *maintainer-owned* canary/test endpoints per provider and open an issue automatically if response shape changes. This is the structural defense against the drift that erodes recipe-based tools.

---

## 11. CI & guardrails

`ci.yml` gates every PR:
- lint (ruff) + format (black) + types (mypy).
- pytest with coverage threshold.
- **`ai_ban` check** — fail if any dependency or import matches a denylist of AI/LLM SDKs, or if any source file references a model *inference endpoint*, enforcing `plan.md` §1.
- **`network_isolation` check** — fail if any file under `providers/` imports `httpx`/`socket`/`requests` directly (probes must go through `ProbeContext`).
- **`read_only` check** — static scan flags non-idempotent HTTP methods not annotated/reviewed.
- **`no_secrets` check** — keyreach's own detector over the repository.
- **`workflows` check** — the CI definition itself must parse, its expressions must use GitHub's syntax, and every `needs:` must name a job that exists.
- drift checks — regenerate `report.schema.json` and the golden reports, and fail on diff.

### 11.1 Notes on the implementation (landed in R0.9)

The five checks are Python modules under `tools/guardrails/`, not shell inlined in the workflow. Each exposes `check() -> list[Violation]` and a `main()`, so one implementation runs as a CI job, as a pre-commit hook, and under `pytest`. `tools/` is outside the distributed package: a user installing keyreach gets a key analyser, not a linter.

- **Every guardrail is unit-tested by planting the violation it exists to catch.** This is the whole point rather than a nicety. R0.6 found ruff's `banned-api` rule had been *silently inert since R0.2* — configured, parsed, and applied to nothing — while three pull requests asserted it was enforcing; R0.8 found an ad-hoc secret scan that enumerated the wrong set of files and reported a clean result it had not earned. `tests/test_guardrails.py` plants an AI SDK, a direct socket under `providers/`, and a non-idempotent probe, and asserts each is caught. Negative controls matter equally: a check that rejects valid code gets switched off.
- **`ai_ban` bans inference endpoints, not provider hostnames.** §11 previously said "grep source for known model API hostnames too". That rule would make **R1.1 and R1.2 impossible**: enumerating what an exposed Gemini or OpenAI key can reach *is the product*, and doing so means writing `https://api.openai.com/v1/models` into a provider plugin. The distinction that matters is not which host is named but what is asked of it — listing models is a read-only capability probe, `POST /v1/chat/completions` is inference. A test pins both halves. See also `plan.md` §1, which now states the line in product terms.
- **`ai_ban`'s endpoint paths carry no API version** (corrected in R1.2). They read `/v1/chat/completions` as shipped, which made the check blind to the convention every provider plugin here follows: a plugin declares `API = "https://api.openai.com/v1"` and composes probes from it, so the line that would call a model reads `f"{API}/chat/completions"` and contains no version. Planting that line during R1.2 produced a clean report from a guardrail whose entire purpose is to catch it — the third time a check in this repository has been believed to work and did not. Fragments are matched with a trailing boundary so `/complete` does not fire on `/completed`, and a following `/` still matches so a sub-resource of a banned endpoint is caught rather than excused.
- **`ai_ban` and `network_isolation` walk the AST**, so an import inside a function body is caught, and they resolve `importlib.import_module("httpx")`, which no import-based linter sees.
- **`network_isolation` is an independent implementation, not a wrapper around the ruff rule.** Two mechanisms sharing an implementation share its failure. A test proves the independence by planting a dynamic import, running ruff over it (which passes cleanly), and asserting this check still rejects it.
- **The provider fixture packages under `tests/` are held to the same rules as real plugins.** A fixture permitted to do what a plugin may not stops proving anything.
- **Coverage threshold is 100**, over `keyreach` *and* `tools`. Set at the level the suite already meets, because a threshold below where a project sits only ratchets downward. It is not a claim that coverage implies correctness — it is a claim that an untested line should be a deliberate, argued `pragma: no cover`.
- **The test matrix covers 3.11, 3.12 and 3.13**, every version the package's classifiers claim. A claim nothing tests is a claim, not a fact.
- **A `package` job installs the built wheel into a clean environment and exercises it from outside the source tree.** keyreach reads three files at run time that are easy to omit from a wheel — the detection rules, the report schema, and the Markdown template — and each works perfectly from a checkout while failing for an installed user.
- **A workflow that does not parse cannot run the checks that would have caught it.** R0.9's first push failed with a single annotation and no jobs: `ci.yml` used `join(needs.*.result, " ")`, and GitHub's expression language has no double-quoted string literal, so the whole file was rejected. Nothing in the repository could have caught it, because everything that would have runs *inside* that workflow. `guardrails/workflows.py` breaks the circularity by running as a pre-commit hook. It is deliberately narrow — `actionlint` is the thorough tool, and would be the right answer if a Go binary were acceptable in the toolchain — and checks only what invalidates a file wholesale.
- **Expression output goes into an environment variable, never into a shell command.** GitHub substitutes `${{ }}` textually before the shell parses anything, so interpolating it into a script is a script injection waiting for the right input.
- **One `ci` anchor job aggregates the rest**, so branch protection needs a single required check. Adding a job does not then require editing branch protection to make it blocking — a gap that is easy to create and invisible once created. It treats `skipped` as failure, since a skipped required job must not read as a pass.

---

## 12. CLI specification

```
keyreach KEY                      # detect → validate → enumerate → score → terminal report
keyreach KEY --report md -o out.md
keyreach KEY --report html -o out.html
keyreach KEY --json               # machine-readable, schema-validated
keyreach -f keys.txt              # batch from file
cat keys.txt | keyreach -         # batch from stdin
keyreach KEY --provider google    # force provider, skip detection
keyreach KEY --no-enumerate       # validity + identity only
keyreach KEY --aggressive         # opt-in noisy enumeration; off by default, warned
keyreach KEY --delay 500ms        # rate-limit probes
keyreach KEY --unmask             # show full key (off by default)
keyreach KEY --fail-on high       # exit nonzero if band >= high (CI gating)
keyreach KEY -o out.md            # write the report to a file
keyreach KEY --quiet              # suppress the banner and warnings
```

Exit codes: `0` success/info, `2` finding at/above `--fail-on` threshold, `1` operational error. Codes are fixed and documented.

**AWS takes a composite credential** (R1.3). Every other provider authenticates with one string; AWS signs each request with an access key ID *and* a secret access key, plus a session token for temporary credentials, so the CLI accepts them colon-joined: `keyreach 'AKIA…:<secret>'`, or `'ASIA…:<secret>:<session token>'`. A bare access key ID is still detected and reported — recognising one in a leak is useful — but it cannot be probed, and validation says which half is missing rather than reporting the credential as dead.

---

### 12.1 Notes on the implementation (landed in R1.5)

- **stdout is the report; stderr is everything else.** The banner, the aggressive-mode warning, the unmask warning and every error go to stderr, so `keyreach KEY --json | jq` works and `keyreach KEY --report md > finding.md` writes a file containing nothing but the finding. A tool that decorates its own machine-readable output cannot be piped.
- **The exit-code contract is enforced, not inherited.** Click exits `2` on a malformed command line and keyreach's `2` means "a finding at or above `--fail-on`" — the same number for "your CI config has a typo" and "this key is Critical", in the one place these codes are read by a machine. The console script therefore points at `keyreach.cli.run`, not at the typer app: `run` is a total mapping from whatever click exited with onto `0`/`1`/`2`, and a finding is signalled internally with a code click never produces. It is built on the exit code rather than on exception types **because typer vendors its own copy of click**, so `except click.UsageError` — imported from the real package — names a class that is never raised and catches nothing. That was written first, and it looked correct.
- **The clock is read exactly once, at this boundary.** Every stage below the CLI is a pure function of its inputs; `generated_at` is stamped here and passed down (§9.1).
- **A single key yields a JSON object; a batch yields an array.** The shape follows the *invocation*, not the number of keys, so a script written against `--file` keeps working on the day that file contains exactly one key. Inferring it from `len(reports)` was the first implementation and a test caught it.
- **Blank lines and `#` comments are skipped in a key file; duplicates are kept.** A scanner's output can be fed in unedited, and a batch never silently scans fewer things than it was asked to.
- **`--json` and `--report` are the same setting spelled two ways, so a contradiction is an error** rather than a precedence rule nobody remembers. Letting one silently win is how a user ends up with Markdown in a file they told keyreach to fill with JSON.
- **`--provider` records that it was used.** A capability map produced by forcing a provider rests on the operator's claim rather than on a rule, and `Report.notes` says so — a reader cannot otherwise tell an assertion from a verdict.
- **Colour is emitted only for a real terminal**: terminal format, no `-o`, and `stdout.isatty()`. ANSI escapes in a pipe or a file are noise that breaks diffing.
- **The banner is plain ASCII**, printed to stderr, and carries the authorized-use reminder `plan.md` §11 asks for. Box-drawing characters become mojibake over ssh, in a Windows console, and in CI log viewers. A test asserts `banner().isascii()` — which failed the first time, because the tagline separators were `·`.

---

## 13. Build phases & milestones

### Phase 0 — Spike (prove the abstraction)
- `core/` skeleton: models, provider base, registry, detect, engine, recordable/redacting HTTP client, scoring.
- **Three archetype providers**, chosen to stress the interface:
  1. **Google `AIza`** — multi-service enumeration incl. Gemini (endpoint list derived from gmapsapiscanner, credited).
  2. **OpenAI or Anthropic** — identity + model list + billing/tier.
  3. **AWS** — `sts get-caller-identity` + read-only permission inference.
- Terminal + JSON output; deterministic scoring.
- **Acceptance:** adding the third provider touched only its own file + a fixture. If not, refactor the interface before proceeding. Determinism test green.

### Phase 1 — MVP (public v0.1)
- 10–15 providers weighted to AI/LLM + high-leak cloud/payment/comms (per `plan.md` §8).
- Detection seeded from secrets-patterns-db (attributed) + gitleaks cross-check.
- Full deterministic severity model with rationale.
- Markdown report + `report.schema.json`.
- `CONTRIBUTING.md` provider template + checklist.
- Governance docs complete.

### 13.1 Notes on the v0.1 release (landed in R1.6)

**Shipped: ten providers across five categories.** `google`, `aws` (cloud);
`openai`, `anthropic` (AI); `stripe`, `razorpay` (payment); `slack`, `twilio`,
`telegram` (comms); `github` (devtools). The measure is asserted in
`tests/test_provider_contract.py`, not counted at release time — it had been
published in `README.md`, `plan.md` and `ROADMAP.md` since R0.1 with nothing
checking it, and this repository has twice found an unchecked claim to be false.

**"Detection seeded from secrets-patterns-db" above is superseded** by R0.5:
that database is CC-BY-SA-4.0 and self-declares AGPL content, so nothing was
copied and every rule is written from vendor documentation. Left in place rather
than edited out, because the trail from plan to correction is the point.

**Three findings from adding six providers at once**, all of which shaped the
result:

1. **A vendor sentence is the only thing that upgrades a read into a write.**
   Stripe publishes that a secret key "has unrestricted permissions on all
   Stripe APIs", so `sk_` capabilities are `admin`; Razorpay and Twilio very
   probably issue unscoped credentials too, but neither documents it, so both
   stop at `read` and say which claim they declined. That asymmetry looks like
   an inconsistency in the output and is in fact the rule working — the same
   rule that already produced opposite verdicts for OpenAI and Anthropic admin
   keys in R1.2.
2. **A capability need not come from a probe.** `telegram` records group-message
   reach from `getMe`'s `can_read_all_group_messages` field, and `github`
   derives access levels from the `X-OAuth-Scopes` response header. Both are
   documented vendor statements read out of a response keyreach already had, so
   neither costs a request — and `github`'s is matched **per resource**, because
   `repo` grants write over repositories and nothing over organizations.
   Applying one token-wide access level would over-report in exactly the way
   §7.1 refuses.
3. **The interface needed nothing.** Six providers, three of them composite
   credentials, and no change to `keyreach/core/`. R1.4 justified `protect()` by
   naming a provider that did not exist yet; Twilio, Razorpay and Telegram all
   needed it and needed nothing more.

### Phase 2 — Depth
- HTML reports; `--batch`; YAML declarative probes for simple providers; opt-in aggressive AWS-style enumeration (gated + warned); `--fail-on` CI gating.

### Phase 3 — Ecosystem
- Consume TruffleHog/gitleaks/Nosey Parker output (they find, keyreach analyzes + reports); GitHub Action; curated provider registry; drift-canary reporting.

---

## 14. First concrete tasks for the implementing agent

1. Scaffold the repo (§3); add `LICENSE` (Apache-2.0), `NOTICE`, `CREDITS.md` (pre-populated from `plan.md` §5.6), `SECURITY.md`, `CONTRIBUTING.md`, `pyproject.toml` with the stack in §1 and **no AI/LLM deps**.
2. Implement `core/models.py`, `core/provider.py`, `core/registry.py`, `core/http.py` (rate-limit + record/replay + redaction + read-only guard), `core/detect.py`, `core/engine.py`, `core/scoring.py`.
3. Wire the CI guardrails in §11 *before* adding providers, so `ai_ban`/`network_isolation`/`read_only` are enforced from the start.
4. Implement the three archetype providers (§13) with recorded fixtures and tests, including the determinism/golden tests.
5. Implement terminal + JSON + Markdown reporting with `report.schema.json`.
6. Seed `patterns/detection_rules.yml` from secrets-patterns-db (attributed) + gitleaks.
7. Verify Phase 0 acceptance, then proceed to Phase 1 breadth.

> Enforce continuously: no AI/LLM anywhere, read-only by default, keys masked by default, deterministic/stable output, third-party licenses verified and credited.
