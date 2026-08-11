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
| Detection patterns | **PyYAML** | Load seeded pattern DB (from secrets-patterns-db, attributed). |
| Tests | **pytest** + **respx** (+ **syrupy** for golden files) | Record/replay HTTP; snapshot reports. |
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
│   │   ├── google_aiza.py          # archetype 1  (credit: gmapsapiscanner)
│   │   ├── openai.py               # archetype 2
│   │   ├── aws.py                  # archetype 3
│   │   └── ...                     # breadth per plan.md §8
│   ├── patterns/
│   │   └── detection_rules.yml     # seeded from secrets-patterns-db (CC-BY, attributed)
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
│   ├── test_providers_*.py
│   └── test_determinism.py
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

## 5. Detection layer

Two deterministic stages, in fixed order:

1. **High-confidence structural match** — unique prefixes/formats: `sk-ant-` (Anthropic), `sk-` (OpenAI), `AKIA`/`ASIA` (AWS), `AIza` (Google), `xox[bap]-` (Slack), `ghp_`/`gho_`/`github_pat_` (GitHub), `sk_live_`/`sk_test_`/`rk_` (Stripe), `SG.` (SendGrid), `AC…`+token (Twilio), etc. Returns high confidence.
2. **Entropy + context fallback** — for generic tokens, a deterministic Shannon-entropy threshold plus surrounding-context hints (learned from detect-secrets' approach, re-implemented). Never a model.

Patterns are loaded from `patterns/detection_rules.yml`, seeded from **secrets-patterns-db** (CC-BY-4.0, attributed in `NOTICE`) and cross-checked against **gitleaks** rules (MIT). In "unknown" mode, all `detect()` run and results are ranked by (confidence, then provider name) for stable ordering. Ambiguity (e.g. a bare `AIza`) is resolved at the **enumerate** stage, not here.

---

## 6. Engine & HTTP layer

- **Concurrency:** probes within a provider run concurrently (bounded semaphore), but results are re-sorted into a deterministic order before scoring/reporting.
- **Rate limiting / delay:** global `--delay` and a bounded, deterministic retry/backoff (fixed schedule, not jittered — jitter would break reproducibility; if backoff is needed use a fixed sequence).
- **Record/replay:** the HTTP client supports a cassette mode (respx-compatible) so every provider ships fixtures and CI never needs live keys.
- **Redaction:** the client masks the key in any logged/recorded request and in evidence strings by default. Full key only surfaces with `--unmask`.
- **Read-only guard:** the client refuses non-idempotent methods (POST/PUT/PATCH/DELETE) unless a probe is explicitly annotated `read_only_post=True` for providers whose *read* endpoints require POST (e.g. some RPC-style APIs), and even then the probe must be reviewed. Default-deny.

---

## 7. Scoring implementation

Pure function: `score(capabilities: list[Capability]) -> Severity` with a rationale. Deterministic, no thresholds pulled from anything but the capability fields.

```python
def score(caps: list[Capability]) -> ScoreResult:
    if not caps:
        return ScoreResult(band="info", rationale=["no capabilities confirmed"])

    worst = max(cap.risk_weight for cap in caps)
    admin = any(c.access == AccessLevel.ADMIN for c in caps)
    write = any(c.access == AccessLevel.WRITE for c in caps)
    data  = any(c.data_sensitive for c in caps)
    cost  = any(c.incurs_cost for c in caps)
    breadth = len({c.service for c in caps})

    # deterministic banding — tune constants during Phase 1, keep them explicit
    if (admin or write) and (data or cost):
        band = "critical"
    elif data or cost or write or admin:
        band = "high"
    elif worst >= 50 or breadth >= 4:
        band = "medium"
    elif worst >= 20:
        band = "low"
    else:
        band = "info"

    rationale = build_rationale(caps, admin, write, data, cost, breadth)
    return ScoreResult(band=band, rationale=rationale)
```

`build_rationale` lists the specific capabilities that pushed the band up, so the report can show exactly why. Restriction signals (referrer/IP/app appearing to block use) are represented as a capability flag that can downgrade the band; they are explicit, not fuzzy.

Every band boundary is covered by a table-driven test (`test_scoring.py`) so tuning never silently changes verdicts.

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
- The only nondeterministic field is `generated_at`, injected via the engine and overridable in tests (fixed to a constant) so golden-file snapshots are stable.
- `test_determinism.py` runs a provider against fixtures twice and asserts byte-identical reports (timestamp fixed), and snapshot-compares against `tests/golden/`.

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
- **`ai_ban` check** — fail if any dependency or import matches a denylist of AI/LLM SDKs/endpoints, enforcing `plan.md` §1. Grep source for known model API hostnames too.
- **`network_isolation` check** — fail if any file under `providers/` imports `httpx`/`socket`/`requests` directly (probes must go through `ProbeContext`).
- **`read_only` check** — static scan flags non-idempotent HTTP methods not annotated/reviewed.
- schema drift check — regenerate `report.schema.json` and fail on diff.

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
keyreach KEY --delay 500ms        # rate-limit probes
keyreach KEY --unmask             # show full key (off by default)
keyreach KEY --fail-on high       # exit nonzero if band >= high (CI gating)
```

Exit codes: `0` success/info, `2` finding at/above `--fail-on` threshold, `1` operational error. Codes are fixed and documented.

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
