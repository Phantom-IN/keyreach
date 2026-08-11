"""OpenAI provider tests (roadmap R1.2).

R1.2's acceptance criterion: "AI-key identity/scope enumerated deterministically".
That runs end to end below, through the real engine and real cassettes.

The tests that matter most are about *not* claiming more than was confirmed. Two
in particular:

* a key that lists models is **not** shown to be able to run one, because
  OpenAI's project keys carry per-endpoint scopes;
* a key that lists organization members is **not** shown to be able to remove
  one, because OpenAI's admin keys carry per-resource scopes.

The second is the exact point where this plugin and the Anthropic plugin reach
opposite verdicts on the same shape of finding — see
``tests/test_provider_anthropic.py`` for the other half.

**On the fixtures.** They are constructed from OpenAI's published response
shapes, not recorded from a live key — keyreach's own rules forbid holding one,
and probing somebody else's would be unauthorised. That is a real limitation:
they prove the parsing and the decision rules, not that OpenAI still answers
this way. Provider API drift is a known structural risk (`plan.md` §12) and
roadmap **R2.10** is the answer to it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.openai import (
    ADMIN_PREFIX,
    COST_WINDOW_START,
    PROBES,
    OpenAIProvider,
    _error,
    _Family,
    _summary,
    family_of,
    probes_for,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal — a joined OpenAI key
#: matches keyreach's own detector and GitHub push protection, and the second
#: would reject the push (see `tools/guardrails/no_secrets.py`).
KEY = "sk-" + "proj-" + "A" * 40
ADMIN_KEY = "sk-" + "admin-" + "A" * 40
NOT_A_KEY = "sk-" + "proj-" + "A" * 3


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    """`CLAUDE.md` asks every plugin to assert this itself."""
    validate_provider(OpenAIProvider(), origin="keyreach.providers.openai")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "openai" in [provider.name for provider in registry.providers()]


def test_it_is_an_ai_provider() -> None:
    """Category drives the v0.1 "≥10 providers across ≥4 categories" measure."""
    assert OpenAIProvider().category == "ai"


def test_it_claims_no_prior_art() -> None:
    """Attribution is a hard rule; so is not claiming a debt that does not exist."""
    assert OpenAIProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(KEY, 0.99, id="project"),
        pytest.param(ADMIN_KEY, 0.99, id="admin"),
        pytest.param("sk-" + "svcacct-" + "A" * 40, 0.99, id="service-account"),
        pytest.param("sk-" + "A" * 48, 0.90, id="classic"),
        pytest.param(NOT_A_KEY, 0.0, id="too-short"),
        pytest.param("sk-" + "ant-" + "A" * 40, 0.0, id="anthropic"),
        pytest.param("pk-" + "proj-" + "A" * 40, 0.0, id="wrong-prefix"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + KEY, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert OpenAIProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = OpenAIProvider()

    assert {provider.detect(KEY) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [KEY, ADMIN_KEY])
def test_the_plugin_and_the_rule_set_agree_on_the_key_format(key: str) -> None:
    """Two places describe an OpenAI key. They must not drift apart.

    `detect()` decides which provider gets probed; the rule set decides what the
    report calls the key. If they disagreed, keyreach could name a key "openai"
    and then decline to probe it — or the reverse.
    """
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["openai"]
    assert OpenAIProvider().detect(key) > 0.0


def test_an_anthropic_key_is_not_claimed() -> None:
    """`sk-ant-` starts with `sk-`. Probing the wrong vendor wastes a request."""
    assert OpenAIProvider().detect("sk-" + "ant-" + "api03-" + "A" * 40) == 0.0


# ---------------------------------------------------------------------------
# Key families
# ---------------------------------------------------------------------------


def test_the_key_family_selects_a_disjoint_endpoint_set() -> None:
    """An admin key reaches no model endpoint, and vice versa.

    OpenAI states that admin keys cannot be used for non-administration
    endpoints. Probing both sets for every key would spend three requests
    guaranteed to return 401 against somebody's production account.
    """
    assert family_of(KEY) is _Family.PLATFORM
    assert family_of(ADMIN_KEY) is _Family.ADMIN

    platform = {probe.service for probe in probes_for(_Family.PLATFORM)}
    admin = {probe.service for probe in probes_for(_Family.ADMIN)}

    assert platform
    assert admin
    assert platform.isdisjoint(admin)
    assert platform | admin == {probe.service for probe in PROBES}


def test_the_admin_prefix_is_the_documented_one() -> None:
    assert ADMIN_KEY.startswith(ADMIN_PREFIX)


@pytest.mark.parametrize("family", list(_Family))
def test_validation_reuses_a_probe_endpoint(family: _Family) -> None:
    """One request, not two: validation is also the family's cheapest probe."""
    assert validation_probe(family) in probes_for(family)


# ---------------------------------------------------------------------------
# The happy path — R1.2's acceptance criterion
# ---------------------------------------------------------------------------


def test_a_live_platform_key_yields_a_scored_capability_map() -> None:
    result = run("openai_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "OpenAI Files",
        "OpenAI Fine-tuning Jobs",
        "OpenAI Models",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("OpenAI Files" in line for line in result.score.rationale)


def test_the_organization_is_recovered_from_the_response_header() -> None:
    """Identity, for free: an exposed key that names its own organization.

    There is no cheap "who am I" endpoint, so this comes off a header on the
    liveness check keyreach already had to make.
    """
    identity = run("openai_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "org-7Qk2Mn"


def test_a_live_admin_key_enumerates_the_administration_api() -> None:
    result = run("openai_admin", ADMIN_KEY)

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "OpenAI Organization Costs",
        "OpenAI Organization Members",
        "OpenAI Organization Projects",
    ]
    assert not any("Models" in c.service for c in result.capabilities)


# ---------------------------------------------------------------------------
# Not claiming more than was confirmed
# ---------------------------------------------------------------------------


def test_the_model_list_does_not_claim_inference() -> None:
    """keyreach never calls a model, so it cannot claim the key could.

    OpenAI project keys carry per-endpoint scopes — a "Read Only" key lists
    models and is refused everything else — so reaching `/v1/models` does not
    establish that the key can spend. Marking it `incurs_cost` would be a guess
    dressed as a finding.
    """
    models = next(
        c for c in run("openai_valid").capabilities if c.service == "OpenAI Models"
    )

    assert not models.incurs_cost
    assert "not tested" in models.detail


def test_no_probe_claims_spend() -> None:
    """The claim, stated once for the whole plugin.

    Confirming that an AI key can spend money means calling a model, which
    `plan.md` §1 forbids and `ai_ban` enforces. So this plugin never sets
    `incurs_cost`, and that under-reports the common case on purpose.
    """
    capabilities = [
        *run("openai_valid").capabilities,
        *run("openai_admin", ADMIN_KEY).capabilities,
    ]

    assert capabilities
    assert not any(capability.incurs_cost for capability in capabilities)


def test_administration_access_is_reported_as_read_not_admin() -> None:
    """The verdict that differs from the Anthropic plugin, and why.

    OpenAI admin keys carry per-resource scopes: `users.read` is a separate
    permission from `users.write`. So a key that lists organization members has
    been shown to hold the read and nothing more. Recording `ADMIN` here would
    claim a member-removal capability keyreach never confirmed.
    """
    members = next(
        c
        for c in run("openai_admin", ADMIN_KEY).capabilities
        if c.service == "OpenAI Organization Members"
    )

    assert members.access is AccessLevel.READ
    assert "Write scopes were not tested" in members.detail


def test_every_capability_is_read_only() -> None:
    assert all(c.access is AccessLevel.READ for c in run("openai_valid").capabilities)


def test_a_denied_probe_is_not_a_capability() -> None:
    """The fixture denies vector stores at 403. That must not become a finding."""
    services = [c.service for c in run("openai_valid").capabilities]

    assert "OpenAI Vector Stores" not in services

    recorded = json.loads((FIXTURES / "openai_valid.json").read_text(encoding="utf-8"))
    denied = next(i for i in recorded["interactions"] if "vector_stores" in i["url"])

    assert denied["status_code"] == 403


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_the_cost_window_is_a_constant_not_a_clock_read() -> None:
    """A relative window would change the request URL on every run.

    The costs endpoint requires a start time. Reading the clock for it would
    give two runs of the same key different URLs, different cassette keys, and
    a report that cannot be reproduced (`plan.md` §1).
    """
    costs = next(p for p in PROBES if p.service == "OpenAI Organization Costs")

    assert costs.params["start_time"] == COST_WINDOW_START
    assert COST_WINDOW_START.isdigit()


def test_repeated_runs_are_identical() -> None:
    first, second = run("openai_valid"), run("openai_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("openai_admin", ADMIN_KEY).capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


# ---------------------------------------------------------------------------
# Evidence: proves access without becoming a copy of the data
# ---------------------------------------------------------------------------


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    """A report gets pasted into a ticket. It must not carry the data with it."""
    files = next(
        c for c in run("openai_valid").capabilities if c.service == "OpenAI Files"
    )

    assert "files: 2 listed" in files.evidence
    assert "customer-list.csv" not in files.evidence
    assert "support-transcripts.jsonl" not in files.evidence


def test_evidence_never_leaks_a_member_email() -> None:
    """The org-members probe reads personal data. The evidence must not carry it."""
    members = next(
        c
        for c in run("openai_admin", ADMIN_KEY).capabilities
        if c.service == "OpenAI Organization Members"
    )

    assert "organization members: 2 listed" in members.evidence
    assert "@example.com" not in members.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("openai_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert KEY not in capability.poc


def test_the_proof_of_concept_carries_the_headers_the_probe_needed() -> None:
    """A reproduction that omits a required header does not reproduce anything."""
    vector_store = next(p for p in PROBES if p.service == "OpenAI Vector Stores")

    assert vector_store.headers == {"OpenAI-Beta": "assistants=v2"}


def test_no_committed_fixture_contains_a_key() -> None:
    """The guarantee that makes committing cassettes acceptable at all."""
    for name in ("valid", "invalid", "admin"):
        text = (FIXTURES / f"openai_{name}.json").read_text(encoding="utf-8")

        assert KEY not in text
        assert ADMIN_KEY not in text


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    """Auditability: a probe nobody can trace to a vendor page cannot be checked."""
    refs = {c.service: c.resource_ref for c in run("openai_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        if probe.service in refs:
            assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_probe_reaches_an_inference_endpoint() -> None:
    """`ai_ban` enforces this repo-wide; asserted here so the plugin owns it too."""
    for probe in PROBES:
        assert "completion" not in probe.url
        assert "response" not in probe.url
        assert "embedding" not in probe.url


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_key_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("openai_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "rejected this key as invalid" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette.

    The three committed cassettes cover the scenarios worth shipping fixtures
    for. These are the remaining branches of OpenAI's error vocabulary — codes
    keyreach must interpret but which do not warrant a whole recorded scenario.
    """

    class _Stub:
        """Minimal ProbeContext stand-in: `validate` only ever calls `get`."""

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.openai.com/v1/models",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(OpenAIProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def openai_error(
    code: str | None, kind: str = "invalid_request_error"
) -> dict[str, object]:
    return {"error": {"message": "refused", "type": kind, "param": None, "code": code}}


def test_a_quota_error_means_the_key_is_live() -> None:
    """The trap this branch exists to avoid.

    OpenAI only knows whose quota to check once it has accepted the credential,
    so a quota failure is proof of a working key. Reporting it as invalid would
    retire a key that starts working again the moment the account is topped up.
    """
    result = validate_against(429, openai_error(None, kind="insufficient_quota"))

    assert result.valid  # type: ignore[attr-defined]
    assert "billing quota is exhausted" in result.note  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "code",
    [
        "credit_balance_exhausted",
        "organization_spend_limit_exceeded",
        "organization_usage_limit_exceeded",
        "project_spend_limit_exceeded",
    ],
)
def test_every_billing_code_means_the_key_is_live(code: str) -> None:
    result = validate_against(429, openai_error(code))

    assert result.valid  # type: ignore[attr-defined]


def test_a_region_block_says_nothing_about_the_key() -> None:
    """Neither "valid" nor "invalid" is honest; the note carries the reason."""
    result = validate_against(403, openai_error("unsupported_country_region_territory"))

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_plain_rate_limit_still_means_the_key_is_live() -> None:
    result = validate_against(429, openai_error("rate_limit_exceeded"))

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_unrecognised_401_names_the_family_trap() -> None:
    """The likeliest cause of a surprising 401 is the wrong endpoint set."""
    result = validate_against(401, openai_error("invalid_organization"))

    assert not result.valid  # type: ignore[attr-defined]
    assert "invalid_organization" in result.note  # type: ignore[attr-defined]
    assert "admin key cannot reach the platform API" in result.note  # type: ignore[attr-defined]


def test_a_401_with_no_code_still_reports_a_refusal() -> None:
    result = validate_against(401, openai_error(None))

    assert not result.valid  # type: ignore[attr-defined]
    assert "did not accept this key" in result.note  # type: ignore[attr-defined]


def test_a_non_auth_refusal_with_a_code_reports_the_key_as_live() -> None:
    """Getting past authentication and then being refused means a live key."""
    result = validate_against(503, openai_error("server_error"))

    assert result.valid  # type: ignore[attr-defined]
    assert "server_error" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_identity_is_absent_when_the_header_is() -> None:
    result = validate_against(200, {"object": "list", "data": []})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Error parsing, which reads third-party payloads and must not raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="null"),
        pytest.param("a string", id="scalar"),
        pytest.param({}, id="empty"),
        pytest.param({"error": "oops"}, id="error-not-a-mapping"),
    ],
)
def test_error_parsing_degrades_instead_of_raising(payload: object) -> None:
    """A gateway's HTML error page must not crash a probe."""
    assert _error(payload) == {}


def test_a_non_string_error_code_is_ignored() -> None:
    """Third-party payloads are not schema-checked. A number here must not match."""
    result = validate_against(401, {"error": {"code": 7, "type": 7}})

    assert not result.valid  # type: ignore[attr-defined]
    assert "did not accept this key" in result.note  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"object":"list"}', "request accepted", id="no-data-key"),
        pytest.param('{"data":"x"}', "request accepted", id="data-not-a-list"),
        pytest.param('{"data":[]}', "files: none present", id="empty"),
        pytest.param('{"data":[1]}', "files: 1 listed", id="one"),
        pytest.param('{"data":[1,2]}', "files: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    files = next(p for p in PROBES if p.service == "OpenAI Files")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(files, response) == expected
