"""Anthropic provider tests (roadmap R1.2).

R1.2's acceptance criterion: "AI-key identity/scope enumerated deterministically".
That runs end to end below, through the real engine and real cassettes.

The test that carries the most weight here is
``test_admin_access_is_reported_as_admin_because_console_keys_are_unscoped``. It
is the other half of a pair: on what looks like the same finding, this plugin
records ``ADMIN`` and the OpenAI plugin records ``READ``. Neither is a judgement
about which vendor is riskier — each traces to a sentence in that vendor's own
documentation about whether its admin keys can be scoped. See
``tests/test_provider_openai.py`` for the other half.

**On the fixtures.** They are constructed from Anthropic's published response
shapes, not recorded from a live key — keyreach's own rules forbid holding one,
and probing somebody else's would be unauthorised. That is a real limitation:
they prove the parsing and the decision rules, not that Anthropic still answers
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
from keyreach.providers.anthropic import (
    ADMIN_PREFIX,
    API_VERSION,
    COST_WINDOW_START,
    PROBES,
    AnthropicProvider,
    _error_type,
    _Family,
    _organization,
    _summary,
    family_of,
    probes_for,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal — a joined Anthropic key
#: matches keyreach's own detector and GitHub push protection, and the second
#: would reject the push (see `tools/guardrails/no_secrets.py`).
KEY = "sk-" + "ant-" + "api03-" + "A" * 40
ADMIN_KEY = "sk-" + "ant-" + "admin01-" + "A" * 40
NOT_A_KEY = "sk-" + "ant-" + "A" * 3


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
    validate_provider(AnthropicProvider(), origin="keyreach.providers.anthropic")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "anthropic" in [provider.name for provider in registry.providers()]


def test_it_is_an_ai_provider() -> None:
    assert AnthropicProvider().category == "ai"


def test_it_claims_no_prior_art() -> None:
    assert AnthropicProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(KEY, 0.99, id="api-key"),
        pytest.param(ADMIN_KEY, 0.99, id="admin-key"),
        pytest.param(NOT_A_KEY, 0.0, id="too-short"),
        pytest.param("sk-" + "proj-" + "A" * 40, 0.0, id="openai"),
        pytest.param("sk-" + "ant-" + "!" * 40, 0.0, id="wrong-charset"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + KEY, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert AnthropicProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = AnthropicProvider()

    assert {provider.detect(KEY) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [KEY, ADMIN_KEY])
def test_the_plugin_and_the_rule_set_agree_on_the_key_format(key: str) -> None:
    """Two places describe an Anthropic key. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["anthropic"]
    assert AnthropicProvider().detect(key) > 0.0


# ---------------------------------------------------------------------------
# Key families
# ---------------------------------------------------------------------------


def test_the_key_family_selects_a_disjoint_endpoint_set() -> None:
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
    result = run("anthropic_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Claude Files",
        "Claude Models",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("Claude Files" in line for line in result.score.rationale)


def test_a_live_admin_key_is_critical_and_names_its_organization() -> None:
    """The finding this provider exists to produce well.

    An exposed Console admin key can list members, read spend, and — because
    such keys are unscoped — remove people and deactivate keys. Critical is not
    a flourish here; it is what the capability map justifies.
    """
    result = run("anthropic_admin", ADMIN_KEY)

    assert result.valid
    assert result.score.severity is Severity.CRITICAL
    assert [capability.service for capability in result.capabilities] == [
        "Claude Cost Report",
        "Claude Organization",
        "Claude Organization API Keys",
        "Claude Organization Members",
    ]

    identity = result.outcomes[0].validation.identity
    assert identity is not None
    assert identity.account == "3f2a91c4-77b6-4e18-9d21-6c5e4a0b8d33"
    assert identity.extra == {"organization_name": "Northwind Analytics"}


def test_an_admin_key_reaches_no_model_endpoint() -> None:
    services = [c.service for c in run("anthropic_admin", ADMIN_KEY).capabilities]

    assert "Claude Models" not in services


# ---------------------------------------------------------------------------
# The verdict that differs from the OpenAI plugin
# ---------------------------------------------------------------------------


def test_admin_access_is_reported_as_admin_because_console_keys_are_unscoped() -> None:
    """The rule, and its source, in one test.

    Anthropic documents that Claude Console admin keys "do not have selectable
    scopes; every key carries full access to all endpoints that accept Admin API
    keys" — and those endpoints include removing organization members. So the
    write follows from the read by the vendor's own access model, not by
    inference. OpenAI's admin keys *are* scoped, which is why the OpenAI plugin
    records READ for the same shape of probe.
    """
    members = next(
        c
        for c in run("anthropic_admin", ADMIN_KEY).capabilities
        if c.service == "Claude Organization Members"
    )

    assert members.access is AccessLevel.ADMIN
    assert members.data_sensitive
    assert "remove them" in members.detail


def test_platform_capabilities_stay_read() -> None:
    """Only the Admin API family gets the elevated access level."""
    assert all(
        c.access is AccessLevel.READ for c in run("anthropic_valid").capabilities
    )


def test_the_model_list_does_not_claim_inference() -> None:
    """keyreach never calls a model, so it cannot claim the key could."""
    models = next(
        c for c in run("anthropic_valid").capabilities if c.service == "Claude Models"
    )

    assert not models.incurs_cost
    assert "not tested" in models.detail


def test_no_probe_claims_spend() -> None:
    """Confirming spend on an AI key means calling a model. keyreach will not."""
    capabilities = [
        *run("anthropic_valid").capabilities,
        *run("anthropic_admin", ADMIN_KEY).capabilities,
    ]

    assert capabilities
    assert not any(capability.incurs_cost for capability in capabilities)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_the_cost_window_is_a_constant_not_a_clock_read() -> None:
    """A relative window would change the request URL on every run."""
    report = next(p for p in PROBES if p.service == "Claude Cost Report")

    assert report.params["starting_at"] == COST_WINDOW_START
    assert COST_WINDOW_START.endswith("Z")


def test_the_api_version_is_pinned() -> None:
    """Following the newest version would let a vendor release change output."""
    assert API_VERSION == "2023-06-01"

    poc = run("anthropic_valid").capabilities[0].poc
    assert poc is not None
    assert f"anthropic-version: {API_VERSION}" in poc


def test_repeated_runs_are_identical() -> None:
    first, second = run("anthropic_admin", ADMIN_KEY), run("anthropic_admin", ADMIN_KEY)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("anthropic_admin", ADMIN_KEY).capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


# ---------------------------------------------------------------------------
# Evidence: proves access without becoming a copy of the data
# ---------------------------------------------------------------------------


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    files = next(
        c for c in run("anthropic_valid").capabilities if c.service == "Claude Files"
    )

    assert "files: 1 listed" in files.evidence
    assert "q3-board-pack.pdf" not in files.evidence


def test_evidence_never_leaks_a_member_email() -> None:
    members = next(
        c
        for c in run("anthropic_admin", ADMIN_KEY).capabilities
        if c.service == "Claude Organization Members"
    )

    assert "organization members: 1 listed" in members.evidence
    assert "@example.com" not in members.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("anthropic_admin", ADMIN_KEY).capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert ADMIN_KEY not in capability.poc


def test_no_committed_fixture_contains_a_key() -> None:
    """The guarantee that makes committing cassettes acceptable at all."""
    for name in ("valid", "invalid", "admin"):
        text = (FIXTURES / f"anthropic_{name}.json").read_text(encoding="utf-8")

        assert KEY not in text
        assert ADMIN_KEY not in text
        assert "sk-ant" not in text


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("anthropic_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        if probe.service in refs:
            assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_the_message_batch_endpoint_is_deliberately_absent() -> None:
    """A gap worth pinning, because it is a decision rather than an oversight.

    Listing message batches would expose what an account is processing, but its
    path is a prefix match for an inference endpoint that `ai_ban` bans outright
    (`tools/guardrails/ai_ban.py`). The ban is deliberately coarse, and the right
    response to a coarse ban is to accept the loss rather than to spell the URL
    in pieces to slip past it — a guardrail worked around is not a guardrail.
    """
    for probe in PROBES:
        assert "batches" not in probe.url


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_key_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("anthropic_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "rejected this key as invalid" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object, key: str = KEY) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        """Minimal ProbeContext stand-in: `validate` only ever calls `get`."""

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.anthropic.com/v1/models",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(AnthropicProvider().validate(key, _Stub()))  # type: ignore[arg-type]


def anthropic_error(kind: str) -> dict[str, object]:
    return {"type": "error", "error": {"type": kind, "message": "refused"}}


def test_a_permission_error_means_live_but_not_permitted() -> None:
    """Live and refused is a different finding from dead, and from exposed."""
    result = validate_against(403, anthropic_error("permission_error"))

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]
    assert "Enterprise" in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_key_is_live() -> None:
    result = validate_against(429, anthropic_error("rate_limit_error"))

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_unrecognised_error_type_is_not_treated_as_a_verdict() -> None:
    """Anthropic adds error types. An unknown one settles nothing either way."""
    result = validate_against(529, anthropic_error("overloaded_error"))

    assert not result.valid  # type: ignore[attr-defined]
    assert "overloaded_error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_platform_key_reports_no_identity() -> None:
    """The platform API discloses no account, and keyreach does not invent one."""
    result = validate_against(200, {"data": []})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Error and identity parsing, which read third-party payloads and must not raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="null"),
        pytest.param("a string", id="scalar"),
        pytest.param({}, id="empty"),
        pytest.param({"error": "oops"}, id="error-not-a-mapping"),
        pytest.param({"error": {"type": 7}}, id="type-not-a-string"),
    ],
)
def test_error_parsing_degrades_instead_of_raising(payload: object) -> None:
    """A gateway's HTML error page must not crash a probe."""
    assert _error_type(payload) == ""


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="null"),
        pytest.param("a string", id="scalar"),
        pytest.param({}, id="no-id"),
        pytest.param({"id": ""}, id="empty-id"),
        pytest.param({"id": 7}, id="id-not-a-string"),
    ],
)
def test_organization_parsing_returns_none_when_absent(payload: object) -> None:
    assert _organization(payload) is None


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"id": "org_1"}, id="no-name"),
        pytest.param({"id": "org_1", "name": ""}, id="empty-name"),
        pytest.param({"id": "org_1", "name": 7}, id="name-not-a-string"),
    ],
)
def test_an_organization_without_a_usable_name_still_reports_its_id(
    payload: object,
) -> None:
    identity = _organization(payload)

    assert identity is not None
    assert identity.account == "org_1"
    assert identity.extra == {}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"has_more":false}', "request accepted", id="no-data-key"),
        pytest.param('{"data":"x"}', "request accepted", id="data-not-a-list"),
        pytest.param('{"data":[]}', "files: none present", id="empty"),
        pytest.param('{"data":[1]}', "files: 1 listed", id="one"),
        pytest.param('{"data":[1,2]}', "files: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    files = next(p for p in PROBES if p.service == "Claude Files")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(files, response) == expected
