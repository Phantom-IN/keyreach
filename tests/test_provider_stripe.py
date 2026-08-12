"""Stripe provider tests (roadmap R1.6).

The test carrying the most weight here is
``test_a_live_secret_key_is_critical_because_stripe_documents_it_as_unrestricted``.
It is the first time keyreach reports Critical for a payment key, and the whole
claim rests on one published sentence rather than on a write keyreach performed.
Its counterweight is ``test_a_restricted_key_claims_only_the_read_it_confirmed``:
same probe, same response shape, a different prefix, and a deliberately weaker
verdict.

**On the fixtures.** They are constructed from Stripe's published response
shapes, not recorded from a live key — keyreach's own rules forbid holding one,
and probing somebody else's would be unauthorised. That is a real limitation:
they prove the parsing and the decision rules, not that Stripe still answers
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
from keyreach.providers.stripe import (
    PROBES,
    StripeProvider,
    _identity,
    _Kind,
    _Mode,
    _summary,
    access_for,
    kind_of,
    mode_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal — a joined Stripe key
#: matches keyreach's own detector and GitHub push protection, and the second
#: would reject the push (see `tools/guardrails/no_secrets.py`).
BODY = "N0rthw1ndCoffee0000000001"
LIVE_SECRET = "sk_" + "live_" + BODY
TEST_SECRET = "sk_" + "test_" + BODY
LIVE_RESTRICTED = "rk_" + "live_" + BODY
NOT_A_KEY = "sk_" + "live_" + "short"


def run(fixture: str, key: str = LIVE_SECRET) -> EngineResult:
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
    validate_provider(StripeProvider(), origin="keyreach.providers.stripe")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "stripe" in [provider.name for provider in registry.providers()]


def test_it_is_a_payment_provider() -> None:
    assert StripeProvider().category == "payment"


def test_it_claims_no_prior_art() -> None:
    assert StripeProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(LIVE_SECRET, 0.99, id="live-secret"),
        pytest.param(TEST_SECRET, 0.99, id="test-secret"),
        pytest.param(LIVE_RESTRICTED, 0.99, id="live-restricted"),
        pytest.param(NOT_A_KEY, 0.0, id="too-short"),
        pytest.param("pk_" + "live_" + BODY, 0.0, id="publishable"),
        pytest.param("sk_" + "org_" + BODY, 0.0, id="organisation-key"),
        pytest.param("sk_" + "proj-" + BODY, 0.0, id="openai"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + LIVE_SECRET, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert StripeProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = StripeProvider()

    assert {provider.detect(LIVE_SECRET) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [LIVE_SECRET, TEST_SECRET, LIVE_RESTRICTED])
def test_the_plugin_and_the_rule_set_agree_on_the_key_format(key: str) -> None:
    """Two places describe a Stripe key. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["stripe"]
    assert StripeProvider().detect(key) > 0.0


def test_a_publishable_key_is_not_claimed_by_anything() -> None:
    """`pk_` keys are documented as safe to expose. Reporting one would be noise."""
    assert [
        match.provider
        for match in default_detector.detect("pk_" + "live_" + BODY)
        if match.provider is not None
    ] == []


# ---------------------------------------------------------------------------
# What the key's own shape decides, before any request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "kind", "mode"),
    [
        pytest.param(LIVE_SECRET, _Kind.SECRET, _Mode.LIVE, id="live-secret"),
        pytest.param(TEST_SECRET, _Kind.SECRET, _Mode.TEST, id="test-secret"),
        pytest.param(LIVE_RESTRICTED, _Kind.RESTRICTED, _Mode.LIVE, id="restricted"),
    ],
)
def test_kind_and_mode_come_from_the_key(key: str, kind: _Kind, mode: _Mode) -> None:
    assert kind_of(key) is kind
    assert mode_of(key) is mode


def test_the_access_level_follows_the_documented_prefix() -> None:
    """Stripe publishes both halves of this rule; keyreach only reads it."""
    assert access_for(_Kind.SECRET) is AccessLevel.ADMIN
    assert access_for(_Kind.RESTRICTED) is AccessLevel.READ


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# The findings this provider exists to produce
# ---------------------------------------------------------------------------


def test_a_live_secret_key_is_critical_because_stripe_documents_it_as_unrestricted() -> (
    None
):
    """The rule, and its source, in one test.

    Stripe's own key table says a secret key "has unrestricted permissions on
    all Stripe APIs". So the write follows from the vendor's access model rather
    than from anything keyreach did — and keyreach did not create a charge to
    find out. Compare the restricted-key test below, which is the same probe
    against the same shape of response and yields a deliberately weaker verdict.
    """
    result = run("stripe_valid")

    assert result.valid
    assert result.score.severity is Severity.CRITICAL
    assert [capability.service for capability in result.capabilities] == [
        "Stripe Account",
        "Stripe Balance",
        "Stripe Charges",
        "Stripe Customers",
        "Stripe Payment Intents",
        "Stripe Payouts",
        "Stripe Subscriptions",
    ]

    charges = next(c for c in result.capabilities if c.service == "Stripe Charges")
    assert charges.access is AccessLevel.ADMIN
    assert "unrestricted permissions on all Stripe APIs" in charges.detail
    assert "No write was attempted" in charges.detail


def test_a_live_key_names_the_account_it_belongs_to() -> None:
    identity = run("stripe_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "acct_1QeNorthwind0001"
    assert identity.owner == "Northwind Coffee Ltd"
    assert identity.extra == {"mode": "live", "country": "GB"}


def test_a_restricted_key_claims_only_the_read_it_confirmed() -> None:
    """The other half of the pair. Same responses, weaker prefix, weaker verdict."""
    result = run("stripe_restricted", LIVE_RESTRICTED)

    assert result.valid
    assert [c.service for c in result.capabilities] == ["Stripe Charges"]

    charges = result.capabilities[0]
    assert charges.access is AccessLevel.READ
    assert not charges.incurs_cost
    assert "permissions are configurable" in charges.detail


def test_a_restricted_key_denied_the_account_read_is_still_live() -> None:
    """A 403 is a scoped key, not a dead one. Calling it invalid retires it."""
    validation = run("stripe_restricted", LIVE_RESTRICTED).outcomes[0].validation

    assert validation.valid
    assert "does not have permission" in validation.note
    assert "lower bound" in validation.note


def test_only_money_moving_resources_claim_spend() -> None:
    """`incurs_cost` describes the capability, not the key.

    An unrestricted key can spend, but reading the balance is not spending, and
    the report's rationale is assembled out of capabilities rather than keys. A
    balance read filed under "can incur direct financial cost" would be an
    argument a triager could pick apart.
    """
    costly = {c.service for c in run("stripe_valid").capabilities if c.incurs_cost}

    assert costly == {
        "Stripe Charges",
        "Stripe Payment Intents",
        "Stripe Payouts",
        "Stripe Subscriptions",
    }


def test_a_sandbox_key_is_a_weaker_finding_than_a_live_one() -> None:
    """Stripe documents sandbox objects as simulated and sandbox payments as
    not processed, so a test key reaches no real data and moves no real money."""
    result = run("stripe_valid", TEST_SECRET)

    assert result.valid
    assert result.score.severity is Severity.HIGH
    assert not any(c.data_sensitive for c in result.capabilities)
    assert not any(c.incurs_cost for c in result.capabilities)
    assert all(c.access is AccessLevel.ADMIN for c in result.capabilities)
    assert "sandbox key" in result.capabilities[0].detail


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_key_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("stripe_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "no valid API key provided" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object, key: str = LIVE_SECRET) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        """Minimal ProbeContext stand-in: `validate` only ever calls `get`."""

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.stripe.com/v1/account",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(StripeProvider().validate(key, _Stub()))  # type: ignore[arg-type]


def stripe_error(message: str) -> dict[str, object]:
    return {"error": {"message": message, "type": "invalid_request_error"}}


def test_a_rate_limit_still_means_the_key_is_live() -> None:
    result = validate_against(429, stripe_error("Too many requests"))

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_an_error_message_is_quoted_back_when_stripe_supplied_one() -> None:
    result = validate_against(500, stripe_error("Something is wrong"))

    assert "Something is wrong" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    """A gateway can answer 500 with a JSON array. That must not raise."""
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_body_without_an_account_id_yields_no_identity() -> None:
    """A 200 that is not an account object must not invent one."""
    result = validate_against(200, {"object": "account"})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


def test_an_account_without_a_business_profile_still_identifies_itself() -> None:
    result = validate_against(200, {"id": "acct_1", "business_profile": None})

    assert result.identity.account == "acct_1"  # type: ignore[attr-defined]
    assert result.identity.owner is None  # type: ignore[attr-defined]
    assert result.identity.extra == {"mode": "live"}  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("null", id="null"),
        pytest.param('"a string"', id="scalar"),
        pytest.param("[]", id="list"),
    ],
)
def test_identity_parsing_degrades_instead_of_raising(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _identity(LIVE_SECRET, response) is None


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"object":"balance"}', "request accepted", id="no-data-key"),
        pytest.param('{"data":"x"}', "request accepted", id="data-not-a-list"),
        pytest.param('{"data":[]}', "charges: none present", id="empty"),
        pytest.param('{"data":[1]}', "charges: 1 listed", id="one"),
        pytest.param('{"data":[1,2]}', "charges: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    charges = next(p for p in PROBES if p.service == "Stripe Charges")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(charges, response) == expected


# ---------------------------------------------------------------------------
# Determinism, evidence and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("stripe_valid"), run("stripe_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("stripe_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    customers = next(
        c for c in run("stripe_valid").capabilities if c.service == "Stripe Customers"
    )

    assert "customers: 1 listed" in customers.evidence
    assert "buyer@example.invalid" not in customers.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("stripe_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert LIVE_SECRET not in capability.poc


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("stripe_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_a_key() -> None:
    """The guarantee that makes committing cassettes acceptable at all."""
    for name in ("valid", "invalid", "restricted"):
        text = (FIXTURES / f"stripe_{name}.json").read_text(encoding="utf-8")

        assert LIVE_SECRET not in text
        assert LIVE_RESTRICTED not in text
        assert BODY not in text
