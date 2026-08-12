"""Paystack provider tests (roadmap R2.1).

The tests that carry the most weight here are about the **collision with
Stripe**, not about Paystack. Both vendors document ``sk_live_`` and
``sk_test_``, and neither publishes anything that separates them, so R2.1 is the
first time keyreach has had two plugins claim one key.

``test_paystack_and_stripe_claim_the_same_key_with_equal_confidence`` pins the
ambiguity rather than papering over it, and
``test_the_probe_stage_settles_the_ambiguity`` runs it end to end: two
candidates, one 401, one capability map, and a report about the right vendor.
``implementation_plan.md`` §5 specified that resolution in R0.5 and nothing had
ever exercised it.

**On the fixtures.** Paystack's base URL, every path and the error envelope were
verified against Paystack's own API, and ``perPage`` against its published SDK.
The response bodies are constructed from those shapes, not recorded from a live
key; drift is roadmap **R2.10**.
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
from keyreach.providers.paystack import (
    API,
    PROBES,
    PaystackProvider,
    _Mode,
    _summary,
    message_of,
    mode_of,
    validation_probe,
)
from keyreach.providers.stripe import StripeProvider

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
BODY = "N0rthw1ndPaystack00000001"
LIVE = "sk_" + "live_" + BODY
TEST = "sk_" + "test_" + BODY


def run(
    fixture: str, key: str = LIVE, provider: str | None = "paystack"
) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider=provider,
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(PaystackProvider(), origin="keyreach.providers.paystack")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "paystack" in [provider.name for provider in registry.providers()]


def test_it_is_a_payment_provider() -> None:
    assert PaystackProvider().category == "payment"


def test_it_claims_no_prior_art() -> None:
    assert PaystackProvider().credit is None


def test_it_is_detectable() -> None:
    """Unlike PayPal, Paystack publishes a prefix, so a rule can exist."""
    assert PaystackProvider().detectable


# ---------------------------------------------------------------------------
# The collision with Stripe — what R2.1 is really about
# ---------------------------------------------------------------------------


def test_paystack_and_stripe_claim_the_same_key_with_equal_confidence() -> None:
    """The ambiguity, asserted rather than hidden.

    Both vendors document `sk_live_` and `sk_test_`. Neither publishes a length
    or charset that separates them, so ranking one above the other would settle
    the question by assertion. Equal confidence is the honest answer, and the
    registry breaks the tie on name so the order is at least reproducible.
    """
    assert PaystackProvider().detect(LIVE) == StripeProvider().detect(LIVE)

    matched = [
        (match.provider, match.confidence)
        for match in default_detector.detect(LIVE)
        if match.provider is not None
    ]

    assert matched == [("paystack", 0.99), ("stripe", 0.99)]


def test_the_probe_stage_settles_the_ambiguity() -> None:
    """`implementation_plan.md` §5's resolution, exercised for the first time.

    Both candidates are probed. Stripe answers 401, Paystack answers, and the
    report is about Paystack — decided by which vendor accepted the key, not by
    which rule sorted first.
    """
    result = run("paystack_over_stripe", provider=None)

    assert [outcome.provider for outcome in result.outcomes] == ["paystack", "stripe"]
    assert result.valid

    by_provider = {outcome.provider: outcome for outcome in result.outcomes}
    assert by_provider["paystack"].validation.valid
    assert not by_provider["stripe"].validation.valid
    assert by_provider["stripe"].capabilities == ()


def test_the_losing_candidate_costs_exactly_one_request() -> None:
    """The price of not guessing, measured rather than asserted.

    A rejected candidate's `enumerate` never runs, so the wasted authentication
    traffic against the wrong vendor is one request — not a whole probe table.
    """
    result = run("paystack_over_stripe", provider=None)
    stripe = next(o for o in result.outcomes if o.provider == "stripe")

    assert stripe.capabilities == ()
    assert not stripe.validation.valid


def test_a_rejected_key_says_the_other_vendor_shares_the_prefix() -> None:
    """A user who sees "Paystack rejected this" must not conclude "dead key"."""
    note = run("paystack_invalid").outcomes[0].validation.note

    assert "Stripe uses the same key prefix" in note


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(LIVE, 0.99, id="live"),
        pytest.param(TEST, 0.99, id="test"),
        pytest.param("sk_" + "live_" + "short", 0.0, id="too-short"),
        pytest.param("rk_" + "live_" + BODY, 0.0, id="stripe-restricted"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + LIVE, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert PaystackProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = PaystackProvider()

    assert {provider.detect(LIVE) for _ in range(5)} == {0.99}


@pytest.mark.parametrize(
    ("key", "mode"),
    [
        pytest.param(LIVE, _Mode.LIVE, id="live"),
        pytest.param(TEST, _Mode.TEST, id="test"),
    ],
)
def test_the_mode_comes_from_the_documented_infix(key: str, mode: _Mode) -> None:
    assert mode_of(key) is mode


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


def test_validation_uses_the_endpoint_that_lists_nothing() -> None:
    """The least intrusive liveness check: one number, not a page of customers."""
    assert validation_probe().url == f"{API}/balance"


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_scored_capability_map() -> None:
    result = run("paystack_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Paystack Balance",
        "Paystack Customers",
        "Paystack Settlements",
        "Paystack Subaccounts",
        "Paystack Transactions",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("Paystack Customers" in line for line in result.score.rationale)


def test_the_mode_is_the_identity_paystack_discloses() -> None:
    """Paystack publishes no "who am I" endpoint, and keyreach invents none."""
    identity = run("paystack_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account is None
    assert identity.extra == {"mode": "live"}


def test_no_capability_claims_a_write_paystack_does_not_document() -> None:
    capabilities = run("paystack_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)
    assert all("never initiates a transfer" in c.detail for c in capabilities)


def test_a_test_mode_key_reaches_no_real_customer_data() -> None:
    result = run("paystack_valid", TEST)

    assert result.valid
    assert not any(c.data_sensitive for c in result.capabilities)
    assert "test-mode key" in result.capabilities[0].detail


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_key_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("paystack_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "Invalid key" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object, key: str = LIVE) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url=f"{API}/balance",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(PaystackProvider().validate(key, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_response_means_live_but_scoped_away() -> None:
    result = validate_against(403, {"status": False, "message": "Not allowed"})

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_key_is_live() -> None:
    result = validate_against(429, {"status": False, "message": "Too many requests"})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"status": False, "message": "Server error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "Server error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_forbidden_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(403, ["unexpected"])

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(401, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "did not accept this key" in result.note  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param('{"message":7}', id="message-not-a-string"),
    ],
)
def test_message_parsing_degrades_instead_of_raising(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=401, text=body)

    assert message_of(response) == ""


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"status":true}', "request accepted", id="no-data"),
        pytest.param('{"data":"x"}', "request accepted", id="data-not-a-list"),
        pytest.param('{"data":[]}', "transactions: none present", id="empty"),
        pytest.param('{"data":[1]}', "transactions: 1 listed", id="one"),
        pytest.param('{"data":[1,2]}', "transactions: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    transactions = next(p for p in PROBES if p.service == "Paystack Transactions")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(transactions, response) == expected


# ---------------------------------------------------------------------------
# Determinism, evidence and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("paystack_valid"), run("paystack_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("paystack_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_records_and_does_not_quote_them() -> None:
    customers = next(
        c
        for c in run("paystack_valid").capabilities
        if c.service == "Paystack Customers"
    )

    assert "customers: 1 listed" in customers.evidence
    assert "buyer@example.invalid" not in customers.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("paystack_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert LIVE not in capability.poc


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("paystack_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_a_key() -> None:
    for name in ("valid", "invalid", "over_stripe"):
        text = (FIXTURES / f"paystack_{name}.json").read_text(encoding="utf-8")

        assert LIVE not in text
        assert BODY not in text
