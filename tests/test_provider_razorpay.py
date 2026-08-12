"""Razorpay provider tests (roadmap R1.6).

Razorpay is keyreach's third composite credential, after AWS and alongside
Twilio, and the one that departs from the others: only the secret half is
registered for redaction. ``test_only_the_secret_half_is_redacted`` pins that,
because it is the kind of decision that looks like an oversight when nothing
states it.

The other load-bearing test is
``test_no_capability_claims_a_write_razorpay_does_not_document``. Razorpay very
probably issues unscoped keys — but its documentation does not say so, and the
difference between "probably" and "documented" is the whole reason
`keyreach/providers/stripe.py` may say ADMIN and this may not.

**On the fixtures.** They are constructed from Razorpay's published response
shapes, not recorded from a live key. They prove the parsing and the decision
rules, not that Razorpay still answers this way; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    RecordMode,
)
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.razorpay import (
    PROBES,
    RazorpayProvider,
    _auth,
    _count,
    _credential_for,
    _summary,
    parse_credential,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
KEY_ID = "rzp_" + "live_" + "N0rthw1nd01"
TEST_KEY_ID = "rzp_" + "test_" + "N0rthw1nd01"
SECRET = "S3cr3tN0rthw1ndPayments1"  # noqa: S105 - a fixture value, not a secret
PAIR = f"{KEY_ID}:{SECRET}"
TEST_PAIR = f"{TEST_KEY_ID}:{SECRET}"


def run(fixture: str, key: str = PAIR) -> EngineResult:
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
    validate_provider(RazorpayProvider(), origin="keyreach.providers.razorpay")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "razorpay" in [provider.name for provider in registry.providers()]


def test_it_is_a_payment_provider() -> None:
    assert RazorpayProvider().category == "payment"


def test_it_claims_no_prior_art() -> None:
    assert RazorpayProvider().credit is None


# ---------------------------------------------------------------------------
# Detection and credential parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(PAIR, 0.99, id="live-pair"),
        pytest.param(TEST_PAIR, 0.99, id="test-pair"),
        pytest.param(KEY_ID, 0.99, id="bare-key-id"),
        pytest.param(f"{KEY_ID}:short", 0.0, id="secret-too-short"),
        pytest.param("rzp_" + "prod_" + "N0rthw1nd01", 0.0, id="unknown-mode"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + PAIR, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert RazorpayProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = RazorpayProvider()

    assert {provider.detect(PAIR) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [PAIR, TEST_PAIR, KEY_ID])
def test_the_plugin_and_the_rule_set_agree_on_the_key_format(key: str) -> None:
    """Two places describe a Razorpay credential. They must not drift apart."""
    matched = {
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    }

    assert matched == {"razorpay"}
    assert RazorpayProvider().detect(key) > 0.0


def test_the_pair_splits_unambiguously() -> None:
    credential = parse_credential(PAIR)

    assert credential is not None
    assert credential.key_id == KEY_ID
    assert credential.key_secret == SECRET
    assert credential.mode.value == "live"


def test_a_bare_key_id_is_not_a_credential() -> None:
    assert parse_credential(KEY_ID) is None


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_credential_yields_a_scored_capability_map() -> None:
    result = run("razorpay_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Razorpay Customers",
        "Razorpay Orders",
        "Razorpay Payments",
        "Razorpay Settlements",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("Razorpay Payments" in line for line in result.score.rationale)


def test_the_key_id_is_reported_as_the_identity() -> None:
    """Razorpay names no account, so the key id is the fact worth reporting."""
    identity = run("razorpay_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == KEY_ID
    assert identity.extra == {"mode": "live"}


def test_no_capability_claims_a_write_razorpay_does_not_document() -> None:
    """The discipline this plugin exists to demonstrate.

    A leaked live Razorpay secret can probably refund a payment. Razorpay does
    not publish a sentence saying so, and keyreach does not perform a write to
    check, so the capability map stops at what was confirmed and says which
    claim it declined to make.
    """
    capabilities = run("razorpay_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)
    assert all("Write access was not tested" in c.detail for c in capabilities)


def test_a_test_mode_credential_says_the_records_are_not_real() -> None:
    result = run("razorpay_valid", TEST_PAIR)

    assert "test-mode key" in result.capabilities[0].detail


# ---------------------------------------------------------------------------
# Redaction — the decision that differs from the AWS plugin
# ---------------------------------------------------------------------------


def test_only_the_secret_half_is_redacted() -> None:
    """Deliberate, and different from AWS, which registers both halves.

    Razorpay documents that "only the Key Id is visible on the Dashboard, not
    the Key secret". Redacting the key id would remove the one fact that tells
    a recipient which key to revoke, while protecting nothing.
    """
    context = ProbeContext(ProbeClient(), PAIR)
    _credential_for(PAIR, context)

    assert context.mask(SECRET) == "<key>"
    assert context.mask(KEY_ID) == KEY_ID


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("razorpay_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s -u ")
        assert SECRET not in capability.poc
        assert "<key>" in capability.poc


def test_the_proof_of_concept_does_not_ship_the_credential_as_base64() -> None:
    """The request carries Basic auth; the reproduction must not.

    base64 of a secret is not the secret, so the redactor would not touch it and
    a masked-looking header would hand the credential to anyone who can run
    ``base64 -d``.
    """
    blob = base64.b64encode(PAIR.encode()).decode("ascii")

    for capability in run("razorpay_valid").capabilities:
        assert capability.poc is not None
        assert blob not in capability.poc

    assert _auth(parse_credential(PAIR))["Authorization"] == f"Basic {blob}"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_a_bare_key_id_is_reported_without_a_single_request() -> None:
    """Probing it would produce a 401 that keyreach would have to call invalid."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / "razorpay_valid.json"),
        mode=RecordMode.REPLAY,
    )
    result = asyncio.run(engine.run(KEY_ID))

    assert not result.valid
    assert result.capabilities == ()

    validation = result.outcomes[0].validation
    assert "no key secret" in validation.note
    assert "does not mean the credential is dead" in validation.note
    assert validation.identity is not None
    assert validation.identity.account == KEY_ID


def test_an_invalid_credential_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("razorpay_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "Authentication failed" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object, key: str = PAIR) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.razorpay.com/v1/payments?count=1",
                status_code=status,
                text=json.dumps(payload),
            )

        def protect(self, secret: str) -> None:
            del secret

    return asyncio.run(RazorpayProvider().validate(key, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limit_still_means_the_credential_is_live() -> None:
    result = validate_against(429, {"error": {"description": "Too many requests"}})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_description_still_reads_cleanly() -> None:
    result = validate_against(401, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert result.note.endswith("key id and secret")  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"error": {"description": "Server error"}})

    assert not result.valid  # type: ignore[attr-defined]
    assert "Server error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    """A gateway can answer 500 with a JSON array. That must not raise."""
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_enumerate_returns_nothing_for_an_incomplete_credential() -> None:
    context = ProbeContext(ProbeClient(), KEY_ID)

    assert asyncio.run(RazorpayProvider().enumerate(KEY_ID, context)) == []


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param(None, None, id="null"),
        pytest.param("a string", None, id="scalar"),
        pytest.param({}, None, id="empty"),
        pytest.param({"count": True}, None, id="count-is-a-bool"),
        pytest.param({"count": 3}, 3, id="documented-count"),
        pytest.param({"items": [1, 2]}, 2, id="falls-back-to-items"),
        pytest.param({"items": "x"}, None, id="items-not-a-list"),
    ],
)
def test_count_parsing_degrades_instead_of_raising(
    payload: object, expected: int | None
) -> None:
    assert _count(payload) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"count":0,"items":[]}', "payments: none present", id="empty"),
        pytest.param('{"count":1,"items":[1]}', "payments: 1 listed", id="one"),
        pytest.param('{"count":9,"items":[1]}', "payments: 9 listed", id="paginated"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    payments = next(p for p in PROBES if p.service == "Razorpay Payments")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(payments, response) == expected


# ---------------------------------------------------------------------------
# Determinism, evidence and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("razorpay_valid"), run("razorpay_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("razorpay_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    payments = next(
        c
        for c in run("razorpay_valid").capabilities
        if c.service == "Razorpay Payments"
    )

    assert "payments: 1 listed" in payments.evidence
    assert "buyer@example.invalid" not in payments.evidence


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("razorpay_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_a_key() -> None:
    for name in ("valid", "invalid"):
        text = (FIXTURES / f"razorpay_{name}.json").read_text(encoding="utf-8")

        assert SECRET not in text
        assert KEY_ID not in text
