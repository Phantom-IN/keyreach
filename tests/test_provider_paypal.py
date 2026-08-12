"""PayPal provider tests (roadmap R2.1).

Three things here are unique in keyreach, and each has a test that is really
about the design rather than about PayPal.

``test_it_is_deliberately_undetectable`` and its companions cover the first
provider that opts out of detection. PayPal publishes no credential format, so
there is nothing to write a rule from, and ``detectable = False`` says that in
the contract instead of a regex saying it badly.

``test_the_token_is_minted_once_per_run`` is the one that would have caught the
defect this work introduced and then fixed: without ``read_only_post`` responses
being cacheable, keyreach would mint a token in ``validate`` and again in
``enumerate`` — R1.4's double-request defect, back for one provider.

``test_write_access_is_read_out_of_the_documented_scope_field`` covers access
levels derived from PayPal's own answer, matched per resource.

**On the fixtures.** Both host names and every probe path come from PayPal's own
OpenAPI specifications; the response bodies are constructed from those shapes,
not recorded from a live credential. Drift is roadmap **R2.10**.
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
from keyreach.providers.paypal import (
    HOSTS,
    PROBES,
    SCOPE_PREFIX,
    TOKEN_BODY,
    TOKEN_PATH,
    PayPalProvider,
    _Environment,
    _summary,
    access_for,
    access_token,
    parse_credential,
    scopes_of,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
CLIENT_ID = "AeNorthwind" + "ClientIdentifier0001"
CLIENT_SECRET = "ELNorthwind" + "ClientSecret000000001"
CREDENTIAL = f"{CLIENT_ID}:{CLIENT_SECRET}"

INVOICING = f"{SCOPE_PREFIX}invoicing"
SUBSCRIPTIONS = f"{SCOPE_PREFIX}subscriptions"


def run(fixture: str, key: str = CREDENTIAL) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket.

    Always with ``force_provider``: PayPal is undetectable by design, so this is
    the only way any run reaches it — which is exactly how a user reaches it too.
    """
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="paypal",
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(PayPalProvider(), origin="keyreach.providers.paypal")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "paypal" in [provider.name for provider in registry.providers()]


def test_it_is_a_payment_provider() -> None:
    assert PayPalProvider().category == "payment"


def test_it_claims_no_prior_art() -> None:
    assert PayPalProvider().credit is None


# ---------------------------------------------------------------------------
# The first undetectable provider
# ---------------------------------------------------------------------------


def test_it_is_deliberately_undetectable() -> None:
    """PayPal publishes no credential format, so no rule could exist."""
    assert PayPalProvider().detectable is False


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(CREDENTIAL, id="a-real-looking-credential"),
        pytest.param("", id="empty"),
        pytest.param("hello world", id="prose"),
        pytest.param("A" * 80 + ":" + "B" * 80, id="the-shape-it-would-have-matched"),
    ],
)
def test_detect_claims_nothing_at_all(candidate: str) -> None:
    """The opt-out has to mean it in behaviour, not only in metadata.

    A positive confidence here would make the registry rank PayPal as a
    candidate and probe it, and the last parameter is the reason the rule was
    never written: that shape is also a Razorpay pair, a Twilio pair, and a
    large fraction of every base64 blob a scanner emits.
    """
    assert PayPalProvider().detect(candidate) == 0.0


def test_no_detection_rule_names_paypal() -> None:
    """The rule set and the opt-out must agree; one without the other is a bug."""
    named = {rule.provider for rule in default_detector.rules()}

    assert "paypal" not in named


def test_a_paypal_credential_is_not_claimed_by_any_other_provider() -> None:
    """Undetectable must not mean "silently claimed by a neighbour" either."""
    matched = [
        match.provider
        for match in default_detector.detect(CREDENTIAL)
        if match.provider is not None
    ]

    assert matched == []


def test_naming_the_provider_records_that_it_was_asserted() -> None:
    """A capability map reached this way rests on the operator, and says so."""
    result = run("paypal_valid")

    assert any("Detection was overridden" in note for note in result.notes)


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


def test_the_pair_splits_on_the_first_colon_only() -> None:
    """A secret containing a colon must not be silently truncated.

    Truncating it would produce a credential that cannot authenticate, which
    keyreach would then report as "PayPal rejected this" — a confident, wrong
    verdict about a live credential.
    """
    credential = parse_credential(f"{CLIENT_ID}:{CLIENT_SECRET}:extra")

    assert credential is not None
    assert credential.client_id == CLIENT_ID
    assert credential.client_secret == f"{CLIENT_SECRET}:extra"


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(CLIENT_ID, id="no-colon"),
        pytest.param("short:" + CLIENT_SECRET, id="id-too-short"),
        pytest.param(CLIENT_ID + ":short", id="secret-too-short"),
    ],
)
def test_an_unusable_credential_is_rejected_before_any_request(candidate: str) -> None:
    assert parse_credential(candidate) is None


def test_a_credential_that_is_not_a_pair_is_reported_without_probing() -> None:
    result = run("paypal_valid", CLIENT_ID)

    assert not result.valid
    assert result.capabilities == ()
    assert "joined by a colon" in result.outcomes[0].validation.note


# ---------------------------------------------------------------------------
# The token exchange — the one justified read_only_post
# ---------------------------------------------------------------------------


def test_the_token_is_minted_once_per_run() -> None:
    """The defect this work introduced, and the reason the cache changed.

    ``validate`` needs a token and so does ``enumerate``. Before R2.1 the
    per-run response cache covered only idempotent methods, so PayPal would have
    minted two — R1.4's double-request defect, reintroduced for exactly one
    provider. Measured here rather than reasoned about, which is how R1.4 found
    it in the first place.
    """

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "paypal_valid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, CREDENTIAL)
            provider = PayPalProvider()
            await provider.validate(CREDENTIAL, context)
            after_validate = client.requests_made
            await provider.enumerate(CREDENTIAL, context)
            return after_validate, client.requests_made

    mints, total = asyncio.run(measure())

    assert mints == 1, "the token exchange should be a single request"
    assert total == 1 + len(PROBES), "enumerate should re-use the cached token"


def test_the_token_exchange_is_the_documented_one() -> None:
    assert TOKEN_PATH == "/v1/oauth2/token"  # noqa: S105 - a URL path
    assert TOKEN_BODY == "grant_type=client_credentials"  # noqa: S105 - a form body
    assert HOSTS[_Environment.LIVE] == "https://api-m.paypal.com"
    assert HOSTS[_Environment.SANDBOX] == "https://api-m.sandbox.paypal.com"


def test_the_token_is_read_from_the_response() -> None:
    response = ProbeResponse(
        method="POST", url="u", status_code=200, text='{"access_token":"A21AA"}'
    )

    assert access_token(response) == "A21AA"
    assert access_token(ProbeResponse(method="POST", url="u", status_code=200)) == ""


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param(None, frozenset(), id="not-a-mapping"),
        pytest.param({}, frozenset(), id="no-scope-field"),
        pytest.param({"scope": 7}, frozenset(), id="scope-not-a-string"),
        pytest.param({"scope": ""}, frozenset(), id="granted-nothing"),
        pytest.param({"scope": INVOICING}, frozenset({INVOICING}), id="one"),
        pytest.param(
            {"scope": f"{INVOICING}   {SUBSCRIPTIONS}"},
            frozenset({INVOICING, SUBSCRIPTIONS}),
            id="space-separated",
        ),
    ],
)
def test_scope_parsing_reads_the_documented_field(
    payload: object, expected: frozenset[str]
) -> None:
    assert scopes_of(payload) == expected


def test_write_access_is_read_out_of_the_documented_scope_field() -> None:
    invoices = next(p for p in PROBES if p.service == "PayPal Invoices")

    assert access_for(invoices, frozenset({INVOICING})) is AccessLevel.WRITE
    assert access_for(invoices, frozenset({SUBSCRIPTIONS})) is AccessLevel.READ
    assert access_for(invoices, frozenset()) is AccessLevel.READ


def test_a_scope_does_not_elevate_a_resource_it_does_not_cover() -> None:
    """The same per-resource discipline the GitHub plugin uses.

    A credential that can send an invoice cannot necessarily manage
    subscriptions, so one token-wide access level would over-report.
    """
    capabilities = {c.service: c for c in run("paypal_readonly").capabilities}

    assert all(c.access is AccessLevel.READ for c in capabilities.values())
    assert "granted no write scope" in capabilities["PayPal Invoices"].detail


# ---------------------------------------------------------------------------
# The findings this provider exists to produce
# ---------------------------------------------------------------------------


def test_a_live_credential_with_write_scopes_is_critical() -> None:
    result = run("paypal_valid")

    assert result.valid
    assert result.score.severity is Severity.CRITICAL
    assert [capability.service for capability in result.capabilities] == [
        "PayPal Disputes",
        "PayPal Invoices",
        "PayPal Products",
        "PayPal Subscription Plans",
    ]

    invoices = next(c for c in result.capabilities if c.service == "PayPal Invoices")
    assert invoices.access is AccessLevel.WRITE
    assert invoices.data_sensitive
    assert invoices.incurs_cost
    assert "No write was attempted" in invoices.detail


def test_only_money_moving_resources_claim_spend() -> None:
    """`incurs_cost` describes the capability, not the credential."""
    costly = {c.service for c in run("paypal_valid").capabilities if c.incurs_cost}

    assert costly == {"PayPal Invoices", "PayPal Subscription Plans"}


def test_the_application_is_named() -> None:
    identity = run("paypal_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "APP-80W284485P519543T"
    assert identity.plan_or_tier == "live"
    assert identity.extra == {"client_id": CLIENT_ID}


def test_the_scope_count_is_pluralised() -> None:
    """ "1 scopes" is the kind of slip that makes a reader distrust the numbers."""
    assert "granted 1 scope" in run("paypal_readonly").outcomes[0].validation.note
    assert "granted 3 scopes" in run("paypal_valid").outcomes[0].validation.note


# ---------------------------------------------------------------------------
# Live and sandbox
# ---------------------------------------------------------------------------


def test_a_sandbox_credential_is_found_by_falling_back() -> None:
    """Reporting a working sandbox credential as invalid would be wrong."""
    result = run("paypal_sandbox")

    assert result.valid
    assert result.outcomes[0].validation.identity is not None
    assert result.outcomes[0].validation.identity.plan_or_tier == "sandbox"
    assert "sandbox credential" in result.outcomes[0].validation.note


def test_a_sandbox_credential_is_a_weaker_finding() -> None:
    """It reaches PayPal's test environment and cannot move real money."""
    result = run("paypal_sandbox")

    assert result.score.severity is Severity.HIGH
    assert not any(c.data_sensitive for c in result.capabilities)
    assert not any(c.incurs_cost for c in result.capabilities)
    assert "sandbox environment" in result.capabilities[0].detail


def test_a_credential_neither_environment_accepts_is_invalid() -> None:
    result = run("paypal_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "either the live or the sandbox" in result.outcomes[0].validation.note
    assert "Client Authentication failed" in result.outcomes[0].validation.note


# ---------------------------------------------------------------------------
# Validation outcomes not reachable from a cassette
# ---------------------------------------------------------------------------


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic token response."""

    class _Stub:
        async def post(
            self,
            url: str,
            *,
            content: object = None,
            params: object = None,
            headers: object = None,
            read_only_post: bool = False,
        ) -> ProbeResponse:
            del url, content, params, headers, read_only_post
            return ProbeResponse(
                method="POST",
                url=f"{HOSTS[_Environment.LIVE]}{TOKEN_PATH}",
                status_code=status,
                text=json.dumps(payload),
            )

        def protect(self, secret: str) -> None:
            del secret

    return asyncio.run(PayPalProvider().validate(CREDENTIAL, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_exchange_still_means_the_credential_reached_paypal() -> None:
    result = validate_against(429, {"message": "Too many requests"})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"name": "INTERNAL_SERVER_ERROR"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "INTERNAL_SERVER_ERROR" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_credential_granted_no_scopes_says_it_reaches_nothing() -> None:
    result = validate_against(200, {"access_token": "A21AA", "scope": ""})

    assert result.valid  # type: ignore[attr-defined]
    assert "granted no scopes" in result.note  # type: ignore[attr-defined]


def test_an_identity_falls_back_to_the_client_id_when_no_app_id_is_returned() -> None:
    result = validate_against(200, {"access_token": "A21AA"})

    assert result.identity.account == CLIENT_ID  # type: ignore[attr-defined]


def test_enumerate_returns_nothing_for_an_unusable_credential() -> None:
    context = ProbeContext(ProbeClient(), CLIENT_ID)

    assert asyncio.run(PayPalProvider().enumerate(CLIENT_ID, context)) == []


def test_enumerate_returns_nothing_when_no_environment_authenticates() -> None:
    """`enumerate` runs only after a valid `validate`, but must not assume it.

    Driven directly rather than through the engine, because the engine skips
    ``enumerate`` entirely for an invalid key — so going through it would assert
    the engine's behaviour while leaving this path untested.
    """

    async def probe() -> list[object]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "paypal_invalid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, CREDENTIAL)
            return list(await PayPalProvider().enumerate(CREDENTIAL, context))

    assert asyncio.run(probe()) == []
    assert run("paypal_invalid").capabilities == ()


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"total_items":0}', "request accepted", id="no-collection"),
        pytest.param('{"items":"x"}', "request accepted", id="not-a-list"),
        pytest.param('{"items":[]}', "invoices: none present", id="empty"),
        pytest.param('{"items":[1]}', "invoices: 1 listed", id="one"),
        pytest.param('{"items":[1,2]}', "invoices: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    invoices = next(p for p in PROBES if p.service == "PayPal Invoices")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(invoices, response) == expected


# ---------------------------------------------------------------------------
# Determinism, evidence and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("paypal_valid"), run("paypal_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("paypal_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_records_and_does_not_quote_them() -> None:
    invoices = next(
        c for c in run("paypal_valid").capabilities if c.service == "PayPal Invoices"
    )

    assert "invoices: 1 listed" in invoices.evidence
    assert "buyer@example.invalid" not in invoices.evidence


def test_the_proof_of_concept_does_not_ship_the_credential_as_base64() -> None:
    blob = base64.b64encode(CREDENTIAL.encode()).decode("ascii")

    for capability in run("paypal_valid").capabilities:
        assert capability.poc is not None
        assert blob not in capability.poc
        assert CLIENT_SECRET not in capability.poc
        assert "<key>" in capability.poc


def test_every_probe_cites_the_specification_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("paypal_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_the_secret() -> None:
    for name in ("valid", "sandbox", "readonly", "invalid"):
        text = (FIXTURES / f"paypal_{name}.json").read_text(encoding="utf-8")

        assert CLIENT_SECRET not in text
        assert CREDENTIAL not in text
