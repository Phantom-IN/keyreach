"""Twilio provider tests (roadmap R1.6).

Two things here are worth more than the rest.

``test_the_account_sid_never_reaches_a_recorded_url`` is the one that makes
committing these cassettes safe at all: the Account SID is in the request path,
so without registering it for redaction every fixture would contain half a live
credential — and it is a shape keyreach's own detector matches, which would fail
``no_secrets`` on the way in.

``test_the_message_body_never_reaches_the_evidence`` is the one that matters
most to a stranger. The message log carries one-time passcodes. Proving keyreach
can read it must not mean printing one into a bug bounty report.

**On the fixtures.** They are constructed from Twilio's published response
shapes, not recorded from a live credential. They prove the parsing and the
decision rules, not that Twilio still answers this way; drift is roadmap
**R2.10**.
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
from keyreach.providers.twilio import (
    PERMISSION_DENIED,
    PROBES,
    TwilioProvider,
    _credential_for,
    _summary,
    error_code,
    parse_credential,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
ACCOUNT_SID = "AC" + "0" * 32
API_KEY_SID = "SK" + "0" * 32
AUTH_TOKEN = "f" * 32
PAIR = f"{ACCOUNT_SID}:{AUTH_TOKEN}"


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
    validate_provider(TwilioProvider(), origin="keyreach.providers.twilio")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "twilio" in [provider.name for provider in registry.providers()]


def test_it_is_a_comms_provider() -> None:
    assert TwilioProvider().category == "comms"


def test_it_claims_no_prior_art() -> None:
    assert TwilioProvider().credit is None


# ---------------------------------------------------------------------------
# Detection and credential parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(PAIR, 0.99, id="pair"),
        pytest.param(ACCOUNT_SID, 0.95, id="bare-account-sid"),
        pytest.param(API_KEY_SID, 0.95, id="bare-api-key-sid"),
        pytest.param("AC" + "0" * 31, 0.0, id="too-short"),
        pytest.param("AC" + "F" * 32, 0.0, id="uppercase-hex"),
        pytest.param(f"{ACCOUNT_SID}:short", 0.0, id="token-too-short"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + PAIR, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert TwilioProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = TwilioProvider()

    assert {provider.detect(PAIR) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [PAIR, ACCOUNT_SID, API_KEY_SID])
def test_the_plugin_and_the_rule_set_agree_on_the_credential_format(key: str) -> None:
    """Two places describe a Twilio credential. They must not drift apart."""
    matched = {
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    }

    assert matched == {"twilio"}
    assert TwilioProvider().detect(key) > 0.0


def test_the_pair_splits_unambiguously() -> None:
    credential = parse_credential(PAIR)

    assert credential is not None
    assert credential.account_sid == ACCOUNT_SID
    assert credential.auth_token == AUTH_TOKEN


def test_a_bare_sid_is_not_a_credential() -> None:
    assert parse_credential(ACCOUNT_SID) is None


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_credential_yields_a_scored_capability_map() -> None:
    result = run("twilio_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Twilio Account",
        "Twilio Balance",
        "Twilio Call Log",
        "Twilio Message Log",
        "Twilio Phone Numbers",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("Twilio Message Log" in line for line in result.score.rationale)


def test_the_account_is_named_with_the_tier_that_bounds_the_blast_radius() -> None:
    """ "Trial" or "Full" says more about real-world impact than anything else."""
    identity = run("twilio_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == ACCOUNT_SID
    assert identity.owner == "Northwind Ops"
    assert identity.plan_or_tier == "Full"
    assert identity.extra == {"status": "active"}


def test_no_capability_claims_a_send_twilio_does_not_document() -> None:
    """Toll fraud is why a leaked Twilio credential matters, and keyreach will
    not claim it: sending is the write it never performs."""
    capabilities = run("twilio_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)
    assert all("Sending was not tested" in c.detail for c in capabilities)


# ---------------------------------------------------------------------------
# Redaction — what makes committing these fixtures safe
# ---------------------------------------------------------------------------


def test_the_account_sid_never_reaches_a_recorded_url() -> None:
    """The SID is in the path, so it would otherwise be in every fixture.

    It is also a shape keyreach's own detector matches, so an unregistered SID
    would fail `no_secrets` and block the commit — the right outcome from the
    wrong cause. Registering both halves is what `CLAUDE.md` asks for.
    """
    for name in ("valid", "invalid"):
        text = (FIXTURES / f"twilio_{name}.json").read_text(encoding="utf-8")

        assert ACCOUNT_SID not in text
        assert AUTH_TOKEN not in text
        assert "Accounts/<key>" in text


def test_both_halves_are_registered_for_redaction() -> None:
    context = ProbeContext(ProbeClient(), PAIR)
    _credential_for(PAIR, context)

    assert context.mask(ACCOUNT_SID) == "<key>"
    assert context.mask(AUTH_TOKEN) == "<key>"


def test_the_message_body_never_reaches_the_evidence() -> None:
    """Counts, never contents — and here the contents are one-time passcodes."""
    messages = next(
        c for c in run("twilio_valid").capabilities if c.service == "Twilio Message Log"
    )

    assert "messages: 1 listed" in messages.evidence
    assert "411982" not in messages.evidence
    assert "+15550003333" not in messages.evidence


def test_the_proof_of_concept_does_not_ship_the_credential_as_base64() -> None:
    blob = base64.b64encode(PAIR.encode()).decode("ascii")

    for capability in run("twilio_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s -u ")
        assert blob not in capability.poc
        assert AUTH_TOKEN not in capability.poc
        assert "<key>" in capability.poc


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        pytest.param(ACCOUNT_SID, "no Auth Token", id="account-sid"),
        pytest.param(API_KEY_SID, "API Key SID with no secret", id="api-key-sid"),
    ],
)
def test_an_incomplete_credential_is_reported_without_a_single_request(
    key: str, expected: str
) -> None:
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / "twilio_valid.json"),
        mode=RecordMode.REPLAY,
    )
    result = asyncio.run(engine.run(key))

    assert not result.valid
    assert result.capabilities == ()
    assert expected in result.outcomes[0].validation.note
    assert "does not mean the credential is dead" in result.outcomes[0].validation.note


def test_an_invalid_credential_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("twilio_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert str(PERMISSION_DENIED) in result.outcomes[0].validation.note


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.twilio.com/2010-04-01/Accounts/<key>.json",
                status_code=status,
                text=json.dumps(payload),
            )

        def protect(self, secret: str) -> None:
            del secret

    return asyncio.run(TwilioProvider().validate(PAIR, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_response_means_live_but_scoped_away() -> None:
    """20003 bundles "wrong credentials" and "not for this resource" together,
    so the status is what decides — and a 403 must not retire a live token."""
    result = validate_against(403, {"code": PERMISSION_DENIED, "message": "Denied"})

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]


def test_a_forbidden_response_without_a_code_still_reads_cleanly() -> None:
    result = validate_against(403, {"message": "Denied"})

    assert result.valid  # type: ignore[attr-defined]
    assert "permission denied" in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_credential_is_live() -> None:
    result = validate_against(429, {"code": 20429, "message": "Too many requests"})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"message": "Server error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "Server error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_code_still_reads_cleanly() -> None:
    result = validate_against(401, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert result.note.endswith("Auth Token")  # type: ignore[attr-defined]


def test_enumerate_returns_nothing_for_an_incomplete_credential() -> None:
    context = ProbeContext(ProbeClient(), ACCOUNT_SID)

    assert asyncio.run(TwilioProvider().enumerate(ACCOUNT_SID, context)) == []


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", None, id="not-json"),
        pytest.param("[]", None, id="list"),
        pytest.param('{"code":true}', None, id="code-is-a-bool"),
        pytest.param('{"code":"20003"}', None, id="code-is-a-string"),
        pytest.param('{"code":20003}', 20003, id="documented-code"),
    ],
)
def test_error_code_parsing_degrades_instead_of_raising(
    body: str, expected: int | None
) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=401, text=body)

    assert error_code(response) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"page":0}', "request accepted", id="no-collection"),
        pytest.param('{"messages":"x"}', "request accepted", id="not-a-list"),
        pytest.param('{"messages":[]}', "messages: none present", id="empty"),
        pytest.param('{"messages":[1]}', "messages: 1 listed", id="one"),
        pytest.param('{"messages":[1,2]}', "messages: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    messages = next(p for p in PROBES if p.service == "Twilio Message Log")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(messages, response) == expected


def test_a_probe_with_no_collection_reports_acceptance() -> None:
    balance = next(p for p in PROBES if p.service == "Twilio Balance")
    response = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"balance":"1.00"}'
    )

    assert _summary(balance, response) == "request accepted"


# ---------------------------------------------------------------------------
# Determinism and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("twilio_valid"), run("twilio_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("twilio_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("twilio_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))
