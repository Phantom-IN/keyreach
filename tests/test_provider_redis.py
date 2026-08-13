"""Redis Cloud provider tests (roadmap R2.5).

Three things carry the weight here.

**The provider name promises more than the plugin delivers, so the plugin says
so.** ``test_the_scope_is_the_control_plane_not_a_redis_server`` pins that: a
Redis *server* credential is a password spoken over RESP on port 6379, which
cannot go through ``ProbeContext`` at all. What this covers is the Redis Cloud
control-plane key pair.

**Both halves are secret, unlike Bitbucket's.**
``test_both_halves_are_masked`` is the contrast worth reading next to
``tests/test_provider_bitbucket.py``, where the first half is an email address
and is deliberately *not* masked because it is the identity the report exists to
name. Here neither half is an identity.

**Redis answers 401 with an nginx HTML page.** Verified against the live API and
recorded verbatim, so the rejection note has nothing to quote — and
``test_a_rejected_pair_does_not_conclude_the_keys_are_revoked`` covers why that
matters: Redis refuses a wrong key and a caller outside the key's CIDR allow
list identically.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.redis import (
    API,
    PROBES,
    Credential,
    RedisProvider,
    _summary,
    message_of,
    parse_credential,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
ACCOUNT = "N0rthw1nd" + "Acc0untKey" + "0000"
SECRET = "N0rthw1nd" + "SecretKey" + "00000"
KEY = ACCOUNT + ":" + SECRET


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="redis",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int, body: str, url: str = f"{API}/subscriptions"
) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(RedisProvider(), origin="keyreach.providers.redis")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "redis" in [provider.name for provider in registry.providers()]


def test_it_is_a_database_provider() -> None:
    assert RedisProvider().category == "database"


def test_it_claims_no_prior_art() -> None:
    assert RedisProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """Redis publishes no format for either key."""
    assert RedisProvider().detectable is False


@pytest.mark.parametrize(
    "sample", [KEY, "", "not-a-key", "x" * 24 + ":" + "y" * 24, ACCOUNT]
)
def test_detect_claims_nothing_at_all(sample: str) -> None:
    assert RedisProvider().detect(sample) == 0.0


def test_the_scope_is_the_control_plane_not_a_redis_server() -> None:
    """The roadmap says "Redis"; the honest reading is narrower.

    A Redis server credential is a password spoken over RESP on port 6379, not
    HTTP, so it cannot go through `ProbeContext` at all. Every probe here is
    under Redis Cloud's REST host, and a change that pointed one at a server
    would fail this rather than quietly widening what the provider name implies.
    """
    for probe in PROBES:
        assert probe.url.startswith(API)
        assert "redislabs.com" in probe.url


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (KEY, Credential(ACCOUNT, SECRET)),
        # A secret containing a colon survives, because the split is on the first.
        ("account:a:b", Credential("account", "a:b")),
        (ACCOUNT, None),
        (":" + SECRET, None),
        (ACCOUNT + ":", None),
    ],
)
def test_the_credential_is_split_on_the_first_colon(
    key: str, expected: Credential | None
) -> None:
    assert parse_credential(key) == expected


def test_a_lone_key_is_answered_without_a_request() -> None:
    """Both headers are required, so one half cannot be tested at all."""
    verdict = validation(run("redis_invalid", key=ACCOUNT))

    assert not verdict.valid
    assert verdict.note is not None
    assert "No request was made" in verdict.note
    assert "'<account key>:<secret key>'" in verdict.note


def test_both_halves_are_masked() -> None:
    """The contrast with Bitbucket, where the first half is deliberately shown.

    An Atlassian email address is an identity a disclosure report exists to
    name. Neither of these is.
    """
    for item in run("redis_valid").capabilities:
        assert ACCOUNT not in item.evidence
        assert SECRET not in item.evidence
        assert item.poc is not None
        assert ACCOUNT not in item.poc
        assert SECRET not in item.poc


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_pair_yields_a_capability_map() -> None:
    result = run("redis_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Redis Cloud Account",
        "Redis Cloud Cloud Accounts",
        "Redis Cloud Subscriptions",
    ]


def test_no_capability_claims_a_write_redis_cannot_attribute() -> None:
    """Redis names four roles and publishes no way to ask which this key holds."""
    capabilities = run("redis_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)


def test_the_cidr_allow_list_is_named_rather_than_claimed() -> None:
    """keyreach cannot read the list, so it does not set `restricted`.

    Saying a restriction *may* apply is the honest version of a flag that would
    otherwise lower the severity band on a guess.
    """
    subscriptions = capability(run("redis_valid"), "Redis Cloud Subscriptions")

    assert not subscriptions.restricted
    assert "CIDR allow list" in subscriptions.detail


def test_a_rejected_pair_does_not_conclude_the_keys_are_revoked() -> None:
    """Redis refuses a wrong key and a blocked source address identically.

    And it does so with an nginx HTML page, so there is no message to quote.
    """
    result = run("redis_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert verdict.note.startswith("Redis Cloud did not accept this key pair.")
    assert "CIDR allow list" in verdict.note
    assert result.capabilities == ()


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("redis_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("redis_valid"), run("redis_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic response."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return response(status, body)

        def protect(self, secret: str) -> None:
            del secret

    return asyncio.run(RedisProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_request_still_means_the_pair_reached_redis() -> None:
    verdict = validate_against(429, '{"description":"Too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"description":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_message_is_read_where_redis_sends_one() -> None:
    """The 401 is HTML, but other statuses carry a JSON description."""
    assert message_of(response(403, '{"description":"Forbidden"}')) == "Forbidden"
    assert message_of(response(401, "<html>nginx</html>")) == ""


def test_validation_uses_the_documented_read_that_needs_both_keys() -> None:
    assert validation_probe() in PROBES
    assert validation_probe().url == f"{API}/subscriptions"


@pytest.mark.parametrize(
    ("service", "body", "expected"),
    [
        ("Redis Cloud Subscriptions", '{"subscriptions":[]}', "none present"),
        ("Redis Cloud Subscriptions", '{"nothing":true}', "request accepted"),
        ("Redis Cloud Account", '{"account":{}}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    service: str, body: str, expected: str
) -> None:
    probe = next(item for item in PROBES if item.service == service)

    assert expected in _summary(probe, response(200, body))
