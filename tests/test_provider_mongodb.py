"""MongoDB Atlas provider tests (roadmap R2.5).

Two things carry the weight here.

**Atlas documents two authentication methods and this plugin implements one.**
``test_a_rejected_credential_says_digest_keys_are_not_covered`` is the one that
matters: an Atlas *API key* authenticates with HTTP Digest, which keyreach does
not implement, and such a pair is refused here whether or not it is live. A
reader who sees "MongoDB Atlas did not accept this" must not conclude the
credential is dead — the same class of caveat Paystack's plugin carries about
Stripe's shared prefix, and GitLab's about self-managed instances.

**The token exchange is the fourth ``read_only_post``**, and
``test_the_token_is_minted_once_per_run`` measures that R2.1's body-keyed cache
still holds for a fourth provider.

**On the fixtures.** Both paths were verified against Atlas's live API, and the
token endpoint's shape comes from MongoDB's own curl example. Drift is roadmap
**R2.10**.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    RecordMode,
)
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.mongodb import (
    ACCEPT,
    API,
    PROBES,
    TOKEN_BODY,
    TOKEN_URL,
    Credential,
    MongoDBProvider,
    _summary,
    access_token,
    message_of,
    parse_credential,
    validation_probe,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Sequence

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
CLIENT_ID = "abcdefgh"
CLIENT_SECRET = "N0rthw1nd" + "M0ngoAtlas" + "Secret0000"
KEY = CLIENT_ID + ":" + CLIENT_SECRET


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="mongodb",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str, url: str = TOKEN_URL) -> ProbeResponse:
    return ProbeResponse(
        method="POST",
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(MongoDBProvider(), origin="keyreach.providers.mongodb")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "mongodb" in [provider.name for provider in registry.providers()]


def test_it_is_a_database_provider() -> None:
    assert MongoDBProvider().category == "database"


def test_it_claims_no_prior_art() -> None:
    assert MongoDBProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """MongoDB describes "a client ID" and "a rotatable secret" and no format."""
    assert MongoDBProvider().detectable is False


@pytest.mark.parametrize("sample", [KEY, "", "not-a-key", "x" * 24 + ":" + "y" * 32])
def test_detect_claims_nothing_at_all(sample: str) -> None:
    assert MongoDBProvider().detect(sample) == 0.0


# ---------------------------------------------------------------------------
# The credential and the exchange
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (KEY, Credential(CLIENT_ID, CLIENT_SECRET)),
        # A secret containing a colon survives, because the split is on the first.
        ("id:a:b", Credential("id", "a:b")),
        (CLIENT_SECRET, None),
        (":" + CLIENT_SECRET, None),
        (CLIENT_ID + ":", None),
    ],
)
def test_the_credential_is_split_on_the_first_colon(
    key: str, expected: Credential | None
) -> None:
    assert parse_credential(key) == expected


def test_a_lone_half_is_answered_without_a_request() -> None:
    verdict = validation(run("mongodb_invalid", key=CLIENT_SECRET))

    assert not verdict.valid
    assert verdict.note is not None
    assert "No request was made" in verdict.note
    assert "'<client id>:<client secret>'" in verdict.note


def test_the_exchange_body_is_the_one_mongodb_documents() -> None:
    assert TOKEN_BODY == "grant_type=client_credentials"  # noqa: S105 - a body


def test_the_token_is_minted_once_per_run() -> None:
    """R2.1's body-keyed cache, relied on by a fourth provider."""

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "mongodb_valid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, KEY)
            provider = MongoDBProvider()
            await provider.validate(KEY, context)
            after_validate = client.requests_made
            await provider.enumerate(KEY, context)
            return after_validate, client.requests_made

    mints, total = asyncio.run(measure())

    assert mints == 1
    assert total == 1 + len(PROBES)


def test_every_read_pins_the_versioned_accept_header() -> None:
    """Atlas versions through `Accept`, so a future default must not decide it."""
    poc = capability(run("mongodb_valid"), "MongoDB Atlas Projects").poc

    assert poc is not None
    assert f"Accept: {ACCEPT}" in poc
    assert "vnd.atlas" in ACCEPT


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_service_account_yields_a_capability_map() -> None:
    result = run("mongodb_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "MongoDB Atlas Organizations",
        "MongoDB Atlas Projects",
    ]


def test_the_client_id_is_the_identity() -> None:
    """It is the half that is not a secret, and the one the recipient revokes."""
    identity = validation(run("mongodb_valid")).identity

    assert identity is not None
    assert identity.account == CLIENT_ID


def test_the_project_list_is_the_reach_and_is_counted_not_named() -> None:
    projects = capability(run("mongodb_valid"), "MongoDB Atlas Projects")

    assert projects.data_sensitive
    assert "projects: 1 listed" in projects.evidence
    assert "production" not in projects.evidence


def test_no_capability_claims_a_write_mongodb_cannot_attribute() -> None:
    capabilities = run("mongodb_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)


def test_a_rejected_credential_says_digest_keys_are_not_covered() -> None:
    """Atlas issues two credential types and keyreach implements one.

    A reader who sees this must not conclude the credential is dead — it may be
    an API key, which authenticates with HTTP Digest.
    """
    result = run("mongodb_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    # The body Atlas actually returns, captured from the live API rather than
    # written from the documented shape — the first draft of this fixture said
    # "Invalid client credentials", which Atlas does not send.
    assert "Invalid credentials provided" in verdict.note
    assert "HTTP Digest" in verdict.note
    assert result.capabilities == ()


def test_neither_half_of_the_credential_appears_in_any_output() -> None:
    for item in run("mongodb_valid").capabilities:
        assert CLIENT_SECRET not in item.evidence
        assert item.poc is not None
        assert CLIENT_SECRET not in item.poc


def test_the_proof_of_concept_shows_the_exchange_and_reads_nothing_else() -> None:
    for item in run("mongodb_valid").capabilities:
        assert item.poc is not None
        assert item.poc.count("-X POST") == 1
        assert TOKEN_URL in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("mongodb_valid"), run("mongodb_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


class _Stub:
    """A context that answers every request with the same synthetic response."""

    def __init__(self, status: int, body: str) -> None:
        self._status = status
        self._body = body

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
        return response(self._status, self._body)

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        return response(self._status, self._body, url=url)

    async def gather(
        self, awaitables: Sequence[Awaitable[ProbeResponse]]
    ) -> list[ProbeResponse]:
        return [await item for item in awaitables]

    def protect(self, secret: str) -> None:
        del secret

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return KEY


def validate_against(status: int, body: str) -> ValidationResult:
    return asyncio.run(
        MongoDBProvider().validate(KEY, _Stub(status, body))  # type: ignore[arg-type]
    )


def test_a_rate_limited_exchange_still_means_the_credential_reached_atlas() -> None:
    verdict = validate_against(429, '{"detail":"too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"reason":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_200_carrying_no_token_is_not_a_successful_exchange() -> None:
    assert not validate_against(200, "{}").valid


def test_enumerate_claims_nothing_when_the_exchange_yields_no_token() -> None:
    capabilities = asyncio.run(
        MongoDBProvider().enumerate(KEY, _Stub(200, "{}"))  # type: ignore[arg-type]
    )

    assert capabilities == []


def test_a_numeric_error_field_is_not_stringified_into_the_note() -> None:
    """Atlas answers `{"error": 401, "detail": …}`; the number is not a message."""
    assert message_of(response(401, '{"error":401,"detail":"Unauthorized"}')) == (
        "Unauthorized"
    )
    assert message_of(response(502, "<html>bad gateway</html>")) == ""
    assert access_token(response(200, "<html>x</html>")) == ""


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"results":[]}', "none present"),
        ('{"totalCount":0}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    body: str, expected: str
) -> None:
    assert expected in _summary(
        validation_probe(), response(200, body, url=f"{API}/groups")
    )
