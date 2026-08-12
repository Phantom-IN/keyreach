"""Zoom provider tests (roadmap R2.2).

Zoom is keyreach's second OAuth client-credentials provider and its second
three-part credential. The tests that carry the most weight are the ones about
the **scope grammar**: Zoom documents granular scopes as
``resource:operation:action:role``, so access levels are derived from a rule
rather than from a checked-in list of scope names that would be stale within a
release.

``test_the_operation_segment_decides_the_access_level`` covers the rule, and
``test_a_scope_does_not_elevate_a_resource_it_does_not_cover`` keeps it honest —
a credential that can write users is not thereby claimed to write recordings.

**On the fixtures.** The API base, every path and the error shape were confirmed
against Zoom's live API; the token exchange and scope grammar come from Zoom's
documentation. Drift is roadmap **R2.10**.
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
from keyreach.providers.zoom import (
    _REJECTED_STATUSES,
    GRANT_TYPE,
    PROBES,
    TOKEN_URL,
    WRITE_OPERATIONS,
    ZoomProvider,
    _summary,
    access_for,
    access_token,
    granted_writes,
    message_of,
    parse_credential,
    parse_scope,
    scopes_of,
    token_body,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
ACCOUNT_ID = "acct-northwind"
CLIENT_ID = "NwClient" + "Identifier01"
CLIENT_SECRET = "NwClient" + "Secret0000000001"
CREDENTIAL = f"{ACCOUNT_ID}:{CLIENT_ID}:{CLIENT_SECRET}"


def run(fixture: str, key: str = CREDENTIAL) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="zoom",
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Metadata and the opt-out
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(ZoomProvider(), origin="keyreach.providers.zoom")


def test_the_registry_discovers_it() -> None:
    assert "zoom" in [p.name for p in ProviderRegistry("keyreach.providers")]


def test_it_is_a_comms_provider() -> None:
    assert ZoomProvider().category == "comms"


def test_it_claims_no_prior_art() -> None:
    assert ZoomProvider().credit is None


def test_it_is_deliberately_undetectable() -> None:
    """R2.1 framed this as a payment problem; Zoom shows it is not."""
    assert ZoomProvider().detectable is False


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(CREDENTIAL, id="a-real-looking-credential"),
        pytest.param("", id="empty"),
        pytest.param(
            "ASIA" + "A" * 16 + ":" + "s" * 40 + ":" + "t" * 40, id="aws-temp"
        ),
    ],
)
def test_detect_claims_nothing_at_all(candidate: str) -> None:
    """A "three colon-joined opaque strings" rule would claim AWS temporary
    credentials, which are exactly that shape and already detected by prefix."""
    assert ZoomProvider().detect(candidate) == 0.0


def test_no_detection_rule_names_zoom() -> None:
    assert "zoom" not in {rule.provider for rule in default_detector.rules()}


def test_naming_the_provider_records_that_it_was_asserted() -> None:
    assert any("Detection was overridden" in n for n in run("zoom_valid").notes)


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# The three-part credential
# ---------------------------------------------------------------------------


def test_the_credential_splits_in_the_documented_order() -> None:
    credential = parse_credential(CREDENTIAL)

    assert credential is not None
    assert credential.account_id == ACCOUNT_ID
    assert credential.client_id == CLIENT_ID
    assert credential.client_secret == CLIENT_SECRET


def test_a_secret_containing_a_colon_keeps_it() -> None:
    """The last field takes the remainder; truncating it would produce a
    credential that cannot authenticate, reported as "Zoom rejected this"."""
    credential = parse_credential(f"{ACCOUNT_ID}:{CLIENT_ID}:{CLIENT_SECRET}:x")

    assert credential is not None
    assert credential.client_secret == f"{CLIENT_SECRET}:x"


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(f"{ACCOUNT_ID}:{CLIENT_ID}", id="only-two-parts"),
        pytest.param(ACCOUNT_ID, id="one-part"),
        pytest.param(f"{ACCOUNT_ID}:short:{CLIENT_SECRET}", id="a-part-too-short"),
    ],
)
def test_an_unusable_credential_is_rejected_before_any_request(candidate: str) -> None:
    assert parse_credential(candidate) is None


def test_a_credential_with_the_wrong_shape_is_reported_without_probing() -> None:
    result = run("zoom_valid", ACCOUNT_ID)

    assert not result.valid
    assert result.capabilities == ()
    assert "three values" in result.outcomes[0].validation.note


def test_the_token_request_is_the_documented_one() -> None:
    credential = parse_credential(CREDENTIAL)
    assert credential is not None

    assert TOKEN_URL == "https://zoom.us/oauth/token"  # noqa: S105 - a URL
    assert token_body(credential) == f"grant_type={GRANT_TYPE}&account_id={ACCOUNT_ID}"
    assert GRANT_TYPE == "account_credentials"


def test_the_token_is_minted_once_per_run() -> None:
    """The R2.1 cache change, relied on by a second provider."""

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "zoom_valid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, CREDENTIAL)
            provider = ZoomProvider()
            await provider.validate(CREDENTIAL, context)
            after_validate = client.requests_made
            await provider.enumerate(CREDENTIAL, context)
            return after_validate, client.requests_made

    mints, total = asyncio.run(measure())

    assert mints == 1
    assert total == 1 + len(PROBES)


# ---------------------------------------------------------------------------
# The scope grammar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "resource", "operation"),
    [
        pytest.param("user:read:list_users:admin", "user", "read", id="granular-read"),
        pytest.param(
            "meeting:write:meeting:admin", "meeting", "write", id="granular-write"
        ),
        pytest.param("user:read:admin", "user", "read", id="classic"),
        pytest.param("meeting:delete:meeting", "meeting", "delete", id="delete"),
    ],
)
def test_a_scope_splits_into_resource_and_operation(
    scope: str, resource: str, operation: str
) -> None:
    parsed = parse_scope(scope)

    assert parsed is not None
    assert parsed.resource == resource
    assert parsed.operation == operation


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param("user", id="no-operation"),
        pytest.param("", id="empty"),
        pytest.param(":read:x", id="no-resource"),
        pytest.param("user::x", id="empty-operation"),
    ],
)
def test_a_malformed_scope_is_ignored_rather_than_guessed_at(scope: str) -> None:
    assert parse_scope(scope) is None


def test_the_operation_segment_decides_the_access_level() -> None:
    """Read out of the scope name, not from a list that would go stale."""
    users = next(p for p in PROBES if p.service == "Zoom Account Users")

    assert access_for(users, ("user:read:list_users:admin",)) is AccessLevel.READ
    assert access_for(users, ("user:write:user:admin",)) is AccessLevel.WRITE
    assert access_for(users, ("user:update:user",)) is AccessLevel.WRITE
    assert access_for(users, ("user:delete:user",)) is AccessLevel.WRITE
    assert access_for(users, ()) is AccessLevel.READ


def test_every_write_operation_is_covered() -> None:
    assert set(WRITE_OPERATIONS) == {"write", "update", "delete"}


def test_a_scope_does_not_elevate_a_resource_it_does_not_cover() -> None:
    """A credential that can write users cannot thereby write recordings."""
    capabilities = {c.service: c for c in run("zoom_valid").capabilities}

    assert capabilities["Zoom Account Users"].access is AccessLevel.WRITE
    assert capabilities["Zoom Cloud Recordings"].access is AccessLevel.READ
    assert capabilities["Zoom Meetings"].access is AccessLevel.READ
    assert "No granted scope gives more than read" in (
        capabilities["Zoom Cloud Recordings"].detail
    )


def test_the_granted_write_scope_is_named_in_the_detail() -> None:
    users = next(
        c for c in run("zoom_valid").capabilities if c.service == "Zoom Account Users"
    )

    assert "user:write:user:admin" in users.detail
    assert "No write was attempted" in users.detail


def test_granted_writes_reports_only_matching_resources() -> None:
    users = next(p for p in PROBES if p.service == "Zoom Account Users")
    scopes = ("user:write:user:admin", "meeting:write:meeting", "bad")

    assert granted_writes(users, scopes) == ("user:write:user:admin",)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        pytest.param(None, (), id="not-a-mapping"),
        pytest.param({}, (), id="no-scope-field"),
        pytest.param({"scope": 7}, (), id="not-a-string"),
        pytest.param({"scope": ""}, (), id="granted-nothing"),
        pytest.param(
            {"scope": "b:read a:read a:read"}, ("a:read", "b:read"), id="sorted"
        ),
    ],
)
def test_scope_parsing_reads_the_documented_field(
    payload: object, expected: tuple[str, ...]
) -> None:
    """Sorted and de-duplicated, so a set's order never reaches a report."""
    assert scopes_of(payload) == expected


# ---------------------------------------------------------------------------
# The findings this provider exists to produce
# ---------------------------------------------------------------------------


def test_a_credential_with_a_write_scope_over_user_data_is_critical() -> None:
    result = run("zoom_valid")

    assert result.valid
    assert result.score.severity is Severity.CRITICAL
    assert [c.service for c in result.capabilities] == [
        "Zoom Account Users",
        "Zoom Cloud Recordings",
        "Zoom Groups",
        "Zoom Identity",
        "Zoom Meetings",
    ]


def test_a_read_only_credential_is_a_weaker_finding() -> None:
    result = run("zoom_read_only")

    assert result.score.severity is Severity.HIGH
    assert all(c.access is AccessLevel.READ for c in result.capabilities)


def test_the_account_and_its_scopes_are_named() -> None:
    identity = run("zoom_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == ACCOUNT_ID
    assert "user:write:user:admin" in identity.extra["scopes"]


def test_the_scope_count_is_pluralised() -> None:
    assert "granted 5 scopes" in run("zoom_valid").outcomes[0].validation.note


def test_recordings_are_listed_but_never_downloaded() -> None:
    recordings = next(
        c
        for c in run("zoom_valid").capabilities
        if c.service == "Zoom Cloud Recordings"
    )

    assert recordings.data_sensitive
    assert "were not downloaded" in recordings.detail


def test_no_capability_claims_spend() -> None:
    """Zoom bills per licence, not per API call, and keyreach starts no meeting."""
    assert not any(c.incurs_cost for c in run("zoom_valid").capabilities)


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_credential_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("zoom_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "Invalid client_id or client_secret" in result.outcomes[0].validation.note


def test_the_status_zoom_really_uses_for_a_bad_credential_is_a_verdict() -> None:
    """Found by running the binary, not by reading the specification.

    Zoom's token endpoint answers **400** for `invalid_client`, not 401. RFC 6749
    permits either, and an earlier draft of this plugin branched only on 401/403
    — so a credential Zoom had plainly rejected came back as "Zoom's response
    could not be interpreted". A confident non-answer about a dead credential is
    the failure mode `validate` exists to avoid.

    Safe to treat as a credential verdict because keyreach always sends the same
    documented body, so a 400 here is never about the request being malformed.
    """
    assert frozenset({400, 401, 403}) == _REJECTED_STATUSES

    for status in sorted(_REJECTED_STATUSES):
        result = validate_against(
            status, {"reason": "Invalid client_id or client_secret"}
        )

        assert not result.valid, status  # type: ignore[attr-defined]
        assert "did not accept" in result.note, status  # type: ignore[attr-defined]


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
                url=TOKEN_URL,
                status_code=status,
                text=json.dumps(payload),
            )

        def protect(self, secret: str) -> None:
            del secret

    return asyncio.run(ZoomProvider().validate(CREDENTIAL, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_exchange_still_means_the_credential_reached_zoom() -> None:
    result = validate_against(429, {"message": "Too many requests"})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"message": "Internal error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "Internal error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_credential_granted_no_scopes_says_it_reaches_nothing() -> None:
    result = validate_against(200, {"access_token": "t", "scope": ""})

    assert result.valid  # type: ignore[attr-defined]
    assert "granted no scopes" in result.note  # type: ignore[attr-defined]
    assert result.identity.extra == {"scopes": "none"}  # type: ignore[attr-defined]


def test_a_single_scope_is_not_pluralised() -> None:
    result = validate_against(200, {"access_token": "t", "scope": "user:read:admin"})

    assert "granted 1 scope" in result.note  # type: ignore[attr-defined]


def test_enumerate_returns_nothing_for_an_unusable_credential() -> None:
    context = ProbeContext(ProbeClient(), ACCOUNT_ID)

    assert asyncio.run(ZoomProvider().enumerate(ACCOUNT_ID, context)) == []


def test_enumerate_returns_nothing_when_the_exchange_fails() -> None:
    """`enumerate` runs only after a valid `validate`, but must not assume it."""

    async def probe() -> list[object]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "zoom_invalid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, CREDENTIAL)
            return list(await ZoomProvider().enumerate(CREDENTIAL, context))

    assert asyncio.run(probe()) == []


# ---------------------------------------------------------------------------
# Parsing, determinism and hygiene
# ---------------------------------------------------------------------------


def test_the_token_is_read_from_the_response() -> None:
    response = ProbeResponse(
        method="POST", url="u", status_code=200, text='{"access_token":"abc"}'
    )

    assert access_token(response) == "abc"
    assert access_token(ProbeResponse(method="POST", url="u", status_code=200)) == ""


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param('{"message":7}', id="not-a-string"),
    ],
)
def test_message_parsing_degrades_instead_of_raising(body: str) -> None:
    assert (
        message_of(ProbeResponse(method="GET", url="u", status_code=401, text=body))
        == ""
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"page_size":1}', "request accepted", id="no-collection"),
        pytest.param('{"users":"x"}', "request accepted", id="not-a-list"),
        pytest.param('{"users":[]}', "users: none present", id="empty"),
        pytest.param('{"users":[1]}', "users: 1 listed", id="one"),
        pytest.param('{"users":[1,2]}', "users: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    users = next(p for p in PROBES if p.service == "Zoom Account Users")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(users, response) == expected


def test_a_probe_with_no_collection_reports_acceptance() -> None:
    identity = next(p for p in PROBES if p.service == "Zoom Identity")
    response = ProbeResponse(method="GET", url="u", status_code=200, text='{"id":"1"}')

    assert _summary(identity, response) == "request accepted"


def test_repeated_runs_are_identical() -> None:
    first, second = run("zoom_valid"), run("zoom_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("zoom_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_records_and_does_not_quote_them() -> None:
    users = next(
        c for c in run("zoom_valid").capabilities if c.service == "Zoom Account Users"
    )

    assert "users: 1 listed" in users.evidence
    assert "ops@northwind.example" not in users.evidence


def test_the_proof_of_concept_does_not_ship_the_secret_as_base64() -> None:
    blob = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode("ascii")

    for capability in run("zoom_valid").capabilities:
        assert capability.poc is not None
        assert blob not in capability.poc
        assert CLIENT_SECRET not in capability.poc
        assert "<key>" in capability.poc


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("zoom_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    assert len({p.service for p in PROBES}) == len(PROBES)


def test_no_committed_fixture_contains_the_secret() -> None:
    for name in ("valid", "read_only", "invalid"):
        text = (FIXTURES / f"zoom_{name}.json").read_text(encoding="utf-8")

        assert CLIENT_SECRET not in text
        assert CREDENTIAL not in text
