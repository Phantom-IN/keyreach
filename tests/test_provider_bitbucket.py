"""Bitbucket provider tests (roadmap R2.4).

Two things carry the weight here.

**Only the secret half is masked, and that is deliberate.** Bitbucket
authenticates with `<atlassian email>:<api token>`, and
``test_the_identifier_is_reported_and_only_the_secret_is_masked`` pins the
asymmetry: an email address is not a secret, it is the identity a disclosure
report exists to name, and masking it would make the finding useless to whoever
receives it. The token half is registered with the redactor — which matters
because ``/user/emails`` echoes the address straight back, the same shape that
made R1.3 add ``ctx.protect`` for credential *parts*.

**Bitbucket documents a scope vocabulary and no way to read it.**
``test_no_capability_claims_a_write_bitbucket_cannot_attribute`` records the
consequence. GitHub sends `X-OAuth-Scopes`; GitLab and SendGrid expose an
introspection resource; Bitbucket does neither, so the sentence that would
justify a write exists and cannot be attached to this credential.

``test_no_probe_uses_an_endpoint_atlassian_marks_deprecated`` guards the third
decision: `/repositories`, `/workspaces` and `/user/permissions/*` all still
answer and are all deprecated in Atlassian's own specification. A finding built
on one of those disappears without notice.

**On the fixtures.** Every path comes from Atlassian's OpenAPI specification and
was verified against the live API. The bodies are constructed from the
specification's schemas; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.bitbucket import (
    API,
    PROBES,
    BitbucketProvider,
    Credential,
    _identity,
    _summary,
    message_of,
    parse_credential,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
EMAIL = "a.maintainer@northwind.example"
SECRET = "N0rthw1nd" + "B1tbucket" + "T0ken00000"
KEY = EMAIL + ":" + SECRET


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="bitbucket",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str, url: str = f"{API}/user") -> ProbeResponse:
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
    validate_provider(BitbucketProvider(), origin="keyreach.providers.bitbucket")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "bitbucket" in [provider.name for provider in registry.providers()]


def test_it_is_a_devtools_provider() -> None:
    assert BitbucketProvider().category == "devtools"


def test_it_claims_no_prior_art() -> None:
    assert BitbucketProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """Atlassian publishes no format for an API token or an app password."""
    assert BitbucketProvider().detectable is False


@pytest.mark.parametrize(
    "sample",
    [
        KEY,
        "",
        "not-a-key",
        # The shape a guessed rule would have to match, and why it cannot exist.
        "someone@example.invalid:" + "x" * 32,
        "x" * 24 + ":" + "y" * 32,
    ],
)
def test_detect_claims_nothing_at_all(sample: str) -> None:
    """A rule for "any string, colon, any string" would claim every composite
    credential keyreach has ever been handed."""
    assert BitbucketProvider().detect(sample) == 0.0


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (KEY, Credential(EMAIL, SECRET)),
        # A secret containing a colon survives, because the split is on the first.
        ("user:a:b", Credential("user", "a:b")),
        (SECRET, None),
        (":" + SECRET, None),
        (EMAIL + ":", None),
    ],
)
def test_the_credential_is_split_on_the_first_colon(
    key: str, expected: Credential | None
) -> None:
    assert parse_credential(key) == expected


def test_a_lone_secret_is_answered_without_a_request() -> None:
    """A request keyreach cannot authenticate says nothing about the secret."""
    verdict = validation(run("bitbucket_invalid", key=SECRET))

    assert not verdict.valid
    assert verdict.note is not None
    assert "No request was made" in verdict.note
    assert "<atlassian email or username>:<api token>" in verdict.note


# ---------------------------------------------------------------------------
# Probe table hygiene
# ---------------------------------------------------------------------------


def test_every_probe_is_under_the_documented_api_base() -> None:
    for probe in PROBES:
        assert probe.url.startswith(API)


def test_no_probe_uses_an_endpoint_atlassian_marks_deprecated() -> None:
    """All of these still answer, and all are deprecated with named replacements.

    A finding built on a deprecated endpoint disappears without notice, which is
    the drift **R2.10** exists to catch rather than to create.
    """
    deprecated = (
        f"{API}/repositories",
        f"{API}/workspaces",
        f"{API}/user/permissions/repositories",
        f"{API}/user/permissions/workspaces",
    )

    for probe in PROBES:
        assert probe.url not in deprecated


def test_validation_uses_the_read_that_names_nobody_else() -> None:
    assert validation_probe() in PROBES
    assert validation_probe().url == f"{API}/user"


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_credential_is_mapped() -> None:
    result = run("bitbucket_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Bitbucket Account",
        "Bitbucket Email Addresses",
        "Bitbucket Workspaces",
    ]


def test_no_capability_claims_a_write_bitbucket_cannot_attribute() -> None:
    """The scope vocabulary exists; the means to attribute it does not."""
    capabilities = run("bitbucket_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("repository:admin" in item.detail for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)


def test_the_identifier_is_reported_and_only_the_secret_is_masked() -> None:
    """The asymmetry is the point.

    An email address is not a secret — it is the account the recipient has to go
    and lock, and masking it would make the report useless. The token half is
    registered with the redactor, which matters because `/user/emails` echoes an
    address straight back.
    """
    result = run("bitbucket_valid")
    identity = validation(result).identity

    assert identity is not None
    assert identity.extra["identifier"] == EMAIL
    assert identity.owner == "A Maintainer"

    for item in result.capabilities:
        assert SECRET not in item.evidence
        assert item.poc is not None
        assert SECRET not in item.poc


def test_the_email_probe_is_marked_sensitive() -> None:
    emails = capability(run("bitbucket_valid"), "Bitbucket Email Addresses")

    assert emails.data_sensitive
    assert "email addresses: 1 listed" in emails.evidence


def test_a_rejected_credential_says_the_identifier_might_be_the_problem() -> None:
    """Bitbucket rejects a wrong email and a dead token identically.

    And it says nothing about which: the real 401 is `content-type: text/plain`
    with a zero-length body, so there is no message to quote. The first draft of
    this fixture invented a JSON error envelope, which would have made this test
    pass forever while describing a response Bitbucket does not send — found by
    running the binary against the live API, which is now the fourth item where
    that step caught something reading could not.
    """
    verdict = validation(run("bitbucket_invalid"))

    assert not verdict.valid
    assert verdict.note is not None
    # No parenthetical, because Bitbucket supplied no message to put in one.
    assert verdict.note.startswith(
        "Bitbucket did not accept this identifier and secret."
    )
    assert "check the account name or email" in verdict.note


def test_the_error_envelope_is_still_read_where_bitbucket_sends_one() -> None:
    """401 is bare; other statuses carry `{"error": {"message": …}}`.

    Both halves matter: dropping the parser because the 401 is empty would lose
    the message on every refusal that does have one.
    """
    assert (
        message_of(response(403, '{"type":"error","error":{"message":"Forbidden"}}'))
        == "Forbidden"
    )
    assert message_of(response(401, "")) == ""


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("bitbucket_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("bitbucket_valid"), run("bitbucket_valid")

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

    return asyncio.run(BitbucketProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_endpoint_still_means_the_credential_is_live() -> None:
    verdict = validate_against(403, '{"type":"error","error":{"message":"Forbidden"}}')

    assert verdict.valid
    assert verdict.note is not None
    assert "lower bound" in verdict.note


def test_a_rate_limited_request_still_means_the_credential_reached_bitbucket() -> None:
    verdict = validate_against(429, '{"type":"error","error":{"message":"Slow down"}}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(
        500, '{"type":"error","error":{"message":"internal error"}}'
    )

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


@pytest.mark.parametrize(
    "body",
    [
        "<html>bad gateway</html>",
        '{"error":"not an object"}',
        '{"error":{"message":1}}',
    ],
)
def test_a_malformed_error_body_is_not_a_message(body: str) -> None:
    """Defensive parsing: a proxy's HTML must not become an error message."""
    assert message_of(response(502, body)) == ""


def test_an_identity_omits_fields_bitbucket_did_not_send() -> None:
    """An absent field must not become an empty string in the report."""

    identity = _identity(Credential(EMAIL, SECRET), response(200, '{"type":"user"}'))

    assert identity.extra == {"identifier": EMAIL}
    assert identity.account is None
    assert identity.owner is None


@pytest.mark.parametrize(
    ("service", "body", "expected"),
    [
        ("Bitbucket Account", "{}", "request accepted"),
        ("Bitbucket Workspaces", '{"values":[]}', "none present"),
        ("Bitbucket Workspaces", '{"size":0}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    service: str, body: str, expected: str
) -> None:
    probe = next(item for item in PROBES if item.service == service)

    assert expected in _summary(probe, response(200, body))
