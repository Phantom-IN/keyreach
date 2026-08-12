"""Resend provider tests (roadmap R2.3).

Everything that matters here is the **inverted status codes**.

Resend documents ``restricted_api_key`` as a **401** — a live key being told it
may only send email — and ``invalid_api_key`` as a **403**. The live API answers
**400** for a bad key. So the ordinary reading, "401 means the credential is
bad", is wrong in the most expensive direction there is: it retires a key that
can send mail as somebody's verified domain and calls it dead.

``test_a_401_here_means_the_key_works`` and
``test_the_status_resend_really_uses_for_a_bad_key_is_400`` pin both halves, so a
later change that trusts the documentation alone — or that trusts HTTP
convention — fails rather than silently mis-reporting.

**On the fixtures.** Every path was verified against Resend's live API, and the
invalid-key body is the response that API actually returned, verbatim. The
success bodies are constructed from Resend's documented shapes; drift is roadmap
**R2.10**.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.resend import (
    API,
    CONFIDENCE,
    DEAD_KEY_ERRORS,
    PROBES,
    RESTRICTED_ERROR,
    ResendProvider,
    _summary,
    error_of,
    is_restricted,
    message_of,
    rejected,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
KEY = "re" + "_" + "N0rthw1nd" + "_" + "AbCdEfGhIjKlMnOpQrStUvWx"

SEND = "Resend Email Send"


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="resend",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str) -> ProbeResponse:
    """A synthetic response, for the branches a cassette cannot reach cheaply."""
    return ProbeResponse(
        method="GET",
        url=f"{API}/api-keys",
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(ResendProvider(), origin="keyreach.providers.resend")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "resend" in [provider.name for provider in registry.providers()]


def test_it_is_an_email_provider() -> None:
    assert ResendProvider().category == "email"


def test_it_claims_no_prior_art() -> None:
    assert ResendProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_it_claims_a_documented_key() -> None:
    assert ResendProvider().detect(KEY) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-key",
        "re_short",
        # `re` without the underscore is a word, not a prefix.
        "reallylongstringwithnounderscoreatall",
        "sk_" + "live_" + "a" * 24,
    ],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert ResendProvider().detect(sample) == 0.0


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "resend-api-key")

    assert re.match(rule["pattern"], KEY)
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "resend"


def test_the_detector_routes_the_key_to_resend() -> None:
    assert [match.provider for match in default_detector.detect(KEY)] == ["resend"]


# ---------------------------------------------------------------------------
# The inverted status codes — what R2.3 found here
# ---------------------------------------------------------------------------


def test_a_401_here_means_the_key_works() -> None:
    """The opposite of what HTTP convention and this repository's other plugins
    would suggest, which is exactly why it is pinned.

    Resend documents `restricted_api_key` at 401 with "This API key is
    restricted to only send emails". A plugin that treated 401 as a dead
    credential would retire a key that can send mail as somebody's verified
    domain.
    """
    restricted = response(
        401,
        '{"statusCode":401,"message":"This API key is restricted to only send '
        'emails","name":"restricted_api_key"}',
    )

    assert is_restricted(restricted)
    assert not rejected(restricted)
    assert error_of(restricted) == RESTRICTED_ERROR


def test_the_status_resend_really_uses_for_a_bad_key_is_400() -> None:
    """Documented as 403 `invalid_api_key`; observed as 400 `validation_error`.

    Both are treated as a rejection, and the observed one is the fixture, because
    the API is the authority on what the API does.
    """
    observed = response(
        400,
        '{"statusCode":400,"message":"API key is invalid","name":"validation_error"}',
    )
    documented = response(
        403,
        '{"statusCode":403,"message":"API key is invalid","name":"invalid_api_key"}',
    )

    assert rejected(observed)
    assert rejected(documented)
    assert message_of(observed) == "API key is invalid"


def test_both_documented_dead_key_names_and_the_observed_one_are_covered() -> None:
    assert (
        frozenset({"invalid_api_key", "missing_api_key", "validation_error"})
        == DEAD_KEY_ERRORS
    )


def test_a_body_that_is_not_an_object_is_not_a_verdict() -> None:
    """Defensive parsing: an HTML error page must not read as an error name."""
    html = response(502, "<html>bad gateway</html>")

    assert error_of(html) == ""
    assert message_of(html) == ""
    assert not is_restricted(html)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_full_access_key_is_mapped() -> None:
    result = run("resend_valid")

    assert result.valid
    services = [item.service for item in result.capabilities]
    assert services == sorted(services)
    assert "Resend Domains" in services


def test_a_full_access_key_is_a_write_on_resends_own_statement() -> None:
    """`full_access` is documented as create/delete/update over any resource.

    keyreach performs none of those. The access level is the vendor's sentence,
    quoted into the detail so a reader can check the inference.
    """
    domains = capability(run("resend_valid"), "Resend Domains")

    assert domains.access is AccessLevel.WRITE
    assert "create, delete, get and update any resource" in domains.detail


def test_minting_api_keys_is_admin_not_merely_write() -> None:
    assert capability(run("resend_valid"), "Resend API Keys").access is (
        AccessLevel.ADMIN
    )


def test_the_permission_level_is_the_identity_resend_discloses() -> None:
    """Resend publishes no "who am I" endpoint, and keyreach invents none."""
    identity = validation(run("resend_valid")).identity

    assert identity is not None
    assert identity.account is None
    assert identity.extra == {"permission": "full_access"}


def test_a_sending_only_key_is_live_and_says_what_it_can_do() -> None:
    """The finding this plugin exists to get right.

    Four refusals and no readable resource. An empty report would read as a
    harmless credential; what Resend actually said is that this key can send
    email as the account.
    """
    result = run("resend_sending_only")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.note is not None
    assert "restricted to sending email" in verdict.note
    assert verdict.identity is not None
    assert verdict.identity.extra == {"permission": "sending_access"}

    assert [item.service for item in result.capabilities] == [SEND]


def test_the_send_capability_is_derived_and_nothing_was_sent() -> None:
    for fixture in ("resend_valid", "resend_sending_only"):
        send = capability(run(fixture), SEND)

        assert send.access is AccessLevel.WRITE
        assert send.incurs_cost
        assert "No message was sent" in send.detail
        assert send.poc is not None
        # The proof of concept reaches a read endpoint, never the send endpoint.
        assert send.poc.startswith("curl -s")
        assert "/emails" not in send.poc


def test_a_rejected_key_is_reported_as_rejected() -> None:
    result = run("resend_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "did not accept" in verdict.note
    assert "API key is invalid" in verdict.note
    assert result.capabilities == ()


def test_validation_reuses_a_probe_endpoint() -> None:
    """And the one whose *refusal* is informative — see the module docstring."""
    assert validation_probe() in PROBES
    assert validation_probe().url == f"{API}/api-keys"


def test_the_key_never_appears_in_any_output() -> None:
    for item in run("resend_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("resend_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("resend_valid"), run("resend_valid")

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
            self,
            url: str,
            *,
            params: object = None,
            headers: object = None,
        ) -> ProbeResponse:
            del url, params, headers
            return response(status, body)

    return asyncio.run(ResendProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_request_still_means_the_key_reached_resend() -> None:
    verdict = validate_against(
        429,
        '{"statusCode":429,"message":"Too many requests","name":"rate_limit_exceeded"}',
    )

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(
        500,
        '{"statusCode":500,"message":"internal error","name":"internal_server_error"}',
    )

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_rate_limited_key_endpoint_claims_no_send_capability() -> None:
    """The permission level was never established, so nothing is claimed from it.

    `/api-keys` is both the liveness check and the only thing that separates
    `full_access` from `sending_access`. When it is the one call Resend throttles,
    the other reads still succeed — and the send capability, which rests entirely
    on knowing the permission level, is correctly absent.
    """
    result = run("resend_rate_limited")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note

    services = [item.service for item in result.capabilities]
    assert SEND not in services
    assert "Resend Domains" in services


def test_a_response_with_no_data_list_reads_as_accepted() -> None:

    assert _summary(PROBES[0], response(200, '{"object":"list"}')) == "request accepted"
