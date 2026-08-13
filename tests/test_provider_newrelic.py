"""New Relic provider tests (roadmap R2.6).

Two things carry the weight here.

**Only the User key ships**, and ``test_detect_claims_nothing_for_a_license_key``
pins that a 40-char hex string — the documented License key shape — is never
claimed, because it is indistinguishable from a SHA-1 hash.

**The live API corrected the REST v2 header.** New Relic's prose says
``Api-Key``; probing the real API showed it silently ignores that header and
reads ``X-Api-Key`` instead. ``test_the_rest_v2_probe_uses_the_confirmed_header``
is the regression test for that finding — see the module docstring.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.newrelic import (
    PROBES,
    NewRelicProvider,
    _account_summary,
    _applications,
    _applications_summary,
    _rest_v2_headers,
    message_of,
    request_context,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
KEY = "NRAK-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

#: The documented License key shape: 40 hex characters, no prefix.
LICENSE_KEY = "ab" * 20


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="newrelic",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int, body: str, url: str = "https://api.newrelic.com/graphql"
) -> ProbeResponse:
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
    validate_provider(NewRelicProvider(), origin="keyreach.providers.newrelic")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "newrelic" in [provider.name for provider in registry.providers()]


def test_it_is_a_monitoring_provider() -> None:
    assert NewRelicProvider().category == "monitoring"


def test_it_claims_no_prior_art() -> None:
    assert NewRelicProvider().credit is None


def test_it_is_a_detection_candidate_for_the_nrak_prefix() -> None:
    assert NewRelicProvider().detect(KEY) > 0.0


@pytest.mark.parametrize(
    "sample", ["", "not-a-key", "NRAK-short", LICENSE_KEY, "nrak-" + "a" * 25]
)
def test_detect_claims_nothing_for_anything_else(sample: str) -> None:
    assert NewRelicProvider().detect(sample) == 0.0


def test_detect_claims_nothing_for_a_license_key() -> None:
    """License keys are 40-char hex with no prefix — too generic to claim."""
    assert NewRelicProvider().detect(LICENSE_KEY) == 0.0


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_capability_map() -> None:
    result = run("newrelic_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "New Relic APM Applications",
        "New Relic Account Context",
    ]


def test_the_user_id_is_the_identity() -> None:
    identity = validation(run("newrelic_valid")).identity

    assert identity is not None
    assert identity.account == "12345"


def test_every_capability_is_read_only_and_masked() -> None:
    for item in run("newrelic_valid").capabilities:
        assert item.access is AccessLevel.READ
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_applications_is_the_one_marked_data_sensitive() -> None:
    capabilities = run("newrelic_valid").capabilities

    assert {c.service for c in capabilities if c.data_sensitive} == {
        "New Relic APM Applications"
    }


def test_the_applications_list_is_counted() -> None:
    apps = capability(run("newrelic_valid"), "New Relic APM Applications")

    assert "applications: 1 listed" in apps.evidence


def test_a_rejected_key_is_reported() -> None:
    result = run("newrelic_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "authentication required" in verdict.note
    assert result.capabilities == ()


def test_an_unrecognised_key_is_rejected_without_a_request() -> None:
    verdict = validation(run("newrelic_invalid", key="not-a-key"))

    assert not verdict.valid
    assert verdict.note == "This does not look like a New Relic User key (NRAK-...)"


def test_enumerate_returns_nothing_for_an_unrecognised_key() -> None:
    capabilities = asyncio.run(NewRelicProvider().enumerate("not-a-key", None))  # type: ignore[arg-type]

    assert capabilities == []


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("newrelic_valid"), run("newrelic_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_probe_table_has_two_entries_with_unique_services() -> None:
    assert len(PROBES) == 2
    assert len({probe.service for probe in PROBES}) == 2


def test_the_rest_v2_probe_uses_the_confirmed_header() -> None:
    """New Relic's prose says `Api-Key`; the live API needs `X-Api-Key`."""
    assert _rest_v2_headers(KEY) == {"X-Api-Key": KEY}


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def test_message_of_reads_nerdgraph_and_rest_v2_shapes() -> None:
    assert (
        message_of(response(401, '{"errors":[{"message":"authentication required"}]}'))
        == "authentication required"
    )
    assert (
        message_of(response(401, '{"error":{"title":"Invalid API Key"}}'))
        == "Invalid API Key"
    )
    assert message_of(response(401, '{"errors":[{"message":5}]}')) == ""
    assert message_of(response(401, '{"error":{"title":5}}')) == ""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""


def test_request_context_is_empty_for_a_malformed_body() -> None:
    assert request_context(response(200, "{}")) == {}
    assert request_context(response(200, '{"data":"not-a-mapping"}')) == {}
    assert request_context(response(200, '{"data":{"requestContext":5}}')) == {}


def test_applications_falls_back_to_a_bare_array_or_none() -> None:
    assert _applications(response(200, '{"applications":[{"id":1}]}')) == [{"id": 1}]
    assert _applications(response(200, '[{"id":1}]')) == [{"id": 1}]
    assert _applications(response(200, '{"not":"recognised"}')) is None
    assert _applications(response(200, "<html>not json</html>")) is None


def test_a_200_without_a_user_id_is_not_a_successful_validation() -> None:
    verdict = asyncio.run(
        NewRelicProvider().validate(KEY, _Stub(200, "{}"))  # type: ignore[arg-type]
    )

    assert not verdict.valid
    assert verdict.note is not None
    assert "not established either way" in verdict.note


def test_account_summary_falls_back_when_no_user_id() -> None:
    assert _account_summary(response(200, "{}")) == "request accepted"


def test_applications_summary_covers_all_three_shapes() -> None:
    assert _applications_summary(response(200, '{"not":"recognised"}')) == (
        "request accepted"
    )
    assert (
        _applications_summary(response(200, '{"applications":[]}'))
        == "applications: none present"
    )
    assert (
        _applications_summary(response(200, '{"applications":[{"id":1}]}'))
        == "applications: 1 listed"
    )


def test_enumerate_skips_the_account_capability_when_nerdgraph_has_no_user_id() -> None:
    class _NerdGraphNoUser:
        async def post(
            self,
            url: str,
            *,
            content: object = None,
            headers: object = None,
            params: object = None,
            read_only_post: bool = False,
        ) -> ProbeResponse:
            del url, content, headers, params, read_only_post
            return response(200, "{}")

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del params, headers
            return ProbeResponse(
                method="GET",
                url=url,
                status_code=200,
                headers={},
                text='{"applications":[]}',
            )

        async def gather(self, awaitables: object) -> list[ProbeResponse]:
            return [await item for item in awaitables]  # type: ignore[attr-defined]

        def mask(self, text: str) -> str:
            return text

        @property
        def key(self) -> str:
            return KEY

    capabilities = asyncio.run(NewRelicProvider().enumerate(KEY, _NerdGraphNoUser()))  # type: ignore[arg-type]

    assert [c.service for c in capabilities] == ["New Relic APM Applications"]


def test_enumerate_skips_a_capability_whose_read_failed() -> None:
    class _AppsFail:
        def __init__(self) -> None:
            self._nerdgraph_hits = 0

        async def post(
            self,
            url: str,
            *,
            content: object = None,
            headers: object = None,
            params: object = None,
            read_only_post: bool = False,
        ) -> ProbeResponse:
            del url, content, headers, params, read_only_post
            return response(200, '{"data":{"requestContext":{"userId":1}}}')

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del params, headers
            return ProbeResponse(
                method="GET",
                url=url,
                status_code=403,
                headers={},
                text="{}",
            )

        async def gather(self, awaitables: object) -> list[ProbeResponse]:
            return [await item for item in awaitables]  # type: ignore[attr-defined]

        def mask(self, text: str) -> str:
            return text

        @property
        def key(self) -> str:
            return KEY

    capabilities = asyncio.run(NewRelicProvider().enumerate(KEY, _AppsFail()))  # type: ignore[arg-type]

    assert [c.service for c in capabilities] == ["New Relic Account Context"]


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
        headers: object = None,
        params: object = None,
        read_only_post: bool = False,
    ) -> ProbeResponse:
        del content, headers, params, read_only_post
        return response(self._status, self._body, url=url)

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return KEY
