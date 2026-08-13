"""Datadog provider tests (roadmap R2.6).

Two things carry the weight here.

**Each half of the credential is independently meaningful**, unlike every
composite credential keyreach met before this item.
``test_a_bare_api_key_validates_but_enumerates_to_nothing`` is the test that
matters: Datadog's own docs distinguish "write needs an API key" from "read
needs both", so a bare API key is a real, live credential, not a
"recognised, reported, and not probed" half like Docker Hub's or AWS's.

**The live API answers a status Datadog's own OpenAPI spec never documents.**
``test_a_rejected_credential_is_reported_even_though_the_spec_omits_401``
pins ``401`` alongside the spec's documented ``403`` — found by probing the
real API, the same way R2.5 found MongoDB Atlas's actual rejection message.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.datadog import (
    PROBES,
    Credential,
    DatadogProvider,
    _identity,
    _org_id,
    _payload,
    _summary,
    message_of,
    parse_credential,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Sequence

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
API_KEY = "d0d1" + "d0d1d0d1d0d1d0d1d0d1d0d1d0d1d0d1"
APP_KEY = "a9a9a9a9" + "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9"
KEY = API_KEY + ":" + APP_KEY


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="datadog",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int, body: str, url: str = "https://api.datadoghq.com/api/v2/validate"
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
    validate_provider(DatadogProvider(), origin="keyreach.providers.datadog")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "datadog" in [provider.name for provider in registry.providers()]


def test_it_is_a_monitoring_provider() -> None:
    assert DatadogProvider().category == "monitoring"


def test_it_claims_no_prior_art() -> None:
    assert DatadogProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """Datadog documents no prefix, length or charset for either key."""
    assert DatadogProvider().detectable is False


@pytest.mark.parametrize("sample", [KEY, "", "not-a-key", API_KEY])
def test_detect_claims_nothing_at_all(sample: str) -> None:
    assert DatadogProvider().detect(sample) == 0.0


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (KEY, Credential(API_KEY, APP_KEY)),
        # A bare API key is accepted — see the module docstring.
        (API_KEY, Credential(API_KEY, "")),
        # A secret containing a colon survives, because the split is on the first.
        ("apikeyapikey:a:b", Credential("apikeyapikey", "a:b")),
        ("", None),
        (":" + APP_KEY, None),
    ],
)
def test_the_credential_is_split_on_the_first_colon(
    key: str, expected: Credential | None
) -> None:
    assert parse_credential(key) == expected


def test_a_lone_too_short_string_is_answered_without_a_request() -> None:
    verdict = validation(run("datadog_invalid", key="short"))

    assert not verdict.valid
    assert verdict.note is not None
    assert "does not look like a Datadog API key" in verdict.note


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_capability_map() -> None:
    result = run("datadog_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Datadog Dashboards",
        "Datadog Monitors",
        "Datadog Roles",
        "Datadog Users",
    ]


def test_the_org_id_is_the_identity() -> None:
    identity = validation(run("datadog_valid")).identity

    assert identity is not None
    assert identity.account == "550e8400-e29b-41d4-a716-446655440000"
    assert identity.extra["api_key_id"] == "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6"
    assert "dashboards_read" in identity.extra["api_key_scopes"]


def test_every_capability_is_read_only_and_masked() -> None:
    for item in run("datadog_valid").capabilities:
        assert item.access is AccessLevel.READ
        assert API_KEY not in item.evidence
        assert APP_KEY not in item.evidence
        assert item.poc is not None
        assert API_KEY not in item.poc
        assert APP_KEY not in item.poc


def test_users_is_the_one_marked_data_sensitive() -> None:
    capabilities = run("datadog_valid").capabilities

    assert {c.service for c in capabilities if c.data_sensitive} == {"Datadog Users"}


def test_the_bare_dashboard_array_and_the_wrapped_ones_both_count() -> None:
    dashboards = capability(run("datadog_valid"), "Datadog Dashboards")
    monitors = capability(run("datadog_valid"), "Datadog Monitors")

    assert "dashboards: 1 listed" in dashboards.evidence
    assert "monitors: 1 listed" in monitors.evidence


def test_a_rejected_credential_is_reported_even_though_the_spec_omits_401() -> None:
    """Datadog's OpenAPI spec lists only 403 for `/validate`; probing the live
    API returns 401. Both are treated as rejection."""
    result = run("datadog_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "Unauthorized" in verdict.note
    assert result.capabilities == ()


def test_a_bare_api_key_validates_but_enumerates_to_nothing() -> None:
    """Each half is independently meaningful — see the module docstring."""
    result = run("datadog_valid", key=API_KEY)

    assert result.valid
    verdict = validation(result)
    assert verdict.note is not None
    assert "No application key was given" in verdict.note
    assert result.capabilities == ()


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("datadog_valid"), run("datadog_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_probe_table_has_four_entries_with_unique_services() -> None:
    assert len(PROBES) == 4
    assert len({probe.service for probe in PROBES}) == 4


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


class _Stub:
    """A context that answers every request with the same synthetic response."""

    def __init__(self, status: int, body: str) -> None:
        self._status = status
        self._body = body

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
        DatadogProvider().validate(KEY, _Stub(status, body))  # type: ignore[arg-type]
    )


def test_a_rate_limited_validate_still_means_the_credential_reached_datadog() -> None:
    verdict = validate_against(429, "{}")

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"errors":["internal error"]}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_200_with_valid_false_is_not_a_successful_validation() -> None:
    body = '{"data":{"attributes":{"valid":false}}}'

    assert not validate_against(200, body).valid


def test_message_of_reads_the_first_error_string_only() -> None:
    assert message_of(response(403, '{"errors":["Forbidden","second"]}')) == "Forbidden"
    assert message_of(response(403, '{"errors":[{"detail":"not a string"}]}')) == ""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""


def test_summary_falls_back_to_request_accepted_for_an_unrecognised_shape() -> None:
    probe = next(p for p in PROBES if p.collection == "dashboards")
    assert _summary(probe, response(200, "{}")) == "request accepted"

    bare_probe = next(p for p in PROBES if p.collection is None)
    assert (
        _summary(bare_probe, response(200, '{"not":"an array"}')) == "request accepted"
    )


def test_summary_reports_none_present_for_an_empty_collection() -> None:
    probe = next(p for p in PROBES if p.collection == "dashboards")
    assert (
        _summary(probe, response(200, '{"dashboards":[]}'))
        == "dashboards: none present"
    )


def test_org_id_is_none_when_the_data_field_is_missing() -> None:
    assert _org_id({}) is None
    assert _org_id({"data": "not-a-mapping"}) is None


def test_identity_reports_unknown_scopes_when_datadog_returns_none() -> None:
    payload = _payload(response(200, '{"data":{"attributes":{},"id":"org-1"}}'))
    identity = _identity(payload, Credential(API_KEY, ""))

    assert identity.extra["api_key_scopes"] == "none returned by Datadog"
    assert identity.extra["application_key"] == "not given"
    assert identity.extra["api_key_id"] == "unknown"
