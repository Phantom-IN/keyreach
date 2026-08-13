"""Grafana provider tests (roadmap R2.6).

Two things carry the weight here.

**Only Grafana Cloud access policy tokens ship — no self-hosted instance.**
There is no fixed host for a self-managed Grafana's ``glsa_`` tokens, so this
plugin recognises and reaches ``glc_`` tokens only. See the module docstring
for why that is a harder gap than GitLab's self-managed one.

**A 403 here is ambiguous for the same structural reason Sentry's is** — most
access policy tokens are scoped for metrics/logs/traces, not
``accesspolicies:read``. ``test_a_403_names_the_ambiguity`` checks the note
says so.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.grafana import (
    ACCESS_POLICIES_URL,
    PROBES,
    GrafanaProvider,
    _org_id,
    _summary,
    items_of,
    message_of,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
TOKEN = "glc_" + "eyJrIjoi" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def run(fixture: str, key: str = TOKEN) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="grafana",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str, url: str = ACCESS_POLICIES_URL) -> ProbeResponse:
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
    validate_provider(GrafanaProvider(), origin="keyreach.providers.grafana")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "grafana" in [provider.name for provider in registry.providers()]


def test_it_is_a_monitoring_provider() -> None:
    assert GrafanaProvider().category == "monitoring"


def test_it_claims_no_prior_art() -> None:
    assert GrafanaProvider().credit is None


def test_it_is_a_detection_candidate_for_the_glc_prefix() -> None:
    assert GrafanaProvider().detect(TOKEN) > 0.0


@pytest.mark.parametrize("sample", ["", "not-a-key", "glc_short", "glsa_" + "a" * 25])
def test_detect_claims_nothing_for_anything_else(sample: str) -> None:
    assert GrafanaProvider().detect(sample) == 0.0


def test_detect_claims_nothing_for_a_self_hosted_service_account_token() -> None:
    """`glsa_` tokens have no fixed host — see the module docstring."""
    assert GrafanaProvider().detect("glsa_" + "a" * 25) == 0.0


def test_an_unrecognised_key_is_rejected_without_a_request() -> None:
    verdict = validation(run("grafana_invalid", key="not-a-token"))

    assert not verdict.valid
    assert verdict.note == "This does not look like a Grafana Cloud access policy token"


def test_enumerate_returns_nothing_for_an_unrecognised_key() -> None:
    capabilities = asyncio.run(
        GrafanaProvider().enumerate("not-a-token", None)  # type: ignore[arg-type]
    )

    assert capabilities == []


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_capability_map() -> None:
    result = run("grafana_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Grafana Cloud Access Policies",
        "Grafana Cloud Access Policy Tokens",
    ]


def test_the_org_id_is_the_identity() -> None:
    identity = validation(run("grafana_valid")).identity

    assert identity is not None
    assert identity.account == "1"


def test_every_capability_is_read_only_data_sensitive_and_masked() -> None:
    for item in run("grafana_valid").capabilities:
        assert item.access is AccessLevel.READ
        assert item.data_sensitive
        assert TOKEN not in item.evidence
        assert item.poc is not None
        assert TOKEN not in item.poc


def test_the_lists_are_counted() -> None:
    policies = capability(run("grafana_valid"), "Grafana Cloud Access Policies")
    tokens = capability(run("grafana_valid"), "Grafana Cloud Access Policy Tokens")

    assert "access policies: 1 listed" in policies.evidence
    assert "tokens: 1 listed" in tokens.evidence


def test_a_rejected_token_is_reported() -> None:
    result = run("grafana_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "Token could not be parsed" in verdict.note
    assert result.capabilities == ()


def test_a_403_names_the_ambiguity() -> None:
    result = run("grafana_forbidden")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "may mean the token is invalid" in verdict.note
    assert "accesspolicies:read" in verdict.note
    assert result.capabilities == ()


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("grafana_valid"), run("grafana_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_probe_table_has_two_entries_with_unique_services() -> None:
    assert len(PROBES) == 2
    assert len({probe.service for probe in PROBES}) == 2


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def test_message_of_reads_the_message_field() -> None:
    assert message_of(response(401, '{"code":"X","message":"nope"}')) == "nope"
    assert message_of(response(401, '{"message":5}')) == ""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""


def test_items_of_ignores_a_non_list_or_missing_items_field() -> None:
    assert items_of(response(200, "{}")) == []
    assert items_of(response(200, '{"items":"not-a-list"}')) == []


def test_summary_reports_none_present_for_an_empty_list() -> None:
    probe = PROBES[0]

    assert (
        _summary(probe, response(200, '{"items":[]}')) == f"{probe.noun}: none present"
    )


def test_org_id_is_none_when_no_item_carries_one() -> None:
    assert _org_id([]) is None
    assert _org_id([{"id": "1"}]) is None
    assert _org_id([{"orgId": 5}]) is None


def test_a_token_accepted_but_listing_no_policies_is_still_valid() -> None:
    verdict = asyncio.run(
        GrafanaProvider().validate(TOKEN, _Stub(200, '{"items":[]}'))  # type: ignore[arg-type]
    )

    assert verdict.valid
    assert verdict.note is not None
    assert "listed no access policies" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = asyncio.run(
        GrafanaProvider().validate(TOKEN, _Stub(500, '{"message":"boom"}'))  # type: ignore[arg-type]
    )

    assert not verdict.valid
    assert verdict.note is not None
    assert "boom" in verdict.note
    assert "not established either way" in verdict.note


def test_enumerate_skips_a_capability_whose_read_failed() -> None:
    class _TokensFail:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del params, headers
            status = 200 if "accesspolicies" in url else 403
            body = '{"items":[{"orgId":"1"}]}' if status == 200 else "{}"
            return response(status, body, url=url)

        async def gather(self, awaitables: object) -> list[ProbeResponse]:
            return [await item for item in awaitables]  # type: ignore[attr-defined]

        def mask(self, text: str) -> str:
            return text

        @property
        def key(self) -> str:
            return TOKEN

    capabilities = asyncio.run(GrafanaProvider().enumerate(TOKEN, _TokensFail()))  # type: ignore[arg-type]

    assert [c.service for c in capabilities] == ["Grafana Cloud Access Policies"]


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

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return TOKEN
