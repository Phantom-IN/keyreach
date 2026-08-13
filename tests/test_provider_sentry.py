"""Sentry provider tests (roadmap R2.6).

Two things carry the weight here.

**No self-identity endpoint — the org list *is* the scope discovery.**
``test_access_level_comes_from_the_orgs_own_access_field`` is the test that
matters: unlike Zoom or GitLab, Sentry has no dedicated "read my own scopes"
call, so the same ``GET /organizations/`` that proves liveness also carries
the ``access`` array this plugin reads for write/admin detection.

**A 403 here is genuinely ambiguous**, and ``test_a_403_names_the_ambiguity``
checks the note says so rather than reporting a possibly-live, merely
under-scoped token as flatly "invalid".
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.sentry import (
    PROBES,
    Scope,
    SentryProvider,
    _granted_note,
    _organizations,
    _summary,
    access_for,
    granted_beyond_read,
    message_of,
    parse_scope,
    scopes_of,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
TOKEN = "sntryu_" + "0123456789abcdef" * 2


def run(fixture: str, key: str = TOKEN) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="sentry",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url="https://sentry.io/api/0/organizations/",
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(SentryProvider(), origin="keyreach.providers.sentry")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "sentry" in [provider.name for provider in registry.providers()]


def test_it_is_a_monitoring_provider() -> None:
    assert SentryProvider().category == "monitoring"


def test_it_claims_no_prior_art() -> None:
    assert SentryProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """No docs.sentry.io page states the sntryu_/sntrys_ prefix. See the
    module docstring."""
    assert SentryProvider().detectable is False


@pytest.mark.parametrize("sample", [TOKEN, "", "short", "sntryu_x"])
def test_detect_claims_nothing_at_all(sample: str) -> None:
    assert SentryProvider().detect(sample) == 0.0


def test_a_too_short_token_is_answered_without_a_request() -> None:
    verdict = validation(run("sentry_invalid", key="short"))

    assert not verdict.valid
    assert verdict.note == "This does not look like a Sentry auth token"


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("org:read", Scope("org", "read")),
        ("member:admin", Scope("member", "admin")),
        ("malformed", None),
        (":action", None),
        ("resource:", None),
    ],
)
def test_parse_scope(scope: str, expected: Scope | None) -> None:
    assert parse_scope(scope) == expected


def test_scopes_of_ignores_non_string_entries_and_sorts() -> None:
    org = {"access": ["org:write", "org:read", 5, None]}

    assert scopes_of(org) == ("org:read", "org:write")


def test_scopes_of_is_empty_for_a_malformed_org() -> None:
    assert scopes_of({}) == ()
    assert scopes_of({"access": "not-a-list"}) == ()


def test_access_for_defaults_to_read_when_nothing_matches() -> None:
    assert access_for("org", ("member:admin",)) == AccessLevel.READ


def test_access_for_prefers_admin_over_write() -> None:
    assert access_for("org", ("org:write", "org:admin")) == AccessLevel.ADMIN


def test_granted_beyond_read_names_only_non_read_scopes() -> None:
    scopes = ("member:read", "member:write", "org:admin")

    assert granted_beyond_read("member", scopes) == ("member:write",)
    assert granted_beyond_read("org", scopes) == ("org:admin",)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_capability_map() -> None:
    result = run("sentry_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Sentry Members",
        "Sentry Projects",
        "Sentry Teams",
    ]


def test_the_org_slug_is_the_identity() -> None:
    identity = validation(run("sentry_valid")).identity

    assert identity is not None
    assert identity.account == "acme"
    assert "org:read" in identity.extra["scopes"]


def test_access_level_comes_from_the_orgs_own_access_field() -> None:
    """`org:read`/`member:read` only — every capability here is READ."""
    for item in run("sentry_valid").capabilities:
        assert item.access is AccessLevel.READ


def test_a_write_scoped_token_elevates_the_matching_capabilities() -> None:
    result = run("sentry_write_scope")

    projects = capability(result, "Sentry Projects")
    members = capability(result, "Sentry Members")
    teams = capability(result, "Sentry Teams")

    assert projects.access is AccessLevel.WRITE
    assert "org:write" in projects.detail
    assert teams.access is AccessLevel.WRITE
    assert members.access is AccessLevel.ADMIN
    assert "member:admin" in members.detail


def test_members_is_the_one_marked_data_sensitive() -> None:
    capabilities = run("sentry_valid").capabilities

    assert {c.service for c in capabilities if c.data_sensitive} == {"Sentry Members"}


def test_every_capability_is_masked() -> None:
    for item in run("sentry_valid").capabilities:
        assert TOKEN not in item.evidence
        assert item.poc is not None
        assert TOKEN not in item.poc


def test_a_rejected_token_is_reported() -> None:
    result = run("sentry_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "Invalid token" in verdict.note
    assert result.capabilities == ()


def test_a_403_names_the_ambiguity() -> None:
    result = run("sentry_forbidden")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "may mean the token is invalid" in verdict.note
    assert "org:read, org:write or org:admin" in verdict.note
    assert result.capabilities == ()


def test_a_token_granted_no_organizations_is_still_valid() -> None:
    result = run("sentry_no_orgs")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.note is not None
    assert "granted no organizations" in verdict.note
    assert result.capabilities == ()


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("sentry_valid"), run("sentry_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_probe_table_has_three_entries_with_unique_services() -> None:
    assert len(PROBES) == 3
    assert len({probe.service for probe in PROBES}) == 3


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def test_message_of_reads_the_detail_field() -> None:
    assert message_of(response(401, '{"detail":"Invalid token"}')) == "Invalid token"
    assert message_of(response(401, '{"detail":5}')) == ""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = asyncio.run(
        SentryProvider().validate(
            TOKEN,
            _Stub(500, '{"detail":"internal error"}'),  # type: ignore[arg-type]
        )
    )

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_enumerate_returns_nothing_when_the_org_list_fails() -> None:
    capabilities = asyncio.run(
        SentryProvider().enumerate(TOKEN, _Stub(401, '{"detail":"no"}'))  # type: ignore[arg-type]
    )

    assert capabilities == []


def test_enumerate_returns_nothing_when_the_org_has_no_slug() -> None:
    capabilities = asyncio.run(
        SentryProvider().enumerate(
            TOKEN,
            _Stub(200, '[{"id":"1","access":["org:read"]}]'),  # type: ignore[arg-type]
        )
    )

    assert capabilities == []


def test_enumerate_returns_nothing_for_a_too_short_token() -> None:
    capabilities = asyncio.run(
        SentryProvider().enumerate("short", _Stub(200, "[]"))  # type: ignore[arg-type]
    )

    assert capabilities == []


def test_organizations_ignores_a_non_list_body() -> None:
    assert _organizations(response(200, '{"not":"a list"}')) == []


def test_summary_falls_back_to_request_accepted_for_a_non_list_body() -> None:
    probe = PROBES[0]

    assert _summary(probe, response(200, '{"not":"a list"}')) == "request accepted"


def test_summary_reports_none_present_for_an_empty_list() -> None:
    probe = PROBES[0]

    assert _summary(probe, response(200, "[]")) == f"{probe.noun}: none present"


def test_granted_note_covers_zero_one_and_many_scopes() -> None:
    assert "no scopes" in _granted_note(())
    assert "1 scope" in _granted_note(("org:read",))
    assert "2 scopes" in _granted_note(("org:read", "member:read"))


class _Stub:
    """A context that answers every request with the same synthetic response."""

    def __init__(self, status: int, body: str) -> None:
        self._status = status
        self._body = body

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        return ProbeResponse(
            method="GET",
            url=url,
            status_code=self._status,
            headers={"content-type": "application/json"},
            text=self._body,
        )

    async def gather(self, awaitables: object) -> list[ProbeResponse]:
        return [await item for item in awaitables]  # type: ignore[attr-defined]

    def protect(self, secret: str) -> None:
        del secret

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return TOKEN
