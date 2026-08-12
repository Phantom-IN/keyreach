"""Slack provider tests (roadmap R1.6).

The test that carries the most weight is
``test_a_revoked_token_arrives_as_a_200_and_is_still_reported_as_dead``. Slack
answers ``200 OK`` with ``{"ok": false, "error": "invalid_auth"}``, so a plugin
that trusted the HTTP status would report a revoked token as live with four
confirmed capabilities. Its companion,
``test_a_method_the_token_lacks_the_scope_for_produces_no_capability``, pins the
other half: ``missing_scope`` is a clean negative rather than a failure.

**On the fixtures.** They are constructed from Slack's published response
shapes, not recorded from a live token. They prove the parsing and the decision
rules, not that Slack still answers this way; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.slack import (
    DEAD_TOKEN_ERRORS,
    MISSING_SCOPE,
    PROBES,
    RATE_LIMITED,
    SlackProvider,
    _identity,
    _Kind,
    _summary,
    error_of,
    kind_of,
    succeeded,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
BODY = "1111111111-2222222222-" + "N0rthw1ndWorkspace01"
BOT_TOKEN = "xox" + "b-" + BODY
USER_TOKEN = "xox" + "p-" + BODY


def run(fixture: str, key: str = BOT_TOKEN) -> EngineResult:
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
    validate_provider(SlackProvider(), origin="keyreach.providers.slack")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "slack" in [provider.name for provider in registry.providers()]


def test_it_is_a_comms_provider() -> None:
    assert SlackProvider().category == "comms"


def test_it_claims_no_prior_art() -> None:
    assert SlackProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(BOT_TOKEN, 0.99, id="bot"),
        pytest.param(USER_TOKEN, 0.99, id="user"),
        pytest.param("xox" + "a-" + BODY, 0.99, id="app"),
        pytest.param("xox" + "z-" + BODY, 0.0, id="unknown-letter"),
        pytest.param("xox" + "b-" + "short", 0.0, id="too-short"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + BOT_TOKEN, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert SlackProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = SlackProvider()

    assert {provider.detect(BOT_TOKEN) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [BOT_TOKEN, USER_TOKEN])
def test_the_plugin_and_the_rule_set_agree_on_the_token_format(key: str) -> None:
    """Two places describe a Slack token. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["slack"]
    assert SlackProvider().detect(key) > 0.0


@pytest.mark.parametrize(
    ("token", "kind"),
    [
        pytest.param(BOT_TOKEN, _Kind.BOT, id="bot"),
        pytest.param(USER_TOKEN, _Kind.USER, id="user"),
        pytest.param("xox" + "a-" + BODY, _Kind.OTHER, id="other"),
    ],
)
def test_the_principal_comes_from_the_documented_prefix(
    token: str, kind: _Kind
) -> None:
    assert kind_of(token) is kind


def test_validation_uses_the_method_that_needs_no_scope() -> None:
    probe = validation_probe()

    assert probe in PROBES
    assert probe.scope == "none"


# ---------------------------------------------------------------------------
# The 200-means-failure problem this plugin exists to handle
# ---------------------------------------------------------------------------


def test_a_revoked_token_arrives_as_a_200_and_is_still_reported_as_dead() -> None:
    """The failure mode `response.ok` would walk straight into."""
    result = run("slack_invalid")
    interaction = json.loads(
        (FIXTURES / "slack_invalid.json").read_text(encoding="utf-8")
    )["interactions"][0]

    assert interaction["status_code"] == 200
    assert not result.valid
    assert result.capabilities == ()
    assert "invalid_auth" in result.outcomes[0].validation.note


def test_success_requires_both_the_status_and_the_ok_field() -> None:
    ok_body = ProbeResponse(method="GET", url="u", status_code=200, text='{"ok":true}')
    not_ok_body = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"ok":false,"error":"x"}'
    )
    server_error = ProbeResponse(
        method="GET", url="u", status_code=500, text='{"ok":true}'
    )

    assert succeeded(ok_body)
    assert not succeeded(not_ok_body)
    assert not succeeded(server_error)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param('{"error":7}', id="error-not-a-string"),
    ],
)
def test_error_parsing_degrades_instead_of_raising(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert error_of(response) == ""
    assert not succeeded(response)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_scored_capability_map() -> None:
    result = run("slack_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Slack Channels",
        "Slack Identity",
        "Slack Users",
        "Slack Workspace",
    ]
    assert result.score.severity is Severity.HIGH
    assert any("Slack Users" in line for line in result.score.rationale)


def test_a_method_the_token_lacks_the_scope_for_produces_no_capability() -> None:
    """`missing_scope` is a clean negative: the token demonstrably cannot do it."""
    services = [c.service for c in run("slack_valid").capabilities]

    assert "Slack Files" not in services
    assert MISSING_SCOPE == "missing_scope"


def test_the_workspace_and_principal_are_named() -> None:
    identity = run("slack_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "T0NORTHWIND"
    assert identity.owner == "Northwind"
    assert identity.extra["bot_id"] == "B0NORTHWIND"
    assert identity.extra["url"] == "https://northwind.slack.com/"


def test_every_capability_names_the_scope_it_proves() -> None:
    for capability in run("slack_valid").capabilities:
        assert "Confirms the " in capability.detail
        assert "scope" in capability.detail


def test_no_capability_claims_a_write_or_a_send() -> None:
    """Slack scopes are granular: `users:read` says nothing about `chat:write`."""
    capabilities = run("slack_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)
    assert all("never sends a message" in c.detail for c in capabilities)


def test_a_user_token_says_it_acts_as_a_person() -> None:
    """A leaked user token reaches whatever the member who authorised it can."""
    result = run("slack_valid", USER_TOKEN)

    assert all("acts as the member" in c.detail for c in result.capabilities)


def test_a_bot_token_does_not_claim_to_act_as_a_person() -> None:
    assert all(
        "acts as the member" not in c.detail for c in run("slack_valid").capabilities
    )


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def validate_against(payload: object, status: int = 200) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://slack.com/api/auth.test",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(SlackProvider().validate(BOT_TOKEN, _Stub()))  # type: ignore[arg-type]


@pytest.mark.parametrize("error", sorted(DEAD_TOKEN_ERRORS))
def test_every_documented_dead_token_error_means_invalid(error: str) -> None:
    result = validate_against({"ok": False, "error": error})

    assert not result.valid  # type: ignore[attr-defined]
    assert error in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_token_is_live() -> None:
    result = validate_against({"ok": False, "error": RATE_LIMITED})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_unrecognised_error_is_not_treated_as_a_verdict() -> None:
    """Slack adds error strings. An unknown one settles nothing either way."""
    result = validate_against({"ok": False, "error": "fatal_error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "fatal_error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against({"unexpected": "shape"}, status=503)

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_success_without_a_team_reports_no_identity() -> None:
    result = validate_against({"ok": True, "user": "someone"})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


def test_an_identity_falls_back_to_the_team_name_when_the_id_is_absent() -> None:
    response = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"ok":true,"team":"Northwind"}'
    )
    identity = _identity(response)

    assert identity is not None
    assert identity.account == "Northwind"
    assert identity.extra == {}


# ---------------------------------------------------------------------------
# Determinism, evidence and hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"ok":true}', "request accepted", id="no-collection"),
        pytest.param('{"members":"x"}', "request accepted", id="not-a-list"),
        pytest.param('{"members":[]}', "members: none present", id="empty"),
        pytest.param('{"members":[1]}', "members: 1 listed", id="one"),
        pytest.param('{"members":[1,2]}', "members: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    users = next(p for p in PROBES if p.service == "Slack Users")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(users, response) == expected


def test_a_probe_with_no_collection_reports_acceptance() -> None:
    identity = next(p for p in PROBES if p.service == "Slack Identity")
    response = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"ok":true,"team":"x"}'
    )

    assert _summary(identity, response) == "request accepted"


def test_repeated_runs_are_identical() -> None:
    first, second = run("slack_valid"), run("slack_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("slack_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_members_and_does_not_quote_them() -> None:
    users = next(
        c for c in run("slack_valid").capabilities if c.service == "Slack Users"
    )

    assert "members: 1 listed" in users.evidence
    assert "ada@northwind.example" not in users.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("slack_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert BOT_TOKEN not in capability.poc


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("slack_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        if probe.service in refs:
            assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_a_token() -> None:
    for name in ("valid", "invalid"):
        text = (FIXTURES / f"slack_{name}.json").read_text(encoding="utf-8")

        assert BOT_TOKEN not in text
        assert BODY not in text
