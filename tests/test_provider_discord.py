"""Discord provider tests (roadmap R2.2).

Discord was deferred out of R1.6 because its bot-token format is community
knowledge rather than published documentation. R2.1 supplied the answer —
``detectable = False`` — so the tests that matter here are the ones proving the
opt-out is real behaviour, and the one covering the capability that comes from a
documented flag rather than from a probe.

**On the fixtures.** Every path was confirmed against Discord's live API and the
flag bit values against Discord's documentation; the bodies are constructed from
those shapes, not recorded from a live token. Drift is roadmap **R2.10**.
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
from keyreach.providers.discord import (
    API_VERSION,
    GUILD_MEMBERS_INTENT,
    INTENTS,
    MESSAGE_CONTENT_INTENT,
    PROBES,
    DiscordProvider,
    _summary,
    intents_of,
    message_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
TOKEN = "MTI5" + "0000000000000001.Gh3xYz." + "n0rthw1nd0psB0tT0kenValue00"


def run(fixture: str, key: str = TOKEN) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket.

    Always with ``force_provider``: Discord is undetectable by design, so this
    is the only way any run reaches it — which is how a user reaches it too.
    """
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="discord",
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Metadata and the opt-out
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(DiscordProvider(), origin="keyreach.providers.discord")


def test_the_registry_discovers_it() -> None:
    assert "discord" in [p.name for p in ProviderRegistry("keyreach.providers")]


def test_it_is_a_comms_provider() -> None:
    assert DiscordProvider().category == "comms"


def test_it_claims_no_prior_art() -> None:
    assert DiscordProvider().credit is None


def test_it_is_deliberately_undetectable() -> None:
    """The reason R1.6 deferred it, answered rather than worked around."""
    assert DiscordProvider().detectable is False


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(TOKEN, id="a-real-looking-token"),
        pytest.param("", id="empty"),
        pytest.param("hello world", id="prose"),
        pytest.param("abc.def.ghi", id="the-community-pattern"),
        pytest.param("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2ln", id="a-jwt"),
    ],
)
def test_detect_claims_nothing_at_all(candidate: str) -> None:
    """The community three-segment pattern would also claim every JWT.

    That is the whole argument for not writing it: it describes what Discord's
    example token happens to look like, not a format Discord has committed to.
    """
    assert DiscordProvider().detect(candidate) == 0.0


def test_no_detection_rule_names_discord() -> None:
    assert "discord" not in {rule.provider for rule in default_detector.rules()}


def test_naming_the_provider_records_that_it_was_asserted() -> None:
    assert any("Detection was overridden" in n for n in run("discord_valid").notes)


def test_the_api_version_is_pinned() -> None:
    """Discord's *default* version is older than the one it recommends."""
    assert API_VERSION == "v10"
    assert all(f"/api/{API_VERSION}/" in probe.url for probe in PROBES)


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# Privileged intents — a capability from a documented flag
# ---------------------------------------------------------------------------


def test_the_intent_bits_are_the_documented_ones() -> None:
    assert MESSAGE_CONTENT_INTENT == 1 << 18
    assert GUILD_MEMBERS_INTENT == 1 << 14


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        pytest.param(0, (), id="none"),
        pytest.param(
            MESSAGE_CONTENT_INTENT, ("Discord Message Content",), id="content"
        ),
        pytest.param(GUILD_MEMBERS_INTENT, ("Discord Member List",), id="members"),
        pytest.param(
            MESSAGE_CONTENT_INTENT | GUILD_MEMBERS_INTENT,
            ("Discord Member List", "Discord Message Content"),
            id="both",
        ),
        pytest.param(None, (), id="absent"),
        pytest.param("262144", (), id="a-string"),
        pytest.param(True, (), id="a-bool-is-not-a-bitfield"),
    ],
)
def test_intents_are_read_from_the_flags_field(
    flags: object, expected: tuple[str, ...]
) -> None:
    assert tuple(intent.service for intent in intents_of(flags)) == expected


def test_message_content_is_recorded_without_reading_a_message() -> None:
    """Discord states the intent; keyreach records the reach, not the messages."""
    content = next(
        c
        for c in run("discord_valid").capabilities
        if c.service == "Discord Message Content"
    )

    assert content.access is AccessLevel.READ
    assert content.data_sensitive
    assert "GATEWAY_MESSAGE_CONTENT" in content.evidence
    assert "does not collect them" in content.detail
    assert content.poc is not None


def test_an_app_without_privileged_intents_claims_neither() -> None:
    """A capability asserted regardless of the response is not a rule."""
    services = [c.service for c in run("discord_no_intents").capabilities]

    assert "Discord Message Content" not in services
    assert "Discord Member List" not in services


def test_no_intent_is_claimed_when_the_application_read_is_refused() -> None:
    """The intents come from one probe, and that probe can fail on its own.

    A token that reaches `/users/@me` but not `/applications/@me` — Discord
    answers 403 for that — must yield the capabilities it did confirm and claim
    no intent at all, rather than inferring one from a response it never got.
    """
    result = run("discord_no_application")

    assert result.valid
    assert [c.service for c in result.capabilities] == [
        "Discord Bot Identity",
        "Discord Servers",
    ]


def test_every_intent_is_distinctly_named() -> None:
    assert len({intent.service for intent in INTENTS}) == len(INTENTS)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_scored_capability_map() -> None:
    result = run("discord_valid")

    assert result.valid
    assert [c.service for c in result.capabilities] == [
        "Discord Application",
        "Discord Bot Identity",
        "Discord Member List",
        "Discord Message Content",
        "Discord Servers",
    ]
    assert result.score.severity is Severity.HIGH


def test_the_bot_is_named() -> None:
    identity = run("discord_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "1290000000000000001"
    assert identity.owner == "@northwind-ops"


def test_no_capability_claims_a_write_or_a_send() -> None:
    capabilities = run("discord_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_token_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("discord_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "401: Unauthorized" in result.outcomes[0].validation.note


def test_a_token_too_short_to_be_real_is_refused_without_a_request() -> None:
    result = run("discord_valid", "short")

    assert not result.valid
    assert "too short" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://discord.com/api/v10/users/@me",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(DiscordProvider().validate(TOKEN, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_response_means_live_but_refused() -> None:
    result = validate_against(403, {"message": "Missing Access", "code": 50001})

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_token_is_live() -> None:
    result = validate_against(429, {"message": "You are being rate limited."})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"message": "Internal Server Error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_forbidden_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(403, ["unexpected"])

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(401, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "OAuth2 client secret" in result.note  # type: ignore[attr-defined]


def test_a_success_without_an_identity_reports_none() -> None:
    result = validate_against(200, {"bot": True})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Parsing, determinism and hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param('{"message":7}', id="message-not-a-string"),
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
        pytest.param('{"id":"x"}', "request accepted", id="not-a-list"),
        pytest.param("[]", "servers: none present", id="empty"),
        pytest.param("[1]", "servers: 1 listed", id="one"),
        pytest.param("[1,2]", "servers: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    servers = next(p for p in PROBES if p.service == "Discord Servers")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(servers, response) == expected


def test_a_probe_that_returns_an_object_reports_acceptance() -> None:
    identity = next(p for p in PROBES if p.service == "Discord Bot Identity")
    response = ProbeResponse(method="GET", url="u", status_code=200, text='{"id":"1"}')

    assert _summary(identity, response) == "request accepted"


def test_repeated_runs_are_identical() -> None:
    first, second = run("discord_valid"), run("discord_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("discord_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_evidence_counts_servers_and_does_not_name_them() -> None:
    servers = next(
        c for c in run("discord_valid").capabilities if c.service == "Discord Servers"
    )

    assert "servers: 1 listed" in servers.evidence
    assert "Northwind HQ" not in servers.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("discord_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert TOKEN not in capability.poc


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("discord_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    assert len({p.service for p in PROBES}) == len(PROBES)


def test_no_committed_fixture_contains_the_token() -> None:
    for name in ("valid", "no_intents", "no_application", "invalid"):
        text = (FIXTURES / f"discord_{name}.json").read_text(encoding="utf-8")

        assert TOKEN not in text
