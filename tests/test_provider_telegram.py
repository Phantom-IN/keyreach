"""Telegram provider tests (roadmap R1.6).

The distinctive test is
``test_privacy_mode_being_off_is_recorded_as_a_capability``. It is the only
capability in keyreach that comes from a *field in a response* rather than from
a probe succeeding: Telegram states ``can_read_all_group_messages``, and a bot
with it set receives every message in every group it belongs to. Its
counterweight is ``test_privacy_mode_being_on_records_nothing``, because a
capability that is asserted whether or not the vendor said so is not a rule.

The second is ``test_the_token_never_reaches_a_recorded_url``. Telegram puts the
token in the path, so redaction is what makes these fixtures committable at all.

**On the fixtures.** They are constructed from Telegram's published response
shapes, not recorded from a live token; drift is roadmap **R2.10**.
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
from keyreach.providers.telegram import (
    PRIVACY_MODE_FIELD,
    PROBES,
    TelegramProvider,
    _identity,
    _summary,
    bot_id_of,
    method_url,
    privacy_mode_disabled,
    succeeded,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
BOT_ID = "8123456789"
TOKEN = BOT_ID + ":" + "A" * 35


def run(fixture: str, key: str = TOKEN) -> EngineResult:
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
    validate_provider(TelegramProvider(), origin="keyreach.providers.telegram")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "telegram" in [provider.name for provider in registry.providers()]


def test_it_is_a_comms_provider() -> None:
    assert TelegramProvider().category == "comms"


def test_it_claims_no_prior_art() -> None:
    assert TelegramProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(TOKEN, 0.95, id="token"),
        pytest.param("12345678" + ":" + "A" * 35, 0.95, id="short-bot-id"),
        pytest.param(BOT_ID + ":" + "A" * 34, 0.0, id="secret-too-short"),
        pytest.param("123456789012" + ":" + "A" * 35, 0.0, id="bot-id-too-long"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + TOKEN, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert TelegramProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = TelegramProvider()

    assert {provider.detect(TOKEN) for _ in range(5)} == {0.95}


def test_the_plugin_and_the_rule_set_agree_on_the_token_format() -> None:
    """Two places describe a Telegram token. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(TOKEN)
        if match.provider is not None
    ]

    assert matched == ["telegram"]
    assert TelegramProvider().detect(TOKEN) > 0.0


def test_the_bot_id_is_read_from_the_token() -> None:
    assert bot_id_of(TOKEN) == BOT_ID
    assert bot_id_of("not-a-token") == ""


def test_the_request_url_is_the_documented_shape() -> None:
    assert method_url(TOKEN, "getMe") == f"https://api.telegram.org/bot{TOKEN}/getMe"


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# The capability that comes from a documented response field
# ---------------------------------------------------------------------------


def test_privacy_mode_being_off_is_recorded_as_a_capability() -> None:
    """Telegram states it; keyreach records it and says it enumerated nothing.

    "True, if privacy mode is disabled for the bot" is the vendor's own wording,
    and a bot in that state receives every message in every group it is in. The
    groups themselves are not listed, because listing them means reading the
    pending updates.
    """
    result = run("telegram_valid")
    groups = next(
        c for c in result.capabilities if c.service == "Telegram Group Messages"
    )

    assert groups.access is AccessLevel.READ
    assert groups.data_sensitive
    assert PRIVACY_MODE_FIELD in groups.evidence
    assert "were not enumerated" in groups.detail
    assert result.score.severity is Severity.HIGH


def test_privacy_mode_being_on_records_nothing() -> None:
    """A capability asserted regardless of the response is not a rule."""
    result = run("telegram_privacy_on")

    assert result.valid
    assert "Telegram Group Messages" not in [c.service for c in result.capabilities]
    assert result.score.severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param('{"ok":true}', id="no-result"),
        pytest.param('{"ok":true,"result":[]}', id="result-not-a-mapping"),
        pytest.param('{"ok":true,"result":{}}', id="field-absent"),
        pytest.param(
            '{"ok":true,"result":{"can_read_all_group_messages":false}}', id="false"
        ),
        pytest.param(
            '{"ok":true,"result":{"can_read_all_group_messages":"yes"}}', id="a-string"
        ),
    ],
)
def test_privacy_mode_is_only_claimed_when_telegram_asserts_it(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert not privacy_mode_disabled(response)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_scored_capability_map() -> None:
    result = run("telegram_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Telegram Bot Commands",
        "Telegram Bot Identity",
        "Telegram Bot Profile",
        "Telegram Group Messages",
        "Telegram Webhook",
    ]


def test_the_bot_is_named() -> None:
    identity = run("telegram_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == BOT_ID
    assert identity.owner == "@northwind_ops_bot"
    assert identity.extra == {"first_name": "Northwind Ops"}


def test_a_method_the_token_cannot_reach_produces_no_capability() -> None:
    """`getMyDescription` answers ``ok: false`` in this fixture; it is dropped."""
    assert "Telegram Bot Profile" not in [
        c.service for c in run("telegram_privacy_on").capabilities
    ]


def test_no_capability_claims_a_send() -> None:
    """A bot token can post as the bot. keyreach does not post to prove it."""
    capabilities = run("telegram_valid").capabilities

    assert capabilities
    assert all(c.access is AccessLevel.READ for c in capabilities)
    assert not any(c.incurs_cost for c in capabilities)


def test_get_updates_is_deliberately_absent() -> None:
    """A gap worth pinning, because it is a decision rather than an oversight.

    ``getUpdates`` confirms previously received updates when given an offset and
    conflicts with an active webhook, so it is the one getter with side effects
    — and reading a stranger's pending messages is collection `plan.md` §11
    rules out. ``getWebhookInfo`` establishes the same reach without it.
    """
    assert "getUpdates" not in [probe.method for probe in PROBES]


# ---------------------------------------------------------------------------
# Redaction — what makes committing these fixtures safe
# ---------------------------------------------------------------------------


def test_the_token_never_reaches_a_recorded_url() -> None:
    """Telegram puts the secret in the path, so redaction is load-bearing here."""
    for name in ("valid", "privacy_on", "invalid"):
        text = (FIXTURES / f"telegram_{name}.json").read_text(encoding="utf-8")

        assert TOKEN not in text
        assert "/bot<key>/" in text


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("telegram_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert TOKEN not in capability.poc


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_token_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("telegram_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "Unauthorized" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.telegram.org/bot<key>/getMe",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(TelegramProvider().validate(TOKEN, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limit_still_means_the_token_is_live() -> None:
    result = validate_against(
        429, {"ok": False, "error_code": 429, "description": "Too Many Requests"}
    )

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_description_still_reads_cleanly() -> None:
    result = validate_against(401, {"ok": False})

    assert not result.valid  # type: ignore[attr-defined]
    assert result.note.endswith("bot token")  # type: ignore[attr-defined]


def test_a_success_with_an_unexpected_result_still_identifies_the_bot() -> None:
    """The bot id comes from the token, so identity survives a strange body."""
    result = validate_against(200, {"ok": True, "result": "unexpected"})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity.account == BOT_ID  # type: ignore[attr-defined]
    assert result.identity.owner is None  # type: ignore[attr-defined]


def test_an_identity_for_an_unrecognised_token_reports_no_account() -> None:
    response = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"ok":true,"result":{}}'
    )

    assert _identity("not-a-token", response).account is None


# ---------------------------------------------------------------------------
# Parsing third-party payloads, which must never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param('{"ok":"true"}', id="ok-is-a-string"),
    ],
)
def test_success_parsing_degrades_instead_of_raising(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert not succeeded(response)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"ok":true,"result":{}}', "request accepted", id="not-a-list"),
        pytest.param('{"ok":true,"result":[]}', "commands: none present", id="empty"),
        pytest.param('{"ok":true,"result":[1]}', "commands: 1 listed", id="one"),
        pytest.param('{"ok":true,"result":[1,2]}', "commands: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    commands = next(p for p in PROBES if p.service == "Telegram Bot Commands")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(commands, response) == expected


def test_a_probe_with_no_collection_reports_acceptance() -> None:
    webhook = next(p for p in PROBES if p.service == "Telegram Webhook")
    response = ProbeResponse(
        method="GET", url="u", status_code=200, text='{"ok":true,"result":{"url":""}}'
    )

    assert _summary(webhook, response) == "request accepted"


# ---------------------------------------------------------------------------
# Determinism and hygiene
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("telegram_valid"), run("telegram_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("telegram_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("telegram_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))
