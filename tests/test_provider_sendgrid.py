"""SendGrid provider tests (roadmap R2.3).

The tests that carry the most weight here are about the **scope grammar** and
about the **capability with no probe behind it**.

``test_the_access_level_comes_from_the_verb_not_from_a_list`` is the point of
the grammar: SendGrid ships new scopes continuously, so an access level read off
``resource.action`` stays right where a checked-in table of scope names goes
stale. ``test_a_scope_over_one_resource_does_not_elevate_another`` is the
matching restraint — a key that can delete suppressions is not thereby claimed
to be able to delete templates.

``test_the_send_capability_is_derived_and_nothing_was_sent`` covers the one
capability keyreach reports without probing for it. Proving a key can send email
means sending an email, which spends the account's allowance and puts a message
in somebody's inbox, so the evidence is SendGrid's own answer about the key's
permissions instead.

**On the fixtures.** Every path was verified against SendGrid's live API, which
answers 401 for a path that exists and 404 for one that does not. The response
bodies are constructed from SendGrid's documented shapes, not recorded from a
live key; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    RecordMode,
)
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.sendgrid import (
    API,
    CONFIDENCE,
    PROBES,
    SCOPES_URL,
    SEND_SCOPE,
    WRITE_ACTIONS,
    SendGridProvider,
    _detail,
    _identity,
    _Probe,
    _summary,
    access_for,
    action_of,
    covers,
    message_of,
    scopes_of,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
KEY = "SG" + "." + "N0rthw1ndSendGr1dAAAA" + "." + "b" * 43


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="sendgrid",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(SendGridProvider(), origin="keyreach.providers.sendgrid")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "sendgrid" in [provider.name for provider in registry.providers()]


def test_it_is_an_email_provider() -> None:
    """R2.3 opens the `email` category, which `core/registry.py` already allows."""
    assert SendGridProvider().category == "email"


def test_it_claims_no_prior_art() -> None:
    assert SendGridProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_it_claims_a_documented_key() -> None:
    assert SendGridProvider().detect(KEY) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-key",
        "SG.short.short",
        # The prefix alone is not the format.
        "SG." + "a" * 40,
        # A Slack token, which also has dot-free segments.
        "xoxb-" + "1" * 20,
    ],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert SendGridProvider().detect(sample) == 0.0


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    """A rule that matches a key the plugin rejects routes a probe nowhere."""
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "sendgrid-api-key")

    assert re.match(rule["pattern"], KEY)
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "sendgrid"


def test_the_detector_routes_the_key_to_sendgrid() -> None:
    matched = [match.provider for match in default_detector.detect(KEY)]

    assert matched == ["sendgrid"]


def test_the_rule_no_longer_pins_a_length_sendgrid_never_published() -> None:
    """R2.3 relaxed `{22}`/`{43}` — see the comment on the rule.

    Those lengths match every key seen in the wild and appear in no SendGrid
    document. The regression this guards is somebody "tightening" the rule back
    to them: it would look more precise and would be a fact keyreach invented.
    """
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "sendgrid-api-key")

    assert "{22}" not in rule["pattern"]
    assert "{43}" not in rule["pattern"]
    # A key of a length SendGrid has never published is still recognised.
    assert re.match(rule["pattern"], "SG." + "a" * 20 + "." + "b" * 50)


# ---------------------------------------------------------------------------
# The scope grammar — a rule, not a table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "verb"),
    [
        ("mail.send", "send"),
        ("alerts.read", "read"),
        ("api_keys.create", "create"),
        ("user.password.update", "update"),
        # SendGrid nests resources freely; the verb is still last.
        ("templates.versions.activate.create", "create"),
    ],
)
def test_the_access_level_comes_from_the_verb_not_from_a_list(
    scope: str, verb: str
) -> None:
    """Every one of these is a documented SendGrid scope.

    Reading the verb off the grammar is what keeps this correct as SendGrid adds
    scopes. A table of names would have to be edited for each new one, and
    nothing would fail when it was not.
    """
    assert action_of(scope) == verb


@pytest.mark.parametrize(
    ("scope", "resource", "expected"),
    [
        ("suppression.bounces.delete", "suppression", True),
        ("suppression", "suppression", True),
        ("templates.read", "suppression", False),
        # Whole-segment matching: `user` must not swallow `username`.
        ("username.read", "user", False),
        ("user.profile.read", "user", True),
    ],
)
def test_a_scope_is_matched_on_whole_segments(
    scope: str, resource: str, expected: bool
) -> None:
    assert covers(scope, resource) is expected


def test_a_scope_over_one_resource_does_not_elevate_another() -> None:
    """The restraint GitHub's plugin established in R1.6, applied here.

    A key that can delete suppressions can delete suppressions. Labelling its
    template capability `write` on that evidence would be the over-reach
    `core/scoring.py` refuses when it requires *one* capability to be both
    privileged and valuable.
    """
    scopes = frozenset({"suppression.delete", "templates.read"})
    templates = next(probe for probe in PROBES if probe.resource == "templates")
    suppression = next(probe for probe in PROBES if probe.resource == "suppression")

    assert access_for(templates, scopes) is AccessLevel.READ
    assert access_for(suppression, scopes) is AccessLevel.WRITE


def test_minting_api_keys_is_admin_not_merely_write() -> None:
    """A key that can create keys outlives its own revocation."""
    api_keys = next(probe for probe in PROBES if probe.resource == "api_keys")

    assert access_for(api_keys, frozenset({"api_keys.create"})) is AccessLevel.ADMIN
    assert access_for(api_keys, frozenset({"api_keys.read"})) is AccessLevel.READ


def test_unknown_scopes_never_lower_the_floor() -> None:
    """`READ` is proven by the probe answering; a scope can only raise it."""
    probe = PROBES[0]

    assert access_for(probe, frozenset()) is AccessLevel.READ
    assert access_for(probe, frozenset({"user.account.somethingnew"})) is (
        AccessLevel.READ
    )


def test_the_write_verbs_are_sendgrids_documented_ones() -> None:
    assert frozenset({"create", "delete", "update"}) == WRITE_ACTIONS


def test_no_scope_information_means_no_claim_either_way() -> None:
    """`None` scopes is "not determined", which is not "no write access"."""
    assert access_for(PROBES[0], None) is AccessLevel.READ


# ---------------------------------------------------------------------------
# Probe table hygiene
# ---------------------------------------------------------------------------


def test_every_probe_is_under_the_documented_api_base() -> None:
    for probe in PROBES:
        assert probe.url.startswith(API)


def test_only_key_management_is_marked_admin_on_write() -> None:
    """Widening this is a decision, not a detail."""
    admin = [probe.service for probe in PROBES if probe.admin_on_write]

    assert admin == ["SendGrid API Keys"]


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_full_access_key_is_mapped() -> None:
    result = run("sendgrid_valid")

    assert result.valid
    services = [item.service for item in result.capabilities]
    assert services == sorted(services)
    assert "SendGrid Templates" in services


def test_the_scopes_endpoint_is_read_once_for_the_whole_run() -> None:
    """`validate` and `enumerate` both need it; R1.4's cache makes that one call.

    Every probe here is a GET, so the request count is the number of distinct
    URLs — five probes plus the scopes endpoint — rather than seven.
    """

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "sendgrid_valid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, KEY)
            provider = SendGridProvider()
            await provider.validate(KEY, context)
            after_validate = client.requests_made
            await provider.enumerate(KEY, context)
            return after_validate, client.requests_made

    scope_reads, total = asyncio.run(measure())

    assert scope_reads == 1
    assert total == 1 + len(PROBES)


def test_the_send_capability_is_derived_and_nothing_was_sent() -> None:
    """The one capability with no probe behind it.

    Proving a key can send email means sending email. keyreach does not, so the
    evidence is SendGrid's own statement of the key's permissions — the same
    shape as Telegram's privacy-mode capability and Discord's privileged
    intents.
    """
    result = run("sendgrid_valid")
    send = capability(result, "SendGrid Mail Send")

    assert send.access is AccessLevel.WRITE
    assert send.incurs_cost
    assert SEND_SCOPE in send.evidence
    assert "No message was sent" in send.detail
    # The proof of concept must reach the scopes endpoint, not the mail endpoint.
    assert send.poc is not None
    assert SCOPES_URL in send.poc


def test_a_key_without_the_send_scope_gets_no_send_capability() -> None:
    """Absence of the scope claims nothing, rather than claiming absence."""
    result = run("sendgrid_read_only")

    assert "SendGrid Mail Send" not in [item.service for item in result.capabilities]


def test_a_read_only_key_produces_only_reads() -> None:
    result = run("sendgrid_read_only")

    assert {item.access for item in result.capabilities} == {AccessLevel.READ}


def test_an_unreadable_scope_list_says_so_rather_than_guessing() -> None:
    """The honest degradation: what the probe proved, and no more."""
    result = run("sendgrid_no_scopes")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.note is not None
    assert "lower bound" in verdict.note

    account = capability(result, "SendGrid Account")
    assert account.access is AccessLevel.READ
    assert "neither confirmed nor ruled out" in account.detail


def test_a_rejected_key_is_reported_as_rejected() -> None:
    result = run("sendgrid_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "did not accept" in verdict.note
    assert result.capabilities == ()


def test_the_key_never_appears_in_any_output() -> None:
    result = run("sendgrid_valid")

    for item in result.capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("sendgrid_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("sendgrid_valid"), run("sendgrid_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the defensive paths
# ---------------------------------------------------------------------------


def test_a_probe_declares_the_resource_its_scopes_hang_off() -> None:
    probe = _Probe(
        service="X",
        url=f"{API}/x",
        noun="x",
        detail="x",
        resource="x",
        risk_weight=1,
        source="https://example.invalid/",
    )

    assert access_for(probe, frozenset({"x.create"})) is AccessLevel.WRITE


def response(status: int, body: str) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=SCOPES_URL,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic scopes response."""

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

    return asyncio.run(SendGridProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_request_still_means_the_key_reached_sendgrid() -> None:
    verdict = validate_against(429, '{"errors":[{"message":"too many requests"}]}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"errors":[{"message":"internal error"}]}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


@pytest.mark.parametrize(
    "body",
    [
        "<html>bad gateway</html>",
        '{"errors":"not a list"}',
        '{"errors":[]}',
        '{"errors":["not an object"]}',
        '{"errors":[{"message":42}]}',
    ],
)
def test_a_malformed_error_body_is_not_a_message(body: str) -> None:
    """Defensive parsing: a proxy's HTML must not become an error message."""

    assert message_of(response(502, body)) == ""


@pytest.mark.parametrize("body", ['{"scopes":"not a list"}', "[]", "<html>x</html>"])
def test_a_body_without_a_scope_list_yields_no_scopes(body: str) -> None:

    assert scopes_of(response(200, body)) is None


def test_an_empty_scope_list_is_an_identity_and_no_scope_information_is_not() -> None:

    assert _identity(scopes_of(response(200, '{"scopes":[]}'))) is not None
    assert _identity(None) is None


def test_an_empty_collection_reads_as_none_present() -> None:

    probe = next(probe for probe in PROBES if probe.collection is not None)

    assert "none present" in _summary(probe, response(200, '{"result":[]}'))


def test_a_probe_with_no_matching_scope_says_so() -> None:
    """Silence would read as "not checked"; this says "SendGrid lists none"."""

    probe = next(probe for probe in PROBES if probe.resource == "templates")

    assert "lists no scope over templates" in _detail(probe, frozenset({"mail.send"}))
