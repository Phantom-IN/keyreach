"""Mailchimp provider tests (roadmap R2.3).

Two things carry the weight here.

**The key names its own server.** Mailchimp documents the format as ``key-dc``
and refuses a key sent to the wrong data centre with the *same* 401 a dead key
gets — "your API key may be invalid, or you've attempted to access the wrong
datacenter". So a parsing slip in ``datacenter_of`` does not fail loudly; it
reports every live key as revoked. ``test_the_host_comes_from_the_keys_own_suffix``
and ``test_a_key_with_no_datacenter_is_answered_without_a_request`` pin that.

**An unrecognised role is ``UNKNOWN``, not ``READ``.** Mailchimp can add a user
level whenever it likes. ``test_a_role_keyreach_does_not_know_is_undetermined``
is the test that keeps a future role from arriving as "harmless" — a key that
can empty an audience reported as read-only is the failure mode
``AccessLevel.UNKNOWN`` exists for.

**On the fixtures.** Every path was verified against Mailchimp's live API, and
the invalid-key body is the RFC 7807 problem document that API actually
returned, verbatim. The success bodies are constructed from Mailchimp's
documented shapes; drift is roadmap **R2.10**.
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
from keyreach.providers.mailchimp import (
    CONFIDENCE,
    PROBES,
    ROLE_ACCESS,
    SENDING_ROLES,
    MailchimpProvider,
    Role,
    _identity,
    access_for,
    base_url,
    datacenter_of,
    detail_of,
    role_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
DATACENTER = "us14"
KEY = "0" * 8 + "1a2b3c4d" * 3 + "-" + DATACENTER

SEND = "Mailchimp Campaign Send"


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="mailchimp",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def root(body: str, status: int = 200) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=f"{base_url(DATACENTER)}/",
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(MailchimpProvider(), origin="keyreach.providers.mailchimp")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "mailchimp" in [provider.name for provider in registry.providers()]


def test_it_is_an_email_provider() -> None:
    assert MailchimpProvider().category == "email"


def test_it_claims_no_prior_art() -> None:
    assert MailchimpProvider().credit is None


# ---------------------------------------------------------------------------
# Detection and the datacenter suffix
# ---------------------------------------------------------------------------


def test_it_claims_a_documented_key() -> None:
    assert MailchimpProvider().detect(KEY) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-key",
        # Hex with no data centre suffix is not the documented format.
        "0" * 32,
        # The suffix without a hex body is not either.
        "-us14",
        # Uppercase: Mailchimp documents lowercase hex.
        "A" * 32 + "-us14",
    ],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert MailchimpProvider().detect(sample) == 0.0


def test_the_documented_example_key_is_recognised() -> None:
    """Mailchimp's own example has a 31-character body; issued keys have 32.

    The rule spans both rather than picking the one that suits, because the
    vendor's example is the only published length there is.
    """
    example = "0123456789abcdef0123456789abcde" + "-us6"

    assert MailchimpProvider().detect(example) == CONFIDENCE
    assert len(example.split("-", maxsplit=1)[0]) == 31


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "mailchimp-api-key")

    assert re.match(rule["pattern"], KEY)
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "mailchimp"


def test_the_detector_routes_the_key_to_mailchimp() -> None:
    assert [match.provider for match in default_detector.detect(KEY)] == ["mailchimp"]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (KEY, "us14"),
        ("0" * 31 + "-us6", "us6"),
        # No suffix at all.
        ("0" * 32, None),
        # A trailing hyphen names no data centre.
        ("0" * 32 + "-", None),
        ("-us6", None),
    ],
)
def test_the_host_comes_from_the_keys_own_suffix(
    key: str, expected: str | None
) -> None:
    """Mailchimp documents the suffix as the data centre subdomain.

    Getting this wrong does not fail loudly: the wrong host answers with the
    same 401 a revoked key gets, so every live key would look dead.
    """
    assert datacenter_of(key) == expected


def test_the_base_url_is_the_documented_one() -> None:
    assert base_url("us6") == "https://us6.api.mailchimp.com/3.0"


# ---------------------------------------------------------------------------
# The role model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (Role.OWNER, AccessLevel.ADMIN),
        (Role.ADMIN, AccessLevel.ADMIN),
        (Role.MANAGER, AccessLevel.WRITE),
        (Role.AUTHOR, AccessLevel.WRITE),
        (Role.VIEWER, AccessLevel.READ),
    ],
)
def test_each_role_maps_to_what_mailchimp_documents_it_can_do(
    role: Role, expected: AccessLevel
) -> None:
    """Every entry traces to a sentence on Mailchimp's user-levels page."""
    assert access_for(role) is expected
    assert ROLE_ACCESS[role] is expected


def test_only_the_roles_documented_as_able_to_send_are_sending_roles() -> None:
    """Author "can create, edit, and delete emails" — and cannot send them."""
    assert frozenset({Role.OWNER, Role.ADMIN, Role.MANAGER}) == SENDING_ROLES
    assert Role.AUTHOR not in SENDING_ROLES
    assert Role.VIEWER not in SENDING_ROLES


def test_a_role_keyreach_does_not_know_is_undetermined() -> None:
    """Mailchimp can add a user level; keyreach must not default it to harmless.

    Mapping an unknown role down to READ under-reports a key that can empty an
    audience. UNKNOWN is scored as undetermined, never as harmless, which is
    what `CLAUDE.md` asks for when no rule can decide.
    """
    assert role_of(root('{"role":"editor"}')) is None
    assert access_for(None) is AccessLevel.UNKNOWN


def test_a_role_is_read_case_insensitively() -> None:
    assert role_of(root('{"role":"Admin"}')) is Role.ADMIN
    assert role_of(root('{"role":" owner "}')) is Role.OWNER


def test_a_body_that_is_not_an_object_is_not_a_role() -> None:
    """Defensive parsing: an HTML error page must not read as a role."""
    assert role_of(root("<html>bad gateway</html>", status=502)) is None
    assert role_of(root('{"role":42}')) is None
    assert detail_of(root("<html>bad gateway</html>", status=502)) == ""


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_an_admin_key_is_mapped() -> None:
    result = run("mailchimp_valid")

    assert result.valid
    services = [item.service for item in result.capabilities]
    assert services == sorted(services)
    assert "Mailchimp Audiences" in services


def test_the_account_and_role_are_the_identity() -> None:
    identity = validation(run("mailchimp_valid")).identity

    assert identity is not None
    assert identity.owner == "Northwind Traders"
    assert identity.extra["role"] == "admin"
    assert identity.extra["datacenter"] == DATACENTER


def test_an_admin_key_is_admin_on_mailchimps_own_statement() -> None:
    audiences = capability(run("mailchimp_valid"), "Mailchimp Audiences")

    assert audiences.access is AccessLevel.ADMIN
    assert "determines its access" in audiences.detail
    assert "No write was performed" in audiences.detail


def test_the_send_capability_is_derived_and_nothing_was_sent() -> None:
    send = capability(run("mailchimp_valid"), SEND)

    assert send.access is AccessLevel.WRITE
    assert send.incurs_cost
    assert "No campaign was sent or scheduled" in send.detail
    assert send.poc is not None
    assert send.poc.startswith("curl -s")


def test_a_viewer_key_can_read_and_cannot_send() -> None:
    """Viewer "can view email and SMS reports" — and nothing else."""
    result = run("mailchimp_viewer")

    assert {item.access for item in result.capabilities} == {AccessLevel.READ}
    assert SEND not in [item.service for item in result.capabilities]


def test_an_unknown_role_produces_undetermined_access_and_no_send() -> None:
    result = run("mailchimp_unknown_role")

    assert {item.access for item in result.capabilities} == {AccessLevel.UNKNOWN}
    assert SEND not in [item.service for item in result.capabilities]
    assert (
        "undetermined rather than absent"
        in capability(result, "Mailchimp Audiences").detail
    )


def test_a_key_with_no_datacenter_is_answered_without_a_request() -> None:
    """No host can be derived, so guessing one would produce a false negative."""
    result = run("mailchimp_invalid", key="0" * 32)
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "no data centre suffix" in verdict.note
    assert "No request was made" in verdict.note


def test_a_rejected_key_names_the_datacenter_it_was_rejected_at() -> None:
    """ "Wrong datacenter" and "dead key" are the same 401, so say which host."""
    verdict = validation(run("mailchimp_invalid"))

    assert not verdict.valid
    assert verdict.note is not None
    assert DATACENTER in verdict.note
    assert "wrong datacenter" in verdict.note


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES
    assert validation_probe().path == "/"


def test_the_key_never_appears_in_any_output() -> None:
    for item in run("mailchimp_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("mailchimp_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("mailchimp_valid"), run("mailchimp_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic API-root response."""

    class _Stub:
        async def get(
            self,
            url: str,
            *,
            params: object = None,
            headers: object = None,
        ) -> ProbeResponse:
            del url, params, headers
            return root(body, status=status)

    return asyncio.run(MailchimpProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_root_leaves_the_role_undetermined_not_absent() -> None:
    verdict = validate_against(403, '{"detail":"Forbidden"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "undetermined rather than harmless" in verdict.note


def test_a_rate_limited_request_still_means_the_key_reached_mailchimp() -> None:
    verdict = validate_against(429, '{"detail":"Too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"detail":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_root_naming_no_account_is_no_identity_rather_than_an_empty_one() -> None:

    assert _identity(root('{"role":"admin"}'), DATACENTER) is None


def test_an_identity_omits_fields_mailchimp_did_not_send() -> None:
    """An absent field must not become an empty string in the report."""

    identity = _identity(root('{"account_id":"abc","role":"owner"}'), DATACENTER)

    assert identity is not None
    assert identity.extra == {"datacenter": DATACENTER, "role": "owner"}
