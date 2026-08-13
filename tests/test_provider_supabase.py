"""Supabase provider tests (roadmap R2.5).

Three things carry the weight here.

**One vendor sentence decides the severity.** Supabase documents a secret key as
having "full access to your project's data, bypassing Row Level Security", and
Row Level Security is the only thing standing between a Supabase API key and
every row in the database. ``test_a_secret_key_is_admin_on_supabases_own_words``
records that, and its counterpart records the restraint: a publishable key is
``READ``, and the detail says the "safe to expose" claim holds only where RLS is
configured correctly — which keyreach does not check, because checking means
reading somebody's rows.

**Supabase is the first provider detectable for its current formats and
undetectable for its legacy ones.**
``test_a_legacy_jwt_is_not_claimed_by_rule_and_that_is_deliberate`` is the
argument: legacy keys are JWTs, and a rule matching three base64 segments would
claim every JWT ever pasted at keyreach — the same reasoning that kept Discord's
community token pattern out in R2.2.

**The legacy key names its own project.** ``ref`` and ``role`` come out of the
token with no request and no guess, so ``--provider supabase`` is enough for a
legacy key while a current one needs ``<project ref>:<key>``.

**On the fixtures.** Every path comes from Supabase's documentation. Unlike this
item's other three providers, they could **not** be verified against a live API:
``<ref>.supabase.co`` has no wildcard, so reaching one requires a real project,
which keyreach does not have. That is a weaker basis than the rest of R2.5 and
is stated here rather than glossed over; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.supabase import (
    CONFIDENCE,
    PROBES,
    Credential,
    Kind,
    SupabaseProvider,
    _summary,
    base_url,
    decode_claims,
    message_of,
    parse_credential,
    probes_for,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

REF = "abcdefghijklmnopqrst"
API = base_url(REF)


def _jwt(role: str, *, ref: str | None = REF) -> str:
    """A structurally valid, cryptographically worthless Supabase legacy key."""

    def segment(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    claims: dict[str, object] = {
        "iss": "supabase",
        "role": role,
        "iat": 1750000000,
        "exp": 2065360000,
    }
    if ref is not None:
        claims["ref"] = ref
    header = segment({"alg": "HS256", "typ": "JWT"})
    return f"{header}.{segment(claims)}.{'s' * 43}"


#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
SECRET = "sb" + "_secret_" + "N0rthw1ndSupabase00000"
PUBLISHABLE = "sb" + "_publishable_" + "N0rthw1ndSupabase00000"
SERVICE_ROLE_JWT = _jwt("service_role")
ANON_JWT = _jwt("anon")


def run(fixture: str, key: str) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="supabase",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int, body: str, url: str = f"{API}/auth/v1/settings"
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
    validate_provider(SupabaseProvider(), origin="keyreach.providers.supabase")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "supabase" in [provider.name for provider in registry.providers()]


def test_it_is_a_database_provider() -> None:
    assert SupabaseProvider().category == "database"


def test_it_claims_no_prior_art() -> None:
    assert SupabaseProvider().credit is None


# ---------------------------------------------------------------------------
# Detection, and the half of it that deliberately does not exist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sample", [SECRET, PUBLISHABLE, f"{REF}:{SECRET}", f"{REF}:{PUBLISHABLE}"]
)
def test_it_claims_both_documented_formats(sample: str) -> None:
    assert SupabaseProvider().detect(sample) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    ["", "not-a-key", "sb_secret_short", "sb_other_" + "a" * 24, "pcsk_" + "a" * 24],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert SupabaseProvider().detect(sample) == 0.0


def test_a_legacy_jwt_is_not_claimed_by_rule_and_that_is_deliberate() -> None:
    """Legacy keys are JWTs, and a JWT rule would claim every JWT.

    The same argument that kept Discord's community three-segment pattern out in
    R2.2. `--provider supabase` reaches them, and `parse_credential` reads the
    project and role out of the token — so nothing is lost except the routing.
    """
    assert SupabaseProvider().detect(SERVICE_ROLE_JWT) == 0.0
    assert [match.provider for match in default_detector.detect(SERVICE_ROLE_JWT)] != [
        "supabase"
    ]
    # Still parsed, and still fully understood, once the operator names it.
    parsed = parse_credential(SERVICE_ROLE_JWT)
    assert parsed is not None
    assert parsed.kind is Kind.SECRET


@pytest.mark.parametrize("rule_id", ["supabase-secret-key", "supabase-publishable-key"])
def test_the_shipped_rules_and_the_plugin_agree(rule_id: str) -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == rule_id)
    sample = SECRET if "secret" in rule_id else PUBLISHABLE

    assert re.match(rule["pattern"], sample)
    assert re.match(rule["pattern"], f"{REF}:{sample}")
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "supabase"


def test_the_two_rules_are_separate_because_they_are_opposite_findings() -> None:
    """One key bypasses every access rule; the other is documented as public.

    A single rule would give them one description, and the description is the
    only thing a reader sees before the probes run.
    """
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    supabase = [item for item in rules if item["provider"] == "supabase"]

    assert len(supabase) == 2
    assert {item["description"] for item in supabase} == {
        "Supabase secret key",
        "Supabase publishable key",
    }


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (f"{REF}:{SECRET}", Credential(REF, SECRET, Kind.SECRET, legacy=False)),
        (
            f"{REF}:{PUBLISHABLE}",
            Credential(REF, PUBLISHABLE, Kind.PUBLISHABLE, legacy=False),
        ),
        # A legacy key carries its own project reference and role.
        (
            SERVICE_ROLE_JWT,
            Credential(REF, SERVICE_ROLE_JWT, Kind.SECRET, legacy=True),
        ),
        (ANON_JWT, Credential(REF, ANON_JWT, Kind.PUBLISHABLE, legacy=True)),
        # A current key with no project reference names no host.
        (SECRET, None),
        (PUBLISHABLE, None),
        # A legacy key with no `ref` claim names none either.
        (_jwt("service_role", ref=None), None),
        ("", None),
        (f"{REF}:not-a-supabase-key", None),
    ],
)
def test_the_credential_is_parsed_from_whichever_half_carries_the_project(
    key: str, expected: Credential | None
) -> None:
    assert parse_credential(key) == expected


def test_a_colon_that_is_not_a_project_reference_belongs_to_the_credential() -> None:
    """A Supabase project reference is twenty lowercase letters, and only that.

    Anything else before a colon is part of the key, not a host — so a legacy
    JWT that happens to contain one still parses, and a `sb_secret_` key
    prefixed with a wrong-shaped reference is refused rather than sent to a host
    that does not exist.
    """
    assert parse_credential(f"NOT-A-REF:{SECRET}") is None
    assert parse_credential(f"short:{SERVICE_ROLE_JWT}") == Credential(
        REF, SERVICE_ROLE_JWT, Kind.SECRET, legacy=True
    )


def test_an_operator_may_supply_a_reference_alongside_a_legacy_key() -> None:
    """Accepted so somebody who has both can say so; the token still wins on role."""
    parsed = parse_credential(f"{REF}:{ANON_JWT}")

    assert parsed == Credential(REF, ANON_JWT, Kind.PUBLISHABLE, legacy=True)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not.a.jwt",
        "onlyonesegment",
        "a.b",
        # Valid base64 that is not JSON.
        "aGVhZGVy.aGVsbG8.c2ln",
        # Valid JSON that is not an object.
        "aGVhZGVy.WzEsMiwzXQ.c2ln",
    ],
)
def test_a_malformed_token_decodes_to_nothing_rather_than_raising(token: str) -> None:
    """`detect` and `parse_credential` must never raise on a pasted string."""
    assert decode_claims(token) == {}


def test_decoding_reads_the_claims_supabase_documents() -> None:
    claims = decode_claims(SERVICE_ROLE_JWT)

    assert claims["role"] == "service_role"
    assert claims["ref"] == REF
    assert claims["iss"] == "supabase"


def test_the_host_comes_from_the_project_reference() -> None:
    assert base_url(REF) == f"https://{REF}.supabase.co"


def test_a_key_naming_no_project_is_answered_without_a_request() -> None:
    """`<ref>.supabase.co` has no wildcard, so a guess would not even resolve."""
    verdict = validation(run("supabase_invalid", key=SECRET))

    assert not verdict.valid
    assert verdict.note is not None
    assert "No request was made" in verdict.note
    assert "no wildcard" in verdict.note
    assert "'<project ref>:<key>'" in verdict.note


# ---------------------------------------------------------------------------
# Probe routing
# ---------------------------------------------------------------------------


def test_a_publishable_key_never_probes_the_admin_endpoints() -> None:
    """Supabase documents them as requiring a key that bypasses RLS.

    Asking anyway would be a 401 keyreach could have predicted — wasted
    authentication traffic against somebody's production project.
    """
    publishable = {probe.service for probe in probes_for(Kind.PUBLISHABLE)}
    secret = {probe.service for probe in probes_for(Kind.SECRET)}

    assert "Supabase Users" in secret
    assert "Supabase Users" not in publishable
    assert publishable < secret


def test_validation_uses_the_read_every_key_type_can_reach() -> None:
    assert validation_probe() in probes_for(Kind.PUBLISHABLE)
    assert validation_probe().path == "/auth/v1/settings"


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_secret_key_is_admin_on_supabases_own_words() -> None:
    """ "Full access to your project's data, bypassing Row Level Security."

    RLS is the entire access model of a Supabase project, so a key that bypasses
    it is administrative access to every row — established from the vendor's
    sentence, with nothing written and no row read.
    """
    result = run("supabase_service_role", key=SERVICE_ROLE_JWT)

    assert result.valid
    assert {item.access for item in result.capabilities} == {AccessLevel.ADMIN}
    assert all(
        "bypassing Row Level Security" in item.detail for item in result.capabilities
    )
    assert all("No write was performed" in item.detail for item in result.capabilities)


def test_a_secret_key_reaches_the_user_list() -> None:
    users = capability(
        run("supabase_service_role", key=SERVICE_ROLE_JWT), "Supabase Users"
    )

    assert users.data_sensitive
    assert "users: 1 listed" in users.evidence
    assert "buyer@example.invalid" not in users.evidence


def test_a_publishable_key_is_read_and_names_the_assumption_it_rests_on() -> None:
    """ "Safe to expose" is true only where RLS is configured correctly.

    keyreach does not read rows to check, so it reports what Supabase says and
    says what that depends on — rather than filing the key as harmless.
    """
    result = run("supabase_anon", key=ANON_JWT)

    assert result.valid
    assert {item.access for item in result.capabilities} == {AccessLevel.READ}
    assert all("safe to expose" in item.detail for item in result.capabilities)
    assert all(
        "not on its own evidence the project is safe" in item.detail
        for item in result.capabilities
    )
    assert "Supabase Users" not in [item.service for item in result.capabilities]


def test_the_project_and_key_type_are_the_identity() -> None:
    identity = validation(run("supabase_service_role", key=SERVICE_ROLE_JWT)).identity

    assert identity is not None
    assert identity.account == REF
    assert identity.extra == {"key_type": "secret", "format": "legacy JWT"}


def test_a_current_format_key_is_reported_as_current() -> None:
    identity = validation(run("supabase_service_role", key=f"{REF}:{SECRET}")).identity

    assert identity is not None
    assert identity.extra["format"] == "current"


def test_the_exposed_schema_is_counted_not_reprinted() -> None:
    """The schema names every table the API serves; the report does not."""
    schema = capability(
        run("supabase_service_role", key=SERVICE_ROLE_JWT), "Supabase Table Schema"
    )

    assert schema.data_sensitive
    assert "orders" not in schema.evidence


def test_a_rejected_key_names_the_project_it_was_rejected_by() -> None:
    result = run("supabase_invalid", key=SERVICE_ROLE_JWT)
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert REF in verdict.note
    assert "Invalid API key" in verdict.note
    assert result.capabilities == ()


def test_the_key_never_appears_in_any_output() -> None:
    for item in run("supabase_service_role", key=SERVICE_ROLE_JWT).capabilities:
        assert SERVICE_ROLE_JWT not in item.evidence
        assert item.poc is not None
        assert SERVICE_ROLE_JWT not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("supabase_service_role", key=SERVICE_ROLE_JWT).capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first = run("supabase_service_role", key=SERVICE_ROLE_JWT)
    second = run("supabase_service_role", key=SERVICE_ROLE_JWT)

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
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return response(status, body)

    return asyncio.run(
        SupabaseProvider().validate(SERVICE_ROLE_JWT, _Stub())  # type: ignore[arg-type]
    )


def test_a_rate_limited_request_still_means_the_key_reached_supabase() -> None:
    verdict = validate_against(429, '{"message":"Too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"msg":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"message":"a"}', "a"),
        ('{"msg":"b"}', "b"),
        ('{"error":"c"}', "c"),
        ("<html>bad gateway</html>", ""),
        ('{"message":42}', ""),
    ],
)
def test_all_three_supabase_error_shapes_are_read(body: str, expected: str) -> None:
    """PostgREST says `message`, GoTrue says `msg`, the gateway says `error`."""
    assert message_of(response(502, body)) == expected


@pytest.mark.parametrize(
    ("service", "body", "expected"),
    [
        ("Supabase Users", '{"users":[]}', "none present"),
        ("Supabase Users", '{"aud":"authenticated"}', "request accepted"),
        # `/storage/v1/bucket` returns a bare array.
        ("Supabase Storage Buckets", "[]", "none present"),
        ("Supabase Storage Buckets", '{"not":"a list"}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    service: str, body: str, expected: str
) -> None:
    probe = next(item for item in PROBES if item.service == service)

    assert expected in _summary(probe, response(200, body))
