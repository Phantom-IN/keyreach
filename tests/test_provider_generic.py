"""Generic bearer/JWT inspector tests (roadmap R2.7).

Two things carry the weight here.

**A well-formed, unverified JWT reports `valid=False`, on the same precedent
as AWS's bare access key ID.** `test_a_bare_jwt_is_not_reported_valid` is the
test that matters: keyreach decoded real claims out of the token, but
confirmed nothing against a server, so it is not "live" in the sense every
other provider's `valid=True` means — and the claims still populate
`Identity`, because an unverified fact volunteered by the token is more
useful than silence.

**This is the first detection rule sourced to a standard rather than a
vendor**, and it is deliberately the pattern R2.2 and R2.5 kept out of
Discord's and Supabase's own rules: "a regex over three base64 segments
claims every JWT ever pasted at keyreach" is disqualifying for a
vendor-specific rule and is exactly right for a provider that names no
vendor. `test_detect_claims_a_jwt_but_not_the_query_string` pins that the
confidence sits between a vendor prefix rule and the entropy fallback.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.generic import (
    CONFIDENCE,
    PROBES,
    Credential,
    GenericProvider,
    _format_timestamp,
    claims_extra,
    decode,
    parse_credential,
)

FIXTURES = Path(__file__).parent / "fixtures"

ENDPOINT = "https://internal.example.com/whoami"


def _jwt(
    claims: dict[str, object] | None = None,
    *,
    alg: str = "HS256",
) -> str:
    """A structurally valid, cryptographically worthless JWT."""

    def segment(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = segment({"alg": alg, "typ": "JWT"})
    body: dict[str, object] = (
        claims if claims is not None else {"iss": "example", "sub": "user-1"}
    )
    return f"{header}.{segment(body)}.{'s' * 43}"


#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
JWT = _jwt({"iss": "example.com", "sub": "user-1", "aud": "api", "exp": 2065360000})
OPAQUE_TOKEN = "op" + "aque-bearer-token-0000000000000000"


def run(fixture: str, key: str) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="generic",
    )
    return asyncio.run(engine.run(key))


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(GenericProvider(), origin="keyreach.providers.generic")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "generic" in [provider.name for provider in registry.providers()]


def test_it_is_a_generic_provider() -> None:
    assert GenericProvider().category == "generic"


def test_it_claims_no_prior_art() -> None:
    assert GenericProvider().credit is None


def test_it_is_a_detection_candidate_for_a_jwt() -> None:
    assert GenericProvider().detect(JWT) == CONFIDENCE


def test_detect_claims_a_jwt_but_not_the_query_string() -> None:
    """Confidence sits between a vendor prefix rule and the entropy fallback."""
    assert 0.5 < CONFIDENCE < 0.95
    assert GenericProvider().detect(f"{JWT}@{ENDPOINT}") == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-jwt",
        OPAQUE_TOKEN,
        "a.b",
        "a.b.c.d",
        "not-base64!.not-base64!.not-base64!",
    ],
)
def test_detect_claims_nothing_for_anything_else(sample: str) -> None:
    assert GenericProvider().detect(sample) == 0.0


def test_the_default_detector_finds_the_jwt_rule() -> None:
    matches = default_detector.detect(JWT)

    assert any(match.provider == "generic" for match in matches)


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------


def test_parse_credential_splits_on_the_first_at_sign() -> None:
    assert parse_credential(f"{JWT}@{ENDPOINT}") == Credential(JWT, ENDPOINT)
    assert parse_credential(JWT) == Credential(JWT, "")


def test_parse_credential_rejects_a_too_short_token() -> None:
    assert parse_credential("short") is None
    assert parse_credential("") is None


# ---------------------------------------------------------------------------
# JWT decoding
# ---------------------------------------------------------------------------


def test_decode_reads_header_and_payload() -> None:
    decoded = decode(JWT)

    assert decoded is not None
    assert decoded.header["alg"] == "HS256"
    assert decoded.payload["sub"] == "user-1"


@pytest.mark.parametrize(
    "token",
    [
        "not.enough",
        "too.many.segments.here",
        "not-base64!.not-base64!.not-base64!",
        # Valid base64, but not JSON.
        base64.urlsafe_b64encode(b"not json").decode() + "..",
    ],
)
def test_decode_returns_none_for_anything_malformed(token: str) -> None:
    assert decode(token) is None


def test_decode_rejects_a_segment_that_is_not_a_json_object() -> None:
    def segment(value: object) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
        )

    token = f"{segment([1, 2, 3])}.{segment({'sub': 'x'})}.sig"

    assert decode(token) is None


def test_format_timestamp_converts_a_given_number_only() -> None:
    assert _format_timestamp(2065360000) == "2035-06-13T15:06:40+00:00"


@pytest.mark.parametrize("value", [None, "not-a-number", True, float("inf")])
def test_format_timestamp_rejects_anything_that_is_not_a_real_number(
    value: object,
) -> None:
    assert _format_timestamp(value) is None


def test_claims_extra_reports_alg_none_as_a_fact() -> None:
    decoded = decode(_jwt({"sub": "x"}, alg="none"))
    assert decoded is not None

    extra = claims_extra(decoded)

    assert extra["alg"] == "none"
    assert "unsecured JWS" in extra["alg_none"]


def test_claims_extra_tolerates_a_header_with_no_alg() -> None:
    header = (
        base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = base64.urlsafe_b64encode(json.dumps({}).encode()).rstrip(b"=").decode()
    decoded = decode(f"{header}.{payload}.sig")
    assert decoded is not None

    assert "alg" not in claims_extra(decoded)


def test_claims_extra_reports_kid_when_present() -> None:
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "key-1"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = base64.urlsafe_b64encode(json.dumps({}).encode()).rstrip(b"=").decode()
    decoded = decode(f"{header}.{payload}.sig")
    assert decoded is not None

    assert claims_extra(decoded)["kid"] == "key-1"


def test_claims_extra_joins_a_list_scoped_claim() -> None:
    decoded = decode(_jwt({"aud": ["api-a", "api-b"]}))
    assert decoded is not None

    assert claims_extra(decoded)["aud"] == "api-a, api-b"


def test_claims_extra_omits_absent_claims() -> None:
    decoded = decode(_jwt({}))
    assert decoded is not None

    extra = claims_extra(decoded)

    assert "exp" not in extra
    assert "sub" not in extra


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_bare_jwt_is_not_reported_valid() -> None:
    """No server was contacted — see the module docstring."""
    result = run("generic_empty", JWT)
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.identity is not None
    assert verdict.identity.account == "user-1"
    assert verdict.identity.owner == "example.com"
    assert verdict.note is not None
    assert "no signature was checked" in verdict.note
    assert result.capabilities == ()


def test_a_jwt_with_an_accepted_endpoint_is_valid_and_enumerated() -> None:
    result = run("generic_accepted", f"{JWT}@{ENDPOINT}")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.identity is not None
    assert verdict.identity.account == "user-1"
    assert [c.service for c in result.capabilities] == ["Operator-Specified Endpoint"]
    capability = result.capabilities[0]
    assert capability.access is AccessLevel.UNKNOWN
    assert capability.resource_ref == ENDPOINT


def test_a_jwt_with_a_rejected_endpoint_is_not_valid() -> None:
    result = run("generic_rejected", f"{JWT}@{ENDPOINT}")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "responded 401" in verdict.note
    assert result.capabilities == ()


def test_an_opaque_token_with_an_accepted_endpoint_has_no_identity() -> None:
    result = run("generic_accepted", f"{OPAQUE_TOKEN}@{ENDPOINT}")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.identity is None
    assert len(result.capabilities) == 1


def test_an_opaque_token_with_no_endpoint_is_rejected_without_a_request() -> None:
    verdict = validation(run("generic_empty", OPAQUE_TOKEN))

    assert not verdict.valid
    assert verdict.note == (
        "This does not look like a JWT, and no target URL was given. Pass "
        "'TOKEN@https://your-endpoint' to check where this bearer token "
        "authenticates"
    )
    assert not verdict.identity


def test_a_too_short_token_is_rejected_without_a_request() -> None:
    verdict = validation(run("generic_empty", "short"))

    assert not verdict.valid
    assert verdict.note == "This is too short to be a bearer token"


def test_the_capability_and_evidence_are_masked() -> None:
    result = run("generic_accepted", f"{JWT}@{ENDPOINT}")

    for item in result.capabilities:
        assert JWT not in item.evidence
        assert item.poc is not None
        assert JWT not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first = run("generic_accepted", f"{JWT}@{ENDPOINT}")
    second = run("generic_accepted", f"{JWT}@{ENDPOINT}")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_probe_table_has_one_entry() -> None:
    assert len(PROBES) == 1
    assert PROBES[0].source.startswith("https://")


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def test_enumerate_returns_nothing_for_an_unparseable_key() -> None:
    capabilities = asyncio.run(
        GenericProvider().enumerate("short", None)  # type: ignore[arg-type]
    )

    assert capabilities == []


class _FailingGet:
    """A context whose GET always fails, to reach `enumerate`'s `not response.ok`."""

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        return ProbeResponse(
            method="GET", url=url, status_code=500, headers={}, text="{}"
        )

    def protect(self, secret: str) -> None:
        del secret

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return JWT


def test_enumerate_returns_nothing_when_the_endpoint_fails() -> None:
    capabilities = asyncio.run(
        GenericProvider().enumerate(
            f"{JWT}@{ENDPOINT}", _FailingGet()  # type: ignore[arg-type]
        )
    )

    assert capabilities == []
