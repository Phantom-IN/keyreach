"""npm provider tests (roadmap R2.4; migrated to the declarative probe runner
in roadmap R2.8).

This is the **second detection rule keyreach has had to withdraw**, after
Mailgun in R2.3, and ``test_the_withdrawn_rule_has_not_come_back`` is the test
that matters. keyreach shipped ``^npm_[A-Za-z0-9]{36}$`` from R0.5, sourced to
npm's "About access tokens" page. That page describes a token only as "a
hexadecimal string that you can use to authenticate" — no prefix, and a charset
the rule contradicts — and npm's CLI reference and CI/CD guide both deliberately
refuse to print a token value at all. There is nowhere in npm's own
documentation left to source a format from.

Restoring the rule would look like a fix. It would match real tokens. And
nobody could re-verify it, which is the single property `detection_rules.yml`
promises about every line in it.

``test_only_documented_endpoints_are_probed`` guards the other decision. npm's
registry answers ``/-/npm/v1/user``, which is the obvious place to get an
identity from, and npm's API reference does not document it. This item withdrew
a rule for resting on an unverifiable claim; building a probe on one would be
the same mistake pointed the other way, so the report names the account's tokens
rather than the person.

**On the fixtures.** Both paths come from npm's registry API reference and were
verified against the live registry. The 401 body is empty because that is what
the registry actually returns — with ``www-authenticate: Basic, Bearer`` and
nothing else, which is why the rejection note does not quote a message.

**On the migration.** R2.8 rewrote this plugin from a hand-written `enumerate`
to `keyreach/providers/npm.yml`, played back by
`keyreach.core.probes.YamlProvider`. Nothing here tests the runner's own
parsing or matching logic in isolation — that lives in `tests/test_probes.py`
— this module only proves npm's own spec produces the same behaviour the old
Python module did, against the same committed cassettes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.probes import YamlProvider, _message_of, _summary
from keyreach.core.registry import ProviderRegistry, validate_provider

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"
SPEC_PATH = Path(__file__).parent.parent / "keyreach" / "providers" / "npm.yml"
REGISTRY = "https://registry.npmjs.org"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`). This is the *legacy* shape, used here
#: precisely to show that keyreach no longer claims it by rule.
KEY = "npm" + "_" + "kR7pQ2xLm9VtZ4bW8sJhD3nY6cFgA1eU5oPi"


def provider() -> YamlProvider:
    return ProviderRegistry("keyreach.providers").get("npm")  # type: ignore[return-value]


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="npm",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int, body: str, url: str = f"{REGISTRY}/-/npm/v1/tokens"
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
    validate_provider(provider(), origin="keyreach.providers.npm")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "npm" in [item.name for item in registry.providers()]


def test_it_is_loaded_from_the_declarative_runner() -> None:
    """R2.8: npm is one of the first two providers played back from YAML."""
    assert isinstance(provider(), YamlProvider)
    assert provider().source_path == SPEC_PATH


def test_it_is_a_devtools_provider() -> None:
    assert provider().category == "devtools"


def test_it_claims_no_prior_art() -> None:
    assert provider().credit is None


# ---------------------------------------------------------------------------
# The withdrawn rule — the second in two roadmap items
# ---------------------------------------------------------------------------


def test_the_withdrawn_rule_has_not_come_back() -> None:
    """keyreach shipped an npm rule from R0.5 and withdrew it in R2.4.

    The page it cited describes a token as "a hexadecimal string", which is not
    a format and contradicts the rule's own charset. npm's CLI reference and
    CI/CD guide both refuse to print a token value. Restoring the rule would
    look like a fix and would reinstate a claim nobody can re-verify.
    """
    document = RULES.read_text(encoding="utf-8")
    rules = yaml.safe_load(document)["rules"]

    assert [rule for rule in rules if rule["provider"] == "npm"] == []
    # The withdrawal is recorded in the file, so the absence reads as a decision
    # rather than as an oversight.
    assert "WITHDRAWN IN R2.4" in document


def test_it_is_not_a_detection_candidate() -> None:
    assert provider().detectable is False


@pytest.mark.parametrize(
    "sample",
    [KEY, "", "not-a-key", "npm_" + "a" * 36, "0123456789abcdef" * 2],
)
def test_detect_claims_nothing_at_all(sample: str) -> None:
    """`detectable = False` must mean it in both places, including for the
    exact shape the withdrawn rule used to match."""
    assert provider().detect(sample) == 0.0


def test_nothing_routes_a_legacy_shaped_token_to_npm() -> None:
    """The cost of the withdrawal, measured rather than asserted.

    A real npm token is 36 random characters, so the entropy fallback still
    reports it as a secret of unknown provenance — the correct residual answer,
    and the same outcome the Mailgun withdrawal produced in R2.3.
    """
    matches = default_detector.detect(KEY)

    assert [match.provider for match in matches] == [None]
    assert matches[0].rule_id == "entropy-fallback"


def test_the_residual_answer_is_not_guaranteed_and_that_is_worth_knowing() -> None:
    """A withdrawal does not cost the same for every token, and this measures it.

    The entropy fallback is a floor, not a guarantee: `looks_like_secret` gates
    on length, charset, and — the one that bites here — the presence of at least
    one digit, which keeps it off `someVeryLongVariableNameHere`. An npm token
    that happens to be all letters therefore now matches *nothing at all*, where
    before the withdrawn rule named the vendor.
    """
    all_letters = "npm" + "_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"

    assert list(default_detector.detect(all_letters)) == []


# ---------------------------------------------------------------------------
# Probe table hygiene
# ---------------------------------------------------------------------------


def test_only_documented_endpoints_are_probed() -> None:
    """`/-/npm/v1/user` answers and npm's API reference does not document it.

    It is the obvious place to get an identity from, and this item withdrew a
    detection rule for resting on an unverifiable claim. Building a probe on one
    would be the same mistake pointed the other way.
    """
    assert {probe.url for probe in provider().spec.probes} == {
        f"{REGISTRY}/-/npm/v1/tokens",
        f"{REGISTRY}/-/stage",
    }


def test_validation_reuses_a_probe_endpoint() -> None:
    spec = provider().spec

    assert spec.liveness.probe == "npm Tokens"
    assert next(p for p in spec.probes if p.service == "npm Tokens").url == (
        f"{REGISTRY}/-/npm/v1/tokens"
    )


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_token_yields_a_capability_map() -> None:
    result = run("npm_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "npm Staged Versions",
        "npm Tokens",
    ]


def test_the_token_list_is_counted_and_no_token_is_printed() -> None:
    """A leaked token that reads this discloses every other token on the account.

    The count is the finding — the same shape as Postmark's `ApiTokens` in R2.3.
    """
    tokens = capability(run("npm_valid"), "npm Tokens")

    assert tokens.data_sensitive
    assert "tokens: 1 listed" in tokens.evidence
    assert "ci-publish" not in tokens.evidence


def test_no_capability_claims_a_write_npm_cannot_attribute() -> None:
    """`/-/npm/v1/tokens` returns `readonly` per token and does not mark which
    entry is the calling one."""
    capabilities = run("npm_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)


def test_no_identity_is_invented() -> None:
    """npm's API reference documents no endpoint that names the account."""
    assert validation(run("npm_valid")).identity is None


def test_a_rejected_token_is_reported_without_quoting_an_empty_body() -> None:
    """The registry answers 401 with no body at all, verified live."""
    result = run("npm_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note == "npm did not accept this token"
    assert result.capabilities == ()


def test_the_token_never_appears_in_any_output() -> None:
    for item in run("npm_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("npm_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("npm_valid"), run("npm_valid")

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

    return asyncio.run(provider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_endpoint_might_be_a_package_scoped_token() -> None:
    """A granular token restricted to specific packages is refused exactly so."""
    verdict = validate_against(403, '{"error":"Forbidden"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "granular token restricted to specific packages" in verdict.note
    assert "lower bound" in verdict.note


def test_a_rate_limited_request_still_means_the_token_reached_npm() -> None:
    verdict = validate_against(429, '{"error":"Too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"message":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_body_that_is_not_an_object_is_not_a_message() -> None:
    """Defensive parsing: an HTML error page must not read as a message."""
    assert _message_of(provider().spec, response(502, "<html>bad gateway</html>")) == ""


@pytest.mark.parametrize(
    ("service", "body", "expected"),
    [
        ("npm Tokens", '{"objects":[]}', "none present"),
        ("npm Tokens", '{"total":0}', "request accepted"),
        # `/-/stage` returns a bare array, not an object.
        ("npm Staged Versions", "[]", "none present"),
        ("npm Staged Versions", '{"not":"a list"}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    service: str, body: str, expected: str
) -> None:
    probe = next(item for item in provider().spec.probes if item.service == service)

    assert expected in _summary(probe, response(200, body))
