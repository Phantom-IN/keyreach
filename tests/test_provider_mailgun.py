"""Mailgun provider tests (roadmap R2.3).

The tests that carry the weight here are about a **rule that was withdrawn** and
about **two things keyreach deliberately does not claim**.

``test_the_withdrawn_rule_has_not_come_back`` is the important one. keyreach
shipped ``^key-[0-9a-f]{32}$`` for Mailgun from R0.5, sourced to a page that no
longer documents any format at all. The regression it guards is somebody
restoring the rule from memory: it would look like a fix, it would match real
legacy keys, and nobody would be able to re-verify it — which is the one
property ``detection_rules.yml`` promises about every line in it.

``test_no_capability_claims_a_write_mailgun_does_not_attribute_to_this_key``
covers the second. Mailgun says account API keys have "full access", which would
license a write — and also documents an Analyst role with read-only access,
while publishing nothing that says which role the calling key holds. So the
sentence does not apply to every key and is not used.

``test_a_rejected_key_might_be_a_live_sending_key`` covers the third. A domain
sending key can only POST to the message endpoint, so it fails every read here
with the same message a revoked key gets. Mailgun does not distinguish them the
way Resend does, so neither does keyreach.

**On the fixtures.** Every path was verified against Mailgun's live API, and the
invalid-key body is the response that API actually returned, verbatim. The
success bodies are constructed from Mailgun's documented shapes; drift is
roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.mailgun import (
    API,
    PROBES,
    MailgunProvider,
    _summary,
    message_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`). This is the *legacy* shape, used here
#: precisely to show that keyreach no longer claims it by rule.
KEY = "key" + "-" + "0123456789abcdef" * 2


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="mailgun",
    )
    return asyncio.run(engine.run(key))


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(MailgunProvider(), origin="keyreach.providers.mailgun")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "mailgun" in [provider.name for provider in registry.providers()]


def test_it_is_an_email_provider() -> None:
    assert MailgunProvider().category == "email"


def test_it_claims_no_prior_art() -> None:
    assert MailgunProvider().credit is None


# ---------------------------------------------------------------------------
# The withdrawn rule — what R2.3 found here
# ---------------------------------------------------------------------------


def test_the_withdrawn_rule_has_not_come_back() -> None:
    """keyreach shipped a Mailgun rule from R0.5 and withdrew it in R2.3.

    Its source page documents no key format any more, and neither does any
    other page Mailgun publishes. Restoring the rule would look like a fix and
    would reinstate a claim nobody can re-verify, which is the single property
    `detection_rules.yml` promises about every line in it.
    """
    document = RULES.read_text(encoding="utf-8")
    rules = yaml.safe_load(document)["rules"]

    assert [rule for rule in rules if rule["provider"] == "mailgun"] == []
    # The withdrawal is recorded in the file, so the absence reads as a decision
    # rather than as an oversight.
    assert "WITHDRAWN IN R2.3" in document


def test_it_is_not_a_detection_candidate() -> None:
    assert MailgunProvider().detectable is False


@pytest.mark.parametrize(
    "sample",
    [
        KEY,
        "",
        "not-a-key",
        "0123456789abcdef" * 2,
        "pubkey" + "-" + "0123456789abcdef" * 2,
    ],
)
def test_detect_claims_nothing_at_all(sample: str) -> None:
    """`detectable = False` must mean it in both places, including for the
    exact shape the withdrawn rule used to match."""
    assert MailgunProvider().detect(sample) == 0.0


def test_nothing_routes_a_legacy_shaped_key_to_mailgun() -> None:
    """The cost of the withdrawal, measured rather than asserted.

    No rule names Mailgun any more, so a legacy-shaped key reaches this plugin
    only through `--provider mailgun`, and the report records that the operator
    asserted the provider rather than a rule recognising it.

    What the key does *not* become is invisible: the entropy fallback still
    reports it as a secret of unknown provenance, which is the correct residual
    answer and is worth pinning, because "keyreach says nothing at all" would be
    a worse outcome than "keyreach cannot say whose this is".
    """
    matches = default_detector.detect(KEY)

    assert [match.provider for match in matches] == [None]
    assert matches[0].rule_id == "entropy-fallback"


# ---------------------------------------------------------------------------
# Probe table hygiene
# ---------------------------------------------------------------------------


def test_every_probe_is_under_the_documented_api_base() -> None:
    for probe in PROBES:
        assert probe.url.startswith(API)


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


def test_validation_uses_the_read_that_names_nobody() -> None:
    """`/v1/keys` would also prove liveness and would disclose the account's
    other credentials, so it is a probe rather than the liveness check."""
    assert validation_probe().url == f"{API}/v3/domains"


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_capability_map() -> None:
    result = run("mailgun_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Mailgun API Keys",
        "Mailgun Domains",
        "Mailgun Mailing Lists",
        "Mailgun Routes",
    ]


def test_no_capability_claims_a_write_mailgun_does_not_attribute_to_this_key() -> None:
    """ "Full access" is documented for account keys, and Analyst is read-only.

    Nothing Mailgun publishes says which role the calling key holds, so the
    sentence that would license a write does not apply to every key and is not
    used. The detail says so rather than leaving the omission silent.
    """
    capabilities = run("mailgun_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert not any(item.incurs_cost for item in capabilities)
    assert all(
        "Write access is therefore undetermined" in i.detail for i in capabilities
    )


def test_no_identity_is_invented() -> None:
    """Mailgun publishes no "who am I" endpoint, so keyreach reports no account."""
    assert validation(run("mailgun_valid")).identity is None


def test_a_rejected_key_might_be_a_live_sending_key() -> None:
    """The honest verdict where Resend's plugin can give a confident one.

    Resend answers `restricted_api_key` for a live sending key. Mailgun answers
    "Invalid private key" for both a sending key and a revoked one, so a reader
    who sees this must not conclude the credential is dead.
    """
    verdict = validation(run("mailgun_invalid"))

    assert not verdict.valid
    assert verdict.note is not None
    assert "Invalid private key" in verdict.note
    assert "sending keys" in verdict.note
    assert "exactly as a revoked key is" in verdict.note


def test_a_body_that_is_not_an_object_is_not_a_message() -> None:
    """Defensive parsing: an HTML error page must not read as a message."""
    html = ProbeResponse(
        method="GET",
        url=f"{API}/v3/domains",
        status_code=502,
        headers={},
        text="<html>bad gateway</html>",
    )

    assert message_of(html) == ""


def test_the_key_never_appears_in_any_output() -> None:
    for item in run("mailgun_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("mailgun_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("mailgun_valid"), run("mailgun_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def response(status: int, body: str) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=f"{API}/v3/domains",
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic response."""

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

    return asyncio.run(MailgunProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_endpoint_still_means_the_key_is_live() -> None:
    """403 is Mailgun refusing a resource, not the credential."""
    verdict = validate_against(403, '{"message":"Forbidden"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "lower bound" in verdict.note


def test_a_rate_limited_request_still_means_the_key_reached_mailgun() -> None:
    verdict = validate_against(429, '{"message":"Too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"message":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"total_count":0}', "request accepted"),
        ('{"items":[]}', "none present"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    body: str, expected: str
) -> None:

    assert expected in _summary(PROBES[0], response(200, body))
