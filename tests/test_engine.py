"""Engine orchestration tests (roadmap R0.6).

Covers the half of R0.6 that is not the HTTP layer: resolving detections to
providers, running validate then enumerate, keeping ordering stable, and
surviving a provider that misbehaves.

The provider used here is a fixture plugin driven entirely by a cassette, so
these tests exercise the real ``ProbeContext`` surface without a network — which
is the point of the cassette layer, and what lets CI run with no live key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keyreach.core.detect import Detector
from keyreach.core.engine import MAX_PROVIDERS_PROBED, Engine, EngineResult
from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    RecordMode,
    Redactor,
    mask_key,
)
from keyreach.core.models import AccessLevel, ValidationResult
from keyreach.core.provider import Provider
from keyreach.core.registry import ProviderRegistry

CASSETTE_PACKAGE = "tests.cassette_providers"
CASSETTE = Path(__file__).parent / "fixtures" / "cassette_provider.json"

#: Matches the `cassette` rule in tests/fixtures/detection_rules.yml.
VALID_KEY = "csst_" + "a" * 32
INVALID_KEY = "csst_" + "b" * 32
UNKNOWN_KEY = "this-matches-no-rule-at-all"

RULES = Path(__file__).parent / "fixtures" / "detection_rules.yml"


def engine(**kwargs: object) -> Engine:
    kwargs.setdefault("registry", ProviderRegistry(CASSETTE_PACKAGE))
    kwargs.setdefault("detector", Detector(RULES))
    kwargs.setdefault("cassette", Cassette(CASSETTE))
    kwargs.setdefault("mode", RecordMode.REPLAY)
    return Engine(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The happy path, entirely from a committed cassette
# --------------------------------------------------------------------------


async def test_valid_key_is_validated_and_enumerated() -> None:
    result = await engine().run(VALID_KEY)

    assert result.valid
    assert [outcome.provider for outcome in result.outcomes] == ["cassette"]

    outcome = result.outcomes[0]
    assert outcome.validation.identity is not None
    assert outcome.validation.identity.account == "acct_demo"
    assert [c.service for c in outcome.capabilities] == [
        "Cassette Files",
        "Cassette Metadata",
    ]
    assert outcome.errors == ()


async def test_invalid_key_is_reported_without_enumerating() -> None:
    """A dead key produces no capabilities and no wasted probes.

    Its own cassette, per CLAUDE.md ("record fixtures for a valid and an
    invalid/expired key response"). Separate files are required, not just tidy:
    redaction replaces the key with a fixed placeholder, so both keys produce
    the same recorded URL and one cassette cannot hold two answers for it.
    """
    result = await engine(
        cassette=Cassette(CASSETTE.with_name("cassette_provider_invalid.json"))
    ).run(INVALID_KEY)

    assert not result.valid
    assert result.outcomes[0].capabilities == ()
    assert result.outcomes[0].validation.note == "provider rejected the key"


async def test_no_enumerate_stops_after_validation() -> None:
    """Mirrors `--no-enumerate` (R1.5): validity and identity only."""
    result = await engine(enumerate_capabilities=False).run(VALID_KEY)

    assert result.valid
    assert result.outcomes[0].capabilities == ()


async def test_run_is_deterministic() -> None:
    """Same key, same recorded responses, identical result."""
    first = await engine().run(VALID_KEY)
    second = await engine().run(VALID_KEY)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


async def test_capabilities_are_stably_sorted() -> None:
    """The provider returns them unsorted on purpose."""
    result = await engine().run(VALID_KEY)

    assert list(result.capabilities) == sorted(
        result.capabilities, key=lambda c: c.sort_key
    )


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------


async def test_result_carries_a_masked_fingerprint_not_the_key() -> None:
    result = await engine().run(VALID_KEY)

    assert result.key_fingerprint == mask_key(VALID_KEY)
    assert VALID_KEY not in result.model_dump_json()


async def test_unmask_surfaces_the_real_key() -> None:
    """Explicit opt-in, and it must actually take effect."""
    result = await engine(unmask=True).run(VALID_KEY)

    assert result.key_fingerprint == VALID_KEY


async def test_evidence_never_contains_the_raw_key() -> None:
    """Evidence reaches the report, and the report gets pasted into a ticket."""
    result = await engine().run(VALID_KEY)

    for capability in result.capabilities:
        assert VALID_KEY not in capability.evidence
        assert "<key>" in capability.evidence


# --------------------------------------------------------------------------
# Detection to provider resolution
# --------------------------------------------------------------------------


async def test_unrecognised_key_probes_nothing_and_explains_why() -> None:
    result = await engine().run(UNKNOWN_KEY)

    assert result.outcomes == ()
    assert result.notes
    assert "Nothing was probed" in result.notes[0]


async def test_detected_but_unsupported_provider_probes_nothing() -> None:
    """Detection deliberately runs ahead of plugins.

    Recognising a key keyreach cannot yet enumerate is still worth telling the
    user — but it must not be mistaken for a completed scan.
    """
    registry = ProviderRegistry("keyreach.providers")  # empty until R1.1
    result = await engine(registry=registry).run(VALID_KEY)

    assert result.outcomes == ()
    assert "no provider plugin is installed" in result.notes[0]


async def test_high_entropy_unattributed_key_probes_nothing() -> None:
    result = await engine().run("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01")

    assert result.outcomes == ()
    assert "matches no known key format" in result.notes[0]


async def test_only_the_top_candidates_are_probed() -> None:
    """The cap is a real limit, not just a documented constant.

    Detection returning several candidates for an ambiguous prefix is normal;
    probing all of them means authenticating against services the key almost
    certainly does not belong to.
    """
    result = await engine(max_providers=1).run(VALID_KEY)

    assert len(result.outcomes) == 1


def test_probe_breadth_is_capped() -> None:
    """Probing every ambiguous candidate is authentication traffic against
    services the key almost certainly does not belong to (plan.md §11)."""
    assert 1 <= MAX_PROVIDERS_PROBED <= 5


# --------------------------------------------------------------------------
# Failure handling
# --------------------------------------------------------------------------


async def test_a_failing_probe_degrades_that_provider_only() -> None:
    """A cassette with no recording for the enumerate call.

    The validation evidence already gathered must survive, and the report must
    be able to say "could not determine" rather than "no access".
    """
    result = await engine(
        registry=ProviderRegistry("tests.cassette_providers"),
        cassette=Cassette(
            Path(__file__).parent / "fixtures" / "cassette_provider_partial.json"
        ),
    ).run(VALID_KEY)

    outcome = result.outcomes[0]
    assert outcome.validation.valid
    assert outcome.capabilities == ()
    assert outcome.errors
    assert "enumerate failed" in outcome.errors[0]


async def test_probe_errors_are_masked() -> None:
    result = await engine(
        cassette=Cassette(
            Path(__file__).parent / "fixtures" / "cassette_provider_partial.json"
        ),
    ).run(VALID_KEY)

    for error in result.outcomes[0].errors:
        assert VALID_KEY not in error


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------


def test_engine_result_defaults_are_empty() -> None:
    result = EngineResult(key_fingerprint="****")

    assert result.outcomes == ()
    assert result.capabilities == ()
    assert not result.valid


async def test_result_is_frozen() -> None:
    result = await engine().run(VALID_KEY)

    with pytest.raises(Exception, match="frozen"):
        result.key_fingerprint = "changed"


# --------------------------------------------------------------------------
# The cassette fixture itself
# --------------------------------------------------------------------------


def test_committed_cassette_contains_no_secret() -> None:
    """The guarantee that makes committing fixtures acceptable at all.

    Read as raw text, not parsed: a secret smuggled into a header value or a
    nested body would be missed by checking only the fields we expect.
    """
    for path in sorted(CASSETTE.parent.glob("cassette_provider*.json")):
        raw = path.read_text(encoding="utf-8")

        assert VALID_KEY not in raw, path.name
        assert INVALID_KEY not in raw, path.name
        assert "<key>" in raw, path.name


def test_committed_cassette_is_valid_and_deterministic() -> None:
    document = json.loads(CASSETTE.read_text(encoding="utf-8"))
    urls = [i["url"] for i in document["interactions"]]

    assert document["version"] == 1
    assert urls == sorted(urls), "interactions must be written sorted"


async def test_provider_contract_is_satisfied_through_probe_context() -> None:
    """The R0.6 criterion: probes run only through ProbeContext.

    The fixture provider imports no HTTP library — ruff's banned-api rule would
    reject that — and reaches the network solely through the context it is
    handed.
    """
    registry = ProviderRegistry(CASSETTE_PACKAGE)
    provider: Provider = registry.get("cassette")

    cassette = Cassette(CASSETTE)

    async with ProbeClient(
        redactor=Redactor([VALID_KEY]), cassette=cassette, mode=RecordMode.REPLAY
    ) as client:
        context = ProbeContext(client, VALID_KEY)
        validation: ValidationResult = await provider.validate(VALID_KEY, context)
        capabilities = await provider.enumerate(VALID_KEY, context)

    assert validation.valid
    assert all(c.access is AccessLevel.READ for c in capabilities)
