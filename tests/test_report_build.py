"""Report assembly tests (roadmap R0.8).

``build_report`` turns evidence into a finding, which means it decides what a
security team reads first. These tests are mostly about *not overstating*: the
title, the impact line and the status label each have a case where the obvious
implementation would claim more than keyreach actually established.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from keyreach.core.engine import EngineResult, ProviderOutcome
from keyreach.core.models import (
    AccessLevel,
    Capability,
    Identity,
    Report,
    Severity,
    ValidationResult,
)
from keyreach.core.scoring import score
from keyreach.report.build import UNKNOWN_CATEGORY, UNKNOWN_PROVIDER, build_report

FIXED_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
VERSION = "0.0.0-test"


def cap(
    service: str = "Service A",
    access: AccessLevel = AccessLevel.READ,
    *,
    risk_weight: int = 10,
    data_sensitive: bool = False,
    incurs_cost: bool = False,
) -> Capability:
    return Capability(
        service=service,
        access=access,
        detail=f"Can reach {service}",
        evidence=f"GET /{service}?key=<key> -> 200",
        risk_weight=risk_weight,
        data_sensitive=data_sensitive,
        incurs_cost=incurs_cost,
    )


def outcome(
    provider: str = "demo",
    *,
    valid: bool = True,
    confidence: float = 0.9,
    capabilities: tuple[Capability, ...] = (),
    errors: tuple[str, ...] = (),
    identity: Identity | None = None,
) -> ProviderOutcome:
    return ProviderOutcome(
        provider=provider,
        category="generic",
        confidence=confidence,
        docs_url=f"https://{provider}.invalid/docs",
        rotation_guide_url=f"https://{provider}.invalid/rotate",
        validation=ValidationResult(valid=valid, identity=identity),
        capabilities=capabilities,
        errors=errors,
    )


def build(result: EngineResult) -> Report:
    return build_report(result, generated_at=FIXED_TIME, tool_version=VERSION)


def result(**kwargs: object) -> EngineResult:
    kwargs.setdefault("key_fingerprint", "demo****xyz")
    return EngineResult(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Choosing the provider a report is about
# ---------------------------------------------------------------------------


def test_a_live_provider_wins_over_a_more_confident_dead_one() -> None:
    """Detection guesses; a provider that answered knows.

    An ambiguous prefix can rank the wrong provider first. If one candidate
    accepted the key and another did not, the report is about the one that did,
    whatever the pattern suggested.
    """
    report = build(
        result(
            outcomes=(
                outcome("confident", valid=False, confidence=0.99),
                outcome("live", valid=True, confidence=0.50),
            )
        )
    )

    assert report.provider == "live"


def test_confidence_breaks_ties_among_equally_live_providers() -> None:
    report = build(
        result(
            outcomes=(
                outcome("low", valid=True, confidence=0.40),
                outcome("high", valid=True, confidence=0.95),
            )
        )
    )

    assert report.provider == "high"


def test_provider_urls_come_from_the_chosen_outcome() -> None:
    report = build(result(outcomes=(outcome("demo"),)))

    assert report.docs_url == "https://demo.invalid/docs"
    assert report.rotation_guide_url == "https://demo.invalid/rotate"


# ---------------------------------------------------------------------------
# Nothing probed
# ---------------------------------------------------------------------------


def test_an_unidentified_secret_still_produces_a_report() -> None:
    """Telling the finder that keyreach ran and could not help is a result."""
    report = build(result(notes=("Nothing was probed.",)))

    assert report.provider == UNKNOWN_PROVIDER
    assert report.provider_category == UNKNOWN_CATEGORY
    assert report.severity is Severity.INFO
    assert "could not determine the provider" in report.title


def test_an_unidentified_secret_is_not_called_harmless() -> None:
    """The impact line must not read as an all-clear for an untested secret."""
    report = build(result(notes=("Nothing was probed.",)))

    assert "not evidence that the secret is harmless" in report.impact


def test_the_engine_note_becomes_a_report_note_not_a_validation_note() -> None:
    """`valid=False` here would otherwise read as "the provider rejected it"."""
    report = build(result(notes=("Nothing was probed.",)))

    assert report.notes == ["Nothing was probed."]
    assert report.validation.note == ""


# ---------------------------------------------------------------------------
# Probe failures reach the report
# ---------------------------------------------------------------------------


def test_probe_errors_are_carried_into_the_report() -> None:
    """R0.6 collected these so a report could say what it could not determine.

    Dropping them would render a run where three probes failed identically to
    one where three probes found nothing.
    """
    report = build(
        result(outcomes=(outcome("demo", errors=("enumerate failed: timeout",)),))
    )

    assert report.notes == ["demo: enumerate failed: timeout"]


def test_notes_are_empty_when_nothing_went_wrong() -> None:
    report = build(result(outcomes=(outcome("demo", capabilities=(cap(),)),)))

    assert report.notes == []


# ---------------------------------------------------------------------------
# Title and impact
# ---------------------------------------------------------------------------


def test_title_leads_with_the_capability_that_matters_most() -> None:
    """Not the heaviest weight — the one that is both privileged and valuable."""
    report = build(
        result(
            outcomes=(
                outcome(
                    capabilities=(
                        cap("Heavy Read", risk_weight=99),
                        cap(
                            "Billing Write",
                            AccessLevel.WRITE,
                            risk_weight=30,
                            incurs_cost=True,
                        ),
                    )
                ),
            )
        )
    )

    assert "Billing Write" in report.title


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        pytest.param(1, "reaches Service 0", id="one-service"),
        pytest.param(2, "and 1 other service", id="two-services-singular"),
        pytest.param(3, "and 2 other services", id="three-services-plural"),
    ],
)
def test_title_counts_the_remaining_services(count: int, expected: str) -> None:
    capabilities = tuple(cap(f"Service {index}") for index in range(count))
    report = build(result(outcomes=(outcome(capabilities=capabilities),)))

    assert expected in report.title


def test_a_dead_key_is_not_described_as_reaching_anything() -> None:
    report = build(result(outcomes=(outcome(valid=False),)))

    assert report.title == "Exposed demo API key is no longer valid"
    assert "Rotate it anyway" in report.impact


def test_a_live_key_with_no_capability_says_exactly_that() -> None:
    report = build(result(outcomes=(outcome(valid=True),)))

    assert "live, with no capability confirmed" in report.title


@pytest.mark.parametrize(
    ("capabilities", "band"),
    [
        pytest.param(
            (cap(access=AccessLevel.WRITE, data_sensitive=True),),
            Severity.CRITICAL,
            id="critical",
        ),
        pytest.param((cap(data_sensitive=True),), Severity.HIGH, id="high"),
        pytest.param((cap(risk_weight=50),), Severity.MEDIUM, id="medium"),
        pytest.param((cap(risk_weight=20),), Severity.LOW, id="low"),
    ],
)
def test_impact_matches_the_band(
    capabilities: tuple[Capability, ...], band: Severity
) -> None:
    report = build(result(outcomes=(outcome(capabilities=capabilities),)))

    assert report.severity is band
    assert report.impact


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_the_rationale_comes_from_scoring_unchanged() -> None:
    capabilities = (cap(data_sensitive=True),)
    report = build(result(outcomes=(outcome(capabilities=capabilities),)))

    assert report.severity_rationale == list(score(capabilities).rationale)


def test_capabilities_are_merged_and_sorted_across_providers() -> None:
    report = build(
        result(
            outcomes=(
                outcome("b", capabilities=(cap("Zulu"),)),
                outcome("a", capabilities=(cap("Alpha"),)),
            )
        )
    )

    assert [c.service for c in report.capabilities] == ["Alpha", "Zulu"]


def test_the_timestamp_is_the_caller_s_not_the_clock_s() -> None:
    report = build(result(outcomes=(outcome(),)))

    assert report.generated_at == FIXED_TIME


def test_a_naive_timestamp_is_rejected() -> None:
    """The guarantee is enforced by the model; this proves the path reaches it."""
    with pytest.raises(ValueError, match="timezone-aware"):
        build_report(
            result(outcomes=(outcome(),)),
            generated_at=datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001
            tool_version=VERSION,
        )


def test_identity_survives_into_the_report() -> None:
    identity = Identity(account="acct_1", owner="Acme", plan_or_tier="pro")
    report = build(result(outcomes=(outcome(identity=identity),)))

    assert report.validation.identity == identity


def test_remediation_leads_with_rotation() -> None:
    """An exposed key keeps working while somebody reads logs."""
    report = build(result(outcomes=(outcome(),)))

    assert report.remediation
    assert "rotate this key now" in report.remediation[0]
