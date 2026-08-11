"""Core data model tests (roadmap R0.3).

R0.3's acceptance criterion is "models validate and schema is generated
deterministically". These cover the first half; ``test_report_schema.py``
covers the second.

The emphasis is on the invariants that protect keyreach's guarantees rather
than on pydantic's own behaviour: capabilities cannot be recorded in an
unstable order, timestamps cannot be naive, severity bands compare in a fixed
order, and a report round-trips through JSON byte-identically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from keyreach.core.models import (
    SCHEMA_VERSION,
    AccessLevel,
    Capability,
    Identity,
    Report,
    Severity,
    ValidationResult,
)

FIXED_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_capability(**overrides: object) -> Capability:
    defaults: dict[str, object] = {
        "service": "Gemini Files API",
        "access": AccessLevel.READ,
        "detail": "Can list files uploaded to the Gemini project",
        "evidence": "GET /v1beta/files?key=AIza****3xY -> 200, 4 files listed",
        "risk_weight": 70,
        "data_sensitive": True,
        "incurs_cost": True,
    }
    return Capability(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_report(**overrides: object) -> Report:
    defaults: dict[str, object] = {
        "tool_version": "0.1.0.dev0",
        "provider": "google",
        "provider_category": "cloud",
        "generated_at": FIXED_TIME,
        "key_fingerprint": "AIza****************************3xY",
        "title": "Exposed Google API key reaches Gemini Files",
        "severity": Severity.HIGH,
        "impact": "The key can list files uploaded to the project.",
        "validation": ValidationResult(valid=True),
    }
    return Report(**{**defaults, **overrides})  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


def test_access_level_values_match_the_interface_contract() -> None:
    """implementation_plan.md §4 fixes these strings; they appear in --json."""
    assert [level.value for level in AccessLevel] == [
        "read",
        "write",
        "admin",
        "unknown",
    ]


def test_severity_bands_match_the_product_plan() -> None:
    """plan.md §6 defines exactly these five bands, lowest to highest."""
    assert [band.value for band in Severity] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_severity_ranks_are_ordered_lowest_to_highest() -> None:
    assert [band.rank for band in Severity] == [0, 1, 2, 3, 4]


def test_severity_supports_threshold_comparison() -> None:
    """`--fail-on high` (R1.5) needs ordering; enums have none by default."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.INFO < Severity.LOW
    assert Severity.MEDIUM <= Severity.HIGH
    assert not Severity.MEDIUM >= Severity.HIGH


def test_severity_ordering_is_by_band_not_alphabetical() -> None:
    """The bug the custom comparisons exist to prevent.

    ``Severity`` is a ``StrEnum``, so without the overrides it would inherit
    str's lexicographic ordering — under which ``"high" > "critical"`` is True
    and ``--fail-on`` (R1.5) would return the wrong exit code for exactly the
    bands that matter most.
    """
    assert Severity.CRITICAL > Severity.HIGH

    # What the inherited str comparison would have said, for contrast:
    assert sorted(["high", "critical"]) == ["critical", "high"]

    assert sorted(Severity, key=lambda band: band.rank)[-1] is Severity.CRITICAL


@pytest.mark.parametrize("operand", ["high", 3, None])
def test_severity_comparison_defers_on_non_severity_operands(operand: object) -> None:
    """Non-Severity operands get NotImplemented, not an AttributeError.

    Returning NotImplemented lets Python fall back to the other operand's
    comparison — the correct protocol — instead of blowing up on a missing
    ``.rank``.
    """
    for compare in (
        Severity.HIGH.__lt__,
        Severity.HIGH.__le__,
        Severity.HIGH.__gt__,
        Severity.HIGH.__ge__,
    ):
        assert compare(operand) is NotImplemented


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [
        (
            Severity.INFO,
            [
                Severity.INFO,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ],
        ),
        (Severity.HIGH, [Severity.HIGH, Severity.CRITICAL]),
        (Severity.CRITICAL, [Severity.CRITICAL]),
    ],
)
def test_severity_threshold_filtering(
    threshold: Severity, expected: list[Severity]
) -> None:
    assert [band for band in Severity if band >= threshold] == expected


# --------------------------------------------------------------------------
# Capability
# --------------------------------------------------------------------------


def test_capability_defaults_are_conservative() -> None:
    """A capability is not sensitive or costly unless a plugin says so.

    These two flags drive the High and Critical bands (plan.md §6), so the
    default must be the one that cannot silently inflate a severity.
    """
    capability = Capability(
        service="Maps Static API",
        access=AccessLevel.READ,
        detail="Can render static map tiles",
        evidence="GET /maps/api/staticmap?key=AIza****3xY -> 200, image/png",
        risk_weight=10,
    )

    assert capability.data_sensitive is False
    assert capability.incurs_cost is False
    assert capability.resource_ref is None
    assert capability.poc is None


@pytest.mark.parametrize("weight", [0, 50, 100])
def test_capability_accepts_risk_weight_across_the_declared_range(weight: int) -> None:
    assert make_capability(risk_weight=weight).risk_weight == weight


@pytest.mark.parametrize("weight", [-1, 101, 1000])
def test_capability_rejects_risk_weight_outside_0_to_100(weight: int) -> None:
    with pytest.raises(ValidationError):
        make_capability(risk_weight=weight)


@pytest.mark.parametrize("field", ["service", "detail", "evidence"])
def test_capability_rejects_empty_required_prose(field: str) -> None:
    """An empty service, detail or evidence yields a finding nobody can act on."""
    with pytest.raises(ValidationError):
        make_capability(**{field: ""})


def test_capability_rejects_unknown_fields() -> None:
    """extra='forbid' turns a typo in a provider plugin into a loud failure."""
    with pytest.raises(ValidationError):
        make_capability(data_sensitiveee=True)


def test_capability_is_immutable() -> None:
    """Scoring must not be able to edit the evidence it already weighed."""
    capability = make_capability()

    with pytest.raises(ValidationError):
        capability.risk_weight = 100


def test_capability_sort_key_disambiguates_within_one_service() -> None:
    """Service alone is not a stable key — one service yields many capabilities."""
    read = make_capability(access=AccessLevel.READ, detail="Can list files")
    write = make_capability(access=AccessLevel.WRITE, detail="Can list files")

    assert read.sort_key != write.sort_key
    assert sorted([write, read], key=lambda c: c.sort_key) == [read, write]


# --------------------------------------------------------------------------
# Identity and ValidationResult
# --------------------------------------------------------------------------


def test_identity_is_entirely_optional() -> None:
    """A live key is a finding even when the provider names no owner."""
    identity = Identity()

    assert identity.account is None
    assert identity.owner is None
    assert identity.plan_or_tier is None
    assert identity.extra == {}


def test_identity_extra_instances_do_not_share_state() -> None:
    """Guards the classic mutable-default bug on a field plugins will populate."""
    first = Identity(extra={"project": "alpha"})
    second = Identity()

    assert second.extra == {}
    assert first.extra == {"project": "alpha"}


def test_validation_result_defaults_to_no_identity_and_no_note() -> None:
    result = ValidationResult(valid=False)

    assert result.identity is None
    assert result.note == ""


def test_validation_result_carries_identity_when_available() -> None:
    result = ValidationResult(
        valid=True,
        identity=Identity(account="acct_123", plan_or_tier="pro"),
        note="restricted by HTTP referrer",
    )

    assert result.identity is not None
    assert result.identity.account == "acct_123"
    assert result.note == "restricted by HTTP referrer"


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def test_report_carries_its_attribution_footer() -> None:  # plan.md §7 item 9
    report = make_report()

    assert report.tool == "keyreach"
    assert report.tool_version == "0.1.0.dev0"
    assert report.schema_version == SCHEMA_VERSION


def test_report_rejects_a_naive_timestamp() -> None:
    """A naive timestamp serializes without an offset and breaks reproducibility."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_report(generated_at=datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001


def test_report_accepts_any_timezone_aware_timestamp() -> None:
    """The engine injects UTC, but a non-UTC offset is still unambiguous."""
    report = make_report(
        generated_at=datetime(
            2026, 1, 1, 17, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))
        )
    )

    assert report.generated_at.tzinfo is not None


def test_report_sorts_capabilities_on_construction() -> None:
    """Probes complete concurrently, so arrival order is not reproducible."""
    stripe = make_capability(service="Stripe Charges", detail="Can list charges")
    gemini = make_capability(service="Gemini Files API", detail="Can list files")
    maps = make_capability(service="Maps Static API", detail="Can render tiles")

    report = make_report(capabilities=[stripe, maps, gemini])

    assert [c.service for c in report.capabilities] == [
        "Gemini Files API",
        "Maps Static API",
        "Stripe Charges",
    ]


def test_report_sorting_is_independent_of_input_order() -> None:
    """Any permutation of the same capability set must produce one report."""
    caps = [
        make_capability(service="B service", detail="second"),
        make_capability(service="A service", detail="first"),
        make_capability(service="A service", detail="also first"),
    ]

    forwards = make_report(capabilities=list(caps))
    backwards = make_report(capabilities=list(reversed(caps)))

    assert forwards.model_dump_json() == backwards.model_dump_json()


def test_report_defaults_to_empty_collections() -> None:
    report = make_report()

    assert report.capabilities == []
    assert report.severity_rationale == []
    assert report.remediation == []


@pytest.mark.parametrize("field", ["title", "impact", "key_fingerprint", "provider"])
def test_report_rejects_empty_required_prose(field: str) -> None:
    with pytest.raises(ValidationError):
        make_report(**{field: ""})


def test_report_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_report(sevrity="high")


def test_report_round_trips_through_json_unchanged() -> None:
    """--json output must parse back into an identical report."""
    original = make_report(
        capabilities=[make_capability()],
        severity_rationale=["read access to private user data"],
        remediation=["Rotate the key", "Add an HTTP referrer restriction"],
    )

    restored = Report.model_validate_json(original.model_dump_json())

    assert restored == original
    assert restored.model_dump_json() == original.model_dump_json()


def test_report_serialization_is_byte_identical_across_runs() -> None:
    """The determinism guarantee (plan.md §1), asserted at the model layer."""
    first = make_report(capabilities=[make_capability()]).model_dump_json()
    second = make_report(capabilities=[make_capability()]).model_dump_json()

    assert first == second


def test_report_serializes_enums_as_their_string_values() -> None:
    """Consumers of --json read strings, not Python enum reprs."""
    payload = make_report(capabilities=[make_capability()]).model_dump(mode="json")

    assert payload["severity"] == "high"
    assert payload["capabilities"][0]["access"] == "read"
