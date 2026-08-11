"""Severity scoring tests (roadmap R0.7).

R0.7's acceptance criterion is "identical capability sets always produce
identical band + rationale", and ``implementation_plan.md`` §7 requires every
band boundary to be covered by a table-driven test "so tuning never silently
changes verdicts".

Both sides of every threshold are pinned below. The tables reference the
constants rather than repeating their values, so retuning a constant moves the
test with it — but the *boundary* assertions (at the constant, one below it)
survive, which is the property that actually protects past findings.
"""

from __future__ import annotations

import pytest

from keyreach.core.models import AccessLevel, Capability, Severity
from keyreach.core.scoring import (
    BROAD_SERVICE_COUNT,
    LOW_RISK_WEIGHT,
    MAX_CITED_CAPABILITIES,
    MEDIUM_RISK_WEIGHT,
    ScoreResult,
    score,
)


def cap(
    service: str = "Service A",
    access: AccessLevel = AccessLevel.READ,
    *,
    risk_weight: int = 0,
    data_sensitive: bool = False,
    incurs_cost: bool = False,
    restricted: bool = False,
    detail: str | None = None,
) -> Capability:
    """A capability with everything harmless by default, so each test opts in."""
    return Capability(
        service=service,
        access=access,
        detail=detail or f"Can reach {service}",
        evidence=f"GET /{service} -> 200",
        risk_weight=risk_weight,
        data_sensitive=data_sensitive,
        incurs_cost=incurs_cost,
        restricted=restricted,
    )


def services(count: int, **kwargs: object) -> list[Capability]:
    """``count`` capabilities across ``count`` distinct services."""
    return [cap(f"Service {index}", **kwargs) for index in range(count)]  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Band boundaries
# ---------------------------------------------------------------------------

BAND_CASES: list[tuple[str, list[Capability], Severity]] = [
    (
        "empty set is info, not unknown",
        [],
        Severity.INFO,
    ),
    (
        "read-only, public, zero weight",
        [cap()],
        Severity.INFO,
    ),
    (
        "one below the low threshold stays info",
        [cap(risk_weight=LOW_RISK_WEIGHT - 1)],
        Severity.INFO,
    ),
    (
        "at the low threshold",
        [cap(risk_weight=LOW_RISK_WEIGHT)],
        Severity.LOW,
    ),
    (
        "one below the medium threshold stays low",
        [cap(risk_weight=MEDIUM_RISK_WEIGHT - 1)],
        Severity.LOW,
    ),
    (
        "at the medium threshold",
        [cap(risk_weight=MEDIUM_RISK_WEIGHT)],
        Severity.MEDIUM,
    ),
    (
        "one below the breadth threshold stays info on weight alone",
        services(BROAD_SERVICE_COUNT - 1),
        Severity.INFO,
    ),
    (
        "at the breadth threshold",
        services(BROAD_SERVICE_COUNT),
        Severity.MEDIUM,
    ),
    (
        "breadth counts distinct services, not capabilities",
        [cap("Service A", detail=f"probe {index}") for index in range(10)],
        Severity.INFO,
    ),
    (
        "read access to private data is high",
        [cap(data_sensitive=True)],
        Severity.HIGH,
    ),
    (
        "read access that spends money is high",
        [cap(incurs_cost=True)],
        Severity.HIGH,
    ),
    (
        "write to something harmless is high",
        [cap(access=AccessLevel.WRITE)],
        Severity.HIGH,
    ),
    (
        "admin over something harmless is high",
        [cap(access=AccessLevel.ADMIN)],
        Severity.HIGH,
    ),
    (
        "write to private data is critical",
        [cap(access=AccessLevel.WRITE, data_sensitive=True)],
        Severity.CRITICAL,
    ),
    (
        "admin over money movement is critical",
        [cap(access=AccessLevel.ADMIN, incurs_cost=True)],
        Severity.CRITICAL,
    ),
    (
        "high weight never outranks a real signal",
        [cap(risk_weight=100)],
        Severity.MEDIUM,
    ),
]


@pytest.mark.parametrize(
    ("capabilities", "expected"),
    [pytest.param(caps, band, id=name) for name, caps, band in BAND_CASES],
)
def test_band_boundaries(capabilities: list[Capability], expected: Severity) -> None:
    assert score(capabilities).severity is expected


def test_critical_requires_one_capability_to_be_both() -> None:
    """Write *here* plus sensitive data *there* is not write access to data.

    ``implementation_plan.md`` §7 sketched the Critical test as
    ``(admin or write) and (data or cost)`` over the whole set, which rates this
    pair Critical. It is High: no single confirmed capability both writes and
    touches anything valuable, so a Critical would not survive triage.
    """
    split = [
        cap("Service A", AccessLevel.WRITE),
        cap("Service B", AccessLevel.READ, data_sensitive=True),
    ]
    assert score(split).severity is Severity.HIGH

    combined = [cap("Service A", AccessLevel.WRITE, data_sensitive=True)]
    assert score(combined).severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Undetermined access
# ---------------------------------------------------------------------------


def test_unknown_access_never_reaches_critical() -> None:
    """UNKNOWN is "not determined" — it cannot stand in for a confirmed write."""
    result = score([cap(access=AccessLevel.UNKNOWN, data_sensitive=True)])
    assert result.severity is Severity.HIGH


def test_unknown_access_is_not_treated_as_harmless() -> None:
    result = score([cap(access=AccessLevel.UNKNOWN)])
    assert any("could not be determined" in line for line in result.rationale)
    assert any("understate" in line for line in result.rationale)


def test_unknown_access_still_counts_for_breadth() -> None:
    caps = services(BROAD_SERVICE_COUNT, access=AccessLevel.UNKNOWN)
    assert score(caps).severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# Restriction downgrade
# ---------------------------------------------------------------------------


def test_restriction_downgrades_by_one_band() -> None:
    unrestricted = [cap(access=AccessLevel.WRITE, data_sensitive=True)]
    restricted = [cap(access=AccessLevel.WRITE, data_sensitive=True, restricted=True)]
    assert score(unrestricted).severity is Severity.CRITICAL
    assert score(restricted).severity is Severity.HIGH


def test_restriction_downgrades_only_when_every_capability_is_restricted() -> None:
    """One restricted service does not shrink the blast radius of four others."""
    mixed = [
        cap("Service A", AccessLevel.WRITE, data_sensitive=True, restricted=True),
        cap("Service B", AccessLevel.WRITE, data_sensitive=True),
    ]
    assert score(mixed).severity is Severity.CRITICAL


def test_restriction_never_collapses_more_than_one_band() -> None:
    """A spoofable referrer header must not turn a live payment key into noise."""
    result = score([cap(access=AccessLevel.ADMIN, incurs_cost=True, restricted=True)])
    assert result.severity is Severity.HIGH
    assert result.severity.rank == Severity.CRITICAL.rank - 1


def test_restriction_does_not_underflow_below_info() -> None:
    result = score([cap(restricted=True)])
    assert result.severity is Severity.INFO
    assert any("already Info" in line for line in result.rationale)


def test_restriction_downgrade_is_stated_in_the_rationale() -> None:
    result = score([cap(access=AccessLevel.WRITE, restricted=True)])
    assert any("lowered by one" in line for line in result.rationale)
    assert any("bypassable" in line for line in result.rationale)


@pytest.mark.parametrize(
    "capabilities",
    [
        pytest.param(
            [cap(access=AccessLevel.WRITE, data_sensitive=True)], id="critical"
        ),
        pytest.param([cap(data_sensitive=True)], id="high"),
        pytest.param([cap(risk_weight=MEDIUM_RISK_WEIGHT)], id="medium"),
        pytest.param([cap(risk_weight=LOW_RISK_WEIGHT)], id="low"),
    ],
)
def test_restriction_downgrades_exactly_one_band_from_anywhere(
    capabilities: list[Capability],
) -> None:
    before = score(capabilities).severity
    restricted = [c.model_copy(update={"restricted": True}) for c in capabilities]
    after = score(restricted).severity
    assert after.rank == before.rank - 1


# ---------------------------------------------------------------------------
# Rationale
# ---------------------------------------------------------------------------


def test_rationale_is_never_empty() -> None:
    for capabilities in ([], [cap()], [cap(access=AccessLevel.ADMIN)]):
        assert score(capabilities).rationale


def test_empty_set_says_so() -> None:
    assert score([]).rationale == ("No capabilities were confirmed.",)


def test_rationale_names_the_capability_that_drove_the_band() -> None:
    result = score(
        [
            cap("Stripe Charges", AccessLevel.WRITE, incurs_cost=True),
            cap("Stripe Balance", AccessLevel.READ),
        ]
    )
    assert result.severity is Severity.CRITICAL
    assert "Stripe Charges" in result.rationale[0]
    assert "spend" in result.rationale[0]


def test_each_capability_is_cited_once() -> None:
    """The strongest applicable reason claims a capability; weaker ones skip it."""
    result = score([cap("Stripe Charges", AccessLevel.WRITE, incurs_cost=True)])
    mentions = sum("Stripe Charges" in line for line in result.rationale)
    assert mentions == 1


def test_distinct_drivers_get_distinct_lines() -> None:
    result = score(
        [
            cap("Files", AccessLevel.WRITE, data_sensitive=True),
            cap("Records", AccessLevel.READ, data_sensitive=True),
            cap("Inference", AccessLevel.READ, incurs_cost=True),
            cap("Config", AccessLevel.ADMIN),
        ]
    )
    joined = "\n".join(result.rationale)
    assert "Files" in joined
    assert "Records" in joined
    assert "Inference" in joined
    assert "Config" in joined
    assert len(result.rationale) >= 4


def test_rationale_citations_are_bounded() -> None:
    caps = services(MAX_CITED_CAPABILITIES + 3, data_sensitive=True)
    line = next(
        line for line in score(caps).rationale if "private or user data" in line
    )
    assert "and 3 more" in line


def test_breadth_line_appears_at_the_threshold() -> None:
    at = score(services(BROAD_SERVICE_COUNT)).rationale
    below = score(services(BROAD_SERVICE_COUNT - 1)).rationale
    assert any("distinct services" in line for line in at)
    assert not any("distinct services" in line for line in below)


def test_weight_line_names_the_heaviest_capability() -> None:
    result = score(
        [
            cap("Light", risk_weight=1),
            cap("Heavy", risk_weight=MEDIUM_RISK_WEIGHT, detail="Can read config"),
        ]
    )
    line = next(line for line in result.rationale if "declared risk weight" in line)
    assert f"{MEDIUM_RISK_WEIGHT}/100" in line
    assert "Heavy" in line
    assert "Can read config" in line


def test_weight_line_is_omitted_when_weight_did_not_decide_the_band() -> None:
    """A High driven by data does not need a sentence about a number."""
    result = score([cap(risk_weight=100, data_sensitive=True)])
    assert not any("declared risk weight" in line for line in result.rationale)


def test_weight_line_is_omitted_when_breadth_decided_the_band() -> None:
    """Citing a weight of 0/100 as the reason for a Medium argues the other way."""
    result = score(services(BROAD_SERVICE_COUNT))
    assert result.severity is Severity.MEDIUM
    assert any("distinct services" in line for line in result.rationale)
    assert not any("declared risk weight" in line for line in result.rationale)


def test_weight_line_survives_a_restriction_downgrade_only_if_still_true() -> None:
    """The band handed to the rationale is post-downgrade; the weight is not."""
    breadth_only = score(
        [
            c.model_copy(update={"restricted": True})
            for c in services(BROAD_SERVICE_COUNT)
        ]
    )
    assert breadth_only.severity is Severity.LOW
    assert not any("declared risk weight" in line for line in breadth_only.rationale)

    by_weight = score([cap(risk_weight=MEDIUM_RISK_WEIGHT, restricted=True)])
    assert by_weight.severity is Severity.LOW
    assert any(f"{MEDIUM_RISK_WEIGHT}/100" in line for line in by_weight.rationale)


# ---------------------------------------------------------------------------
# Determinism — R0.7's acceptance criterion
# ---------------------------------------------------------------------------

MIXED_SET = [
    cap("Zebra", AccessLevel.ADMIN, risk_weight=90, data_sensitive=True),
    cap("Alpha", AccessLevel.READ, risk_weight=10),
    cap("Mango", AccessLevel.WRITE, risk_weight=60, incurs_cost=True),
    cap("Alpha", AccessLevel.UNKNOWN, risk_weight=30),
]


def test_repeated_scoring_is_identical() -> None:
    first = score(MIXED_SET)
    assert all(score(MIXED_SET) == first for _ in range(5))


def test_input_order_does_not_change_the_result() -> None:
    """Probes complete concurrently, so arrival order must not reach the output."""
    forward = score(MIXED_SET)
    reversed_ = score(list(reversed(MIXED_SET)))
    rotated = score(MIXED_SET[2:] + MIXED_SET[:2])
    assert forward == reversed_ == rotated


def test_result_serializes_identically_across_runs() -> None:
    dumps = {score(MIXED_SET).model_dump_json() for _ in range(3)}
    assert len(dumps) == 1


def test_score_does_not_mutate_its_input() -> None:
    original = list(MIXED_SET)
    score(MIXED_SET)
    assert original == MIXED_SET


def test_result_is_frozen() -> None:
    result = score([cap()])
    with pytest.raises(ValueError, match="frozen"):
        result.severity = Severity.CRITICAL


def test_result_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError, match="extra"):
        ScoreResult(
            severity=Severity.INFO,
            rationale=(),
            band="info",  # type: ignore[call-arg]
        )


def test_every_band_is_reachable() -> None:
    """No band is dead code — each is produced by some capability set."""
    produced = {score(caps).severity for _, caps, _ in BAND_CASES}
    assert produced == set(Severity)
