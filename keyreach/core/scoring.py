"""Deterministic severity scoring: what band do these capabilities justify?

A pure function of the confirmed capability set and nothing else
(``implementation_plan.md`` §7, ``plan.md`` §6). No clock, no network, no
provider name, no model. The same capabilities always produce the same band
*and* the same rationale, which is what lets a triager on the receiving end
re-derive the verdict instead of taking it on trust.

**Severity is never assigned per provider.** A "Maps key" is not informational
because it is a Maps key; it is informational because the capabilities keyreach
actually confirmed are informational. If the same key also reaches an LLM
inference endpoint, the confirmed set says so and the band moves. That inversion
is the entire product argument in ``plan.md`` §6.

**The rationale is the deliverable.** A band with no explanation is an assertion;
a band with the specific capabilities that produced it is an argument. Every
line emitted here names the capabilities responsible, so the report can show
exactly why — see ``plan.md`` §7 item 6.

**Undetermined is not harmless.** ``AccessLevel.UNKNOWN`` never satisfies the
privileged-access test, because keyreach cannot claim a write it did not
confirm. It is still counted for breadth and risk weight, and it always adds a
rationale line saying the band may understate real impact. Silently scoring it
as read would be a guess, and guessing is what this tool does not do.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Severity

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# --------------------------------------------------------------------------
# Banding constants
#
# Explicit and named, never inlined, because each one is a published verdict
# boundary. `tests/test_scoring.py` pins both sides of every threshold, so
# retuning a number here is a visible, reviewed change rather than a silent
# reclassification of findings already filed against an earlier version.
# --------------------------------------------------------------------------

#: Provider-declared ``risk_weight`` at or above which a capability set with no
#: data, spend or privileged access still rates Medium. The midpoint of the
#: 0-100 range: a plugin author saying "half as bad as the worst thing this
#: provider offers" is claiming meaningful non-public functionality.
MEDIUM_RISK_WEIGHT: Final = 50

#: ``risk_weight`` at or above which such a set rates Low rather than Info.
#: Below it, the plugin is describing largely public functionality.
LOW_RISK_WEIGHT: Final = 20

#: Distinct services at or above which breadth alone reaches Medium. Reaching
#: four separate services is a different exposure from reaching one, even when
#: each is individually dull: it is the difference between a leaked key for a
#: single API and a leaked key for a project.
BROAD_SERVICE_COUNT: Final = 4

#: Capabilities named per rationale line before the rest are summarised. A key
#: with sixty confirmed capabilities should not produce a sixty-item sentence;
#: the full list is in the capability map beside it. Cited capabilities are
#: taken in sort order, so the truncation is reproducible.
MAX_CITED_CAPABILITIES: Final = 5

#: Access levels that count as privileged. Deliberately excludes ``UNKNOWN``:
#: an undetermined access level is not evidence of a write. Membership tests
#: only — never iterated, so the set does not reach an output path.
PRIVILEGED_ACCESS: Final = frozenset({AccessLevel.WRITE, AccessLevel.ADMIN})

#: Bands in ascending order, derived from the enum's own ranking rather than
#: re-listed, so ``Severity`` stays the single source of truth for the ordering.
_BANDS_BY_RANK: Final = tuple(sorted(Severity, key=lambda band: band.rank))


class ScoreResult(BaseModel):
    """A computed band and the argument for it.

    Field names mirror ``Report.severity`` and ``Report.severity_rationale`` so
    the reporting layer (roadmap R0.8) copies them across without translating.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    severity: Severity = Field(description="Computed band.")
    rationale: tuple[str, ...] = Field(
        description="The specific confirmed capabilities that produced the band."
    )


class _Signals(BaseModel):
    """The facts the banding rules read, extracted once.

    Separated from the rules themselves so that ``_band`` is a readable table of
    thresholds rather than a wall of comprehensions, and so a test can assert on
    the extracted facts independently of the banding.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    worst_risk_weight: int
    breadth: int
    privileged_and_valuable: bool
    privileged: bool
    data_sensitive: bool
    incurs_cost: bool
    undetermined: bool
    all_restricted: bool


def _is_privileged(capability: Capability) -> bool:
    return capability.access in PRIVILEGED_ACCESS


def _is_valuable(capability: Capability) -> bool:
    """Reaches private data or moves money — the two things that raise a band."""
    return capability.data_sensitive or capability.incurs_cost


def _is_privileged_and_valuable(capability: Capability) -> bool:
    """The Critical test, applied to **one** capability.

    ``implementation_plan.md`` §7 originally sketched this as
    ``(admin or write) and (data or cost)`` evaluated across the whole set. That
    is wrong in a way that matters: it rates a key Critical when one capability
    can write to something harmless and a *different* capability can read
    something sensitive. Neither of those is "write access to sensitive data",
    and a Critical filed on that basis falls apart the moment a triager reads
    the capability map. Critical requires a single capability that is both.
    """
    return _is_privileged(capability) and _is_valuable(capability)


def _extract(capabilities: Sequence[Capability]) -> _Signals:
    return _Signals(
        worst_risk_weight=max(c.risk_weight for c in capabilities),
        # Counted through a set, but only its size is used; no set is iterated,
        # so nothing order-dependent reaches the output.
        breadth=len({c.service for c in capabilities}),
        privileged_and_valuable=any(map(_is_privileged_and_valuable, capabilities)),
        privileged=any(map(_is_privileged, capabilities)),
        data_sensitive=any(c.data_sensitive for c in capabilities),
        incurs_cost=any(c.incurs_cost for c in capabilities),
        undetermined=any(c.access is AccessLevel.UNKNOWN for c in capabilities),
        all_restricted=all(c.restricted for c in capabilities),
    )


def _band(signals: _Signals) -> Severity:
    """The banding table. First match wins; every branch is reachable.

    Bands come from ``plan.md`` §6 and thresholds from ``implementation_plan.md``
    §7. Kept as a flat cascade rather than a scoring formula on purpose — a
    reviewer can check a cascade against the written policy line by line, and a
    weighted sum would make "why is this High?" unanswerable without a debugger.
    """
    if signals.privileged_and_valuable:
        return Severity.CRITICAL
    if signals.data_sensitive or signals.incurs_cost or signals.privileged:
        return Severity.HIGH
    if (
        signals.worst_risk_weight >= MEDIUM_RISK_WEIGHT
        or signals.breadth >= BROAD_SERVICE_COUNT
    ):
        return Severity.MEDIUM
    if signals.worst_risk_weight >= LOW_RISK_WEIGHT:
        return Severity.LOW
    return Severity.INFO


def _downgrade_for_restrictions(band: Severity, signals: _Signals) -> Severity:
    """Lower the band by one when every confirmed capability is restricted.

    Two deliberate limits, both of which keep this honest:

    * **Only when *every* capability is restricted.** A referrer check on one of
      five reachable services does not shrink the blast radius; the other four
      are still abusable.
    * **Only one band, never to Info.** keyreach observes that a restriction
      *appears* to be in force; it cannot prove the restriction holds. HTTP
      referrer and IP restrictions are routinely bypassed by sending the header
      the check expects, which is exactly why ``plan.md`` §6 lists
      "restricted-but-bypassable" at Medium rather than dismissing it. Collapsing
      a live payment key to Info on the strength of a spoofable header would be
      the worst mistake this function could make.
    """
    if not signals.all_restricted or band is Severity.INFO:
        return band
    return _BANDS_BY_RANK[band.rank - 1]


def _cite(capabilities: Sequence[Capability]) -> str:
    """Render capabilities for a rationale line, in sort order, bounded."""
    shown = capabilities[:MAX_CITED_CAPABILITIES]
    rendered = "; ".join(f"{c.service} ({c.access.value}) — {c.detail}" for c in shown)
    remaining = len(capabilities) - len(shown)
    if remaining:
        rendered += f"; and {remaining} more"
    return rendered


class _Citations:
    """Cites each capability under the strongest reason that applies to it.

    Without this, a Stripe charge capability would appear on three lines — as
    privileged-and-valuable, as spending, and as write access — and the
    rationale would read as three findings instead of one.
    """

    def __init__(self, capabilities: Sequence[Capability]) -> None:
        # Already sorted by the engine and by `Report`, but sorted again here
        # because `score` is public and a caller may pass an unsorted list.
        self._ordered = sorted(capabilities, key=lambda c: c.sort_key)
        # Membership tests only; iteration order of this set never escapes.
        self._claimed: set[int] = set()

    def take(self, predicate: Callable[[Capability], bool]) -> list[Capability]:
        """Return not-yet-cited capabilities matching ``predicate``, in order."""
        taken: list[Capability] = []
        for index, capability in enumerate(self._ordered):
            if index in self._claimed or not predicate(capability):
                continue
            self._claimed.add(index)
            taken.append(capability)
        return taken


def _weight_decided(band: Severity, signals: _Signals) -> bool:
    """Did ``risk_weight`` reach this band on its own?

    Checked against the threshold rather than inferred from the band, because
    the band handed in here is the one *after* any restriction downgrade. A
    breadth-driven Medium lowered to Low still has whatever weight it started
    with, which may be nothing at all.
    """
    if band is Severity.MEDIUM:
        return signals.worst_risk_weight >= MEDIUM_RISK_WEIGHT
    if band is Severity.LOW:
        return signals.worst_risk_weight >= LOW_RISK_WEIGHT
    return False


def _rationale(
    capabilities: Sequence[Capability],
    signals: _Signals,
    band: Severity,
    downgraded: bool,
) -> tuple[str, ...]:
    """Build the argument for the band, strongest driver first."""
    citations = _Citations(capabilities)
    lines: list[str] = []

    privileged_valuable = citations.take(_is_privileged_and_valuable)
    if privileged_valuable:
        lines.append(
            "Write or admin access to a service holding private data or able to "
            f"spend: {_cite(privileged_valuable)}."
        )

    sensitive = citations.take(lambda c: c.data_sensitive)
    if sensitive:
        lines.append(f"Reaches private or user data: {_cite(sensitive)}.")

    costly = citations.take(lambda c: c.incurs_cost)
    if costly:
        lines.append(
            "Can incur direct financial cost or send communications: "
            f"{_cite(costly)}."
        )

    privileged = citations.take(_is_privileged)
    if privileged:
        lines.append(f"Write or admin access: {_cite(privileged)}.")

    if signals.breadth >= BROAD_SERVICE_COUNT:
        lines.append(
            f"Reaches {signals.breadth} distinct services, so the exposure is "
            "the project rather than a single API."
        )

    # Only when the weight is what actually reached the band. Reporting a
    # weight of 10/100 as a reason for a Medium that breadth produced would
    # weaken the argument with a number that argues the other way.
    if _weight_decided(band, signals):
        # `max` returns the first maximum in iteration order, so sorting first
        # makes the tie-break between equally-weighted capabilities stable.
        heaviest = max(
            sorted(capabilities, key=lambda c: c.sort_key),
            key=lambda c: c.risk_weight,
        )
        lines.append(
            f"Highest declared risk weight is {signals.worst_risk_weight}/100 "
            f"({heaviest.service} — {heaviest.detail})."
        )

    if signals.undetermined:
        undetermined = sorted(
            (c for c in capabilities if c.access is AccessLevel.UNKNOWN),
            key=lambda c: c.sort_key,
        )
        lines.append(
            "Access level could not be determined for "
            f"{_cite(undetermined)}. The band may understate real impact."
        )

    if signals.all_restricted:
        lines.append(
            "Every confirmed capability appears restricted. "
            + (
                "The band was lowered by one; restrictions such as HTTP "
                "referrer checks are commonly bypassable, so this is an "
                "adjustment, not a dismissal."
                if downgraded
                else "The band is already Info, so no further reduction applies."
            )
        )

    if not lines:
        lines.append(
            "Confirmed capabilities are read-only, reach no private data, "
            "cannot spend, and carry low declared risk."
        )

    return tuple(lines)


def score(capabilities: Sequence[Capability]) -> ScoreResult:
    """Compute the severity band and its rationale from confirmed capabilities.

    Pure: the same input always produces the same output, byte for byte.

    An empty set is Info, not "unknown". Reaching this function at all means the
    pipeline ran; nothing confirmed means nothing was confirmed. Whether the key
    was even valid is a separate fact, carried by ``ValidationResult`` and
    rendered beside the band by the report.
    """
    if not capabilities:
        return ScoreResult(
            severity=Severity.INFO,
            rationale=("No capabilities were confirmed.",),
        )

    signals = _extract(capabilities)
    initial = _band(signals)
    band = _downgrade_for_restrictions(initial, signals)
    return ScoreResult(
        severity=band,
        rationale=_rationale(
            capabilities, signals, band, downgraded=band is not initial
        ),
    )
