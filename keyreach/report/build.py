"""Assemble a :class:`Report` from what the engine found.

The last pure stage. :class:`~keyreach.core.engine.EngineResult` is evidence —
what was detected, whether it was live, what it reached. A ``Report`` is that
evidence turned into a finding somebody can act on: a title, a band, a one-line
impact, the argument for the band, and remediation.

Everything here is a rule over the engine's output. The title is not a
description of the key, the impact line is not a summary of the provider's prose
— both are derived from confirmed facts, because a disclosure that overstates is
worse than one that says less (``plan.md`` §11).

**Time is a parameter, not something this module reads.** ``generated_at`` is
passed in, so a report is a pure function of a run plus a timestamp, and a
golden-file test can pin the timestamp and compare bytes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from keyreach.core.models import (
    Capability,
    Report,
    Severity,
    ValidationResult,
)
from keyreach.core.scoring import PRIVILEGED_ACCESS, score

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from keyreach.core.engine import EngineResult, ProviderOutcome

#: Stand-in provider name when detection could not name one. ``Report.provider``
#: is required and non-empty, and a report for an unidentified secret is still
#: worth producing — it tells the finder that keyreach ran and could not help.
UNKNOWN_PROVIDER: Final = "unknown"

#: Category for that case. Deliberately a member of the closed set
#: `core/registry.py` enforces, so a consumer grouping reports by category never
#: encounters a value the registry would reject.
UNKNOWN_CATEGORY: Final = "generic"

#: Services named in a title before the rest are counted rather than listed.
_TITLE_SERVICES: Final = 1


def _headline(capabilities: Sequence[Capability]) -> Capability:
    """The capability a human would lead with.

    Ordered by what actually makes a finding serious, not by risk weight alone:
    a privileged capability that reaches data or money outranks a heavy weight on
    something read-only. Ties fall through to ``sort_key`` so the choice is
    reproducible.
    """

    def rank(capability: Capability) -> tuple[int, int, int, tuple[str, str, str]]:
        valuable = capability.data_sensitive or capability.incurs_cost
        privileged = capability.access in PRIVILEGED_ACCESS
        return (
            -int(privileged and valuable),
            -int(valuable),
            -capability.risk_weight,
            capability.sort_key,
        )

    return min(capabilities, key=rank)


def _primary_outcome(result: EngineResult) -> ProviderOutcome | None:
    """The provider this report is about.

    A live key outranks detection confidence: if one candidate answered and
    another did not, the one that answered is the provider, whatever the prefix
    suggested. Within each group the engine's own ordering (confidence, then
    name) decides, so the choice never depends on probe completion order.
    """
    if not result.outcomes:
        return None
    return min(
        result.outcomes,
        key=lambda outcome: (not outcome.validation.valid, outcome.sort_key),
    )


def _title(
    provider: str,
    validation: ValidationResult,
    capabilities: Sequence[Capability],
    *,
    identified: bool,
) -> str:
    """One line, stating what was found — the subject line of a disclosure."""
    if not identified:
        return "Unidentified secret: keyreach could not determine the provider"
    if not validation.valid:
        return f"Exposed {provider} API key is no longer valid"
    if not capabilities:
        return f"Exposed {provider} API key is live, with no capability confirmed"

    headline = _headline(capabilities)
    others = len({c.service for c in capabilities}) - _TITLE_SERVICES
    if others <= 0:
        return f"Exposed {provider} API key reaches {headline.service}"
    plural = "service" if others == 1 else "services"
    return (
        f"Exposed {provider} API key reaches {headline.service} "
        f"and {others} other {plural}"
    )


#: One line per band, stated as consequence rather than as classification. A
#: recipient reading only this line should know whether to page someone.
_IMPACT_BY_BAND: Final[dict[Severity, str]] = {
    Severity.CRITICAL: (
        "Anyone holding this key can change data or move money. Treat this as an "
        "active compromise: rotate now, then audit for use."
    ),
    Severity.HIGH: (
        "Anyone holding this key can read private data or spend money against "
        "this account. Rotate now."
    ),
    Severity.MEDIUM: (
        "Anyone holding this key can use non-public functionality on this "
        "account. Rotate at the next opportunity."
    ),
    Severity.LOW: (
        "Anyone holding this key can use limited functionality. The practical "
        "impact is quota consumption and billing noise."
    ),
    Severity.INFO: ("No capability with practical impact was confirmed for this key."),
}


def _impact(
    severity: Severity,
    validation: ValidationResult,
    *,
    identified: bool,
) -> str:
    if not identified:
        return (
            "keyreach could not identify this secret's provider, so nothing was "
            "probed and no impact was established. This is not evidence that "
            "the secret is harmless."
        )
    if not validation.valid:
        return (
            "The provider rejected this key, so it cannot be used as it stands. "
            "Rotate it anyway if it was ever live, and check for prior use."
        )
    return _IMPACT_BY_BAND[severity]


#: Remediation, in the order it should be done. Rotation comes before
#: investigation on purpose: an exposed key keeps working while somebody reads
#: logs. Provider-specific detail arrives through `rotation_guide_url`, and
#: provider plugins may extend this from R1.1 onward.
_REMEDIATION: Final = (
    "Revoke or rotate this key now. It was found outside the systems that "
    "should hold it, so treat it as known to others.",
    "Remove the key from wherever it leaked — including git history, build "
    "logs and image layers, not only the current file.",
    "Check the provider's audit or usage logs for calls made with this key, "
    "especially from addresses or times you do not recognise.",
    "Scope the replacement: least-privilege permissions, plus referrer, IP or "
    "app restrictions where the provider supports them.",
    "Store the replacement in a secret manager and re-scan the repository "
    "before the next deployment.",
)


def build_report(
    result: EngineResult,
    *,
    generated_at: datetime,
    tool_version: str,
) -> Report:
    """Turn an engine run into a finding.

    ``generated_at`` must be timezone-aware (``Report`` rejects naive datetimes)
    and is supplied by the caller rather than read here, which is what keeps
    every stage below the CLI a pure function of its inputs.
    """
    outcome = _primary_outcome(result)
    identified = outcome is not None

    # When nothing was probed, `valid=False` is the only value the model can
    # hold — but it would read as "the provider rejected this key", which is a
    # different and much weaker claim than "keyreach never asked". The note is
    # left empty here and the engine's explanation goes to `Report.notes`,
    # where it is presented as a gap; the renderers show "not probed" rather
    # than "not valid" for exactly this case.
    validation = (
        outcome.validation
        if outcome is not None
        else ValidationResult(valid=False, note="")
    )
    capabilities = list(result.capabilities)
    scored = score(capabilities)

    return Report(
        tool_version=tool_version,
        provider=outcome.provider if outcome is not None else UNKNOWN_PROVIDER,
        provider_category=(
            outcome.category if outcome is not None else UNKNOWN_CATEGORY
        ),
        generated_at=generated_at,
        key_fingerprint=result.key_fingerprint,
        title=_title(
            outcome.provider if outcome is not None else UNKNOWN_PROVIDER,
            validation,
            capabilities,
            identified=identified,
        ),
        severity=scored.severity,
        impact=_impact(scored.severity, validation, identified=identified),
        severity_rationale=list(scored.rationale),
        validation=validation,
        capabilities=capabilities,
        # Probe failures and "nothing was probed" notes both land here. R0.6
        # collected them so a report could distinguish "no capability" from
        # "could not determine"; dropping them would present a partial
        # capability map as a complete one.
        notes=_notes(result),
        remediation=list(_REMEDIATION),
        rotation_guide_url=(
            outcome.rotation_guide_url if outcome is not None else None
        ),
        docs_url=outcome.docs_url if outcome is not None else None,
    )


def _notes(result: EngineResult) -> list[str]:
    """Engine notes plus every provider's probe errors, in a stable order."""
    collected = list(result.notes)
    for outcome in result.outcomes:
        collected.extend(f"{outcome.provider}: {error}" for error in outcome.errors)
    return collected
