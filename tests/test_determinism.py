"""Determinism and golden-snapshot tests (roadmap R0.8).

R0.8's acceptance criterion is "same inputs reproduce byte-identical reports
(modulo timestamp)", and ``implementation_plan.md`` §9 asks specifically for a
provider run against fixtures twice, plus snapshot comparison against
``tests/golden/``.

Both halves are here. The double-run test is the stronger of the two — it proves
the property directly, across the whole pipeline rather than the renderer alone.
The goldens are the safety net: they catch the case where the pipeline is
reproducibly *wrong*, and they put the actual report text into the pull-request
diff, which is what makes a change to the deliverable reviewable.

Nothing here opens a socket. Every scenario replays a committed cassette.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from keyreach.report.render import ReportFormat, render
from tests.goldens import (
    FIXED_TIME,
    GOLDEN_DIR,
    INVALID_KEY,
    SCENARIOS,
    SUFFIXES,
    VALID_KEY,
    Scenario,
    report_for,
    stale,
)

SCENARIO_PARAMS = [pytest.param(scenario, id=scenario.name) for scenario in SCENARIOS]
FORMAT_PARAMS = [pytest.param(fmt, id=fmt.value) for fmt in ReportFormat]

#: Deliberately far from `FIXED_TIME` in every component, so a partial
#: substitution — a date rendered one way here and another way there — shows up
#: as a mismatch rather than coincidentally agreeing.
OTHER_TIME = datetime(2030, 6, 15, 8, 30, 45, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Double-run byte equality
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", FORMAT_PARAMS)
@pytest.mark.parametrize("scenario", SCENARIO_PARAMS)
def test_two_runs_render_identically(scenario: Scenario, fmt: ReportFormat) -> None:
    """The whole pipeline, twice, compared as bytes.

    Each run re-detects, re-replays, re-scores and re-renders from scratch, so
    an unstable ordering anywhere in the chain fails here — not only in the
    renderer.
    """
    assert render(report_for(scenario), fmt) == render(report_for(scenario), fmt)


@pytest.mark.parametrize("fmt", FORMAT_PARAMS)
@pytest.mark.parametrize("scenario", SCENARIO_PARAMS)
def test_the_timestamp_is_the_only_thing_that_varies(
    scenario: Scenario, fmt: ReportFormat
) -> None:
    """`plan.md` §1's carve-out, tested rather than assumed.

    Renders the same run at two different timestamps and asserts the outputs
    differ *only* where the timestamp appears. Anything else reading the clock,
    or any ordering that happened to shift, would put a difference somewhere
    that this substitution cannot account for.
    """
    baseline = render(report_for(scenario), fmt)
    shifted = render(report_for(scenario, generated_at=OTHER_TIME), fmt)

    assert baseline != shifted
    assert baseline.replace(FIXED_TIME.isoformat(), OTHER_TIME.isoformat()) == shifted


# ---------------------------------------------------------------------------
# Golden snapshots
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", FORMAT_PARAMS)
@pytest.mark.parametrize("scenario", SCENARIO_PARAMS)
def test_matches_golden(scenario: Scenario, fmt: ReportFormat) -> None:
    path = GOLDEN_DIR / f"{scenario.name}.{SUFFIXES[fmt]}"

    assert path.exists(), f"missing golden: {path}"
    assert path.read_text(encoding="utf-8") == render(report_for(scenario), fmt)


def test_no_golden_is_stale() -> None:
    """The whole set at once, so a failure names every file that drifted.

    Mirrors ``python -m keyreach.report.schema --check``. Regenerate with
    ``python -m tests.regenerate_goldens`` and read the diff before committing:
    a change here is a change to what a security team receives.
    """
    assert stale() == []


def test_every_scenario_has_a_golden_in_every_format() -> None:
    """No format is silently untested because nobody generated its snapshot."""
    expected = {
        f"{scenario.name}.{suffix}"
        for scenario in SCENARIOS
        for suffix in SUFFIXES.values()
    }

    assert {path.name for path in GOLDEN_DIR.iterdir()} == expected


def test_goldens_contain_no_raw_key() -> None:
    """These files are committed, so the masking guarantee has to hold here too."""
    for path in sorted(GOLDEN_DIR.iterdir()):
        text = path.read_text(encoding="utf-8")

        assert VALID_KEY not in text, path
        assert INVALID_KEY not in text, path
