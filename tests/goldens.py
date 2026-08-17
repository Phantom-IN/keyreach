"""Golden-file scenarios, shared by the determinism test and the regenerator.

Three end-to-end runs through the committed cassettes — a live key, a dead key,
and a key no rule recognises — rendered in all four formats. Twelve files under
``tests/golden/`` since roadmap R2.9 added HTML to the three R0.8 shipped.

The scenarios live here rather than inside ``test_determinism.py`` so that
regenerating a snapshot is a deliberate act (``python -m tests.regenerate_goldens``)
and never a side effect of running the suite. A test that can silently rewrite
its own expectation is not a test.

Two values are pinned. ``generated_at`` is the one field ``plan.md`` §1 allows to
vary between runs, so a snapshot has to fix it. ``tool_version`` is pinned to a
constant rather than read from ``keyreach.__version__`` so that cutting a release
does not invalidate every golden file — the version's *presence* in the footer is
what these snapshots are checking, not its value.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NamedTuple

from keyreach.core.detect import Detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, RecordMode
from keyreach.core.models import Report
from keyreach.core.registry import ProviderRegistry
from keyreach.report.build import build_report
from keyreach.report.render import ReportFormat, render

FIXTURES: Final = Path(__file__).parent / "fixtures"
GOLDEN_DIR: Final = Path(__file__).parent / "golden"

#: Fixed timestamp. Timezone-aware, because `Report` rejects naive datetimes —
#: a naive one renders differently depending on where the suite runs, which is
#: exactly the nondeterminism these files exist to catch.
FIXED_TIME: Final = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

FIXED_VERSION: Final = "0.0.0-golden"

CASSETTE_PACKAGE: Final = "tests.cassette_providers"
RULES: Final = FIXTURES / "detection_rules.yml"

VALID_KEY: Final = "csst_" + "a" * 32
INVALID_KEY: Final = "csst_" + "b" * 32
UNKNOWN_KEY: Final = "this-matches-no-rule-at-all"

#: File suffix per format. `.txt` rather than `.ansi` because the golden is the
#: colourless rendering — colour is a terminal concern and never reaches a file.
SUFFIXES: Final[dict[ReportFormat, str]] = {
    ReportFormat.TERMINAL: "txt",
    ReportFormat.MARKDOWN: "md",
    ReportFormat.JSON: "json",
    ReportFormat.HTML: "html",
}


class Scenario(NamedTuple):
    name: str
    key: str
    cassette: str


SCENARIOS: Final = (
    Scenario("valid", VALID_KEY, "cassette_provider.json"),
    Scenario("invalid", INVALID_KEY, "cassette_provider_invalid.json"),
    # No provider answers, so the cassette is never opened; named anyway so the
    # engine is constructed identically in all three cases.
    Scenario("unidentified", UNKNOWN_KEY, "cassette_provider.json"),
)


async def _run(scenario: Scenario) -> EngineResult:
    engine = Engine(
        registry=ProviderRegistry(CASSETTE_PACKAGE),
        detector=Detector(RULES),
        cassette=Cassette(FIXTURES / scenario.cassette),
        mode=RecordMode.REPLAY,
    )
    return await engine.run(scenario.key)


def engine_result_for(scenario: Scenario) -> EngineResult:
    """Run the detect → validate → enumerate half. Replay only, no socket."""
    return asyncio.run(_run(scenario))


def report_for(scenario: Scenario, *, generated_at: datetime = FIXED_TIME) -> Report:
    """Run one scenario end to end, into a finished report."""
    return build_report(
        engine_result_for(scenario),
        generated_at=generated_at,
        tool_version=FIXED_VERSION,
    )


def expected() -> dict[Path, str]:
    """Every golden file and the content it should hold, keyed by path."""
    rendered: dict[Path, str] = {}
    for scenario in SCENARIOS:
        report = report_for(scenario)
        for fmt, suffix in SUFFIXES.items():
            path = GOLDEN_DIR / f"{scenario.name}.{suffix}"
            rendered[path] = render(report, fmt)
    return rendered


def stale() -> list[Path]:
    """Golden files that are missing or no longer match, in a stable order."""
    return sorted(
        path
        for path, content in expected().items()
        if not path.exists() or path.read_text(encoding="utf-8") != content
    )
