"""CLI scaffold tests (roadmap R0.2).

R0.2's acceptance criterion is narrow: ``keyreach --help`` prints and the
package is installable with zero real logic. These tests hold that line, and
guard the two things that silently rot in a scaffold — a console script that
stops resolving, and a version that drifts from the distribution metadata.
"""

from __future__ import annotations

from importlib import metadata

import pytest
from typer.testing import CliRunner

from keyreach import __version__
from keyreach.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_help_exits_zero_and_describes_the_tool(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "--version" in result.output


def test_help_states_the_read_only_and_no_ai_guarantees(runner: CliRunner) -> None:
    """The guarantees are the product (plan.md §1). Keep them in front of users."""
    result = runner.invoke(app, ["--help"])
    output = result.output.lower()

    assert "read-only" in output
    assert "no ai/llm" in output
    assert "authorized" in output


def test_version_flag_prints_the_version(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"keyreach {__version__}"


def test_bare_invocation_shows_help_rather_than_pretending_to_work(
    runner: CliRunner,
) -> None:
    """There is no pipeline yet. A bare run must not imply otherwise."""
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "--version" in result.output


def test_installed_metadata_matches_dunder_version() -> None:
    """hatchling single-sources the version from ``keyreach/__init__.py``.

    If this fails, the wheel was built from a different ``__version__`` than the
    one now on disk — reinstall, or the CLI will report a version that does not
    match what was shipped.
    """
    assert metadata.version("keyreach") == __version__


def test_version_output_is_byte_identical_across_runs(runner: CliRunner) -> None:
    """Determinism is the whole product (plan.md §1), so it is tested from day one.

    Trivial while the CLI only prints a version; the same assertion grows into
    the golden-file and double-run report checks in R0.8.
    """
    first = runner.invoke(app, ["--version"]).output
    second = runner.invoke(app, ["--version"]).output

    assert first == second
