"""CLI scaffold tests (roadmap R0.2).

R0.2's acceptance criterion is narrow: ``keyreach --help`` prints and the
package is installable with zero real logic. These tests hold that line, and
guard the two things that silently rot in a scaffold — a console script that
stops resolving, and a version that drifts from the distribution metadata.
"""

from __future__ import annotations

import re
from importlib import metadata

import pytest
from typer.testing import CliRunner

from keyreach import __version__
from keyreach.cli import app

#: ANSI SGR escapes, which `rich` emits to colour the help panel.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def readable(output: str) -> str:
    """Help text as a human reads it: no styling, no layout-dependent breaks.

    Asserting on raw help output looks harmless and is not. Two things about it
    vary with the environment rather than with keyreach:

    * **Styling.** `rich` colours the options panel, and it styles the leading
      hyphen of a flag as its own span — `--version` is emitted as
      ``\\x1b[1;36m-\\x1b[0m\\x1b[1;36m-version\\x1b[0m``, in which the literal
      substring ``--version`` does not occur. Whether that happens depends on
      whether `rich` thinks it is writing to a terminal, and GitHub Actions sets
      ``CI=true``, which makes it decide that it is. So these assertions passed
      on every developer machine and failed on the first CI run that executed
      them (roadmap R0.9).
    * **Width.** `rich` wraps to the terminal width, so any asserted phrase can
      acquire a newline in the middle depending on where it is run.

    Stripping the escapes and collapsing whitespace removes both. The runner
    fixture also pins colour and width, so this is belt and braces — the point
    being that a test of user-facing text should assert on the text.
    """
    return " ".join(_ANSI.sub("", output).split())


@pytest.fixture
def runner() -> CliRunner:
    # `NO_COLOR` and `TERM=dumb` are the two conventions `rich` honours to
    # disable styling; `COLUMNS` pins the wrap width. Set here rather than left
    # to the ambient environment so the same output is produced on a
    # developer's terminal, in CI, and in a container.
    return CliRunner(env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "100"})


def test_help_exits_zero_and_describes_the_tool(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "--version" in readable(result.output)


def test_help_states_the_read_only_and_no_ai_guarantees(runner: CliRunner) -> None:
    """The guarantees are the product (plan.md §1). Keep them in front of users."""
    output = readable(runner.invoke(app, ["--help"]).output).lower()

    assert "read-only" in output
    assert "no ai/llm" in output
    assert "authorized" in output


def test_help_is_readable_with_colour_forced_on(runner: CliRunner) -> None:
    """Regression test for the failure that R0.9's first CI run exposed.

    `FORCE_COLOR` reproduces what GitHub Actions does to `rich` by setting
    ``CI=true``. The guarantees above must still reach a user whose terminal
    supports colour — and the assertions that check them must not quietly stop
    checking anything.
    """
    coloured = CliRunner(env={"FORCE_COLOR": "1", "COLUMNS": "100"}).invoke(
        app, ["--help"]
    )

    assert "\x1b[" in coloured.output, "expected rich to emit styling here"
    assert "--version" not in coloured.output, (
        "rich splits the leading hyphen into its own span; if this ever stops "
        "being true the helper is still correct, but the hazard is gone"
    )
    assert "--version" in readable(coloured.output)
    assert "no ai/llm" in readable(coloured.output).lower()


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
    assert "--version" in readable(result.output)


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
