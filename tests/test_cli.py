"""CLI tests (roadmap R0.2 scaffold, completed in R1.5).

The CLI is the only part of keyreach a user actually touches, and the only part
whose contract is read by a machine — CI reads the exit code. So the sections
below are organised around the three promises `implementation_plan.md` §12
makes: the flags do what they say, **stdout carries only the report**, and the
exit codes are `0` / `1` / `2` and nothing else.

**No test here opens a socket.** `use_cassette` swaps the CLI's `Engine` for one
bound to a committed fixture in replay mode, so these run the *real* pipeline —
detection, probing, scoring, report assembly, rendering — against recorded
responses. Patching `_scan` instead would have tested the argument parsing and
nothing underneath it.
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from keyreach import __version__
from keyreach.cli import (
    _FINDING_SIGNAL,
    AGGRESSIVE_WARNING,
    BANNER,
    EXIT_ERROR,
    EXIT_FINDING,
    EXIT_OK,
    CliError,
    _exit_code,
    app,
    banner,
    parse_delay,
    parse_format,
    parse_threshold,
    read_keys,
    run,
)
from keyreach.core.engine import Engine
from keyreach.core.http import Cassette, RecordMode
from keyreach.report.render import ReportFormat

if TYPE_CHECKING:
    from collections.abc import Callable

FIXTURES = Path(__file__).parent / "fixtures"

GOOGLE_KEY = "AIza" + "0" * 35
AWS_ROOT_KEY = (
    "AKIA" + "IOSFODNN7EXAMPLE" + ":" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
)

#: ANSI SGR escapes, which `rich` emits to colour the help panel.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


_TIMESTAMP = re.compile(r'"generated_at": "[^"]+"')


def _untimed(rendered: str) -> str:
    """Report text with the injected timestamp removed.

    `generated_at` is the single field two runs of the same key may legitimately
    differ in, so every comparison of rendered output blanks it first.
    """
    return _TIMESTAMP.sub('"generated_at": ""', rendered)


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


@pytest.fixture
def use_cassette(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Bind the CLI's engine to a committed cassette. Opens no socket.

    Returned as a factory so a test picks the scenario it needs. Replay mode
    constructs no HTTP client at all, so a test that forgets to call this fails
    by trying to reach the internet rather than by quietly passing.
    """

    def bind(name: str) -> None:
        def factory(**kwargs: object) -> Engine:
            return Engine(
                cassette=Cassette(FIXTURES / f"{name}.json"),
                mode=RecordMode.REPLAY,
                **kwargs,  # type: ignore[arg-type]
            )

        monkeypatch.setattr("keyreach.cli.Engine", factory)

    return bind


def invoke(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, str, str]:
    """Run the real console-script entry point. Returns ``(code, stdout, stderr)``.

    Deliberately `run()` and not `CliRunner`: `run()` is what the `keyreach`
    binary calls, and it is where the exit-code contract is enforced. A test
    that invoked the typer app directly would see an internal signal code and
    would not exercise the mapping at all.
    """
    monkeypatch.setattr("sys.argv", ["keyreach", *args])
    code = run()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------------------------------------------------------------------------
# Help and version — the scaffold's promises, still held
# ---------------------------------------------------------------------------


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


def test_help_documents_the_exit_codes(runner: CliRunner) -> None:
    """They are a contract a machine reads; an undocumented contract is folklore."""
    output = readable(runner.invoke(app, ["--help"]).output).lower()

    assert "exit codes" in output
    assert "--fail-on" in output


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


def test_version_carries_no_banner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Release tooling parses this. Decorating it would be a breaking change."""
    code, out, err = invoke(monkeypatch, capsys, "--version")

    assert code == EXIT_OK
    assert out.strip() == f"keyreach {__version__}"
    assert err == ""


def test_bare_invocation_shows_help_rather_than_erroring(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Somebody typing `keyreach` is looking around, not making a mistake."""
    code, out, _ = invoke(monkeypatch, capsys)

    assert code == EXIT_OK
    assert "--fail-on" in readable(out)


def test_installed_metadata_matches_dunder_version() -> None:
    """hatchling single-sources the version from ``keyreach/__init__.py``.

    If this fails, the wheel was built from a different ``__version__`` than the
    one now on disk — reinstall, or the CLI will report a version that does not
    match what was shipped.
    """
    assert metadata.version("keyreach") == __version__


# ---------------------------------------------------------------------------
# The banner
# ---------------------------------------------------------------------------


def test_the_banner_is_plain_ascii() -> None:
    """It goes to terminals keyreach does not control.

    A box-drawing wordmark becomes mojibake over ssh, in a Windows console, and
    in half the CI log viewers people paste output into.
    """
    assert banner().isascii()


def test_the_banner_carries_the_authorized_use_reminder() -> None:
    """`plan.md` §11 asks for a first-run reminder. This is it."""
    text = banner()

    assert "authorized to test" in text
    assert "read-only" in text
    assert "no AI" in text
    assert __version__ in text


def test_the_banner_goes_to_stderr_not_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """The whole reason `keyreach KEY --json | jq` works.

    A tool that decorates its own machine-readable output is a tool nobody can
    pipe, and this is the assertion that keeps that true.
    """
    use_cassette("google_valid")
    code, out, err = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json")

    assert code == EXIT_OK
    assert BANNER.splitlines()[-1] in err
    assert "keyreach" not in out.split('"tool"')[0]
    json.loads(out)


def test_quiet_suppresses_the_banner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, _, err = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")

    assert err == ""


# ---------------------------------------------------------------------------
# Output formats, and stdout staying clean
# ---------------------------------------------------------------------------


def test_json_output_is_schema_shaped_and_parseable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    code, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")
    payload = json.loads(out)

    assert code == EXIT_OK
    assert payload["provider"] == "google"
    assert payload["schema_version"] == "1.0"
    assert payload["capabilities"]


def test_json_shorthand_and_report_flag_agree(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, shorthand, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")
    use_cassette("google_valid")
    _, spelled, _ = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--report", "json", "--quiet"
    )

    # Modulo the injected timestamp, which is the one field allowed to differ
    # between two runs (`plan.md` §1).
    assert _untimed(shorthand) == _untimed(spelled)


def test_contradictory_format_flags_are_an_error_not_a_precedence_rule(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Silently letting one win is how a user gets Markdown in a file meant
    for JSON."""
    code, out, err = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--json", "--report", "md", "--quiet"
    )

    assert code == EXIT_ERROR
    assert out == ""
    assert "contradict" in err


def test_markdown_output_is_the_disclosure_artifact(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--report", "md", "--quiet")

    assert out.startswith("# ")
    assert "## Capabilities" in out


def test_html_output_is_a_self_contained_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--report", "html", "--quiet")

    assert out.startswith("<!doctype html>")
    assert out.rstrip().endswith("</html>")
    assert "<h2>Capabilities</h2>" in out


def test_html_output_can_be_written_to_a_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    use_cassette("google_valid")
    target = tmp_path / "finding.html"
    code, out, err = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--report", "html", "-o", str(target)
    )

    assert code == EXIT_OK
    assert out == ""
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert str(target) in err


def test_output_file_receives_the_report_and_stdout_stays_empty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    use_cassette("google_valid")
    target = tmp_path / "finding.md"
    code, out, err = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--report", "md", "-o", str(target)
    )

    assert code == EXIT_OK
    assert out == ""
    assert target.read_text(encoding="utf-8").startswith("# ")
    assert str(target) in err


def test_quiet_silences_the_wrote_confirmation_too(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    """`--quiet` means quiet: a script redirecting stderr gets nothing at all."""
    use_cassette("google_valid")
    target = tmp_path / "finding.md"
    code, out, err = invoke(
        monkeypatch,
        capsys,
        GOOGLE_KEY,
        "--report",
        "md",
        "-o",
        str(target),
        "--quiet",
    )

    assert code == EXIT_OK
    assert out == ""
    assert err == ""
    assert target.read_text(encoding="utf-8").startswith("# ")


def test_an_unwritable_output_path_is_an_operational_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    use_cassette("google_valid")
    code, _, err = invoke(
        monkeypatch,
        capsys,
        GOOGLE_KEY,
        "-o",
        str(tmp_path / "no-such-directory" / "out.txt"),
        "--quiet",
    )

    assert code == EXIT_ERROR
    assert "could not write" in err


def test_terminal_output_carries_no_colour_when_piped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """ANSI escapes belong to a live terminal, never to a pipe or a file."""
    use_cassette("google_valid")
    _, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--quiet")

    assert "\x1b[" not in out


# ---------------------------------------------------------------------------
# Batch input
# ---------------------------------------------------------------------------


def test_a_batch_from_a_file_reports_every_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    use_cassette("google_valid")
    keys = tmp_path / "keys.txt"
    keys.write_text(
        f"# found by a scanner\n{GOOGLE_KEY}\n\nnot-a-key-but-long-enough-to-look\n",
        encoding="utf-8",
    )

    code, out, _ = invoke(monkeypatch, capsys, "-f", str(keys), "--json", "--quiet")
    payload = json.loads(out)

    assert code == EXIT_OK
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert payload[0]["provider"] == "google"
    assert payload[1]["provider"] == "unknown"


def test_a_single_key_is_an_object_and_a_batch_is_an_array(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    """Which shape you get follows the invocation, not the input length.

    A script written against `--file` keeps working on the day the file happens
    to contain exactly one key.
    """
    keys = tmp_path / "one.txt"
    keys.write_text(f"{GOOGLE_KEY}\n", encoding="utf-8")

    use_cassette("google_valid")
    _, batched, _ = invoke(monkeypatch, capsys, "-f", str(keys), "--json", "--quiet")
    use_cassette("google_valid")
    _, single, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")

    assert isinstance(json.loads(batched), list)
    assert isinstance(json.loads(single), dict)


def test_keys_can_be_piped_in(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """`cat keys.txt | keyreach -`, and the way to keep a key out of shell history."""
    use_cassette("google_valid")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(f"{GOOGLE_KEY}\n"))

    code, out, _ = invoke(monkeypatch, capsys, "-f", "-", "--json", "--quiet")

    assert code == EXIT_OK
    assert json.loads(out)[0]["provider"] == "google"


def test_html_refuses_a_batch_even_of_one_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """One self-contained document, not several `<html>` trees concatenated.

    Rejected on `--file` alone — whether the file holds one key or many —
    because which shape you get follows the invocation, matching how
    JSON's object-vs-array split already works
    (`test_a_single_key_is_an_object_and_a_batch_is_an_array`). No cassette
    is needed: the CLI must refuse this before a single probe runs.
    """
    keys = tmp_path / "one.txt"
    keys.write_text(f"{GOOGLE_KEY}\n", encoding="utf-8")

    code, out, err = invoke(
        monkeypatch, capsys, "-f", str(keys), "--report", "html", "--quiet"
    )

    assert code == EXIT_ERROR
    assert out == ""
    assert "--report html" in err
    assert "batch" in err


def test_a_batch_of_terminal_reports_is_separated(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    use_cassette("google_valid")
    keys = tmp_path / "keys.txt"
    keys.write_text(f"{GOOGLE_KEY}\n{GOOGLE_KEY}\n", encoding="utf-8")

    _, out, _ = invoke(monkeypatch, capsys, "-f", str(keys), "--quiet")

    assert out.count("Why this severity") == 2
    assert "-" * 60 in out


# ---------------------------------------------------------------------------
# Exit codes — the contract a machine reads
# ---------------------------------------------------------------------------


def test_a_clean_run_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    code, _, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--quiet")

    assert code == EXIT_OK


def test_a_finding_at_the_threshold_exits_two(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """CI gating, which is the only reason these codes exist."""
    use_cassette("aws_root")
    code, _, _ = invoke(
        monkeypatch, capsys, AWS_ROOT_KEY, "--fail-on", "high", "--quiet"
    )

    assert code == EXIT_FINDING


def test_a_finding_below_the_threshold_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    code, _, _ = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--fail-on", "critical", "--quiet"
    )

    assert code == EXIT_OK


def test_the_worst_key_in_a_batch_decides_the_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
    tmp_path: Path,
) -> None:
    """One Critical key must fail the run even if it is last in the file."""
    use_cassette("aws_root")
    keys = tmp_path / "keys.txt"
    keys.write_text(f"harmless-looking-token-value\n{AWS_ROOT_KEY}\n", encoding="utf-8")

    code, _, _ = invoke(
        monkeypatch, capsys, "-f", str(keys), "--fail-on", "critical", "--quiet"
    )

    assert code == EXIT_FINDING


def test_a_malformed_command_line_exits_one_not_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The trap this contract exists to avoid.

    Click exits 2 on an unknown option, and keyreach's 2 means "a finding at or
    above --fail-on". Left alone, a typo in a CI config would be indistinguishable
    from a Critical key — in the one place these codes are read by a machine.
    """
    code, _, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--no-such-flag")

    assert code == EXIT_ERROR


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(_FINDING_SIGNAL, EXIT_FINDING, id="finding-signal"),
        pytest.param(0, EXIT_OK, id="success"),
        pytest.param(None, EXIT_OK, id="no-code"),
        pytest.param(1, EXIT_ERROR, id="our-error"),
        pytest.param(2, EXIT_ERROR, id="clicks-usage-error"),
        pytest.param("boom", EXIT_ERROR, id="a-message-instead-of-a-code"),
    ],
)
def test_every_exit_path_maps_onto_the_three_documented_codes(
    raw: int | str | None, expected: int
) -> None:
    """The mapping is total, so nothing outside 0/1/2 can reach a shell."""
    assert _exit_code(raw) == expected


# ---------------------------------------------------------------------------
# Warnings that `plan.md` §11 requires
# ---------------------------------------------------------------------------


def test_aggressive_mode_warns_loudly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """`plan.md` §11: opt-in, explicitly flagged, and loudly warned."""
    use_cassette("aws_valid")
    _, _, err = invoke(monkeypatch, capsys, AWS_ROOT_KEY, "--aggressive", "--json")

    assert AGGRESSIVE_WARNING in err
    assert "in scope" in err


def test_unmask_warns_before_printing_the_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, out, err = invoke(monkeypatch, capsys, GOOGLE_KEY, "--unmask", "--json")

    assert "--unmask is set" in err
    assert GOOGLE_KEY in out


def test_masking_is_the_default(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")

    assert GOOGLE_KEY not in out


# ---------------------------------------------------------------------------
# Flags that change what runs
# ---------------------------------------------------------------------------


def test_no_enumerate_stops_after_validation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    use_cassette("google_valid")
    _, out, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")
    use_cassette("google_valid")
    _, minimal, _ = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet", "--no-enumerate"
    )

    assert json.loads(out)["capabilities"]
    assert json.loads(minimal)["capabilities"] == []
    assert json.loads(minimal)["validation"]["valid"]


def test_forcing_a_provider_skips_detection_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """A capability map produced this way rests on the operator's claim.

    The report says which, because a reader cannot otherwise tell an
    operator's assertion from a rule's verdict.
    """
    use_cassette("google_valid")
    code, out, _ = invoke(
        monkeypatch,
        capsys,
        GOOGLE_KEY,
        "--provider",
        "google",
        "--json",
        "--quiet",
    )
    payload = json.loads(out)

    assert code == EXIT_OK
    assert payload["provider"] == "google"
    assert any("Detection was overridden" in note for note in payload["notes"])


def test_an_unknown_provider_names_the_ones_that_exist(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = invoke(
        monkeypatch, capsys, GOOGLE_KEY, "--provider", "azure", "--quiet"
    )

    assert code == EXIT_ERROR
    assert "google" in err


# ---------------------------------------------------------------------------
# Option parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("0", 0.0, id="zero"),
        pytest.param("2", 2.0, id="bare-seconds"),
        pytest.param("0.5", 0.5, id="fractional-seconds"),
        pytest.param("500ms", 0.5, id="milliseconds"),
        pytest.param("2s", 2.0, id="explicit-seconds"),
        pytest.param("  250ms  ", 0.25, id="surrounding-space"),
    ],
)
def test_delay_accepts_the_durations_the_spec_documents(
    raw: str, expected: float
) -> None:
    assert parse_delay(raw) == pytest.approx(expected)


@pytest.mark.parametrize("raw", ["soon", "-1", "5m", "", "1.2.3", "500 ms"])
def test_delay_rejects_anything_it_cannot_read_exactly(raw: str) -> None:
    """A misread delay would silently hammer an endpoint the user meant to pace."""
    with pytest.raises(CliError, match="--delay"):
        parse_delay(raw)


def test_format_parsing_lists_the_choices_when_it_fails() -> None:
    with pytest.raises(CliError, match="terminal, json, md, html"):
        parse_format("pdf")


def test_every_report_format_is_accepted() -> None:
    for fmt in ReportFormat:
        assert parse_format(fmt.value) is fmt


def test_threshold_parsing_lists_the_bands_in_order() -> None:
    with pytest.raises(CliError, match="info, low, medium, high, critical"):
        parse_threshold("catastrophic")


def test_every_band_is_accepted_as_a_threshold() -> None:
    assert parse_threshold("critical").value == "critical"


# ---------------------------------------------------------------------------
# Reading keys
# ---------------------------------------------------------------------------


def test_comments_and_blank_lines_are_skipped(tmp_path: Path) -> None:
    """So a scanner's output, or a hand-kept list, can be fed in unedited."""
    keys = tmp_path / "keys.txt"
    keys.write_text("# header\n\n  key-one  \n\n# tail\nkey-two\n", encoding="utf-8")

    assert read_keys(str(keys), None) == ["key-one", "key-two"]


def test_duplicates_are_kept(tmp_path: Path) -> None:
    """Silently collapsing input is how a batch scans fewer things than asked."""
    keys = tmp_path / "keys.txt"
    keys.write_text("same\nsame\n", encoding="utf-8")

    assert read_keys(str(keys), None) == ["same", "same"]


def test_a_key_and_a_file_together_is_an_error() -> None:
    with pytest.raises(CliError, match="not both"):
        read_keys("keys.txt", "a-key")


def test_no_key_at_all_is_an_error() -> None:
    with pytest.raises(CliError, match="no key given"):
        read_keys(None, None)


def test_an_empty_file_is_an_error_rather_than_a_silent_success(
    tmp_path: Path,
) -> None:
    keys = tmp_path / "empty.txt"
    keys.write_text("# nothing but a comment\n", encoding="utf-8")

    with pytest.raises(CliError, match="no keys found"):
        read_keys(str(keys), None)


def test_empty_stdin_names_stdin_in_the_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(""))

    with pytest.raises(CliError, match="stdin"):
        read_keys("-", None)


def test_an_unreadable_file_is_an_operational_error(tmp_path: Path) -> None:
    with pytest.raises(CliError, match="could not read"):
        read_keys(str(tmp_path / "absent.txt"), None)


# ---------------------------------------------------------------------------
# Determinism, end to end through the CLI
# ---------------------------------------------------------------------------


def test_two_runs_of_one_key_differ_only_by_timestamp(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    use_cassette: Callable[[str], None],
) -> None:
    """`plan.md` §1, asserted at the surface a user actually touches."""
    use_cassette("google_valid")
    _, first, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")
    use_cassette("google_valid")
    _, second, _ = invoke(monkeypatch, capsys, GOOGLE_KEY, "--json", "--quiet")

    assert _untimed(first) == _untimed(second)
    assert '"generated_at"' in first
