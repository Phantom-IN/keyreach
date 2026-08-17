"""keyreach command-line entrypoint — roadmap R1.5.

The surface is specified in ``implementation_plan.md`` §12 and implemented here
in full: a key or a batch, four output formats, provider forcing, pacing,
unmasking, opt-in aggressive enumeration, and fixed exit codes.

Three rules shape everything below.

**stdout is the report; stderr is everything else.** The banner, warnings and
errors go to stderr, so ``keyreach KEY --json | jq`` works and
``keyreach KEY --report md > finding.md`` produces a file with nothing in it but
the finding. A tool that decorates its own machine-readable output is a tool
nobody can pipe.

**The clock is read exactly once, here.** Every stage below this module is a
pure function of its inputs; ``generated_at`` is stamped at this boundary and
passed down (``implementation_plan.md`` §9.1). That is what lets a golden test
pin a timestamp and compare bytes.

**Exit codes are a contract, so they are enforced rather than inherited.**
``0`` clean, ``2`` a finding at or above ``--fail-on``, ``1`` anything went
wrong. Click's default for a malformed command line is ``2``, which would make
a mistyped flag indistinguishable from a Critical finding in CI — the one place
these codes actually get read by a machine. :func:`run` maps that case onto
``1`` instead.
"""

from __future__ import annotations

import asyncio
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import typer

from keyreach import __version__
from keyreach.core.engine import Engine
from keyreach.core.models import Severity
from keyreach.core.registry import UnknownProviderError, default_registry
from keyreach.report.build import build_report
from keyreach.report.render import DEFAULT_WIDTH, ReportFormat, render

if TYPE_CHECKING:
    from collections.abc import Sequence

    from keyreach.core.models import Report

# --------------------------------------------------------------------------
# Exit codes (`implementation_plan.md` §12)
# --------------------------------------------------------------------------

#: Ran cleanly, and nothing reached the `--fail-on` threshold.
EXIT_OK: Final = 0

#: Something went wrong: an unreadable file, an unknown provider, a malformed
#: flag. Deliberately **not** 2 — see this module's docstring.
EXIT_ERROR: Final = 1

#: At least one key produced a finding at or above `--fail-on`. The only
#: non-zero code that means keyreach worked.
EXIT_FINDING: Final = 2

#: Internal only, and never seen by a user. Click owns exit code 2 for a
#: malformed command line, and keyreach owns it for "a finding at or above
#: --fail-on" — the same number for "your CI config has a typo" and "this key is
#: Critical", which is intolerable in the one place these codes are read by a
#: machine. `main` therefore signals a finding with a code click never produces,
#: and :func:`run` translates. Chosen over catching exception classes because
#: typer vendors its own copy of click, so `except click.UsageError` silently
#: never fires — as this module discovered the hard way.
_FINDING_SIGNAL: Final = 3


# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------

#: Printed to **stderr** before a run. Plain ASCII on purpose: a box-drawing
#: wordmark turns into mojibake over ssh, in a Windows console, and in half the
#: CI log viewers people paste output into.
BANNER: Final = r"""    __                                   __
   / /_____  __  ______  ___  ____ _____/ /_
  / //_/ _ \/ / / / ___// _ \/ __ `/ ___/ __ \
 / ,< /  __/ /_/ / /   /  __/ /_/ / /__/ / / /
/_/|_|\___/\__, /_/    \___/\__,_/\___/_/ /_/
          /____/"""

#: The one-line reminder `plan.md` §11 asks for. It rides on the banner because
#: that is the moment a user is looking, and it is short enough to read.
AUTHORIZED_USE: Final = (
    "Use only against keys you own or are explicitly authorized to test."
)

#: Shown when `--aggressive` is set. `plan.md` §11 requires the noisy mode to be
#: "explicitly flagged and loudly warned"; this is the loud part.
AGGRESSIVE_WARNING: Final = (
    "AGGRESSIVE MODE: probing services beyond the credential itself. Still "
    "read-only, but broad enough to look like reconnaissance in the target's "
    "logs. Make sure this is in scope."
)


def banner(*, version: str = __version__) -> str:
    """The startup banner, as text. Returned rather than printed, so it is testable."""
    return (
        f"{BANNER}\n"
        f"  v{version}  |  deterministic  |  read-only  |  no AI\n"
        f"  {AUTHORIZED_USE}\n"
    )


def _warn(message: str) -> None:
    """Write to stderr. Never stdout — that belongs to the report."""
    typer.echo(message, err=True)


# --------------------------------------------------------------------------
# Option parsing
# --------------------------------------------------------------------------

#: `--delay` accepts a bare number of seconds or a duration with a unit, which
#: is how §12 spells it (`--delay 500ms`). Anchored, and the only two units are
#: the two anybody would type.
_DURATION: Final = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s)?$")

_UNIT_SECONDS: Final[dict[str, float]] = {"ms": 0.001, "s": 1.0, "": 1.0}


class CliError(Exception):
    """An operational failure that should exit ``1`` with a readable message."""


def parse_delay(raw: str) -> float:
    """``"500ms"`` → ``0.5``. Seconds when no unit is given."""
    matched = _DURATION.match(raw.strip())
    if matched is None:
        msg = (
            f"could not read --delay {raw!r}. Use seconds ('0.5'), or a "
            "duration with a unit ('500ms', '2s')."
        )
        raise CliError(msg)
    return float(matched["value"]) * _UNIT_SECONDS[matched["unit"] or ""]


def parse_format(raw: str) -> ReportFormat:
    try:
        return ReportFormat(raw)
    except ValueError:
        choices = ", ".join(fmt.value for fmt in ReportFormat)
        msg = f"unknown --report {raw!r}. Choose one of: {choices}."
        raise CliError(msg) from None


def parse_threshold(raw: str) -> Severity:
    try:
        return Severity(raw)
    except ValueError:
        choices = ", ".join(
            band.value for band in sorted(Severity, key=lambda b: b.rank)
        )
        msg = f"unknown --fail-on {raw!r}. Choose one of: {choices}."
        raise CliError(msg) from None


def read_keys(source: str | None, positional: str | None) -> list[str]:
    """The keys to scan, in the order they were given.

    Blank lines and ``#`` comments are skipped so a scanner's output, or a
    hand-kept list, can be fed in unedited. Duplicates are **kept**: if a key
    appears twice in a file the user gets two reports, because silently
    collapsing input is how a batch run quietly scans fewer things than it was
    asked to.
    """
    if positional is not None and source is not None:
        msg = "give a key or --file, not both."
        raise CliError(msg)

    if source is None:
        if positional is None:
            msg = "no key given. Pass one as an argument, or use --file/-."
            raise CliError(msg)
        return [positional]

    if source == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"could not read {source}: {exc}"
            raise CliError(msg) from exc

    keys = [
        stripped
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
    if not keys:
        where = "stdin" if source == "-" else source
        msg = f"no keys found in {where}."
        raise CliError(msg)
    return keys


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------


def _scan(  # noqa: PLR0913 - one parameter per documented CLI flag; a config
    # object would add indirection between the flag and the thing it sets
    keys: Sequence[str],
    *,
    provider: str | None,
    enumerate_capabilities: bool,
    aggressive: bool,
    delay: float,
    unmask: bool,
    generated_at: datetime,
) -> list[Report]:
    """Run the pipeline once per key, in the order given."""
    engine = Engine(
        delay=delay,
        unmask=unmask,
        enumerate_capabilities=enumerate_capabilities,
        force_provider=provider,
        aggressive=aggressive,
    )
    return [
        build_report(
            asyncio.run(engine.run(key)),
            generated_at=generated_at,
            tool_version=__version__,
        )
        for key in keys
    ]


#: Separator between reports in a batch run, for the human-readable formats.
#: JSON gets an array instead — see `_serialize`.
_SEPARATOR: Final = "\n" + "-" * DEFAULT_WIDTH + "\n\n"


def _serialize(
    reports: Sequence[Report], fmt: ReportFormat, *, color: bool, batch: bool
) -> str:
    """Render one or many reports into the text that goes to stdout or a file.

    A single key produces a single JSON **object**, which is what
    ``report.schema.json`` describes. A batch produces an **array** of them.

    ``batch`` is passed in rather than inferred from ``len(reports)`` on purpose.
    Which shape you get follows how keyreach was invoked, not how many keys
    happened to be in the file — so a script written against ``--file`` keeps
    working on the day that file contains exactly one key. Inferring it was the
    first implementation, and a test caught it.
    """
    if fmt is ReportFormat.JSON and batch:
        body = ",\n".join(
            "  " + render(report, fmt).rstrip("\n").replace("\n", "\n  ")
            for report in reports
        )
        return f"[\n{body}\n]\n"

    return _SEPARATOR.join(render(report, fmt, color=color) for report in reports)


def _worst(reports: Sequence[Report]) -> Severity:
    """The highest band across a batch. One bad key fails the whole run."""
    return max((report.severity for report in reports), key=lambda band: band.rank)


# --------------------------------------------------------------------------
# The command
# --------------------------------------------------------------------------

# A single-command app: typer collapses it so the binary is `keyreach [OPTIONS]`
# rather than `keyreach <subcommand>`.
#
# Help text comes from `main`'s docstring, not from a `help=` argument on this
# constructor — typer ignores the latter for a single-command app, and two
# sources of truth is one too many.
app = typer.Typer(name="keyreach", add_completion=False)


def _version_callback(value: bool) -> None:
    """Print the version and exit.

    Eager, so ``keyreach --version`` answers without requiring a key. No banner:
    this output gets parsed by release tooling.
    """
    if value:
        typer.echo(f"keyreach {__version__}")
        raise typer.Exit(code=EXIT_OK)


@app.command()
def main(  # noqa: PLR0913, PLR0917 - the CLI surface is the specification
    # in implementation_plan.md §12; collapsing it into a config object would
    # put an indirection between a flag and the thing it sets
    ctx: typer.Context,
    key: str | None = typer.Argument(
        None,
        metavar="KEY",
        help=(
            "The key to analyse. AWS takes both halves joined by a colon: "
            "'AKIA...:<secret access key>'."
        ),
    ),
    file: str | None = typer.Option(
        None,
        "--file",
        "-f",
        metavar="PATH",
        help="Read keys from a file, one per line. '-' reads standard input.",
    ),
    report: str = typer.Option(
        ReportFormat.TERMINAL.value,
        "--report",
        help="Output format: terminal, json, md, or html.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Shorthand for --report json."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", metavar="PATH", help="Write the report to a file."
    ),
    provider: str | None = typer.Option(
        None, "--provider", help="Force this provider and skip detection."
    ),
    no_enumerate: bool = typer.Option(
        False, "--no-enumerate", help="Validity and identity only; no capability map."
    ),
    aggressive: bool = typer.Option(
        False,
        "--aggressive",
        help="Opt in to broad, noisy (but still read-only) enumeration.",
    ),
    delay: str = typer.Option(
        "0", "--delay", metavar="DURATION", help="Pace probes, e.g. 500ms or 2s."
    ),
    unmask: bool = typer.Option(
        False, "--unmask", help="Show the full key. Off by default."
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        metavar="BAND",
        help="Exit 2 if any finding is at or above this band. For CI gating.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress the banner and warnings on stderr."
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the keyreach version and exit.",
    ),
) -> None:
    """Map what an exposed API key can actually reach.

    Detect the provider by rule, confirm liveness and identity, enumerate
    reachable services with read-only probes, compute a severity band, and emit
    a disclosure-ready report.

    Deterministic and rule-based — no AI/LLM anywhere. Read-only by default.
    Keys are masked by default.

    Use only against keys you own or are explicitly authorized to test, such as
    an in-scope bug bounty program or a documented engagement. See SECURITY.md.

    Exit codes: 0 clean, 2 a finding at or above --fail-on, 1 an error.
    """
    del version  # consumed by the eager callback above

    # A bare invocation has nothing to do and should say so rather than erroring
    # at somebody who is just looking around.
    if key is None and file is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=EXIT_OK)

    try:
        code = _run_scan(
            key=key,
            file=file,
            report=report,
            json_output=json_output,
            # Compared by name rather than by identity: typer vendors its own
            # copy of click, so the `ParameterSource` a `typer.Context` returns
            # is not the enum member `click.core.ParameterSource` exposes.
            explicit_format=_was_given(ctx, "report"),
            output=output,
            provider=provider,
            no_enumerate=no_enumerate,
            aggressive=aggressive,
            delay=delay,
            unmask=unmask,
            fail_on=fail_on,
            quiet=quiet,
        )
    except CliError as error:
        _warn(f"keyreach: {error}")
        raise typer.Exit(code=EXIT_ERROR) from error

    raise typer.Exit(code=_FINDING_SIGNAL if code == EXIT_FINDING else code)


def _was_given(ctx: typer.Context, name: str) -> bool:
    """Did the user actually type this option, or is it just the default?

    Needed to tell `--report json` (agreeing with `--json`) apart from an
    untouched default (which `--json` may freely override).
    """
    source = ctx.get_parameter_source(name)
    return source is not None and source.name != "DEFAULT"


def _run_scan(  # noqa: PLR0913 - mirrors `main`'s flags one for one
    *,
    key: str | None,
    file: str | None,
    report: str,
    json_output: bool,
    explicit_format: bool,
    output: Path | None,
    provider: str | None,
    no_enumerate: bool,
    aggressive: bool,
    delay: str,
    unmask: bool,
    fail_on: str | None,
    quiet: bool,
) -> int:
    """Everything between parsing and the exit code. Raises :class:`CliError`."""
    fmt = _resolve_format(report, json_output=json_output, explicit=explicit_format)
    if fmt is ReportFormat.HTML and file is not None:
        msg = (
            "--report html renders one self-contained finding, not a batch. "
            "Use --report md or --json with --file, or run keyreach once per "
            "key for HTML output."
        )
        raise CliError(msg)
    threshold = parse_threshold(fail_on) if fail_on is not None else None
    paced = parse_delay(delay)
    keys = read_keys(file, key)

    if provider is not None and provider not in default_registry:
        known = ", ".join(default_registry.names())
        msg = f"unknown --provider {provider!r}. Known providers: {known}."
        raise CliError(msg)

    if not quiet:
        _warn(banner())
        if aggressive:
            _warn(f"keyreach: {AGGRESSIVE_WARNING}\n")
        if unmask:
            _warn(
                "keyreach: --unmask is set; the full key will appear in the "
                "output. Do not paste this into a ticket.\n"
            )

    # The one clock read in the whole pipeline. Everything downstream is a pure
    # function of its inputs plus this value.
    generated_at = datetime.now(tz=UTC)

    try:
        reports = _scan(
            keys,
            provider=provider,
            enumerate_capabilities=not no_enumerate,
            aggressive=aggressive,
            delay=paced,
            unmask=unmask,
            generated_at=generated_at,
        )
    except UnknownProviderError as error:  # pragma: no cover - guarded above
        raise CliError(str(error)) from error

    # Colour is for a person watching a terminal, never for a file or a pipe.
    color = fmt is ReportFormat.TERMINAL and output is None and sys.stdout.isatty()
    rendered = _serialize(reports, fmt, color=color, batch=file is not None)

    if output is None:
        sys.stdout.write(rendered)
    else:
        try:
            output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            msg = f"could not write {output}: {exc}"
            raise CliError(msg) from exc
        if not quiet:
            _warn(f"keyreach: wrote {len(reports)} report(s) to {output}")

    if threshold is not None and _worst(reports) >= threshold:
        return EXIT_FINDING
    return EXIT_OK


def _resolve_format(report: str, *, json_output: bool, explicit: bool) -> ReportFormat:
    """``--json`` and ``--report`` mean the same thing, so they must not disagree.

    Letting one silently win is how a user ends up with Markdown in a file they
    told keyreach to fill with JSON. Both spellings exist because §12 documents
    both; a contradiction is an error rather than a precedence rule nobody
    remembers.
    """
    fmt = parse_format(report)
    if not json_output:
        return fmt
    if explicit and fmt is not ReportFormat.JSON:
        msg = f"--json and --report {report} contradict each other. Pick one."
        raise CliError(msg)
    return ReportFormat.JSON


def run() -> int:
    """Console-script entry point, and the guardian of the exit-code contract.

    Every path out of the command — ours, click's usage errors, an abort —
    arrives here as a ``SystemExit``, and this is the single place that decides
    what the shell sees. Deliberately built on the exit code rather than on
    exception types: typer vendors its own copy of click, so ``click.UsageError``
    imported from the real package names a class that is never raised, and an
    ``except`` clause for it looks correct while catching nothing.

    The mapping is total, so no code outside the documented ``0``/``1``/``2`` can
    escape.
    """
    try:
        app()
    except SystemExit as exit_signal:
        return _exit_code(exit_signal.code)
    # Click always exits rather than returning, so this is unreachable in
    # practice; returning success is the only sane answer if that ever changes.
    return EXIT_OK  # pragma: no cover - click always raises SystemExit


def _exit_code(raw: int | str | None) -> int:
    """Map whatever click exited with onto keyreach's three documented codes."""
    if raw == _FINDING_SIGNAL:
        return EXIT_FINDING
    if raw is None or raw == EXIT_OK:
        return EXIT_OK
    # Everything else — our own CliError exit, click's 2 for a bad command
    # line, an abort — is an operational failure.
    return EXIT_ERROR
