"""keyreach command-line entrypoint.

**Roadmap R0.2 scaffold — deliberately zero real logic.** This module exposes
``--help`` and ``--version`` and nothing else. It exists so the package is
installable and the console script resolves; the pipeline behind it is built
one roadmap item at a time.

The full CLI surface (``--report``, ``--json``, ``-f``, ``--provider``,
``--no-enumerate``, ``--delay``, ``--unmask``, ``--fail-on``, and the fixed
exit codes ``0``/``1``/``2``) is specified in ``implementation_plan.md`` §12
and lands in roadmap item **R1.5**. Do not add flags here ahead of that item —
the specification is the contract, and inventing CLI surface early is how a
tool ends up with two ways to do everything.
"""

from __future__ import annotations

import typer

from keyreach import __version__

# A single-command app: typer collapses it so the binary is `keyreach [OPTIONS]`
# rather than `keyreach <subcommand>`. That already matches the shape specified
# for the finished CLI (`keyreach KEY --json`), so R1.5 adds arguments here
# instead of restructuring.
#
# Help text therefore comes from `main`'s docstring, not from a `help=` argument
# on this constructor — typer ignores the latter for a single-command app, and
# two sources of truth is one too many.
app = typer.Typer(name="keyreach", add_completion=False)


def _version_callback(value: bool) -> None:
    """Print the version and exit.

    Registered as an eager callback so ``keyreach --version`` answers without
    requiring any other argument, and keeps working unchanged once R1.5 adds
    the real arguments around it.
    """
    if value:
        typer.echo(f"keyreach {__version__}")
        raise typer.Exit(code=0)


@app.command()
def main(
    ctx: typer.Context,
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

    Not wired up yet: detection, validation, enumeration, scoring and reporting
    are roadmap items R0.3 through R1.5. Until then a bare invocation prints
    this help rather than pretending to work.
    """
    # `version` is consumed by the eager callback above before this body runs;
    # it is named here only so typer registers the option.
    del version

    typer.echo(ctx.get_help())
