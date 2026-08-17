"""Render a :class:`Report` to terminal text, JSON, Markdown, or HTML.

Four formats, one input, no shared mutable state (``implementation_plan.md``
§9). HTML landed in roadmap R2.9, through the same autoescaping loader that
was configured to expect it from R0.8 onward — ``select_autoescape`` matches
the ``report.html.j2`` template on its ``.html.j2`` suffix.

**Determinism is the whole contract here.** ``plan.md`` §1 requires the same key
against the same provider state to reproduce the same report byte for byte, and
rendering is the stage where that is easiest to lose:

* **Terminal width is a parameter, not the terminal's.** ``rich`` wraps to
  whatever ``COLUMNS`` says, so an unpinned width makes the same finding render
  differently on two machines. The default is fixed and the caller may override
  it; nothing reads the environment.
* **Colour is off unless asked for.** ANSI escapes are for a human at a
  terminal, never for a file or a golden snapshot.
* **JSON is emitted through the pydantic model**, so it cannot drift from
  ``report.schema.json`` — which is generated from that same model and pinned by
  the schema-drift check.
* **Nothing here reads the clock.** ``Report.generated_at`` was injected before
  this module ever sees it (``core/models.py``).
"""

from __future__ import annotations

import io
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from keyreach.core.models import Severity
from keyreach.report.build import UNKNOWN_PROVIDER

if TYPE_CHECKING:
    from collections.abc import Sequence

    from keyreach.core.models import Report

#: Fixed render width. Wide enough for a service, an access level and a sentence
#: of detail without wrapping mid-word; narrow enough to paste into a ticket.
DEFAULT_WIDTH: Final = 100

#: Terminal colour per band. Only ever applied when the caller asks for colour,
#: so it can never reach a file or a golden snapshot.
_BAND_STYLE: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_TEMPLATES: Final = "templates"


class ReportFormat(StrEnum):
    """Output formats. Values are exactly what ``--report`` accepts in R1.5."""

    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "md"
    HTML = "html"


def status_label(report: Report) -> str:
    """What to print for "Status" — three answers, not two.

    ``ValidationResult.valid`` is a bool, so a key nothing ever asked about is
    indistinguishable from one a provider rejected. Those are very different
    claims to put in front of a security team: "we asked and it was refused"
    versus "we could not work out who to ask". The report knows the difference
    because ``build.py`` names the provider ``unknown`` in the second case.
    """
    if report.validation.valid:
        return "valid"
    if report.provider == UNKNOWN_PROVIDER:
        return "not probed"
    return "not valid"


def _environment() -> Environment:
    """The Jinja environment, built once per call and never mutated.

    ``StrictUndefined`` so a renamed model field fails loudly instead of
    rendering an empty cell into a disclosure report. Autoescaping is selected
    by extension rather than switched off wholesale: escaping Markdown would
    corrupt it, but ``report.html.j2`` must be escaped — a capability's
    evidence or detail can legitimately contain a vendor's raw JSON or an
    HTML error page a proxy returned, and this is what stops either from
    being interpreted as markup.
    """
    return Environment(
        loader=PackageLoader("keyreach.report", _TEMPLATES),
        autoescape=select_autoescape(
            enabled_extensions=("html", "html.j2", "xml"),
            default_for_string=False,
            default=False,
        ),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_json(report: Report) -> str:
    """Machine-readable output, conforming to ``report.schema.json``.

    Serialized by pydantic from the same model the schema is generated from, so
    the two cannot disagree — there is no hand-built dict to fall out of step.
    """
    return report.model_dump_json(indent=2) + "\n"


def render_markdown(report: Report) -> str:
    """The disclosure artifact: what gets pasted into a report or a ticket."""
    return (
        _environment()
        .get_template("report.md.j2")
        .render(report=report, status=status_label(report))
    )


def render_html(report: Report) -> str:
    """A self-contained HTML document: one finding, opened straight from disk.

    Every style rule is inlined in the template's ``<style>`` block — no
    external stylesheet, font, script or image — so the file this produces
    needs no network fetch to render correctly, matching the read-only spirit
    of ``plan.md`` §11 for the artifact itself, not only for the probes that
    fed it.
    """
    return (
        _environment()
        .get_template("report.html.j2")
        .render(report=report, status=status_label(report))
    )


def _capability_table(report: Report) -> Table:
    # Not `expand=True`: an expanded table stretches every column to fill the
    # width, which pads short cells with spaces that then differ from the
    # whitespace-trimmed golden file.
    table = Table(header_style="bold", show_lines=False)
    table.add_column("Service", no_wrap=True)
    table.add_column("Access", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    table.add_column("Flags", no_wrap=True)
    for capability in report.capabilities:
        flags = " ".join(
            label
            for label, present in (
                ("data", capability.data_sensitive),
                ("cost", capability.incurs_cost),
                ("restricted", capability.restricted),
            )
            if present
        )
        table.add_row(
            capability.service,
            capability.access.value,
            capability.detail,
            flags or "—",
        )
    return table


def _marked_list(
    console: Console, heading: str, rows: Sequence[tuple[str, str]]
) -> None:
    """A marker/text block whose continuation lines stay under the text.

    Printed through a grid rather than as ``"  • " + line``: rationale and
    remediation entries are full sentences, and plain wrapping returns the
    continuation to column zero, where it reads as a new item rather than as the
    rest of the one above it.
    """
    console.print(Text(heading, style="bold"))
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    for marker, text in rows:
        grid.add_row(f"  {marker}", text)
    console.print(grid)
    console.print()


def _bullets(console: Console, heading: str, lines: Sequence[str]) -> None:
    _marked_list(console, heading, [("•", line) for line in lines])


def render_terminal(
    report: Report,
    *,
    width: int = DEFAULT_WIDTH,
    color: bool = False,
) -> str:
    """The operator view: what keyreach prints after a run.

    Returns a string rather than writing to stdout so the same code path is what
    the golden tests compare. ``color`` defaults to off — the caller that has an
    actual terminal is the one that knows it has one.
    """
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=width,
        force_terminal=color,
        no_color=not color,
        # `highlight` would style numbers and URLs inside evidence strings
        # according to rich's own guesses; report text is not source code.
        highlight=False,
        # Not `soft_wrap`: wrapping must happen at the fixed width above, not at
        # whatever the receiving terminal happens to be.
        soft_wrap=False,
    )

    # The title goes in the body, not in the panel's title bar: a panel title
    # longer than the width is silently truncated, and truncating the one line
    # that states the finding is the worst thing this renderer could do.
    heading = Text(report.title, style="bold")
    heading.append("\n\n")
    heading.append(report.impact)
    console.print(
        Panel(
            heading,
            title=report.severity.value.upper(),
            title_align="left",
            border_style=_BAND_STYLE[report.severity] if color else "none",
        )
    )

    facts = Table.grid(padding=(0, 2))
    facts.add_column(style="bold", no_wrap=True)
    facts.add_column(overflow="fold")
    facts.add_row("Provider", f"{report.provider} ({report.provider_category})")
    facts.add_row("Key", report.key_fingerprint)
    facts.add_row("Status", status_label(report))
    facts.add_row("Generated", report.generated_at.isoformat())
    identity = report.validation.identity
    if identity is not None:
        for label, value in (
            ("Account", identity.account),
            ("Owner", identity.owner),
            ("Plan", identity.plan_or_tier),
        ):
            if value:
                facts.add_row(label, value)
        # Sorted: `extra` is a dict a provider plugin populated, and insertion
        # order is not a contract keyreach can rely on for stable output.
        for name in sorted(identity.extra):
            facts.add_row(name, identity.extra[name])
    if report.validation.note:
        facts.add_row("Note", report.validation.note)
    console.print(facts)
    console.print()

    if report.capabilities:
        console.print(Text("Capabilities", style="bold"))
        console.print(_capability_table(report))
        console.print()

    _bullets(console, "Why this severity", report.severity_rationale)

    if report.notes:
        _bullets(console, "Not determined", report.notes)

    steps = [
        (f"{index}.", step) for index, step in enumerate(report.remediation, start=1)
    ]
    links = [
        ("", f"{label}: {url}")
        for label, url in (
            ("Rotation guide", report.rotation_guide_url),
            ("Provider docs", report.docs_url),
        )
        if url
    ]
    if links:
        # A blank row, so the links do not read as a continuation of the last
        # numbered step they would otherwise sit directly beneath.
        steps.append(("", ""))
        steps.extend(links)
    _marked_list(console, "Remediation", steps)

    console.print(
        Text(
            f"{report.tool} {report.tool_version} · schema "
            f"{report.schema_version} · deterministic, read-only, no AI",
            style="dim",
        )
    )
    return _trim(buffer.getvalue(), color=color)


def _trim(rendered: str, *, color: bool) -> str:
    """Strip trailing spaces from every line of plain output.

    ``rich`` pads grid and table cells to their column width, leaving trailing
    spaces that carry no information. They matter for two reasons: the repo's
    ``trailing-whitespace`` pre-commit hook would rewrite any golden file
    containing them, making the snapshot disagree with the renderer forever, and
    a report pasted into a ticket should not arrive full of invisible padding.

    Only when colour is off. With colour on, a trailing run of spaces is what
    paints a background style to the edge of a panel, so stripping it would
    visibly break the output — and coloured output goes to a live terminal, not
    to a file or a snapshot.
    """
    if color:
        return rendered
    return "\n".join(line.rstrip() for line in rendered.split("\n"))


def render(
    report: Report,
    fmt: ReportFormat = ReportFormat.TERMINAL,
    *,
    width: int = DEFAULT_WIDTH,
    color: bool = False,
) -> str:
    """Render ``report`` in ``fmt``. The single entry point R1.5's CLI calls."""
    if fmt is ReportFormat.JSON:
        return render_json(report)
    if fmt is ReportFormat.MARKDOWN:
        return render_markdown(report)
    if fmt is ReportFormat.HTML:
        return render_html(report)
    return render_terminal(report, width=width, color=color)
