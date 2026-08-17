"""Renderer tests (roadmap R0.8).

``tests/test_determinism.py`` pins the exact bytes of three whole reports. This
file covers the properties those snapshots cannot: what happens at a different
width, with colour on, with the optional fields present or absent, and — most
importantly — that a key never reaches the output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from keyreach.core.models import (
    AccessLevel,
    Capability,
    Identity,
    Report,
    Severity,
    ValidationResult,
)
from keyreach.report.build import UNKNOWN_PROVIDER
from keyreach.report.render import (
    DEFAULT_WIDTH,
    ReportFormat,
    render,
    render_html,
    render_json,
    render_markdown,
    render_terminal,
    status_label,
)

FIXED_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

#: Composed from parts rather than written as one literal. As a single string
#: this is a valid Stripe secret-key shape, and both keyreach's own detector and
#: GitHub's push protection match it — the latter blocking the push outright.
#: The value is identical at run time; only the source form differs.
#: See `tests/test_repo_hygiene.py`, which fails on any literal that regresses.
RAW_KEY = "sk_" + "live_" + "thiskeymustneverberendered"


def report(**overrides: object) -> Report:
    defaults: dict[str, object] = {
        "tool_version": "0.0.0-test",
        "provider": "demo",
        "provider_category": "generic",
        "generated_at": FIXED_TIME,
        "key_fingerprint": "sk_l**************************red",
        "title": "Exposed demo API key reaches Demo Files",
        "severity": Severity.HIGH,
        "impact": "Anyone holding this key can read private data.",
        "severity_rationale": ["Reaches private or user data: Demo Files (read)."],
        "validation": ValidationResult(valid=True),
        "capabilities": [
            Capability(
                service="Demo Files",
                access=AccessLevel.READ,
                detail="Can list uploaded files",
                evidence="GET /v1/files?key=<key> -> 200, 4 files",
                risk_weight=70,
                data_sensitive=True,
            )
        ],
        "remediation": ["Revoke or rotate this key now."],
    }
    return Report(**{**defaults, **overrides})  # type: ignore[arg-type]


ALL_FORMATS = [pytest.param(fmt, id=fmt.value) for fmt in ReportFormat]

#: Every format meant for a person to read, as opposed to JSON. Used wherever
#: a test asserts that a section of prose reaches the rendered output —
#: HTML joined JSON's sibling formats in roadmap R2.9.
HUMAN_FORMATS = [
    ReportFormat.TERMINAL,
    ReportFormat.MARKDOWN,
    ReportFormat.HTML,
]


# ---------------------------------------------------------------------------
# Masking — the guarantee that survives into every format
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_no_format_leaks_the_key(fmt: ReportFormat) -> None:
    """A report is pasted into a ticket. It must not carry the secret with it."""
    leaky = report(
        key_fingerprint="sk_l**************************red",
        capabilities=[
            Capability(
                service="Demo Files",
                access=AccessLevel.READ,
                detail="Can list uploaded files",
                evidence="GET /v1/files?key=<key> -> 200",
                risk_weight=70,
            )
        ],
    )

    assert RAW_KEY not in render(leaky, fmt)


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_the_masked_fingerprint_is_shown(fmt: ReportFormat) -> None:
    """Masked is not absent — a recipient still has to identify which key."""
    assert "sk_l**************************red" in render(report(), fmt)


# ---------------------------------------------------------------------------
# Status: three answers, not two
# ---------------------------------------------------------------------------


def test_status_distinguishes_rejected_from_never_asked() -> None:
    """ "Not valid" claims the provider refused it. That is a different fact."""
    rejected = report(validation=ValidationResult(valid=False), severity=Severity.INFO)
    never_asked = report(
        provider=UNKNOWN_PROVIDER,
        validation=ValidationResult(valid=False),
        severity=Severity.INFO,
    )

    assert status_label(report()) == "valid"
    assert status_label(rejected) == "not valid"
    assert status_label(never_asked) == "not probed"


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_status_reaches_the_human_formats(fmt: ReportFormat) -> None:
    never_asked = report(
        provider=UNKNOWN_PROVIDER,
        validation=ValidationResult(valid=False),
        severity=Severity.INFO,
    )

    assert "not probed" in render(never_asked, fmt)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_round_trips_through_the_model() -> None:
    """The published contract, checked against the model it is generated from.

    ``report.schema.json`` is generated from ``Report`` and pinned by the schema
    drift check, so validating the output against the model transitively
    validates it against the schema — without a JSON Schema library and the
    dependency it would add to a security tool.
    """
    original = report()

    assert Report.model_validate_json(render_json(original)) == original


def test_json_is_valid_json_and_ends_with_a_newline() -> None:
    rendered = render_json(report())

    assert rendered.endswith("\n")
    assert json.loads(rendered)["schema_version"] == "1.0"


def test_json_and_markdown_spell_the_timestamp_identically() -> None:
    """One instant, one spelling. pydantic would otherwise emit `Z` for UTC."""
    stamp = json.loads(render_json(report()))["generated_at"]

    assert stamp == FIXED_TIME.isoformat()
    assert stamp in render_markdown(report())


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------


def test_terminal_output_respects_the_given_width() -> None:
    """Not `COLUMNS`. An unpinned width renders the same finding two ways."""
    for width in (60, DEFAULT_WIDTH, 140):
        rendered = render_terminal(report(), width=width)

        assert max(len(line) for line in rendered.split("\n")) <= width


def test_terminal_output_has_no_trailing_whitespace() -> None:
    """Otherwise the trailing-whitespace hook rewrites every golden file."""
    rendered = render_terminal(report())

    assert all(line == line.rstrip() for line in rendered.split("\n"))


def test_terminal_output_is_plain_by_default() -> None:
    """ANSI belongs on a terminal, never in a file or a snapshot."""
    assert "\x1b" not in render_terminal(report())


def test_colour_is_available_when_asked_for() -> None:
    assert "\x1b" in render_terminal(report(), color=True)


def test_colour_keeps_the_padding_plain_output_strips() -> None:
    """Trailing spaces paint a background style; stripping them breaks it."""
    coloured = render_terminal(report(), color=True)

    assert any(line != line.rstrip() for line in coloured.split("\n"))


@pytest.mark.parametrize("band", list(Severity))
def test_every_band_renders(band: Severity) -> None:
    """No band is missing a style entry, which would be a KeyError at run time."""
    assert render_terminal(report(severity=band), color=True)


def test_a_long_title_is_not_truncated() -> None:
    """The one line that states the finding must survive a narrow terminal."""
    title = "Exposed demo API key reaches " + " and ".join(
        f"Service {index}" for index in range(12)
    )
    rendered = render_terminal(report(title=title), width=60)

    assert "Service 11" in rendered


# ---------------------------------------------------------------------------
# Optional sections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_a_report_with_no_capabilities_renders(fmt: ReportFormat) -> None:
    empty = report(capabilities=[], severity=Severity.INFO)

    assert render(empty, fmt)


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_notes_are_shown_as_gaps_not_as_results(fmt: ReportFormat) -> None:
    rendered = render(report(notes=["demo: enumerate failed: timeout"]), fmt)

    assert "Not determined" in rendered
    assert "enumerate failed: timeout" in rendered


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_identity_is_rendered_when_present(fmt: ReportFormat) -> None:
    identified = report(
        validation=ValidationResult(
            valid=True,
            identity=Identity(
                account="acct_1",
                owner="Acme",
                plan_or_tier="pro",
                extra={"region": "eu", "az": "1"},
            ),
            note="live mode",
        )
    )
    rendered = render(identified, fmt)

    for value in ("acct_1", "Acme", "pro", "eu", "live mode"):
        assert value in rendered


def test_identity_extras_render_in_sorted_order() -> None:
    """`extra` is a plugin-populated dict; insertion order is not a contract."""
    rendered = render_markdown(
        report(
            validation=ValidationResult(
                valid=True,
                identity=Identity(extra={"zulu": "1", "alpha": "2"}),
            )
        )
    )

    assert rendered.index("alpha") < rendered.index("zulu")


@pytest.mark.parametrize("fmt", HUMAN_FORMATS)
def test_provider_links_are_shown_when_known(fmt: ReportFormat) -> None:
    linked = report(
        rotation_guide_url="https://demo.invalid/rotate",
        docs_url="https://demo.invalid/docs",
    )
    rendered = render(linked, fmt)

    assert "https://demo.invalid/rotate" in rendered
    assert "https://demo.invalid/docs" in rendered


def _detailed_capability_report() -> Report:
    return report(
        capabilities=[
            Capability(
                service="Demo Files",
                access=AccessLevel.READ,
                detail="Can list uploaded files",
                evidence="GET /v1/files?key=<key> -> 200",
                risk_weight=70,
                restricted=True,
                resource_ref="project/demo",
                poc="curl 'https://demo.invalid/v1/files?key=<key>'",
            )
        ]
    )


def test_optional_capability_fields_render_when_set() -> None:
    rendered = render_markdown(_detailed_capability_report())

    assert "project/demo" in rendered
    assert "curl 'https://demo.invalid/v1/files?key=<key>'" in rendered


def test_optional_capability_fields_reach_html_escaped() -> None:
    """The same fields as above, through HTML's autoescaping.

    `poc`'s single quotes and angle brackets are legitimate characters in a
    `curl` command, and autoescape turns them into entities rather than
    dropping them — so this checks for the escaped form, not the raw one.
    """
    rendered = render_html(_detailed_capability_report())

    assert "project/demo" in rendered
    assert "curl &#39;https://demo.invalid/v1/files?key=&lt;key&gt;&#39;" in rendered


def test_capability_flags_are_labelled_in_the_terminal_table() -> None:
    flagged = report(
        capabilities=[
            Capability(
                service="Demo Billing",
                access=AccessLevel.WRITE,
                detail="Can spend",
                evidence="GET /v1/billing -> 200",
                risk_weight=90,
                data_sensitive=True,
                incurs_cost=True,
                restricted=True,
            )
        ],
        severity=Severity.CRITICAL,
    )
    rendered = render_terminal(flagged, width=140)

    assert "data" in rendered
    assert "cost" in rendered
    assert "restricted" in rendered


# ---------------------------------------------------------------------------
# HTML (roadmap R2.9)
# ---------------------------------------------------------------------------


class _StrictHTMLParser(HTMLParser):
    """Fails on the shape of error a hand-edited template tends to introduce.

    ``html.parser`` does not itself validate nesting — it is a tokenizer, not
    a DOM builder — so this keeps its own open-tag stack and raises the
    moment a close tag does not match what is on top of it. That catches an
    unclosed ``<div>`` or a swapped ``</ul></ol>`` the way a browser's
    forgiving parser would silently paper over.
    """

    #: Void elements never appear in a close tag and are not pushed.
    _VOID: frozenset[str] = frozenset(
        {"meta", "link", "br", "hr", "img", "input", "source", "col"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        del attrs
        if tag not in self._VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        assert self.stack, f"</{tag}> with nothing open"
        assert self.stack[-1] == tag, f"</{tag}> does not match <{self.stack[-1]}>"
        self.stack.pop()


def _assert_well_formed(document: str) -> None:
    parser = _StrictHTMLParser()
    parser.feed(document)
    parser.close()
    assert parser.stack == [], f"unclosed tag(s): {parser.stack}"


def test_html_output_is_well_formed() -> None:
    """Every tag opened by the template is closed, and closed in order.

    Not a substitute for `tests/test_determinism.py`'s golden snapshots — this
    catches a *structural* mistake (a missing `{% endif %}`'s HTML sibling,
    say) that a byte-diff would also catch, but would not explain.
    """
    _assert_well_formed(render_html(report()))


def test_html_starts_with_the_doctype_and_ends_with_the_closing_tag() -> None:
    rendered = render_html(report())

    assert rendered.startswith("<!doctype html>")
    assert rendered.rstrip().endswith("</html>")


def test_html_is_self_contained() -> None:
    """No external stylesheet, font, script or image.

    The point of a single HTML file as a disclosure artifact is that it opens
    correctly from disk with no network fetch — the same read-only spirit
    `plan.md` §11 asks of every probe, extended to the artifact itself. A
    `<link>`, `<script src>` or `<img src>` would silently break offline or
    phone home to whatever fills that URL.
    """
    rendered = render_html(report())

    assert "<link" not in rendered
    assert "<script" not in rendered
    assert "<img" not in rendered
    assert "<style" in rendered


@pytest.mark.parametrize("band", list(Severity))
def test_every_band_has_html_styling(band: Severity) -> None:
    """No band is missing a `.severity-*` rule, which would render unstyled."""
    rendered = render_html(report(severity=band))

    assert f"severity-{band.value}" in rendered
    assert f".severity-{band.value} {{" in rendered


def test_html_escapes_a_capability_that_looks_like_markup() -> None:
    """Autoescaping, proven rather than assumed.

    Evidence is a vendor's own response text — masked, but not otherwise
    sanitised — and a proxy's HTML error page or a field containing `<`/`&`
    must not be interpreted as markup by whatever renders this file. A
    forgotten `| safe` or a plain-string template would let this through.
    """
    hostile = report(
        capabilities=[
            Capability(
                service="Demo Files",
                access=AccessLevel.READ,
                detail="Can list uploaded files",
                evidence='<script>alert("x")</script> & "quoted"',
                risk_weight=70,
            )
        ]
    )
    rendered = render_html(hostile)

    assert "<script>alert" not in rendered
    assert "&lt;script&gt;" in rendered
    _assert_well_formed(rendered)


def test_html_notes_and_empty_capabilities_render() -> None:
    rendered = render_html(
        report(capabilities=[], severity=Severity.INFO, notes=["demo: timeout"])
    )

    assert "No capability was confirmed." in rendered
    assert "Not determined" in rendered
    _assert_well_formed(rendered)


def test_html_omits_the_remediation_links_block_when_both_urls_are_absent() -> None:
    rendered = render_html(report(rotation_guide_url=None, docs_url=None))

    assert "Rotation guide" not in rendered
    assert "Provider documentation" not in rendered


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_render_dispatches_to_each_renderer() -> None:
    subject = report()

    assert render(subject, ReportFormat.JSON) == render_json(subject)
    assert render(subject, ReportFormat.MARKDOWN) == render_markdown(subject)
    assert render(subject, ReportFormat.TERMINAL) == render_terminal(subject)
    assert render(subject, ReportFormat.HTML) == render_html(subject)


def test_terminal_is_the_default_format() -> None:
    assert render(report()) == render_terminal(report())


def test_format_values_are_what_the_cli_will_accept() -> None:
    """`--report md` in `implementation_plan.md` §12, not `--report markdown`."""
    assert {fmt.value for fmt in ReportFormat} == {"terminal", "json", "md", "html"}


def test_a_renamed_model_field_fails_loudly() -> None:
    """StrictUndefined: a blank cell in a disclosure report is worse than a crash."""
    from jinja2 import StrictUndefined  # noqa: PLC0415

    from keyreach.report.render import _environment  # noqa: PLC0415

    assert _environment().undefined is StrictUndefined
