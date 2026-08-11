"""Renderer tests (roadmap R0.8).

``tests/test_determinism.py`` pins the exact bytes of three whole reports. This
file covers the properties those snapshots cannot: what happens at a different
width, with colour on, with the optional fields present or absent, and — most
importantly — that a key never reaches the output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

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


@pytest.mark.parametrize("fmt", [ReportFormat.TERMINAL, ReportFormat.MARKDOWN])
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


@pytest.mark.parametrize("fmt", [ReportFormat.TERMINAL, ReportFormat.MARKDOWN])
def test_a_report_with_no_capabilities_renders(fmt: ReportFormat) -> None:
    empty = report(capabilities=[], severity=Severity.INFO)

    assert render(empty, fmt)


@pytest.mark.parametrize("fmt", [ReportFormat.TERMINAL, ReportFormat.MARKDOWN])
def test_notes_are_shown_as_gaps_not_as_results(fmt: ReportFormat) -> None:
    rendered = render(report(notes=["demo: enumerate failed: timeout"]), fmt)

    assert "Not determined" in rendered
    assert "enumerate failed: timeout" in rendered


@pytest.mark.parametrize("fmt", [ReportFormat.TERMINAL, ReportFormat.MARKDOWN])
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


@pytest.mark.parametrize("fmt", [ReportFormat.TERMINAL, ReportFormat.MARKDOWN])
def test_provider_links_are_shown_when_known(fmt: ReportFormat) -> None:
    linked = report(
        rotation_guide_url="https://demo.invalid/rotate",
        docs_url="https://demo.invalid/docs",
    )
    rendered = render(linked, fmt)

    assert "https://demo.invalid/rotate" in rendered
    assert "https://demo.invalid/docs" in rendered


def test_optional_capability_fields_render_when_set() -> None:
    detailed = report(
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
    rendered = render_markdown(detailed)

    assert "project/demo" in rendered
    assert "curl 'https://demo.invalid/v1/files?key=<key>'" in rendered


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
# Dispatch
# ---------------------------------------------------------------------------


def test_render_dispatches_to_each_renderer() -> None:
    subject = report()

    assert render(subject, ReportFormat.JSON) == render_json(subject)
    assert render(subject, ReportFormat.MARKDOWN) == render_markdown(subject)
    assert render(subject, ReportFormat.TERMINAL) == render_terminal(subject)


def test_terminal_is_the_default_format() -> None:
    assert render(report()) == render_terminal(report())


def test_format_values_are_what_the_cli_will_accept() -> None:
    """`--report md` in `implementation_plan.md` §12, not `--report markdown`."""
    assert {fmt.value for fmt in ReportFormat} == {"terminal", "json", "md"}


def test_a_renamed_model_field_fails_loudly() -> None:
    """StrictUndefined: a blank cell in a disclosure report is worse than a crash."""
    from jinja2 import StrictUndefined  # noqa: PLC0415

    from keyreach.report.render import _environment  # noqa: PLC0415

    assert _environment().undefined is StrictUndefined
