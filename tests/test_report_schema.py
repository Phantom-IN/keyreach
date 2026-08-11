"""Report schema tests (roadmap R0.3).

Covers the second half of R0.3's acceptance criterion — "schema is generated
deterministically" — plus the drift guard that keeps the checked-in
``report.schema.json`` honest.

``test_checked_in_schema_matches_the_models`` is the schema-drift check from
``implementation_plan.md`` §11. It runs under ``pytest`` today; roadmap item
**R0.9** wires the same assertion into CI as a dedicated job.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from keyreach.core.models import Report
from keyreach.report.schema import (
    SCHEMA_PATH,
    build_schema,
    check_schema,
    main,
    render_schema,
    write_schema,
)


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return data


# --------------------------------------------------------------------------
# Determinism and drift
# --------------------------------------------------------------------------


def test_schema_generation_is_byte_identical_across_runs() -> None:
    """R0.3 acceptance: the schema is generated deterministically."""
    assert render_schema() == render_schema()


def test_checked_in_schema_matches_the_models() -> None:
    """The schema-drift check (implementation_plan.md §11).

    If this fails, someone changed a model without regenerating the published
    contract. Fix it by running::

        python -m keyreach.report.schema --write

    and committing the result in the same PR as the model change.
    """
    assert check_schema(), (
        f"{SCHEMA_PATH} is stale. " "Run: python -m keyreach.report.schema --write"
    )


def test_schema_file_ends_with_a_single_trailing_newline() -> None:
    """Otherwise the generator and pre-commit's end-of-file-fixer fight."""
    text = SCHEMA_PATH.read_text(encoding="utf-8")

    assert text.endswith("\n")
    assert not text.endswith("\n\n")


# --------------------------------------------------------------------------
# Contract shape
# --------------------------------------------------------------------------


def test_schema_declares_its_dialect_and_id(schema: dict[str, Any]) -> None:
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].endswith("keyreach/report/report.schema.json")


def test_schema_defines_every_nested_model(schema: dict[str, Any]) -> None:
    """Nested models stay named $defs so consumers get referenceable types."""
    assert set(schema["$defs"]) == {
        "AccessLevel",
        "Capability",
        "Identity",
        "Severity",
        "ValidationResult",
    }


def test_schema_covers_all_nine_required_report_contents(
    schema: dict[str, Any],
) -> None:
    """plan.md §7 lists nine things every report must contain."""
    properties = schema["properties"]
    required_contents = {
        "title": "title",
        "severity": "severity",
        "impact": "impact",
        "masked key": "key_fingerprint",
        "provider": "provider",
        "category": "provider_category",
        "timestamp": "generated_at",
        "validity and identity": "validation",
        "capability map and evidence": "capabilities",
        "severity rationale": "severity_rationale",
        "remediation": "remediation",
        "attribution": "tool_version",
    }
    missing = {
        content: field
        for content, field in required_contents.items()
        if field not in properties
    }

    assert not missing, f"report schema is missing: {missing}"


def test_schema_forbids_additional_properties(schema: dict[str, Any]) -> None:
    """A closed schema turns a typo'd field into an error, not a silent drop."""
    assert schema["additionalProperties"] is False
    for name, definition in schema["$defs"].items():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False, name


def test_schema_pins_the_severity_bands(schema: dict[str, Any]) -> None:
    assert schema["$defs"]["Severity"]["enum"] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_schema_pins_the_access_levels(schema: dict[str, Any]) -> None:
    assert schema["$defs"]["AccessLevel"]["enum"] == [
        "read",
        "write",
        "admin",
        "unknown",
    ]


def test_schema_constrains_risk_weight_to_0_to_100(schema: dict[str, Any]) -> None:
    risk_weight = schema["$defs"]["Capability"]["properties"]["risk_weight"]

    assert risk_weight["minimum"] == 0
    assert risk_weight["maximum"] == 100


def test_schema_descriptions_are_consumer_facing(schema: dict[str, Any]) -> None:
    """Internal design rationale must not leak into the published contract.

    Descriptions come from ``_config(...)`` and ``Field(description=...)``,
    never from class docstrings — which reference ``plan.md`` sections and use
    RST markup that means nothing to an external consumer, and which would make
    a reworded docstring look like a breaking schema change.
    """
    definitions = [schema, *schema["$defs"].values()]
    leaking = [
        definition.get("title", "<root>")
        for definition in definitions
        if "plan.md" in str(definition.get("description", ""))
        or "``" in str(definition.get("description", ""))
    ]

    assert not leaking, f"internal documentation leaked into the schema: {leaking}"


def test_every_report_field_is_documented(schema: dict[str, Any]) -> None:
    """The schema is a published contract; an undocumented field is a gap."""
    undocumented = [
        name
        for name, definition in schema["properties"].items()
        if not definition.get("description")
    ]

    assert not undocumented, f"undocumented report fields: {undocumented}"


def test_build_schema_matches_the_model_directly(schema: dict[str, Any]) -> None:
    """Guards the generator itself against drifting from Report."""
    built = build_schema()

    assert built["properties"].keys() == Report.model_fields.keys()
    assert built["properties"].keys() == schema["properties"].keys()


# --------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------


def test_check_mode_passes_against_the_checked_in_schema(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out


def test_check_mode_reports_a_stale_schema(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale schema must fail loudly, with the fix in the message."""
    stale = tmp_path / "report.schema.json"
    stale.write_text('{"stale": true}\n', encoding="utf-8")
    monkeypatch.setattr("keyreach.report.schema.SCHEMA_PATH", stale)

    assert main(["--check"]) == 1
    assert "--write" in capsys.readouterr().err


def test_check_mode_reports_a_missing_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "keyreach.report.schema.SCHEMA_PATH", tmp_path / "does-not-exist.json"
    )

    assert main(["--check"]) == 1


def test_write_mode_is_idempotent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "report.schema.json"
    monkeypatch.setattr("keyreach.report.schema.SCHEMA_PATH", target)

    assert main(["--write"]) == 0
    assert "updated" in capsys.readouterr().out

    assert main(["--write"]) == 0
    assert "unchanged" in capsys.readouterr().out


def test_module_level_schema_path_is_honoured_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SCHEMA_PATH must be overridable, not frozen into a default argument.

    Binding it as a default would make every helper write to the real
    checked-in schema regardless of the module attribute — quietly, and in
    tests most of all.
    """
    target = tmp_path / "report.schema.json"
    monkeypatch.setattr("keyreach.report.schema.SCHEMA_PATH", target)

    assert write_schema() is True
    assert target.exists()
    assert check_schema() is True


def test_cli_requires_a_mode() -> None:
    with pytest.raises(SystemExit):
        main([])
