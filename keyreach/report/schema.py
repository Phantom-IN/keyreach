"""Generate ``report.schema.json`` from the pydantic ``Report`` model.

The checked-in schema is keyreach's published contract for ``--json`` output.
It is generated, never hand-edited, so it cannot drift from the model that
actually produces reports (``implementation_plan.md`` §9).

Regenerate after any change to the models::

    python -m keyreach.report.schema --write

Verify without writing — this is what the schema drift check runs (roadmap
R0.9, ``implementation_plan.md`` §11)::

    python -m keyreach.report.schema --check

``tests/test_report_schema.py`` asserts the same thing, so the drift is caught
by ``pytest`` today and by CI once R0.9 lands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from keyreach.core.models import Report

#: The checked-in schema. Ships inside the package so a consumer can validate
#: `--json` output against the exact version of keyreach that produced it.
SCHEMA_PATH = Path(__file__).parent / "report.schema.json"

#: Trailing newline included: POSIX text files end with one, and without it
#: every editor and pre-commit's end-of-file-fixer would fight the generator.
_TRAILING_NEWLINE = "\n"


def build_schema() -> dict[str, Any]:
    """Build the JSON Schema document for ``Report``.

    Deterministic by construction: pydantic derives the schema from the model
    definition alone — no clock, no environment, no dict ordering surprises —
    so the same model always yields the same document.
    """
    schema: dict[str, Any] = Report.model_json_schema(
        # Referenced definitions keep nested models (Capability, Identity,
        # ValidationResult) as named `$defs` entries rather than inlining them
        # at each use site. Consumers get stable, referenceable type names, and
        # the diff on a model change stays small and readable.
        ref_template="#/$defs/{model}",
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://raw.githubusercontent.com/Phantom-IN/keyreach/main/"
        "keyreach/report/report.schema.json"
    )
    return schema


def render_schema() -> str:
    """Render the schema to its exact on-disk bytes.

    ``sort_keys`` is deliberately off. pydantic emits properties in model
    declaration order, which mirrors the nine required report contents in
    ``plan.md`` §7 and makes the file readable; sorting alphabetically would
    scatter that for no determinism gain, since the order is already a pure
    function of the model.
    """
    return json.dumps(build_schema(), indent=2, ensure_ascii=False) + _TRAILING_NEWLINE


def _resolve(path: Path | None) -> Path:
    """Resolve the target path, reading ``SCHEMA_PATH`` at call time.

    Deliberately not ``path: Path = SCHEMA_PATH``. A default argument binds at
    import time, which would make the module-level constant look overridable
    while silently ignoring any later change to it — including the one tests
    make to avoid writing to the real checked-in schema.
    """
    return SCHEMA_PATH if path is None else path


def write_schema(path: Path | None = None) -> bool:
    """Write the schema. Returns ``True`` if the file changed."""
    target = _resolve(path)
    rendered = render_schema()
    if target.exists() and target.read_text(encoding="utf-8") == rendered:
        return False
    target.write_text(rendered, encoding="utf-8")
    return True


def check_schema(path: Path | None = None) -> bool:
    """Return ``True`` if the checked-in schema matches the current models."""
    target = _resolve(path)
    if not target.exists():
        return False
    return target.read_text(encoding="utf-8") == render_schema()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--write", action="store_true", help="Regenerate report.schema.json."
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the checked-in schema is stale.",
    )
    args = parser.parse_args(argv)

    if args.write:
        changed = write_schema()
        print(  # noqa: T201 — a maintenance script; rich is for user-facing output
            f"{'updated' if changed else 'unchanged'}: {SCHEMA_PATH}"
        )
        return 0

    if check_schema():
        print(f"up to date: {SCHEMA_PATH}")  # noqa: T201
        return 0

    print(  # noqa: T201
        f"STALE: {SCHEMA_PATH} does not match the models.\n"
        "Run: python -m keyreach.report.schema --write",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
