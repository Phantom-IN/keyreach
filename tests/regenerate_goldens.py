"""Rewrite — or verify — the snapshots under ``tests/golden/``.

    python -m tests.regenerate_goldens            # rewrite
    python -m tests.regenerate_goldens --check    # exit non-zero if stale

Deliberately a separate entrypoint from the test suite, mirroring
``python -m keyreach.report.schema --write``: a snapshot is a checked-in
expectation, and updating one should show up in a diff rather than happen as a
side effect of ``pytest``.

``--check`` is what CI runs. Both checked-in artifacts — the JSON Schema and
these reports — are generated from code and must not drift from it, so both are
verified the same way.

When a golden changes, read the diff before committing. A report is what a
security team receives; a change here is a change to the deliverable.
"""

from __future__ import annotations

import argparse
import sys

from tests.goldens import GOLDEN_DIR, expected, stale
from tools.guardrails.base import REPO_ROOT


def write() -> list[str]:
    """Rewrite any stale golden. Returns the paths that changed."""
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    changed = []
    for path, content in sorted(expected().items()):
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        path.write_text(content, encoding="utf-8")
        changed.append(str(path))
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.regenerate_goldens")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any golden is stale, without writing.",
    )
    args = parser.parse_args(argv)

    if args.check:
        drifted = stale()
        if not drifted:
            print("goldens up to date")  # noqa: T201 - a maintenance script
            return 0
        for stale_path in drifted:
            # Repo-relative: GitHub only attaches an annotation to a line in the
            # diff when the path is relative to the workspace root.
            print(  # noqa: T201
                f"::error file={stale_path.relative_to(REPO_ROOT)},line=1::"
                "golden is stale; run python -m tests.regenerate_goldens"
            )
        print(  # noqa: T201
            f"\nSTALE: {len(drifted)} golden file(s) do not match the "
            "renderers.\nRun: python -m tests.regenerate_goldens",
            file=sys.stderr,
        )
        return 1

    changed = write()
    if not changed:
        print("goldens unchanged")  # noqa: T201
        return 0
    for path in changed:
        print(f"updated: {path}")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
