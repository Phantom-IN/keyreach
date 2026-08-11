"""Rewrite the snapshots under ``tests/golden/``.

    python -m tests.regenerate_goldens

Deliberately a separate entrypoint from the test suite, mirroring
``python -m keyreach.report.schema --write``: a snapshot is a checked-in
expectation, and updating one should be a decision that shows up in a diff, not
something ``pytest`` does on its way past.

When a golden changes, read the diff before committing it. A report is what a
security team receives; a change here is a change to the deliverable.
"""

from __future__ import annotations

import sys

from tests.goldens import GOLDEN_DIR, expected


def main() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    changed = []
    for path, content in sorted(expected().items()):
        if path.exists() and path.read_text(encoding="utf-8") == content:
            continue
        path.write_text(content, encoding="utf-8")
        changed.append(path)

    if not changed:
        print("goldens unchanged")  # noqa: T201 — a maintenance script
        return 0

    for path in changed:
        print(f"updated: {path}")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
