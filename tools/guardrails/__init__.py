"""The checks that enforce keyreach's hard rules (``implementation_plan.md`` §11).

Each module exposes ``check() -> list[Violation]`` and a ``main()`` returning an
exit code, so every one runs three ways from a single implementation: as a CI
job, as a pre-commit hook, and as a pytest assertion. Run them all with::

    python -m tools.guardrails

The registry of checks lives in ``__main__`` rather than here, so there is one
list to keep current instead of two that can disagree.

The rules these enforce are in ``plan.md`` §1 and §11 and in ``CLAUDE.md``'s hard
rules. Weakening one is not a refactor — it is a change to what keyreach
promises, and belongs in a pull request that says so.
"""

from __future__ import annotations
