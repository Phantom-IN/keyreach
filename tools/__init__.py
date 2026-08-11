"""Development tooling. Not shipped — `[tool.hatch.build]` packages `keyreach` only.

These are the checks that enforce keyreach's hard rules
(``implementation_plan.md`` §11). They live outside the distributed package
because they are repository discipline, not tool functionality: a user
installing keyreach gets a key analyser, not a linter.
"""

from __future__ import annotations
