"""keyreach — map what an exposed API key can actually reach.

keyreach takes a single API key that has already been found (it is *not* a
secret scanner) and answers the only question that determines a finding's
value: what can this key actually do? It detects the provider by rule,
confirms liveness and identity, enumerates reachable services with read-only
probes, computes a severity band from the confirmed capabilities, and emits a
disclosure-ready report.

Three constraints shape every line of this package (``plan.md`` §1):

* **Deterministic and rule-based — no AI/LLM, ever.** Same key plus same
  provider responses must always produce the same report. Anything a rule
  cannot decide is reported as unknown, never guessed.
* **Read-only by default.** No writes, deletes, or spend.
* **Keys masked by default**, everywhere: output, logs, evidence, fixtures.

See ``plan.md`` for scope and ``implementation_plan.md`` for architecture.
"""

from __future__ import annotations

__all__ = ["__version__"]

# Single source of truth for the version. ``pyproject.toml`` reads this value at
# build time via hatchling (``[tool.hatch.version]``), so the CLI's ``--version``
# and the installed distribution metadata cannot drift apart.
#
# This is a ``.dev`` release: the PyPI name is reserved, but ``pip install
# keyreach`` deliberately resolves nothing, because there is nothing worth
# installing yet. The first real release is ``0.1.0`` — roadmap item R1.6.
__version__ = "0.1.0.dev0"
