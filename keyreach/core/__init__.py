"""keyreach core: the deterministic machinery behind the pipeline.

``detect → validate → enumerate → score → report``

Everything nondeterministic — network I/O, the clock, concurrency — is confined
to the engine and HTTP layer (``implementation_plan.md`` §6). Detection,
scoring, and report rendering are pure functions of their inputs, which is what
makes the same key against the same provider state reproduce the same report.

Landed so far: ``models.py`` (roadmap R0.3). The rest arrives one item at a
time — ``provider.py`` and ``registry.py`` in R0.4, ``detect.py`` in R0.5,
``engine.py`` and ``http.py`` in R0.6, ``scoring.py`` in R0.7.
"""

from __future__ import annotations
