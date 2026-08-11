"""keyreach core: the deterministic machinery behind the pipeline.

``detect → validate → enumerate → score → report``

Everything nondeterministic — network I/O, the clock, concurrency — is confined
to the engine and HTTP layer (``implementation_plan.md`` §6). Detection,
scoring, and report rendering are pure functions of their inputs, which is what
makes the same key against the same provider state reproduce the same report.

Landed so far: ``models.py`` (roadmap R0.3), ``provider.py`` and ``registry.py``
(R0.4), ``detect.py`` (R0.5), ``engine.py`` and ``http.py`` (R0.6), and
``scoring.py`` (R0.7). Report rendering follows in R0.8.
"""

from __future__ import annotations
