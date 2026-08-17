"""The drift canary (roadmap R2.10, ``implementation_plan.md`` §10, §13.3).

Every provider plugin encodes two claims about a vendor that keyreach itself
does not control: a **detection rule** says a key format is still documented
the way ``keyreach/patterns/detection_rules.yml``'s ``source`` field claims,
and a **probe** says an endpoint still exists and still means what its
``detail`` says. R2.3 (Mailgun) and R2.4 (npm, GitLab) found both claims can
go stale without any of keyreach's own tests noticing, because no test opens
a vendor's website — that is what makes re-verification a maintenance
problem rather than a one-time cost at authoring (§13.2). This package is the
scheduled check that does, run by ``.github/workflows/drift-canary.yml``
rather than by ``pytest``. Its findings depend on the live Internet, so they
are not reproducible the way everything under ``keyreach/`` is required to
be — that is the point of a canary rather than a bug in one; see
``tools/drift_canary/base.py`` for why that puts it outside the
determinism and ``ProbeContext`` rules ``CLAUDE.md`` states for plugins.

Two checks, matching ``implementation_plan.md`` §13.3's specification for
what R2.10 has to verify:

* :mod:`tools.drift_canary.sources` — every active rule in
  ``detection_rules.yml`` still resolves at its cited ``source``, and that
  page still documents the format the rule claims (a best-effort, literal
  reading of the pattern's fixed prefix; see the module docstring for
  exactly what it can and cannot extract, and why that is a drawn boundary
  rather than an oversight).
* :mod:`tools.drift_canary.endpoints` — every probe a **declarative**
  provider (``.yml``, roadmap R2.8) declares still answers with a status its
  own liveness vocabulary expects, rather than a ``404`` or a response
  carrying an RFC 8594 ``Deprecation``/``Sunset`` header — the ``404``-vs-
  ``401`` distinction and the deprecation signal §13.3 names explicitly.

**Scoped to declarative providers, on purpose, not to every provider yet.**
A ``.yml`` spec already states its probe URLs, their vendor ``source`` and
the status-code vocabulary that means "this endpoint exists but the key
didn't work", as data (``core/probes.py``'s ``ProviderSpec``). A
hand-written ``.py`` plugin states the same facts as Python inside
``enumerate()``, with no structured way to read them back out short of
running the plugin against a real key — which this canary deliberately never
has; it has no key at all (``base.py``). As more providers migrate to the
declarative format, they gain endpoint-drift coverage for free without this
package changing; the twenty-nine that have not are covered by the source
check alone, which reads ``detection_rules.yml`` and does not depend on the
format a plugin happens to be written in.

Not shipped: ``tools/`` is dev tooling, exactly like ``tools/guardrails/``,
and is not part of the ``keyreach`` package a user installs.
"""

from __future__ import annotations
