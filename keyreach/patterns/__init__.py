"""Detection pattern data.

Holds ``detection_rules.yml``, loaded by :mod:`keyreach.core.detect`. A package
rather than a bare directory so the rules ship inside the wheel and can be
located with :mod:`importlib.resources` regardless of how keyreach was
installed.

Every pattern is written from the provider's own public documentation, and each
rule records its ``source`` URL. See the header of ``detection_rules.yml`` for
why nothing is copied from an existing rule set.
"""

from __future__ import annotations
