"""Two providers in one module, plus an imported class that must NOT register.

`AlphaProvider` is imported here for reuse. Discovery keys off where a class is
*defined* (`__module__`), so importing it must not register a second `alpha` and
trip the duplicate-name guard.
"""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider
from tests.dummy_providers.zulu import AlphaProvider  # noqa: F401 — see docstring


class MikeProvider(DummyProvider):
    name = "mike"
    category = "ai"
    prefix = "mike_"
    docs_url = "https://example.invalid/mike"


class NovemberProvider(DummyProvider):
    name = "november"
    category = "comms"
    prefix = "november_"
    docs_url = "https://example.invalid/november"
