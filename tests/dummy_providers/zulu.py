"""Defines the provider named `alpha` — module name deliberately sorts last.

Paired with `alpha.py`, which defines `zebra`. If the registry returned
providers in module-import order instead of sorting by provider name, the two
would come back reversed.
"""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider


class AlphaProvider(DummyProvider):
    name = "alpha"
    category = "cloud"
    prefix = "alpha_"
    docs_url = "https://example.invalid/alpha"
    rotation_guide_url = "https://example.invalid/alpha/rotate"
