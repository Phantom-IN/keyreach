"""Second of two providers claiming the name `clash`."""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider


class ClashTwoProvider(DummyProvider):
    name = "clash"
    category = "ai"
    docs_url = "https://example.invalid/two"
