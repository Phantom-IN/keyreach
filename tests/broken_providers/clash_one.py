"""First of two providers claiming the name `clash`."""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider


class ClashOneProvider(DummyProvider):
    name = "clash"
    category = "cloud"
    docs_url = "https://example.invalid/one"
