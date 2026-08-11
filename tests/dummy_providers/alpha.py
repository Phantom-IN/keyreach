"""Defines the provider named `zebra` — module name deliberately sorts first."""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider


class ZebraProvider(DummyProvider):
    name = "zebra"
    category = "payment"
    prefix = "zebra_"
    docs_url = "https://example.invalid/zebra"
    credit = "some-upstream-project"
