"""A provider whose detect() returns a confidence outside 0.0-1.0.

Metadata validation cannot catch this: the value only exists once detect() is
actually called, so the registry has to check it at ranking time.
"""

from __future__ import annotations

from tests.dummy_providers._shared import DummyProvider


class OutOfRangeProvider(DummyProvider):
    name = "outofrange"
    category = "generic"
    docs_url = "https://example.invalid/out-of-range"

    def detect(self, key: str) -> float:
        return 42.0
