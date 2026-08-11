"""Shared base for the dummy providers.

Underscore-prefixed, so the registry must skip it. If discovery ever picked this
module up it would try to register ``DummyProvider`` itself — the test for that
is ``test_private_modules_are_not_scanned``.
"""

from __future__ import annotations

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider


class DummyProvider(Provider):
    """Concrete provider with harmless, offline implementations.

    ``validate`` and ``enumerate`` do no I/O — the ``ProbeContext`` argument is
    accepted and ignored. R0.4 only needs the contract to be implementable and
    discoverable; the first plugin that actually probes anything is R1.1.
    """

    name = "dummy"
    category = "generic"
    docs_url = "https://example.invalid/docs"

    #: Prefix `detect` matches on, so each subclass can claim a different key
    #: shape without reimplementing the method.
    prefix = "dummy_"

    def detect(self, key: str) -> float:
        return 1.0 if key.startswith(self.prefix) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        return ValidationResult(valid=key.startswith(self.prefix))

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        return [
            Capability(
                service=f"{self.name} service",
                access=AccessLevel.READ,
                detail="Can read dummy data",
                evidence=f"GET /dummy?key={self.prefix}**** -> 200",
                risk_weight=10,
            )
        ]
