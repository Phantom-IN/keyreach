"""A provider whose every probe is served from a cassette.

Note what this module does **not** import: no `httpx`, no `requests`, no
`socket`. Ruff's banned-api rule rejects all three outside
`keyreach/core/http.py`, and the `network_isolation` CI check (roadmap R0.9)
rejects them again. A provider reaches the network only through the
`ProbeContext` it is handed — that is the R0.6 acceptance criterion, and this
file is what demonstrates it.
"""

from __future__ import annotations

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

BASE = "https://api.cassette.invalid"


class CassetteProvider(Provider):
    name = "cassette"
    category = "generic"
    docs_url = "https://example.invalid/docs"
    rotation_guide_url = "https://example.invalid/rotate"

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        response = await ctx.get(f"{BASE}/v1/whoami", params={"key": key})
        if not response.ok:
            return ValidationResult(valid=False, note="provider rejected the key")

        payload = response.json_or_none() or {}
        return ValidationResult(
            valid=True,
            identity=Identity(
                account=payload.get("account"),
                plan_or_tier=payload.get("plan"),
            ),
            note="",
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        # Deliberately returned unsorted: the engine and the Report model are
        # both responsible for ordering, and this is what proves it.
        metadata, files = await ctx.gather(
            [
                ctx.get(f"{BASE}/v1/metadata", params={"key": key}),
                ctx.get(f"{BASE}/v1/files", params={"key": key}),
            ]
        )

        capabilities: list[Capability] = []
        if files.ok:
            payload = files.json_or_none() or {}
            capabilities.append(
                Capability(
                    service="Cassette Files",
                    access=AccessLevel.READ,
                    detail="Can list uploaded files",
                    evidence=files.evidence(f"{len(payload.get('files', []))} files"),
                    risk_weight=70,
                    data_sensitive=True,
                )
            )
        if metadata.ok:
            capabilities.append(
                Capability(
                    service="Cassette Metadata",
                    access=AccessLevel.READ,
                    detail="Can read project metadata",
                    evidence=metadata.evidence("project metadata returned"),
                    risk_weight=20,
                )
            )
        return capabilities

    def detect(self, key: str) -> float:
        return 0.99 if key.startswith("csst_") else 0.0
