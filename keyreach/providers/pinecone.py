"""Pinecone API keys (``pcsk_…``) — roadmap R2.5.

No prior art. Every path and header below comes from Pinecone's own API
reference and was verified against the live API, which answers 401 for a path
that exists and 404 for one that does not.

**The prefix is published in exactly one place, and it is the CLI reference.**
Pinecone's authentication page and its key-management guide both show only
``YOUR_API_KEY``; ``pc config set-api-key pcsk_abc123`` appears in the command
reference. That page was read rather than trusted to a search result — R2.4
found a search engine confidently reporting an npm token format the cited page
did not carry, which is the same mistake in the other direction.

**Pinecone's error body is plain text, not JSON.** A rejected key returns the
bytes ``Invalid API key`` with no envelope at all, so the parsing here does not
assume a structured body and the rejection note quotes the text as given.
Verified against the live API.

**Every capability is ``READ``.** A key that can list indexes can almost
certainly write vectors into them — Pinecone documents no read-only key type
— but it documents no way to ask what *this* key may do either, and keyreach
does not upsert a vector to find out. So the access level is what the probe
proved, and the detail says which question was left open. The same position
Mailgun's plugin takes in R2.3 and three of R2.4's four.

**What listing indexes actually discloses.** Not the vectors — the *shape* of
somebody's retrieval estate: how many indexes, their names, dimensions and
regions. The names alone usually say what the company embeds, which is why the
risk weight here is high while the capability stays a read.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Key format
# --------------------------------------------------------------------------
#
# Mirrors the `pinecone-api-key` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_pinecone.py`
# asserts the two agree.
# Source: https://docs.pinecone.io/reference/cli/command-reference

_PATTERN: Final = re.compile(r"^pcsk_[A-Za-z0-9_-]{20,}$")

CONFIDENCE: Final = 0.99


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.pinecone.io"

#: Pinecone asks for an explicit API version on every request. Pinning it means
#: a future default cannot change what keyreach reads.
#: Source: https://docs.pinecone.io/reference/api/versioning
API_VERSION: Final = "2025-10"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Recorded so the capability detail names the question keyreach left open.
SCOPE_STATEMENT: Final = (
    "Pinecone publishes no way to ask what this key may write, and keyreach "
    "does not upsert a vector to find out, so write access is undetermined and "
    "none was attempted"
)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    collection: str = Field(
        description="Response field holding the list, for the evidence count."
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Pinecone Assistants",
        url=f"{API}/assistant/assistants",
        collection="assistants",
        noun="assistants",
        detail=(
            "Can list the project's assistants, which are built over files the "
            "account uploaded"
        ),
        risk_weight=85,
        # An assistant is a named surface over somebody's uploaded documents.
        data_sensitive=True,
        source="https://docs.pinecone.io/reference/api/introduction",
    ),
    _Probe(
        service="Pinecone Backups",
        url=f"{API}/backups",
        collection="data",
        noun="backups",
        detail="Can list the project's index backups",
        risk_weight=80,
        source="https://docs.pinecone.io/reference/api/introduction",
    ),
    _Probe(
        service="Pinecone Collections",
        url=f"{API}/collections",
        collection="collections",
        noun="collections",
        detail="Can list the project's collections, which are index snapshots",
        risk_weight=80,
        source="https://docs.pinecone.io/reference/api/introduction",
    ),
    _Probe(
        service="Pinecone Indexes",
        url=f"{API}/indexes",
        collection="indexes",
        noun="indexes",
        detail=(
            "Can list the project's indexes with their names, dimensions, "
            "metrics and regions — the shape of what this account has embedded"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://docs.pinecone.io/reference/api/database/list-indexes",
    ),
)

#: ``/indexes`` is the endpoint Pinecone's own authentication example calls, and
#: the cheapest read that proves a key is live.
VALIDATE_SERVICE: Final = "Pinecone Indexes"


def validation_probe() -> _Probe:
    """The cheapest read that proves the key is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """The headers Pinecone documents on every request.

    Source: https://docs.pinecone.io/reference/api/authentication
    """
    return {"Api-Key": key, "X-Pinecone-Api-Version": API_VERSION}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively because this parses a third-party payload — and here it
    is load-bearing rather than paranoid: Pinecone's own rejection body is plain
    text, so this returns an empty mapping on the path keyreach hits most.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Pinecone's error text, from either shape it uses.

    A rejected key returns the bare bytes ``Invalid API key`` — no JSON, no
    envelope — verified against the live API. Structured errors carry
    ``{"error": {"message": …}}``, so both are read and the plain-text case is
    the fallback rather than an afterthought.
    """
    error = _payload(response).get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str):
            return message
    text = response.text.strip()
    # Only a short, single-line body is a message; an HTML error page is not.
    if text and "\n" not in text and len(text) <= _MAX_PLAIN_MESSAGE:
        return text
    return ""


#: Longer than this and a plain-text body is a page, not a message.
_MAX_PLAIN_MESSAGE: Final = 200


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    items = _payload(response).get(probe.collection)
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    return ctx.mask(
        f"curl -s -H 'Api-Key: {ctx.key}' "
        f"-H 'X-Pinecone-Api-Version: {API_VERSION}' '{url}'"
    )


class PineconeProvider(Provider):
    """Pinecone API keys."""

    name = "pinecone"
    category = "database"
    docs_url = "https://docs.pinecone.io/reference/api/authentication"
    rotation_guide_url = "https://docs.pinecone.io/guides/projects/manage-api-keys"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``pcsk_`` prefix."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/indexes``, the endpoint Pinecone's own example calls.

        No identity is returned: Pinecone publishes no endpoint that names the
        project or organization a key belongs to, and keyreach does not invent
        one from an undocumented path — the line R2.4 drew at npm.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True)

        if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    "Pinecone did not accept this key"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Pinecone rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Pinecone's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered."""
        headers = _auth(key)
        responses = await ctx.gather(
            [ctx.get(probe.url, headers=headers) for probe in PROBES]
        )

        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere, deliberately — see the module docstring.
                access=AccessLevel.READ,
                detail=f"{probe.detail}. {SCOPE_STATEMENT}",
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
