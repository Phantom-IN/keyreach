"""New Relic User keys — roadmap R2.6.

No prior art. This plugin covers exactly one of New Relic's several key
families, and says why the others are out of scope rather than silently
ignoring them.

**Only the User key (``NRAK-``) ships.** New Relic issues at least four kinds:
User keys (NerdGraph + REST v2, read and write, tied to a person), License
keys (40-character hex, no prefix, ingest-only), Ingest - Browser keys (same
ingest family), and Query keys. The ``NRAK`` prefix is confirmed from New
Relic's own REST-API-keys retirement notice — "If your API key starts with
`NRAK`, no update is required" — which is a primary-source statement even
though it is not the dedicated key-format page. The other three formats are
either undocumented (Browser/Query key prefixes appear only in third-party
references, never on ``docs.newrelic.com``) or too generic to detect safely:
New Relic documents a License key only as "a 40-character hexadecimal
string", which is the exact shape of a SHA-1 hash and would false-positive
constantly. No rule was written for any of them, and this plugin does not
attempt to validate or enumerate them.

**License keys are un-enumerable, joining Sentry's DSN and PyPI's token this
roadmap era.** New Relic documents no read-only way to confirm a License key
is live — the only documented signal is ``202`` (accepted) vs ``403``
(rejected) on the Metric API, and reaching either means submitting a real
ingest payload, which ``plan.md`` §11 forbids. Unlike PyPI, keyreach ships no
detection rule for it either, for the reason above: the format is real but
too generic to write a safe pattern from.

**NerdGraph is GraphQL, so even a pure read is a POST — the fifth
``read_only_post`` in this codebase**, after PayPal, Zoom, Docker Hub and
MongoDB Atlas. Every one of those existed because the *only* way to
authenticate needed POST; this one is different and arguably cleaner: the
POST carries a query operation, never a mutation, and NerdGraph has no GET
form for any query at all. ``{ requestContext { userId apiKey } }`` is the
one complete example New Relic's own NerdGraph introduction page shows
verbatim — deliberately the only NerdGraph query this plugin sends, rather
than a richer one (``actor { accounts { ... } }``, entity search) assembled
from field names seen only in third-party tooling and not confirmed on
``docs.newrelic.com`` in this session.

**Probed against the live API, which corrected two assumptions.** New
Relic's REST v2 documentation calls its header ``Api-Key`` in prose; probing
``GET /v2/applications.json`` with that exact header returns
``401 {"error":{"title":"No API key specified"}}`` — New Relic silently
dropped it. The header REST v2 actually reads is ``X-Api-Key``, confirmed by
the same probe returning ``401 {"error":{"title":"Invalid API Key",...}}``
once the header name was corrected. NerdGraph's own header, by contrast, is
confirmed correct as documented — ``API-Key`` returns
``401 {"errors":[{"message":"authentication required"}]}``, a real
authentication attempt rather than a missing-header error. Both error shapes
above are quoted from the live API's actual bytes, not from a doc page.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
#
# Source: https://docs.newrelic.com/whats-new/2025/01/whats-new-03-01-rest-api-keys-eol/
# ("If your API key starts with NRAK, no update is required"). No exact
# length or charset is published beyond the prefix, so the pattern uses an
# open floor rather than inventing a count, the same treatment Pinecone's and
# Docker Hub's rules give an unconfirmed length.
_PATTERN: Final = re.compile(r"^NRAK-[A-Za-z0-9]{20,}$")
CONFIDENCE: Final = 0.95

# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

NERDGRAPH_URL: Final = "https://api.newrelic.com/graphql"
REST_V2: Final = "https://api.newrelic.com/v2"
APPLICATIONS_URL: Final = f"{REST_V2}/applications.json"

#: The one NerdGraph query New Relic's own docs show verbatim. See the module
#: docstring for why nothing richer is sent.
REQUEST_CONTEXT_QUERY: Final = "{ requestContext { userId apiKey } }"

_HTTP_UNAUTHORIZED: Final = 401


def _nerdgraph_headers(key: str) -> dict[str, str]:
    return {"API-Key": key, "Content-Type": "application/json"}


def _rest_v2_headers(key: str) -> dict[str, str]:
    """``X-Api-Key``, confirmed against the live API. See the module docstring."""
    return {"X-Api-Key": key}


def _nerdgraph_body() -> str:
    return json.dumps({"query": REQUEST_CONTEXT_QUERY})


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _payload(response: ProbeResponse) -> dict[str, Any]:
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def request_context(response: ProbeResponse) -> dict[str, Any]:
    """``data.requestContext`` from a successful NerdGraph response."""
    data = _payload(response).get("data")
    if not isinstance(data, dict):
        return {}
    context = data.get("requestContext")
    return context if isinstance(context, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """New Relic's error text, from whichever of the two shapes it used.

    NerdGraph answers standard GraphQL ``{"errors": [{"message": "..."}]}``.
    REST v2 answers ``{"error": {"title": "..."}}}``. Both confirmed by
    probing the live API with an invalid key; New Relic's own docs quote
    neither.
    """
    payload = _payload(response)

    errors = payload.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        message = errors[0].get("message")
        if isinstance(message, str):
            return message

    error = payload.get("error")
    if isinstance(error, dict):
        title = error.get("title")
        if isinstance(title, str):
            return title

    return ""


def _applications(response: ProbeResponse) -> list[Any] | None:
    """The application list, from whichever shape New Relic answers with.

    New Relic's REST v2 convention wraps a list resource in its own name
    (``{"applications": [...]}}``), matching every other v2 endpoint this
    plugin's docstring could confirm the *path* for — but this exact response
    body was not observed against a live, successful request, since no test
    account was available. Falls back to treating the body as a bare array,
    and to ``None`` (which reads as "request accepted" with no count) rather
    than guessing a count from an unrecognised shape.
    """
    body = response.json_or_none()
    if isinstance(body, dict):
        applications = body.get("applications")
        if isinstance(applications, list):
            return applications
        return None
    if isinstance(body, list):
        return body
    return None


def _account_summary(response: ProbeResponse) -> str:
    context = request_context(response)
    user_id = context.get("userId")
    if user_id is None:
        return "request accepted"
    return f"authenticated as user {user_id}"


def _applications_summary(response: ProbeResponse) -> str:
    applications = _applications(response)
    if applications is None:
        return "request accepted"
    if not applications:
        return "applications: none present"
    return f"applications: {len(applications)} listed"


def _identity(response: ProbeResponse) -> Identity:
    context = request_context(response)
    user_id = context.get("userId")
    return Identity(account=str(user_id) if user_id is not None else None)


def _poc_nerdgraph(ctx: ProbeContext, key: str) -> str:
    return ctx.mask(
        f"curl -s -H 'API-Key: {key}' -H 'Content-Type: application/json' "
        f"-d '{_nerdgraph_body()}' '{NERDGRAPH_URL}'"
    )


def _poc_rest_v2(ctx: ProbeContext, key: str, url: str) -> str:
    return ctx.mask(f"curl -s -H 'X-Api-Key: {key}' '{url}'")


class _Probe(BaseModel):
    """One capability's metadata. Unlike every other provider's ``PROBES``,
    this does not carry a URL — NerdGraph and REST v2 need different request
    shapes (POST-with-body vs GET), built in ``enumerate`` directly — but the
    service name, risk weight and source URL are still declared here rather
    than inlined, so the provider contract's checks over ``PROBES`` still
    cover this plugin.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str


_DOCS: Final = "https://docs.newrelic.com/docs/apis"

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="New Relic Account Context",
        detail=(
            "Can confirm the requesting user's id via NerdGraph, which "
            "authenticates this key"
        ),
        risk_weight=30,
        source=f"{_DOCS}/nerdgraph/get-started/introduction-new-relic-nerdgraph/",
    ),
    _Probe(
        service="New Relic APM Applications",
        detail="Can list the account's monitored applications via the REST v2 API",
        risk_weight=65,
        data_sensitive=True,
        source=f"{_DOCS}/rest-api-v2/get-started/introduction-new-relic-rest-api-v2/",
    ),
)


def _probe(service: str) -> _Probe:
    return next(probe for probe in PROBES if probe.service == service)


class NewRelicProvider(Provider):
    """New Relic User keys (``NRAK-``). See the module docstring for scope."""

    name = "newrelic"
    category = "monitoring"
    docs_url = f"{_DOCS}/intro-apis/new-relic-api-keys/"
    rotation_guide_url = f"{_DOCS}/intro-apis/new-relic-api-keys/#user-key"

    def detect(self, key: str) -> float:
        """Pure structural match against the confirmed ``NRAK-`` prefix."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """The NerdGraph ``requestContext`` query — a read, sent as ``POST``."""
        if not _PATTERN.match(key):
            return ValidationResult(
                valid=False,
                note="This does not look like a New Relic User key (NRAK-...)",
            )

        response = await ctx.post(
            NERDGRAPH_URL,
            content=_nerdgraph_body(),
            headers=_nerdgraph_headers(key),
            read_only_post=True,
        )
        message = message_of(response)

        if response.ok and request_context(response).get("userId") is not None:
            return ValidationResult(valid=True, identity=_identity(response))

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "New Relic did not accept this User key"
                    + (f" ({message})" if message else "")
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "New Relic's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """The NerdGraph identity read plus the REST v2 application list.

        The NerdGraph call is the same request ``validate`` already made —
        R1.4's per-run cache, keyed on method, URL and body, answers this one
        from cache rather than minting a second request.
        """
        if not _PATTERN.match(key):
            return []

        nerdgraph_response, applications_response = await ctx.gather(
            [
                ctx.post(
                    NERDGRAPH_URL,
                    content=_nerdgraph_body(),
                    headers=_nerdgraph_headers(key),
                    read_only_post=True,
                ),
                ctx.get(APPLICATIONS_URL, headers=_rest_v2_headers(key)),
            ]
        )

        capabilities: list[Capability] = []
        if (
            nerdgraph_response.ok
            and request_context(nerdgraph_response).get("userId") is not None
        ):
            probe = _probe("New Relic Account Context")
            capabilities.append(
                Capability(
                    service=probe.service,
                    access=AccessLevel.READ,
                    detail=probe.detail,
                    evidence=nerdgraph_response.evidence(
                        _account_summary(nerdgraph_response)
                    ),
                    risk_weight=probe.risk_weight,
                    data_sensitive=probe.data_sensitive,
                    poc=_poc_nerdgraph(ctx, key),
                    resource_ref=probe.source,
                )
            )

        if applications_response.ok:
            probe = _probe("New Relic APM Applications")
            capabilities.append(
                Capability(
                    service=probe.service,
                    access=AccessLevel.READ,
                    detail=probe.detail,
                    evidence=applications_response.evidence(
                        _applications_summary(applications_response)
                    ),
                    risk_weight=probe.risk_weight,
                    data_sensitive=probe.data_sensitive,
                    poc=_poc_rest_v2(ctx, key, applications_response.url),
                    resource_ref=probe.source,
                )
            )

        return sorted(capabilities, key=lambda capability: capability.sort_key)
