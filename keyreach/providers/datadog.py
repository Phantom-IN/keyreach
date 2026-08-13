"""Datadog API key + application key — roadmap R2.6.

No prior art. Every endpoint, response shape and security requirement below
comes from Datadog's own OpenAPI specifications
(``github.com/DataDog/datadog-api-client-python``, ``.generator/schemas/v1``
and ``v2``), read directly rather than from prose documentation pages, which
do not publish response schemas at all.

**Two keys, and — unlike every composite credential keyreach has met before —
each half is independently meaningful.** PayPal, Zoom and MongoDB Atlas all
exchange their parts together for one OAuth token; a lone half authenticates
nothing. Datadog's own authentication page states the opposite split:
"Requests that write data require reporting access and require an API key.
Requests that read data require full access and also require an application
key." So keyreach accepts a bare API key (no application key at all) as a
partial credential, distinct from PayPal-style "recognised, reported, and not
probed" bare halves — Datadog's own ``/api/v2/validate`` proves a bare API key
is live on its own. Enumeration, all of which reads, still needs both, so a
bare API key validates but enumerates to nothing.

**Undetectable.** Neither key is documented with a prefix, length or charset
anywhere in Datadog's API or account-management docs — confirmed by reading
the raw HTML rather than trusting a summary, after R2.4 found a search engine
inventing an npm token format no page carried. ``detectable = False``;
``keyreach 'API_KEY:APP_KEY' --provider datadog`` is the route in.

**Validation costs nothing and needs no scope.** ``GET /api/v2/validate`` is
marked ``x-permission: {operator: OPEN, permissions: []}`` in the spec — any
live API key can call it, which is what makes it the cheapest possible liveness
check. It also happens to return the credential's own scopes
(``api_key_scopes``) and the organization's UUID in one request, which is why
identity comes from here rather than a second call.

**A fourth shape for reading a token's own scope, on top of the three R2.4
found** (a header at GitHub, a resource at SendGrid, a resource carrying
``active``/``expires_at`` at GitLab): here the scope list is a field on the
same response that proves liveness, because Datadog's "Restricted API Keys"
feature scopes the *API key* itself, separately from the paired application
key's own (unread here) scopes.

**The spec under-documents its own status codes.** Datadog's OpenAPI spec
lists only 200/403/429 for ``/api/v2/validate``. Probing it directly with a
garbage key returns ``401 {"errors":["Unauthorized"]}`` — a real status the
spec omits, found the same way R2.5 found MongoDB Atlas's actual rejection
message: by running a request against the live API rather than trusting the
document.

**No default region.** Datadog operates nine regional sites
(``datadoghq.com``, ``datadoghq.eu``, ``us3``, ``us5``, ``ap1``, ``ap2``,
``uk1``, ``gov``, ``gov2``) and documents no way to tell which one a key
belongs to from the key itself. keyreach probes ``datadoghq.com`` (site
``US1``, the default new organizations get) only — the same under-reporting
AWS's plugin already carries for ``us-east-1``-only enumeration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------

#: Not a published fact — Datadog documents no minimum length for either key.
#: Only rejects empty/obviously-garbage input before a request is made.
MIN_API_KEY_LENGTH: Final = 8


class Credential(NamedTuple):
    """A Datadog credential. ``app_key`` is ``""`` when only the API key was given."""

    api_key: str
    app_key: str


def parse_credential(key: str) -> Credential | None:
    """Split ``api_key:app_key``, or accept a bare API key.

    Unlike ``mongodb``/``zoom``, a missing second half is not rejected here —
    it is a real, independently valid Datadog credential (see the module
    docstring), so it is parsed and passed through with ``app_key=""``.
    """
    api_key, separator, app_key = key.partition(":")
    if len(api_key) < MIN_API_KEY_LENGTH:
        return None
    return Credential(api_key, app_key if separator else "")


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
#
# Site is fixed to US1; see the module docstring. Confirmed against Datadog's
# OpenAPI specs rather than prose docs, which publish no response schemas.

SITE: Final = "datadoghq.com"
API_V1: Final = f"https://api.{SITE}/api/v1"
API_V2: Final = f"https://api.{SITE}/api/v2"

VALIDATE_URL: Final = f"{API_V2}/validate"

_DOCS: Final = "https://docs.datadoghq.com/api/latest"

#: Statuses that mean "this API key was not accepted". Datadog's own OpenAPI
#: spec documents only 403 for `/validate`; the live API also answers 401
#: (`{"errors":["Unauthorized"]}`), confirmed by probing it directly, which
#: the spec does not mention at all — the same kind of drift R2.5 found in
#: MongoDB Atlas's rejection message.
_REJECTED_STATUSES: Final[frozenset[int]] = frozenset({401, 403})
_HTTP_TOO_MANY_REQUESTS: Final = 429


def _api_headers(credential: Credential) -> dict[str, str]:
    """``DD-API-KEY`` always; ``DD-APPLICATION-KEY`` only when one was given."""
    headers = {"DD-API-KEY": credential.api_key}
    if credential.app_key:
        headers["DD-APPLICATION-KEY"] = credential.app_key
    return headers


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------
#
# All four require both headers (`x-permission` in the spec lists
# `apiKeyAuth` + `appKeyAuth`), so none of these run against a bare API key.


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    collection: str | None = Field(
        default=None,
        description="Response field holding the list; None means a bare array.",
    )
    noun: str
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Datadog Dashboards",
        url=f"{API_V1}/dashboard",
        collection="dashboards",
        noun="dashboards",
        detail="Can list the organization's dashboards, including their titles",
        risk_weight=60,
        source=f"{_DOCS}/dashboards/#get-all-dashboards",
    ),
    _Probe(
        service="Datadog Monitors",
        url=f"{API_V1}/monitor",
        collection=None,
        noun="monitors",
        detail="Can list the organization's alerting monitors and their queries",
        risk_weight=65,
        source=f"{_DOCS}/monitors/#get-all-monitors",
    ),
    _Probe(
        service="Datadog Users",
        url=f"{API_V2}/users",
        collection="data",
        noun="users",
        detail="Can list every user in the organization, including their emails",
        risk_weight=85,
        data_sensitive=True,
        source=f"{_DOCS}/users/#list-all-users",
    ),
    _Probe(
        service="Datadog Roles",
        url=f"{API_V2}/roles",
        collection="data",
        noun="roles",
        detail="Can list the organization's RBAC roles",
        risk_weight=55,
        source=f"{_DOCS}/roles/#list-roles",
    ),
)


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload — an edge
    returning an HTML error page must degrade to "no structured body".
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def _attributes(payload: dict[str, Any]) -> dict[str, Any]:
    """``data.attributes`` from Datadog's JSON:API-shaped ``/validate`` body."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _scopes(attributes: dict[str, Any]) -> tuple[str, ...]:
    raw = attributes.get("api_key_scopes")
    if not isinstance(raw, list):
        return ()
    return tuple(sorted({item for item in raw if isinstance(item, str)}))


def message_of(response: ProbeResponse) -> str:
    """Datadog's error text.

    Both error schemas the spec defines for these endpoints (``APIErrorResponse``
    on ``/validate`` and ``/validate_keys``) shape ``errors`` as a **list of
    plain strings** — not the ``{message, ...}`` objects most other providers'
    error envelopes carry.
    """
    payload = _payload(response)
    errors = payload.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], str):
        return errors[0]
    return ""


def _org_id(payload: dict[str, Any]) -> str | None:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    org_id = data.get("id")
    return org_id if isinstance(org_id, str) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    body = response.json_or_none()
    if probe.collection is None:
        items = body if isinstance(body, list) else None
    else:
        items = body.get(probe.collection) if isinstance(body, dict) else None
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _identity(payload: dict[str, Any], credential: Credential) -> Identity:
    """The org, API key id and scopes, from the ``/validate`` response.

    The API key is reported by id, never by value; the application key half
    (if any) never appears here at all, because ``/validate`` never saw it.
    """
    attributes = _attributes(payload)
    scopes = _scopes(attributes)
    api_key_id = attributes.get("api_key_id")
    extra = {
        "api_key_id": api_key_id if isinstance(api_key_id, str) else "unknown",
        "api_key_scopes": (", ".join(scopes) if scopes else "none returned by Datadog"),
        "application_key": "present" if credential.app_key else "not given",
        "site": f"{SITE} (default; other regional sites are not probed)",
    }
    return Identity(account=_org_id(payload), extra=extra)


def _poc(ctx: ProbeContext, credential: Credential, url: str) -> str:
    """A masked, read-only reproduction of the request that proved access."""
    header_args = " ".join(
        f"-H '{name}: {value}'" for name, value in _api_headers(credential).items()
    )
    return ctx.mask(f"curl -s {header_args} '{url}'")


class DatadogProvider(Provider):
    """Datadog API key, paired with an optional application key."""

    name = "datadog"
    category = "monitoring"
    docs_url = "https://docs.datadoghq.com/api/latest/"
    rotation_guide_url = "https://docs.datadoghq.com/account_management/api-app-keys/"

    #: Neither key has a published prefix, length or charset. See the module
    #: docstring; ``--provider datadog`` is the documented route.
    detectable = False

    def detect(self, key: str) -> float:
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Check the API key alone via ``/api/v2/validate`` — no scope required.

        Deliberately not ``/api/v2/validate_keys``: that call needs both keys
        and would report a perfectly live, write-capable API key as "invalid"
        whenever no application key was supplied, which is not true (see the
        module docstring on why the two halves are independently meaningful).
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This does not look like a Datadog API key. Datadog also "
                    "documents an application key, needed for every read probe "
                    "keyreach runs, so pass 'API_KEY:APP_KEY' when you have both"
                ),
            )

        response = await ctx.get(VALIDATE_URL, headers=_api_headers(credential))
        payload = _payload(response)
        attributes = _attributes(payload)
        message = message_of(response)

        if response.ok and attributes.get("valid") is True:
            return ValidationResult(
                valid=True,
                identity=_identity(payload, credential),
                note=_scope_note(credential),
            )

        if response.status_code in _REJECTED_STATUSES:
            return ValidationResult(
                valid=False,
                note=(
                    "Datadog did not accept this API key"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential reached Datadog, which rate limited the "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Datadog's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint that needs both headers.

        Returns empty for a bare API key with no application key — every probe
        here requires both, per the spec's ``apiKeyAuth`` + ``appKeyAuth``
        security block, and keyreach does not guess at a missing half.
        """
        credential = _credential_for(key, ctx)
        if credential is None or not credential.app_key:
            return []

        headers = _api_headers(credential)
        responses = await ctx.gather(
            [ctx.get(probe.url, headers=headers) for probe in PROBES]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=AccessLevel.READ,
                detail=probe.detail,
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, credential, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _scope_note(credential: Credential) -> str:
    if not credential.app_key:
        return (
            "Datadog accepted this API key. No application key was given, so "
            "read capabilities (dashboards, monitors, users, roles) could not "
            "be enumerated — Datadog requires both for every read"
        )
    return "Datadog accepted this API key and application key"


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register both halves for redaction.

    The redactor is seeded with the whole pasted string, which would not mask
    a response echoing back one half alone — neither observed in practice, but
    the same discipline every composite-credential plugin here follows.
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.api_key)
    if credential.app_key:
        ctx.protect(credential.app_key)
    return credential
