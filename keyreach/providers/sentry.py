"""Sentry auth tokens — roadmap R2.6.

No prior art. The scope grammar, every endpoint's security requirement and
response shape below come from Sentry's own OpenAPI specification,
`github.com/getsentry/sentry-api-schema` (``openapi-derefed.json``) — a
primary source Sentry publishes and keeps in sync with its actual API, read
directly rather than trusted from a prose page or a search result, after
R2.4 found a search engine inventing an npm token format no vendor page
carried.

**Undetectable, and for a different reason than most.** Community references
show auth tokens shaped ``sntryu_…`` (user) and ``sntrys_…`` (org), but
``docs.sentry.io`` does not state either prefix on any page this item could
reach — not the auth-tokens guide, not the API auth reference, not the
create-a-token walkthrough. A prefix that is true in practice but unconfirmed
from the vendor is exactly the gap ``detection_rules.yml`` exists to close by
requiring a ``source:`` URL that actually supports the pattern, so no rule was
written. ``detectable = False``; ``keyreach 'TOKEN' --provider sentry`` is the
route in.

**No self-identity endpoint — the scope grammar comes from the read itself.**
Every other undetectable-but-scoped provider so far (Zoom, GitLab) reads
granted scopes from a dedicated identity call. Sentry's OpenAPI spec has no
``/auth/`` path at all; the closest thing, ``GET /api/0/organizations/``,
returns each organization with its own ``access: [string]`` field — the
scopes this token holds *for that org* — so the read that proves liveness is
also the read that answers "what can this do", with no second request.

**Scopes are ``resource:action``**, confirmed from the spec's `security`
blocks across every endpoint this plugin probes: ``org:read``/``org:write``/
``org:admin``, ``member:read``/``member:write``/``member:admin``. Read the
same way Zoom's ``resource:operation:action:role`` grammar is read — by
splitting the string, not by matching a checked-in list of scope names Sentry
ships new ones into continuously.

**A ``403`` here is genuinely ambiguous, and this plugin says so rather than
guessing.** ``GET /api/0/organizations/`` accepts any of ``org:read``,
``org:write`` or ``org:admin`` (an OR, per the spec) and requires at least
one, so a ``403`` could mean an invalid token or a live token Sentry simply
never granted any org-level scope. There is no scope-free call to
disambiguate, unlike Datadog's ``/validate`` in this same roadmap item. The
validation note names the ambiguity instead of picking a side.

**The Sentry DSN gets neither a rule nor a plugin, on purpose — a fourth
combination.** Sentry's own docs state a DSN "only allow[s] submission of new
events and related event data; they do not allow read access to any
information", which makes it un-enumerable exactly like a New Relic license
key or a PyPI token: the one thing it authorizes is a write, and confirming
liveness read-only is not possible. PyPI still ships a **detection rule with
no plugin** because PyPI has no other credential to confuse it with. Sentry
does — this file. A DSN detection rule under the same provider name would
hand a live, correctly-functioning write credential to a plugin built for
auth tokens, which would report it "invalid" for not being one. That is worse
than the silence Firebase gets, so DSNs get exactly that: nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
#
# Confirmed from https://github.com/getsentry/sentry-api-schema
# (openapi-derefed.json). Sentry SaaS only; self-hosted instances publish the
# same API under an operator-chosen host this plugin has no way to discover.

API: Final = "https://sentry.io/api/0"
ORGANIZATIONS_URL: Final = f"{API}/organizations/"

#: Not a published fact — only rejects empty input before a request is made.
MIN_TOKEN_LENGTH: Final = 8

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------
#
# `resource:action` — confirmed from the OpenAPI spec's `security` blocks
# (e.g. `org:read`/`org:write`/`org:admin`, `member:read`/`member:write`/
# `member:admin`). Parsed rather than matched against a list, since Sentry's
# scope catalogue is not fully enumerated in the spec.

WRITE_ACTION: Final = "write"
ADMIN_ACTION: Final = "admin"


class Scope(NamedTuple):
    resource: str
    action: str


def parse_scope(scope: str) -> Scope | None:
    resource, separator, action = scope.partition(":")
    if not separator or not resource or not action:
        return None
    return Scope(resource, action)


def scopes_of(org: dict[str, Any]) -> tuple[str, ...]:
    """The ``access`` array Sentry returns on each organization object."""
    raw = org.get("access")
    if not isinstance(raw, list):
        return ()
    return tuple(sorted({item for item in raw if isinstance(item, str)}))


def _matching(resource: str, scopes: tuple[str, ...]) -> tuple[Scope, ...]:
    parsed = (parse_scope(scope) for scope in scopes)
    return tuple(s for s in parsed if s is not None and s.resource == resource)


def access_for(resource: str, scopes: tuple[str, ...]) -> AccessLevel:
    """The access level granted scopes establish over one resource.

    Defaults to ``READ`` when the read succeeded but none of the granted
    scopes name this resource — the call would not have succeeded at all
    without the security block's OR of read/write/admin being satisfied, so
    at least read-level access is a confirmed fact even if ``access`` is
    sparse.
    """
    matching = _matching(resource, scopes)
    if any(scope.action == ADMIN_ACTION for scope in matching):
        return AccessLevel.ADMIN
    if any(scope.action == WRITE_ACTION for scope in matching):
        return AccessLevel.WRITE
    return AccessLevel.READ


def granted_beyond_read(resource: str, scopes: tuple[str, ...]) -> tuple[str, ...]:
    """Granted scope names over ``resource`` whose action is write or admin."""
    return tuple(
        f"{scope.resource}:{scope.action}"
        for scope in _matching(resource, scopes)
        if scope.action in (WRITE_ACTION, ADMIN_ACTION)
    )


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, keyed by the org-level resource it needs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    path: str = Field(description="Path segment under the org, e.g. 'projects'.")
    noun: str
    detail: str
    resource: str = Field(
        description="Scope resource this endpoint's security requires."
    )
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str


_DOCS: Final = "https://docs.sentry.io/api"

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Sentry Projects",
        path="projects",
        noun="projects",
        detail="Can list the organization's projects",
        resource="org",
        risk_weight=60,
        source=f"{_DOCS}/organizations/#get-/api/0/organizations/{{organization_id_or_slug}}/projects/",
    ),
    _Probe(
        service="Sentry Members",
        path="members",
        noun="members",
        detail="Can list the organization's members, including their names and emails",
        resource="member",
        risk_weight=85,
        data_sensitive=True,
        source=f"{_DOCS}/organizations/#get-/api/0/organizations/{{organization_id_or_slug}}/members/",
    ),
    _Probe(
        service="Sentry Teams",
        path="teams",
        noun="teams",
        detail="Can list the organization's teams",
        resource="org",
        risk_weight=55,
        source=f"{_DOCS}/organizations/#get-/api/0/organizations/{{organization_id_or_slug}}/teams/",
    ),
)


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _organizations(response: ProbeResponse) -> list[dict[str, Any]]:
    body = response.json_or_none()
    if not isinstance(body, list):
        return []
    return [item for item in body if isinstance(item, dict)]


def message_of(response: ProbeResponse) -> str:
    """Sentry's error text, where it names one.

    Sentry's OpenAPI spec documents no example body for 401/403 on this
    endpoint — only "Unauthorized"/"Forbidden" as descriptions, no schema. This
    tries the ``detail`` field Django REST Framework (which Sentry's API is
    built on) conventionally uses, and degrades to nothing rather than
    inventing a shape the spec does not carry.
    """
    body = response.json_or_none()
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
    return ""


def _items(response: ProbeResponse) -> list[Any] | None:
    body = response.json_or_none()
    return body if isinstance(body, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    items = _items(response)
    if items is None:
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _identity(org: dict[str, Any], scopes: tuple[str, ...]) -> Identity:
    slug = org.get("slug")
    return Identity(
        account=slug if isinstance(slug, str) else None,
        extra={"scopes": ", ".join(scopes) if scopes else "none granted"},
    )


def _poc(ctx: ProbeContext, token: str, url: str) -> str:
    return ctx.mask(f"curl -s -H 'Authorization: Bearer {token}' '{url}'")


def _detail(probe: _Probe, scopes: tuple[str, ...]) -> str:
    beyond_read = granted_beyond_read(probe.resource, scopes)
    if beyond_read:
        return (
            f"{probe.detail}. Sentry granted {', '.join(beyond_read)}, whose "
            "action is not a read, so this credential can change this resource "
            "as well. No write was attempted"
        )
    return f"{probe.detail}. No granted scope gives more than read here"


class SentryProvider(Provider):
    """Sentry auth tokens (user and organization)."""

    name = "sentry"
    category = "monitoring"
    docs_url = "https://docs.sentry.io/api/"
    rotation_guide_url = "https://docs.sentry.io/account/auth-tokens/"

    #: No vendor-confirmed prefix for either token kind. See the module
    #: docstring; ``--provider sentry`` is the documented route.
    detectable = False

    def detect(self, key: str) -> float:
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """List organizations — the only call Sentry's spec offers with no path params.

        "For API key-based requests this will only return the organization
        that belongs to the key" (Sentry's own description), which is what
        makes this both the liveness check and the identity source.
        """
        if len(key) < MIN_TOKEN_LENGTH:
            return ValidationResult(
                valid=False,
                note="This does not look like a Sentry auth token",
            )

        response = await ctx.get(ORGANIZATIONS_URL, headers=_headers(key))
        message = message_of(response)

        if response.ok:
            organizations = _organizations(response)
            if not organizations:
                return ValidationResult(
                    valid=True,
                    note="Sentry accepted this token but granted no organizations",
                )
            scopes = scopes_of(organizations[0])
            return ValidationResult(
                valid=True,
                identity=_identity(organizations[0], scopes),
                note=_granted_note(scopes),
            )

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Sentry did not accept this token"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=False,
                note=(
                    "Sentry returned 403 for the organization list. This may "
                    "mean the token is invalid, or that it is live but was "
                    "never granted org:read, org:write or org:admin — Sentry "
                    "documents no endpoint that confirms liveness without at "
                    "least one org-level scope" + (f" ({message})" if message else "")
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Sentry's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """List organizations, then probe each org-scoped resource.

        The organization list is fetched again here rather than threaded
        through from ``validate`` — R1.4's per-run response cache means this
        costs no extra request, since it is the same idempotent GET.
        """
        if len(key) < MIN_TOKEN_LENGTH:
            return []

        headers = _headers(key)
        org_response = await ctx.get(ORGANIZATIONS_URL, headers=headers)
        if not org_response.ok:
            return []
        organizations = _organizations(org_response)
        if not organizations:
            return []

        slug = organizations[0].get("slug")
        if not isinstance(slug, str):
            return []
        scopes = scopes_of(organizations[0])

        responses = await ctx.gather(
            [
                ctx.get(f"{ORGANIZATIONS_URL}{slug}/{probe.path}/", headers=headers)
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=access_for(probe.resource, scopes),
                detail=_detail(probe, scopes),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _granted_note(scopes: tuple[str, ...]) -> str:
    if not scopes:
        return "Sentry granted this token no scopes over its own organization"
    if len(scopes) == 1:
        return "Sentry granted 1 scope over the token's organization"
    return f"Sentry granted {len(scopes)} scopes over the token's organization"
