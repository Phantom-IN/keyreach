"""Docker Hub access tokens (``dckr_pat_…``, ``dckr_oat_…``) — roadmap R2.4.

No prior art. Every path, parameter and both token prefixes below come from
Docker's own OpenAPI specification for the Hub API, and each probe cites it.

**Docker publishes its token prefixes in exactly one place, and it is not the
page about tokens.** The prose access-token pages document three permission
levels and no format at all. The OpenAPI specification examples the auth
request's ``secret`` field as ``dckr_pat_…`` and the organization-token
response's ``token`` field as ``dckr_oat_…``. A machine-readable specification
the vendor publishes and generates its own documentation from is a primary
source, so this provider is detectable where Bitbucket and npm — whose vendors
publish neither prose nor specification for their formats — are not.

**The credential is two halves, because Docker's token exchange requires two.**
The specification says the ``identifier`` "must be a username" for a personal
access token and "must be an organization name" for an organization access
token. So keyreach takes ``identifier:token``, and a bare token is recognised,
reported and explicitly **not** probed — the same treatment a bare AWS access
key id gets in R1.3. Guessing a username would produce a confident "Docker
rejected this" about a live credential.

**The prefix decides which probe table runs**, on Docker's own sentence above.
A ``dckr_pat_`` identifier names a user and a ``dckr_oat_`` one names an
organization, so probing an organization's members with a personal token would
be a 404 keyreach could have predicted — wasted authentication traffic against
somebody's production service, which ``plan.md`` §11 counts as a real cost.

**This is the third ``read_only_post`` in keyreach**, after PayPal (R2.1) and
Zoom (R2.2), and it rests on the same argument: the exchange creates no
resource, moves nothing and pushes no image. It returns a JWT that Docker
documents as expiring in ten minutes.

**Every capability is ``READ``, and the reason is specific.** Docker documents
personal access token scopes — ``repo:admin``, ``repo:write``, ``repo:read``,
``repo:public_read`` — and publishes no endpoint that says which of them *this*
token holds. ``/v2/access-tokens`` lists the account's tokens with their scopes
but does not mark which entry is the one asking. So the scope vocabulary exists
and is not attributable, and keyreach reports what it proved. The same position
Mailgun's plugin takes in R2.3, for the same reason.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential format
# --------------------------------------------------------------------------
#
# Mirrors the `dockerhub-access-token` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_dockerhub.py`
# asserts the two agree.
# Source: https://docs.docker.com/reference/api/hub/latest/

#: The token half on its own. Both prefixes are exampled in Docker's OpenAPI
#: specification; neither appears on any prose page Docker publishes.
_TOKEN: Final = r"dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}"  # noqa: S105 - a regex

#: The whole credential: an optional `identifier:` and the token.
_PATTERN: Final = re.compile(rf"^(?:[A-Za-z0-9][A-Za-z0-9._-]*:)?{_TOKEN}$")

#: The token alone, which is recognised and deliberately not probed.
_BARE_PATTERN: Final = re.compile(rf"^{_TOKEN}$")

CONFIDENCE: Final = 0.99

_SEPARATOR: Final = ":"


class Kind(StrEnum):
    """Which kind of token this is, from its documented prefix.

    Load-bearing rather than decorative: Docker's specification says the
    ``identifier`` accompanying a personal token is a username and the one
    accompanying an organization token is an organization name, so the prefix
    decides what the other half *is*.
    """

    PERSONAL = "personal"
    ORGANIZATION = "organization"


_PERSONAL_PREFIX: Final = "dckr_pat_"


def kind_of(token: str) -> Kind:
    """Personal or organization, from the documented prefix."""
    return Kind.PERSONAL if token.startswith(_PERSONAL_PREFIX) else Kind.ORGANIZATION


class Credential(NamedTuple):
    """A parsed Docker Hub credential: the identifier and the token."""

    identifier: str
    token: str

    @property
    def kind(self) -> Kind:
        return kind_of(self.token)


def parse_credential(key: str) -> Credential | None:
    """Split ``identifier:token``, or ``None`` when the identifier is missing.

    Split on the **last** colon, not the first: Docker's identifiers are
    usernames and organization names, which cannot contain a colon, while
    nothing published rules one out of the token. Splitting the other way would
    silently truncate a token into a credential that cannot authenticate, and
    keyreach would then report "Docker rejected this" — a confident, wrong
    verdict, which is the failure PayPal's plugin avoided the mirror image of in
    R2.1.
    """
    identifier, separator, token = key.rpartition(_SEPARATOR)
    if not separator or not identifier or not _BARE_PATTERN.match(token):
        return None
    return Credential(identifier, token)


# --------------------------------------------------------------------------
# The token exchange
# --------------------------------------------------------------------------

HUB: Final = "https://hub.docker.com"

TOKEN_URL: Final = f"{HUB}/v2/auth/token"

TOKEN_SOURCE: Final = (
    "https://docs.docker.com/reference/api/hub/latest/"  # noqa: S105 - a URL
)

#: Page size for every list probe. Docker spells it ``page_size``.
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_NOT_FOUND: Final = 404
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Docker's documented scope vocabulary for a personal access token, recorded
#: so the capability detail can say what keyreach could *not* determine.
#: Source: the `createAccessTokenRequest` schema — "Valid scopes: "repo:admin",
#: "repo:write", "repo:read", "repo:public_read"".
SCOPE_STATEMENT: Final = (
    "Docker documents personal access token scopes as repo:admin, repo:write, "
    "repo:read and repo:public_read, and publishes no endpoint saying which of "
    "them this token holds, so write access is undetermined and none was "
    "attempted"
)


def token_body(credential: Credential) -> str:
    """The exchange request body, exactly as Docker's specification defines it.

    Serialised here rather than handed to the client as a mapping so that the
    bytes on the wire are fixed: the per-run cache keys a ``read_only_post`` on
    its body (R2.1), and two spellings of the same request would mint twice.
    """
    return json.dumps(
        {"identifier": credential.identifier, "secret": credential.token},
        separators=(",", ":"),
        sort_keys=True,
    )


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    kind: Kind | None = Field(
        default=None,
        description="Token kind this probe applies to; None means both.",
    )
    path: str = Field(description="Path template; {name} is the identifier.")
    params: dict[str, str] = Field(default_factory=dict)
    collection: str | None = Field(
        default=None,
        description="Response field holding the list, for the evidence count.",
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Docker Hub Organization Members",
        kind=Kind.ORGANIZATION,
        path="/v2/orgs/{name}/members",
        noun="members",
        detail=(
            "Can list the organization's members, which are the named people "
            "who can publish under this namespace"
        ),
        risk_weight=85,
        data_sensitive=True,
        source=TOKEN_SOURCE,
    ),
    _Probe(
        service="Docker Hub Organization Settings",
        kind=Kind.ORGANIZATION,
        path="/v2/orgs/{name}/settings",
        noun="settings",
        detail="Can read the organization's settings",
        risk_weight=70,
        source=TOKEN_SOURCE,
    ),
    _Probe(
        service="Docker Hub Organization Tokens",
        kind=Kind.ORGANIZATION,
        path="/v2/orgs/{name}/access-tokens",
        params={"page_size": PAGE_SIZE},
        collection="results",
        noun="organization access tokens",
        detail=(
            "Can list the organization's other access tokens, including their "
            "labels and who created each one"
        ),
        risk_weight=90,
        data_sensitive=True,
        source=TOKEN_SOURCE,
    ),
    _Probe(
        service="Docker Hub Personal Tokens",
        kind=Kind.PERSONAL,
        path="/v2/access-tokens",
        params={"page_size": PAGE_SIZE},
        collection="results",
        noun="personal access tokens",
        detail=(
            "Can list the account's other personal access tokens, including "
            "their labels and the scopes each one holds"
        ),
        risk_weight=90,
        data_sensitive=True,
        source=TOKEN_SOURCE,
    ),
    _Probe(
        service="Docker Hub Repositories",
        path="/v2/namespaces/{name}/repositories",
        params={"page_size": PAGE_SIZE},
        collection="results",
        noun="repositories",
        detail=(
            "Can list the namespace's repositories, including private ones, "
            "which are the images this account ships"
        ),
        risk_weight=95,
        # A private image list is the shape of somebody's internal estate, and
        # each entry is pullable by the same credential.
        data_sensitive=True,
        source=TOKEN_SOURCE,
    ),
)


def probes_for(kind: Kind) -> tuple[_Probe, ...]:
    """The probes a token of this kind can reach.

    Filtered on Docker's own statement that the identifier is a username for a
    personal token and an organization name for an organization token — so the
    other table's paths would 404 by construction.
    """
    return tuple(probe for probe in PROBES if probe.kind in (None, kind))


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def access_token(response: ProbeResponse) -> str:
    """The short-lived JWT from a successful exchange, or ``""``."""
    return _string(_payload(response), "access_token")


def message_of(response: ProbeResponse) -> str:
    """Docker's error message, or ``""``.

    A rejected credential returns ``{"message": "unauthorized", "errinfo": {}}``,
    verified against the live API.
    """
    for field in ("message", "detail"):
        text = _string(_payload(response), field)
        if text:
            return text
    return ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    body = response.json_or_none()
    items = (
        _payload(response).get(probe.collection)
        if probe.collection is not None
        else body
    )
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _identity(credential: Credential) -> Identity:
    """The identifier and the token kind, which is what Docker discloses.

    Docker's Hub API publishes no "who am I" endpoint in its specification, so
    there is nothing to read. The identifier is already in the credential, and
    the kind is the fact that matters most: an organization token reaches a
    whole company's namespace.
    """
    return Identity(
        account=credential.identifier, extra={"token_type": credential.kind.value}
    )


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Shows the exchange rather than the probe's own bearer header: the JWT is
    short-lived and reproducing the probe means minting a fresh one, so the
    useful reproduction is the whole two-step.
    """
    return ctx.mask(
        f"TOKEN=$(curl -s -X POST '{TOKEN_URL}' "
        "-H 'Content-Type: application/json' "
        f'-d \'{{"identifier":"{ctx.key}"}}\' | jq -r .access_token); '
        f"curl -s -H \"Authorization: Bearer $TOKEN\" '{url}'"
    )


class DockerHubProvider(Provider):
    """Docker Hub personal and organization access tokens."""

    name = "dockerhub"
    category = "devtools"
    docs_url = "https://docs.docker.com/reference/api/hub/latest/"
    rotation_guide_url = "https://docs.docker.com/security/access-tokens/"

    def detect(self, key: str) -> float:
        """Pure structural match against the two prefixes Docker's spec examples."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One token exchange, which is the only thing that proves the pair works."""
        credential = parse_credential(key)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This is a Docker Hub access token with no identifier. "
                    "Docker's token exchange requires the account or "
                    "organization name alongside it, so no request was made — "
                    "guessing a name would produce a rejection that says "
                    "nothing about whether the token is live. Re-run as "
                    "'<identifier>:<token>'"
                ),
            )

        ctx.protect(credential.token)
        response = await _mint(credential, ctx)
        message = message_of(response)

        if response.ok and access_token(response):
            return ValidationResult(valid=True, identity=_identity(credential))

        if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    "Docker Hub did not accept this identifier and token"
                    + (f" ({message})" if message else "")
                    + ". Docker rejects a wrong identifier and a dead token the "
                    "same way, so check the name before concluding the token is "
                    "revoked"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=_identity(credential),
                note=(
                    "The credential reached Docker Hub, which rate limited this "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Docker Hub's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Mint once, then probe only the paths this kind of token can reach.

        The mint costs nothing beyond ``validate``'s: R2.1 put
        ``read_only_post`` responses into the per-run cache with the request
        body in the key, so the two identical exchanges reach the network once.
        """
        credential = parse_credential(key)
        if credential is None:  # pragma: no cover - `validate` stops the run first
            return []

        ctx.protect(credential.token)
        minted = await _mint(credential, ctx)
        bearer = access_token(minted)
        if not bearer:
            return []
        ctx.protect(bearer)

        probes = probes_for(credential.kind)
        headers = _bearer(bearer)
        responses = await ctx.gather(
            [
                ctx.get(
                    f"{HUB}{probe.path.format(name=credential.identifier)}",
                    params=probe.params or None,
                    headers=headers,
                )
                for probe in probes
            ]
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
            for probe, response in zip(probes, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


async def _mint(credential: Credential, ctx: ProbeContext) -> ProbeResponse:
    """Exchange the credential for a short-lived bearer token.

    The third ``read_only_post`` in keyreach, after PayPal (R2.1) and Zoom
    (R2.2). It creates no repository, pushes no image and moves nothing; Docker
    documents the result as expiring in ten minutes. Annotated so the
    ``read_only`` guardrail forces that argument to be made in review.
    """
    return await ctx.post(
        TOKEN_URL,
        content=token_body(credential),
        headers={"Content-Type": "application/json"},
        read_only_post=True,
    )
