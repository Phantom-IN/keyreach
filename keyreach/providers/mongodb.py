"""MongoDB Atlas service account credentials — roadmap R2.5.

No prior art. The token exchange, both header requirements and every path below
come from MongoDB's own Atlas Administration API documentation, and each was
verified against the live API, which answers 401 for a path that exists and 404
for one that does not.

**Atlas documents two authentication methods and keyreach implements one.**
MongoDB names them outright: "Service account access tokens (OAuth 2.0)" and
"API keys (HTTP Digest Authentication)". This plugin does the first. Digest is a
challenge-response scheme — the server's own ``WWW-Authenticate`` header carries
a nonce that has to be hashed back — which means two requests per probe and a
client nonce that must be fixed to keep runs byte-identical. It is
implementable, and it would buy coverage of the credential type MongoDB itself
describes as the older of the two. The service-account path is the current one,
is a plain OAuth2 client-credentials exchange, and reuses machinery keyreach
already has. Digest is recorded as a known gap rather than half-built.

**This is the fourth ``read_only_post``**, after PayPal (R2.1), Zoom (R2.2) and
Docker Hub (R2.4), and it rests on the same argument: the exchange creates no
cluster, stores nothing and spends nothing. MongoDB documents the resulting
token as lasting 3600 seconds.

**``detectable = False``: MongoDB publishes no format for either half.** Its
authentication pages describe a service account as having "a client ID" and "a
rotatable secret" and never say what either looks like. Reached with
``--provider mongodb``.

**Atlas requires a versioned ``Accept`` header on every request**, and pinning it
means a future default cannot change what keyreach reads — the same reason the
GitHub plugin pins ``X-GitHub-Api-Version`` and Pinecone's pins its own.

**Every capability is ``READ``.** Atlas service accounts carry project and
organization roles, and nothing keyreach can read attributes a role to the
calling credential. The detail names the gap. What the probes *do* establish is
worth having on its own: the organizations and projects a credential reaches are
the list of every cluster it could go on to touch.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import (
    AccessLevel,
    Capability,
    Identity,
    ValidationResult,
)
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

CLOUD: Final = "https://cloud.mongodb.com"

API: Final = f"{CLOUD}/api/atlas/v2"

TOKEN_URL: Final = f"{CLOUD}/api/oauth/token"

#: The body MongoDB's own curl example sends.
TOKEN_BODY: Final = "grant_type=client_credentials"  # noqa: S105 - a form body

TOKEN_SOURCE: Final = (
    "https://www.mongodb.com/docs/atlas/api/service-accounts/"  # noqa: S105 - a URL
    "generate-oauth2-token/"
)

DOCS: Final = "https://www.mongodb.com/docs/atlas/api/api-authentication/"

#: Atlas versions its API through the ``Accept`` header rather than the path.
#: Source: https://www.mongodb.com/docs/atlas/api/api-versioning/
API_VERSION: Final = "2025-03-12"

ACCEPT: Final = f"application/vnd.atlas.{API_VERSION}+json"

#: Page size for every list probe.
PAGE_SIZE: Final = "1"

_SEPARATOR: Final = ":"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Recorded so the capability detail names the question keyreach left open.
SCOPE_STATEMENT: Final = (
    "Atlas service accounts carry project and organization roles, and MongoDB "
    "publishes no endpoint saying which this credential holds, so write access "
    "is undetermined and none was attempted"
)


class Credential(NamedTuple):
    """A parsed Atlas service account: the client id and the client secret."""

    client_id: str
    client_secret: str


def parse_credential(key: str) -> Credential | None:
    """Split ``client_id:client_secret``, or ``None`` if that is not the shape.

    Split on the **first** colon, for the reason PayPal's plugin records in
    R2.1: neither half is documented as excluding one, and truncating a secret
    would produce a credential that cannot authenticate — which keyreach would
    then report as "MongoDB rejected this", a confident and wrong verdict.
    """
    client_id, separator, client_secret = key.partition(_SEPARATOR)
    if not separator or not client_id or not client_secret:
        return None
    return Credential(client_id, client_secret)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="MongoDB Atlas Organizations",
        url=f"{API}/orgs",
        params={"itemsPerPage": PAGE_SIZE},
        noun="organizations",
        detail=(
            "Can list the Atlas organizations this credential reaches, which is "
            "the top of the account it belongs to"
        ),
        risk_weight=90,
        source=DOCS,
    ),
    _Probe(
        service="MongoDB Atlas Projects",
        url=f"{API}/groups",
        params={"itemsPerPage": PAGE_SIZE},
        noun="projects",
        detail=(
            "Can list the Atlas projects this credential reaches. Each project "
            "is a set of clusters, so this is the list of every database it "
            "could go on to reach"
        ),
        risk_weight=100,
        data_sensitive=True,
        source=DOCS,
    ),
)

#: ``/groups`` is the endpoint MongoDB's own examples call, and the cheapest
#: read that proves a minted token works.
VALIDATE_SERVICE: Final = "MongoDB Atlas Projects"


def validation_probe() -> _Probe:
    """The cheapest read that proves the minted token works."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _basic(credential: Credential) -> dict[str, str]:
    """Basic auth over ``client_id:client_secret``, as MongoDB documents it."""
    raw = f"{credential.client_id}{_SEPARATOR}{credential.client_secret}".encode()
    return {
        "Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }


def _bearer(token: str) -> dict[str, str]:
    """The minted token plus the versioned ``Accept`` header Atlas requires."""
    return {"Authorization": f"Bearer {token}", "Accept": ACCEPT}


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
    """The bearer token from a successful exchange, or ``""``."""
    return _string(_payload(response), "access_token")


def message_of(response: ProbeResponse) -> str:
    """MongoDB's error text, from either of the two shapes it uses.

    The token endpoint answers OAuth-style ``{"error", "error_description"}``;
    the Atlas API answers ``{"error", "detail", "reason"}`` where ``error`` is a
    number. Both are read, and the numeric field is skipped rather than
    stringified into a note that reads like nonsense.
    """
    payload = _payload(response)
    for field in ("error_description", "detail", "errorCode", "reason", "error"):
        text = _string(payload, field)
        if text:
            return text
    return ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Atlas paginates with ``{"results": [...], "totalCount": n}``.
    """
    items = _payload(response).get("results")
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Shows the exchange as well as the read: the token lasts an hour, so
    reproducing a probe means minting one first.
    """
    return ctx.mask(
        f"TOKEN=$(curl -s -u '{ctx.key}' -X POST '{TOKEN_URL}' "
        f"-d '{TOKEN_BODY}' | jq -r .access_token); "
        f'curl -s -H "Authorization: Bearer $TOKEN" '
        f"-H 'Accept: {ACCEPT}' '{url}'"
    )


class MongoDBProvider(Provider):
    """MongoDB Atlas service account credentials."""

    name = "mongodb"
    category = "database"
    docs_url = DOCS
    rotation_guide_url = "https://www.mongodb.com/docs/atlas/configure-api-access/"

    #: MongoDB publishes no format for a service account client id or secret.
    #: See the module docstring.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``: there is no published format to match against.

        Not a stub. A rule for "any string, colon, any string" would claim every
        composite credential keyreach has ever been handed, which is the
        false-positive machine `plan.md` §5.2 rules out.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One token exchange, which is the only thing that proves the pair works."""
        credential = parse_credential(key)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "An Atlas service account is a client id and a client "
                    "secret, and only one was supplied. No request was made: a "
                    "request keyreach cannot authenticate says nothing about "
                    "whether the secret is live. Re-run as "
                    "'<client id>:<client secret>'"
                ),
            )

        ctx.protect(credential.client_secret)
        response = await _mint(credential, ctx)
        message = message_of(response)

        if response.ok and access_token(response):
            return ValidationResult(
                valid=True,
                identity=_identity(credential),
            )

        if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    "MongoDB Atlas did not accept this service account"
                    + (f" ({message})" if message else "")
                    + ". Note that Atlas also issues API keys that authenticate "
                    "with HTTP Digest, which keyreach does not implement — such "
                    "a pair is refused here whether or not it is live"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=_identity(credential),
                note=(
                    "The credential reached Atlas, which rate limited this "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "MongoDB Atlas's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Mint once, then probe every endpoint concurrently.

        The mint costs nothing beyond ``validate``'s: R2.1 put
        ``read_only_post`` responses into the per-run cache with the request
        body in the key, so the two identical exchanges reach the network once.
        """
        credential = parse_credential(key)
        if credential is None:  # pragma: no cover - `validate` stops the run first
            return []

        ctx.protect(credential.client_secret)
        minted = await _mint(credential, ctx)
        bearer = access_token(minted)
        if not bearer:
            return []
        ctx.protect(bearer)

        headers = _bearer(bearer)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
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
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _identity(credential: Credential) -> Identity:
    """The client id, which is the half that is not a secret.

    MongoDB publishes no endpoint that names the service account, so this is
    what the credential itself carries — and it is what the recipient revokes.
    """
    return Identity(account=credential.client_id)


async def _mint(credential: Credential, ctx: ProbeContext) -> ProbeResponse:
    """Exchange the service account for a bearer token.

    The fourth ``read_only_post`` in keyreach, after PayPal (R2.1), Zoom (R2.2)
    and Docker Hub (R2.4). It creates no cluster, stores nothing and spends
    nothing; MongoDB documents the result as lasting 3600 seconds. Annotated so
    the ``read_only`` guardrail forces that argument to be made in review.
    """
    return await ctx.post(
        TOKEN_URL,
        content=TOKEN_BODY,
        headers=_basic(credential),
        read_only_post=True,
    )
