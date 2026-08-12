"""Bitbucket Cloud API tokens and app passwords — roadmap R2.4.

No prior art. Every path and scope name below comes from Atlassian's own
Bitbucket Cloud OpenAPI specification (``api.bitbucket.org/swagger.json``), and
each was verified against the live API, which answers 401 for a path that exists
and 404 for one that does not.

**``detectable = False``: Atlassian publishes no format for either credential.**
The API-token guide describes how to send one — "the API token, along with the
user's Atlassian account email, can be sent as login credentials" — and never
says what one looks like. Neither does the specification, which describes the
scheme as plain HTTP basic. So a rule could only come from a guess, and
``--provider bitbucket`` is the route; the report records that the operator
asserted the provider.

**The credential is two halves, and the first half is a person's email
address.** Bitbucket authenticates with basic auth over
``<atlassian email>:<api token>`` — or ``<username>:<app password>`` for the
older form, which Atlassian is retiring. keyreach takes them colon-joined and
registers **only the second half** with the redactor: an email address is not a
secret, it is the identity the report exists to name, and masking it would make
the finding useless to whoever receives it. The token half is protected, and
``/user/emails`` echoing the address back is exactly why R1.3 added
``ctx.protect`` for parts rather than wholes.

**Every capability is ``READ``, and Bitbucket is the reason.** Its
specification documents a full scope vocabulary — ``repository`` is "Read your
repositories", ``repository:write`` is "Read and modify your repositories",
``repository:admin`` is "Administer your repositories" — and documents no way to
ask which scopes the calling credential holds. GitHub sends ``X-OAuth-Scopes``,
GitLab and SendGrid expose an introspection resource; Bitbucket does neither, so
the vocabulary that would justify a write exists and cannot be attributed. That
is the same position Mailgun's plugin takes in R2.3 and Docker Hub's takes in
this item.

**Two probes are avoided on purpose.** ``/repositories``,
``/workspaces`` and ``/user/permissions/*`` all still answer, and Atlassian's
own specification marks every one of them deprecated with a named replacement.
Probing a deprecated endpoint buys a finding that will disappear without notice,
which is the drift **R2.10** exists to catch rather than to create.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

API: Final = "https://api.bitbucket.org/2.0"

SPEC: Final = "https://developer.atlassian.com/cloud/bitbucket/rest/intro/"

#: Page size for every list probe. Bitbucket spells it ``pagelen``.
PAGE_SIZE: Final = "1"

_SEPARATOR: Final = ":"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Quoted from the ``oauth2`` scope descriptions in Bitbucket's own
#: specification, and recorded so the capability detail can say precisely what
#: keyreach could not determine.
SCOPE_STATEMENT: Final = (
    "Bitbucket documents repository, repository:write and repository:admin as "
    "separate scopes but publishes no way to ask which of them this credential "
    "holds, so write access is undetermined and none was attempted"
)


class Credential(NamedTuple):
    """A parsed Bitbucket credential: the account identifier and the secret."""

    identifier: str
    secret: str


def parse_credential(key: str) -> Credential | None:
    """Split ``<email or username>:<token>``, or ``None`` if that is not the shape.

    Split on the **first** colon. An Atlassian account email cannot contain one
    and nothing published rules one out of the token, so this keeps a token with
    a colon intact — the same reasoning PayPal's plugin records in R2.1.
    """
    identifier, separator, secret = key.partition(_SEPARATOR)
    if not separator or not identifier or not secret:
        return None
    return Credential(identifier, secret)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    collection: str | None = Field(
        default=None,
        description="Response field holding the list, for the evidence count.",
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    scope: str = Field(description="Bitbucket scope this endpoint requires.")
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Bitbucket Account",
        url=f"{API}/user",
        noun="account",
        detail=(
            "Can authenticate to Bitbucket and read the account's display name, "
            "UUID and account id"
        ),
        scope="account",
        risk_weight=60,
        source=(
            "https://developer.atlassian.com/cloud/bitbucket/rest/"
            "api-group-users/#api-user-get"
        ),
    ),
    _Probe(
        service="Bitbucket Email Addresses",
        url=f"{API}/user/emails",
        params={"pagelen": PAGE_SIZE},
        collection="values",
        noun="email addresses",
        detail=(
            "Can list the account's email addresses, confirmed and unconfirmed, "
            "which is the address an attacker would target for a password reset"
        ),
        scope="email",
        risk_weight=80,
        data_sensitive=True,
        source=(
            "https://developer.atlassian.com/cloud/bitbucket/rest/"
            "api-group-users/#api-user-emails-get"
        ),
    ),
    _Probe(
        service="Bitbucket Workspaces",
        url=f"{API}/user/workspaces",
        params={"pagelen": PAGE_SIZE},
        collection="values",
        noun="workspaces",
        detail=(
            "Can list the workspaces this credential reaches, and Bitbucket "
            "states this response also says whether the caller has admin "
            "permissions on each one"
        ),
        scope="account",
        risk_weight=85,
        data_sensitive=True,
        source=(
            "https://developer.atlassian.com/cloud/bitbucket/rest/"
            "api-group-workspaces/#api-user-workspaces-get"
        ),
    ),
)

#: ``/user`` is the cheapest read that proves the credential works and lists
#: nobody's address.
VALIDATE_SERVICE: Final = "Bitbucket Account"


def validation_probe() -> _Probe:
    """The cheapest read that proves the credential is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _basic(credential: Credential) -> dict[str, str]:
    """Basic auth over ``identifier:secret``, as Atlassian documents it."""
    raw = f"{credential.identifier}{_SEPARATOR}{credential.secret}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Bitbucket's error message, or ``""``.

    Errors arrive as ``{"type": "error", "error": {"message": …}}``.
    """
    error = _payload(response).get("error")
    if not isinstance(error, dict):
        return ""
    message = error.get("message")
    return message if isinstance(message, str) else ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    if probe.collection is None:
        return "request accepted"
    items = _payload(response).get(probe.collection)
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(credential: Credential, response: ProbeResponse) -> Identity:
    """Who Bitbucket says this is.

    The identifier is included because it is half the credential and is not a
    secret — it is the account the recipient has to go and lock.
    """
    payload = _payload(response)
    extra = {"identifier": credential.identifier}
    for field in ("nickname", "account_status", "uuid"):
        value = _string(payload, field)
        if value:
            extra[field] = value

    return Identity(
        account=_string(payload, "account_id") or None,
        owner=_string(payload, "display_name") or None,
        extra=extra,
    )


def _poc(ctx: ProbeContext, credential: Credential, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Uses ``-u`` rather than a base64 header so the reproduction is legible and
    the masked secret is visible as a secret — the same choice Zoom's and
    Mailchimp's plugins make.
    """
    return ctx.mask(f"curl -s -u '{credential.identifier}:{credential.secret}' '{url}'")


class BitbucketProvider(Provider):
    """Bitbucket Cloud API tokens and app passwords."""

    name = "bitbucket"
    category = "devtools"
    docs_url = "https://developer.atlassian.com/cloud/bitbucket/rest/intro/"
    rotation_guide_url = (
        "https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/"
    )

    #: Atlassian publishes no prefix, length or charset for either an API token
    #: or an app password. See the module docstring.
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
        """One read of ``/user``, the cheapest read that names nobody else."""
        credential = parse_credential(key)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "Bitbucket authenticates with basic auth over an account "
                    "identifier and a secret, and only one was supplied. No "
                    "request was made: a request keyreach cannot authenticate "
                    "says nothing about whether the secret is live. Re-run as "
                    "'<atlassian email or username>:<api token>'"
                ),
            )

        # Only the secret. The identifier is an email address or a username —
        # not a secret, and the thing a disclosure report exists to name.
        ctx.protect(credential.secret)

        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_basic(credential))
        message = message_of(response)

        if response.ok:
            return ValidationResult(
                valid=True, identity=_identity(credential, response)
            )

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Bitbucket did not accept this identifier and secret"
                    + (f" ({message})" if message else "")
                    + ". Bitbucket rejects a wrong identifier and a dead secret "
                    "the same way, so check the account name or email before "
                    "concluding the secret is revoked"
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential is live; Bitbucket refused this endpoint"
                    + (f" ({message})" if message else "")
                    + ". The capabilities below are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential is live; Bitbucket rate limited this "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Bitbucket's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered."""
        credential = parse_credential(key)
        if credential is None:  # pragma: no cover - `validate` stops the run first
            return []

        ctx.protect(credential.secret)
        headers = _basic(credential)
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
                detail=(
                    f"{probe.detail}. Confirms the {probe.scope} scope. "
                    f"{SCOPE_STATEMENT}"
                ),
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
