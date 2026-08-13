"""Redis Cloud REST API keys — roadmap R2.5.

No prior art. Both header names and the two-key scheme below come from Redis's
own documentation, and every path was verified against the live API, which
answers 401 for a path that exists and 404 for one that does not.

**This is Redis Cloud's control plane, not a Redis server.** The roadmap says
"Redis", and the honest reading is narrower than it sounds. A Redis *server*
credential is a password spoken over RESP on port 6379 — not HTTP, so it cannot
go through ``ProbeContext`` at all, and keyreach's whole I/O layer is HTTP
(``implementation_plan.md`` §6). What this plugin covers is the credential pair
that manages Redis Cloud subscriptions and databases through
``api.redislabs.com``, which is the thing that actually leaks out of CI
configuration. The module docstring says so rather than letting the provider
name imply more.

**``detectable = False``: Redis publishes no format for either key.** Its
key-management guide describes what each key *is* — "the **Account key**
identifies the account associated with the Redis Cloud subscription", "**API
user keys** (also known as _secret keys_)" — and never what one looks like.
Reached with ``--provider redis``.

**The credential is two halves and both are secret.** Redis documents
``x-api-key`` for the account key and ``x-api-secret-key`` for the user key, and
both must be present on every request. keyreach takes them colon-joined and
**registers both with the redactor** — unlike Bitbucket in R2.4, where the first
half is an email address and is the identity the report exists to name. Here
neither half is an identity and neither is safe to print.

**Redis answers 401 with an nginx HTML page, not JSON.** Verified against the
live API. So the rejection note quotes nothing, and the parsing here does not
assume a structured body.

**Every capability is ``READ``, and Redis names the roles it will not attribute.**
Its documentation lists owner (read-write), viewer (read-only), billing admin
and logs viewer, and publishes no endpoint that says which role the calling key
holds. Fourth provider in three items to take that position.

**CIDR allow lists are why ``restricted`` exists.** Redis documents a per-key
CIDR allow list, so a leaked pair may be unusable from anywhere but the
account's own addresses. keyreach cannot see that list without reading it from
somewhere it has no endpoint for, so it does not claim the restriction — it says
in the detail that one may apply, which is the honest version of a flag it
cannot set.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

API: Final = "https://api.redislabs.com/v1"

DOCS: Final = "https://redis.io/docs/latest/operate/rc/api/get-started/manage-api-keys/"

_SEPARATOR: Final = ":"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Recorded so the capability detail names both questions keyreach left open.
SCOPE_STATEMENT: Final = (
    "Redis documents owner, viewer, billing admin and logs viewer roles and "
    "publishes no endpoint saying which this key holds, so write access is "
    "undetermined and none was attempted. A per-key CIDR allow list may also "
    "restrict where these keys work, which keyreach cannot read"
)


class Credential(NamedTuple):
    """A parsed Redis Cloud credential: the account key and the secret key."""

    account_key: str
    secret_key: str


def parse_credential(key: str) -> Credential | None:
    """Split ``<account key>:<secret key>``, or ``None`` if that is not the shape.

    Split on the **first** colon. Redis publishes no format for either half, so
    nothing rules a colon out of the second one, and splitting the other way
    would silently truncate the account key into a credential that cannot
    authenticate — which keyreach would then report as "Redis rejected this".
    """
    account_key, separator, secret_key = key.partition(_SEPARATOR)
    if not separator or not account_key or not secret_key:
        return None
    return Credential(account_key, secret_key)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
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
        service="Redis Cloud Account",
        url=f"{API}/",
        noun="account",
        detail="Can authenticate to the Redis Cloud API and read the account",
        risk_weight=60,
        source=DOCS,
    ),
    _Probe(
        service="Redis Cloud Cloud Accounts",
        url=f"{API}/cloud-accounts",
        collection="cloudAccounts",
        noun="cloud accounts",
        detail=(
            "Can list the cloud provider accounts Redis deploys into, which "
            "names the AWS or GCP accounts behind these databases"
        ),
        risk_weight=85,
        data_sensitive=True,
        source=DOCS,
    ),
    _Probe(
        service="Redis Cloud Subscriptions",
        url=f"{API}/subscriptions",
        collection="subscriptions",
        noun="subscriptions",
        detail=(
            "Can list the account's subscriptions, which is every Redis "
            "deployment this account pays for, with its regions and providers"
        ),
        risk_weight=95,
        data_sensitive=True,
        source=DOCS,
    ),
)

#: ``/subscriptions`` is the cheapest read that requires both keys and proves
#: the pair works. The bare root is a probe rather than the liveness check
#: because Redis does not document what it returns.
VALIDATE_SERVICE: Final = "Redis Cloud Subscriptions"


def validation_probe() -> _Probe:
    """The cheapest documented read that proves the pair is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(credential: Credential) -> dict[str, str]:
    """Both headers Redis documents, which are both required.

    "The **API account key** is used as the value of the `x-api-key` HTTP
    header"; "**API user keys** … are used as the value of the
    `x-api-secret-key` HTTP header".
    """
    return {
        "x-api-key": credential.account_key,
        "x-api-secret-key": credential.secret_key,
    }


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Load-bearing rather than paranoid: Redis answers 401 with an nginx HTML
    page, so this returns an empty mapping on the path keyreach hits most.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Redis's error message, or ``""``.

    Usually ``""`` — the 401 is an HTML page — which is why the rejection note
    below does not depend on it.
    """
    for field in ("description", "message", "error"):
        value = _payload(response).get(field)
        if isinstance(value, str):
            return value
    return ""


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


def _poc(ctx: ProbeContext, credential: Credential, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    return ctx.mask(
        f"curl -s -H 'x-api-key: {credential.account_key}' "
        f"-H 'x-api-secret-key: {credential.secret_key}' '{url}'"
    )


class RedisProvider(Provider):
    """Redis Cloud REST API key pairs."""

    name = "redis"
    category = "database"
    docs_url = "https://redis.io/docs/latest/operate/rc/api/get-started/"
    rotation_guide_url = DOCS

    #: Redis publishes no format for the account key or the secret key. See the
    #: module docstring.
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
        """One read of ``/subscriptions``, which requires both halves."""
        credential = parse_credential(key)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "The Redis Cloud API requires an account key and a secret "
                    "key on every request, and only one was supplied. No "
                    "request was made: a request keyreach cannot authenticate "
                    "says nothing about whether either key is live. Re-run as "
                    "'<account key>:<secret key>'"
                ),
            )

        # Both halves. Unlike Bitbucket's, neither of these is an identity.
        ctx.protect(credential.account_key)
        ctx.protect(credential.secret_key)

        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(credential))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True)

        if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    "Redis Cloud did not accept this key pair"
                    + (f" ({message})" if message else "")
                    + ". Redis refuses a wrong account key, a wrong secret key "
                    "and a caller outside the key's CIDR allow list the same "
                    "way, so this is not on its own evidence that either key is "
                    "revoked"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key pair is live; Redis Cloud rate limited this "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Redis Cloud's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key pair's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered."""
        credential = parse_credential(key)
        if credential is None:  # pragma: no cover - `validate` stops the run first
            return []

        ctx.protect(credential.account_key)
        ctx.protect(credential.secret_key)
        headers = _auth(credential)
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
                poc=_poc(ctx, credential, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
