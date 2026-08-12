"""Resend API keys (``re_…``) — roadmap R2.3.

No prior art. Every path and error name below was written from Resend's own
documentation, and the status codes were then checked against Resend's live API,
which is how the finding in the next paragraph turned up.

**Resend answers 401 for a key that works and 400 for one that does not, and
both of those contradict something.** Resend documents ``restricted_api_key`` as
a **401** with the message "This API key is restricted to only send emails" —
that is a *live* key being told it may not read this resource. It documents
``invalid_api_key`` as a **403**. Against the live API a bad key actually comes
back **400 ``validation_error``**, message "API key is invalid".

So the ordinary reading — 401 means the credential is bad — is wrong here in the
most expensive direction available: it would retire a working key that can send
mail as the account, and report it as dead. This plugin therefore branches on
Resend's ``name`` field, which is a contract, and treats the status as
corroboration. ``tests/test_provider_resend.py`` pins both halves, including the
documented-versus-observed status gap, so a later "cleanup" that trusts the
documentation alone fails instead of silently mis-reporting.

**That same 401 is how keyreach reports a sending key without sending mail.**
Resend documents exactly two permission levels — ``full_access`` ("can create,
delete, get, and update any resource") and ``sending_access`` ("can only send
emails") — and does not return either from any read endpoint. But the two are
distinguishable by what the API says: a key refused with ``restricted_api_key``
is, in Resend's own words, restricted to sending. That is a vendor statement
that the key can send email, obtained from a refusal, and it is the only
capability here that sets ``incurs_cost``.

**A key that reads ``/api-keys`` is ``full_access`` by Resend's definition**, and
``full_access`` is documented as covering create, delete and update over every
resource. So the access levels here are ``WRITE`` — with key management as
``ADMIN``, since a key that mints keys outlives its own revocation — on the
strength of the vendor's sentence rather than of a write keyreach performed. The
same line the Stripe plugin draws around "unrestricted permissions" in R1.6.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Key format
# --------------------------------------------------------------------------
#
# Mirrors the `resend-api-key` rule in `keyreach/patterns/detection_rules.yml`;
# `tests/test_provider_resend.py` asserts the two agree.
#
# Source: the create-API-key response example, which is the only place Resend
# publishes what a key looks like.
# https://resend.com/docs/api-reference/api-keys/create-api-key

_PATTERN: Final = re.compile(r"^re_[A-Za-z0-9_]{16,}$")

#: 0.95: a unique prefix with a body Resend states no length for.
CONFIDENCE: Final = 0.95


# --------------------------------------------------------------------------
# Resend's error vocabulary
# --------------------------------------------------------------------------
#
# Errors arrive as {"statusCode": int, "message": str, "name": str}. The `name`
# is the contract; the status is not, for the reasons in the module docstring.
# Source: https://resend.com/docs/api-reference/errors

#: The key is **live** and Resend is saying it may only send email. Documented
#: at 401 with "This API key is restricted to only send emails".
RESTRICTED_ERROR: Final = "restricted_api_key"

#: The key is not, or is no longer, a key. `invalid_api_key` and
#: `missing_api_key` are documented; `validation_error` is what the live API
#: actually returns for a bad key, at 400.
DEAD_KEY_ERRORS: Final[frozenset[str]] = frozenset(
    {"invalid_api_key", "missing_api_key", "validation_error"}
)

_HTTP_BAD_REQUEST: Final = 400
_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Statuses that mean "Resend refused this credential", covering the documented
#: 403 and the 400 the API really uses.
_REJECTED_STATUSES: Final[frozenset[int]] = frozenset(
    {_HTTP_BAD_REQUEST, _HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}
)


# --------------------------------------------------------------------------
# Permission levels
# --------------------------------------------------------------------------
#
# Resend documents exactly two, and returns neither from any read endpoint:
#
#   full_access     "Can create, delete, get, and update any resource."
#   sending_access  "Can only send emails."
#
# Source: https://resend.com/docs/api-reference/api-keys/create-api-key

#: Resend's own words for what a `full_access` key may do, quoted into the
#: capability detail so a reader can check the inference rather than trust it.
FULL_ACCESS_STATEMENT: Final = (
    "Resend documents this permission level as able to create, delete, get and "
    "update any resource"
)


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.resend.com"


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    admin: bool = Field(
        default=False,
        description=(
            "Is a write over this resource administration of the account "
            "itself, rather than of one of its records?"
        ),
    )
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Resend API Keys",
        url=f"{API}/api-keys",
        noun="API keys",
        detail=(
            "Can list the account's other API keys, including their names and "
            "when each was last used"
        ),
        # Creating an API key is administering the account: a key that can mint
        # keys outlives its own revocation.
        admin=True,
        risk_weight=90,
        source="https://resend.com/docs/api-reference/api-keys/list-api-keys",
    ),
    _Probe(
        service="Resend Audiences",
        url=f"{API}/audiences",
        noun="audiences",
        detail=(
            "Can list the account's audiences, which are the contact lists its "
            "marketing email is sent to"
        ),
        risk_weight=85,
        # An audience is a list of real people who gave this company an address.
        data_sensitive=True,
        source="https://resend.com/docs/api-reference/audiences/list-audiences",
    ),
    _Probe(
        service="Resend Broadcasts",
        url=f"{API}/broadcasts",
        noun="broadcasts",
        detail="Can list the account's broadcasts, including their subject lines",
        risk_weight=70,
        source="https://resend.com/docs/api-reference/broadcasts/list-broadcasts",
    ),
    _Probe(
        service="Resend Domains",
        url=f"{API}/domains",
        noun="domains",
        detail=(
            "Can list the account's verified sending domains, which are the "
            "domains this key's mail is trusted to come from"
        ),
        risk_weight=80,
        source="https://resend.com/docs/api-reference/domains/list-domains",
    ),
)

#: ``/api-keys`` is the validation endpoint for a reason beyond cheapness: it is
#: the resource a ``sending_access`` key is documented to be refused, so the
#: refusal itself establishes what the key is.
VALIDATE_SERVICE: Final = "Resend API Keys"


def validation_probe() -> _Probe:
    """The cheapest read, chosen so that its refusal is also informative."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """Bearer auth, as Resend documents it.

    Source: https://resend.com/docs/api-reference/introduction
    """
    return {"Authorization": f"Bearer {key}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def error_of(response: ProbeResponse) -> str:
    """Resend's documented error name, or ``""``."""
    value = _payload(response).get("name")
    return value if isinstance(value, str) else ""


def message_of(response: ProbeResponse) -> str:
    """Resend's human-readable message, or ``""``."""
    value = _payload(response).get("message")
    return value if isinstance(value, str) else ""


def is_restricted(response: ProbeResponse) -> bool:
    """Is this Resend saying "live key, sending only"?

    Checked on the ``name`` field rather than the 401, because 401 is also what
    an ordinary reading would call a dead credential — and here it is the
    opposite. See the module docstring.
    """
    return error_of(response) == RESTRICTED_ERROR


def rejected(response: ProbeResponse) -> bool:
    """Did Resend refuse the credential itself?

    A restricted key is explicitly not rejected: it is live and it can send.
    """
    if is_restricted(response):
        return False
    return (
        error_of(response) in DEAD_KEY_ERRORS
        or response.status_code in _REJECTED_STATUSES
    )


def _count(response: ProbeResponse) -> int | None:
    """How many records ``data`` held, when it held a list."""
    data = _payload(response).get("data")
    return len(data) if isinstance(data, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    found = _count(response)
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _identity(*, full_access: bool) -> Identity:
    """The permission level, which is what Resend discloses about the key.

    Resend publishes no "who am I" endpoint, so there is no account name to
    report. The permission level is the fact that matters most to a recipient
    anyway: one of these keys can rewrite the account, and the other can only
    send mail as it.
    """
    return Identity(
        extra={"permission": "full_access" if full_access else "sending_access"}
    )


def _poc(ctx: ProbeContext, key: str, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(key).items())
    )
    return ctx.mask(f"curl -s{headers} '{url}'")


def _send_capability(
    ctx: ProbeContext, key: str, response: ProbeResponse, *, restricted: bool
) -> Capability:
    """The capability derived from Resend's own words, never from a send.

    Reached two ways. A ``sending_access`` key gets here from the refusal that
    says so verbatim; a ``full_access`` key gets here because Resend documents
    that level as covering every resource, which includes sending. Neither path
    puts a message in anybody's inbox.
    """
    origin = (
        "Resend refused a read with restricted_api_key, whose documented "
        'message is "This API key is restricted to only send emails"'
        if restricted
        else FULL_ACCESS_STATEMENT
    )
    return Capability(
        service="Resend Email Send",
        access=AccessLevel.WRITE,
        detail=(
            "Can send email as this account, over its verified sending domains "
            f"and their SPF and DKIM records. {origin}. No message was sent: "
            "this is Resend's own statement of the key's permissions"
        ),
        evidence=response.evidence(
            f"permission level: {'sending_access' if restricted else 'full_access'}"
        ),
        risk_weight=100,
        # Every message spends the account's plan allowance.
        incurs_cost=True,
        poc=_poc(ctx, key, validation_probe().url),
        resource_ref="https://resend.com/docs/api-reference/emails/send-email",
    )


class ResendProvider(Provider):
    """Resend API keys."""

    name = "resend"
    category = "email"
    docs_url = "https://resend.com/docs/api-reference/introduction"
    rotation_guide_url = "https://resend.com/docs/dashboard/api-keys/introduction"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``re_`` prefix."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/api-keys``, whose refusal is as informative as its answer.

        The ordering matters: ``restricted_api_key`` is a 401, and a plugin that
        checked the status before the error name would report a live sending key
        as dead. That is the single most expensive mistake available here, so it
        is the first branch.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(full_access=True))

        if is_restricted(response):
            return ValidationResult(
                valid=True,
                identity=_identity(full_access=False),
                note=(
                    "The key is live and restricted to sending email, which is "
                    "Resend's own description of it. Read endpoints are refused, "
                    "so there is nothing further to enumerate"
                ),
            )

        message = message_of(response)

        if rejected(response):
            return ValidationResult(
                valid=False,
                note=(
                    "Resend did not accept this key"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=_identity(full_access=True),
                note=(
                    "The key is live; Resend rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Resend's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered.

        A restricted key answers none of them, and gets the one capability it
        has actually been documented to hold rather than an empty report that
        reads like a harmless credential.
        """
        headers = _auth(key)
        responses = await ctx.gather(
            [ctx.get(probe.url, headers=headers) for probe in PROBES]
        )

        restricted = any(is_restricted(response) for response in responses)
        if restricted:
            first = responses[0]
            return [_send_capability(ctx, key, first, restricted=True)]

        capabilities = [
            Capability(
                service=probe.service,
                # Reading `/api-keys` at all means Resend calls this key
                # `full_access`, which it documents as create/delete/update over
                # every resource. The vendor's sentence, not a write.
                access=AccessLevel.ADMIN if probe.admin else AccessLevel.WRITE,
                detail=f"{probe.detail}. {FULL_ACCESS_STATEMENT}",
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]

        validation = next(
            (
                response
                for probe, response in zip(PROBES, responses, strict=True)
                if probe.service == VALIDATE_SERVICE and response.ok
            ),
            None,
        )
        if validation is not None:
            capabilities.append(
                _send_capability(ctx, key, validation, restricted=False)
            )

        return sorted(capabilities, key=lambda capability: capability.sort_key)
