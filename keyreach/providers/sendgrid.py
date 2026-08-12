"""SendGrid API keys (``SG.…``) — roadmap R2.3.

No prior art. Every path, header and scope name below was written from
SendGrid's own documentation, and each probe cites the page it came from.

**The second plugin that can prove a write without performing one, and the
first that can prove a key sends email without sending one.** SendGrid publishes
a read-only endpoint that returns the calling key's own permission list:

    "Retrieve a list of scopes for which this user has access."

    — https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions

GitHub does this in a response header (R1.6); SendGrid does it as a resource,
which is better — one ``GET`` both proves the key is live and enumerates
everything it may do, including the things keyreach declines to try.

**Scopes are a grammar, not a list.** SendGrid names them ``resource.action``,
optionally nested — ``alerts.read``, ``api_keys.create``,
``templates.versions.activate.create``. The **last** segment is the verb, so an
access level is read off the grammar rather than out of a checked-in table of
scope names. This is the same choice Zoom's plugin made in R2.2 and for the same
reason: SendGrid ships new scopes continuously, and a table would be wrong
within a release while a rule stays right.

**``mail.send`` is a capability with no probe behind it.** There is no read-only
endpoint that demonstrates the ability to send mail — demonstrating it *is*
sending mail, which spends the account's quota and puts a message in somebody's
inbox. So the send capability is derived from the documented scope, exactly as
Discord's privileged intents were in R2.2, and it is the only capability here
that sets ``incurs_cost``. A key that can send as a company's verified domain is
the most valuable thing in this file: it is a phishing platform with the
victim's own SPF and DKIM records behind it.

**What is still not claimed.** A scope absent from the list produces nothing at
all, a probe SendGrid refuses produces nothing at all, and if the scopes endpoint
itself cannot be read every capability falls back to ``READ`` — what the probe
proved — rather than to a guess.
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
# Mirrors the `sendgrid-api-key` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_sendgrid.py`
# asserts the two agree.
#
# Source: the create-API-key response example, which is the only place SendGrid
# publishes what a key looks like — "SG.xxxxxxxx.yyyyyyyy".
# https://www.twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys

_PATTERN: Final = re.compile(r"^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$")

#: 0.95, not 0.99. The `SG.` prefix is SendGrid's alone, but the two segment
#: lengths are keyreach's entropy floor rather than a published format — see the
#: comment on the rule. A confidence of 0.99 would claim a precision the vendor
#: has not supplied.
CONFIDENCE: Final = 0.95


# --------------------------------------------------------------------------
# The scope grammar
# --------------------------------------------------------------------------
#
# SendGrid documents scopes as `resource.action`, nesting the resource freely:
#
#   mail.send                            alerts.read
#   api_keys.create                      user.password.update
#   templates.versions.activate.create   mail.batch.delete
#
# The verb is always last. That is the whole rule, and it is why nothing here
# needs a list of scope names to stay correct.
# Source: https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions

_SEPARATOR: Final = "."

#: Verbs SendGrid uses for state-changing operations. A key holding any of them
#: on a resource can change that resource.
WRITE_ACTIONS: Final[frozenset[str]] = frozenset({"create", "delete", "update"})

#: The verb on `mail.send`, and the one action that costs the account money and
#: reaches a stranger's inbox. Kept apart from `WRITE_ACTIONS` because it is not
#: a write to a resource — it is an outbound email.
SEND_ACTION: Final = "send"

#: The one scope that makes a key a phishing platform. Named explicitly because
#: it is the only capability in this file with no probe behind it.
SEND_SCOPE: Final = f"mail{_SEPARATOR}{SEND_ACTION}"


def action_of(scope: str) -> str:
    """The verb in a scope — its last dot-separated segment."""
    return scope.rsplit(_SEPARATOR, 1)[-1]


def covers(scope: str, resource: str) -> bool:
    """Does ``scope`` grant something over ``resource``?

    Prefix matching on whole segments, so ``suppression`` covers
    ``suppression.bounces.delete`` but ``user`` does not cover ``username`` —
    a substring test would silently elevate the wrong capability.
    """
    return scope == resource or scope.startswith(resource + _SEPARATOR)


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.sendgrid.com/v3"

#: Page size for every list probe.
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


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
    resource: str = Field(
        description="Scope resource prefix whose verbs elevate this capability."
    )
    admin_on_write: bool = Field(
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
        service="SendGrid Account",
        url=f"{API}/user/account",
        noun="account",
        detail="Can read the account's plan type and reputation",
        resource="user.account",
        risk_weight=55,
        source="https://www.twilio.com/docs/sendgrid/api-reference/users-api/get-a-users-account-information",
    ),
    _Probe(
        service="SendGrid API Keys",
        url=f"{API}/api_keys",
        params={"limit": PAGE_SIZE},
        collection="result",
        noun="API keys",
        detail=(
            "Can list the account's other API keys, including their names and "
            "the scopes each one holds"
        ),
        resource="api_keys",
        # Creating an API key is administering the account, not editing one of
        # its records: a key that can mint keys outlives its own revocation.
        admin_on_write=True,
        risk_weight=90,
        source="https://www.twilio.com/docs/sendgrid/api-reference/api-keys",
    ),
    _Probe(
        service="SendGrid Profile",
        url=f"{API}/user/profile",
        noun="profile",
        detail=("Can read the account holder's name, company and postal address"),
        resource="user.profile",
        risk_weight=70,
        # A named human and their company's registered address.
        data_sensitive=True,
        source="https://www.twilio.com/docs/sendgrid/api-reference/users-api/get-a-users-profile",
    ),
    _Probe(
        service="SendGrid Suppressions",
        url=f"{API}/suppression/bounces",
        params={"limit": PAGE_SIZE},
        noun="bounced addresses",
        detail=(
            "Can list bounced recipients, which is a list of real email "
            "addresses the account has sent to"
        ),
        resource="suppression",
        risk_weight=85,
        # Recipient addresses are other people's personal data, and a bounce
        # list is a ready-made target list for the same domain's next campaign.
        data_sensitive=True,
        source="https://www.twilio.com/docs/sendgrid/api-reference/bounces-api",
    ),
    _Probe(
        service="SendGrid Templates",
        url=f"{API}/templates",
        params={"generations": "dynamic", "page_size": PAGE_SIZE},
        collection="result",
        noun="templates",
        detail=(
            "Can list the account's transactional email templates, which are "
            "the messages its customers are used to receiving"
        ),
        resource="templates",
        risk_weight=75,
        source="https://www.twilio.com/docs/sendgrid/api-reference/transactional-templates",
    ),
)

#: The scopes endpoint doubles as the liveness check: SendGrid documents it as
#: the list of scopes *this* key has, so it is reachable by every live key and
#: discloses nothing about the account's data.
SCOPES_URL: Final = f"{API}/scopes"

SCOPES_SOURCE: Final = (
    "https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions"
)


def _auth(key: str) -> dict[str, str]:
    """Bearer auth, as SendGrid documents it.

    Source: https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication
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


def message_of(response: ProbeResponse) -> str:
    """SendGrid's first error message, or ``""``.

    Errors arrive as ``{"errors": [{"field": null, "message": "unauthorized"}]}``.
    """
    errors = _payload(response).get("errors")
    if not isinstance(errors, list) or not errors:
        return ""
    first = errors[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    return message if isinstance(message, str) else ""


def scopes_of(response: ProbeResponse) -> frozenset[str] | None:
    """The key's scopes, or ``None`` when SendGrid did not state them.

    ``None`` and ``frozenset()`` are kept apart for the reason the GitHub plugin
    keeps them apart: no answer means "this key's permissions were not
    determined", while an empty list means "this key holds no scopes". Only the
    second justifies saying anything about what a key cannot do.
    """
    if not response.ok:
        return None
    scopes = _payload(response).get("scopes")
    if not isinstance(scopes, list):
        return None
    return frozenset(item for item in scopes if isinstance(item, str))


def access_for(probe: _Probe, scopes: frozenset[str] | None) -> AccessLevel:
    """The access level a probe's result justifies, given the key's scopes.

    ``READ`` is the floor, because a capability is only built from a probe that
    answered. Scopes can raise it and can never lower it: a documented
    ``suppression.delete`` grant is a write whatever the read returned.
    """
    if scopes is None:
        return AccessLevel.READ

    verbs = {action_of(scope) for scope in scopes if covers(scope, probe.resource)}

    if verbs & WRITE_ACTIONS:
        return AccessLevel.ADMIN if probe.admin_on_write else AccessLevel.WRITE
    return AccessLevel.READ


def _count(probe: _Probe, response: ProbeResponse) -> int | None:
    """Length of the list this endpoint returns, by its documented field name."""
    if probe.collection is None:
        return None
    items = _payload(response).get(probe.collection)
    return len(items) if isinstance(items, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    found = _count(probe, response)
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _identity(scopes: frozenset[str] | None) -> Identity | None:
    """What SendGrid discloses about the key itself.

    SendGrid publishes no endpoint that names the account and that *every* key
    can reach — a custom-access key without ``user.profile.read`` cannot read
    the profile — so the identity here is the size of the key's own grant. That
    is the fact the scopes endpoint actually establishes, and it is the one a
    recipient needs first: a key holding sixty scopes is a different disclosure
    from a key holding one.
    """
    if scopes is None:
        return None
    return Identity(extra={"scopes": str(len(scopes))})


def _poc(ctx: ProbeContext, key: str, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(key).items())
    )
    return ctx.mask(f"curl -s{headers} '{url}'")


def _send_capability(
    ctx: ProbeContext, key: str, response: ProbeResponse, scopes: frozenset[str]
) -> Capability | None:
    """The one capability derived from a scope rather than from a probe.

    keyreach will not send an email to prove a key can send email, so the
    evidence is SendGrid's own answer about the key's permissions. The same
    shape as Telegram's privacy-mode capability (R1.6) and Discord's privileged
    intents (R2.2): the vendor stated it, so it is recorded, and nothing was
    sent to find out.
    """
    if SEND_SCOPE not in scopes:
        return None

    return Capability(
        service="SendGrid Mail Send",
        # A write, and the only one here that is not a write to a record: it
        # puts a message in somebody else's inbox.
        access=AccessLevel.WRITE,
        detail=(
            "Can send email as this account, over its verified sending domains "
            "and their SPF and DKIM records. Confirms the "
            f"{SEND_SCOPE} scope. No message was sent: this is SendGrid's own "
            "statement of the key's permissions"
        ),
        evidence=response.evidence(f"scopes include {SEND_SCOPE}"),
        risk_weight=100,
        # Every message spends the account's plan allowance.
        incurs_cost=True,
        poc=_poc(ctx, key, SCOPES_URL),
        resource_ref=SCOPES_SOURCE,
    )


class SendGridProvider(Provider):
    """SendGrid API keys."""

    name = "sendgrid"
    category = "email"
    docs_url = (
        "https://www.twilio.com/docs/sendgrid/api-reference/"
        "how-to-use-the-sendgrid-v3-api/authentication"
    )
    rotation_guide_url = (
        "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``SG.`` shape."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of the scopes endpoint, which every live key can reach."""
        response = await ctx.get(SCOPES_URL, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(scopes_of(response)))

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "SendGrid did not accept this key"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; SendGrid refused the scopes endpoint"
                    + (f" ({message})" if message else "")
                    + ". Access levels below are what each probe proved, with "
                    "no scope information to raise them, so they are a lower "
                    "bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; SendGrid rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "SendGrid's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Read the key's scopes, then probe every endpoint concurrently.

        The scopes read costs nothing beyond ``validate``'s: ``ProbeClient``
        caches repeated idempotent GETs for a run (R1.4), so the two calls to
        the same URL reach the network once.
        """
        headers = _auth(key)
        scopes_response = await ctx.get(SCOPES_URL, headers=headers)
        scopes = scopes_of(scopes_response)

        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=access_for(probe, scopes),
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

        if scopes is not None:
            send = _send_capability(ctx, key, scopes_response, scopes)
            if send is not None:
                capabilities.append(send)

        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, scopes: frozenset[str] | None) -> str:
    """The capability detail, including where its access level came from."""
    if scopes is None:
        return (
            f"{probe.detail}. This key's scopes could not be read, so write "
            "access was neither confirmed nor ruled out"
        )

    granted = sorted(scope for scope in scopes if covers(scope, probe.resource))
    if not granted:
        return f"{probe.detail}. SendGrid lists no scope over {probe.resource}"

    return (
        f"{probe.detail}. SendGrid lists {', '.join(granted)}. No write was "
        "performed: the access level is SendGrid's own statement of this key's "
        "permissions"
    )
