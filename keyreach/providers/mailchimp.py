"""Mailchimp Marketing API keys (``<hex>-<dc>``) — roadmap R2.3.

No prior art. Every path, the datacenter rule and the role model below were
written from Mailchimp's own documentation, and each probe cites the page it
came from.

**The key tells you which server to send it to.** Mailchimp documents the key as
``key-dc`` — a hex body, a hyphen, and a data centre subdomain such as ``us6`` —
and the base URL is ``https://<dc>.api.mailchimp.com/3.0/``. (Mailchimp's docs
give a worked example; it is not reproduced here, because a key-shaped literal
in source is what ``no_secrets`` exists to catch, and it caught this docstring.)
A key sent to the wrong datacenter is
refused with "your API key may be invalid, or you've attempted to access the
wrong datacenter" — the same 401 a dead key gets. So the suffix is not
decoration: parse it wrong and every live key looks revoked. keyreach derives the
host from the key and never guesses a datacenter.

**Access comes from a role, and Mailchimp says so in one sentence:** "The role of
the user who generated the API key determines access to each endpoint." The API
root returns that role, and Mailchimp documents what each of the five roles may
do. So the access level is read off a vendor statement rather than out of a
write keyreach performed — the same basis as Stripe's "unrestricted permissions"
in R1.6 and Anthropic's admin-key statement in R1.2.

**An unrecognised role produces ``UNKNOWN``, not a guess.** Mailchimp can add a
role tomorrow. Mapping an unknown one down to ``READ`` would under-report a key
that can empty an audience, and mapping it up would invent a finding; ``UNKNOWN``
is scored as undetermined and is the answer `CLAUDE.md` asks for when no rule can
decide.

**Sending is derived, never performed.** Mailchimp documents Owner, Admin and
Manager as able to send campaigns, and Author and Viewer as not. A key at one of
the first three can mail this company's entire audience from its own verified
domain, which is the worst outcome available here — and keyreach establishes it
from the role, with no campaign sent.
"""

from __future__ import annotations

import base64
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Key format and the datacenter it carries
# --------------------------------------------------------------------------
#
# Mirrors the `mailchimp-api-key` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_mailchimp.py`
# asserts the two agree.
# Source: https://mailchimp.com/developer/marketing/docs/fundamentals/

_PATTERN: Final = re.compile(r"^[0-9a-f]{30,32}-[a-z]{2,4}[0-9]{1,3}$")

#: 0.95: the datacenter suffix makes the shape distinctive, but the body is
#: plain hex and Mailchimp's own example and its issued keys differ in length.
CONFIDENCE: Final = 0.95

_SEPARATOR: Final = "-"


def datacenter_of(key: str) -> str | None:
    """The data centre subdomain the key must be sent to, or ``None``.

    ``None`` means the key carries no suffix — which can only be reached through
    ``--provider mailchimp``, since the detection rule requires one. It is
    answered without a request rather than by picking a datacenter and hoping.
    """
    prefix, separator, suffix = key.rpartition(_SEPARATOR)
    if not separator or not prefix or not suffix:
        return None
    return suffix


def base_url(datacenter: str) -> str:
    """``https://<dc>.api.mailchimp.com/3.0``, as Mailchimp documents it."""
    return f"https://{datacenter}.api.mailchimp.com/3.0"


# --------------------------------------------------------------------------
# The role model
# --------------------------------------------------------------------------
#
# "The role of the user who generated the API key determines access to each
# endpoint."  — https://mailchimp.com/help/about-api-keys/
#
# And what each role may do, quoted from Mailchimp's user-levels page:
#
#   Owner    "can perform all actions", including closing the account
#   Admin    "has the same permissions as the Owner"
#   Manager  "can create and send emails and SMS messages, import audiences,
#             and view reports, but can't view billing information, export
#             audiences, or close the account"
#   Author   "can create, edit, and delete emails and templates, and view
#             reports"
#   Viewer   "can view email and SMS reports in the account"
#
# Source: https://mailchimp.com/help/manage-user-levels-in-your-account/


class Role(StrEnum):
    """A Mailchimp user level, as returned by the API root."""

    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    AUTHOR = "author"
    VIEWER = "viewer"


#: Role to access level, each entry traceable to the sentence above.
ROLE_ACCESS: Final[dict[Role, AccessLevel]] = {
    Role.OWNER: AccessLevel.ADMIN,
    Role.ADMIN: AccessLevel.ADMIN,
    Role.MANAGER: AccessLevel.WRITE,
    Role.AUTHOR: AccessLevel.WRITE,
    Role.VIEWER: AccessLevel.READ,
}

#: The roles Mailchimp documents as able to send. Author can create and delete
#: emails but not send them, and Viewer can only read reports.
SENDING_ROLES: Final[frozenset[Role]] = frozenset(
    {Role.OWNER, Role.ADMIN, Role.MANAGER}
)


def role_of(response: ProbeResponse) -> Role | None:
    """The key's role, or ``None`` when Mailchimp named one keyreach cannot map.

    ``None`` covers both "no role in the body" and "a role this version does not
    know", and both lead to ``UNKNOWN`` rather than to a default. A new Mailchimp
    role must not silently arrive as ``READ``.
    """
    raw = _payload(response).get("role")
    if not isinstance(raw, str):
        return None
    try:
        return Role(raw.strip().lower())
    except ValueError:
        return None


def access_for(role: Role | None) -> AccessLevel:
    """The access level a role justifies, or ``UNKNOWN`` when none does."""
    if role is None:
        return AccessLevel.UNKNOWN
    return ROLE_ACCESS[role]


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

#: Page size for every list probe. Mailchimp spells it ``count``.
#: Source: https://mailchimp.com/developer/marketing/docs/methods-parameters/
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    path: str
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
        service="Mailchimp Account",
        path="/",
        noun="account",
        detail=(
            "Can read the account's name, contact details, plan and the role "
            "this key holds"
        ),
        risk_weight=60,
        source="https://mailchimp.com/developer/marketing/api/root/",
    ),
    _Probe(
        service="Mailchimp Audiences",
        path="/lists",
        params={"count": PAGE_SIZE},
        collection="lists",
        noun="audiences",
        detail=(
            "Can list the account's audiences and their subscriber counts. Each "
            "audience is a list of real people who gave this company an address"
        ),
        risk_weight=100,
        data_sensitive=True,
        source="https://mailchimp.com/developer/marketing/api/lists/",
    ),
    _Probe(
        service="Mailchimp Automations",
        path="/automations",
        params={"count": PAGE_SIZE},
        collection="automations",
        noun="automations",
        detail="Can list the account's automated email workflows and their triggers",
        risk_weight=70,
        source="https://mailchimp.com/developer/marketing/api/automation/",
    ),
    _Probe(
        service="Mailchimp Campaigns",
        path="/campaigns",
        params={"count": PAGE_SIZE},
        collection="campaigns",
        noun="campaigns",
        detail=(
            "Can list the account's campaigns, including their subject lines "
            "and the audience each was sent to"
        ),
        risk_weight=75,
        source="https://mailchimp.com/developer/marketing/api/campaigns/",
    ),
    _Probe(
        service="Mailchimp Reports",
        path="/reports",
        params={"count": PAGE_SIZE},
        collection="reports",
        noun="reports",
        detail=(
            "Can read campaign reports, including how many recipients opened "
            "and clicked each message"
        ),
        risk_weight=70,
        data_sensitive=True,
        source="https://mailchimp.com/developer/marketing/api/reports/",
    ),
)

#: The API root doubles as the liveness check: Mailchimp documents it as
#: returning the account details, and it is the endpoint that carries the role
#: every other capability is scored against.
VALIDATE_SERVICE: Final = "Mailchimp Account"


def validation_probe() -> _Probe:
    """The cheapest read, and the one that carries the key's role."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """Basic auth with any username and the key as the password.

    "Use any username with your token as the password."
    Source: https://mailchimp.com/developer/marketing/docs/fundamentals/
    """
    raw = f"keyreach:{key}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def detail_of(response: ProbeResponse) -> str:
    """Mailchimp's error detail, or ``""``.

    Errors are RFC 7807 problem documents:
    ``{"type": …, "title": "API Key Invalid", "status": 401, "detail": …}``.
    """
    value = _payload(response).get("detail")
    return value if isinstance(value, str) else ""


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


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(response: ProbeResponse, datacenter: str) -> Identity | None:
    """Account and role, from the API root.

    An exposed key that names its own account tells the recipient which
    Mailchimp account to go to, and the role tells them how much damage the key
    could already have done.
    """
    payload = _payload(response)
    account_id = _string(payload, "account_id")
    account_name = _string(payload, "account_name")
    if not account_id and not account_name:
        return None

    extra = {"datacenter": datacenter}
    for field in ("role", "email", "login_id"):
        value = _string(payload, field)
        if value:
            extra[field] = value

    return Identity(
        account=account_id or account_name,
        owner=account_name or None,
        extra=extra,
    )


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Uses ``-u`` rather than a base64 header so the reproduction is legible and
    the masked key is visible as a key — the same choice the Zoom plugin made.
    """
    return ctx.mask(f"curl -s -u 'keyreach:{ctx.key}' '{url}'")


def _send_capability(
    ctx: ProbeContext, response: ProbeResponse, role: Role, url: str
) -> Capability | None:
    """The capability derived from the role, never from a send.

    Mailchimp documents Owner, Admin and Manager as able to send email. A key at
    one of those levels can mail this company's whole audience from its own
    verified domain, which is the worst thing in this file — and establishing it
    costs nothing and sends nothing.
    """
    if role not in SENDING_ROLES:
        return None

    return Capability(
        service="Mailchimp Campaign Send",
        access=AccessLevel.WRITE,
        detail=(
            f"Can send campaigns to this account's audiences. Mailchimp "
            f"documents the {role.value} role as able to create and send email, "
            "and states that the role of the user who generated an API key "
            "determines its access. No campaign was sent or scheduled"
        ),
        evidence=response.evidence(f"role: {role.value}"),
        risk_weight=100,
        # A campaign spends the account's plan allowance and reaches every
        # subscriber on the audience.
        incurs_cost=True,
        data_sensitive=True,
        poc=_poc(ctx, url),
        resource_ref="https://mailchimp.com/help/manage-user-levels-in-your-account/",
    )


class MailchimpProvider(Provider):
    """Mailchimp Marketing API keys."""

    name = "mailchimp"
    category = "email"
    docs_url = "https://mailchimp.com/developer/marketing/docs/fundamentals/"
    rotation_guide_url = "https://mailchimp.com/help/about-api-keys/"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``key-dc`` shape."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of the API root, on the host the key's own suffix names."""
        datacenter = datacenter_of(key)
        if datacenter is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This key carries no data centre suffix, and Mailchimp "
                    "documents the suffix as the only thing that says which "
                    "server the key belongs to. No request was made: guessing a "
                    "data centre would produce the same 401 as a dead key"
                ),
            )

        probe = validation_probe()
        url = f"{base_url(datacenter)}{probe.path}"
        response = await ctx.get(url, headers=_auth(key))
        detail = detail_of(response)

        if response.ok:
            return ValidationResult(
                valid=True, identity=_identity(response, datacenter)
            )

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    f"Mailchimp did not accept this key at {datacenter}"
                    + (f" ({detail})" if detail else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Mailchimp refused the API root"
                    + (f" ({detail})" if detail else "")
                    + ". Without the root there is no role, so the capabilities "
                    "below are recorded as undetermined rather than harmless"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Mailchimp rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Mailchimp's response could not be interpreted"
                + (f" ({detail})" if detail else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; score each against the key's role.

        The root read costs nothing beyond ``validate``'s: ``ProbeClient``
        caches repeated idempotent GETs for a run (R1.4).
        """
        datacenter = datacenter_of(key)
        if datacenter is None:  # pragma: no cover - `validate` stops the run first
            return []

        api = base_url(datacenter)
        headers = _auth(key)
        responses = await ctx.gather(
            [
                ctx.get(
                    f"{api}{probe.path}", params=probe.params or None, headers=headers
                )
                for probe in PROBES
            ]
        )

        root = next(
            response
            for probe, response in zip(PROBES, responses, strict=True)
            if probe.service == VALIDATE_SERVICE
        )
        role = role_of(root)
        access = access_for(role)

        capabilities = [
            Capability(
                service=probe.service,
                access=access,
                detail=_detail(probe, role),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]

        if role is not None and root.ok:
            send = _send_capability(ctx, root, role, root.url)
            if send is not None:
                capabilities.append(send)

        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, role: Role | None) -> str:
    """The capability detail, including where its access level came from."""
    if role is None:
        return (
            f"{probe.detail}. Mailchimp named no role keyreach recognises, so "
            "this key's write access is undetermined rather than absent"
        )
    return (
        f"{probe.detail}. This key holds the {role.value} role, and Mailchimp "
        "states that the role of the user who generated an API key determines "
        "its access to each endpoint. No write was performed"
    )
