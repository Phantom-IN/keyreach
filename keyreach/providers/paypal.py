"""PayPal REST credentials (``client_id:client_secret``) — roadmap R2.1.

No prior art. The token exchange comes from PayPal's authentication guide; every
probe path and both host names were taken from PayPal's own OpenAPI
specifications (``github.com/paypal/paypal-rest-api-specifications``), which is
why the invoicing path here is ``/v2/`` and the rest are ``/v1/`` — a difference
no amount of remembering would have got right.

**This is the first provider keyreach cannot detect, and the first that has to
POST.** Both follow from the same fact: PayPal authenticates with OAuth 2.0
client credentials rather than with a formatted secret.

**1. Undetectable, declared rather than guessed.** A PayPal client id and secret
are opaque strings. PayPal publishes no prefix, no length and no charset for
them, so there is nothing to write a detection rule *from* — and a rule matching
"long base64-ish string, colon, long base64-ish string" would claim a large part
of the internet. ``detectable = False`` says so in the contract instead, and
``detect`` returns ``0.0`` for everything. keyreach reaches this plugin only
when the operator names it::

    keyreach 'CLIENT_ID:CLIENT_SECRET' --provider paypal

which already records in ``Report.notes`` that detection was overridden (R1.5),
so a reader can tell an operator's assertion from a rule's verdict.

**2. The token exchange is the one justified ``read_only_post``.** PayPal
documents ``POST /v1/oauth2/token`` with ``grant_type=client_credentials`` as
the only way to authenticate; there is no GET alternative and no way to reach
any read endpoint without it. It creates no merchant resource, moves no money,
and returns a short-lived bearer token. That is the narrow case
``implementation_plan.md`` §6 reserved the flag for, and it is annotated so the
``read_only`` guardrail forces exactly this argument to be made in review.

It also revealed that ``ProbeClient`` excluded ``read_only_post`` calls from its
per-run cache, which would have made keyreach mint two tokens per run — the
double-request defect R1.4 removed, reintroduced for one provider. Fixed in the
client, not worked around here.

**3. Access levels come from the documented ``scope`` field.** The token
response carries the scopes the credential was granted, as space-separated URIs.
That is a vendor statement of what the credential can do, so ``WRITE`` here is
read out of PayPal's own answer rather than inferred from a read — the same
standard as GitHub's ``X-OAuth-Scopes`` in R1.6, and matched **per resource** for
the same reason: a credential that can send an invoice cannot necessarily issue
a refund.

**Live and sandbox are indistinguishable in the credential**, so keyreach asks
live first and falls back to sandbox only when live rejects the credential. A
sandbox credential reported as "invalid" would be wrong, and a sandbox finding
is a much weaker one — it moves no real money.
"""

from __future__ import annotations

import base64
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------

#: Shortest half keyreach will treat as a credential. Not a published fact —
#: PayPal documents no length — so it is used only to reject obvious rubbish
#: *after* the operator has already named the provider, never to detect one.
MIN_HALF_LENGTH: Final = 16


class Credential(NamedTuple):
    """A parsed PayPal credential: the client id and the client secret."""

    client_id: str
    client_secret: str


def parse_credential(key: str) -> Credential | None:
    """Split ``client_id:client_secret``, or ``None`` if that is not the shape.

    Split on the **first** colon only. Neither half is documented as excluding
    one, and a secret containing a colon would otherwise be silently truncated
    into a credential that cannot authenticate — which keyreach would then
    report as "PayPal rejected this credential", a confident and wrong verdict.
    """
    client_id, separator, client_secret = key.partition(":")
    if not separator:
        return None
    if len(client_id) < MIN_HALF_LENGTH or len(client_secret) < MIN_HALF_LENGTH:
        return None
    return Credential(client_id, client_secret)


class _Environment(StrEnum):
    """Which PayPal environment answered. Not knowable from the credential."""

    LIVE = "live"
    SANDBOX = "sandbox"


#: Host per environment, from the ``servers`` block of every PayPal OpenAPI
#: specification.
HOSTS: Final[dict[_Environment, str]] = {
    _Environment.LIVE: "https://api-m.paypal.com",
    _Environment.SANDBOX: "https://api-m.sandbox.paypal.com",
}

#: Tried in this order. Live first because a live credential is the finding that
#: matters, and because falling back costs a request only when live says no.
ENVIRONMENT_ORDER: Final[tuple[_Environment, ...]] = (
    _Environment.LIVE,
    _Environment.SANDBOX,
)

#: The documented token exchange.
#: Source: https://developer.paypal.com/api/rest/authentication/
TOKEN_PATH: Final = "/v1/oauth2/token"  # noqa: S105 - a URL path, not a token
TOKEN_BODY: Final = "grant_type=client_credentials"  # noqa: S105 - a form body

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------
#
# The token response carries `scope`: space-separated URIs naming what the
# credential was granted. Matched per resource, never token-wide — a credential
# holding the invoicing scope can send an invoice and cannot refund a payment,
# and one access level applied to every capability would claim otherwise.

#: Prefix every PayPal service scope carries.
SCOPE_PREFIX: Final = "https://uri.paypal.com/services/"


def scopes_of(payload: Any) -> frozenset[str]:
    """The scopes PayPal said this credential holds.

    An empty set is a real answer — a credential granted nothing — and is kept
    distinct from a malformed body only by the caller already knowing the token
    exchange succeeded.
    """
    if not isinstance(payload, dict):
        return frozenset()
    raw = payload.get("scope")
    if not isinstance(raw, str):
        return frozenset()
    return frozenset(raw.split())


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, with the specification it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    path: str = Field(description="Appended to the environment host.")
    params: dict[str, str] = Field(default_factory=dict)
    collection: str = Field(description="Response field holding the list.")
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    write_scopes: tuple[str, ...] = Field(
        default=(),
        description="Scopes PayPal documents as granting write over this resource.",
    )
    moves_money: bool = Field(
        default=False,
        description="Would a write here move money rather than merely data?",
    )
    source: str = Field(description="Vendor specification URL for this endpoint.")

    def url_for(self, environment: _Environment) -> str:
        return f"{HOSTS[environment]}{self.path}"


#: One item is enough to prove a capability and is the least of somebody's
#: payment data keyreach can pull to do it (``plan.md`` §11).
PAGE_SIZE: Final = "1"

_SPECS: Final = (
    "https://github.com/paypal/paypal-rest-api-specifications/blob/main/openapi"
)

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="PayPal Disputes",
        path="/v1/customer/disputes",
        params={"page_size": PAGE_SIZE},
        collection="items",
        noun="disputes",
        detail=(
            "Can list customer disputes, including the buyer's messages and the "
            "evidence attached to each case"
        ),
        risk_weight=90,
        data_sensitive=True,
        write_scopes=(f"{SCOPE_PREFIX}disputes/update-seller",),
        source=f"{_SPECS}/customer_disputes_v1.json",
    ),
    _Probe(
        service="PayPal Invoices",
        path="/v2/invoicing/invoices",
        params={"page_size": PAGE_SIZE},
        collection="items",
        noun="invoices",
        detail=(
            "Can list invoices, including recipient names, email addresses and "
            "amounts billed"
        ),
        risk_weight=95,
        data_sensitive=True,
        # Sending an invoice asks a real person for money in the merchant's name.
        write_scopes=(f"{SCOPE_PREFIX}invoicing",),
        moves_money=True,
        source=f"{_SPECS}/invoicing_v2.json",
    ),
    _Probe(
        service="PayPal Products",
        path="/v1/catalogs/products",
        params={"page_size": PAGE_SIZE},
        collection="products",
        noun="products",
        detail="Can list the merchant's product catalogue",
        risk_weight=60,
        write_scopes=(f"{SCOPE_PREFIX}subscriptions",),
        source=f"{_SPECS}/catalogs_products_v1.json",
    ),
    _Probe(
        service="PayPal Subscription Plans",
        path="/v1/billing/plans",
        params={"page_size": PAGE_SIZE},
        collection="plans",
        noun="plans",
        detail="Can list billing plans and the recurring revenue behind them",
        risk_weight=80,
        data_sensitive=True,
        # A subscription plan bills a real person on a schedule.
        write_scopes=(f"{SCOPE_PREFIX}subscriptions",),
        moves_money=True,
        source=f"{_SPECS}/billing_subscriptions_v1.json",
    ),
)


def access_for(probe: _Probe, scopes: frozenset[str]) -> AccessLevel:
    """The access level this credential holds over **this** resource.

    ``READ`` unless PayPal named a scope it documents as granting more over this
    specific resource. Never ``UNKNOWN``: the read was confirmed, so
    "undetermined" would understate a fact keyreach holds evidence for.
    """
    return (
        AccessLevel.WRITE
        if scopes.intersection(probe.write_scopes)
        else AccessLevel.READ
    )


def _basic(credential: Credential) -> dict[str, str]:
    """Basic auth over ``client_id:client_secret``, as PayPal documents it."""
    raw = f"{credential.client_id}:{credential.client_secret}".encode()
    return {
        "Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a gateway
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


def _error_text(response: ProbeResponse) -> str:
    """PayPal's error text, from either of the two shapes it uses.

    The token endpoint answers OAuth-style ``{"error", "error_description"}``;
    the REST APIs answer ``{"name", "message"}``. Both are read rather than
    guessed at, because the note a user sees is only useful if it quotes what
    the vendor actually said.
    """
    payload = _payload(response)
    for field in ("error_description", "message", "error", "name"):
        text = _string(payload, field)
        if text:
            return text
    return ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    items = _payload(response).get(probe.collection)
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _identity(
    credential: Credential, environment: _Environment, response: ProbeResponse
) -> Identity:
    """The credential and the environment that accepted it.

    ``app_id`` is PayPal's identifier for the application the credential belongs
    to and is what a recipient searches for in the developer dashboard. The
    client id is reported alongside it because it is the non-secret half — it is
    embedded in PayPal's own client-side JavaScript SDK — while the secret is
    registered for redaction and never appears.
    """
    payload = _payload(response)
    return Identity(
        account=_string(payload, "app_id") or credential.client_id,
        plan_or_tier=environment.value,
        extra={"client_id": credential.client_id},
    )


def _poc(ctx: ProbeContext, credential: Credential, response: ProbeResponse) -> str:
    """A masked, read-only reproduction: the token exchange, then the read.

    Written as ``-u client_id:secret`` rather than as the base64 header the
    request carried, for the reason the Razorpay and Twilio plugins give: base64
    of a secret is not the secret, so a masked header would ship the credential
    to anyone who can run ``base64 -d``.
    """
    return ctx.mask(
        f"curl -s -u '{credential.client_id}:{credential.client_secret}' "
        f"-d '{TOKEN_BODY}' '{HOSTS[_Environment.LIVE]}{TOKEN_PATH}'  "
        f"# then: curl -s -H 'Authorization: Bearer <token>' '{response.url}'"
    )


class PayPalProvider(Provider):
    """PayPal REST client credentials."""

    name = "paypal"
    category = "payment"
    docs_url = "https://developer.paypal.com/api/rest/authentication/"
    rotation_guide_url = "https://developer.paypal.com/dashboard/applications/live"

    #: PayPal publishes no credential format, so no rule could recognise one.
    #: See the module docstring; ``--provider paypal`` is the documented route.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``. PayPal credentials have no publishable shape.

        Deliberately not "match a colon-joined pair of long strings": that would
        claim Razorpay and Twilio credentials, and a good fraction of every
        base64 blob a scanner has ever emitted. Returning a hedge here would
        cost authentication traffic against PayPal for keys that are not PayPal's
        (``plan.md`` §11), which is the cost ``Provider.detect`` exists to avoid.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Exchange the client credentials for a token, live first then sandbox.

        The exchange *is* the validation: PayPal exposes nothing a credential can
        read without a token, so there is no cheaper check to make.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This does not look like a PayPal credential. PayPal "
                    "authenticates with a client id and secret, so pass them "
                    "joined by a colon: 'CLIENT_ID:CLIENT_SECRET'"
                ),
            )

        last: ProbeResponse | None = None
        for environment in ENVIRONMENT_ORDER:
            response = await _mint(credential, environment, ctx)
            if response.ok:
                return _accepted(credential, environment, response)
            last = response
            if response.status_code not in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
                break

        return _rejected(last)

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every read endpoint on whichever environment accepted the credential.

        The token exchange here is answered from ``ProbeClient``'s per-run cache
        rather than performed again — see the module docstring.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return []

        for environment in ENVIRONMENT_ORDER:
            token_response = await _mint(credential, environment, ctx)
            if token_response.ok:
                return await _probe_all(credential, environment, token_response, ctx)
        return []


async def _probe_all(
    credential: Credential,
    environment: _Environment,
    token_response: ProbeResponse,
    ctx: ProbeContext,
) -> list[Capability]:
    """Run every probe against one environment and score it against the scopes."""
    token = access_token(token_response)
    scopes = scopes_of(token_response.json_or_none())
    headers = _bearer(token)

    responses = await ctx.gather(
        [
            ctx.get(
                probe.url_for(environment), params=probe.params or None, headers=headers
            )
            for probe in PROBES
        ]
    )

    live = environment is _Environment.LIVE
    capabilities = [
        Capability(
            service=probe.service,
            access=access_for(probe, scopes),
            detail=_detail(probe, scopes, live=live),
            evidence=response.evidence(_summary(probe, response)),
            risk_weight=probe.risk_weight,
            # Sandbox records are PayPal's test data, not somebody's customers.
            data_sensitive=probe.data_sensitive and live,
            # Spend is claimed only where PayPal granted a scope that would move
            # money, and only against the live environment.
            incurs_cost=(
                probe.moves_money
                and live
                and bool(scopes.intersection(probe.write_scopes))
            ),
            poc=_poc(ctx, credential, response),
            resource_ref=probe.source,
        )
        for probe, response in zip(PROBES, responses, strict=True)
        if response.ok
    ]
    return sorted(capabilities, key=lambda capability: capability.sort_key)


async def _mint(
    credential: Credential, environment: _Environment, ctx: ProbeContext
) -> ProbeResponse:
    """Exchange client credentials for a bearer token.

    The single ``read_only_post`` in keyreach. It creates no merchant resource
    and moves no money; it is annotated so the ``read_only`` guardrail forces the
    argument in the module docstring to be made in review.
    """
    return await ctx.post(
        f"{HOSTS[environment]}{TOKEN_PATH}",
        content=TOKEN_BODY,
        headers=_basic(credential),
        read_only_post=True,
    )


def _accepted(
    credential: Credential, environment: _Environment, response: ProbeResponse
) -> ValidationResult:
    """A successful exchange, with the environment recorded in the note."""
    scopes = scopes_of(response.json_or_none())
    note = f"Authenticated against PayPal {environment.value}."
    # Pluralised rather than "1 scopes". The same small wrongness that made
    # "1 fine-tuning jobs listed" worth fixing in R1.2: a reader who catches the
    # tool being sloppy about a number starts doubting the numbers beside it.
    if not scopes:
        note += " PayPal granted no scopes, so this credential reaches nothing"
    elif len(scopes) == 1:
        note += " PayPal granted 1 scope"
    else:
        note += f" PayPal granted {len(scopes)} scopes"
    if environment is _Environment.SANDBOX:
        note += (
            ". This is a sandbox credential: it reaches PayPal's test "
            "environment and cannot move real money"
        )
    return ValidationResult(
        valid=True,
        identity=_identity(credential, environment, response),
        note=note,
    )


def _rejected(response: ProbeResponse | None) -> ValidationResult:
    """Neither environment accepted the credential, or something else went wrong."""
    if response is None:  # pragma: no cover - ENVIRONMENT_ORDER is never empty
        return ValidationResult(valid=False, note="No PayPal environment was tried")

    text = _error_text(response)

    if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
        return ValidationResult(
            valid=False,
            note=(
                "PayPal did not accept this client id and secret in either the "
                "live or the sandbox environment" + (f" ({text})" if text else "")
            ),
        )

    if response.status_code == _HTTP_TOO_MANY_REQUESTS:
        return ValidationResult(
            valid=True,
            note=(
                "The credential reached PayPal, which rate limited the token "
                "exchange. Re-run with --delay for a complete capability map"
            ),
        )

    return ValidationResult(
        valid=False,
        note=(
            "PayPal's response could not be interpreted"
            + (f" ({text})" if text else "")
            + ", so this credential's validity was not established either way"
        ),
    )


def _detail(probe: _Probe, scopes: frozenset[str], *, live: bool) -> str:
    """The capability detail, naming the scope that justifies its access level."""
    granted = sorted(scopes.intersection(probe.write_scopes))
    if granted:
        short = ", ".join(scope.removeprefix(SCOPE_PREFIX) for scope in granted)
        detail = (
            f"{probe.detail}. PayPal granted the {short} scope, which it "
            "documents as more than read over this resource. No write was "
            "attempted"
        )
    else:
        detail = f"{probe.detail}. PayPal granted no write scope for this resource"

    if not live:
        detail += ". This is the sandbox environment, so the records are not real"
    return detail


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register the secret half for redaction.

    The redactor is seeded with the whole pasted string, which would not mask a
    response echoing back the secret alone. Only the secret is registered: the
    client id is the half PayPal itself puts in client-side JavaScript, and
    masking it would remove the fact that tells a recipient which application to
    rotate — the same reasoning as the Razorpay plugin (R1.6).
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.client_secret)
    return credential
