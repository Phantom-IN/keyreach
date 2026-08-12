"""Stripe API keys (``sk_…`` / ``rk_…``) — roadmap R1.6.

No prior art. Every endpoint, header and status code below was written from
Stripe's own documentation, and each probe cites the page it came from.

**This is the first plugin whose verdict can be Critical from a single read**,
and the reason is a sentence Stripe publishes about its own access model rather
than anything keyreach inferred:

    Secret API key ``sk_...`` — "API key that has unrestricted permissions on
    all Stripe APIs."

    Restricted API key (RAK) ``rk_...`` — "API key with permissions you
    control."

    — https://docs.stripe.com/keys

So a successful read with an ``sk_`` key establishes the matching write by the
vendor's documented access model, exactly as an Anthropic Console admin key
does in ``keyreach/providers/anthropic.py``. A successful read with an ``rk_``
key establishes a read and nothing else, exactly as an OpenAI admin key does in
``keyreach/providers/openai.py``. Two prefixes, two verdicts, both traceable to
one published table.

**Live and sandbox keys are not the same finding.** Stripe documents that in a
sandbox "card networks and payment providers don't process payments" and that
"API calls return simulated objects". A leaked ``sk_test_`` key is a real
exposure — it is unrestricted over that sandbox — but it cannot move money and
the customer records it reaches are simulated. So ``data_sensitive`` is set for
live-mode keys only, and ``incurs_cost`` needs all three of live mode, an
unrestricted key, and a resource where writing would actually move money. The
mode comes from the key itself (``_live_`` / ``_test_``), which means it is
known before a single request is made, and the same infix is what the detection
rule already matches.

**What this plugin will not claim.** It never creates a charge, a refund or a
payout to prove that it could; that is the write ``plan.md`` §4 forbids outright.
The Critical verdict rests on Stripe's published sentence, and the capability
``detail`` says so, so a recipient can check the claim against the vendor's
documentation rather than against keyreach's opinion.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Key formats
# --------------------------------------------------------------------------
#
# Deliberately identical to the two `stripe-*` rules in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_stripe.py`
# asserts the two agree, so the plugin and the rule set cannot drift apart and
# disagree about what a Stripe key looks like.
# Source: https://docs.stripe.com/keys

_PATTERNS: Final[tuple[tuple[str, float], ...]] = (
    (r"^sk_(live|test)_[0-9A-Za-z]{24,}$", 0.99),
    (r"^rk_(live|test)_[0-9A-Za-z]{24,}$", 0.99),
)

_COMPILED: Final = tuple((re.compile(pattern), score) for pattern, score in _PATTERNS)


class _Kind(StrEnum):
    """What Stripe says the key's permissions are, from its documented prefix."""

    SECRET = "secret"  # noqa: S105 - an enum member, not a credential
    """``sk_`` — "unrestricted permissions on all Stripe APIs"."""

    RESTRICTED = "restricted"
    """``rk_`` — "permissions you control", so a read proves only a read."""


class _Mode(StrEnum):
    """Live money or a sandbox. Documented in the key, so free to determine."""

    LIVE = "live"
    TEST = "test"


#: The two documented markers this plugin reads out of a key. Both are facts
#: Stripe publishes about the format, so both are known before a request is made.
#:
#: Stripe also documents an organisation key (``sk_org_…``) that operates across
#: several accounts. It is deliberately not matched: Stripe publishes the prefix
#: but not a body pattern, and a rule written from a guess is the one thing the
#: detection layer is not allowed to contain (``detection_rules.yml``). An
#: ``sk_org_`` key therefore falls through to the entropy stage and is reported
#: as an unidentified secret rather than as a Stripe key keyreach cannot probe.
_RESTRICTED_PREFIX: Final = "rk_"
_LIVE_INFIX: Final = "_live_"


def kind_of(key: str) -> _Kind:
    """Secret or restricted, from the documented prefix."""
    return _Kind.RESTRICTED if key.startswith(_RESTRICTED_PREFIX) else _Kind.SECRET


def mode_of(key: str) -> _Mode:
    """Live or sandbox, from the documented infix."""
    return _Mode.LIVE if _LIVE_INFIX in key else _Mode.TEST


# --------------------------------------------------------------------------
# Stripe's error vocabulary
# --------------------------------------------------------------------------
#
# Stripe's error object carries a `type`, but its four documented values —
# api_error, card_error, idempotency_error, invalid_request_error — say nothing
# about *authentication*: an invalid key and a malformed parameter are both
# `invalid_request_error`. The status code is the documented discriminator:
#
#   401 Unauthorized — "No valid API key provided."
#   403 Forbidden    — "The API key doesn't have permissions to perform the
#                       request."
#
# Source: https://docs.stripe.com/api/errors
#
# That difference is the whole reason validation cannot simply test `ok`. A 403
# is a **live** key that is merely scoped away from this endpoint, and reporting
# it as invalid would retire a working credential — the more dangerous direction
# to be wrong in.

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.stripe.com/v1"

#: Page size for every list probe. One item is enough to prove the capability
#: and is the smallest amount of somebody's payment data keyreach can pull to do
#: it (``plan.md`` §11).
PAGE_SIZE: Final = "1"


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = Field(
        default=False,
        description="Holds real customer or commercial data — in live mode only.",
    )
    moves_money: bool = Field(
        default=False,
        description="Writing to this resource would move money, not merely data.",
    )
    source: str = Field(description="Vendor documentation URL for this endpoint.")


#: Every probe, in a fixed order. Seven authenticated requests against somebody's
#: payment processor is already a lot, so the list stays short and every entry
#: earns its place by proving a distinct kind of reach (``plan.md`` §11).
PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Stripe Account",
        url=f"{API}/account",
        noun="account",
        detail=(
            "Can read the Stripe account itself, including the business "
            "profile, contact email, country and payout status"
        ),
        risk_weight=70,
        data_sensitive=True,
        source="https://docs.stripe.com/api/accounts/object",
    ),
    _Probe(
        service="Stripe Balance",
        url=f"{API}/balance",
        noun="balance",
        detail="Can read the account's available and pending balance",
        risk_weight=75,
        # Not personal data, but private commercial data: how much money the
        # business is holding and in which currencies.
        data_sensitive=True,
        source="https://docs.stripe.com/api/balance/balance_retrieve",
    ),
    _Probe(
        service="Stripe Charges",
        url=f"{API}/charges",
        params={"limit": PAGE_SIZE},
        noun="charges",
        detail=(
            "Can list charges, including amounts, billing details and the "
            "payment methods used"
        ),
        risk_weight=95,
        data_sensitive=True,
        moves_money=True,
        source="https://docs.stripe.com/api/charges/list",
    ),
    _Probe(
        service="Stripe Customers",
        url=f"{API}/customers",
        params={"limit": PAGE_SIZE},
        noun="customers",
        detail=(
            "Can list customers, including names, email addresses and stored "
            "billing addresses"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://docs.stripe.com/api/customers/list",
    ),
    _Probe(
        service="Stripe Payment Intents",
        url=f"{API}/payment_intents",
        params={"limit": PAGE_SIZE},
        noun="payment intents",
        detail="Can list payment intents and the state of in-flight payments",
        risk_weight=85,
        data_sensitive=True,
        moves_money=True,
        source="https://docs.stripe.com/api/payment_intents/list",
    ),
    _Probe(
        service="Stripe Payouts",
        url=f"{API}/payouts",
        params={"limit": PAGE_SIZE},
        noun="payouts",
        detail="Can list payouts to the business's own bank account",
        risk_weight=85,
        data_sensitive=True,
        moves_money=True,
        source="https://docs.stripe.com/api/payouts/list",
    ),
    _Probe(
        service="Stripe Subscriptions",
        url=f"{API}/subscriptions",
        params={"limit": PAGE_SIZE},
        noun="subscriptions",
        detail="Can list subscriptions and the recurring revenue behind them",
        risk_weight=80,
        data_sensitive=True,
        moves_money=True,
        source="https://docs.stripe.com/api/subscriptions/list",
    ),
)

#: The probe whose endpoint doubles as the liveness check. It is the one that
#: also discloses identity, so validation and the first capability come from the
#: same response.
VALIDATE_SERVICE: Final = "Stripe Account"


def validation_probe() -> _Probe:
    """The cheapest read that proves a key is live and says whose it is."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def access_for(kind: _Kind) -> AccessLevel:
    """``ADMIN`` for a secret key, ``READ`` for a restricted one.

    Both verdicts come from the same published table (see the module docstring):
    Stripe states that a secret key has "unrestricted permissions on all Stripe
    APIs", and that a restricted key has "permissions you control". keyreach
    confirms the read; the vendor's own access model supplies the rest for one
    of the two prefixes and withholds it for the other.
    """
    return AccessLevel.READ if kind is _Kind.RESTRICTED else AccessLevel.ADMIN


def _auth(key: str) -> dict[str, str]:
    """Bearer auth, the documented alternative to putting the key in basic auth.

    Stripe accepts either. Bearer is used here because it keeps the secret out
    of a base64 blob that neither the redactor's plain-text matching nor a human
    reading the evidence would recognise as the key.
    Source: https://docs.stripe.com/api/authentication
    """
    return {"Authorization": f"Bearer {key}"}


def _error(payload: Any) -> dict[str, Any]:
    """The ``error`` object from a Stripe error body, or an empty mapping.

    Written defensively because this parses a third-party payload: a gateway
    returning an HTML error page must degrade to "no structured error", not
    raise out of the middle of a probe.
    """
    if not isinstance(payload, dict):
        return {}
    error = payload.get("error")
    return error if isinstance(error, dict) else {}


def _text(error: dict[str, Any], field: str) -> str:
    """A string field of an error object, or ``""`` if absent or not a string."""
    value = error.get(field)
    return value if isinstance(value, str) else ""


def _count(payload: Any) -> int | None:
    """Length of the ``data`` list a Stripe list response carries."""
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return len(payload["data"])
    return None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Counts, never contents. ``/v1/account`` and ``/v1/balance`` return single
    objects rather than lists, so they fall through to "request accepted" —
    which is the honest summary for an endpoint that has nothing to count.
    """
    found = _count(response.json_or_none())
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(key: str, response: ProbeResponse) -> Identity | None:
    """Who the account belongs to, from the ``/v1/account`` response.

    An exposed key that names its own account tells the recipient which Stripe
    dashboard to go and open, which is most of what identity is for. The mode is
    recorded alongside because "live" versus "sandbox" is the first question
    anyone triaging a payment key asks.
    """
    payload = response.json_or_none()
    if not isinstance(payload, dict):
        return None

    account = _string(payload, "id")
    if not account:
        return None

    business = payload.get("business_profile")
    owner = _string(business, "name") if isinstance(business, dict) else ""

    extra = {"mode": mode_of(key).value}
    country = _string(payload, "country")
    if country:
        extra["country"] = country

    return Identity(
        account=account,
        owner=owner or None,
        extra=extra,
    )


def _poc(ctx: ProbeContext, key: str, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    The URL comes from the response rather than being rebuilt from the probe, so
    the command reproduces the request that was actually made — query encoding
    included — instead of one that merely resembles it.
    """
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(key).items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


class StripeProvider(Provider):
    """Stripe secret and restricted API keys."""

    name = "stripe"
    category = "payment"
    docs_url = "https://docs.stripe.com/keys"
    rotation_guide_url = "https://docs.stripe.com/keys#rolling-keys"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``sk_``/``rk_`` formats.

        Returns the highest confidence of any matching pattern. The two patterns
        are mutually exclusive by construction, so in practice at most one
        matches; taking the maximum rather than the first hit means a future
        overlap cannot make the answer depend on declaration order.
        """
        scores = [score for pattern, score in _COMPILED if pattern.match(key)]
        return max(scores) if scores else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read against ``/v1/account``, the endpoint that also names the account.

        Only a 401 means the key is not a key. A 403 is a **live** key whose
        permissions do not include this endpoint, which is the ordinary state of
        a restricted key and says nothing about whether the key is dangerous —
        the enumeration that follows is what answers that.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(key, response))

        error = _error(response.json_or_none())
        message = _text(error, "message")

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note="Stripe rejected this key: no valid API key provided (401)",
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; it does not have permission to read the "
                    "account (403). That is normal for a restricted key, and "
                    "the capabilities below are a lower bound on what it reaches"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Stripe rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Stripe's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered.

        A probe that comes back 403 is dropped rather than recorded as a
        restricted capability: the key genuinely cannot reach that resource, so
        recording it would inflate the capability map with things the key cannot
        do. ``Capability.restricted`` describes a referrer/IP-style control that
        *appears* to block an otherwise-present capability, which is a different
        fact (``plan.md`` §6).
        """
        kind, mode = kind_of(key), mode_of(key)
        access = access_for(kind)
        live = mode is _Mode.LIVE

        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=_auth(key))
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=access,
                detail=_detail(probe, kind, mode),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                # Sandbox objects are simulated, per Stripe's own documentation,
                # so a test-mode key reaches no real customer data and cannot
                # move real money. Both flags follow the mode rather than the
                # endpoint.
                data_sensitive=probe.data_sensitive and live,
                # Spend is claimed only where writing would actually move
                # money, and only for an unrestricted live key. Marking the
                # balance read as "can spend" would be true of the key and
                # false of the capability, and the rationale in the report is
                # built out of capabilities.
                incurs_cost=probe.moves_money and kind is _Kind.SECRET and live,
                poc=_poc(ctx, key, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, kind: _Kind, mode: _Mode) -> str:
    """The capability detail, with the reason its access level is what it is.

    The qualifier is in the ``detail`` because the detail is what a recipient
    reads. A Critical filed on "Stripe says secret keys are unrestricted" is
    checkable in one click; a Critical filed on nothing is an assertion.
    """
    if kind is _Kind.SECRET:
        claim = (
            "This is a secret key, which Stripe documents as having "
            "unrestricted permissions on all Stripe APIs, so the matching "
            "write access follows from the vendor's access model. No write "
            "was attempted"
        )
    else:
        claim = (
            "This is a restricted key, whose permissions are configurable, so "
            "only the read confirmed here is claimed"
        )

    if mode is _Mode.TEST:
        claim += (
            ". The key is a sandbox key: Stripe documents that sandbox objects "
            "are simulated and that no payment is processed there"
        )

    return f"{probe.detail}. {claim}"
