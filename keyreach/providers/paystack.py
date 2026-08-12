"""Paystack secret keys (``sk_live_…`` / ``sk_test_…``) — roadmap R2.1.

No prior art. The base URL, every path and the error envelope below were
verified against Paystack's own API, and the ``perPage`` parameter against
Paystack's own published SDKs (``github.com/PaystackOSS/paystack-node``).

**Paystack and Stripe share a prefix, and this is the first time that has
happened.** Both document ``sk_live_`` and ``sk_test_``, and neither publishes a
length or charset that separates them. keyreach does not resolve that by
guessing: both plugins claim the key, the engine probes both candidates, and
whichever vendor accepts it is the one the report is about
(``implementation_plan.md`` §5 — "ambiguity between providers sharing a prefix
is resolved later, at the enumerate stage, not by inflating confidence").

That machinery existed from R0.5 and had never run against a real collision.
It works, and it costs exactly one wasted request: the loser's validation call
returns 401 and its enumeration never happens. A wasted authentication attempt
against a vendor the key does not belong to is a real cost under ``plan.md``
§11, and it is the honest price of not pretending to know which is which. A user
who does know can settle it for nothing with ``--provider``.

**Paystack's HTTP status is trustworthy, unlike Slack's**, but its body carries
the detail: every response is ``{"status": bool, "message": str, "data": …}``,
and an authentication failure adds ``"type"`` and ``"code"``. Both are read.

**What this plugin will not claim.** Paystack does not document its secret keys
as unrestricted, and keyreach never initiates a transfer to find out, so every
capability is ``READ`` and none sets ``incurs_cost`` — the same line drawn for
Razorpay in R1.6, and the same reason: a stronger verdict needs a vendor
sentence, not an inference. What *is* confirmed is enough: the customer list
carries names, email addresses and phone numbers.
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
# Key format
# --------------------------------------------------------------------------
#
# Mirrors the `paystack-secret-key` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_paystack.py`
# asserts the two agree, and also asserts the deliberate overlap with Stripe.
# Source: https://paystack.com/docs/api/authentication/

_PATTERN: Final = re.compile(r"^sk_(live|test)_[0-9A-Za-z]{24,}$")

#: Deliberately identical to Stripe's confidence. Neither vendor publishes
#: anything that would justify ranking one above the other, and a thumb on the
#: scale here would decide the ambiguity by assertion rather than by asking.
#: The registry breaks the tie on provider name, so the order is at least
#: reproducible.
CONFIDENCE: Final = 0.99

_LIVE_INFIX: Final = "_live_"


class _Mode(StrEnum):
    """Live money or test mode, from the documented infix."""

    LIVE = "live"
    TEST = "test"


def mode_of(key: str) -> _Mode:
    """Live or test, from the documented infix."""
    return _Mode.LIVE if _LIVE_INFIX in key else _Mode.TEST


# --------------------------------------------------------------------------
# Paystack's response envelope
# --------------------------------------------------------------------------
#
# Every response is {"status": bool, "message": str, "data": ...}. An
# unauthenticated request answers 401 with, verbatim from the API:
#
#   {"status": false, "message": "No Authorization header was found",
#    "meta": {...}, "type": "validation_error", "code": "invalid_Key"}
#
# The status code is the verdict here — Paystack does not answer 200 for an
# auth failure the way Slack does — but the message is what makes the note
# useful to a reader.

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.paystack.co"

#: Page size for every list probe. Paystack spells it ``perPage``, verified from
#: its own published SDK rather than from a documentation page this repository
#: could not fetch.
#: Source: https://github.com/PaystackOSS/paystack-node
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
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Paystack Balance",
        url=f"{API}/balance",
        noun="balance",
        detail="Can read the account's available balance and currency",
        risk_weight=70,
        # Private commercial data: what the business is holding.
        data_sensitive=True,
        source="https://paystack.com/docs/api/transfer/#balance",
    ),
    _Probe(
        service="Paystack Customers",
        url=f"{API}/customer",
        params={"perPage": PAGE_SIZE},
        noun="customers",
        detail=(
            "Can list customers, including their names, email addresses and "
            "phone numbers"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://paystack.com/docs/api/customer/",
    ),
    _Probe(
        service="Paystack Settlements",
        url=f"{API}/settlement",
        params={"perPage": PAGE_SIZE},
        noun="settlements",
        detail="Can list settlements paid out to the business's own bank account",
        risk_weight=85,
        data_sensitive=True,
        source="https://paystack.com/docs/api/settlement/",
    ),
    _Probe(
        service="Paystack Subaccounts",
        url=f"{API}/subaccount",
        params={"perPage": PAGE_SIZE},
        noun="subaccounts",
        detail=(
            "Can list subaccounts, including the bank accounts revenue is split to"
        ),
        risk_weight=85,
        data_sensitive=True,
        source="https://paystack.com/docs/api/subaccount/",
    ),
    _Probe(
        service="Paystack Transactions",
        url=f"{API}/transaction",
        params={"perPage": PAGE_SIZE},
        noun="transactions",
        detail=(
            "Can list transactions, including amounts, the payer's email address "
            "and the card details Paystack retains"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://paystack.com/docs/api/transaction/",
    ),
)

#: ``/balance`` is the cheapest read and the only probe here that lists nothing,
#: which makes it the least intrusive way to prove a key is live: it discloses
#: one number about the account rather than a page of somebody's customers.
VALIDATE_SERVICE: Final = "Paystack Balance"


def validation_probe() -> _Probe:
    """The cheapest read that proves the key is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """Bearer auth, as Paystack documents it.

    Source: https://paystack.com/docs/api/authentication/
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
    """Paystack's human-readable message, or ``""`` if the body carried none."""
    value = _payload(response).get("message")
    return value if isinstance(value, str) else ""


def _count(response: ProbeResponse) -> int | None:
    """How many records ``data`` held, when it held a list.

    ``/balance`` returns a list of one entry per currency; the list endpoints
    return a list of records. Both are counted the same way, and neither count
    reveals anything but a number.
    """
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


def _identity(key: str) -> Identity:
    """The mode, which is all Paystack discloses without a dashboard.

    Paystack publishes no "who am I" endpoint, so there is no account name to
    report. The mode still matters more than anything else a reader could be
    told: a live key moves real money and a test key does not.
    """
    return Identity(extra={"mode": mode_of(key).value})


def _poc(ctx: ProbeContext, key: str, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(key).items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


class PaystackProvider(Provider):
    """Paystack secret keys."""

    name = "paystack"
    category = "payment"
    docs_url = "https://paystack.com/docs/api/authentication/"
    rotation_guide_url = "https://support.paystack.com/en/articles/2123458"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``sk_`` formats.

        Returns the same confidence Stripe does for the same string, on purpose.
        Nothing published separates the two formats, so this reports "yes, this
        could be mine" and lets the probe stage decide — see the module
        docstring.
        """
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/balance``, the cheapest endpoint that lists nothing."""
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(key))

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Paystack did not accept this key"
                    + (f" ({message})" if message else "")
                    + ". Note that Stripe uses the same key prefix, so a key "
                    "rejected here may still be a live Stripe key"
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                identity=_identity(key),
                note=(
                    "The key is live; Paystack refused this endpoint"
                    + (f" ({message})" if message else "")
                    + ". The capabilities below are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=_identity(key),
                note=(
                    "The key is live; Paystack rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Paystack's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered."""
        headers = _auth(key)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
            ]
        )

        live = mode_of(key) is _Mode.LIVE
        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere. Paystack does not document its keys as
                # unrestricted, and keyreach does not initiate a transfer to
                # find out.
                access=AccessLevel.READ,
                detail=_detail(probe, live=live),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                # A test-mode key reaches test records, which are not somebody's
                # customers.
                data_sensitive=probe.data_sensitive and live,
                poc=_poc(ctx, key, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, *, live: bool) -> str:
    """The capability detail, including what was deliberately not tested."""
    detail = (
        f"{probe.detail}. Write access was not tested: keyreach never "
        "initiates a transfer or a refund"
    )
    if not live:
        detail += ". This is a test-mode key, so the records are not real"
    return detail
