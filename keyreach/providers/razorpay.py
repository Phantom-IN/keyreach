"""Razorpay API keys (``rzp_live_…`` / ``rzp_test_…``) — roadmap R1.6.

No prior art. Every endpoint and header below was written from Razorpay's own
documentation, and each probe cites the page it came from.

**A Razorpay credential is two halves**, like an AWS one and unlike everything
else keyreach supports: Razorpay documents Basic auth over
``[YOUR_KEY_ID]:[YOUR_KEY_SECRET]``, and nothing can be signed without the
secret. keyreach therefore accepts them colon-joined, and a bare ``rzp_…`` key
id is detected, reported, and explicitly *not* probed — saying which half is
missing is more useful than calling a live credential dead.

**Only the secret is registered for redaction**, which is a deliberate departure
from the AWS plugin, where both halves are. Razorpay documents that after
generation "only the Key Id is visible on the Dashboard, not the Key secret":
the key id is the half the vendor itself treats as disclosable, and it is what
tells a recipient *which* key to revoke. Masking it would remove the only
identifying fact in the report while protecting nothing.

**What this plugin will not claim.** Razorpay's documentation does not state
that an API key carries unrestricted permissions, and keyreach never writes to
find out, so every capability here is ``READ`` and none sets ``incurs_cost``.
That under-reports the likely reality — a leaked live Razorpay secret can very
probably create refunds — and under-reporting is the correct side to err on
(``CLAUDE.md`` hard rule 1). Compare ``keyreach/providers/stripe.py``, where the
stronger verdict is available because Stripe publishes the sentence that
justifies it.
"""

from __future__ import annotations

import base64
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Key formats
# --------------------------------------------------------------------------
#
# Mirrors the two `razorpay-*` rules in `keyreach/patterns/detection_rules.yml`;
# `tests/test_provider_razorpay.py` asserts the two agree.
# Source: https://razorpay.com/docs/api/authentication/

#: The key id alone. Recognised so an exposure is still reported, but it cannot
#: be probed: Basic auth needs the secret.
ID_PATTERN: Final = r"rzp_(?:live|test)_[A-Za-z0-9]{10,}"

#: The secret half. Razorpay does not publish a fixed length, so this asks only
#: for an alphanumeric run long enough not to match punctuation or a stray word.
SECRET_PATTERN: Final = r"[A-Za-z0-9]{20,}"  # noqa: S105 - a shape, not a secret

_ID_RE: Final = re.compile(f"^{ID_PATTERN}$")
_PAIR_RE: Final = re.compile(f"^(?P<id>{ID_PATTERN}):(?P<secret>{SECRET_PATTERN})$")

#: Confidence for a complete pair and for a bare key id. Both formats are
#: unambiguous — the ``rzp_`` prefix is Razorpay's alone — so both are 0.99.
PAIR_CONFIDENCE: Final = 0.99
ID_CONFIDENCE: Final = 0.99

_LIVE_INFIX: Final = "_live_"


class _Mode(StrEnum):
    """Live money or test mode, from the documented infix in the key id."""

    LIVE = "live"
    TEST = "test"


class Credential(NamedTuple):
    """A parsed Razorpay credential: the public key id and the secret."""

    key_id: str
    key_secret: str

    @property
    def mode(self) -> _Mode:
        return _Mode.LIVE if _LIVE_INFIX in self.key_id else _Mode.TEST


def parse_credential(key: str) -> Credential | None:
    """Split ``key_id:key_secret``, or ``None`` if this is not a complete pair.

    A colon appears in neither half — both are alphanumeric — so the split is
    unambiguous and does not need to guess.
    """
    matched = _PAIR_RE.match(key)
    if matched is None:
        return None
    return Credential(matched.group("id"), matched.group("secret"))


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.razorpay.com/v1"

#: Page size for every list probe. Razorpay spells it ``count``.
#: Source: https://razorpay.com/docs/api/payments/fetch-all-payments/
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_TOO_MANY_REQUESTS: Final = 429


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
        service="Razorpay Customers",
        url=f"{API}/customers",
        params={"count": PAGE_SIZE},
        noun="customers",
        detail="Can list customers, including names, email addresses and phone numbers",
        risk_weight=95,
        data_sensitive=True,
        source="https://razorpay.com/docs/api/customers/",
    ),
    _Probe(
        service="Razorpay Orders",
        url=f"{API}/orders",
        params={"count": PAGE_SIZE},
        noun="orders",
        detail="Can list orders and the amounts they were raised for",
        risk_weight=85,
        data_sensitive=True,
        source="https://razorpay.com/docs/api/orders/",
    ),
    _Probe(
        service="Razorpay Payments",
        url=f"{API}/payments",
        params={"count": PAGE_SIZE},
        noun="payments",
        detail=(
            "Can list payments, including amounts, methods, and the payer's "
            "email address and contact number"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://razorpay.com/docs/api/payments/fetch-all-payments/",
    ),
    _Probe(
        service="Razorpay Settlements",
        url=f"{API}/settlements",
        params={"count": PAGE_SIZE},
        noun="settlements",
        detail="Can list settlements paid out to the business's own bank account",
        risk_weight=85,
        data_sensitive=True,
        source="https://razorpay.com/docs/api/settlements/",
    ),
)

#: Razorpay publishes no "who am I" endpoint, so the cheapest list read doubles
#: as the liveness check.
VALIDATE_SERVICE: Final = "Razorpay Payments"


def validation_probe() -> _Probe:
    """The cheapest read that proves the credential is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(credential: Credential) -> dict[str, str]:
    """Basic auth over ``key_id:key_secret``, as Razorpay documents it.

    Source: https://razorpay.com/docs/api/authentication/
    """
    raw = f"{credential.key_id}:{credential.key_secret}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _error(payload: Any) -> dict[str, Any]:
    """The ``error`` object from a Razorpay error body, or an empty mapping."""
    if not isinstance(payload, dict):
        return {}
    error = payload.get("error")
    return error if isinstance(error, dict) else {}


def _description(payload: Any) -> str:
    """Razorpay's human-readable error text, if the body carried one.

    Source: https://razorpay.com/docs/errors/
    """
    value = _error(payload).get("description")
    return value if isinstance(value, str) else ""


def _count(payload: Any) -> int | None:
    """The ``count`` a Razorpay collection response carries.

    Read from the documented ``count`` field rather than ``len(items)`` so the
    evidence reports what Razorpay said it returned. Falls back to the length of
    ``items`` when ``count`` is absent or not an integer, because a collection
    that lists something has proved the capability either way.
    """
    if not isinstance(payload, dict):
        return None
    count = payload.get("count")
    # `bool` is an `int` in Python, and `{"count": true}` is not a count.
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    items = payload.get("items")
    return len(items) if isinstance(items, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    found = _count(response.json_or_none())
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _identity(credential: Credential) -> Identity:
    """The key id and its mode.

    Built from the credential rather than from a response because Razorpay
    exposes no endpoint that names the account. The key id is still the single
    most useful fact for a recipient: it is what they search for in the
    Dashboard to find and revoke the key.
    """
    return Identity(
        account=credential.key_id,
        extra={"mode": credential.mode.value},
    )


def _poc(ctx: ProbeContext, credential: Credential, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Written as ``-u key_id:secret`` rather than as the base64 Authorization
    header the request actually carried. Both are the same credential, but only
    this form is redactable: base64 of a secret is not the secret, so a masked
    header would ship the credential in plain sight of every reader who can run
    ``base64 -d``.
    """
    return ctx.mask(
        f"curl -s -u '{credential.key_id}:{credential.key_secret}' '{response.url}'"
    )


class RazorpayProvider(Provider):
    """Razorpay API key id and secret."""

    name = "razorpay"
    category = "payment"
    docs_url = "https://razorpay.com/docs/api/authentication/"
    rotation_guide_url = (
        "https://razorpay.com/docs/payments/dashboard/account-settings/api-keys/"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``rzp_`` formats.

        A complete pair and a bare key id are both recognised. They score the
        same because both are unambiguous; what differs is whether keyreach can
        do anything with them, and that is decided in ``validate``, not here.
        """
        if _PAIR_RE.match(key):
            return PAIR_CONFIDENCE
        if _ID_RE.match(key):
            return ID_CONFIDENCE
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read against the cheapest collection endpoint.

        A bare key id is answered without any request at all. Razorpay Basic
        auth needs both halves, so there is nothing to ask — and asking anyway
        would produce a 401 that keyreach would then have to report as "this
        credential is invalid", which is exactly the wrong answer.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                identity=Identity(account=key) if _ID_RE.match(key) else None,
                note=(
                    "This is a Razorpay key id with no key secret. Razorpay "
                    "authenticates with both halves, so nothing could be "
                    "probed. Re-run with 'key_id:key_secret' to map what it "
                    "reaches — the key id alone does not mean the credential "
                    "is dead"
                ),
            )

        probe = validation_probe()
        response = await ctx.get(
            probe.url, params=probe.params or None, headers=_auth(credential)
        )
        identity = _identity(credential)

        if response.ok:
            return ValidationResult(valid=True, identity=identity)

        description = _description(response.json_or_none())

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Razorpay did not accept this key id and secret"
                    + (f": {description}" if description else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=identity,
                note=(
                    "The credential is live; Razorpay rate limited this "
                    "request. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Razorpay's response could not be interpreted"
                + (f" ({description})" if description else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every collection endpoint concurrently; keep the ones that answered.

        Every capability is ``READ``. Razorpay does not document its keys as
        unrestricted, so the write that probably exists is not claimed — see the
        module docstring.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return []

        headers = _auth(credential)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=AccessLevel.READ,
                detail=_detail(probe, credential),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, credential, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, credential: Credential) -> str:
    """The capability detail, including what was deliberately not tested."""
    detail = (
        f"{probe.detail}. Write access was not tested: keyreach never creates, "
        "refunds or captures a payment"
    )
    if credential.mode is _Mode.TEST:
        detail += ". This is a test-mode key, so the records are not real"
    return detail


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register the secret half for redaction.

    The redactor is seeded with the whole pasted string, which would not mask a
    response echoing back the secret on its own. Only the secret is registered;
    see the module docstring for why the key id deliberately is not.
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.key_secret)
    return credential
