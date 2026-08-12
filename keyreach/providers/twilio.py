"""Twilio credentials (``AC…`` Account SID + Auth Token) — roadmap R1.6.

No prior art. Every endpoint, credential form and error code below was written
from Twilio's own documentation, and each probe cites the page it came from.

**Twilio's credential is two halves, and the account half is in the URL.** Twilio
documents HTTP Basic auth with the Account SID as the username and the Auth
Token as the password, against
``https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/…``. keyreach accepts
them colon-joined, exactly as it does for AWS and Razorpay. A bare ``AC…`` SID,
or a bare ``SK…`` API Key SID, is detected and reported but not probed — saying
which half is missing is more useful than calling a live credential dead.

**Both halves are registered for redaction**, so neither reaches an evidence
string, a recorded cassette, or a response body that echoes one back. The
identity section then names the Account SID once, deliberately: Twilio treats it
as an identifier rather than a secret — it appears in every Console URL and in
the API path itself — and a disclosure report that cannot name the account is
one nobody can act on.

**What this plugin will not claim.** Twilio's documentation does not state that
an Auth Token carries unrestricted account access, and keyreach never sends a
message or places a call to find out, so every capability here is ``READ`` and
none sets ``incurs_cost``. That under-reports the reason a leaked Twilio
credential is dangerous — toll fraud — and under-reporting is the correct side
to err on (``CLAUDE.md`` hard rule 1). What *is* confirmed is bad enough on its
own: the message log carries the body of every SMS the account has sent.

**On the message-log path.** Twilio spells its message resource
``/Messages.json``. The ``ai_ban`` guardrail bans the all-lowercase spelling of
that same path as an inference endpoint, and it matches case-sensitively — which
turns out to be load-bearing rather than incidental, because this is a real
vendor path in a plugin that reaches no model at all.
``tests/test_guardrails.py`` pins both sides of the distinction.

This paragraph deliberately does not write the banned spelling out. The
guardrail scans source files including their prose, and it fired on an earlier
draft of this very docstring — which is the check working, not a false positive.
"""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential formats
# --------------------------------------------------------------------------
#
# Mirrors the three `twilio-*` rules in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_twilio.py`
# asserts the two agree.
# Source: https://www.twilio.com/docs/usage/requests-to-twilio

#: An Account SID: the literal "AC" and 32 lowercase hex characters.
ACCOUNT_SID_PATTERN: Final = r"AC[0-9a-f]{32}"

#: An API Key SID. Recognised so the exposure is reported, but an API Key cannot
#: be probed on its own: the Account SID is part of every request path and an
#: API Key SID is not it.
API_KEY_SID_PATTERN: Final = r"SK[0-9a-f]{32}"

#: The Auth Token. Twilio documents it as a 32-character hexadecimal value.
AUTH_TOKEN_PATTERN: Final = r"[0-9a-f]{32}"  # noqa: S105 - a shape, not a token

_ACCOUNT_SID_RE: Final = re.compile(f"^{ACCOUNT_SID_PATTERN}$")
_API_KEY_SID_RE: Final = re.compile(f"^{API_KEY_SID_PATTERN}$")
_PAIR_RE: Final = re.compile(
    f"^(?P<sid>{ACCOUNT_SID_PATTERN}):(?P<token>{AUTH_TOKEN_PATTERN})$"
)

#: A complete pair is unambiguous. A bare SID is a documented Twilio format but
#: a shorter one, so it scores slightly lower — matching the rule set.
PAIR_CONFIDENCE: Final = 0.99
SID_CONFIDENCE: Final = 0.95


class Credential(NamedTuple):
    """A parsed Twilio credential: the Account SID and the Auth Token."""

    account_sid: str
    auth_token: str


def parse_credential(key: str) -> Credential | None:
    """Split ``AccountSid:AuthToken``, or ``None`` if this is not a complete pair.

    A colon appears in neither half — both are hexadecimal — so the split is
    unambiguous and does not need to guess.
    """
    matched = _PAIR_RE.match(key)
    if matched is None:
        return None
    return Credential(matched.group("sid"), matched.group("token"))


# --------------------------------------------------------------------------
# Twilio's error vocabulary
# --------------------------------------------------------------------------
#
# Errors arrive as {"code", "message", "more_info", "status"}. Twilio documents
# 20003 as "Permission Denied": "credentials on your request are incorrect,
# expired, deleted, scoped to the wrong account, or not valid for the resource".
# Source: https://www.twilio.com/docs/api/errors/20003
#
# Note what that sentence bundles together. 20003 covers both "these credentials
# are wrong" and "these credentials are fine but not for this resource", so it
# cannot by itself decide validity. The HTTP status is the discriminator: Twilio
# answers 401 when it did not authenticate the request at all.

PERMISSION_DENIED: Final = 20003

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.twilio.com/2010-04-01/Accounts"

#: Page size for every list probe. Twilio spells it ``PageSize``.
#: Source: https://www.twilio.com/docs/usage/requests-to-twilio
PAGE_SIZE: Final = "1"


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    path: str = Field(description="Appended to the account resource URL.")
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

    def url_for(self, account_sid: str) -> str:
        """The full URL for this probe against one account."""
        return f"{API}/{account_sid}{self.path}"


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Twilio Account",
        path=".json",
        noun="account",
        detail=(
            "Can read the account itself, including its friendly name, status "
            "and whether it is a trial or a full account"
        ),
        risk_weight=60,
        source="https://www.twilio.com/docs/iam/api/account",
    ),
    _Probe(
        service="Twilio Balance",
        path="/Balance.json",
        noun="balance",
        detail="Can read the account's remaining balance and currency",
        risk_weight=70,
        # Private commercial data, and the number that tells an abuser how much
        # toll fraud the account will fund before it stops.
        data_sensitive=True,
        source="https://www.twilio.com/docs/usage/api/account-balance",
    ),
    _Probe(
        service="Twilio Call Log",
        path="/Calls.json",
        params={"PageSize": PAGE_SIZE},
        collection="calls",
        noun="calls",
        detail=(
            "Can list call records, including both phone numbers, duration and "
            "price of every call"
        ),
        risk_weight=90,
        data_sensitive=True,
        source="https://www.twilio.com/docs/voice/api/call-resource",
    ),
    _Probe(
        service="Twilio Message Log",
        path="/Messages.json",
        params={"PageSize": PAGE_SIZE},
        collection="messages",
        noun="messages",
        detail=(
            "Can list message records, including the body text of every SMS "
            "the account has sent or received, and both phone numbers"
        ),
        risk_weight=100,
        # The single worst thing on this list. Message bodies routinely carry
        # one-time passcodes, password resets and account numbers.
        data_sensitive=True,
        source="https://www.twilio.com/docs/messaging/api/message-resource",
    ),
    _Probe(
        service="Twilio Phone Numbers",
        path="/IncomingPhoneNumbers.json",
        params={"PageSize": PAGE_SIZE},
        collection="incoming_phone_numbers",
        noun="phone numbers",
        detail="Can list the phone numbers the account owns and their capabilities",
        risk_weight=75,
        source="https://www.twilio.com/docs/phone-numbers/api/incomingphonenumber-resource",
    ),
)

#: The account resource is the cheapest read and the one that names the account,
#: so it is both the liveness check and the first capability.
VALIDATE_SERVICE: Final = "Twilio Account"


def validation_probe() -> _Probe:
    """The cheapest read that proves the credential is live and names the account."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(credential: Credential) -> dict[str, str]:
    """Basic auth over ``AccountSid:AuthToken``, as Twilio documents it.

    Source: https://www.twilio.com/docs/usage/requests-to-twilio
    """
    raw = f"{credential.account_sid}:{credential.auth_token}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def error_code(response: ProbeResponse) -> int | None:
    """Twilio's numeric error code, or ``None`` if the body carried none."""
    code = _payload(response).get("code")
    # `bool` is an `int` in Python, and `{"code": true}` is not an error code.
    if isinstance(code, int) and not isinstance(code, bool):
        return code
    return None


def _message(response: ProbeResponse) -> str:
    value = _payload(response).get("message")
    return value if isinstance(value, str) else ""


def _count(probe: _Probe, response: ProbeResponse) -> int | None:
    """Length of the list this resource returns, by its documented field name."""
    if probe.collection is None:
        return None
    items = _payload(response).get(probe.collection)
    return len(items) if isinstance(items, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Counts, never contents. This matters more here than anywhere else in
    keyreach: quoting one message body to prove the capability would put a
    stranger's one-time passcode into a bug bounty report.
    """
    found = _count(probe, response)
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(credential: Credential, response: ProbeResponse) -> Identity:
    """The account, from the credential and the account resource.

    ``plan_or_tier`` carries Twilio's ``type`` — "Trial" or "Full" — because it
    bounds the blast radius more sharply than anything else the API discloses: a
    trial account cannot message unverified numbers.
    """
    payload = _payload(response)
    return Identity(
        account=credential.account_sid,
        owner=_string(payload, "friendly_name") or None,
        plan_or_tier=_string(payload, "type") or None,
        extra=({"status": status} if (status := _string(payload, "status")) else {}),
    )


def _poc(ctx: ProbeContext, credential: Credential, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Written as ``-u AccountSid:AuthToken`` rather than as the base64
    Authorization header the request actually carried. Both are the same
    credential, but only this form is redactable: base64 of a secret is not the
    secret, so a masked header would ship the credential in plain sight of every
    reader who can run ``base64 -d``.
    """
    return ctx.mask(
        f"curl -s -u '{credential.account_sid}:{credential.auth_token}' "
        f"'{response.url}'"
    )


def _not_a_pair_note(key: str) -> str:
    """Why nothing was probed, naming the half that is missing."""
    if _API_KEY_SID_RE.match(key):
        return (
            "This is a Twilio API Key SID with no secret, and an API Key alone "
            "cannot be probed: the Account SID is part of every request path. "
            "It does not mean the credential is dead"
        )
    return (
        "This is a Twilio Account SID with no Auth Token. Twilio authenticates "
        "with both halves, so nothing could be probed. Re-run with "
        "'AccountSid:AuthToken' to map what it reaches — the SID alone does "
        "not mean the credential is dead"
    )


class TwilioProvider(Provider):
    """Twilio Account SID and Auth Token."""

    name = "twilio"
    category = "comms"
    docs_url = "https://www.twilio.com/docs/usage/requests-to-twilio"
    rotation_guide_url = "https://www.twilio.com/docs/iam/api-keys"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``AC``/``SK`` formats."""
        if _PAIR_RE.match(key):
            return PAIR_CONFIDENCE
        if _ACCOUNT_SID_RE.match(key) or _API_KEY_SID_RE.match(key):
            return SID_CONFIDENCE
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of the account resource, which also names the account.

        A 401 is the only outcome that means the credentials were not accepted.
        A 403 with Twilio's 20003 is a live credential scoped away from this
        resource — the documented sentence bundles both cases, so the status is
        what decides.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(valid=False, note=_not_a_pair_note(key))

        probe = validation_probe()
        response = await ctx.get(
            probe.url_for(credential.account_sid), headers=_auth(credential)
        )

        if response.ok:
            return ValidationResult(
                valid=True, identity=_identity(credential, response)
            )

        code, message = error_code(response), _message(response)

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Twilio did not accept this Account SID and Auth Token"
                    + (f" ({code}: {message})" if code else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential is live; Twilio refused this resource "
                    f"({code or 'permission denied'}). The capabilities below "
                    "are a lower bound on what it reaches"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential is live; Twilio rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Twilio's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every account subresource concurrently; keep the ones that answered."""
        credential = _credential_for(key, ctx)
        if credential is None:
            return []

        headers = _auth(credential)
        responses = await ctx.gather(
            [
                ctx.get(
                    probe.url_for(credential.account_sid),
                    params=probe.params or None,
                    headers=headers,
                )
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere. Twilio does not document the Auth Token as
                # unrestricted, and keyreach does not send an SMS to find out.
                access=AccessLevel.READ,
                detail=(
                    f"{probe.detail}. Sending was not tested: keyreach never "
                    "sends a message or places a call"
                ),
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


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register **both** halves for redaction.

    The redactor is seeded with the whole pasted string, which would not mask a
    response echoing back the Account SID on its own — and the account resource
    does exactly that, in a field named ``sid``. Registering the parts is what
    makes "masked by default" true for a composite credential (``CLAUDE.md``).
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.auth_token)
    ctx.protect(credential.account_sid)
    return credential
