"""Zoom Server-to-Server OAuth credentials — roadmap R2.2.

No prior art. The token exchange comes from Zoom's Server-to-Server OAuth guide
and the scope grammar from its granular-scopes reference; the API base, every
path and the error shape were confirmed against Zoom's live API, which answers
``{"code":124,"message":"Invalid access token."}`` at ``401`` for a path that
exists.

**Three parts, not two.** Zoom documents ``POST https://zoom.us/oauth/token``
with ``Authorization: Basic base64(client_id:client_secret)`` and a body of
``grant_type=account_credentials&account_id=…``. The account id is a third,
separate value, so keyreach takes the credential colon-joined in the order Zoom
lists them::

    keyreach 'ACCOUNT_ID:CLIENT_ID:CLIENT_SECRET' --provider zoom

**Undetectable, like PayPal and Discord.** All three parts are opaque strings
with no published prefix, length or charset, so ``detectable = False``. R2.1
found that OAuth client credentials cannot be detected and framed it as a
payment-category problem; Zoom and Discord show it is not — it is a property of
the credential design, and it is spreading. See `plan.md` §5.2.

**Access levels come from Zoom's scope grammar, which is a rule rather than a
list.** Zoom documents granular scopes as ``resource:operation:action:role`` —
``user:read:list_users:admin``, ``meeting:write:meeting:admin`` — with the
operation segment carrying read, write, update or delete. So keyreach reads the
operation out of the scope name instead of maintaining a table of every scope
Zoom has ever shipped, which would be stale within a release. The resource
segment decides *which* capability a scope elevates, so a credential that can
write meetings is not thereby claimed to write users.

**The ``:admin`` role qualifier is recorded and deliberately not used to
elevate.** Zoom documents it as an authorization level, and a write scope
carrying it acts across the whole account — which is arguably ``ADMIN``. That
inference is left unmade: the detail names the scope in full so a reader can see
the qualifier and judge, and keyreach under-reports rather than reaching for a
band (`CLAUDE.md` hard rule 1).
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------

#: Number of colon-joined parts, in Zoom's own documentation order.
CREDENTIAL_PARTS: Final = 3

#: Shortest part keyreach will accept. Not a published fact — Zoom documents no
#: length — so it only rejects obvious rubbish after the operator has already
#: named the provider, and never detects anything.
MIN_PART_LENGTH: Final = 8


class Credential(NamedTuple):
    """A parsed Zoom credential, in the order Zoom's documentation lists it."""

    account_id: str
    client_id: str
    client_secret: str


def parse_credential(key: str) -> Credential | None:
    """Split ``account_id:client_id:client_secret``, or ``None``.

    Split from the left with a fixed part count, so a secret containing a colon
    keeps it: the last field takes the remainder. Truncating a secret would
    produce a credential that cannot authenticate, which keyreach would then
    report as "Zoom rejected this" — a confident, wrong verdict.
    """
    parts = key.split(":", CREDENTIAL_PARTS - 1)
    if len(parts) != CREDENTIAL_PARTS:
        return None
    if any(len(part) < MIN_PART_LENGTH for part in parts):
        return None
    return Credential(*parts)


# --------------------------------------------------------------------------
# Token exchange
# --------------------------------------------------------------------------
#
# Source: https://developers.zoom.us/docs/internal-apps/s2s-oauth/

TOKEN_URL: Final = "https://zoom.us/oauth/token"  # noqa: S105 - a URL, not a token
GRANT_TYPE: Final = "account_credentials"

API: Final = "https://api.zoom.us/v2"

#: Zoom's documented code for a request it did not authenticate, confirmed
#: against the live API.
INVALID_TOKEN_CODE: Final = 124

#: Statuses that mean "these credentials were not accepted".
#:
#: **400 is in this set because Zoom actually uses it**, which cost a wrong
#: verdict to find out: keyreach reported "Zoom's response could not be
#: interpreted" for a credential Zoom had plainly rejected. RFC 6749 permits
#: either 400 or 401 for `invalid_client`, and Zoom's token endpoint answers
#: `400 {"reason":"Invalid client_id or client_secret","error":"invalid_client"}`.
#: Safe to treat as a credential verdict here because keyreach always sends the
#: same documented body, so a 400 from this endpoint is never about the request.
_REJECTED_STATUSES: Final[frozenset[int]] = frozenset({400, 401, 403})
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------
#
# Granular scopes are `resource:operation:action:role`. keyreach reads the
# operation rather than matching a list of scope names, because Zoom ships new
# scopes continuously and a checked-in list would be wrong within a release.
# Source: https://developers.zoom.us/docs/integrations/oauth-scopes-granular/

#: Operations that are not reads. `update` and `delete` are listed by Zoom
#: alongside `write` as distinct operations, so all three are matched.
WRITE_OPERATIONS: Final[frozenset[str]] = frozenset({"write", "update", "delete"})

#: Fewest colon-separated segments a granular scope has: resource and operation.
_MIN_SCOPE_SEGMENTS: Final = 2


class Scope(NamedTuple):
    """A parsed Zoom scope: what it is over, and what it may do."""

    resource: str
    operation: str


def parse_scope(scope: str) -> Scope | None:
    """Split one scope into its resource and operation, or ``None`` if malformed.

    Zoom also issues classic scopes such as ``user:read:admin``, whose second
    segment is still the operation, so the same split reads both grammars.
    """
    segments = scope.split(":")
    if len(segments) < _MIN_SCOPE_SEGMENTS:
        return None
    resource, operation = segments[0], segments[1]
    if not resource or not operation:
        return None
    return Scope(resource, operation)


def scopes_of(payload: Any) -> tuple[str, ...]:
    """The scopes Zoom granted, space-separated in the token response.

    Returned sorted, so a set's iteration order never reaches a report.
    """
    if not isinstance(payload, dict):
        return ()
    raw = payload.get("scope")
    if not isinstance(raw, str):
        return ()
    return tuple(sorted(set(raw.split())))


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


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
    noun: str = Field(description="What the response describes, for the evidence.")
    detail: str
    resource: str = Field(description="Zoom scope resource this endpoint sits under.")
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PAGE_SIZE: Final = "1"

_DOCS: Final = "https://developers.zoom.us/docs/api"

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Zoom Account Users",
        url=f"{API}/users",
        params={"page_size": PAGE_SIZE},
        collection="users",
        noun="users",
        detail=(
            "Can list the account's users, including their names, email "
            "addresses and login types"
        ),
        resource="user",
        risk_weight=90,
        data_sensitive=True,
        source=f"{_DOCS}/rest/reference/user/methods/#operation/users",
    ),
    _Probe(
        service="Zoom Cloud Recordings",
        url=f"{API}/users/me/recordings",
        params={"page_size": PAGE_SIZE},
        collection="meetings",
        noun="recordings",
        detail=(
            "Can list cloud recordings, which are the recorded contents of "
            "meetings. The recordings themselves were not downloaded"
        ),
        resource="cloud_recording",
        risk_weight=100,
        # The single worst thing on this list: a meeting recording is the
        # meeting, and Zoom recordings routinely contain everything said in it.
        data_sensitive=True,
        source=f"{_DOCS}/rest/reference/zoom-api/methods/#operation/recordingsList",
    ),
    _Probe(
        service="Zoom Groups",
        url=f"{API}/groups",
        collection="groups",
        noun="groups",
        detail="Can list the account's user groups",
        resource="group",
        risk_weight=70,
        source=f"{_DOCS}/rest/reference/zoom-api/methods/#operation/groups",
    ),
    _Probe(
        service="Zoom Identity",
        url=f"{API}/users/me",
        noun="account owner",
        detail="Can read the account the credential authenticates as",
        resource="user",
        risk_weight=60,
        source=f"{_DOCS}/rest/reference/zoom-api/methods/#operation/user",
    ),
    _Probe(
        service="Zoom Meetings",
        url=f"{API}/users/me/meetings",
        params={"page_size": PAGE_SIZE},
        collection="meetings",
        noun="meetings",
        detail=(
            "Can list scheduled meetings, including their topics and join "
            "information"
        ),
        resource="meeting",
        risk_weight=85,
        data_sensitive=True,
        source=f"{_DOCS}/rest/reference/zoom-api/methods/#operation/meetings",
    ),
)

#: ``/users/me`` is the cheapest read and the one that names the account.
VALIDATE_SERVICE: Final = "Zoom Identity"


def validation_probe() -> _Probe:
    """The cheapest read that proves the credential works and names the account."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def access_for(probe: _Probe, scopes: tuple[str, ...]) -> AccessLevel:
    """The access level the granted scopes establish over **this** resource.

    ``READ`` unless a granted scope names this probe's resource with a
    non-read operation. Never ``UNKNOWN``: the read was confirmed, so
    "undetermined" would understate a fact keyreach holds evidence for.
    """
    return (
        AccessLevel.WRITE
        if any(
            scope.operation in WRITE_OPERATIONS for scope in _matching(probe, scopes)
        )
        else AccessLevel.READ
    )


def _matching(probe: _Probe, scopes: tuple[str, ...]) -> tuple[Scope, ...]:
    """Every granted scope that is about this probe's resource."""
    parsed = (parse_scope(scope) for scope in scopes)
    return tuple(
        scope
        for scope in parsed
        if scope is not None and scope.resource == probe.resource
    )


def granted_writes(probe: _Probe, scopes: tuple[str, ...]) -> tuple[str, ...]:
    """The granted scope names that give more than read over this resource."""
    return tuple(
        scope
        for scope in scopes
        if (parsed := parse_scope(scope)) is not None
        and parsed.resource == probe.resource
        and parsed.operation in WRITE_OPERATIONS
    )


def _basic(credential: Credential) -> dict[str, str]:
    """Basic auth over ``client_id:client_secret``, as Zoom documents it."""
    raw = f"{credential.client_id}:{credential.client_secret}".encode()
    return {
        "Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def token_body(credential: Credential) -> str:
    """The documented form body for the account-credentials grant."""
    return f"grant_type={GRANT_TYPE}&account_id={credential.account_id}"


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: an edge
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


def message_of(response: ProbeResponse) -> str:
    """Zoom's error text, from either shape it uses.

    The token endpoint answers OAuth-style ``{"reason", "error"}``; the API
    answers ``{"code", "message"}``. Both are read rather than guessed at.
    """
    payload = _payload(response)
    for field in ("reason", "message", "error_description", "error"):
        text = _string(payload, field)
        if text:
            return text
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


def _identity(credential: Credential, scopes: tuple[str, ...]) -> Identity:
    """The account, from the credential and the scopes Zoom granted.

    The account id is reported because it is what a recipient searches for in
    the Zoom App Marketplace to find and rotate the app. The client secret is
    registered for redaction and never appears.
    """
    return Identity(
        account=credential.account_id,
        extra=({"scopes": ", ".join(scopes)} if scopes else {"scopes": "none"}),
    )


def _poc(ctx: ProbeContext, credential: Credential, response: ProbeResponse) -> str:
    """A masked, read-only reproduction: the token exchange, then the read.

    Written with ``-u client_id:secret`` rather than the base64 header the
    request carried, for the reason the PayPal, Razorpay and Twilio plugins
    give: base64 of a secret is not the secret, so a masked header would ship
    the credential to anyone who can run ``base64 -d``.
    """
    return ctx.mask(
        f"curl -s -u '{credential.client_id}:{credential.client_secret}' "
        f"-d '{token_body(credential)}' '{TOKEN_URL}'  "
        f"# then: curl -s -H 'Authorization: Bearer <token>' '{response.url}'"
    )


class ZoomProvider(Provider):
    """Zoom Server-to-Server OAuth credentials."""

    name = "zoom"
    category = "comms"
    docs_url = "https://developers.zoom.us/docs/internal-apps/s2s-oauth/"
    rotation_guide_url = "https://marketplace.zoom.us/user/build"

    #: Every part is an opaque string with no published format. See the module
    #: docstring; ``--provider zoom`` is the documented route.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``. Zoom publishes no format for any of the three parts.

        A rule for "three colon-joined opaque strings" would claim AWS temporary
        credentials, which are exactly that shape and are already detected
        properly by prefix.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Exchange the credential for a token; the exchange is the validation.

        Zoom exposes nothing an account credential can read without a token, so
        there is no cheaper check to make.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This does not look like a Zoom Server-to-Server OAuth "
                    "credential. Zoom needs three values, so pass them joined "
                    "by colons: 'ACCOUNT_ID:CLIENT_ID:CLIENT_SECRET'"
                ),
            )

        response = await _mint(credential, ctx)
        message = message_of(response)

        if response.ok:
            scopes = scopes_of(response.json_or_none())
            return ValidationResult(
                valid=True,
                identity=_identity(credential, scopes),
                note=_granted_note(scopes),
            )

        if response.status_code in _REJECTED_STATUSES:
            return ValidationResult(
                valid=False,
                note=(
                    "Zoom did not accept this account id, client id and secret"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The credential reached Zoom, which rate limited the token "
                    "exchange. Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Zoom's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe each endpoint and score it against the granted scopes.

        The token exchange is answered from ``ProbeClient``'s per-run cache
        rather than performed again — the R2.1 change that made a
        ``read_only_post`` cacheable.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return []

        token_response = await _mint(credential, ctx)
        if not token_response.ok:
            return []

        scopes = scopes_of(token_response.json_or_none())
        headers = {"Authorization": f"Bearer {access_token(token_response)}"}
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
                # Zoom bills per licence, not per API call, and keyreach starts
                # no meeting — so nothing here spends.
                poc=_poc(ctx, credential, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


async def _mint(credential: Credential, ctx: ProbeContext) -> ProbeResponse:
    """Exchange the credential for a bearer token.

    The second ``read_only_post`` in keyreach, on the same argument as PayPal's:
    Zoom documents this as the only way to authenticate, it creates no account
    resource and moves no money, and annotating it is what forces the argument
    to be made in review.
    """
    return await ctx.post(
        TOKEN_URL,
        content=token_body(credential),
        headers=_basic(credential),
        read_only_post=True,
    )


def _granted_note(scopes: tuple[str, ...]) -> str:
    """How many scopes Zoom granted, pluralised."""
    if not scopes:
        return "Zoom granted no scopes, so this credential reaches nothing"
    if len(scopes) == 1:
        return "Zoom granted 1 scope"
    return f"Zoom granted {len(scopes)} scopes"


def _detail(probe: _Probe, scopes: tuple[str, ...]) -> str:
    """The capability detail, naming the scope that justifies its access level."""
    writes = granted_writes(probe, scopes)
    if writes:
        return (
            f"{probe.detail}. Zoom granted {', '.join(writes)}, whose operation "
            "segment is not a read, so this credential can change this resource "
            "as well. No write was attempted"
        )
    return f"{probe.detail}. No granted scope gives more than read here"


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register the secret for redaction.

    The redactor is seeded with the whole pasted string, which would not mask a
    response echoing back the secret alone. The account id and client id are
    identifiers rather than secrets — the account id is what a recipient needs
    in order to find the app — so only the secret is registered, as for Razorpay
    and PayPal.
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.client_secret)
    return credential
