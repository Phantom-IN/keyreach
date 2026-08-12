"""Postmark server and account tokens — roadmap R2.3.

No prior art. Every path and header below was written from Postmark's own
documentation, and each was then verified against Postmark's live API, which
answers 401 for a path that exists and 404 for one that does not.

**Postmark has two kinds of token, they look identical, and the holder of a
leaked one often cannot say which they have.** Postmark documents
``X-Postmark-Server-Token`` for "requests that require server level privileges"
and ``X-Postmark-Account-Token`` for "requests that require account level
privileges", and publishes no format for either. So keyreach discovers the kind
rather than being told it: both headers are tried, and Postmark's own refusal
names the one it wanted — "Request does not contain a valid **Server** token"
against "…valid **Account** token". Whichever authenticates decides which probe
table runs.

That is a new shape for this repository. PayPal and Zoom were undetectable but
structurally known — a client id and a secret, joined by colons. Here one opaque
string is two different credentials with two different blast radii, and the only
way to tell is to ask.

**``detectable = False``, for the usual reason.** Postmark publishes no prefix,
length or charset for either token, so a rule could only be written from a guess.
``--provider postmark`` is the route, and the report records that the operator
asserted the provider.

**The access levels are Postmark's sentences, not keyreach's writes.** Postmark
documents every Servers API operation — including create and delete — as
requiring the account token, "only accessible by the account owner", so an
account token is ``ADMIN``. It documents Edit Server and the send endpoint as
requiring the server token, so a server token is ``WRITE`` over its server and
can send mail as it. No server was edited and no message was sent.

**A server token discloses the server's other tokens.** ``GET /server`` returns
an ``ApiTokens`` field. keyreach counts them and never prints one — the count is
the finding, since it says how many more credentials the same leak exposed.

**One probe was removed because ``ai_ban`` forbids its path, and that is the
guardrail working.** Postmark's outbound-mail search lives under the same
lowercase path as Anthropic's inference endpoint, and ``ai_ban`` matches that
path with a trailing boundary that deliberately includes sub-resources — so that
Anthropic's message-batches path is caught rather than excused. Nothing in a
single line of source distinguishes an email vendor's sent-mail archive from a
model endpoint; only the host does, and ``ai_ban`` bans paths rather than hosts
on purpose (``plan.md`` §1). Twilio hit the same collision in R1.6 and survived
it on letter case alone. This one does not, so the probe is gone and the bounce
list carries the recipient-data finding instead. Weakening the check to keep a
probe would be a change to what keyreach promises, not a refactor.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

API: Final = "https://api.postmarkapp.com"

#: Page size and offset for every list probe. Postmark requires both.
PAGE_SIZE: Final = "1"
OFFSET: Final = "0"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


# --------------------------------------------------------------------------
# The two kinds of token
# --------------------------------------------------------------------------
#
# "Server Token — Used for requests that require server level privileges."
# "Account Token — Used for requests that require account level privileges."
# Source: https://postmarkapp.com/developer/api/overview


class Kind(StrEnum):
    """Which of Postmark's two token types a credential turns out to be."""

    SERVER = "server"
    ACCOUNT = "account"


#: The header each kind is sent in. Postmark notes headers are case insensitive;
#: these are spelled as documented.
HEADERS: Final[dict[Kind, str]] = {
    Kind.SERVER: "X-Postmark-Server-Token",
    Kind.ACCOUNT: "X-Postmark-Account-Token",
}


def headers_for(kind: Kind, token: str) -> dict[str, str]:
    """The token header for this kind, plus the ``Accept`` Postmark insists on.

    Without it the bounce endpoint answers ``409``: "Content-Type and Accept
    headers must be set to application/json" — a refusal that has nothing to do
    with the credential and would otherwise read as one.
    """
    return {HEADERS[kind]: token, "Accept": "application/json"}


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    kind: Kind = Field(description="Which token type reaches this endpoint.")
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    collection: str | None = Field(
        default=None,
        description="Response field holding the list, for the evidence count.",
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    access: AccessLevel = Field(
        description="Access level Postmark's own documentation attributes here."
    )
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Postmark Domains",
        kind=Kind.ACCOUNT,
        url=f"{API}/domains",
        params={"count": PAGE_SIZE, "offset": OFFSET},
        collection="Domains",
        noun="domains",
        detail=(
            "Can list the account's sending domains and their DKIM and return "
            "path records"
        ),
        # Every Domains API operation is documented as account level, and the
        # account token is "only accessible by the account owner".
        access=AccessLevel.ADMIN,
        risk_weight=85,
        source="https://postmarkapp.com/developer/api/domains-api",
    ),
    _Probe(
        service="Postmark Message Streams",
        kind=Kind.SERVER,
        url=f"{API}/message-streams",
        collection="MessageStreams",
        noun="message streams",
        detail="Can list the server's message streams and their types",
        access=AccessLevel.WRITE,
        risk_weight=65,
        source="https://postmarkapp.com/developer/api/message-streams-api",
    ),
    _Probe(
        service="Postmark Bounces",
        kind=Kind.SERVER,
        url=f"{API}/bounces",
        params={"count": PAGE_SIZE, "offset": OFFSET},
        collection="Bounces",
        noun="bounced recipients",
        detail=(
            "Can list bounced recipients, which is a list of real addresses "
            "this server has sent to"
        ),
        access=AccessLevel.WRITE,
        risk_weight=90,
        # Recipient addresses are other people's personal data, and a bounce
        # list is a ready-made target list for the same server's next message.
        data_sensitive=True,
        source="https://postmarkapp.com/developer/api/bounce-api",
    ),
    _Probe(
        service="Postmark Sender Signatures",
        kind=Kind.ACCOUNT,
        url=f"{API}/senders",
        params={"count": PAGE_SIZE, "offset": OFFSET},
        collection="SenderSignatures",
        noun="sender signatures",
        detail=(
            "Can list the addresses the account is verified to send from, "
            "which are real mailboxes belonging to real people"
        ),
        access=AccessLevel.ADMIN,
        risk_weight=85,
        data_sensitive=True,
        source="https://postmarkapp.com/developer/api/signatures-api",
    ),
    _Probe(
        service="Postmark Server",
        kind=Kind.SERVER,
        url=f"{API}/server",
        noun="server",
        detail=(
            "Can read the server's configuration, including its webhook URLs "
            "and its other API tokens"
        ),
        # Postmark documents Edit Server as requiring the same server token.
        access=AccessLevel.WRITE,
        risk_weight=95,
        # The response carries the server's other API tokens.
        data_sensitive=True,
        source="https://postmarkapp.com/developer/api/server-api",
    ),
    _Probe(
        service="Postmark Servers",
        kind=Kind.ACCOUNT,
        url=f"{API}/servers",
        params={"count": PAGE_SIZE, "offset": OFFSET},
        collection="Servers",
        noun="servers",
        detail=(
            "Can list every server on the account. Postmark documents creating "
            "and deleting servers as requiring this same token"
        ),
        access=AccessLevel.ADMIN,
        risk_weight=100,
        data_sensitive=True,
        source="https://postmarkapp.com/developer/api/servers-api",
    ),
)


def probes_for(kind: Kind) -> tuple[_Probe, ...]:
    """The probes a token of this kind can reach."""
    return tuple(probe for probe in PROBES if probe.kind is kind)


#: The endpoint whose answer — or whose refusal — establishes each kind.
#: ``/server`` and ``/servers`` are one character apart and are the two Postmark
#: names by which token type it wanted, which is what makes the kind
#: discoverable at all.
VALIDATE_SERVICES: Final[dict[Kind, str]] = {
    Kind.SERVER: "Postmark Server",
    Kind.ACCOUNT: "Postmark Servers",
}


def validation_probe(kind: Kind) -> _Probe:
    """The cheapest read that proves a token of this kind is live."""
    wanted = VALIDATE_SERVICES[kind]
    return next(probe for probe in probes_for(kind) if probe.service == wanted)


#: The field on ``GET /server`` holding the server's other API tokens. Counted,
#: never printed: the count is what tells a recipient how many more credentials
#: this one leak exposed.
API_TOKENS_FIELD: Final = "ApiTokens"


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Postmark's message, or ``""``.

    A refusal is ``{"ErrorCode": 10, "Message": "Request does not contain a
    valid Server token."}``, verified against the live API. The message is the
    part that names which token type was wanted.
    """
    value = _payload(response).get("Message")
    return value if isinstance(value, str) else ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    ``/server`` returns a single object rather than a list, and the number worth
    reporting about it is how many API tokens it carries — see
    :data:`API_TOKENS_FIELD`.
    """
    field = probe.collection or API_TOKENS_FIELD
    found = _payload(response).get(field)
    if not isinstance(found, list):
        return "request accepted"
    if probe.collection is None:
        return f"{probe.noun}: {len(found)} API tokens on it"
    if not found:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(found)} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(kind: Kind, response: ProbeResponse) -> Identity:
    """What Postmark discloses about the token, including which kind it is.

    The kind is the single most useful thing a recipient can be told here: a
    server token reaches one server's mail, and an account token reaches every
    server on the account and can create more.
    """
    payload = _payload(response)
    extra = {"token_type": kind.value}

    name = _string(payload, "Name")
    if name:
        extra["server"] = name

    return Identity(extra=extra)


def _poc(ctx: ProbeContext, kind: Kind, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    header = HEADERS[kind]
    return ctx.mask(f"curl -s -H '{header}: {ctx.key}' '{url}'")


def _send_capability(ctx: ProbeContext, response: ProbeResponse) -> Capability:
    """The capability derived from Postmark's documentation, never from a send.

    Postmark documents its send endpoint as requiring the server token and
    server level privileges. A live server token therefore sends mail as this
    server's verified signatures, and keyreach establishes that without putting
    a message in anybody's inbox.
    """
    return Capability(
        service="Postmark Email Send",
        access=AccessLevel.WRITE,
        detail=(
            "Can send email as this server, over the account's verified sender "
            "signatures. Postmark documents its send endpoint as requiring "
            "exactly this token. No message was sent"
        ),
        evidence=response.evidence(f"token type: {Kind.SERVER.value}"),
        risk_weight=100,
        # Every message spends the account's plan allowance.
        incurs_cost=True,
        poc=_poc(ctx, Kind.SERVER, validation_probe(Kind.SERVER).url),
        resource_ref="https://postmarkapp.com/developer/api/email-api",
    )


class PostmarkProvider(Provider):
    """Postmark server and account tokens."""

    name = "postmark"
    category = "email"
    docs_url = "https://postmarkapp.com/developer/api/overview"
    rotation_guide_url = "https://postmarkapp.com/support/article/1008-what-are-the-account-and-server-api-tokens"

    #: Postmark publishes no format for either token type, so a detection rule
    #: could only be written from a guess. See the module docstring.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``: there is no published format to match against."""
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Ask Postmark which kind of token this is, by trying both.

        Two requests rather than one, and unavoidably so: the two kinds are
        indistinguishable by shape, and sending an account token in the server
        header is a read that fails, not a write that succeeds.
        """
        responses = await ctx.gather(
            [
                ctx.get(
                    validation_probe(kind).url,
                    params=validation_probe(kind).params or None,
                    headers=headers_for(kind, key),
                )
                for kind in Kind
            ]
        )
        by_kind = dict(zip(Kind, responses, strict=True))

        for kind, response in by_kind.items():
            if response.ok:
                return ValidationResult(valid=True, identity=_identity(kind, response))

        server = by_kind[Kind.SERVER]
        messages = " / ".join(
            filter(None, (message_of(response) for response in responses))
        )

        if server.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; Postmark rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        if server.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    "Postmark accepted this token as neither a server token nor "
                    "an account token" + (f" ({messages})" if messages else "")
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Postmark's response could not be interpreted"
                + (f" ({messages})" if messages else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe only the endpoints this kind of token can reach.

        Rediscovering the kind costs nothing: ``validate`` already made both
        calls and ``ProbeClient`` caches repeated idempotent GETs for a run
        (R1.4). Probing the other kind's endpoints would be authentication
        traffic against a stranger's service for a result already known.
        """
        discovered = await self._kind_of(key, ctx)
        if discovered is None:
            return []
        kind, accepted = discovered

        probes = probes_for(kind)
        headers = headers_for(kind, key)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in probes
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=probe.access,
                detail=_detail(probe),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, kind, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(probes, responses, strict=True)
            if response.ok
        ]

        if kind is Kind.SERVER:
            # The response that established the kind is also the evidence for
            # the send capability, so there is no second lookup to get wrong.
            capabilities.append(_send_capability(ctx, accepted))

        return sorted(capabilities, key=lambda capability: capability.sort_key)

    @staticmethod
    async def _kind_of(
        key: str, ctx: ProbeContext
    ) -> tuple[Kind, ProbeResponse] | None:
        """Which kind of token this is, with the response that proved it.

        ``None`` when Postmark accepted it as neither.
        """
        for kind in Kind:
            probe = validation_probe(kind)
            response = await ctx.get(
                probe.url, params=probe.params or None, headers=headers_for(kind, key)
            )
            if response.ok:
                return kind, response
        return None


def _detail(probe: _Probe) -> str:
    """The capability detail, including where its access level came from."""
    privilege = (
        "account level privileges, which Postmark documents as accessible only "
        "to the account owner"
        if probe.kind is Kind.ACCOUNT
        else "server level privileges"
    )
    return (
        f"{probe.detail}. Postmark documents this endpoint as requiring "
        f"{privilege}. No write was performed"
    )
