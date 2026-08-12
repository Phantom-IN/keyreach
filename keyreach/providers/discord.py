"""Discord bot tokens — roadmap R2.2.

No prior art. The base URL, the authorization header, the application flags and
their bit values come from Discord's own documentation; every path was confirmed
against Discord's live API, which answers ``401`` for a path that exists and
``404`` for one that does not.

**Discord is undetectable, and that is why this item was deferred.** R1.6 left
Discord out with a one-line reason: its bot-token format is community knowledge
rather than published documentation. Discord's reference shows an *example*
token and documents only how to send it — ``Authorization: Bot <token>`` — never
its prefix, length or segment structure. A rule built from one example is a
guess, and `plan.md` §5.2 forbids exactly that.

R2.1 supplied the answer without needing a guess: ``detectable = False``. The
plugin is never a detection candidate, so it can never produce a false positive,
and the operator reaches it by name::

    keyreach 'BOT_TOKEN' --provider discord

which the report records as an assertion rather than a rule's verdict. Two
providers in R2.2 are in this state and neither is a payment API, which
generalises R2.1's finding: **undetectable credentials are not a quirk of the
payment category.** See `plan.md` §5.2.

**One capability comes from a documented flag rather than from a probe.**
``GET /applications/@me`` returns ``flags``, and Discord documents
``GATEWAY_MESSAGE_CONTENT`` (``1 << 18``) as the privileged intent required to
receive message content. A bot holding it reads what people type, across every
server it is in. keyreach records that reach and does **not** enumerate the
messages — the same line the Telegram plugin draws around ``getUpdates`` (R1.6).
When the flag is absent, nothing is claimed.

**What this plugin will not claim.** A bot token can post, ban and manage
channels. keyreach sends no message and touches no guild, so every capability is
``READ`` and none sets ``incurs_cost`` — Discord's API is free, so the exposure
is data and impersonation rather than billing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

#: Pinned. Discord's reference notes that the *default* version is older than
#: the one it recommends, so following the default would silently change what
#: keyreach reads.
#: Source: https://docs.discord.com/developers/reference
API_VERSION: Final = "v10"
API: Final = f"https://discord.com/api/{API_VERSION}"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Shortest string worth sending to Discord. Not a published fact and never used
#: to *detect* anything — only to refuse an obviously empty argument after the
#: operator has already named the provider.
MIN_TOKEN_LENGTH: Final = 16


# --------------------------------------------------------------------------
# Privileged intents
# --------------------------------------------------------------------------
#
# Discord documents these as bits of the application's `flags` field, and as
# "privileged": an app only holds one if a human enabled it in the developer
# portal, and for large apps only after Discord approved it. So the bit is a
# vendor statement about what the bot can receive.
# Source: https://docs.discord.com/developers/resources/application

MESSAGE_CONTENT_INTENT: Final = 1 << 18
GUILD_MEMBERS_INTENT: Final = 1 << 14


class _Intent(BaseModel):
    """A privileged intent, and the capability holding it establishes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bit: int
    service: str
    flag: str
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = True


INTENTS: Final[tuple[_Intent, ...]] = (
    _Intent(
        bit=GUILD_MEMBERS_INTENT,
        service="Discord Member List",
        flag="GATEWAY_GUILD_MEMBERS",
        detail=(
            "The app holds the privileged guild members intent, so it receives "
            "member-related events for every server it is in — the membership "
            "of those servers, as it changes"
        ),
        risk_weight=85,
    ),
    _Intent(
        bit=MESSAGE_CONTENT_INTENT,
        service="Discord Message Content",
        flag="GATEWAY_MESSAGE_CONTENT",
        detail=(
            "The app holds the privileged message content intent, so it "
            "receives the text of messages across every server it is in. The "
            "messages themselves were not read: keyreach does not collect them"
        ),
        risk_weight=95,
    ),
)


def intents_of(flags: object) -> tuple[_Intent, ...]:
    """The privileged intents this application's ``flags`` field asserts.

    ``bool`` is rejected alongside non-integers: ``{"flags": true}`` is not a
    bitfield, and in Python it would otherwise test as ``1``.
    """
    if not isinstance(flags, int) or isinstance(flags, bool):
        return ()
    return tuple(intent for intent in INTENTS if flags & intent.bit)


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    lists: bool = Field(
        default=False, description="Does this endpoint return a bare JSON array?"
    )
    noun: str = Field(description="What the response describes, for the evidence.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


#: Page size for the guild list. Discord spells it ``limit``.
PAGE_SIZE: Final = "1"

_DOCS: Final = "https://docs.discord.com/developers"

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Discord Application",
        url=f"{API}/applications/@me",
        noun="application",
        detail=(
            "Can read the application itself, including its owner and the "
            "privileged intents it holds"
        ),
        risk_weight=75,
        source=f"{_DOCS}/resources/application",
    ),
    _Probe(
        service="Discord Bot Identity",
        url=f"{API}/users/@me",
        noun="bot user",
        detail="Can authenticate to Discord and read the bot's own account",
        risk_weight=60,
        source=f"{_DOCS}/resources/user",
    ),
    _Probe(
        service="Discord Servers",
        url=f"{API}/users/@me/guilds",
        params={"limit": PAGE_SIZE},
        lists=True,
        noun="servers",
        detail=(
            "Can list the servers the bot has been added to, which is the set "
            "of communities it can act in"
        ),
        risk_weight=85,
        # A server list names the organisations and communities that trusted
        # this bot — useful to an attacker before a single message is read.
        data_sensitive=True,
        source=f"{_DOCS}/resources/user",
    ),
)

#: ``/users/@me`` is the cheapest read and the one that names the bot.
VALIDATE_SERVICE: Final = "Discord Bot Identity"

#: The probe whose ``flags`` field carries the privileged intents.
APPLICATION_SERVICE: Final = "Discord Application"


def validation_probe() -> _Probe:
    """The cheapest read that proves a token is live and says which bot it is."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(token: str) -> dict[str, str]:
    """The documented bot authorization header.

    Source: https://docs.discord.com/developers/reference
    """
    return {"Authorization": f"Bot {token}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: Discord's
    edge returns HTML for some failures, and that must degrade to "no structured
    body" rather than raise out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Discord's human-readable error message, or ``""``."""
    value = _payload(response).get("message")
    return value if isinstance(value, str) else ""


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    if not probe.lists:
        return "request accepted"
    body = response.json_or_none()
    if not isinstance(body, list):
        return "request accepted"
    if not body:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(body)} listed"


def _identity(response: ProbeResponse) -> Identity | None:
    """The bot, from its own ``/users/@me`` response.

    An exposed token that names its own bot tells the recipient which
    application to go and regenerate, which is most of what identity is for.
    """
    payload = _payload(response)
    bot_id = _string(payload, "id")
    username = _string(payload, "username")
    if not bot_id and not username:
        return None
    return Identity(
        account=bot_id or None,
        owner=f"@{username}" if username else None,
    )


def _poc(ctx: ProbeContext, token: str, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(token).items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


def _intent_capability(
    intent: _Intent, response: ProbeResponse, ctx: ProbeContext, token: str
) -> Capability:
    """A capability Discord states in a flag rather than one keyreach probed for."""
    return Capability(
        service=intent.service,
        access=AccessLevel.READ,
        detail=intent.detail,
        evidence=response.evidence(f"application flags include {intent.flag}"),
        risk_weight=intent.risk_weight,
        data_sensitive=intent.data_sensitive,
        poc=_poc(ctx, token, response),
        resource_ref=f"{_DOCS}/resources/application",
    )


class DiscordProvider(Provider):
    """Discord bot tokens."""

    name = "discord"
    category = "comms"
    docs_url = "https://docs.discord.com/developers/reference"
    rotation_guide_url = "https://discord.com/developers/applications"

    #: Discord publishes no bot-token format, so no rule could recognise one.
    #: See the module docstring; ``--provider discord`` is the documented route.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``. Discord publishes no token format.

        The community pattern — three dot-separated segments — describes what
        Discord's example token happens to look like, not a format Discord has
        committed to. Encoding it here would be a guess wearing a regular
        expression, and it would also claim every JWT ever pasted at keyreach.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/users/@me``, the cheapest endpoint that names the bot."""
        if len(key) < MIN_TOKEN_LENGTH:
            return ValidationResult(
                valid=False,
                note=(
                    "This is too short to be a Discord bot token. Pass the bot "
                    "token from the application's Bot page"
                ),
            )

        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(response))

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Discord rejected this token"
                    + (f" ({message})" if message else "")
                    + ". Note that a bot token and an OAuth2 client secret are "
                    "different credentials; only the first is used here"
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; Discord refused this request"
                    + (f" ({message})" if message else "")
                    + ". The capabilities below are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; Discord rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Discord's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe each endpoint, then add whatever the application flags assert."""
        headers = _auth(key)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere. A bot token can post and ban; keyreach does
                # neither to find out.
                access=AccessLevel.READ,
                detail=(
                    f"{probe.detail}. Posting and moderation were not tested: "
                    "keyreach never sends a message or touches a server"
                ),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]

        application = responses[PROBES.index(_application_probe())]
        if application.ok:
            capabilities.extend(
                _intent_capability(intent, application, ctx, key)
                for intent in intents_of(_payload(application).get("flags"))
            )

        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _application_probe() -> _Probe:
    return next(probe for probe in PROBES if probe.service == APPLICATION_SERVICE)
