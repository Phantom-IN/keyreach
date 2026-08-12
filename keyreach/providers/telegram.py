"""Telegram bot tokens (``<bot id>:<secret>``) — roadmap R1.6.

No prior art. Every method and response field below was written from Telegram's
own Bot API documentation, and each probe cites it.

**The token is in the path, not a header.** Telegram documents requests as
``https://api.telegram.org/bot<token>/METHOD_NAME``. That makes redaction load
bearing rather than cosmetic: without it every recorded cassette, every evidence
string and every proof-of-concept command in the report would contain a live
bot token. The redactor already rewrites URLs, so the recorded form is
``…/bot<key>/getMe`` and a committed fixture replays against any token.

**One capability is derived from a response field rather than from a probe.**
``getMe`` returns ``can_read_all_group_messages``, which Telegram documents as
"True, if privacy mode is disabled for the bot". A bot with privacy mode
disabled receives *every* message in every group it belongs to, not just the
ones addressed to it. That is a capability the vendor states outright, so
keyreach records it — and it is the difference between a leaked bot token being
an impersonation problem and being a data-exposure problem. When the field is
absent or false, no such capability is recorded; keyreach does not guess.

**``getUpdates`` is deliberately not probed.** It is the one getter with side
effects: Telegram documents that supplying an ``offset`` confirms previously
received updates, and that it conflicts with an active webhook. Reading a
stranger's pending messages would also be exactly the kind of collection
``plan.md`` §11 rules out. The webhook URL from ``getWebhookInfo`` establishes
the same reach without it.

**What this plugin will not claim.** A bot token can send messages as the bot,
which is an impersonation risk rather than a billing one — the Bot API is free —
so no capability sets ``incurs_cost``, and none is a write, because keyreach
never sends a message to prove it could.
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
# Token format
# --------------------------------------------------------------------------
#
# Mirrors the `telegram-bot-token` rule in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_telegram.py`
# asserts the two agree.
# Source: https://core.telegram.org/bots/api#authorizing-your-bot

_PATTERN: Final = re.compile(r"^(?P<bot_id>[0-9]{8,10}):[A-Za-z0-9_-]{35}$")

#: Below 0.99 on purpose. The shape — digits, a colon, 35 token characters — is
#: distinctive but carries no vendor prefix, so it is a strong signal rather than
#: an unambiguous one.
CONFIDENCE: Final = 0.95


def bot_id_of(token: str) -> str:
    """The numeric bot id, which Telegram puts in front of the colon.

    Not a secret: it is the bot's account number and appears in its public
    profile. It is what tells a recipient *which* bot to revoke, so it is the
    one part of the token the report names.
    """
    matched = _PATTERN.match(token)
    return matched.group("bot_id") if matched else ""


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.telegram.org"


def method_url(token: str, method: str) -> str:
    """The documented request URL for one Bot API method."""
    return f"{API}/bot{token}/{method}"


#: Telegram answers ``401`` with ``{"ok": false, "description": "Unauthorized"}``
#: for a token it does not recognise. Both signals are available; ``ok`` is the
#: one branched on, because the body is the documented contract and a proxy can
#: rewrite a status.
_HTTP_UNAUTHORIZED: Final = 401
_HTTP_TOO_MANY_REQUESTS: Final = 429


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    method: str = Field(description="Bot API method name.")
    collection: str | None = Field(
        default=None,
        description="Set when ``result`` is a list, for the evidence count.",
    )
    noun: str = Field(description="What the response describes, for the evidence.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this method.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Telegram Bot Commands",
        method="getMyCommands",
        collection="result",
        noun="commands",
        detail="Can read the command list the bot advertises to users",
        risk_weight=35,
        source="https://core.telegram.org/bots/api#getmycommands",
    ),
    _Probe(
        service="Telegram Bot Identity",
        method="getMe",
        noun="bot",
        detail=(
            "Can authenticate as the bot and read its identity, including its "
            "username and whether privacy mode is disabled"
        ),
        risk_weight=60,
        source="https://core.telegram.org/bots/api#getme",
    ),
    _Probe(
        service="Telegram Bot Profile",
        method="getMyDescription",
        noun="description",
        detail="Can read the bot's public description",
        risk_weight=30,
        source="https://core.telegram.org/bots/api#getmydescription",
    ),
    _Probe(
        service="Telegram Webhook",
        method="getWebhookInfo",
        noun="webhook",
        detail=(
            "Can read the webhook configuration, which discloses the URL of "
            "the backend service receiving the bot's updates"
        ),
        risk_weight=70,
        source="https://core.telegram.org/bots/api#getwebhookinfo",
    ),
)

#: ``getMe`` is the documented way to test a token, and it is also where the
#: identity and the privacy-mode capability come from.
VALIDATE_SERVICE: Final = "Telegram Bot Identity"

#: The field ``getMe`` sets when privacy mode is off. Telegram: "True, if
#: privacy mode is disabled for the bot".
PRIVACY_MODE_FIELD: Final = "can_read_all_group_messages"


def validation_probe() -> _Probe:
    """The cheapest read that proves a token is live and says which bot it is."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def succeeded(response: ProbeResponse) -> bool:
    """Did Telegram say the call worked? The ``ok`` field is the contract."""
    return _payload(response).get("ok") is True


def _description(response: ProbeResponse) -> str:
    value = _payload(response).get("description")
    return value if isinstance(value, str) else ""


def _result(response: ProbeResponse) -> Any:
    return _payload(response).get("result")


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    result = _result(response)
    if probe.collection is None:
        return "request accepted"
    if not isinstance(result, list):
        return "request accepted"
    if not result:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(result)} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def privacy_mode_disabled(response: ProbeResponse) -> bool:
    """Does ``getMe`` say this bot receives every group message?

    Strictly ``is True``: a missing field, a null, or a string means Telegram did
    not assert it, and an unasserted capability is not a confirmed one.
    """
    result = _result(response)
    if not isinstance(result, dict):
        return False
    return result.get(PRIVACY_MODE_FIELD) is True


def _identity(token: str, response: ProbeResponse) -> Identity:
    """The bot, from its own ``getMe`` response.

    The bot id comes from the token rather than the response so that an identity
    is still produced when Telegram answers with an unexpected shape — it is the
    fact a recipient needs in order to find and revoke the bot.
    """
    result = _result(response)
    payload = result if isinstance(result, dict) else {}
    username = _string(payload, "username")
    return Identity(
        account=bot_id_of(token) or None,
        owner=f"@{username}" if username else None,
        extra=(
            {"first_name": name} if (name := _string(payload, "first_name")) else {}
        ),
    )


def _poc(ctx: ProbeContext, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    The URL from the response is already redacted, so this is masked twice over
    — which is the intended belt and braces for a provider that carries its
    secret in the path.
    """
    return ctx.mask(f"curl -s '{response.url}'")


def _group_message_capability(ctx: ProbeContext, response: ProbeResponse) -> Capability:
    """The capability Telegram states rather than one keyreach probed for.

    Privacy mode is a documented property of the bot, returned by ``getMe``. A
    bot with it disabled receives every message sent in every group it is a
    member of. keyreach cannot enumerate those groups without reading updates,
    which it will not do, so the capability records the reach without the
    contents — and says which it is.
    """
    return Capability(
        service="Telegram Group Messages",
        access=AccessLevel.READ,
        detail=(
            "Privacy mode is disabled, so this bot receives every message sent "
            "in every group it belongs to, not only those addressed to it. The "
            "groups themselves were not enumerated: that would mean reading "
            "the pending updates"
        ),
        evidence=response.evidence(f"getMe reports {PRIVACY_MODE_FIELD}: true"),
        risk_weight=90,
        data_sensitive=True,
        # The same `getMe` call the capability was read out of. A finding whose
        # only support is "keyreach says so" is one a triager cannot check, and
        # this is the one capability here with no probe of its own.
        poc=_poc(ctx, response),
        resource_ref="https://core.telegram.org/bots/api#getme",
    )


class TelegramProvider(Provider):
    """Telegram Bot API tokens."""

    name = "telegram"
    category = "comms"
    docs_url = "https://core.telegram.org/bots/api#authorizing-your-bot"
    rotation_guide_url = "https://core.telegram.org/bots/features#botfather"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``<bot id>:<secret>`` form."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One ``getMe`` call, which Telegram documents as the way to test a token."""
        probe = validation_probe()
        response = await ctx.get(method_url(key, probe.method))

        if succeeded(response):
            return ValidationResult(valid=True, identity=_identity(key, response))

        description = _description(response)

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Telegram rejected this bot token"
                    + (f" ({description})" if description else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; Telegram rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Telegram's response could not be interpreted"
                + (f" ({description})" if description else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Call every getter concurrently; keep the ones Telegram said ``ok`` to."""
        responses = await ctx.gather(
            [ctx.get(method_url(key, probe.method)) for probe in PROBES]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=AccessLevel.READ,
                detail=(
                    f"{probe.detail}. Sending was not tested: keyreach never "
                    "posts a message as the bot"
                ),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if succeeded(response)
        ]

        identity_response = responses[PROBES.index(validation_probe())]
        if succeeded(identity_response) and privacy_mode_disabled(identity_response):
            capabilities.append(_group_message_capability(ctx, identity_response))

        return sorted(capabilities, key=lambda capability: capability.sort_key)
