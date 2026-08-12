"""Slack API tokens (``xox…``) — roadmap R1.6.

No prior art. Every method, header and error string below was written from
Slack's own documentation, and each probe cites the page it came from.

**The HTTP status is not the verdict.** Slack's Web API answers ``200 OK`` and
puts the outcome in the body: ``{"ok": false, "error": "invalid_auth"}``. A
plugin that trusted ``response.ok`` would report a revoked token as a live one
with five confirmed capabilities. Everything here therefore branches on the
``ok`` field, and ``tests/test_provider_slack.py`` pins that with a 200 that
means failure. keyreach has met this shape once before — the Google plugin has
to read ``REQUEST_DENIED`` out of a 200 — which is why it is worth stating
rather than discovering twice.

**Scopes, and why every capability is ``READ``.** Slack tokens carry granular
scopes: ``users:read`` is a different grant from ``chat:write``. A token that
lists the member directory has proved ``users:read`` and nothing about its
ability to post, so no capability here is a write and none sets
``incurs_cost``. When a token is live but lacks a scope, Slack returns
``missing_scope`` — a clean negative, and the reason a token typically produces
two or three capabilities rather than five.

**Bot tokens and user tokens are not the same exposure.** Slack documents
``xoxb-`` as a bot token and ``xoxp-`` as a user token that acts on behalf of the
person who authorised it. A leaked user token therefore reaches whatever that
human can reach, which is usually every private channel they are in. keyreach
cannot enumerate that reach without reading messages, which it will not do, so
the difference is recorded in the capability detail rather than invented into a
capability.
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
# Token formats
# --------------------------------------------------------------------------
#
# Mirrors the `slack-token` rule in `keyreach/patterns/detection_rules.yml`;
# `tests/test_provider_slack.py` asserts the two agree.
# Source: https://docs.slack.dev/authentication/tokens

_PATTERN: Final = re.compile(r"^xox[baprs]-[0-9A-Za-z-]{10,}$")

#: Confidence for the whole ``xox…`` family. The prefix is Slack's alone and no
#: other vendor uses it, but the body is unconstrained, so this is 0.99 for the
#: prefix rather than for a fixed shape.
CONFIDENCE: Final = 0.99


class _Kind(StrEnum):
    """Which kind of principal the token acts as, from its documented prefix."""

    BOT = "bot"
    """``xoxb-`` — acts as the app's bot user."""

    USER = "user"
    """``xoxp-`` — acts on behalf of the member who authorised the app."""

    OTHER = "other"
    """Any other ``xox…`` form. Recognised, but nothing extra is claimed."""


_BOT_PREFIX: Final = "xoxb-"
_USER_PREFIX: Final = "xoxp-"


def kind_of(token: str) -> _Kind:
    """The principal a token acts as, from its documented prefix."""
    if token.startswith(_BOT_PREFIX):
        return _Kind.BOT
    if token.startswith(_USER_PREFIX):
        return _Kind.USER
    return _Kind.OTHER


# --------------------------------------------------------------------------
# Slack's error vocabulary
# --------------------------------------------------------------------------
#
# Every documented error arrives as a string in the `error` field of a 200
# response. Branching on these rather than on prose keeps the verdict
# deterministic: Slack rewrites messages, but these strings are a contract.
# Source: https://docs.slack.dev/reference/methods/auth.test

#: The token is not, or is no longer, a token.
DEAD_TOKEN_ERRORS: Final[frozenset[str]] = frozenset(
    {
        "account_inactive",
        "invalid_auth",
        "not_authed",
        "token_expired",
        "token_revoked",
    }
)

#: The token is live and simply lacks the scope for this method. A clean
#: negative: no capability, and emphatically not a dead token.
MISSING_SCOPE: Final = "missing_scope"

#: The token is live and Slack is throttling.
RATE_LIMITED: Final = "ratelimited"


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://slack.com/api"

#: Page size for every list method. Slack spells it ``limit`` on the modern
#: cursor-paginated methods and ``count`` on ``files.list``.
PAGE_SIZE: Final = "1"


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
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    scope: str = Field(description="Slack scope this method requires.")
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this method.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Slack Channels",
        url=f"{API}/conversations.list",
        params={"limit": PAGE_SIZE},
        collection="channels",
        noun="conversations",
        detail=(
            "Can list the workspace's channels, including private ones the "
            "token can see"
        ),
        scope="channels:read",
        risk_weight=70,
        source="https://docs.slack.dev/reference/methods/conversations.list",
    ),
    _Probe(
        service="Slack Files",
        url=f"{API}/files.list",
        params={"count": PAGE_SIZE},
        collection="files",
        noun="files",
        detail="Can list files shared in the workspace, with their download URLs",
        scope="files:read",
        risk_weight=90,
        # A file list is an index of whatever the company shares internally,
        # and each entry carries a URL the same token can fetch.
        data_sensitive=True,
        source="https://docs.slack.dev/reference/methods/files.list",
    ),
    _Probe(
        service="Slack Identity",
        url=f"{API}/auth.test",
        noun="identity",
        detail="Can authenticate to Slack and identify the workspace and principal",
        scope="none",
        risk_weight=55,
        source="https://docs.slack.dev/reference/methods/auth.test",
    ),
    _Probe(
        service="Slack Users",
        url=f"{API}/users.list",
        params={"limit": PAGE_SIZE},
        collection="members",
        noun="members",
        detail=(
            "Can list workspace members, including their real names, email "
            "addresses and time zones"
        ),
        scope="users:read",
        risk_weight=90,
        # Names and email addresses of real people: personal data, and a ready
        # made target list for phishing the workspace.
        data_sensitive=True,
        source="https://docs.slack.dev/reference/methods/users.list",
    ),
    _Probe(
        service="Slack Workspace",
        url=f"{API}/team.info",
        noun="workspace",
        detail="Can read the workspace's name, domain and email domain",
        scope="team:read",
        risk_weight=60,
        source="https://docs.slack.dev/reference/methods/team.info",
    ),
)

#: ``auth.test`` requires no scope at all, which makes it the one method every
#: live token can reach — so it is both the liveness check and the capability
#: that proves the token authenticates.
VALIDATE_SERVICE: Final = "Slack Identity"


def validation_probe() -> _Probe:
    """The cheapest read that proves a token is live and says whose it is."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(token: str) -> dict[str, str]:
    """Bearer auth, which Slack states it prefers over the ``token`` parameter.

    Source: https://docs.slack.dev/apis/web-api/
    """
    return {"Authorization": f"Bearer {token}"}


def _body(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    payload = response.json_or_none()
    return payload if isinstance(payload, dict) else {}


def succeeded(response: ProbeResponse) -> bool:
    """Did Slack say the call worked?

    ``response.ok`` is not enough and never has been: Slack answers 200 for
    ``invalid_auth``. Both are required — a 500 with no body is not a success
    either — but the ``ok`` field is the one that carries the verdict.
    """
    return response.ok and _body(response).get("ok") is True


def error_of(response: ProbeResponse) -> str:
    """Slack's documented error string, or ``""`` if the body carried none."""
    value = _body(response).get("error")
    return value if isinstance(value, str) else ""


def _count(probe: _Probe, response: ProbeResponse) -> int | None:
    """Length of the list this method returns, by its documented field name."""
    if probe.collection is None:
        return None
    items = _body(response).get(probe.collection)
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


def _identity(response: ProbeResponse) -> Identity | None:
    """Workspace and principal, from an ``auth.test`` response.

    An exposed token that names its own workspace tells the recipient which
    Slack admin to contact, and the principal tells them which app or member to
    disable — which is most of what a disclosure report is for.
    """
    payload = _body(response)
    team = _string(payload, "team")
    team_id = _string(payload, "team_id")
    if not team and not team_id:
        return None

    extra = {}
    for field in ("user", "user_id", "bot_id", "url"):
        value = _string(payload, field)
        if value:
            extra[field] = value

    return Identity(account=team_id or team, owner=team or None, extra=extra)


def _poc(ctx: ProbeContext, token: str, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(token).items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


class SlackProvider(Provider):
    """Slack bot, user and app tokens."""

    name = "slack"
    category = "comms"
    docs_url = "https://docs.slack.dev/authentication/tokens"
    rotation_guide_url = (
        "https://docs.slack.dev/authentication/best-practices-for-security"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``xox…`` prefixes."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One call to ``auth.test``, the method that needs no scope.

        Only Slack's documented dead-token errors mean the token is not a token.
        ``missing_scope`` cannot occur here — ``auth.test`` requires none — and
        ``ratelimited`` means a live token being throttled, so collapsing either
        into "invalid" would retire a working credential.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))

        if succeeded(response):
            return ValidationResult(valid=True, identity=_identity(response))

        error = error_of(response)

        if error in DEAD_TOKEN_ERRORS:
            return ValidationResult(
                valid=False, note=f"Slack rejected this token ({error})"
            )

        if error == RATE_LIMITED:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; Slack rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Slack's response could not be interpreted"
                + (f" ({error})" if error else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Call every method concurrently; keep the ones Slack said ``ok`` to.

        A ``missing_scope`` reply drops the probe silently, which is the correct
        outcome: the token demonstrably cannot do that thing, and recording it
        would describe a workspace the token cannot actually reach.
        """
        kind = kind_of(key)
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
                # READ everywhere. Slack scopes are granular, so `users:read`
                # says nothing about `chat:write`, and keyreach does not post a
                # message to find out.
                access=AccessLevel.READ,
                detail=_detail(probe, kind),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if succeeded(response)
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, kind: _Kind) -> str:
    """The capability detail, including the scope it proves and what it does not."""
    detail = f"{probe.detail}. Confirms the {probe.scope} scope"
    if kind is _Kind.USER:
        detail += (
            ". This is a user token, so it acts as the member who authorised "
            "it and reaches whatever they can reach"
        )
    return f"{detail}. Posting was not tested: keyreach never sends a message"
