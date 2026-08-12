"""Mailgun API keys — roadmap R2.3.

No prior art. Every path below was verified against Mailgun's live API, which
answers 401 for a path that exists and 404 for one that does not, and each probe
cites the vendor page it came from.

**This plugin sets ``detectable = False``, and doing so meant withdrawing a
detection rule keyreach had shipped since R0.5.** That rule was
``^key-[0-9a-f]{32}$``, sourced to Mailgun's authentication page. Re-reading that
page for this item found it now documents only ``curl --user 'api:YOUR_API_KEY'``
— no prefix, no length, no charset — and neither does any other page Mailgun
publishes, including the API key management guide it rewrote around its RBAC
roles. A rule whose cited source no longer supports it cannot be re-verified by
anybody, which is the property ``detection_rules.yml`` exists to guarantee, so it
is withdrawn rather than quietly kept. Mailgun is reached with ``--provider
mailgun``, and the report records that the operator asserted the provider.

Every provider that has declared itself undetectable so far — PayPal, Discord,
Zoom — never had a published format to begin with. **Mailgun is the first where
keyreach had one and lost it**, which is a different event: it is drift, and it
is what roadmap **R2.10**'s canary is meant to catch without a human re-reading
the documentation.

**Every capability here is ``READ``, and that is not conservatism for its own
sake.** Mailgun documents account API keys as having "full access to your
Mailgun account", which would justify a write — but it also documents four RBAC
roles (Admin, Analyst, Developer, Support), of which Analyst is "read only
access to data and metrics". Nothing Mailgun publishes exposes *which* role the
calling key holds; ``/v1/keys`` lists the account's keys with a ``role`` field
but does not say which entry is the key doing the asking. So the vendor sentence
that would license a write does not apply to every key, and keyreach cannot tell
which kind it is holding. It reports what it proved.

**A domain sending key cannot be validated at all, and the rejection says so.**
Mailgun documents those keys as permitting only a POST to the message endpoint,
which keyreach will never make. Every read here therefore fails for such a key,
with the same "Invalid private key" a revoked key gets — Mailgun does not
distinguish the two the way Resend does. Reporting "dead key" would be a guess
dressed as a verdict, so the note says which of the two it could be.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.mailgun.net"

#: Page size for every list probe. Mailgun spells it ``limit``.
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: What Mailgun documents an account API key as holding, quoted so a reader can
#: see why it is *not* used to claim a write here — see the module docstring.
FULL_ACCESS_STATEMENT: Final = (
    "Mailgun documents account API keys as having full access to the account, "
    "but also documents an Analyst role with read-only access, and publishes "
    "nothing that says which role this key holds. Write access is therefore "
    "undetermined, and no write was attempted"
)


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
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Mailgun API Keys",
        url=f"{API}/v1/keys",
        collection="items",
        noun="API keys",
        detail=(
            "Can list the account's API keys, including each one's kind, role "
            "and the address of whoever requested it"
        ),
        risk_weight=90,
        # Key metadata plus the email addresses of the people who hold them.
        data_sensitive=True,
        source="https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/keys",
    ),
    _Probe(
        service="Mailgun Domains",
        url=f"{API}/v3/domains",
        params={"limit": PAGE_SIZE},
        collection="items",
        noun="domains",
        detail=(
            "Can list the account's sending domains, which are the domains this "
            "account's mail is trusted to come from"
        ),
        risk_weight=80,
        source="https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/domains",
    ),
    _Probe(
        service="Mailgun Mailing Lists",
        url=f"{API}/v3/lists/pages",
        params={"limit": PAGE_SIZE},
        collection="items",
        noun="mailing lists",
        detail=(
            "Can list the account's mailing lists and their member counts, "
            "which are lists of real people who gave this company an address"
        ),
        risk_weight=95,
        data_sensitive=True,
        source="https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/mailing-lists",
    ),
    _Probe(
        service="Mailgun Routes",
        url=f"{API}/v3/routes",
        params={"limit": PAGE_SIZE},
        collection="items",
        noun="routes",
        detail=(
            "Can list inbound routes, which say where the account's incoming "
            "mail is forwarded to"
        ),
        risk_weight=85,
        # A route is a destination address, and often an internal endpoint.
        data_sensitive=True,
        source="https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/routes",
    ),
)

#: ``/v3/domains`` is the cheapest read that proves the credential works and
#: lists nothing about a person. ``/v1/keys`` would also work and would disclose
#: the account's other credentials, so it is a probe rather than the liveness
#: check.
VALIDATE_SERVICE: Final = "Mailgun Domains"


def validation_probe() -> _Probe:
    """The cheapest read that proves the key is live and names nobody."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """Basic auth with the username ``api``, as Mailgun documents it.

    "Authentication to the Mailgun API is done by providing an Authorization
    header using HTTP Basic Auth" — username ``api``, password the API key.
    Source: https://documentation.mailgun.com/docs/mailgun/api-reference/mg-auth
    """
    raw = f"api:{key}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Mailgun's message, or ``""``.

    A rejected credential returns ``{"message": "Invalid private key"}``,
    verified against the live API.
    """
    value = _payload(response).get("message")
    return value if isinstance(value, str) else ""


def _count(probe: _Probe, response: ProbeResponse) -> int | None:
    """Length of the list this endpoint returns, by its documented field name."""
    if probe.collection is None:  # pragma: no cover - every probe declares one
        return None
    items = _payload(response).get(probe.collection)
    return len(items) if isinstance(items, list) else None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    found = _count(probe, response)
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {found} listed"


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    Uses ``-u`` rather than a base64 header so the reproduction is legible and
    the masked key is visible as a key.
    """
    return ctx.mask(f"curl -s -u 'api:{ctx.key}' '{url}'")


#: Said whenever Mailgun refuses the credential. A domain sending key is
#: documented as permitting only a POST to the message endpoint, so it fails
#: every read here — with the same message a revoked key gets. keyreach cannot
#: tell the two apart, and says so rather than picking one.
_SENDING_KEY_CAVEAT: Final = (
    "Note that Mailgun domain sending keys are documented as permitting only a "
    "send, which keyreach will not perform, so a live sending key is refused "
    "here exactly as a revoked key is"
)


class MailgunProvider(Provider):
    """Mailgun API keys."""

    name = "mailgun"
    category = "email"
    docs_url = "https://documentation.mailgun.com/docs/mailgun/api-reference/mg-auth"
    rotation_guide_url = (
        "https://documentation.mailgun.com/docs/mailgun/user-manual/api-key-mgmt/"
        "rbac-mgmt"
    )

    #: Mailgun publishes no credential format. It did — `key-<32 hex>` — and the
    #: page that documented it no longer does, so the rule was withdrawn in R2.3
    #: rather than kept as an unverifiable claim. See the module docstring.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``: there is no published format to match against.

        Not a stub. Returning anything else would make this plugin a detection
        candidate on the strength of a shape Mailgun does not publish, which is
        the false-positive machine `plan.md` §5.2 rules out.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/v3/domains``, the cheapest read that names nobody."""
        probe = validation_probe()
        response = await ctx.get(
            probe.url, params=probe.params or None, headers=_auth(key)
        )
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True)

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Mailgun did not accept this key"
                    + (f" ({message})" if message else "")
                    + f". {_SENDING_KEY_CAVEAT}"
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Mailgun refused this endpoint"
                    + (f" ({message})" if message else "")
                    + ". The capabilities below are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Mailgun rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Mailgun's response could not be interpreted"
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

        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere, deliberately — see the module docstring. The
                # sentence that would license a write does not apply to every
                # Mailgun key, and nothing exposes which kind this one is.
                access=AccessLevel.READ,
                detail=f"{probe.detail}. {FULL_ACCESS_STATEMENT}",
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
