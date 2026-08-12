"""npm registry access tokens — roadmap R2.4.

No prior art. Both paths below come from npm's own registry API reference
(``api-docs.npmjs.com``) and were verified against the live registry, which
answers 401 for a path that exists and 404 for one that does not.

**This plugin sets ``detectable = False``, and doing so meant withdrawing a
detection rule keyreach had shipped since R0.5** — the second withdrawal in two
roadmap items, after Mailgun in R2.3. That rule was ``^npm_[A-Za-z0-9]{36}$``,
sourced to npm's "About access tokens" page. Re-reading that page for this item
found it describes a token only as "a hexadecimal string that you can use to
authenticate": no prefix, and a charset the rule contradicts. npm's CLI
reference says "for security purposes the full token is not displayed", and its
CI/CD guide says "Do **not** put a token in this file" — so npm deliberately
avoids printing a token value anywhere in its own documentation, and there is
nowhere left to source a format from.

The same page records that legacy tokens were removed in November 2025 and only
granular access tokens remain, so the rule was also written against a format npm
no longer issues. Reached with ``--provider npm``.

**Two probes, and that is all npm publishes that a bare token can reach.** Its
documented endpoints are otherwise scoped to an organization or a package name
that keyreach does not have and will not guess. Notably npm publishes **no
"who am I" endpoint** in its API reference, so this report names the account's
tokens rather than the person — an unusual gap, and one keyreach declines to
paper over with an undocumented path.

**Every capability is ``READ``.** npm documents granular tokens as read-only or
read-and-write, and ``/-/npm/v1/tokens`` returns ``readonly``, ``permissions``
and ``scopes`` **per token in the account** without marking which entry is the
one asking. So the vocabulary exists, is not attributable to the calling
credential, and is not used — the third provider in this item to take that
position, after Bitbucket and Docker Hub.

**What the token list is, though, is the finding.** A leaked npm token that can
read it discloses every other token on the account, including which of them can
publish. That is the same shape as Postmark's ``ApiTokens`` in R2.3: keyreach
counts them and prints none.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

REGISTRY: Final = "https://registry.npmjs.org"

API_DOCS: Final = "https://api-docs.npmjs.com/"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Quoted from npm's access-token documentation, and recorded so the capability
#: detail says precisely what keyreach could not determine.
SCOPE_STATEMENT: Final = (
    "npm documents granular tokens as read-only or read-and-write and returns "
    "readonly, permissions and scopes per token in the account without marking "
    "which entry is the calling one, so write access is undetermined and none "
    "was attempted"
)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
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
        service="npm Staged Versions",
        url=f"{REGISTRY}/-/stage",
        noun="staged versions",
        detail=(
            "Can list package versions staged for publication, which are "
            "releases the account has prepared and not yet made public"
        ),
        risk_weight=75,
        source=API_DOCS,
    ),
    _Probe(
        service="npm Tokens",
        url=f"{REGISTRY}/-/npm/v1/tokens",
        collection="objects",
        noun="tokens",
        detail=(
            "Can list every access token on the account, including whether "
            "each is read-only, its permissions and its CIDR restrictions"
        ),
        risk_weight=95,
        # An inventory of the account's other credentials, and which of them
        # can publish.
        data_sensitive=True,
        source=API_DOCS,
    ),
)

#: ``/-/npm/v1/tokens`` is the cheapest documented read that requires
#: authentication, so it is both the liveness check and a capability.
VALIDATE_SERVICE: Final = "npm Tokens"


def validation_probe() -> _Probe:
    """The cheapest documented read that proves the token is live."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(token: str) -> dict[str, str]:
    """Bearer auth, as npm's registry API reference documents it.

    "Bearer token for authentication. Must be an npm access token."
    Source: https://api-docs.npmjs.com/
    """
    return {"Authorization": f"Bearer {token}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """npm's error message, or ``""``.

    The registry answers a rejected token with an empty body and
    ``www-authenticate: Basic, Bearer``, so this is usually empty — which is
    why the rejection note does not depend on it.
    """
    for field in ("error", "message"):
        value = _payload(response).get(field)
        if isinstance(value, str):
            return value
    return ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    body = response.json_or_none()
    items = (
        _payload(response).get(probe.collection)
        if probe.collection is not None
        else body
    )
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    return ctx.mask(f"curl -s -H 'Authorization: Bearer {ctx.key}' '{url}'")


class NpmProvider(Provider):
    """npm registry access tokens."""

    name = "npm"
    category = "devtools"
    docs_url = "https://api-docs.npmjs.com/"
    rotation_guide_url = "https://docs.npmjs.com/creating-and-viewing-access-tokens/"

    #: npm publishes no credential format. It did — or keyreach believed it did
    #: — and the page the rule cited documents none, so the rule was withdrawn
    #: in R2.4 rather than kept as an unverifiable claim. See the module
    #: docstring.
    detectable = False

    def detect(self, key: str) -> float:
        """Always ``0.0``: there is no published format to match against.

        Not a stub. Returning anything else would make this plugin a detection
        candidate on the strength of a shape npm does not publish, which is the
        false-positive machine `plan.md` §5.2 rules out.
        """
        del key
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of the token list, the cheapest documented authenticated read.

        No identity is returned, because npm's API reference documents no
        endpoint that names the authenticated account. Inventing one from an
        undocumented path would be the same mistake this item withdrew a
        detection rule for.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True)

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "npm did not accept this token"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; npm refused this endpoint"
                    + (f" ({message})" if message else "")
                    + ". A granular token restricted to specific packages is "
                    "refused here exactly like this, so the capabilities below "
                    "are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; npm rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "npm's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe both documented endpoints concurrently; keep the ones that answered."""
        headers = _auth(key)
        responses = await ctx.gather(
            [ctx.get(probe.url, headers=headers) for probe in PROBES]
        )

        capabilities = [
            Capability(
                service=probe.service,
                # READ everywhere, deliberately — see the module docstring.
                access=AccessLevel.READ,
                detail=f"{probe.detail}. {SCOPE_STATEMENT}",
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
