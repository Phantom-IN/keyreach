"""Generic bearer/JWT inspector — roadmap R2.7.

No prior art, and no single vendor. Every provider before this one is built
around one issuer's documented format and endpoints. This one exists for the
opposite case: a bearer token that does not match anything keyreach knows,
which is most of what a scanner turns up once the named vendors are covered.
It does two unrelated things, both gated on the same credential shape.

**Decoding a JWT is not the same as trusting one.** A JSON Web Token
(RFC 7519, compact serialization RFC 7515) is three dot-separated
base64url segments, and the first two decode to JSON with no key or
network required. `decode` reads the header and payload the same way
`keyreach/providers/supabase.py` reads a legacy Supabase key's `ref` and
`role` — pure, offline, deterministic, and **with no signature check**:
keyreach is reading a claim out of a credential its holder already has, not
accepting the token as proof of anything. This is also, finally, the home
for the pattern R2.2 and R2.5 explicitly kept out of Discord's and
Supabase's own detection: "a regex over three base64 segments claims every
JWT ever pasted at keyreach" was true and disqualifying *for a
vendor-specific rule*. It is exactly the shape a provider that names no
vendor should claim, so `generic` does.

**Timestraps are formatted, not compared.** `exp`, `iat` and `nbf` are
rendered as ISO-8601 UTC strings converted from the number the token itself
carries — `datetime.fromtimestamp(claim, tz=utc)` on a *given* number, never
`datetime.now()`. `CLAUDE.md` bans a plugin from reading the clock outside
request signing, and computing "is this expired" would need to compare
against the current moment. So this reports what the token asserts and lets
the reader do that arithmetic, rather than asserting a verdict that would be
wrong the moment the process's clock disagreed with the reader's.

**`alg: none` is reported as a fact, not exploited.** RFC 7515 defines
``none`` as a legitimate algorithm value meaning "unsecured" — no signature
at all. A token declaring it is worth flagging loudly; forging one to prove
the point is exactly the exploitation `plan.md` §11 forbids, so this plugin
only names the claim.

**The live half needs the operator to name a target, because nothing else
can.** Every other provider's `enumerate` probes endpoints its own file
documents. A bearer token with no known issuer has no such list — the
roadmap calls this "a user-directed generic bearer probe" for exactly that
reason. keyreach accepts ``TOKEN@URL``, colon-composite credentials'
sibling shape: ``@`` rather than ``:`` because a URL already contains a
colon after its scheme, which would make first- or last-colon splitting
ambiguous. Only ``GET`` is ever sent — the read-only guard would refuse a
POST outright, and every real inference endpoint this could accidentally be
pointed at requires one, so `ai_ban`'s static check is not the only thing
standing between this plugin and an inference call.

**A well-formed, unverified JWT reports ``valid=False``, on the same
precedent as AWS's bare access key ID.** `keyreach/providers/aws.py`
answers a key with no secret half `valid=False` and a note explaining
nothing could be checked, rather than inventing a verdict. Decoding a JWT
with no target URL is the same situation: keyreach has read real claims out
of the token, but confirmed nothing against a server, so it is not "live"
in the sense every other provider's `valid=True` means. The claims still
populate `Identity` — an unverified fact volunteered by the token is more
useful than silence — and the note says plainly that nothing was verified.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------
#
# `@` rather than `:` — see the module docstring.

_SEPARATOR: Final = "@"

#: Not a published fact — nothing publishes a length for an arbitrary bearer
#: token. Only rejects empty input before a request is made.
MIN_TOKEN_LENGTH: Final = 8


class Credential(NamedTuple):
    """A bearer token, and the URL to check it against if one was given."""

    token: str
    url: str


def parse_credential(key: str) -> Credential | None:
    token, separator, url = key.partition(_SEPARATOR)
    if len(token) < MIN_TOKEN_LENGTH:
        return None
    return Credential(token, url if separator else "")


# --------------------------------------------------------------------------
# JWT decoding
# --------------------------------------------------------------------------
#
# Source: RFC 7519 (JSON Web Token), RFC 7515 (JWS compact serialization).

_JWT_SEGMENTS: Final = 3

#: Confidence for a decoded JWT. Lower than any vendor-prefix rule (0.95+):
#: this plugin knows the *shape*, never the issuer, which is a weaker claim
#: than "this is specifically a Stripe key". Still well above the entropy
#: fallback's flat 0.30 — decoding two segments to real JSON is much stronger
#: structural evidence than character variety alone — and above
#: `tests/test_detect.py`'s 0.8 floor for a shipped structural rule.
CONFIDENCE: Final = 0.85

#: RFC 7515's "unsecured JWS" algorithm — a token asserting this has no
#: signature at all.
_ALG_NONE: Final = "none"

#: Registered numeric-date claims (RFC 7519 §4.1), formatted rather than
#: compared. See the module docstring.
_TIMESTAMP_CLAIMS: Final = ("exp", "iat", "nbf")

#: Claims surfaced as identity when present, beyond the timestamps above.
#: Deliberately not interpreted into an access level — a generic decoder does
#: not know what any issuer's `scope` or `role` values mean.
_IDENTITY_CLAIMS: Final = ("iss", "sub", "aud", "scope", "scopes", "role", "roles")


def _decode_segment(segment: str) -> dict[str, Any] | None:
    """One base64url JWT segment as a JSON object, or ``None``.

    No signature check — see the module docstring. Pure, offline, and
    deterministic, the same properties ``detect`` is required to have.
    """
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = json.loads(base64.urlsafe_b64decode(padded))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if isinstance(decoded, dict) else None


class DecodedJWT(NamedTuple):
    header: dict[str, Any]
    payload: dict[str, Any]


def decode(token: str) -> DecodedJWT | None:
    """Split and decode a JWT's header and payload, or ``None`` if it is not one."""
    parts = token.split(".")
    if len(parts) != _JWT_SEGMENTS:
        return None
    header = _decode_segment(parts[0])
    payload = _decode_segment(parts[1])
    if header is None or payload is None:
        return None
    return DecodedJWT(header, payload)


def _stringify(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _format_timestamp(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def claims_extra(decoded: DecodedJWT) -> dict[str, str]:
    """``Identity.extra`` from a decoded JWT's registered and common claims."""
    extra: dict[str, str] = {}

    alg = decoded.header.get("alg")
    if isinstance(alg, str):
        extra["alg"] = alg
        if alg.lower() == _ALG_NONE:
            extra["alg_none"] = (
                "this token declares alg=none — RFC 7515's unsecured JWS, no "
                "signature at all"
            )
    kid = decoded.header.get("kid")
    if isinstance(kid, str):
        extra["kid"] = kid

    for claim in _TIMESTAMP_CLAIMS:
        formatted = _format_timestamp(decoded.payload.get(claim))
        if formatted is not None:
            extra[claim] = formatted

    for claim in _IDENTITY_CLAIMS:
        value = decoded.payload.get(claim)
        if isinstance(value, (str, list)) and value:
            extra[claim] = _stringify(value)

    return extra


def _identity(decoded: DecodedJWT) -> Identity:
    extra = claims_extra(decoded)
    subject = decoded.payload.get("sub")
    issuer = decoded.payload.get("iss")
    return Identity(
        account=subject if isinstance(subject, str) else None,
        owner=issuer if isinstance(issuer, str) else None,
        extra=extra,
    )


# --------------------------------------------------------------------------
# The operator-specified probe
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """The one capability shape this provider can ever report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Operator-Specified Endpoint",
        detail=(
            "Can authenticate to the endpoint the operator named. keyreach "
            "cannot determine what it grants beyond that, since no vendor "
            "rule describes this credential"
        ),
        # Below MEDIUM_RISK_WEIGHT (`core/scoring.py`) on purpose: real impact
        # is unknown, and this plugin does not guess at it.
        risk_weight=45,
        source="https://www.rfc-editor.org/rfc/rfc6750",
    ),
)


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _poc(ctx: ProbeContext, credential: Credential) -> str:
    return ctx.mask(
        f"curl -s -H 'Authorization: Bearer {credential.token}' '{credential.url}'"
    )


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register the token half for redaction.

    ``ProbeContext`` seeds the redactor with the whole pasted string
    (``TOKEN@URL``), which would not mask a response or a built ``curl``
    command echoing back the token alone — the same reason MongoDB's,
    Zoom's and Datadog's composite credentials each register their own
    secret half explicitly.
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.token)
    return credential


class GenericProvider(Provider):
    """A bearer token with no known issuer: JWT claims, or an operator-named probe."""

    name = "generic"
    category = "generic"
    docs_url = "https://www.rfc-editor.org/rfc/rfc7519"
    # No vendor issues this credential, so there is no vendor rotation page to
    # point to. RFC 7009 is the closest honest answer: it is the specification
    # for revoking a bearer/access token in the general case, which is what a
    # recipient of this report actually needs to act on.
    rotation_guide_url = "https://www.rfc-editor.org/rfc/rfc7009"

    #: A JWT's structure is a public specification, not one vendor's secret —
    #: see the module docstring. An arbitrary non-JWT bearer token is not
    #: detectable at all, and is reachable only via ``--provider generic``.
    detectable = True

    def detect(self, key: str) -> float:
        """Pure structural + decode check: three segments, header and payload parse.

        Any ``@url`` suffix is stripped first, since it is not part of the
        token.
        """
        token = key.partition(_SEPARATOR)[0]
        return CONFIDENCE if decode(token) is not None else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Decode the JWT if there is one; probe the URL if one was given.

        ``valid`` reflects only what was actually checked — see the module
        docstring on why a well-formed, unverified JWT is ``False`` here, on
        the same precedent as AWS's bare access key ID.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                note="This is too short to be a bearer token",
            )

        decoded = decode(credential.token)
        identity = _identity(decoded) if decoded is not None else None

        if not credential.url:
            if decoded is None:
                return ValidationResult(
                    valid=False,
                    note=(
                        "This does not look like a JWT, and no target URL was "
                        "given. Pass 'TOKEN@https://your-endpoint' to check "
                        "where this bearer token authenticates"
                    ),
                )
            return ValidationResult(
                valid=False,
                identity=identity,
                note=(
                    "This is a syntactically valid JSON Web Token. keyreach "
                    "decoded its claims without contacting any server — no "
                    "signature was checked and no endpoint was probed. Pass "
                    "'TOKEN@https://your-endpoint' to check whether a specific "
                    "endpoint accepts it"
                ),
            )

        response = await ctx.get(credential.url, headers=_headers(credential.token))
        if response.ok:
            return ValidationResult(
                valid=True,
                identity=identity,
                note=f"{credential.url} accepted this bearer token",
            )
        return ValidationResult(
            valid=False,
            identity=identity,
            note=(
                f"{credential.url} responded {response.status_code}, so this "
                "bearer token was not accepted there. It may still be valid "
                "against a different endpoint"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """The one capability this plugin can ever report: the named URL, if any.

        A decoded JWT's claims are not a capability — reading a claim out of a
        credential its holder already possesses is not reaching anything new.
        Nothing is enumerated without an operator-specified URL.
        """
        credential = _credential_for(key, ctx)
        if credential is None or not credential.url:
            return []

        response = await ctx.get(credential.url, headers=_headers(credential.token))
        if not response.ok:
            return []

        probe = PROBES[0]
        return [
            Capability(
                service=probe.service,
                access=AccessLevel.UNKNOWN,
                detail=probe.detail,
                evidence=response.evidence("request accepted"),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, credential),
                resource_ref=credential.url,
            )
        ]
