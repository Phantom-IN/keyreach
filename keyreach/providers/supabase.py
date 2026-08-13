"""Supabase project API keys — roadmap R2.5.

No prior art. Every key type, header and claim below comes from Supabase's own
documentation, and each probe cites the page it came from.

**Supabase publishes a sentence that decides the severity outright.** A secret
key "has full access to your project's data, bypassing Row Level Security", and
the legacy ``service_role`` key uses "the BYPASSRLS attribute, skipping any and
all Row Level Security policies". Row Level Security is the *only* thing
standing between a Supabase API key and every row in the database, so a key that
bypasses it is administrative access to the whole project — recorded as ``ADMIN``
on the vendor's words, with nothing written to find out.

**Four key types, and only two of them are detectable.** Supabase documents
``sb_publishable_…`` and ``sb_secret_…`` as the current formats, and both have
rules. The legacy ``anon`` and ``service_role`` keys are **JWTs**, which have no
distinctive regex — a rule matching three base64 segments would claim every JWT
ever pasted at keyreach, which is the argument that kept Discord's community
token pattern out in R2.2. So a legacy key is reached with
``--provider supabase``, and this plugin reads its type from the token itself.
That makes Supabase the first provider that is detectable for its **current**
credential formats and undetectable for its **legacy** ones.

**The legacy key says which project it belongs to; the new one does not.** A
Supabase JWT carries ``ref`` — the project reference — and ``role``, so the host
``https://<ref>.supabase.co`` is derived from the credential with no request and
no guess. A ``sb_secret_`` key is opaque, so it must be supplied as
``<project ref>:<key>``. Decoding the JWT is pure, offline and deterministic:
one base64url decode and a JSON parse, no signature check, because keyreach is
reading a claim the holder already has rather than trusting it.

**A wrong project reference does not resolve at all.** ``<ref>.supabase.co`` has
no wildcard, so a mistyped reference fails DNS rather than answering 401. That
is a better failure than a confident rejection, and it is left to the engine's
transport-error path rather than caught and reworded here.

**What a publishable key means is a question keyreach cannot answer.** Supabase
documents it as "safe to expose online: web page, mobile or desktop app, GitHub
actions, CLIs, source code" — and that is only true if Row Level Security is
configured correctly, which keyreach cannot check without reading somebody's
rows. So the report says what Supabase says *and* names the assumption it rests
on, rather than filing an exposed publishable key as harmless.
"""

from __future__ import annotations

import base64
import binascii
import json
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
# Mirrors the two `supabase-*` rules in
# `keyreach/patterns/detection_rules.yml`; `tests/test_provider_supabase.py`
# asserts they agree.
# Source: https://supabase.com/docs/guides/api/api-keys

SECRET_PREFIX: Final = "sb_secret_"  # noqa: S105 - a prefix, not a secret
PUBLISHABLE_PREFIX: Final = "sb_publishable_"

_PATTERN: Final = re.compile(
    r"^(?:[a-z]{20}:)?sb_(?:secret|publishable)_[A-Za-z0-9_-]{20,}$"
)

CONFIDENCE: Final = 0.99

#: A Supabase project reference is twenty lowercase letters, which is what the
#: host `<ref>.supabase.co` is built from.
_REF: Final = re.compile(r"^[a-z]{20}$")

_SEPARATOR: Final = ":"


class Kind(StrEnum):
    """Which side of Supabase's own line a key falls on."""

    SECRET = "secret"  # noqa: S105 - an enum member naming a key type
    """`sb_secret_` or legacy `service_role`: bypasses Row Level Security."""

    PUBLISHABLE = "publishable"
    """`sb_publishable_` or legacy `anon`: documented as safe to expose."""


#: The `role` claim values Supabase documents on its legacy JWT keys.
#: Source: https://supabase.com/docs/guides/auth/jwt-fields
SERVICE_ROLE: Final = "service_role"
ANON_ROLE: Final = "anon"


class Credential(NamedTuple):
    """A parsed Supabase credential: the project, the key and what it is."""

    project_ref: str
    key: str
    kind: Kind
    legacy: bool


def decode_claims(token: str) -> dict[str, Any]:
    """The payload of a JWT, or an empty mapping.

    No signature check, deliberately: keyreach is reading a claim out of a
    credential its holder already possesses, not accepting a token as proof of
    anything. Pure, offline and deterministic — the same properties `detect`
    is required to have.
    """
    parts = token.split(".")
    if len(parts) != _JWT_SEGMENTS:
        return {}
    payload = parts[1]
    # base64url without padding is what JWT uses; restore it before decoding.
    padded = payload + "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        claims = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return {}
    return claims if isinstance(claims, dict) else {}


_JWT_SEGMENTS: Final = 3


def parse_credential(key: str) -> Credential | None:
    """Work out the project, the key and its kind, or ``None``.

    Three shapes are accepted, and the difference between them is the whole
    reason this function exists:

    * ``<ref>:sb_secret_…`` / ``<ref>:sb_publishable_…`` — the current formats,
      which carry no project reference of their own.
    * a legacy ``anon`` or ``service_role`` JWT — which carries both the project
      reference and the role, so nothing needs supplying alongside it.
    * ``<ref>:<legacy JWT>`` — accepted so an operator who has both can say so.
    """
    head, separator, tail = key.partition(_SEPARATOR)
    # A JWT contains no colon — its charset is base64url plus dots — so when
    # there is one, everything after it is the credential whatever came before.
    # Only a well-formed reference before the colon is *used* as one; anything
    # else is ignored rather than sent to a host that cannot exist.
    remainder = tail if separator else key
    project_ref = head if separator and _REF.match(head) else ""

    claims = decode_claims(remainder)
    role = claims.get("role")
    if isinstance(role, str) and role in (SERVICE_ROLE, ANON_ROLE):
        ref = claims.get("ref")
        resolved = project_ref or (ref if isinstance(ref, str) else "")
        if not resolved:
            return None
        return Credential(
            project_ref=resolved,
            key=remainder,
            kind=Kind.SECRET if role == SERVICE_ROLE else Kind.PUBLISHABLE,
            legacy=True,
        )

    if not project_ref:
        return None
    if remainder.startswith(SECRET_PREFIX):
        return Credential(project_ref, remainder, Kind.SECRET, legacy=False)
    if remainder.startswith(PUBLISHABLE_PREFIX):
        return Credential(project_ref, remainder, Kind.PUBLISHABLE, legacy=False)
    return None


def base_url(project_ref: str) -> str:
    """``https://<ref>.supabase.co``, as Supabase documents it."""
    return f"https://{project_ref}.supabase.co"


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

DOCS: Final = "https://supabase.com/docs/guides/api"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Supabase's own words for what a secret key reaches, quoted into the detail so
#: a reader can check the inference rather than trust it.
BYPASS_STATEMENT: Final = (
    "Supabase documents this key as having full access to the project's data, "
    "bypassing Row Level Security, which is the only thing standing between an "
    "API key and every row in the database. No write was performed"
)

#: And what a publishable key reaches, with the assumption it rests on named.
PUBLISHABLE_STATEMENT: Final = (
    "Supabase documents this key as safe to expose, which holds only where Row "
    "Level Security policies are configured correctly — keyreach does not read "
    "rows to check, so this is not on its own evidence the project is safe"
)


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    path: str
    params: dict[str, str] = Field(default_factory=dict)
    collection: str | None = Field(
        default=None,
        description="Response field holding the list, for the evidence count.",
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    secret_only: bool = Field(
        default=False,
        description="Does Supabase document this as requiring a secret key?",
    )
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Supabase Auth Settings",
        path="/auth/v1/settings",
        noun="auth settings",
        detail=(
            "Can read the project's auth configuration, including which sign-in "
            "providers are enabled"
        ),
        risk_weight=60,
        source="https://supabase.com/docs/guides/auth",
    ),
    _Probe(
        service="Supabase Storage Buckets",
        path="/storage/v1/bucket",
        noun="buckets",
        detail=(
            "Can list the project's storage buckets and whether each one is " "public"
        ),
        risk_weight=85,
        data_sensitive=True,
        source="https://supabase.com/docs/guides/storage",
    ),
    _Probe(
        service="Supabase Table Schema",
        path="/rest/v1/",
        noun="schema",
        detail=(
            "Can read the project's exposed schema, which names every table and "
            "column the API serves — the map an attacker would otherwise have "
            "to guess"
        ),
        risk_weight=90,
        data_sensitive=True,
        source=DOCS,
    ),
    _Probe(
        service="Supabase Users",
        path="/auth/v1/admin/users",
        params={"page": "1", "per_page": "1"},
        collection="users",
        noun="users",
        detail=(
            "Can list the project's end users, including their email addresses "
            "and sign-in history"
        ),
        # Supabase documents the admin auth endpoints as requiring a key that
        # bypasses Row Level Security.
        secret_only=True,
        risk_weight=100,
        data_sensitive=True,
        source="https://supabase.com/docs/reference/javascript/auth-admin-listusers",
    ),
)


def probes_for(kind: Kind) -> tuple[_Probe, ...]:
    """The probes a key of this kind can reach.

    A publishable key is documented as unable to reach the admin endpoints, so
    asking would be a 401 keyreach could have predicted — wasted authentication
    traffic against somebody's production project.
    """
    if kind is Kind.SECRET:
        return PROBES
    return tuple(probe for probe in PROBES if not probe.secret_only)


#: ``/auth/v1/settings`` is the cheapest read every key type can reach, and it
#: discloses configuration rather than anybody's data.
VALIDATE_SERVICE: Final = "Supabase Auth Settings"


def validation_probe() -> _Probe:
    """The cheapest read that proves the key is live and names nobody."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _auth(key: str) -> dict[str, str]:
    """Both headers Supabase's own curl example sends.

    Source: https://supabase.com/docs/guides/api/creating-routes
    """
    return {"apikey": key, "Authorization": f"Bearer {key}"}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """Supabase's error message, or ``""``.

    PostgREST answers ``{"message": …}``, GoTrue answers ``{"msg": …}`` and the
    gateway answers ``{"error": …}``. All three are read, because the note a
    user sees is only useful if it quotes what the service actually said.
    """
    payload = _payload(response)
    for field in ("message", "msg", "error_description", "error"):
        value = payload.get(field)
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


def _identity(credential: Credential) -> Identity:
    """The project and what kind of key this is.

    Both come from the credential rather than from a request — the project
    reference because a legacy key carries it and a new one is supplied with
    it, and the kind because Supabase's prefixes and its ``role`` claim both say
    so outright. It is also the fact that matters most: one of these keys
    bypasses every access rule the project has.
    """
    return Identity(
        account=credential.project_ref,
        extra={
            "key_type": credential.kind.value,
            "format": "legacy JWT" if credential.legacy else "current",
        },
    )


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    return ctx.mask(
        f"curl -s -H 'apikey: {ctx.key}' "
        f"-H 'Authorization: Bearer {ctx.key}' '{url}'"
    )


class SupabaseProvider(Provider):
    """Supabase publishable, secret and legacy project API keys."""

    name = "supabase"
    category = "database"
    docs_url = "https://supabase.com/docs/guides/api/api-keys"
    rotation_guide_url = (
        "https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the two documented ``sb_`` formats.

        Legacy keys are deliberately **not** claimed here. They are JWTs, and a
        rule matching three base64 segments would claim every JWT ever pasted at
        keyreach — the argument that kept Discord's community token pattern out
        in R2.2. ``--provider supabase`` reaches them, and ``parse_credential``
        reads the project and role out of the token itself.
        """
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/auth/v1/settings``, on the host the credential names."""
        credential = parse_credential(key)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "This key names no Supabase project. A legacy anon or "
                    "service_role key carries its project reference in the "
                    "token; a current sb_publishable_ or sb_secret_ key does "
                    "not, so it must be supplied. No request was made: "
                    "<ref>.supabase.co has no wildcard, so a guessed reference "
                    "would not resolve at all. Re-run as '<project ref>:<key>'"
                ),
            )

        probe = validation_probe()
        url = f"{base_url(credential.project_ref)}{probe.path}"
        response = await ctx.get(url, headers=_auth(credential.key))
        message = message_of(response)

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(credential))

        if response.status_code in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
            return ValidationResult(
                valid=False,
                note=(
                    f"Supabase project {credential.project_ref} did not accept "
                    "this key" + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=_identity(credential),
                note=(
                    "The key is live; Supabase rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Supabase's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this key's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe the endpoints this kind of key can reach, concurrently."""
        credential = parse_credential(key)
        if credential is None:  # pragma: no cover - `validate` stops the run first
            return []

        api = base_url(credential.project_ref)
        probes = probes_for(credential.kind)
        headers = _auth(credential.key)
        responses = await ctx.gather(
            [
                ctx.get(
                    f"{api}{probe.path}", params=probe.params or None, headers=headers
                )
                for probe in probes
            ]
        )

        secret = credential.kind is Kind.SECRET
        capabilities = [
            Capability(
                service=probe.service,
                # ADMIN on Supabase's own sentence: a secret key bypasses Row
                # Level Security, which is the project's whole access model.
                access=AccessLevel.ADMIN if secret else AccessLevel.READ,
                detail=(
                    f"{probe.detail}. "
                    f"{BYPASS_STATEMENT if secret else PUBLISHABLE_STATEMENT}"
                ),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(probes, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
