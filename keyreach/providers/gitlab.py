"""GitLab access tokens (``glpat-…``) — roadmap R2.4.

No prior art. Every path, header and scope name below was written from GitLab's
own documentation, and each probe cites the page it came from.

**GitLab publishes the calling token's own scopes as a resource**, at
``GET /api/v4/personal_access_tokens/self``. That makes it the third shape
keyreach has met for the same problem — GitHub answers in a response header
(R1.6), SendGrid answers as a resource (R2.3), GitLab answers as a resource and
adds ``active``, ``revoked`` and ``expires_at`` alongside. One request proves
the token is live *and* enumerates what it may do, so a ``write`` here is
GitLab's own statement rather than a push keyreach made.

**The access levels are quoted, not inferred.** GitLab documents ``api`` as
"complete read and write access to the API", ``write_repository`` as "read and
write access (pull and push) to repositories", and ``sudo`` as "permission to
perform API actions as any user in the system, when authenticated as an
administrator". Those three sentences are the whole mapping, and each is
recorded next to the constant it produced.

**Scopes are matched per resource, for the reason R1.6 established at GitHub.**
A token holding ``write_repository`` can push code and cannot administer a
group. ``api`` and the two admin scopes are the exceptions that legitimately
apply everywhere, because GitLab documents them as applying everywhere.

**One prefix, three kinds of token.** GitLab documents ``glpat-`` for personal,
project *and* group access tokens, and publishes nothing that separates them.
That is fine here — ``/personal_access_tokens/self`` answers for all three — but
it means the report cannot say which kind it is holding beyond what GitLab
returns, and a group token's reach is much wider than a personal one's.

**Only gitlab.com is probed.** GitLab is self-hostable, and a token from a
private instance is not reachable from here; worse, GitLab documents the
``glpat-`` prefix as the *default*, which a self-managed administrator can
change. So a customised instance's token is neither detected nor probed. Both
limits under-report, which is the correct side to err on.
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
# Mirrors the `gitlab-pat` rule in `keyreach/patterns/detection_rules.yml`;
# `tests/test_provider_gitlab.py` asserts the two agree.
# Source: https://docs.gitlab.com/security/tokens/

_PATTERN: Final = re.compile(r"^glpat-[A-Za-z0-9_-]{20,}$")

CONFIDENCE: Final = 0.99


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------
#
# Every description below is quoted from GitLab's access-token scopes page:
# https://docs.gitlab.com/security/tokens/access_token_scopes/

#: "Grants complete read and write access to the API for the token's scope.
#: Includes the container registry, the dependency proxy, and the package
#: registry." The one scope that elevates every capability, because GitLab
#: documents it as covering the whole API rather than one resource.
API_SCOPE: Final = "api"

#: Scopes GitLab documents as granting administrative reach over the instance,
#: regardless of resource:
#:   sudo       "perform API actions as any user in the system, when
#:               authenticated as an administrator"
#:   admin_mode "perform API actions when Admin Mode is enabled. Available only
#:               to administrators on GitLab Self-Managed instances"
ADMIN_SCOPES: Final[frozenset[str]] = frozenset({"admin_mode", "sudo"})


def scopes_of(response: ProbeResponse) -> frozenset[str] | None:
    """The token's scopes, or ``None`` when GitLab did not state them.

    ``None`` and ``frozenset()`` are kept apart for the reason the GitHub plugin
    keeps them apart: no answer means "this token's permissions were not
    determined", while an empty list means "this token holds no scopes".
    """
    if not response.ok:
        return None
    scopes = _payload(response).get("scopes")
    if not isinstance(scopes, list):
        return None
    return frozenset(item for item in scopes if isinstance(item, str))


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://gitlab.com/api/v4"

#: Page size for every list probe.
PAGE_SIZE: Final = "1"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_TOO_MANY_REQUESTS: Final = 429


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    listing: bool = Field(
        default=True, description="Does this endpoint return a JSON array?"
    )
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    write_scopes: tuple[str, ...] = Field(
        default=(),
        description="Scopes GitLab documents as granting write over this resource.",
    )
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="GitLab Account",
        url=f"{API}/user",
        listing=False,
        noun="account",
        detail="Can authenticate to GitLab and read the account's profile",
        risk_weight=60,
        source="https://docs.gitlab.com/api/users/",
    ),
    _Probe(
        service="GitLab Groups",
        url=f"{API}/groups",
        params={"per_page": PAGE_SIZE},
        noun="groups",
        detail=(
            "Can list the groups this token can see, which is the shape of the "
            "organization around the code"
        ),
        risk_weight=70,
        source="https://docs.gitlab.com/api/groups/",
    ),
    _Probe(
        service="GitLab Projects",
        url=f"{API}/projects",
        params={"membership": "true", "per_page": PAGE_SIZE},
        noun="projects",
        detail=(
            "Can list the projects this token is a member of, which is the "
            "source code the account was relying on nobody being able to read"
        ),
        # "Grants read and write access (pull and push) to repositories for the
        # token's scope: private projects for a personal access token."
        write_scopes=("write_repository",),
        risk_weight=100,
        data_sensitive=True,
        source="https://docs.gitlab.com/api/projects/",
    ),
)

#: The token-introspection endpoint doubles as the liveness check: GitLab
#: documents it as returning *this* token's own record, so it is reachable by
#: any live token and discloses nothing about anybody's code.
SELF_URL: Final = f"{API}/personal_access_tokens/self"

SELF_SOURCE: Final = "https://docs.gitlab.com/api/personal_access_tokens/"


def _auth(token: str) -> dict[str, str]:
    """The header GitLab documents for personal access tokens.

    Source: https://docs.gitlab.com/api/rest/authentication/
    """
    return {"PRIVATE-TOKEN": token}


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe. GitLab's list endpoints return arrays, which
    this deliberately reports as "no object" — :func:`_summary` counts those.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def message_of(response: ProbeResponse) -> str:
    """GitLab's error message, or ``""``.

    A rejected token returns ``{"message": "401 Unauthorized"}``, verified
    against the live API.
    """
    for field in ("message", "error"):
        value = _payload(response).get(field)
        if isinstance(value, str):
            return value
    return ""


def is_active(response: ProbeResponse) -> bool | None:
    """GitLab's own verdict on whether the token is still usable.

    ``/personal_access_tokens/self`` carries ``active`` and ``revoked``. A
    revoked token would not authenticate in the first place, so this is belt to
    that brace — but it is the vendor saying so, which is worth reporting.
    """
    payload = _payload(response)
    active = payload.get("active")
    return active if isinstance(active, bool) else None


def access_for(probe: _Probe, scopes: frozenset[str] | None) -> AccessLevel:
    """The access level a probe's result justifies, given the token's scopes.

    ``READ`` is the floor, because a capability is only built from a probe that
    answered. Scopes raise it and never lower it.
    """
    if scopes is None:
        return AccessLevel.READ
    if scopes & ADMIN_SCOPES:
        return AccessLevel.ADMIN
    if API_SCOPE in scopes or scopes & frozenset(probe.write_scopes):
        return AccessLevel.WRITE
    return AccessLevel.READ


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    if not probe.listing:
        return "request accepted"
    body = response.json_or_none()
    if not isinstance(body, list):
        return "request accepted"
    if not body:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(body)} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(response: ProbeResponse) -> Identity | None:
    """What GitLab discloses about the token itself.

    The token's own name and id, not the user's — ``/personal_access_tokens/
    self`` is about the credential. That is the more useful fact for a
    disclosure: it is what the recipient revokes.
    """
    payload = _payload(response)
    token_id = payload.get("id")
    name = _string(payload, "name")
    if token_id is None and not name:
        return None

    extra = {}
    for field in ("expires_at", "last_used_at"):
        value = _string(payload, field)
        if value:
            extra[field] = value
    user_id = payload.get("user_id")
    if isinstance(user_id, int):
        extra["user_id"] = str(user_id)

    return Identity(
        account=str(token_id) if token_id is not None else None,
        owner=name or None,
        extra=extra,
    )


def _poc(ctx: ProbeContext, url: str) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    return ctx.mask(f"curl -s -H 'PRIVATE-TOKEN: {ctx.key}' '{url}'")


class GitLabProvider(Provider):
    """GitLab personal, project and group access tokens."""

    name = "gitlab"
    category = "devtools"
    docs_url = "https://docs.gitlab.com/api/rest/authentication/"
    rotation_guide_url = "https://docs.gitlab.com/user/profile/personal_access_tokens/"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``glpat-`` prefix."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of the token's own record, which every live token can reach."""
        response = await ctx.get(SELF_URL, headers=_auth(key))
        message = message_of(response)

        if response.ok:
            if is_active(response) is False:
                return ValidationResult(
                    valid=True,
                    identity=_identity(response),
                    note=(
                        "GitLab returned this token's record but marks it "
                        "inactive, so its capability map may be narrower than "
                        "it appears"
                    ),
                )
            return ValidationResult(valid=True, identity=_identity(response))

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "GitLab.com did not accept this token"
                    + (f" ({message})" if message else "")
                    + ". Note that keyreach probes gitlab.com only, so a token "
                    "for a self-managed instance is refused here whether or not "
                    "it is live"
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; GitLab refused the token-introspection "
                    "endpoint"
                    + (f" ({message})" if message else "")
                    + ". Without it there are no scopes, so the access levels "
                    "below are what each probe proved and are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; GitLab rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "GitLab's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Read the token's scopes, then probe every endpoint concurrently.

        The introspection read costs nothing beyond ``validate``'s:
        ``ProbeClient`` caches repeated idempotent GETs for a run (R1.4).
        """
        headers = _auth(key)
        introspection = await ctx.get(SELF_URL, headers=headers)
        scopes = scopes_of(introspection)

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
                poc=_poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe, scopes: frozenset[str] | None) -> str:
    """The capability detail, including where its access level came from."""
    if scopes is None:
        return (
            f"{probe.detail}. This token's scopes could not be read, so write "
            "access was neither confirmed nor ruled out"
        )

    if scopes & ADMIN_SCOPES:
        granted = sorted(scopes & ADMIN_SCOPES)
        return (
            f"{probe.detail}. This token holds {', '.join(granted)}, which "
            "GitLab documents as acting as any user in the system. No write "
            "was performed"
        )

    relevant = sorted(
        scope for scope in scopes if scope == API_SCOPE or scope in probe.write_scopes
    )
    if not relevant:
        return (
            f"{probe.detail}. GitLab lists no scope granting write over this "
            "resource. No write was performed"
        )

    return (
        f"{probe.detail}. GitLab lists {', '.join(relevant)}, which it "
        "documents as granting write. No write was performed: the access level "
        "is GitLab's own statement of this token's scopes"
    )
