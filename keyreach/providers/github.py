"""GitHub access tokens (``ghp_…``, ``github_pat_…``) — roadmap R1.6.

No prior art. Every endpoint, header and scope name below was written from
GitHub's own documentation, and each probe cites the page it came from.

**This is the first plugin that can prove a write without performing one.**
GitHub documents a response header that lists a token's grants:

    "Check headers to see what OAuth scopes you have, and what the API action
    accepts" — ``X-OAuth-Scopes`` "lists the scopes your token has authorized".

    — https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps

Every other provider keyreach supports leaves it inferring an access level from
what a read returned, or declining to. Here the vendor states the answer on
every response, so ``AccessLevel.WRITE`` and ``AccessLevel.ADMIN`` come from a
documented scope name rather than from a write keyreach was never going to make.

**Scopes are matched per resource, not per token.** A token holding ``repo`` can
push code; it cannot add an organization member. Applying one token-wide access
level to every capability would therefore label the organization finding
``write`` on the strength of a repository grant — the same over-reach
``core/scoring.py`` refuses when it requires *one* capability to be both
privileged and valuable. So each probe declares the scopes that would elevate
**it**, and each capability is scored against those alone.

**Fine-grained tokens are honestly weaker findings.** GitHub does not send
``X-OAuth-Scopes`` for a ``github_pat_…`` token, because its permissions are
per-repository rather than a scope list. keyreach then records ``READ`` — what
it confirmed — and says in the capability detail that the token's write
permissions were not determined. That under-reports a fine-grained token that
can push, and under-reporting is the correct side to err on.
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
# Token formats
# --------------------------------------------------------------------------
#
# Mirrors the two `github-*` rules in `keyreach/patterns/detection_rules.yml`;
# `tests/test_provider_github.py` asserts the two agree.
# Source: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github

_PATTERNS: Final[tuple[tuple[str, float], ...]] = (
    # ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server,
    # ghr_ refresh. All share the 36-character body.
    (r"^gh[pousr]_[A-Za-z0-9]{36}$", 0.99),
    (r"^github_pat_[A-Za-z0-9_]{22,}$", 0.99),
)

_COMPILED: Final = tuple((re.compile(pattern), score) for pattern, score in _PATTERNS)

#: The prefix GitHub uses for fine-grained personal access tokens, whose
#: permissions are per-repository and are therefore not reported in a scope
#: header.
FINE_GRAINED_PREFIX: Final = "github_pat_"


def is_fine_grained(token: str) -> bool:
    """Is this a fine-grained token, whose permissions no header describes?"""
    return token.startswith(FINE_GRAINED_PREFIX)


# --------------------------------------------------------------------------
# Scopes
# --------------------------------------------------------------------------

#: Response header listing the scopes a classic token holds. Absent for
#: fine-grained tokens.
SCOPES_HEADER: Final = "x-oauth-scopes"


def scopes_of(response: ProbeResponse) -> frozenset[str] | None:
    """The token's scopes, or ``None`` when GitHub did not state them.

    ``None`` and ``frozenset()`` are different answers and are kept apart on
    purpose: no header means "GitHub does not describe this token's permissions
    this way", while an empty header means "this token holds no scopes at all".
    Collapsing them would let a fine-grained token with push access be reported
    with the same confidence as a scopeless one.
    """
    if SCOPES_HEADER not in response.headers:
        return None
    raw = response.headers[SCOPES_HEADER]
    return frozenset(scope.strip() for scope in raw.split(",") if scope.strip())


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.github.com"

#: GitHub asks for an explicit media type and API version on every request.
#: Pinning the version means a future default cannot change what keyreach reads.
#: Source: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api
API_VERSION: Final = "2022-11-28"

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
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    write_scopes: tuple[str, ...] = Field(
        default=(),
        description="Scopes GitHub documents as granting write over this resource.",
    )
    admin_scopes: tuple[str, ...] = Field(
        default=(),
        description="Scopes GitHub documents as granting admin over this resource.",
    )
    source: str = Field(description="Vendor documentation URL for this endpoint.")


PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="GitHub Account",
        url=f"{API}/user",
        noun="account",
        detail="Can authenticate to GitHub and read the account's profile",
        risk_weight=60,
        # "user" is documented as read/write access to profile info.
        write_scopes=("user",),
        source="https://docs.github.com/en/rest/users/users#get-the-authenticated-user",
    ),
    _Probe(
        service="GitHub Email Addresses",
        url=f"{API}/user/emails",
        params={"per_page": PAGE_SIZE},
        noun="email addresses",
        detail="Can list the account's email addresses, including private ones",
        risk_weight=80,
        data_sensitive=True,
        write_scopes=("user",),
        source="https://docs.github.com/en/rest/users/emails",
    ),
    _Probe(
        service="GitHub Gists",
        url=f"{API}/gists",
        params={"per_page": PAGE_SIZE},
        noun="gists",
        detail="Can list the account's gists, including secret ones",
        risk_weight=75,
        # Secret gists are where people put the snippet they did not want in a
        # repository, which is frequently a configuration file with a token in it.
        data_sensitive=True,
        write_scopes=("gist",),
        source="https://docs.github.com/en/rest/gists/gists",
    ),
    _Probe(
        service="GitHub Organizations",
        url=f"{API}/user/orgs",
        params={"per_page": PAGE_SIZE},
        noun="organizations",
        detail="Can list the organizations the account belongs to",
        risk_weight=70,
        write_scopes=("write:org", "admin:org"),
        # "admin:org" is documented as fully managing the organization, its
        # teams, projects and memberships.
        admin_scopes=("admin:org",),
        source="https://docs.github.com/en/rest/orgs/orgs",
    ),
    _Probe(
        service="GitHub Repositories",
        url=f"{API}/user/repos",
        params={"per_page": PAGE_SIZE, "visibility": "private"},
        noun="private repositories",
        detail=(
            "Can list the account's private repositories, which is the "
            "source code the account was relying on nobody being able to read"
        ),
        risk_weight=100,
        data_sensitive=True,
        # "repo" is documented as full access to public and private
        # repositories, including read/write access to code.
        write_scopes=("repo",),
        # "delete_repo" is documented as access to delete adminable
        # repositories, which no amount of write access implies.
        admin_scopes=("delete_repo",),
        source="https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user",
    ),
)

#: ``/user`` is the cheapest read, the one that names the account, and the one
#: whose response headers carry the scope list.
VALIDATE_SERVICE: Final = "GitHub Account"


def validation_probe() -> _Probe:
    """The cheapest read that proves a token is live and says whose it is."""
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def access_for(probe: _Probe, scopes: frozenset[str] | None) -> AccessLevel:
    """The access level this token holds over **this** resource.

    ``READ`` when GitHub did not describe the token's permissions, or described
    them and none of them elevates this resource. Never ``UNKNOWN``: the read
    was confirmed, so "undetermined" would understate a fact keyreach holds
    evidence for — what is undetermined is only whether more is possible, and
    the capability detail says so.
    """
    if scopes is None:
        return AccessLevel.READ
    if scopes.intersection(probe.admin_scopes):
        return AccessLevel.ADMIN
    if scopes.intersection(probe.write_scopes):
        return AccessLevel.WRITE
    return AccessLevel.READ


def _auth(token: str) -> dict[str, str]:
    """Bearer auth plus the media type and API version GitHub asks for.

    Source: https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
    """
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VERSION,
    }


def _payload(response: ProbeResponse) -> Any:
    """The parsed response body, or ``None``.

    Written defensively because this parses a third-party payload: a proxy
    returning an HTML error page must degrade to "no structured body", not raise
    out of the middle of a probe.
    """
    return response.json_or_none()


def _message(response: ProbeResponse) -> str:
    """GitHub's human-readable error text, if the body carried one."""
    payload = _payload(response)
    if not isinstance(payload, dict):
        return ""
    value = payload.get("message")
    return value if isinstance(value, str) else ""


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    GitHub list endpoints return a bare JSON array; ``/user`` returns an object.
    Both are handled, and neither quotes anything the response contained.
    """
    payload = _payload(response)
    if not isinstance(payload, list):
        return "request accepted"
    if not payload:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(payload)} listed"


def _string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _identity(response: ProbeResponse) -> Identity | None:
    """The account, from a ``/user`` response, with the token's scopes attached.

    The scope list goes into ``extra`` because it is the single most useful
    thing a recipient can be told: it is what decides whether the exposure is
    "somebody can read our code" or "somebody can push to it".
    """
    payload = _payload(response)
    if not isinstance(payload, dict):
        return None

    login = _string(payload, "login")
    if not login:
        return None

    extra: dict[str, str] = {}
    scopes = scopes_of(response)
    if scopes is not None:
        # Sorted, because a set's iteration order must never reach output.
        extra["scopes"] = ", ".join(sorted(scopes)) or "none"

    return Identity(
        account=login,
        owner=_string(payload, "name") or None,
        plan_or_tier=_plan(payload),
        extra=extra,
    )


def _plan(payload: dict[str, Any]) -> str | None:
    plan = payload.get("plan")
    if not isinstance(plan, dict):
        return None
    return _string(plan, "name") or None


def _poc(ctx: ProbeContext, token: str, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe."""
    headers = "".join(
        f" -H '{name}: {value}'" for name, value in sorted(_auth(token).items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


class GitHubProvider(Provider):
    """GitHub personal access tokens, OAuth tokens and app tokens."""

    name = "github"
    category = "devtools"
    docs_url = (
        "https://docs.github.com/en/rest/authentication/"
        "authenticating-to-the-rest-api"
    )
    rotation_guide_url = (
        "https://docs.github.com/en/authentication/"
        "keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the documented token formats."""
        scores = [score for pattern, score in _COMPILED if pattern.match(key)]
        return max(scores) if scores else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read of ``/user``, which also carries the scope header.

        A 403 is a live token that GitHub refused — most often because the
        account or organization applies an IP allow list, or because the token
        was flagged. Reporting that as invalid would retire a working credential.
        """
        probe = validation_probe()
        response = await ctx.get(probe.url, headers=_auth(key))

        if response.ok:
            return ValidationResult(valid=True, identity=_identity(response))

        message = _message(response)

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "GitHub rejected this token" + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; GitHub refused this request"
                    + (f" ({message})" if message else "")
                    + ". An IP allow list or a flagged token will do that, so "
                    "the capabilities below are a lower bound"
                ),
            )

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                note=(
                    "The token is live; GitHub rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "GitHub's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this token's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently, and score each against the scopes.

        The scope list is read from whichever response carried the header rather
        than from a dedicated call — GitHub sends it on every response to a
        classic token, so it costs nothing.
        """
        headers = _auth(key)
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params=probe.params or None, headers=headers)
                for probe in PROBES
            ]
        )
        scopes = _scopes_from(responses)

        capabilities = [
            Capability(
                service=probe.service,
                access=access_for(probe, scopes),
                detail=_detail(probe, scopes),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _scopes_from(responses: list[ProbeResponse]) -> frozenset[str] | None:
    """The first stated scope list across the probe responses.

    Taken in probe order, which is fixed, so the answer does not depend on which
    request finished first. GitHub sends the same header on every response to a
    given token, so "first" here means "deterministic", not "arbitrary".
    """
    for response in responses:
        scopes = scopes_of(response)
        if scopes is not None:
            return scopes
    return None


def _detail(probe: _Probe, scopes: frozenset[str] | None) -> str:
    """The capability detail, naming the scope that justifies its access level."""
    if scopes is None:
        return (
            f"{probe.detail}. This is a fine-grained token, whose permissions "
            "are per-repository and are not reported in a scope header, so "
            "only the read confirmed here is claimed"
        )

    granted = sorted(scopes.intersection(probe.admin_scopes + probe.write_scopes))
    if granted:
        return (
            f"{probe.detail}. The token holds {', '.join(granted)}, which "
            "GitHub documents as granting more than read over this resource. "
            "No write was attempted"
        )
    return (
        f"{probe.detail}. The token's scopes grant no more than read over this "
        "resource"
    )
