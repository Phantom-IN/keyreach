"""Anthropic API keys (``sk-ant-…``) — roadmap R1.2.

No prior art. Every endpoint, header and error type below was written from
Anthropic's own documentation, and each probe cites the page it came from.

Like OpenAI, an ``sk-ant-`` key is really two credentials sharing a prefix. An
**Admin API key** (``sk-ant-admin…``) reaches the Admin API — organization
members, workspaces, API keys, spend — and a normal API key reaches the platform.
This plugin selects the endpoint set from the documented prefix and probes only
that, so a key costs two or four requests instead of six (``plan.md`` §11).

**The one place this plugin claims more than its OpenAI sibling, and why.**
Anthropic documents that Claude Console admin keys "do not have selectable
scopes; every key carries full access to all endpoints that accept Admin API
keys" — and those endpoints include removing organization members and
deactivating API keys. So a *read* that succeeds against the Admin API with such
a key establishes, by the vendor's own access model rather than by inference,
that the key can also write. These capabilities are recorded as
``AccessLevel.ADMIN``.

That is the opposite of the verdict in ``keyreach/providers/openai.py``, on what
looks like the same finding, and the difference is not an inconsistency: OpenAI
admin keys *do* carry per-resource scopes (``users.read`` is separate from
``users.write``), so there a successful list proves only the read. Both verdicts
trace to a sentence in the respective vendor's documentation. Neither is a
judgement call about which provider is riskier.

**What this plugin will not claim.** Inference. keyreach never calls a model
(``plan.md`` §1, enforced by ``ai_ban``), so no capability here sets
``incurs_cost``, and the model-list capability says in as many words that
inference was not tested.

**Known limitation.** Claude Enterprise issues scoped admin keys under the
``sk-ant-api01-`` prefix, which is not distinguishable from a platform key by
shape. Such a key is probed as a platform key, and if Anthropic answers with an
authentication error rather than a permission error, keyreach will report it as
invalid when it is live. Recorded here rather than papered over: guessing a
family from a prefix keyreach cannot see would be a guess.
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
# Key format
# --------------------------------------------------------------------------

#: ``sk-ant-`` plus at least 24 characters of the documented alphabet, anchored.
#: Deliberately identical to the ``anthropic-api-key`` rule in
#: ``keyreach/patterns/detection_rules.yml`` — ``tests/test_provider_anthropic.py``
#: asserts the two agree, so the plugin and the rule set cannot drift apart and
#: disagree about what an Anthropic key looks like.
#: Source: https://docs.anthropic.com/en/api/getting-started
_KEY_PATTERN: Final = "^sk-ant-[A-Za-z0-9_-]{24,}$"

_KEY_RE: Final = re.compile(_KEY_PATTERN)

#: High because the prefix is unique and vendor-documented; not 1.0 because a
#: string can look like a key without being one, and only a probe settles that.
_DETECT_CONFIDENCE: Final = 0.99

#: The documented prefix of an Admin API credential.
#: Source: https://platform.claude.com/docs/en/manage-claude/admin-api-keys
ADMIN_PREFIX: Final = "sk-ant-admin"


class _Family(StrEnum):
    """Which API surface a key can reach."""

    PLATFORM = "platform"
    """Models and files. Every ``sk-ant-`` key that is not an admin key."""

    ADMIN = "admin"
    """The Admin API: organization, members, API keys, spend."""


def family_of(key: str) -> _Family:
    """The endpoint set this key can reach, from its documented prefix."""
    return _Family.ADMIN if key.startswith(ADMIN_PREFIX) else _Family.PLATFORM


# --------------------------------------------------------------------------
# Anthropic's error vocabulary
# --------------------------------------------------------------------------
#
# Errors arrive as {"type": "error", "error": {"type", "message"}}. Branching on
# the inner `type` rather than on `message` is what keeps this deterministic:
# the prose is rewritten without notice, the types are a documented contract.
# Source: https://docs.anthropic.com/en/api/errors

#: The one type that means "this string is not a key".
_TYPE_AUTHENTICATION: Final = "authentication_error"

#: The key is real; it may not do *this*. A scoped Claude Enterprise key, or an
#: admin key aimed at a platform endpoint. Live, with a caveat — not dead.
_TYPE_PERMISSION: Final = "permission_error"

#: Live, and being throttled. Reporting this as invalid would retire a working
#: credential, which is the more dangerous direction to be wrong in.
_TYPE_RATE_LIMIT: Final = "rate_limit_error"


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.anthropic.com/v1"

#: Required on every request. Pinned rather than tracked: an API version is a
#: contract, and following the newest one would let a vendor release change what
#: keyreach reports without a commit in this repository.
#: Source: https://docs.anthropic.com/en/api/versioning
API_VERSION: Final = "2023-06-01"

#: Opt-in header for the Files API, which is still in beta.
#: Source: https://platform.claude.com/docs/en/api/files-list
FILES_BETA: Final = "files-api-2025-04-14"

#: Start of the window the cost probe asks about, RFC 3339 as that endpoint
#: requires. A **constant**, never "thirty days ago": a clock read here would
#: make two runs of the same key produce different request URLs, different
#: cassette keys, and a report that cannot be reproduced (``plan.md`` §1).
COST_WINDOW_START: Final = "2025-01-01T00:00:00Z"


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    family: _Family
    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    noun: str = Field(description="What the response lists, for the evidence line.")
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


#: Every probe, in a fixed order, tagged with the key family that can reach it.
#: Six exist; a single key runs at most four, because the families are disjoint.
PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        family=_Family.PLATFORM,
        service="Claude Models",
        url=f"{API}/models",
        noun="models",
        detail=(
            "Can reach the Claude API and list available models. Inference was "
            "not tested: keyreach never calls a model"
        ),
        risk_weight=55,
        source="https://platform.claude.com/docs/en/api/models-list",
    ),
    _Probe(
        family=_Family.PLATFORM,
        service="Claude Files",
        url=f"{API}/files",
        headers={"anthropic-beta": FILES_BETA},
        noun="files",
        detail="Can list files uploaded to the account",
        risk_weight=80,
        # Documents and PDFs somebody uploaded for a model to read. This is what
        # makes a leaked Anthropic key a data finding rather than a billing one.
        data_sensitive=True,
        source="https://platform.claude.com/docs/en/api/files-list",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="Claude Organization",
        url=f"{API}/organizations/me",
        noun="organization records",
        detail="Can read the organization the key belongs to via the Admin API",
        risk_weight=60,
        source="https://platform.claude.com/docs/en/manage-claude/admin-api",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="Claude Organization Members",
        url=f"{API}/organizations/users",
        params={"limit": "1"},
        noun="organization members",
        detail=(
            "Can list organization members, including their email addresses, "
            "and — since Console admin keys are unscoped — change their roles "
            "or remove them"
        ),
        risk_weight=90,
        # Email addresses of real people: personal data, and a ready-made target
        # list for phishing whoever administers the account.
        data_sensitive=True,
        source="https://platform.claude.com/docs/en/manage-claude/admin-api",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="Claude Organization API Keys",
        url=f"{API}/organizations/api_keys",
        params={"limit": "1"},
        noun="API keys",
        detail=(
            "Can list the organization's API keys and — since Console admin "
            "keys are unscoped — deactivate them"
        ),
        risk_weight=85,
        # Key *metadata*, not key material: Anthropic never returns a secret
        # here. The exposure is the ability to inventory and disable them.
        source="https://platform.claude.com/docs/en/manage-claude/admin-api",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="Claude Cost Report",
        url=f"{API}/organizations/cost_report",
        params={"starting_at": COST_WINDOW_START, "limit": "1"},
        noun="daily cost buckets",
        detail="Can read the organization's billed spend",
        risk_weight=70,
        # Not user data, but private commercial data: what an organisation
        # spends on AI, by workspace, is exactly what a competitor would want.
        data_sensitive=True,
        source="https://platform.claude.com/docs/en/manage-claude/usage-cost-api",
    ),
)

#: The probe whose endpoint doubles as each family's liveness check. Reused
#: rather than duplicated, so a live key costs one request here and not two.
VALIDATE_SERVICE: Final[dict[_Family, str]] = {
    _Family.PLATFORM: "Claude Models",
    _Family.ADMIN: "Claude Organization",
}


def probes_for(family: _Family) -> tuple[_Probe, ...]:
    """The probes a key of this family can reach, in declaration order."""
    return tuple(probe for probe in PROBES if probe.family is family)


def validation_probe(family: _Family) -> _Probe:
    """The cheapest read that proves a key of this family is live."""
    wanted = VALIDATE_SERVICE[family]
    return next(probe for probe in PROBES if probe.service == wanted)


def _auth(key: str) -> dict[str, str]:
    return {"x-api-key": key, "anthropic-version": API_VERSION}


def _error_type(payload: Any) -> str:
    """The inner ``error.type`` from an Anthropic error body, or ``""``.

    Written defensively because this parses a third-party payload: a gateway
    returning an HTML error page must degrade to "no structured error", not
    raise out of the middle of a probe.
    """
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if not isinstance(error, dict):
        return ""
    kind = error.get("type")
    return kind if isinstance(kind, str) else ""


def _count(payload: Any) -> int | None:
    """Length of the ``data`` list every Anthropic list response carries."""
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return len(payload["data"])
    return None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Counts, never contents. The evidence has to convince a triager that the key
    reached real data without the report itself becoming a copy of that data.
    """
    found = _count(response.json_or_none())
    if found is None:
        return "request accepted"
    if found == 0:
        return f"{probe.noun}: none present"
    # Noun first, count second, so the line stays grammatical at every count.
    # "1 daily cost buckets listed" would be the sort of small wrongness that
    # makes a reader distrust the numbers beside it.
    return f"{probe.noun}: {found} listed"


def _organization(payload: Any) -> Identity | None:
    """The organization ``/v1/organizations/me`` names, if it named one.

    Read from the documented ``id``/``name`` fields, never scraped from prose.
    An exposed key that names its own organization tells the recipient which
    account to go and audit, which is most of what identity is for.
    """
    if not isinstance(payload, dict):
        return None
    identifier = payload.get("id")
    if not isinstance(identifier, str) or not identifier:
        return None
    name = payload.get("name")
    extra = {"organization_name": name} if isinstance(name, str) and name else {}
    return Identity(account=identifier, extra=extra)


def _poc(ctx: ProbeContext, key: str, probe: _Probe, response: ProbeResponse) -> str:
    """A masked, copy-pasteable, read-only reproduction of one probe.

    The URL comes from the response rather than being rebuilt from the probe, so
    the command reproduces the request that was actually made — query encoding
    included — instead of one that merely resembles it. Headers are assembled
    from the real key and then masked through the context, so ``--unmask``
    produces a command that runs and the default produces one that cannot.
    """
    headers = "".join(
        f" -H '{name}: {value}'"
        for name, value in sorted({**_auth(key), **probe.headers}.items())
    )
    return ctx.mask(f"curl -s{headers} '{response.url}'")


def _access(family: _Family) -> AccessLevel:
    """Admin-family capabilities are ``ADMIN``; platform ones are ``READ``.

    Not a judgement about severity. Anthropic documents that a Console admin key
    carries full access to every endpoint accepting admin keys, so a successful
    Admin API read establishes the matching writes by the vendor's own access
    model. See this module's docstring for the contrast with OpenAI.
    """
    return AccessLevel.ADMIN if family is _Family.ADMIN else AccessLevel.READ


class AnthropicProvider(Provider):
    """Anthropic platform and Admin API keys."""

    name = "anthropic"
    category = "ai"
    docs_url = "https://docs.anthropic.com/en/api/getting-started"
    rotation_guide_url = "https://platform.claude.com/settings/keys"

    def detect(self, key: str) -> float:
        """Pure structural match on the documented ``sk-ant-`` format."""
        return _DETECT_CONFIDENCE if _KEY_RE.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read against the key family's cheapest endpoint.

        Only ``authentication_error`` means the key is not a key. A permission
        error means a live key refused *this* endpoint, and a rate-limit error
        means a live key being throttled. Collapsing either into "invalid" would
        under-report an exposure, which is the more dangerous direction to be
        wrong in.
        """
        family = family_of(key)
        probe = validation_probe(family)
        response = await ctx.get(
            probe.url,
            params=probe.params or None,
            headers={**_auth(key), **probe.headers},
        )

        if response.ok:
            return ValidationResult(
                valid=True,
                identity=(
                    _organization(response.json_or_none())
                    if family is _Family.ADMIN
                    else None
                ),
            )

        kind = _error_type(response.json_or_none())

        if kind == _TYPE_AUTHENTICATION:
            return ValidationResult(
                valid=False, note="Anthropic rejected this key as invalid"
            )

        if kind == _TYPE_PERMISSION:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live but is not permitted on this endpoint, so "
                    "the capability map below is a lower bound. Scoped Claude "
                    "Enterprise keys present this way"
                ),
            )

        if kind == _TYPE_RATE_LIMIT:
            return ValidationResult(
                valid=True,
                note=(
                    "The key is live; Anthropic rate limited this request. "
                    "Re-run with --delay for a complete capability map"
                ),
            )

        if kind:
            return ValidationResult(
                valid=False,
                note=(
                    f"Anthropic refused this request ({kind}), so this key's "
                    "validity was not established either way"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Anthropic's response could not be interpreted, so this key's "
                "validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe the key family's endpoints concurrently; keep the ones that answered."""
        family = family_of(key)
        selected = probes_for(family)
        responses = await ctx.gather(
            [
                ctx.get(
                    probe.url,
                    params=probe.params or None,
                    headers={**_auth(key), **probe.headers},
                )
                for probe in selected
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=_access(family),
                detail=probe.detail,
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                # No probe sets `incurs_cost`. keyreach cannot confirm spend on
                # an AI key without calling a model, and it never calls a model.
                poc=_poc(ctx, key, probe, response),
                resource_ref=probe.source,
            )
            for probe, response in zip(selected, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
