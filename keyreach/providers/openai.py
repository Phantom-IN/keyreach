"""OpenAI API keys (``sk-…``) — roadmap R1.2.

No prior art. Every endpoint, header and error code below was written from
OpenAI's own documentation, and each probe cites the page it came from.

**An OpenAI key is really two different credentials wearing the same prefix.**
An admin key (``sk-admin-…``) reaches the Administration API — organization
members, projects, spend — and reaches no model at all; OpenAI states plainly
that "admin API keys cannot be used for non-administration endpoints". Every
other key is the reverse. Probing one set with the other's key would produce
nothing but 401s, so this plugin selects the endpoint set from the key's
documented prefix and probes only that. A key therefore costs three or four
requests, not seven, which is the point of ``plan.md`` §11.

**What this plugin will not claim, and why.**

* **Inference.** keyreach never calls a model (``plan.md`` §1, enforced by the
  ``ai_ban`` guardrail), so nothing here can establish that a key can generate
  text — and reaching ``/v1/models`` does not imply it. OpenAI's project keys
  carry **per-endpoint scopes**: a "Read Only" key holds ``api.model.read`` and
  can list models while being refused every write-shaped call. So no capability
  below sets ``incurs_cost``. That is deliberate and it does under-report the
  common case, where a leaked key really can spend; the alternative is asserting
  a spend capability keyreach did not confirm, which is the guess this tool does
  not make.
* **Administrative *write* access.** This is the one place OpenAI and Anthropic
  genuinely differ, and it is worth stating because the two plugins reach
  opposite verdicts on what looks like the same finding. OpenAI admin keys have
  **selectable scopes** — ``users.read`` and ``users.write`` are separate — so a
  key that lists organization members has been shown to hold ``users.read`` and
  nothing more. These capabilities are therefore ``READ``. Anthropic's Console
  admin keys have no selectable scopes at all, which is why
  ``keyreach/providers/anthropic.py`` records ``ADMIN`` for the same shape of
  probe. Both verdicts trace to a sentence in the respective vendor's docs.

**On duplication with the Anthropic plugin.** The two files share a probe table
shape and an enumerate loop, and deliberately do not share code. Roadmap
**R1.4** is the checkpoint that asks whether adding a provider touches only its
own file; extracting a shared AI base class *now* would answer that question by
assuming it. If R1.4 concludes the abstraction is real, that is where it belongs.
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
# Key formats
# --------------------------------------------------------------------------
#
# Deliberately identical to the four `openai-*` rules in
# `keyreach/patterns/detection_rules.yml`. `tests/test_provider_openai.py`
# asserts the two agree, so the plugin and the rule set cannot drift apart and
# disagree about what an OpenAI key looks like.
# Source: https://platform.openai.com/docs/api-reference/authentication

#: ``(pattern, confidence)``, mirroring the rule set. The generic rule is last
#: and carries the lowest confidence because ``sk-`` alone is a weak signal —
#: the negative lookahead keeps it from also claiming the specific formats, and
#: from claiming Anthropic's ``sk-ant-`` keys.
_PATTERNS: Final[tuple[tuple[str, float], ...]] = (
    ("^sk-proj-[A-Za-z0-9_-]{20,}$", 0.99),
    ("^sk-svcacct-[A-Za-z0-9_-]{20,}$", 0.99),
    ("^sk-admin-[A-Za-z0-9_-]{20,}$", 0.99),
    ("^sk-(?!admin-|ant-|proj-|svcacct-)[A-Za-z0-9_-]{20,}$", 0.90),
)

_COMPILED: Final = tuple((re.compile(pattern), score) for pattern, score in _PATTERNS)

#: The documented prefix of an Administration API credential.
#: Source: https://developers.openai.com/api/docs/guides/admin-apis
ADMIN_PREFIX: Final = "sk-admin-"


class _Family(StrEnum):
    """Which API surface a key can reach. Disjoint, per OpenAI's docs."""

    PLATFORM = "platform"
    """Models, files, fine-tuning, vector stores. Everything but ``sk-admin-``."""

    ADMIN = "admin"
    """The Administration API, and nothing else. ``sk-admin-`` keys."""


def family_of(key: str) -> _Family:
    """The endpoint set this key can reach, from its documented prefix."""
    return _Family.ADMIN if key.startswith(ADMIN_PREFIX) else _Family.PLATFORM


# --------------------------------------------------------------------------
# OpenAI's error vocabulary
# --------------------------------------------------------------------------
#
# Errors arrive as {"error": {"message", "type", "param", "code"}}. Branching on
# `code`/`type` rather than on `message` is what keeps this deterministic: the
# prose is rewritten without notice, the codes are a documented contract.
# Source: https://developers.openai.com/api/docs/guides/error-codes

#: The one code that means "this string is not a key".
_CODE_INVALID_KEY: Final = "invalid_api_key"

#: Billing exhaustion. A quota error is proof of a *live* key: OpenAI only knows
#: whose quota to check once it has accepted the credential. Reporting one of
#: these as "invalid" would retire a key that still works the moment somebody
#: tops the account up — the more dangerous direction to be wrong in.
_TYPE_INSUFFICIENT_QUOTA: Final = "insufficient_quota"
_BILLING_CODES: Final[frozenset[str]] = frozenset(
    {
        "credit_balance_exhausted",
        "organization_spend_limit_exceeded",
        "organization_usage_limit_exceeded",
        "project_spend_limit_exceeded",
    }
)

#: Geographic refusal. This says something about where keyreach is running, not
#: about the key, so neither "valid" nor "invalid" would be honest.
_CODE_REGION_BLOCKED: Final = "unsupported_country_region_territory"

#: HTTP statuses this plugin interprets specially.
_HTTP_UNAUTHORIZED: Final = 401
_HTTP_TOO_MANY_REQUESTS: Final = 429

#: Response header carrying the organization the request was billed to. An
#: exposed key that names its own organization tells the recipient which account
#: to go and audit, which is most of what identity is for.
_ORG_HEADER: Final = "openai-organization"


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

API: Final = "https://api.openai.com/v1"

#: Start of the window the cost probe asks about: 2025-01-01T00:00:00Z, in Unix
#: seconds, as that endpoint requires. A **constant**, never "now minus thirty
#: days" — a clock read here would make two runs of the same key produce
#: different request URLs, different cassette keys, and a report that cannot be
#: reproduced (``plan.md`` §1).
COST_WINDOW_START: Final = "1735689600"


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


#: Header that opts into the Assistants v2 surface, which the vector store
#: endpoints still sit behind.
#: Source: https://platform.openai.com/docs/api-reference/vector-stores/list
_ASSISTANTS_BETA: Final[dict[str, str]] = {"OpenAI-Beta": "assistants=v2"}

#: Every probe, in a fixed order, tagged with the key family that can reach it.
#: Seven exist; a single key runs at most four, because the families are
#: disjoint. Each is an authenticated request logged against somebody's
#: production account, so the list stays short on purpose (``plan.md`` §11).
PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        family=_Family.PLATFORM,
        service="OpenAI Models",
        url=f"{API}/models",
        noun="models",
        # The caveat lives in the detail because the detail is what a recipient
        # reads; the reasoning is in this module's docstring.
        detail=(
            "Can reach the OpenAI platform API and list available models. "
            "Inference was not tested: keyreach never calls a model"
        ),
        risk_weight=55,
        source="https://developers.openai.com/api/reference/resources/models/methods/list",
    ),
    _Probe(
        family=_Family.PLATFORM,
        service="OpenAI Files",
        url=f"{API}/files",
        noun="files",
        detail="Can list files uploaded to the account",
        risk_weight=80,
        # Training sets, assistant documents, batch inputs and outputs. This is
        # what makes a leaked OpenAI key a data finding rather than a billing one.
        data_sensitive=True,
        source="https://platform.openai.com/docs/api-reference/files/list",
    ),
    _Probe(
        family=_Family.PLATFORM,
        service="OpenAI Vector Stores",
        url=f"{API}/vector_stores",
        headers=_ASSISTANTS_BETA,
        noun="vector stores",
        detail="Can list vector stores holding the account's retrieval corpora",
        risk_weight=75,
        # A vector store is somebody's document collection, indexed. Listing it
        # establishes reach into whatever the account put behind retrieval.
        data_sensitive=True,
        source="https://platform.openai.com/docs/api-reference/vector-stores/list",
    ),
    _Probe(
        family=_Family.PLATFORM,
        service="OpenAI Fine-tuning Jobs",
        url=f"{API}/fine_tuning/jobs",
        noun="fine-tuning jobs",
        detail="Can list fine-tuning jobs and the files they were trained on",
        risk_weight=70,
        # Job records name their training files and the models produced, which
        # describes the account's proprietary data even before it is fetched.
        data_sensitive=True,
        source="https://platform.openai.com/docs/api-reference/fine-tuning/list",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="OpenAI Organization Projects",
        url=f"{API}/organization/projects",
        noun="projects",
        detail=(
            "Can list the organization's projects via the Administration API. "
            "Write scopes were not tested: admin keys carry per-resource scopes"
        ),
        risk_weight=85,
        source="https://developers.openai.com/api/docs/guides/admin-apis",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="OpenAI Organization Members",
        url=f"{API}/organization/users",
        noun="organization members",
        detail=(
            "Can list organization members, including their names and email "
            "addresses. Write scopes were not tested"
        ),
        risk_weight=90,
        # Names and email addresses of real people: personal data, and a ready
        # made target list for phishing whoever administers the account.
        data_sensitive=True,
        source="https://developers.openai.com/api/docs/guides/admin-apis",
    ),
    _Probe(
        family=_Family.ADMIN,
        service="OpenAI Organization Costs",
        url=f"{API}/organization/costs",
        params={"start_time": COST_WINDOW_START, "limit": "1"},
        noun="cost buckets",
        detail="Can read the organization's billed spend",
        risk_weight=70,
        # Not user data, but private commercial data: what the account spends on
        # AI, broken down by project, is exactly what a competitor would want.
        data_sensitive=True,
        source=(
            "https://developers.openai.com/api/reference/resources/admin/"
            "subresources/organization/subresources/usage/methods/costs"
        ),
    ),
)

#: The probe whose endpoint doubles as each family's liveness check.
#:
#: R1.4 measured this and found the claim that used to sit here — "one request,
#: and not two" — was false: naming the same endpoint twice made the request
#: twice, once in ``validate`` and again in ``enumerate``. It is one request now
#: because ``ProbeClient`` answers a repeated idempotent GET from a per-run
#: cache, not because of anything this line does.
VALIDATE_SERVICE: Final[dict[_Family, str]] = {
    _Family.PLATFORM: "OpenAI Models",
    _Family.ADMIN: "OpenAI Organization Projects",
}


def probes_for(family: _Family) -> tuple[_Probe, ...]:
    """The probes a key of this family can reach, in declaration order."""
    return tuple(probe for probe in PROBES if probe.family is family)


def validation_probe(family: _Family) -> _Probe:
    """The cheapest read that proves a key of this family is live."""
    wanted = VALIDATE_SERVICE[family]
    return next(probe for probe in PROBES if probe.service == wanted)


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _error(payload: Any) -> dict[str, Any]:
    """The ``error`` object from an OpenAI error body, or an empty mapping.

    Written defensively because this parses a third-party payload: a gateway
    returning an HTML error page must degrade to "no structured error", not
    raise out of the middle of a probe.
    """
    if not isinstance(payload, dict):
        return {}
    error = payload.get("error")
    return error if isinstance(error, dict) else {}


def _text(error: dict[str, Any], field: str) -> str:
    """A string field of an error object, or ``""`` if absent or not a string."""
    value = error.get(field)
    return value if isinstance(value, str) else ""


def _is_billing_failure(error: dict[str, Any]) -> bool:
    """Did the request fail because the account is out of money, not out of key?"""
    return (
        _text(error, "type") == _TYPE_INSUFFICIENT_QUOTA
        or _text(error, "code") in _BILLING_CODES
    )


def _count(payload: Any) -> int | None:
    """Length of the ``data`` list every OpenAI list response carries."""
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
    # "1 fine-tuning jobs listed" would be the sort of small wrongness that
    # makes a reader distrust the numbers beside it.
    return f"{probe.noun}: {found} listed"


def _identity(response: ProbeResponse) -> Identity | None:
    """The organization OpenAI says the request belonged to, if it said.

    Read from a response header rather than a dedicated endpoint, because there
    is no free "who am I" call — so this costs nothing and is available on the
    liveness check keyreach already had to make.
    """
    organization = response.headers.get(_ORG_HEADER, "")
    return Identity(account=organization) if organization else None


def _verdict_by_code(
    error: dict[str, Any], identity: Identity | None
) -> ValidationResult | None:
    """The three outcomes decided by the error code alone, or ``None``.

    Split out from :meth:`OpenAIProvider.validate` so that neither half is a
    wall of branches. Order matters and is preserved: a key OpenAI calls invalid
    is invalid whatever else the payload says, and a billing failure outranks
    the status code it arrives under.
    """
    code = _text(error, "code")

    if code == _CODE_INVALID_KEY:
        return ValidationResult(valid=False, note="OpenAI rejected this key as invalid")

    if _is_billing_failure(error):
        return ValidationResult(
            valid=True,
            identity=identity,
            note=(
                "The key is live; the account's billing quota is exhausted. "
                "It starts working again the moment the account is topped up"
            ),
        )

    if code == _CODE_REGION_BLOCKED:
        return ValidationResult(
            valid=False,
            note=(
                "OpenAI refused the request for this country or region, so "
                "this key's validity was not established either way. Re-run "
                "from a supported region"
            ),
        )

    return None


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


class OpenAIProvider(Provider):
    """OpenAI platform and Administration API keys."""

    name = "openai"
    category = "ai"
    docs_url = "https://platform.openai.com/docs/api-reference/authentication"
    rotation_guide_url = "https://platform.openai.com/api-keys"

    def detect(self, key: str) -> float:
        """Pure structural match against the documented ``sk-`` formats.

        Returns the highest confidence of any matching pattern. The patterns are
        mutually exclusive by construction, so in practice at most one matches;
        taking the maximum rather than the first hit means a future overlap
        cannot make the answer depend on declaration order.
        """
        scores = [score for pattern, score in _COMPILED if pattern.match(key)]
        return max(scores) if scores else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One read against the key family's cheapest endpoint.

        Only ``invalid_api_key`` means the key is not a key. A quota error means
        a live key on an account that has run out of money; a 429 means a live
        key that is being rate limited. Collapsing either into "invalid" would
        retire a working credential, and under-reporting an exposure is the more
        dangerous direction to be wrong in.
        """
        probe = validation_probe(family_of(key))
        response = await ctx.get(
            probe.url,
            params=probe.params or None,
            headers={**_auth(key), **probe.headers},
        )
        identity = _identity(response)

        if response.ok:
            return ValidationResult(valid=True, identity=identity)

        error = _error(response.json_or_none())
        code = _text(error, "code")

        by_code = _verdict_by_code(error, identity)
        if by_code is not None:
            return by_code

        if response.status_code == _HTTP_TOO_MANY_REQUESTS:
            return ValidationResult(
                valid=True,
                identity=identity,
                note=(
                    "The key is live; OpenAI rate limited this request. Re-run "
                    "with --delay for a complete capability map"
                ),
            )

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "OpenAI did not accept this key"
                    + (f" ({code})" if code else "")
                    + ". Note that an admin key cannot reach the platform API, "
                    "and a platform key cannot reach the Administration API"
                ),
            )

        if code:
            return ValidationResult(
                valid=True,
                note=f"The key is live; OpenAI refused this request ({code})",
            )

        return ValidationResult(
            valid=False,
            note=(
                "OpenAI's response could not be interpreted, so this key's "
                "validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe the key family's endpoints concurrently; keep the ones that answered."""
        selected = probes_for(family_of(key))
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
                # READ everywhere, including the Administration API: OpenAI
                # admin keys carry per-resource scopes, so listing members
                # proves `users.read` and nothing about `users.write`.
                access=AccessLevel.READ,
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
