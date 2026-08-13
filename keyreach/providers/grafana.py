"""Grafana Cloud access policy tokens — roadmap R2.6.

No prior art. Narrowed the same way Redis was in R2.5: the roadmap says
"Grafana", and what ships is one specific credential Grafana issues, not
everything the vendor name could mean.

**"Grafana" cannot mean a self-hosted instance, because there is no fixed
host.** A self-hosted or self-managed Grafana's service account tokens
(``glsa_...``) authenticate against ``https://<the operator's own
hostname>/api/...`` — a URL Grafana Labs does not publish and that keyreach's
detection layer, which recognises a credential by shape alone, has no way to
recover from the token itself. This is a harder version of GitLab's
self-managed gap (R2.4): GitLab at least has ``gitlab.com`` as a real default
host to probe. Grafana has no analogous default — a Grafana Cloud *stack* is
also reached at a per-stack hostname (``https://<stack-slug>.grafana.net``),
not a fixed one. Legacy Grafana API keys compound the problem: they are
deprecated in favour of service accounts and were never published with any
prefix or format at all, the same shape of dead end as Bitbucket's and npm's
withdrawn rules.

**What does have a fixed host is Grafana Cloud's *organization-level* access
policy API**, confirmed from ``grafana.com/docs/grafana-cloud/...`` —
``https://www.grafana.com/api/v1/accesspolicies`` and
``.../v1/tokens``, independent of any stack. Its tokens are prefixed
``glc_``, confirmed from Grafana's own documented example
(``Authorization: Bearer glc_eyJrIjoi...``). This is the credential this
plugin covers; a self-hosted ``glsa_`` token is recognised by no rule here and
reached by no ``--provider grafana`` probe either, because there is nowhere
to send it.

**The one endpoint keyreach can reach needs a scope most of these tokens
won't have — a second provider this item with that shape, after Sentry's
``org:read``/``org:write``/``org:admin`` gate.** Grafana Cloud access policies
carry narrow, purpose-specific scopes (``metrics:read``, ``logs:write``,
``accesspolicies:read``, ...), and the two endpoints reachable at the fixed
``grafana.com`` host — listing access policies and listing their tokens —
both need ``accesspolicies:read``. A token minted for its ordinary purpose
(writing metrics or logs from an agent) will not carry that scope, so
keyreach cannot confirm it is live at all: Grafana documents no
scope-free "whoami" call at this host, the same gap New Relic's license key
and Atlas's HTTP Digest keys leave elsewhere in this roadmap item. The
validation note says so rather than reporting such a token "invalid".

**Region is a required, undiscoverable query parameter**, confirmed from
Grafana's Cloud API reference (``region``: "us", "eu", "au",
"prod-eu-west-3", ...). Nothing about a ``glc_`` token names its region, so
keyreach probes ``us`` only and says so — the same under-reporting Datadog's
site and AWS's ``us-east-1``-only enumeration already carry elsewhere in this
codebase.

**Probed against the live API.** A syntactically invalid token against
``/v1/accesspolicies?region=us`` returns
``401 {"code":"InvalidCredentials","message":"Token could not be parsed",
"requestId":"..."}}`` — this exact shape is what ``message_of`` reads; Grafana's
docs show the *success* body for this endpoint but not the error one.
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
# Detection
# --------------------------------------------------------------------------
#
# Source: https://grafana.com/docs/grafana-cloud/account-management/authentication-and-permissions/access-policies/
# example: `Authorization: Bearer glc_eyJrIjoi...`. No exact length is
# published, so the pattern uses an open floor rather than inventing one.
_PATTERN: Final = re.compile(r"^glc_[A-Za-z0-9_=-]{20,}$")
CONFIDENCE: Final = 0.95

# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
#
# Source: https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/

API: Final = "https://www.grafana.com/api/v1"
ACCESS_POLICIES_URL: Final = f"{API}/accesspolicies"
TOKENS_URL: Final = f"{API}/tokens"

#: Not derivable from the token. See the module docstring.
REGION: Final = "us"

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _params() -> dict[str, str]:
    return {"region": REGION}


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    noun: str
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    source: str


_DOCS: Final = (
    "https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/"
)

PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Grafana Cloud Access Policies",
        url=ACCESS_POLICIES_URL,
        noun="access policies",
        detail=(
            "Can list the organization's access policies, including their "
            "scopes and realms"
        ),
        risk_weight=65,
        data_sensitive=True,
        source=f"{_DOCS}#list-access-policies",
    ),
    _Probe(
        service="Grafana Cloud Access Policy Tokens",
        url=TOKENS_URL,
        noun="tokens",
        detail=(
            "Can list every token issued under the organization's access "
            "policies, by name and expiry — not their values"
        ),
        risk_weight=70,
        data_sensitive=True,
        source=f"{_DOCS}#list-tokens",
    ),
)


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _payload(response: ProbeResponse) -> dict[str, Any]:
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def items_of(response: ProbeResponse) -> list[dict[str, Any]]:
    """The ``items`` array both list endpoints share, or ``[]``."""
    raw = _payload(response).get("items")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def message_of(response: ProbeResponse) -> str:
    """Grafana Cloud's error text.

    Confirmed live: ``{"code": "InvalidCredentials", "message": "Token could
    not be parsed", "requestId": "..."}``. ``message`` is human-readable;
    ``code`` is a stable identifier kept out of the note to avoid duplicating
    it.
    """
    message = _payload(response).get("message")
    return message if isinstance(message, str) else ""


def _org_id(items: list[dict[str, Any]]) -> str | None:
    for item in items:
        org_id = item.get("orgId")
        if isinstance(org_id, str):
            return org_id
    return None


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    items = items_of(response)
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _identity(items: list[dict[str, Any]]) -> Identity:
    return Identity(account=_org_id(items))


def _poc(ctx: ProbeContext, token: str, url: str) -> str:
    return ctx.mask(
        f"curl -s -H 'Authorization: Bearer {token}' '{url}?region={REGION}'"
    )


class GrafanaProvider(Provider):
    """Grafana Cloud access policy tokens (``glc_``). See the module docstring."""

    name = "grafana"
    category = "monitoring"
    docs_url = (
        "https://grafana.com/docs/grafana-cloud/developer-resources/"
        "api-reference/cloud-api/"
    )
    rotation_guide_url = (
        "https://grafana.com/docs/grafana-cloud/account-management/"
        "authentication-and-permissions/access-policies/"
    )

    def detect(self, key: str) -> float:
        """Pure structural match against the confirmed ``glc_`` prefix."""
        return CONFIDENCE if _PATTERN.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """List access policies — the only fixed-host, no-instance-URL call.

        Needs ``accesspolicies:read``; see the module docstring for why a
        rejection here does not necessarily mean the token is dead.
        """
        if not _PATTERN.match(key):
            return ValidationResult(
                valid=False,
                note="This does not look like a Grafana Cloud access policy token",
            )

        response = await ctx.get(
            ACCESS_POLICIES_URL, params=_params(), headers=_headers(key)
        )
        message = message_of(response)

        if response.ok:
            items = items_of(response)
            if not items:
                return ValidationResult(
                    valid=True,
                    note="Grafana Cloud accepted this token but listed no access policies",
                )
            return ValidationResult(
                valid=True,
                identity=_identity(items),
                note=f"Grafana Cloud listed {len(items)} access polic"
                + ("y" if len(items) == 1 else "ies"),
            )

        if response.status_code == _HTTP_UNAUTHORIZED:
            return ValidationResult(
                valid=False,
                note=(
                    "Grafana Cloud did not accept this token"
                    + (f" ({message})" if message else "")
                ),
            )

        if response.status_code == _HTTP_FORBIDDEN:
            return ValidationResult(
                valid=False,
                note=(
                    "Grafana Cloud returned 403 listing access policies. This "
                    "may mean the token is invalid, or that it is live but was "
                    "never granted accesspolicies:read — most access policy "
                    "tokens are scoped narrowly for metrics/logs/traces, and "
                    "Grafana documents no endpoint that confirms liveness "
                    "without that specific scope" + (f" ({message})" if message else "")
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "Grafana Cloud's response could not be interpreted"
                + (f" ({message})" if message else "")
                + ", so this credential's validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """List access policies and their tokens — both need ``accesspolicies:read``.

        Both empty for a token scoped only for metrics/logs/traces, honestly
        reflecting that keyreach cannot see past the fixed host into what such
        a token can reach on a stack it has no way to address.
        """
        if not _PATTERN.match(key):
            return []

        headers = _headers(key)
        params = _params()
        responses = await ctx.gather(
            [ctx.get(probe.url, params=params, headers=headers) for probe in PROBES]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=AccessLevel.READ,
                detail=probe.detail,
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=_poc(ctx, key, probe.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
