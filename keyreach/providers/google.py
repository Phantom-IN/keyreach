"""Google Cloud API keys (``AIza…``) — roadmap R1.1.

Blueprint credit: **gmapsapiscanner** by Ozgur Alp
(<https://github.com/ozguralp/gmapsapiscanner>), **MIT** — license verified from
the upstream repository on 2026-08-11 and recorded in ``CREDITS.md`` and
``THIRD_PARTY_LICENSES.md``. No code was copied. That project established *which
Google APIs are worth probing with an exposed key*, which is the hard-won part;
every endpoint, parameter and success rule below was then written from Google's
own documentation and each probe cites the page it came from.

An ``AIza`` key is a project-scoped Google Cloud API key, so what it reaches
depends on which APIs are enabled on that project and how the key is restricted.
There is no endpoint that reports either. Enumeration therefore means asking a
handful of APIs directly and recording which answer — which is exactly why the
capability map, not the key format, is the finding.

**Two response conventions, and getting this wrong would invent capabilities.**
The Maps Platform web services return **HTTP 200 with a ``status`` field in the
body**, so ``REQUEST_DENIED`` for a key with no access arrives as a perfectly
successful HTTP response. Treating 2xx as success would report every Maps API as
reachable for every key, including keys with no Maps access at all. The Gemini
and Roads APIs use ordinary HTTP status codes. Each probe declares which
convention it follows.

**On cost.** ``plan.md`` §11 says probes are read-only and must not spend. The
Maps Platform has no free metadata endpoint: the only way to establish that a key
can call the Geocoding API is to call it, and that call is billed to the key's
owner at a fraction of a cent. keyreach accepts that narrowly — a handful of
single requests, to establish an exposure the owner needs to know about, where no
free equivalent exists — and never at scale. The Gemini probes below are list
endpoints and are free. See ``plan.md`` §11, which now states the rule.

**On what is deliberately not probed.**

* **Inference.** keyreach never calls a model — no ``generateContent``, no
  embeddings (``plan.md`` §1, enforced by the ``ai_ban`` guardrail). So the
  Gemini capability below is *reachability of the Generative Language API*, and
  it does not claim the key can run inference. It might not: Google API key
  restrictions can be scoped to individual **methods** within a service, so a key
  that lists models has not thereby been shown to generate with them. Claiming
  otherwise would be a guess, and guessing is the thing this tool does not do.
* **FCM.** The roadmap listed it, and it is not here. The only known probe for a
  legacy FCM server key is to *send a message*, which is a write and would push a
  notification to a real device — outside ``plan.md`` §11 regardless of how
  useful the signal would be. Legacy FCM was decommissioned in 2024 in any case,
  so an ``AIza`` key no longer reaches it.
* **Places Photo, Static Maps, Street View.** These return image bytes rather
  than a status, cost more per call, and prove nothing the cheaper Places probe
  does not.
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

#: ``AIza`` plus 35 characters of base64url alphabet, anchored.
#: Deliberately identical to the ``google-api-key`` rule in
#: ``keyreach/patterns/detection_rules.yml`` — ``tests/test_provider_google.py``
#: asserts the two agree, so the plugin and the rule set cannot drift apart and
#: disagree about what a Google key looks like.
#: Source: https://cloud.google.com/docs/authentication/api-keys
_KEY_PATTERN: Final = "^AIza[0-9A-Za-z_-]{35}$"

_KEY_RE: Final = re.compile(_KEY_PATTERN)

#: Confidence for a structural match. High because the prefix and length are
#: distinctive and documented; not 1.0 because a string can look like a key
#: without being one, and only a probe settles that.
_DETECT_CONFIDENCE: Final = 0.99


# --------------------------------------------------------------------------
# Google's error vocabulary
# --------------------------------------------------------------------------
#
# Google APIs return a structured error whose `details` array carries an
# ErrorInfo with a machine-readable `reason`. Branching on `reason` rather than
# on the human-readable `message` is what keeps this deterministic: the prose
# is localised and changes, the reason code is a documented contract.
# Source: https://google.aip.dev/193

#: The one reason that means "this key is not a key". Everything else means the
#: key was recognised and something *else* refused the request, which is a very
#: different finding and must not be reported as "the provider rejected it".
_REASON_KEY_INVALID: Final = "API_KEY_INVALID"

#: The service exists and the key is real, but this API is not enabled on the
#: project. Useful rather than disappointing: the error names the project.
_REASON_SERVICE_DISABLED: Final = "SERVICE_DISABLED"

#: Application restrictions (`plan.md` §6). The key is live; Google refused this
#: particular caller. Recorded, and it downgrades severity — see `core/scoring.py`.
_RESTRICTION_REASONS: Final[dict[str, str]] = {
    "API_KEY_HTTP_REFERRER_BLOCKED": "an HTTP referrer restriction",
    "API_KEY_IP_ADDRESS_BLOCKED": "an IP address restriction",
    "API_KEY_ANDROID_APP_BLOCKED": "an Android app restriction",
    "API_KEY_IOS_APP_BLOCKED": "an iOS app restriction",
    "API_KEY_SERVICE_BLOCKED": "an API restriction on this key",
}

#: Maps web-service `status` values that mean the call was authorised. Both
#: count: a search that legitimately matched nothing still proves the key may
#: call the API, which is the capability being established.
#: Source: https://developers.google.com/maps/documentation/places/web-service/search-find-place
_MAPS_SUCCESS: Final[frozenset[str]] = frozenset({"OK", "ZERO_RESULTS"})


class _Style(StrEnum):
    """How an endpoint signals failure."""

    REST = "rest"
    """Ordinary HTTP status codes. Gemini and Roads."""

    MAPS_WEB_SERVICE = "maps"
    """HTTP 200 always; the verdict is the body's ``status`` field."""


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    style: _Style
    data_sensitive: bool = False
    incurs_cost: bool = False
    source: str = Field(description="Vendor documentation URL for this endpoint.")


GEMINI: Final = "https://generativelanguage.googleapis.com/v1beta"
MAPS: Final = "https://maps.googleapis.com/maps/api"
ROADS: Final = "https://roads.googleapis.com/v1"

#: The validation endpoint: free, read-only, and the same list call used as a
#: capability probe.
#:
#: R1.4 measured this and found the claim that used to sit here — "one request,
#: not two" — was false: naming the same endpoint twice made the request twice,
#: once in ``validate`` and again in ``enumerate``. It is one request now
#: because ``ProbeClient`` answers a repeated idempotent GET from a per-run
#: cache, not because of anything this line does.
VALIDATE_URL: Final = f"{GEMINI}/models"

#: Every probe, in a fixed order. Six is deliberate — each additional probe is
#: another authenticated request logged against somebody's production project,
#: and three of these are billed to its owner (`plan.md` §11).
PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        service="Gemini Files",
        url=f"{GEMINI}/files",
        detail="Can list files uploaded to the project's Gemini account",
        risk_weight=80,
        style=_Style.REST,
        # Documents, images and audio a user uploaded for a model to read. This
        # is the capability that makes an `AIza` key a data-exposure finding
        # rather than a billing one.
        data_sensitive=True,
        source="https://ai.google.dev/api/files",
    ),
    _Probe(
        service="Gemini Cached Content",
        url=f"{GEMINI}/cachedContents",
        detail="Can list cached prompt content held for the project",
        risk_weight=75,
        style=_Style.REST,
        # Cached content is whole prompts and documents kept server-side for
        # reuse, so listing it exposes what the account is processing.
        data_sensitive=True,
        source="https://ai.google.dev/api/caching",
    ),
    _Probe(
        service="Gemini Models",
        url=f"{GEMINI}/models",
        # The caveat is in the detail because the detail is what a recipient
        # reads in the report; the reasoning behind it is in this module's
        # docstring. Kept to one clause so it does not swamp the capability
        # table — every capability's detail shares that table with five others.
        detail=(
            "Can reach the Generative Language API and list models. Inference "
            "was not tested: keyreach never calls a model"
        ),
        risk_weight=55,
        style=_Style.REST,
        # Not `incurs_cost`: listing models is free, and inference was neither
        # attempted nor established. See the module docstring.
        source="https://ai.google.dev/api/models",
    ),
    _Probe(
        service="Places API (Find Place)",
        url=f"{MAPS}/place/findplacefromtext/json",
        params={"input": "museum", "inputtype": "textquery"},
        detail="Can run Places text searches, billed to the project",
        risk_weight=50,
        style=_Style.MAPS_WEB_SERVICE,
        incurs_cost=True,
        source=(
            "https://developers.google.com/maps/documentation/places/"
            "web-service/search-find-place"
        ),
    ),
    _Probe(
        service="Geocoding API",
        url=f"{MAPS}/geocode/json",
        params={"address": "1600 Amphitheatre Parkway"},
        detail="Can geocode addresses, billed to the project",
        risk_weight=40,
        style=_Style.MAPS_WEB_SERVICE,
        incurs_cost=True,
        source=(
            "https://developers.google.com/maps/documentation/geocoding/"
            "requests-geocoding"
        ),
    ),
    _Probe(
        service="Roads API",
        url=f"{ROADS}/nearestRoads",
        params={"points": "60.170880,24.942795"},
        detail="Can snap coordinates to roads, billed to the project",
        risk_weight=40,
        style=_Style.REST,
        incurs_cost=True,
        source="https://developers.google.com/maps/documentation/roads/nearest",
    ),
)


def _error_info(payload: Any) -> dict[str, Any]:
    """The ``ErrorInfo`` detail from a Google error body, or an empty mapping.

    Written defensively because this parses a third-party error payload: a
    provider returning an HTML maintenance page must degrade to "no structured
    error", not raise out of the middle of a probe.
    """
    if not isinstance(payload, dict):
        return {}
    error = payload.get("error")
    if not isinstance(error, dict):
        return {}
    details = error.get("details")
    if not isinstance(details, list):
        return {}
    for detail in details:
        if (
            isinstance(detail, dict)
            and detail.get("@type") == "type.googleapis.com/google.rpc.ErrorInfo"
        ):
            return detail
    return {}


def _project(info: dict[str, Any]) -> str | None:
    """The project a ``SERVICE_DISABLED`` error names, e.g. ``projects/123``.

    Read from ``metadata.consumer`` rather than scraped out of the message
    prose, which is localised and rewritten. An exposed key that names its own
    project is a materially better finding: it tells the recipient which project
    to go and audit.
    """
    metadata = info.get("metadata")
    if not isinstance(metadata, dict):
        return None
    consumer = metadata.get("consumer")
    return consumer if isinstance(consumer, str) and consumer else None


def _count(payload: Any, field: str) -> int | None:
    """Length of a list field in a Gemini list response, if present."""
    if isinstance(payload, dict) and isinstance(payload.get(field), list):
        return len(payload[field])
    return None


#: Gemini list responses name their collection differently per endpoint. Used
#: only to count items for evidence — never to read their contents.
_COLLECTION: Final[dict[str, str]] = {
    "Gemini Files": "files",
    "Gemini Cached Content": "cachedContents",
    "Gemini Models": "models",
}


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Counts, never contents. The evidence has to convince a triager that the key
    reached real data without the report itself becoming a copy of that data.
    """
    payload = response.json_or_none()
    field = _COLLECTION.get(probe.service)
    if field is not None:
        found = _count(payload, field)
        if found is not None:
            return f"{found} {field} listed"
        # A 200 with no collection key means the account simply has none.
        return f"no {field} present"
    if isinstance(payload, dict) and isinstance(payload.get("status"), str):
        return f"status {payload['status']}"
    return "request accepted"


def _succeeded(probe: _Probe, response: ProbeResponse) -> bool:
    """Did this probe confirm access?

    The Maps branch is the reason this function exists. See the module docstring
    — a Maps web service answers ``REQUEST_DENIED`` with HTTP 200, so trusting
    the status code would report Maps access for keys that have none.
    """
    if probe.style is _Style.REST:
        return response.ok
    if not response.ok:
        return False
    payload = response.json_or_none()
    if not isinstance(payload, dict):
        return False
    return payload.get("status") in _MAPS_SUCCESS


class GoogleProvider(Provider):
    """Google Cloud API keys — Maps Platform and the Gemini API."""

    name = "google"
    category = "cloud"
    docs_url = "https://cloud.google.com/docs/authentication/api-keys"
    rotation_guide_url = (
        "https://cloud.google.com/docs/authentication/api-keys#delete_an_api_key"
    )
    credit = "gmapsapiscanner"

    def detect(self, key: str) -> float:
        """Pure structural match on the documented ``AIza`` format."""
        return _DETECT_CONFIDENCE if _KEY_RE.match(key) else 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One free read against the Gemini model list, interpreted by reason code.

        Only ``API_KEY_INVALID`` means the key is not a key. Every other Google
        error means the key was recognised and something else refused *this*
        request — a disabled API, a referrer restriction — which is a live key
        with a caveat, not a dead one. Collapsing those into "invalid" would
        under-report an exposure, which is the more dangerous direction to be
        wrong in.
        """
        response = await ctx.get(VALIDATE_URL, params={"key": key})
        if response.ok:
            return ValidationResult(valid=True)

        info = _error_info(response.json_or_none())
        reason = info.get("reason")

        if reason == _REASON_KEY_INVALID:
            return ValidationResult(
                valid=False, note="Google rejected this key as invalid"
            )

        if isinstance(reason, str) and reason in _RESTRICTION_REASONS:
            return ValidationResult(
                valid=True,
                note=(
                    f"The key is live but this request was blocked by "
                    f"{_RESTRICTION_REASONS[reason]}. Such restrictions are "
                    "often bypassable, so treat the capability map below as a "
                    "lower bound"
                ),
            )

        if reason == _REASON_SERVICE_DISABLED:
            project = _project(info)
            return ValidationResult(
                valid=True,
                identity=Identity(account=project) if project else None,
                note=(
                    "The key is live; the Generative Language API is not "
                    "enabled on its project"
                ),
            )

        if isinstance(reason, str) and reason:
            return ValidationResult(
                valid=True,
                note=f"The key is live; Google refused this request ({reason})",
            )

        return ValidationResult(
            valid=False,
            note=(
                "Google's response could not be interpreted, so this key's "
                "validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every endpoint concurrently; keep the ones that answered."""
        responses = await ctx.gather(
            [
                ctx.get(probe.url, params={**probe.params, "key": key})
                for probe in PROBES
            ]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=AccessLevel.READ,
                detail=probe.detail,
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                incurs_cost=probe.incurs_cost,
                poc=f"curl -s '{response.url}'",
                resource_ref=probe.source,
            )
            for probe, response in zip(PROBES, responses, strict=True)
            if _succeeded(probe, response)
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)
