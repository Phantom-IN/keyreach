"""The declarative probe runner (roadmap R2.8).

``implementation_plan.md`` §8 named this the genuine shared abstraction behind
every hand-written plugin, and named it in an unusual way: not by looking at
the code and generalising it, but by predicting it in R1.4 and then watching
seven providers in a row (R2.1-R2.7) confirm the prediction by needing nothing
from ``keyreach/core/``. What those seven *do* share, looked at side by side —
npm, Pinecone, and a dozen others besides — is one request shape repeated with
different vendor nouns: authenticate with a header built from the key, GET a
handful of read-only endpoints, decide liveness from the status code the
cheapest one returns, and turn each 2xx into a :class:`~keyreach.core.models.Capability`
with a masked ``curl`` reproduction. A :class:`ProviderSpec` says that once, as
data; :class:`YamlProvider` is the engine that plays it back.

**What stays in Python.** ``implementation_plan.md`` §8 draws the line at
"complex logic — chained calls, identity parsing"; this runner draws it the
same place. There is no identity extraction here (compare Telegram's ``getMe``
parsing or Supabase's JWT decode), no multi-step auth exchange (compare
PayPal's client-credentials grant), and no per-response branching beyond a
fixed liveness state machine. A provider that needs any of those stays a
Python plugin — this format is for the shape most providers actually have, not
for all of them.

**The liveness state machine is the one piece of "logic" here, and it is
declarative because it is data, not control flow.** Reading npm's and
Pinecone's plugins side by side (both R2.4/R2.5) shows the same four-way
branch on a status code — 2xx is live, a configured "not accepted" set is
dead, a configured "refused but live" set means the key works but this
endpoint said no, a configured rate-limit set means try again — with only the
status codes in each bucket and the note text differing per vendor. That is
exactly what :class:`_LivenessSpec` declares.

**Deliberately GET-only.** Every ``read_only_post`` provider so far (PayPal,
Zoom, Docker Hub, MongoDB Atlas, New Relic) needed it for a *different* reason
each time — an OAuth exchange, a GraphQL-only read — which is precisely the
kind of provider-specific argument ``read_only`` (``tools/guardrails/``) wants
made in review, not declared in a YAML file nobody reviews line by line for
that. A provider that needs POST is a Python provider.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from keyreach.core.http import ProbeResponse

#: Provider spec files shipped inside the package, alongside the Python
#: plugins. Matched the same way `.py` modules are: sorted, and a leading
#: underscore marks a shared fragment rather than a plugin.
SPEC_SUFFIXES: Final = (".yml", ".yaml")

#: Longer than this and a plain-text body is a page, not a message. Mirrors
#: the constant Pinecone's hand-written plugin used before migrating.
_MAX_PLAIN_MESSAGE: Final = 200


class ProbeSpecError(Exception):
    """A declarative provider file could not be loaded or is invalid."""


# --------------------------------------------------------------------------
# The spec
# --------------------------------------------------------------------------


class _DetectSpec(BaseModel):
    """Structural detection, mirroring a `detection_rules.yml` entry.

    Kept here too, rather than only in the shared rule file, because
    `Provider.detect` must work standalone — the contract suite calls it
    directly, and `--provider` bypasses the rule file entirely.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str = Field(min_length=1, description="Anchored regular expression.")
    confidence: float = Field(gt=0.0, le=1.0)


class _AuthSpec(BaseModel):
    """Static headers sent with every request, with ``{key}`` substituted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    headers: dict[str, str] = Field(min_length=1)


class _LivenessNotes(BaseModel):
    """The four outcomes a status code resolves to, as note templates.

    Each template may contain ``{message_suffix}``, which the runner fills
    with either ``""`` or ``" (<vendor message>)"`` — the same
    ``+ (f" ({message})" if message else "")`` idiom every hand-written
    plugin used before migrating.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    unauthorized: str = Field(min_length=1)
    live_but_refused: str = ""
    rate_limited: str = Field(min_length=1)
    unparseable: str = Field(min_length=1)


class _LivenessSpec(BaseModel):
    """How to decide liveness from one probe's response status.

    ``probe`` names an entry in :attr:`ProviderSpec.probes` that doubles as
    the liveness check — every migrated provider reuses a capability probe
    for this rather than spending a second request, continuing the practice
    R1.4 made mandatory by caching identical requests.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe: str = Field(min_length=1)
    unauthorized_statuses: tuple[int, ...] = (401,)
    live_but_refused_statuses: tuple[int, ...] = ()
    rate_limited_statuses: tuple[int, ...] = (429,)
    notes: _LivenessNotes

    @model_validator(mode="after")
    def _statuses_and_notes_agree(self) -> _LivenessSpec:
        if self.live_but_refused_statuses and not self.notes.live_but_refused:
            msg = (
                "live_but_refused_statuses is set but notes.live_but_refused "
                "is empty"
            )
            raise ValueError(msg)

        buckets = {
            "unauthorized_statuses": self.unauthorized_statuses,
            "live_but_refused_statuses": self.live_but_refused_statuses,
            "rate_limited_statuses": self.rate_limited_statuses,
        }
        seen: dict[int, str] = {}
        for bucket_name, statuses in buckets.items():
            for status in statuses:
                if status in seen:
                    msg = (
                        f"status {status} appears in both {seen[status]!r} and "
                        f"{bucket_name!r} — a response can only mean one thing"
                    )
                    raise ValueError(msg)
                seen[status] = bucket_name

        return self


class ProbeEndpoint(BaseModel):
    """One read-only capability probe — the YAML equivalent of the `_Probe`
    row every hand-written plugin declared through R2.7.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str = Field(min_length=1)
    url: str = Field(min_length=1)
    collection: str | None = Field(
        default=None,
        description=(
            "Response field holding the list, for the evidence count. Unset "
            "means the response body itself is the list."
        ),
    )
    noun: str = Field(min_length=1, description="What the response lists.")
    detail: str = Field(min_length=1)
    access: AccessLevel
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    incurs_cost: bool = False
    source: str = Field(min_length=1, description="Vendor documentation URL.")

    @model_validator(mode="after")
    def _source_is_a_url(self) -> ProbeEndpoint:
        if not self.source.startswith("https://"):
            msg = f"source must start with https://, got {self.source!r}"
            raise ValueError(msg)
        return self


class ProviderSpec(BaseModel):
    """A whole provider, declared as data (roadmap R2.8).

    The declarative counterpart of a hand-written plugin module: metadata,
    the reasoning behind it (``description``, playing the role a module
    docstring plays for a Python plugin), the detection pattern, the auth
    headers, and the probe table.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    category: str = Field(min_length=1)
    docs_url: str = Field(min_length=1)
    rotation_guide_url: str = Field(min_length=1)
    credit: str | None = None
    detectable: bool = True
    description: str = Field(min_length=1)
    detect: _DetectSpec | None = None
    auth: _AuthSpec
    error_fields: tuple[str, ...] = ()
    plain_text_fallback: bool = False
    scope_statement: str | None = None
    liveness: _LivenessSpec
    probes: tuple[ProbeEndpoint, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _detect_agrees_with_detectable(self) -> ProviderSpec:
        if self.detectable and self.detect is None:
            msg = "detectable providers must declare a `detect` pattern"
            raise ValueError(msg)
        if not self.detectable and self.detect is not None:
            msg = "a `detect` pattern is meaningless when detectable is false"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _probes_are_uniquely_named(self) -> ProviderSpec:
        services = [probe.service for probe in self.probes]
        if len(services) != len(set(services)):
            msg = f"probe services must be unique: {services}"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _liveness_probe_exists(self) -> ProviderSpec:
        services = {probe.service for probe in self.probes}
        if self.liveness.probe not in services:
            msg = (
                f"liveness.probe {self.liveness.probe!r} is not one of the "
                f"declared probes: {sorted(services)}"
            )
            raise ValueError(msg)
        return self


@lru_cache(maxsize=128)
def _compiled(pattern: str) -> re.Pattern[str]:
    """Compile and cache a spec's detection pattern.

    Cached for the same reason `detect.py`'s rule patterns are: `detect` is
    called by the registry's ranking pass for every provider, every key.
    """
    try:
        return re.compile(pattern)
    except re.error as exc:
        msg = f"invalid detect pattern {pattern!r}: {exc}"
        raise ProbeSpecError(msg) from exc


def load_provider_spec(path: Path) -> ProviderSpec:
    """Parse and validate one provider spec file.

    Raises :class:`ProbeSpecError` for anything a plugin author could get
    wrong — unreadable file, invalid YAML, a shape the spec rejects — so the
    registry can report which file is broken rather than a bare traceback.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"could not read provider spec {path}: {exc}"
        raise ProbeSpecError(msg) from exc

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"{path} is not valid YAML: {exc}"
        raise ProbeSpecError(msg) from exc

    if not isinstance(document, dict):
        msg = f"{path} must be a mapping"
        raise ProbeSpecError(msg)

    try:
        spec = ProviderSpec.model_validate(document)
    except ValidationError as exc:
        msg = f"{path} does not satisfy the provider spec: {exc}"
        raise ProbeSpecError(msg) from exc

    if spec.detect is not None:
        _compiled(spec.detect.pattern)

    return spec


# --------------------------------------------------------------------------
# Response interpretation — shared by validate() and enumerate()
# --------------------------------------------------------------------------


def _payload(response: ProbeResponse) -> dict[str, Any]:
    """The parsed response body when it is an object, or an empty mapping.

    Written defensively, as every hand-written plugin's equivalent was: this
    parses a third-party payload, and a proxy's HTML error page must degrade
    to "no structured body" rather than raise mid-probe.
    """
    body = response.json_or_none()
    return body if isinstance(body, dict) else {}


def _dotted(payload: dict[str, Any], path: str) -> Any:
    """Walk a dotted field path (``"error.message"``) through a JSON object."""
    value: Any = payload
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _message_of(spec: ProviderSpec, response: ProbeResponse) -> str:
    """The vendor's error message, trying each configured field in order.

    Falls back to the raw body only when ``plain_text_fallback`` is set —
    Pinecone answers a rejected key with bare, unwrapped text, and this is
    the one case among the migrated providers that needs it. A short,
    single-line body is a message; anything longer or multi-line is a page.
    """
    payload = _payload(response)
    for path in spec.error_fields:
        value = _dotted(payload, path)
        if isinstance(value, str):
            return value

    if not spec.plain_text_fallback:
        return ""

    text = response.text.strip()
    if text and "\n" not in text and len(text) <= _MAX_PLAIN_MESSAGE:
        return text
    return ""


def _summary(probe: ProbeEndpoint, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it."""
    items = (
        response.json_or_none()
        if probe.collection is None
        else _payload(response).get(probe.collection)
    )
    if not isinstance(items, list):
        return "request accepted"
    if not items:
        return f"{probe.noun}: none present"
    return f"{probe.noun}: {len(items)} listed"


def _detail(spec: ProviderSpec, probe: ProbeEndpoint) -> str:
    if spec.scope_statement:
        return f"{probe.detail}. {spec.scope_statement}"
    return probe.detail


# --------------------------------------------------------------------------
# The provider
# --------------------------------------------------------------------------


class YamlProvider(Provider):
    """A :class:`Provider` played back from a :class:`ProviderSpec`.

    Every method here is the runner: the reasoning behind any one probe lives
    in the spec's ``description`` and per-probe ``detail`` fields, not in this
    class, exactly as a hand-written plugin's reasoning lives in its module
    docstring rather than in ``core/provider.py``.
    """

    def __init__(self, spec: ProviderSpec, source_path: Path) -> None:
        self.spec = spec
        #: The file this provider was loaded from — a YAML provider's
        #: equivalent of a Python plugin's module file, and where the
        #: contract suite (`tests/test_provider_contract.py`) reads its
        #: "own source" from.
        self.source_path = source_path
        self.name = spec.name
        self.category = spec.category
        self.docs_url = spec.docs_url
        self.rotation_guide_url = spec.rotation_guide_url
        self.credit = spec.credit
        self.detectable = spec.detectable

    def __repr__(self) -> str:
        return (
            f"<YamlProvider name={self.name!r} category={self.category!r} "
            f"source={self.source_path.name!r}>"
        )

    def detect(self, key: str) -> float:
        if self.spec.detect is None:
            return 0.0
        return (
            self.spec.detect.confidence
            if _compiled(self.spec.detect.pattern).match(key)
            else 0.0
        )

    def _headers(self, key: str) -> dict[str, str]:
        return {
            name: value.format(key=key)
            for name, value in self.spec.auth.headers.items()
        }

    def _probe(self, service: str) -> ProbeEndpoint:
        return next(probe for probe in self.spec.probes if probe.service == service)

    def _poc(self, ctx: ProbeContext, url: str) -> str:
        """A masked, copy-pasteable, read-only reproduction of one probe."""
        headers = self._headers(ctx.key)
        flags = " ".join(f"-H '{name}: {value}'" for name, value in headers.items())
        return ctx.mask(f"curl -s {flags} '{url}'")

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Run the liveness probe and classify the response by status code.

        The classification is the declarative state machine
        :class:`_LivenessSpec` describes: 2xx is live; a configured
        "unauthorized" status is dead; a configured "live but refused" status
        means the key works and this endpoint said no; a configured
        "rate limited" status means the key reached the vendor at all; and
        anything else could not be interpreted.
        """
        probe = self._probe(self.spec.liveness.probe)
        response = await ctx.get(probe.url, headers=self._headers(key))
        message = _message_of(self.spec, response)
        message_suffix = f" ({message})" if message else ""
        notes = self.spec.liveness.notes

        if response.ok:
            return ValidationResult(valid=True)

        if response.status_code in self.spec.liveness.rate_limited_statuses:
            return ValidationResult(
                valid=True,
                note=notes.rate_limited.format(message_suffix=message_suffix),
            )

        if response.status_code in self.spec.liveness.live_but_refused_statuses:
            return ValidationResult(
                valid=True,
                note=notes.live_but_refused.format(message_suffix=message_suffix),
            )

        if response.status_code in self.spec.liveness.unauthorized_statuses:
            return ValidationResult(
                valid=False,
                note=notes.unauthorized.format(message_suffix=message_suffix),
            )

        return ValidationResult(
            valid=False,
            note=notes.unparseable.format(message_suffix=message_suffix),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe every declared endpoint concurrently; keep the ones that answered."""
        headers = self._headers(key)
        responses = await ctx.gather(
            [ctx.get(probe.url, headers=headers) for probe in self.spec.probes]
        )

        capabilities = [
            Capability(
                service=probe.service,
                access=probe.access,
                detail=_detail(self.spec, probe),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                incurs_cost=probe.incurs_cost,
                poc=self._poc(ctx, response.url),
                resource_ref=probe.source,
            )
            for probe, response in zip(self.spec.probes, responses, strict=True)
            if response.ok
        ]
        return sorted(capabilities, key=lambda capability: capability.sort_key)


def load_yaml_provider(path: Path) -> YamlProvider:
    """Load one provider spec file into a ready-to-register plugin."""
    return YamlProvider(load_provider_spec(path), path)
