"""Pipeline orchestration: detect → validate → enumerate → score.

The engine is where the stages meet. It owns the two things a single stage
cannot: the lifetime of the HTTP client, and the ordering guarantees that make a
run reproducible (``implementation_plan.md`` §6).

Reporting is not here yet — it arrives with ``report/render.py`` in roadmap
R0.8. What the engine produces today is an :class:`EngineResult`: what the key
is, whether it is live, what it reaches, and the band that reachable set
justifies.

**Ordering.** Providers are tried in detection-confidence order, ties broken by
name. Capabilities are re-sorted before they leave the engine, because probes
complete concurrently and arrival order is not reproducible. Nothing downstream
has to remember to sort.

**Failure.** A provider that raises does not abort the run. keyreach probes live
third-party APIs; one endpoint returning something unparseable should degrade
that provider's result, not discard the evidence already gathered from others.
Errors are collected onto the result so the report can say what was not
determined, rather than silently presenting a partial capability map as
complete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field

# `scoring` is imported as a module, not `from ... import score`:
# `EngineResult.score` is a property of the same name, and a bare `score(...)`
# inside it would read as recursion to anyone skimming the file, even though
# Python resolves it to the module global.
from keyreach.core import scoring
from keyreach.core.detect import DetectionMatch, Detector, default_detector
from keyreach.core.http import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeError,
    RecordMode,
    Redactor,
    mask_key,
)
from keyreach.core.models import Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, default_registry

if TYPE_CHECKING:
    from keyreach.core.provider import Provider


class ProviderOutcome(BaseModel):
    """What one provider concluded about a key."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str = Field(description="Provider name.")
    category: str = Field(description="Provider category.")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence.")
    # Copied off the plugin here rather than looked up again at report time, so
    # a report can be rendered from an EngineResult alone — including one
    # deserialized from a file, where the registry is not in play.
    docs_url: str | None = Field(
        default=None, description="Provider's API documentation."
    )
    rotation_guide_url: str | None = Field(
        default=None, description="Provider's key rotation documentation."
    )
    validation: ValidationResult = Field(description="Liveness and identity.")
    capabilities: tuple[Capability, ...] = Field(
        default=(), description="Confirmed capabilities, stably sorted."
    )
    errors: tuple[str, ...] = Field(
        default=(),
        description=(
            "Probe failures, masked. Present so a report can distinguish "
            "'no capability' from 'could not determine'."
        ),
    )

    @property
    def sort_key(self) -> tuple[float, str]:
        return (-self.confidence, self.provider)


class EngineResult(BaseModel):
    """Everything one key run produced.

    Not a report — reporting is R0.8. This is the evidence a report will be
    rendered from, plus enough context to explain a run that found nothing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_fingerprint: str = Field(description="Masked key. Never the raw secret.")
    detections: tuple[DetectionMatch, ...] = Field(
        default=(), description="Detection candidates, most confident first."
    )
    outcomes: tuple[ProviderOutcome, ...] = Field(
        default=(), description="Per-provider results, most confident first."
    )
    notes: tuple[str, ...] = Field(
        default=(),
        description="Why a run produced nothing, when it produced nothing.",
    )

    @property
    def valid(self) -> bool:
        """Did any provider confirm the key is live?"""
        return any(outcome.validation.valid for outcome in self.outcomes)

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        """Every confirmed capability across providers, stably sorted."""
        merged = [
            capability
            for outcome in self.outcomes
            for capability in outcome.capabilities
        ]
        return tuple(sorted(merged, key=lambda capability: capability.sort_key))

    @property
    def score(self) -> scoring.ScoreResult:
        """Severity and rationale for the merged capability set.

        A property rather than a stored field: scoring is pure, so recomputing
        it can never disagree with the capabilities it is derived from, and a
        stored band could be left stale by a caller constructing an
        ``EngineResult`` by hand in a test.
        """
        return scoring.score(self.capabilities)


#: Providers probed for one key, at most. Detection can legitimately return
#: several candidates for an ambiguous prefix, but probing every one of them
#: means authentication traffic against services the key almost certainly does
#: not belong to (``plan.md`` §11).
MAX_PROVIDERS_PROBED: Final = 3


class Engine:
    """Runs the pipeline for one key at a time."""

    def __init__(  # noqa: PLR0913 - keyword-only run configuration, each
        # flag mapping to a documented CLI option in implementation_plan.md §12
        self,
        *,
        registry: ProviderRegistry | None = None,
        detector: Detector | None = None,
        delay: float = 0.0,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        unmask: bool = False,
        cassette: Cassette | None = None,
        mode: RecordMode = RecordMode.OFF,
        enumerate_capabilities: bool = True,
        max_providers: int = MAX_PROVIDERS_PROBED,
    ) -> None:
        self.registry = registry if registry is not None else default_registry
        self.detector = detector if detector is not None else default_detector
        self.delay = delay
        self.timeout = timeout
        self.concurrency = concurrency
        self.unmask = unmask
        self.cassette = cassette
        self.mode = mode
        #: Mirrors `--no-enumerate` (R1.5): validity and identity only.
        self.enumerate_capabilities = enumerate_capabilities
        self.max_providers = max_providers

    async def run(self, key: str) -> EngineResult:
        """Detect, validate and enumerate a single key."""
        fingerprint = key if self.unmask else mask_key(key)
        detections = self.detector.detect(key)

        candidates = self._candidates(detections)
        if not candidates:
            return EngineResult(
                key_fingerprint=fingerprint,
                detections=detections,
                notes=(self._no_candidate_note(detections),),
            )

        redactor = Redactor([key], unmask=self.unmask)
        client = ProbeClient(
            redactor=redactor,
            delay=self.delay,
            timeout=self.timeout,
            concurrency=self.concurrency,
            cassette=self.cassette,
            mode=self.mode,
        )

        outcomes: list[ProviderOutcome] = []
        async with client:
            context = ProbeContext(client, key)
            for provider, confidence in candidates:
                outcomes.append(await self._probe(provider, confidence, key, context))

        return EngineResult(
            key_fingerprint=fingerprint,
            detections=detections,
            outcomes=tuple(sorted(outcomes, key=lambda outcome: outcome.sort_key)),
        )

    def _candidates(
        self, detections: tuple[DetectionMatch, ...]
    ) -> list[tuple[Provider, float]]:
        """Resolve detection matches to registered providers, in probe order.

        A detection whose provider has no plugin yet is skipped rather than
        raising: the rule set deliberately runs ahead of the plugins, and
        recognising a key keyreach cannot enumerate is still worth reporting.
        """
        candidates: list[tuple[Provider, float]] = []
        seen: set[str] = set()
        for match in detections:
            if match.provider is None or match.provider in seen:
                continue
            seen.add(match.provider)
            try:
                provider = self.registry.get(match.provider)
            except KeyError:
                continue
            candidates.append((provider, match.confidence))
            if len(candidates) >= self.max_providers:
                break
        return candidates

    @staticmethod
    def _no_candidate_note(detections: tuple[DetectionMatch, ...]) -> str:
        if not detections:
            return (
                "No known key format matched, and the value does not look like "
                "a credential. Nothing was probed."
            )
        named = sorted({m.provider for m in detections if m.provider is not None})
        if not named:
            return (
                "The value looks like a secret but matches no known key format, "
                "so keyreach cannot tell which provider to ask. Nothing was "
                "probed."
            )
        return (
            "Detected as "
            + ", ".join(named)
            + ", but no provider plugin is installed for it yet. Nothing was "
            "probed."
        )

    async def _probe(
        self,
        provider: Provider,
        confidence: float,
        key: str,
        context: ProbeContext,
    ) -> ProviderOutcome:
        """Validate, then enumerate. Never raises."""
        errors: list[str] = []

        try:
            validation = await provider.validate(key, context)
        except ProbeError as exc:
            return ProviderOutcome(
                provider=provider.name,
                category=provider.category,
                confidence=confidence,
                docs_url=provider.docs_url,
                rotation_guide_url=provider.rotation_guide_url,
                validation=ValidationResult(
                    valid=False, note="validation could not be completed"
                ),
                errors=(context.mask(f"validate failed: {exc}"),),
            )

        capabilities: tuple[Capability, ...] = ()
        if validation.valid and self.enumerate_capabilities:
            try:
                found = await provider.enumerate(key, context)
                # Sorted here as well as in Report: the engine's own output is
                # consumed before a report exists, and a caller should never
                # have to know which layer guarantees the order.
                capabilities = tuple(
                    sorted(found, key=lambda capability: capability.sort_key)
                )
            except ProbeError as exc:
                errors.append(context.mask(f"enumerate failed: {exc}"))

        return ProviderOutcome(
            provider=provider.name,
            category=provider.category,
            confidence=confidence,
            docs_url=provider.docs_url,
            rotation_guide_url=provider.rotation_guide_url,
            validation=validation,
            capabilities=capabilities,
            errors=tuple(errors),
        )
