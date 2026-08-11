"""The typed data that flows through the keyreach pipeline.

These models are the contract between the stages
(``detect → validate → enumerate → score → report``) and, via the generated
``report.schema.json``, keyreach's contract with anything consuming ``--json``.
Interfaces come from ``implementation_plan.md`` §4; ``Report``'s contents come
from ``plan.md`` §7.

Three properties are enforced here rather than left to convention:

* **Immutability.** Every model is frozen. A ``Capability`` that scoring has
  already weighed must not be edited afterwards, or the rationale in the report
  stops matching the evidence beside it.
* **Closed schemas.** ``extra="forbid"`` everywhere, so a typo'd field in a
  provider plugin or a YAML probe fails loudly instead of vanishing.
* **No naive timestamps.** ``Report.generated_at`` must be timezone-aware. A
  naive datetime renders differently depending on where it is run, which breaks
  the byte-identical guarantee in ``plan.md`` §1.

Nothing here reads the clock, the network, or the filesystem. ``generated_at``
is injected by the engine (``implementation_plan.md`` §9) precisely so tests can
pin it and golden files stay stable.

**On docstrings and the published schema:** the descriptions that reach
``report.schema.json`` come from ``_config(...)`` and ``Field(description=...)``,
never from these docstrings. External consumers should not receive internal
design rationale or ``plan.md`` cross-references, and decoupling the two means
rewording a docstring cannot trigger a spurious schema-drift failure.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Bumped when the report structure changes in a way that could break a consumer
# parsing `--json`. The generated report.schema.json pins it, and the schema
# drift check (roadmap R0.9) fails any PR that changes the shape without
# regenerating the schema.
#
# Declared as a Literal so the value is pinned in the type system, not just at
# runtime: `Report.schema_version` is typed `SchemaVersion`, so a bump has to be
# made here and nowhere else, and any mismatch is a type error rather than a
# report that quietly claims the wrong contract version.
SchemaVersion = Literal["1.0"]
SCHEMA_VERSION: SchemaVersion = "1.0"

#: A short, non-empty string. Used for the fields a report is unreadable
#: without — an empty `service` or `detail` produces a finding nobody can act on.
NonEmptyStr = Annotated[str, Field(min_length=1)]


def _config(description: str) -> ConfigDict:
    """Shared model configuration, with the schema description supplied per model.

    ``frozen`` for immutability, ``extra="forbid"`` so unknown fields are an
    error rather than silently dropped, and an explicit ``description`` that
    overrides the class docstring in the generated JSON Schema.
    """
    return ConfigDict(
        frozen=True,
        extra="forbid",
        json_schema_extra={"description": description},
    )


# Docstrings on the two enums below are deliberately short: pydantic copies an
# enum's docstring straight into the published schema, and unlike the models
# there is no per-enum override hook. The design rationale therefore lives in
# comments like this one rather than in the docstring.
#
# On AccessLevel.UNKNOWN — it is a first-class answer, not a failure. When no
# rule can decide a capability, keyreach says so rather than guessing; that is
# the whole point of banning model-assisted classification (plan.md §1). Read it
# as "not determined", never as "probably harmless".


class AccessLevel(StrEnum):
    """How much a key can do against one service. UNKNOWN means undetermined."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    UNKNOWN = "unknown"


# On Severity — never assigned per provider by name. Always derived from the
# capabilities keyreach actually confirmed, and always shipped with the
# rationale that produced it (plan.md §6).


class Severity(StrEnum):
    """Computed severity band, from the confirmed capabilities alone."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in the band ordering, ``info`` (0) through ``critical`` (4).

        Defined on the type rather than in the CLI so that ``--fail-on high``
        (roadmap R1.5) and any future comparison share one ordering. Relying on
        declaration order instead would make a reordering silently change exit
        codes.
        """
        return _SEVERITY_RANK[self]

    # Comparison is overridden because `StrEnum` would otherwise inherit str's
    # lexicographic ordering, under which `Severity.HIGH > Severity.CRITICAL`
    # is True — "high" sorts after "critical". Left alone, the obvious way to
    # write `--fail-on` in R1.5 (`severity >= threshold`) would return the wrong
    # answer and produce the wrong exit code, silently and only for some bands.
    #
    # Each returns NotImplemented for non-Severity operands so Python falls back
    # to the other operand's comparison rather than raising AttributeError on a
    # missing `.rank`.

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Capability(BaseModel):
    """One confirmed thing a key can reach.

    A ``Capability`` is only ever created from a probe that actually succeeded.
    It is evidence, not speculation: ``evidence`` must contain the masked
    request and a benign response summary that *proves* the access, because that
    string is what a triager on the receiving end will check.

    ``data_sensitive``, ``incurs_cost`` and ``restricted`` matter more than
    anything else on this model — they are what push a finding into the High and
    Critical bands, and what pulls one back down (``plan.md`` §6, and
    ``core/scoring.py`` for the exact rules). Getting them wrong misreports
    real-world impact in both directions.
    """

    model_config = _config(
        "A single confirmed capability: one service the key can reach, at a "
        "known access level, with evidence proving it."
    )

    service: NonEmptyStr = Field(
        description="Reachable service, e.g. 'Gemini Files API', 'S3', 'Stripe Charges'.",
    )
    access: AccessLevel = Field(
        description="Confirmed access level. UNKNOWN when no rule could decide.",
    )
    detail: NonEmptyStr = Field(
        description="What the key can do here, e.g. 'Can list uploaded files'.",
    )
    evidence: NonEmptyStr = Field(
        description=(
            "Masked request plus a benign response summary proving the access. "
            "Never contains an unmasked key unless --unmask was passed."
        ),
    )
    risk_weight: int = Field(
        ge=0,
        le=100,
        description="Plugin-declared base risk for this capability, 0-100.",
    )
    data_sensitive: bool = Field(
        default=False,
        description="Reaches private or user data (records, files, messages, PII)?",
    )
    incurs_cost: bool = Field(
        default=False,
        description="Can spend money or send communications (inference, cloud, SMS)?",
    )
    restricted: bool = Field(
        default=False,
        description=(
            "Did a referrer, IP or app restriction appear to block real use of "
            "this capability? Lowers severity when it holds for every "
            "capability, since such restrictions are often bypassable."
        ),
    )
    resource_ref: str | None = Field(
        default=None,
        description="Specific resource this capability reaches, if identified.",
    )
    poc: str | None = Field(
        default=None,
        description="Safe, read-only proof-of-concept command for the report.",
    )

    @property
    def sort_key(self) -> tuple[str, str, str]:
        """Stable ordering key for capability lists.

        Ordering lives here so every call site sorts identically. Sorting by
        ``service`` alone is not enough — a provider can return several
        capabilities for one service, and their relative order would then depend
        on probe completion order, which is concurrent and therefore not
        reproducible (``implementation_plan.md`` §6).
        """
        return (self.service, self.access.value, self.detail)


class Identity(BaseModel):
    """Who a key belongs to, as far as the provider will say.

    Every field is optional because providers differ wildly in what they
    disclose to an unprivileged read call — and a key being live is a finding
    even when the provider says nothing about its owner.
    """

    model_config = _config(
        "Account identity behind the key, as far as the provider discloses it. "
        "Every field is optional."
    )

    account: str | None = Field(
        default=None, description="Account, organisation, or project identifier."
    )
    owner: str | None = Field(
        default=None, description="Owning user or team, where exposed."
    )
    plan_or_tier: str | None = Field(
        default=None,
        description="Billing plan or tier, which often bounds the blast radius.",
    )
    extra: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Provider-specific identity details. Values are strings so the "
            "report renders and serializes deterministically; convert at the "
            "provider boundary rather than storing mixed types here."
        ),
    )


class ValidationResult(BaseModel):
    """The outcome of the cheapest read-only liveness and identity check."""

    model_config = _config(
        "Outcome of the liveness check: whether the provider accepted the key, "
        "and any identity it disclosed."
    )

    valid: bool = Field(description="Did the provider accept this key?")
    identity: Identity | None = Field(
        default=None, description="Identity, when the validation call exposed one."
    )
    note: str = Field(
        default="",
        description=(
            "Human-readable qualifier — why a key was rejected, or which "
            "restriction (referrer/IP/app) appears to be in force."
        ),
    )


class Report(BaseModel):
    """A self-contained, deterministic finding — the tool's actual output.

    Field order follows the nine required contents in ``plan.md`` §7. Re-running
    the same key against the same provider state reproduces this byte for byte,
    with ``generated_at`` the single exception, which is why it is injected by
    the engine instead of read from the clock here.
    """

    model_config = _config(
        "A keyreach finding: what an exposed API key can reach, its computed "
        "severity, the evidence behind each capability, and how to remediate."
    )

    # 9 — attribution footer, first in the payload so consumers can branch on
    # the schema version before parsing anything else.
    schema_version: SchemaVersion = Field(
        default=SCHEMA_VERSION,
        description="Report schema version. Bumped on any breaking shape change.",
    )
    tool: Literal["keyreach"] = Field(
        default="keyreach", description="Producing tool, for reproducibility."
    )
    tool_version: NonEmptyStr = Field(
        description="keyreach version that produced this."
    )

    # 3 — provider, category, detection timestamp
    provider: NonEmptyStr = Field(description="Detected provider, e.g. 'google'.")
    provider_category: NonEmptyStr = Field(
        description="Provider category, e.g. 'cloud', 'ai', 'payment', 'comms'."
    )
    generated_at: datetime = Field(
        description=(
            "When this report was produced. Timezone-aware and engine-injected; "
            "the only field that legitimately varies between identical runs."
        ),
    )

    # 2 — masked key fingerprint
    key_fingerprint: NonEmptyStr = Field(
        description=(
            "Masked key, e.g. 'AIza****************************3xY'. The full "
            "secret appears only when --unmask is passed."
        ),
    )

    # 1 — title, severity, one-line impact
    title: NonEmptyStr = Field(description="One-line finding title.")
    severity: Severity = Field(description="Computed band, never provider-assigned.")
    impact: NonEmptyStr = Field(description="One-line statement of real-world impact.")

    # 6 — severity rationale
    severity_rationale: list[str] = Field(
        default_factory=list,
        description=(
            "The specific confirmed capabilities that produced the band. This "
            "is the bounty argument, and what lets a triager verify the claim."
        ),
    )

    # 4 — validity and identity
    validation: ValidationResult = Field(description="Liveness and identity outcome.")

    # 5 and 7 — capability map with per-capability evidence
    capabilities: list[Capability] = Field(
        default_factory=list,
        description="Confirmed capabilities, stably sorted by service then access.",
    )

    # 8 — remediation
    remediation: list[str] = Field(
        default_factory=list,
        description="Provider-specific rotation and restriction guidance.",
    )
    rotation_guide_url: str | None = Field(
        default=None, description="Provider's key rotation documentation."
    )
    docs_url: str | None = Field(
        default=None, description="Provider's API documentation."
    )

    @field_validator("generated_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        """Reject naive datetimes.

        A naive timestamp serializes without an offset, so the same run on two
        machines produces two different reports — exactly the nondeterminism
        ``plan.md`` §1 forbids. Failing here is much cheaper than discovering it
        in a golden-file diff.
        """
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            msg = (
                "generated_at must be timezone-aware; got a naive datetime. "
                "Use datetime.now(tz=timezone.utc) at the engine boundary."
            )
            raise ValueError(msg)
        return value

    @field_validator("capabilities")
    @classmethod
    def _require_stable_capability_order(
        cls, value: list[Capability]
    ) -> list[Capability]:
        """Sort capabilities, so a report cannot record an unstable order.

        Probes run concurrently (``implementation_plan.md`` §6), so the order
        capabilities arrive in is not reproducible. Sorting on the way into the
        report means no caller can forget to, and two runs that confirmed the
        same set always render identically.
        """
        return sorted(value, key=lambda capability: capability.sort_key)
