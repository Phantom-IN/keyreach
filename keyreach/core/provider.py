"""The provider plugin contract.

Every provider keyreach supports is a subclass of :class:`Provider` implementing
three methods — ``detect``, ``validate``, ``enumerate`` — plus metadata. That is
the whole contract (``implementation_plan.md`` §4). Adding a provider should be
roughly a thirty-minute contribution, and the surface is deliberately small to
keep it that way.

**Plugins declare probes; the engine executes them.** A provider never opens a
socket. All HTTP goes through the :class:`ProbeContext` it is handed, which is
where rate limiting, record/replay, redaction and the read-only guard live
(``implementation_plan.md`` §6). Concentrating I/O in one place is what makes
determinism enforceable at all — a plugin that reached the network directly
would bypass every one of those guarantees at once. Ruff rejects a direct
``httpx``/``requests``/``socket`` import at lint time, and the
``network_isolation`` CI check (roadmap R0.9) rejects it again in CI.

``detect`` must additionally be **pure**: same key in, same confidence out, with
no I/O and no clock. Detection ordering feeds directly into which provider gets
probed, so a nondeterministic ``detect`` would make the whole run irreproducible.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from keyreach.core.models import Capability, ValidationResult


@runtime_checkable
class ProbeContext(Protocol):
    """The sanctioned, recordable HTTP surface handed to a provider.

    **Placeholder until roadmap R0.6.** The concrete implementation — a
    rate-limited, recordable, redacting, read-only-guarded client — lands with
    the engine in ``keyreach/core/http.py`` (``implementation_plan.md`` §6),
    which is the item that owns the design of ``get``/``post`` and the response
    type they return.

    It is declared here, empty, rather than left as an untyped parameter so that
    the plugin contract reads correctly today and R0.6 can fill in the surface
    without changing a single provider signature. Being structurally empty, it
    currently accepts any object; that is a known and temporary gap, not a
    statement that providers may pass anything.
    """


class Provider(ABC):
    """Base class for a provider plugin.

    Subclasses set the metadata attributes and implement the three methods.
    :class:`~keyreach.core.registry.ProviderRegistry` discovers them, validates
    the metadata, and loads them in a stable order.

    Deliberately an ABC: a plugin that forgets ``enumerate`` should fail when it
    is registered, not halfway through probing somebody's production API.
    """

    #: Stable, lowercase provider identifier — "google", "openai", "aws".
    #: Doubles as the registry key and the value accepted by ``--provider``,
    #: so renaming one is a breaking change to the CLI.
    name: str

    #: Category from ``plan.md`` §8: "cloud", "ai", "payment", "comms",
    #: "email", "devtools", "database", "monitoring", "auth", "generic".
    #: Reported to the user and used to measure v0.1 coverage breadth.
    category: str

    #: Provider's API documentation, cited in the report.
    docs_url: str

    #: Provider's key rotation/revocation guide. Included in the report's
    #: remediation section, which is the first thing a recipient needs.
    rotation_guide_url: str | None = None

    #: Upstream project this plugin derives from, if any (for example
    #: "gmapsapiscanner" for the Google plugin). Set this whenever prior art
    #: informed the endpoint list, and add the matching entry to CREDITS.md —
    #: attribution is a hard rule, not a courtesy (plan.md §5).
    credit: str | None = None

    @abstractmethod
    def detect(self, key: str) -> float:
        """Confidence between 0.0 and 1.0 that ``key`` belongs to this provider.

        **Must be pure**: no network, no filesystem, no clock, no randomness.
        Structural evidence only — a distinctive prefix, length, charset, or
        checksum.

        Return ``0.0`` for "definitely not mine" rather than a small nonzero
        value; the registry treats any positive confidence as a candidate worth
        probing, and probing the wrong provider is wasted authentication traffic
        against somebody's production service.

        Ambiguity between providers sharing a prefix is resolved later, at the
        enumerate stage, not by inflating confidence here
        (``implementation_plan.md`` §5).
        """

    @abstractmethod
    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """Run the cheapest read-only liveness and identity check.

        One request where possible. This is the call that decides whether a key
        is live at all, so it should be the least intrusive endpoint the
        provider offers that still proves authentication.
        """

    @abstractmethod
    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Map what the key reaches, using read-only probes only.

        Return a stably-sorted list — sort by
        :attr:`~keyreach.core.models.Capability.sort_key`. Probes run
        concurrently, so arrival order is not reproducible.

        Set ``data_sensitive`` and ``incurs_cost`` accurately on every
        capability. They drive the High and Critical severity bands
        (``plan.md`` §6), and getting them wrong misreports real impact in both
        directions.

        Keep the probe count minimal. Every probe is authentication traffic and
        a log entry on somebody's production service (``plan.md`` §11).
        """

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} category={self.category!r}>"
