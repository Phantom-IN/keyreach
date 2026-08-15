"""Deterministic discovery and loading of provider plugins.

Providers are found two ways in :data:`PROVIDERS_PACKAGE`: scanning its modules
for concrete :class:`~keyreach.core.provider.Provider` subclasses, and — since
roadmap **R2.8** — scanning it for declarative spec files, each loaded into a
:class:`~keyreach.core.probes.YamlProvider` by
:func:`~keyreach.core.probes.load_yaml_provider` (``implementation_plan.md``
§3, §4, §8). Both land in the same registry, sorted together by name; nothing
downstream of discovery can tell which format a given provider came from.
Discovery is the first place nondeterminism would creep into a run, so three
rules hold throughout:

* **Module iteration is sorted before import.** ``pkgutil`` walks a package in
  filesystem order, which varies by platform and by checkout. Sorting first
  means providers are imported, and therefore registered, in the same sequence
  everywhere.
* **Results are ordered by an explicit key**, never by insertion. Providers sort
  by ``name``; detection candidates sort by descending confidence then ``name``,
  matching ``implementation_plan.md`` §5, so equally-confident providers never
  swap places between runs.
* **Spec files follow the same underscore convention `.py` modules do.** A
  leading underscore marks a shared fragment rather than a plugin, so it is
  skipped rather than loaded and validated.

Metadata is validated at registration rather than at first use. A plugin with a
missing ``name`` or an unknown ``category`` is a packaging mistake, and it should
surface when the registry loads — not once a scan is already underway against a
live key.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Final, NamedTuple

from keyreach.core.probes import SPEC_SUFFIXES, ProbeSpecError, load_yaml_provider
from keyreach.core.provider import Provider

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Package scanned for provider plugins.
PROVIDERS_PACKAGE: Final = "keyreach.providers"

#: Categories a provider may declare, from ``plan.md`` §8. Closed on purpose:
#: category drives how v0.1 coverage breadth is measured ("≥10 providers across
#: ≥4 categories"), and a typo'd category would quietly inflate that count.
VALID_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "cloud",
        "ai",
        "payment",
        "comms",
        "email",
        "devtools",
        "database",
        "monitoring",
        "auth",
        "generic",
    }
)


class RegistryError(Exception):
    """Base class for provider registry failures."""


class InvalidProviderError(RegistryError):
    """A provider's metadata or behaviour violates the plugin contract."""


class DuplicateProviderError(RegistryError):
    """Two providers claim the same name."""


class UnknownProviderError(RegistryError, KeyError):
    """No registered provider goes by the requested name."""

    def __str__(self) -> str:
        # KeyError.__str__ reprs its argument, turning a helpful message into
        # "'no provider named ...'". Bypass it — this message is user-facing,
        # since it is what `--provider typo` prints.
        return str(self.args[0]) if self.args else super().__str__()


class ProviderMatch(NamedTuple):
    """A provider that recognised a key, and how confident it was."""

    provider: Provider
    confidence: float


def validate_provider(provider: Provider, origin: str = "<provider>") -> None:
    """Reject a plugin whose metadata breaks the contract.

    Called by the registry at load time. Public because it is also the check a
    provider author wants in their own test — catching a bad ``category`` in the
    plugin's test suite is far better than catching it when the registry loads.

    ``origin`` only shapes the error message; pass something that identifies the
    plugin, such as its module path.
    """
    where = origin

    for attribute in ("name", "category", "docs_url"):
        value = getattr(provider, attribute, None)
        if not isinstance(value, str) or not value.strip():
            msg = f"{where} must set a non-empty {attribute!r}"
            raise InvalidProviderError(msg)

    if provider.name != provider.name.strip().lower():
        msg = (
            f"{where} has name {provider.name!r}; provider names must be "
            "lowercase and unpadded, because they are matched literally "
            "against --provider"
        )
        raise InvalidProviderError(msg)

    if provider.category not in VALID_CATEGORIES:
        msg = (
            f"{where} has unknown category {provider.category!r}. "
            f"Valid categories: {', '.join(sorted(VALID_CATEGORIES))}"
        )
        raise InvalidProviderError(msg)


def _checked_confidence(provider: Provider, confidence: object) -> float:
    """Validate what ``detect()`` actually returned, and narrow it to a float.

    Typed ``object`` deliberately. ``Provider.detect`` is annotated ``-> float``,
    so a type checker considers these checks redundant — but plugins are
    third-party code, and an annotation is a promise rather than a guarantee. A
    provider returning ``42.0`` would dominate every ranking; one returning
    ``True`` would silently rank as ``1.0``, since ``bool`` is an ``int`` in
    Python. Both are caught here, at the one place a plugin's return value
    crosses into the engine.
    """
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        msg = (
            f"{type(provider).__name__}.detect() returned "
            f"{confidence!r}; expected a float between 0.0 and 1.0"
        )
        raise InvalidProviderError(msg)

    if not 0.0 <= confidence <= 1.0:
        msg = (
            f"{type(provider).__name__}.detect() returned {confidence!r}, "
            "which is outside the required range 0.0-1.0"
        )
        raise InvalidProviderError(msg)

    return float(confidence)


class ProviderRegistry:
    """Loads provider plugins from a package, in a stable order.

    Discovery is lazy and cached: the first call that needs providers imports
    the package's modules, and later calls reuse the result. Importing plugin
    modules has side effects, so doing it once per registry keeps a run
    reproducible and cheap.
    """

    def __init__(self, package: str = PROVIDERS_PACKAGE) -> None:
        self._package = package
        self._providers: tuple[Provider, ...] | None = None

    def __repr__(self) -> str:
        loaded = "unloaded" if self._providers is None else f"{len(self._providers)}"
        return f"<ProviderRegistry package={self._package!r} providers={loaded}>"

    # ---------------------------------------------------------------- loading

    def providers(self) -> tuple[Provider, ...]:
        """Every registered provider, sorted by name. Cached after first call."""
        if self._providers is None:
            self._providers = self._load()
        return self._providers

    def reload(self) -> tuple[Provider, ...]:
        """Discard the cache and rediscover. Intended for tests."""
        self._providers = None
        return self.providers()

    def _load(self) -> tuple[Provider, ...]:
        discovered: dict[str, Provider] = {}

        for module in self._iter_modules():
            for provider_class in self._provider_classes(module):
                provider = provider_class()
                self._register(
                    discovered, provider, f"{module.__name__}.{provider_class.__name__}"
                )

        # YAML specs are scanned after every `.py` module, so a plugin that
        # migrates keeps the same discovery order it would have had as a
        # module — `.py` and `.yml` providers interleave by name in the
        # sorted result below, not by which format they happen to be.
        for path in self._iter_spec_paths():
            try:
                provider = load_yaml_provider(path)
            except ProbeSpecError as exc:
                raise InvalidProviderError(str(exc)) from exc
            self._register(discovered, provider, str(path))

        # Sort by an explicit key rather than trusting insertion order, which
        # depends on filesystem iteration.
        return tuple(sorted(discovered.values(), key=lambda p: p.name))

    @staticmethod
    def _register(
        discovered: dict[str, Provider], provider: Provider, origin: str
    ) -> None:
        """Validate one discovered provider and add it, or raise on a name clash."""
        validate_provider(provider, origin)

        existing = discovered.get(provider.name)
        if existing is not None:
            msg = (
                f"duplicate provider name {provider.name!r}: "
                f"{type(existing).__module__}.{type(existing).__name__} "
                f"and {origin}. Provider names are the registry key and the "
                "--provider value, so they must be unique."
            )
            raise DuplicateProviderError(msg)

        discovered[provider.name] = provider

    def _iter_modules(self) -> Iterator[ModuleType]:
        """Import each module in the providers package, in sorted name order."""
        package = importlib.import_module(self._package)
        module_names = sorted(
            info.name
            for info in pkgutil.iter_modules(package.__path__)
            # Private modules are shared helpers, not plugins.
            if not info.name.startswith("_")
        )
        for module_name in module_names:
            yield importlib.import_module(f"{self._package}.{module_name}")

    def _iter_spec_paths(self) -> Iterator[Path]:
        """Every declarative provider spec in the package, in sorted order.

        Mirrors :meth:`_iter_modules`'s two rules: sorted so discovery order
        cannot depend on filesystem iteration, and a leading underscore marks
        a shared fragment rather than a plugin — `core/probes.py`'s module
        docstring is where that convention is explained for `.py` modules,
        and it applies identically here.
        """
        package = importlib.import_module(self._package)
        paths = [
            path
            for root in package.__path__
            for path in Path(root).iterdir()
            if path.is_file()
            and path.suffix in SPEC_SUFFIXES
            and not path.name.startswith("_")
        ]
        yield from sorted(paths, key=lambda path: path.name)

    @staticmethod
    def _provider_classes(module: ModuleType) -> list[type[Provider]]:
        """Concrete Provider subclasses *defined in* this module, sorted by name.

        The ``__module__`` check matters: a provider that imports another
        provider's class for reuse would otherwise register it a second time and
        trip the duplicate-name guard. Ownership is by definition site, not by
        what happens to be in the namespace.
        """
        return sorted(
            (
                member
                for _, member in inspect.getmembers(module, inspect.isclass)
                if issubclass(member, Provider)
                and member.__module__ == module.__name__
                and not inspect.isabstract(member)
            ),
            key=lambda cls: cls.__name__,
        )

    # ---------------------------------------------------------------- lookup

    def names(self) -> tuple[str, ...]:
        """Every registered provider name, sorted."""
        return tuple(provider.name for provider in self.providers())

    def get(self, name: str) -> Provider:
        """Look up one provider by name, as ``--provider`` does."""
        wanted = name.strip().lower()
        for provider in self.providers():
            if provider.name == wanted:
                return provider

        known = ", ".join(self.names()) or "none loaded"
        msg = f"no provider named {name!r}. Known providers: {known}"
        raise UnknownProviderError(msg)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.strip().lower() in self.names()

    def __len__(self) -> int:
        return len(self.providers())

    def __iter__(self) -> Iterator[Provider]:
        return iter(self.providers())

    # ------------------------------------------------------------- detection

    def rank(self, key: str) -> tuple[ProviderMatch, ...]:
        """Providers that recognise ``key``, most confident first.

        Ties break on provider name, so two providers equally confident about a
        shared prefix always appear in the same order
        (``implementation_plan.md`` §5). Providers returning ``0.0`` are omitted
        entirely — a candidate list is a list of things worth spending
        authentication traffic on.

        Ambiguity is resolved at the enumerate stage rather than here, so this
        deliberately returns every candidate instead of picking a winner.
        """
        matches: list[ProviderMatch] = []
        for provider in self.providers():
            confidence = _checked_confidence(provider, provider.detect(key))
            if confidence > 0.0:
                matches.append(ProviderMatch(provider, confidence))

        return tuple(
            sorted(matches, key=lambda match: (-match.confidence, match.provider.name))
        )


#: Shared registry over the real providers package. The engine and CLI use this;
#: tests build their own over a fixture package rather than mutating it, so
#: there is no global state to reset between tests.
default_registry: Final = ProviderRegistry()
