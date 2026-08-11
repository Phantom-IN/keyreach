"""Provider registry tests (roadmap R0.4).

R0.4's acceptance criterion is "registry loads providers in stable order". The
ordering tests here are built so they cannot pass by accident: the fixture
package in ``tests/dummy_providers`` names its modules so that **alphabetical
module order is the reverse of alphabetical provider order** (``zulu.py``
defines ``alpha``, ``alpha.py`` defines ``zebra``). A registry returning
providers in import order would produce exactly the wrong sequence.

Each test builds its own :class:`ProviderRegistry` over a fixture package, so
none of them touch ``keyreach.providers`` or share mutable state.
"""

from __future__ import annotations

import asyncio

import pytest

from keyreach.core.http import ProbeClient, ProbeContext
from keyreach.core.models import AccessLevel, ValidationResult
from keyreach.core.provider import Provider
from keyreach.core.registry import (
    PROVIDERS_PACKAGE,
    VALID_CATEGORIES,
    DuplicateProviderError,
    InvalidProviderError,
    ProviderRegistry,
    UnknownProviderError,
    default_registry,
    validate_provider,
)

DUMMY_PACKAGE = "tests.dummy_providers"
BROKEN_PACKAGE = "tests.broken_providers"
MISBEHAVING_PACKAGE = "tests.misbehaving_providers"

#: Providers defined in tests/dummy_providers, in the order the registry must
#: return them — by provider name, not by module name.
EXPECTED_NAMES = ("alpha", "mike", "november", "zebra")


@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry(DUMMY_PACKAGE)


class StubProvider(Provider):
    """Minimal concrete provider for validating metadata rules in isolation."""

    name = "stub"
    category = "generic"
    docs_url = "https://example.invalid/stub"

    def detect(self, key: str) -> float:
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        return ValidationResult(valid=False)

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[object]:  # type: ignore[override]
        return []


# --------------------------------------------------------------------------
# Discovery and ordering
# --------------------------------------------------------------------------


def test_registry_discovers_every_provider(registry: ProviderRegistry) -> None:
    assert registry.names() == EXPECTED_NAMES


def test_registry_orders_by_provider_name_not_module_name(
    registry: ProviderRegistry,
) -> None:
    """The R0.4 acceptance criterion.

    ``alpha`` is defined in ``zulu.py`` and ``zebra`` in ``alpha.py``. Returning
    them in import order would yield ``zebra`` first.
    """
    names = registry.names()

    assert names == tuple(sorted(names))
    assert names[0] == "alpha"
    assert names[-1] == "zebra"


def test_repeated_loads_return_an_identical_order(
    registry: ProviderRegistry,
) -> None:
    """Determinism across registries, not just within one cached instance."""
    first = ProviderRegistry(DUMMY_PACKAGE).names()
    second = ProviderRegistry(DUMMY_PACKAGE).names()

    assert first == second == registry.names()


def test_discovery_is_cached_until_reload(registry: ProviderRegistry) -> None:
    """Importing plugin modules has side effects; do it once per registry."""
    first = registry.providers()

    assert registry.providers() is first
    assert registry.reload() is not first
    assert registry.names() == EXPECTED_NAMES


def test_multiple_providers_in_one_module_are_all_found(
    registry: ProviderRegistry,
) -> None:
    """`middle.py` defines both `mike` and `november`."""
    assert {"mike", "november"} <= set(registry.names())


def test_private_modules_are_not_scanned(registry: ProviderRegistry) -> None:
    """`_shared.py` defines a concrete provider named `dummy`.

    Underscore-prefixed modules are shared helpers, so its `DummyProvider` base
    must never be registered as a plugin in its own right.
    """
    assert "dummy" not in registry.names()


def test_imported_provider_classes_are_not_double_registered(
    registry: ProviderRegistry,
) -> None:
    """`middle.py` imports `AlphaProvider` from `zulu.py`.

    Ownership is by definition site (`__module__`), not by what happens to be in
    a module's namespace — otherwise this would register `alpha` twice and trip
    the duplicate-name guard.
    """
    assert registry.names().count("alpha") == 1


def test_empty_provider_package_loads_cleanly() -> None:
    """keyreach.providers has no plugins until R1.1; that must not be an error."""
    empty = ProviderRegistry(PROVIDERS_PACKAGE)

    assert empty.providers() == ()
    assert empty.names() == ()


def test_default_registry_targets_the_real_provider_package() -> None:
    assert isinstance(default_registry, ProviderRegistry)
    assert PROVIDERS_PACKAGE in repr(default_registry)


def test_repr_reports_load_state(registry: ProviderRegistry) -> None:
    assert "unloaded" in repr(registry)

    registry.providers()

    assert "4" in repr(registry)


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------


def test_get_returns_the_named_provider(registry: ProviderRegistry) -> None:
    assert registry.get("mike").name == "mike"


@pytest.mark.parametrize("name", ["ALPHA", "  alpha  ", "Alpha"])
def test_get_normalizes_the_requested_name(
    registry: ProviderRegistry, name: str
) -> None:
    """`--provider` comes from a human; casing and stray spaces are not errors."""
    assert registry.get(name).name == "alpha"


def test_get_raises_with_the_known_names_listed(registry: ProviderRegistry) -> None:
    """`--provider typo` should say what the valid options are."""
    with pytest.raises(UnknownProviderError) as caught:
        registry.get("nope")

    message = str(caught.value)
    assert "nope" in message
    assert "alpha" in message


def test_unknown_provider_error_is_a_key_error(registry: ProviderRegistry) -> None:
    """Callers may reasonably catch KeyError from a lookup."""
    with pytest.raises(KeyError):
        registry.get("nope")


def test_membership_and_length_and_iteration(registry: ProviderRegistry) -> None:
    assert "alpha" in registry
    assert "ALPHA" in registry
    assert "nope" not in registry
    assert 123 not in registry
    assert len(registry) == 4
    assert [provider.name for provider in registry] == list(EXPECTED_NAMES)


# --------------------------------------------------------------------------
# Metadata validation
# --------------------------------------------------------------------------


def test_valid_provider_passes_validation() -> None:
    validate_provider(StubProvider())


@pytest.mark.parametrize("attribute", ["name", "category", "docs_url"])
def test_missing_required_metadata_is_rejected(attribute: str) -> None:
    provider = StubProvider()
    object.__setattr__(provider, attribute, "")

    with pytest.raises(InvalidProviderError, match=attribute):
        validate_provider(provider)


@pytest.mark.parametrize("name", ["Google", "  google", "GOOGLE"])
def test_non_lowercase_provider_names_are_rejected(name: str) -> None:
    """The name is matched literally against `--provider`, so casing matters."""
    provider = StubProvider()
    object.__setattr__(provider, "name", name)

    with pytest.raises(InvalidProviderError, match="lowercase"):
        validate_provider(provider)


def test_unknown_category_is_rejected_and_lists_the_valid_ones() -> None:
    """Category feeds the v0.1 "≥4 categories" measure; a typo would inflate it."""
    provider = StubProvider()
    object.__setattr__(provider, "category", "clowd")

    with pytest.raises(InvalidProviderError) as caught:
        validate_provider(provider)

    assert "clowd" in str(caught.value)
    assert "cloud" in str(caught.value)


def test_every_dummy_provider_declares_a_known_category(
    registry: ProviderRegistry,
) -> None:
    assert {provider.category for provider in registry} <= VALID_CATEGORIES


def test_validation_error_names_the_offending_plugin() -> None:
    provider = StubProvider()
    object.__setattr__(provider, "category", "nope")

    with pytest.raises(InvalidProviderError, match=r"my\.module\.MyProvider"):
        validate_provider(provider, "my.module.MyProvider")


def test_duplicate_provider_names_are_rejected() -> None:
    """Two plugins claiming one name would make `--provider` ambiguous."""
    with pytest.raises(DuplicateProviderError) as caught:
        ProviderRegistry(BROKEN_PACKAGE).providers()

    assert "clash" in str(caught.value)


# --------------------------------------------------------------------------
# Detection ranking
# --------------------------------------------------------------------------


def test_rank_returns_only_providers_that_recognise_the_key(
    registry: ProviderRegistry,
) -> None:
    matches = registry.rank("alpha_secret")

    assert [match.provider.name for match in matches] == ["alpha"]
    assert matches[0].confidence == 1.0


def test_rank_returns_nothing_for_an_unrecognised_key(
    registry: ProviderRegistry,
) -> None:
    """Zero confidence means "not mine", not "maybe" — no probe is warranted."""
    assert registry.rank("no-provider-claims-this") == ()


def test_rank_orders_by_confidence_then_name() -> None:
    """implementation_plan.md §5: ties break on provider name, always."""

    class Tied(StubProvider):
        def __init__(self, name: str, confidence: float) -> None:
            object.__setattr__(self, "name", name)
            self._confidence = confidence

        def detect(self, key: str) -> float:
            return self._confidence

    registry = ProviderRegistry(DUMMY_PACKAGE)
    # Injecting the cache directly keeps the fixture packages small; the
    # ordering logic under test is in rank(), not in discovery.
    registry._providers = (
        Tied("charlie", 0.5),
        Tied("bravo", 0.5),
        Tied("alpha", 0.9),
    )

    assert [match.provider.name for match in registry.rank("k")] == [
        "alpha",
        "bravo",
        "charlie",
    ]


def test_rank_is_stable_across_repeated_calls(registry: ProviderRegistry) -> None:
    assert registry.rank("alpha_secret") == registry.rank("alpha_secret")


def test_out_of_range_confidence_is_rejected() -> None:
    """A confidence above 1.0 would dominate ranking and skew every run."""
    registry = ProviderRegistry(MISBEHAVING_PACKAGE)

    with pytest.raises(InvalidProviderError, match=r"0\.0-1\.0"):
        registry.rank("anything")


@pytest.mark.parametrize("returned", ["high", None, True])
def test_non_numeric_confidence_is_rejected(returned: object) -> None:
    """Including `True`, which is an int in Python and would rank as 1.0."""

    class BadDetect(StubProvider):
        def detect(self, key: str) -> float:
            return returned  # type: ignore[return-value]

    registry = ProviderRegistry(DUMMY_PACKAGE)
    registry._providers = (BadDetect(),)

    with pytest.raises(InvalidProviderError, match="expected a float"):
        registry.rank("k")


# --------------------------------------------------------------------------
# The plugin contract itself
# --------------------------------------------------------------------------


def test_provider_cannot_be_instantiated_directly() -> None:
    """An ABC, so a half-implemented plugin fails at registration.

    Discovering a missing `enumerate` halfway through probing a live key would
    be a much worse place to find out.
    """
    with pytest.raises(TypeError):
        Provider()  # type: ignore[abstract]


@pytest.mark.parametrize("method", ["detect", "validate", "enumerate"])
def test_incomplete_provider_cannot_be_instantiated(method: str) -> None:
    namespace = {
        name: getattr(StubProvider, name)
        for name in ("name", "category", "docs_url", "detect", "validate", "enumerate")
    }
    del namespace[method]
    incomplete = type("Incomplete", (Provider,), namespace)

    with pytest.raises(TypeError, match=method):
        incomplete()


def test_optional_metadata_defaults_to_none() -> None:
    provider = StubProvider()

    assert provider.rotation_guide_url is None
    assert provider.credit is None


def test_repr_identifies_the_provider() -> None:
    assert repr(StubProvider()) == ("<StubProvider name='stub' category='generic'>")


def test_dummy_provider_implements_the_full_contract(
    registry: ProviderRegistry,
) -> None:
    """The contract must actually be implementable end to end, offline.

    Driven with ``asyncio.run`` rather than an async test plugin. ``validate``
    and ``enumerate`` are async because R0.6 runs probes concurrently, but
    nothing here awaits real I/O, so pulling in ``pytest-asyncio`` for one
    coroutine would be a dependency ahead of its need. R0.6 is the item that
    adds it, alongside the cassette-backed probe tests that genuinely require
    an event loop.
    """
    provider = registry.get("alpha")
    # ProbeContext became concrete in R0.6, so this is now the real surface a
    # plugin is handed. The dummy provider issues no requests, so the client is
    # never entered and no socket is opened.
    context = ProbeContext(ProbeClient(), "alpha_secret")

    result = asyncio.run(provider.validate("alpha_secret", context))
    capabilities = asyncio.run(provider.enumerate("alpha_secret", context))

    assert result.valid is True
    assert capabilities[0].access is AccessLevel.READ
