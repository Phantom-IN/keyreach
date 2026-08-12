"""The provider contract, asserted against every registered plugin (roadmap R1.4).

R1.4 is the checkpoint that asks whether the Phase-0 promise held: *adding a
provider touches only its own file and its fixtures*. The evidence is in
``implementation_plan.md`` §4.2. The short version is that R1.1 and R1.2 touched
no core file and R1.3 added three ``ProbeContext`` members — so the promise
failed once, for reasons that turned out to be the interface being incomplete
rather than wrong.

This file is what that checkpoint leaves behind. Each provider's own test module
proves *that provider* works; nothing until now proved that every provider obeys
the same rules, so each new plugin re-litigated them in prose. These tests are
parametrised over the live registry, so a plugin added tomorrow is held to them
without anyone remembering to.

**Why this instead of a shared base class.** The obvious alternative reading of
R1.4 is "four ``enumerate`` methods look alike, extract them". They do look
alike, and the parts that differ are exactly the parts that matter: how a request
is authenticated (query parameter, bearer header, ``x-api-key``, SigV4), how
success is decided (an HTTP status, or a Maps body that says ``REQUEST_DENIED``
inside a 200), which access level a result justifies, and whether a capability
can come from a documented rule rather than a probe at all. An abstraction over
that needs a callback per difference, which is the same code wearing a hat, and
it would displace the comments that carry the *reasoning* — the most valuable
thing in those blocks. The genuine shared abstraction is the declarative probe
runner already specified in ``implementation_plan.md`` §8 and scheduled as
**R2.8**; building half of it here would mean building it twice.

So the invariant is enforced instead of the implementation. That is the same
choice the repository already makes for its hard rules: not "trust that every
plugin masks its evidence" but a test that checks each one does.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.http import ProbeClient, ProbeContext
from keyreach.core.provider import Provider
from keyreach.core.registry import (
    PROVIDERS_PACKAGE,
    VALID_CATEGORIES,
    ProviderRegistry,
    validate_provider,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent

REGISTRY = ProviderRegistry(PROVIDERS_PACKAGE)

#: Every shipped plugin, named so a failure says which one broke the contract.
PROVIDERS = list(REGISTRY.providers())

#: Guards against the whole suite passing vacuously if discovery ever breaks.
#: Every assertion below is parametrised, and an empty parameter list is a
#: silent pass — the failure mode that makes a conformance suite worthless.
#:
#: Raised from 4 to 10 in R1.6, where it stopped being only a tripwire and
#: became the release bar itself — see the two constants below.
EXPECTED_MINIMUM_PROVIDERS = 10

#: The v0.1 coverage measure, from `plan.md` §2 and roadmap **R1.6**: "≥10
#: providers across ≥4 categories, including cloud, AI, payment, and comms".
#:
#: Asserted rather than counted by hand at release time. It was written down in
#: three documents from R0.1 onwards and nothing checked it, which is exactly
#: the shape of claim this repository has twice found to be false (`CLAUDE.md`
#: hard rule 7). A provider deleted or a category typo'd now fails the build
#: instead of quietly retiring a published promise.
V01_MINIMUM_CATEGORIES = 4
V01_REQUIRED_CATEGORIES = frozenset({"ai", "cloud", "comms", "payment"})


def by_name(provider: Provider) -> str:
    return provider.name


parametrised = pytest.mark.parametrize("provider", PROVIDERS, ids=by_name)


def test_the_suite_is_not_running_against_an_empty_registry() -> None:
    """A conformance suite over nothing passes everything."""
    assert len(PROVIDERS) >= EXPECTED_MINIMUM_PROVIDERS


def test_the_shipped_coverage_meets_the_v01_measure() -> None:
    """R1.6's acceptance criterion, enforced instead of counted by hand.

    ``README.md`` and ``plan.md`` both publish this number, and a released
    project that misses its own stated target is a worse outcome than one that
    ships late. Naming the four required categories matters as much as the
    count: ten AI providers would satisfy an arithmetic check and none of the
    argument behind it.
    """
    categories = {provider.category for provider in PROVIDERS}

    assert len(PROVIDERS) >= EXPECTED_MINIMUM_PROVIDERS, sorted(
        provider.name for provider in PROVIDERS
    )
    assert len(categories) >= V01_MINIMUM_CATEGORIES, sorted(categories)
    assert categories >= V01_REQUIRED_CATEGORIES, sorted(categories)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


@parametrised
def test_metadata_satisfies_the_registry(provider: Provider) -> None:
    validate_provider(provider, origin=type(provider).__module__)


@parametrised
def test_the_category_is_one_of_the_closed_set(provider: Provider) -> None:
    """Category drives the v0.1 "≥10 providers across ≥4 categories" measure.

    A typo would quietly inflate the count, which is why the set is closed.
    """
    assert provider.category in VALID_CATEGORIES


@parametrised
def test_documentation_links_are_absolute(provider: Provider) -> None:
    """Both reach a report a stranger reads. A relative link is useless there."""
    assert provider.docs_url.startswith("https://")

    if provider.rotation_guide_url is not None:
        assert provider.rotation_guide_url.startswith("https://")


@parametrised
def test_a_rotation_guide_is_provided(provider: Provider) -> None:
    """The first thing a recipient needs is how to revoke the thing."""
    assert provider.rotation_guide_url


@parametrised
def test_the_module_explains_itself(provider: Provider) -> None:
    """Every plugin's reasoning lives in its module docstring, by convention.

    A provider is a set of claims about somebody else's API. Without the
    argument for each one, a reviewer can check the code but not the decision.
    """
    module = inspect.getmodule(type(provider))

    assert module is not None
    assert module.__doc__
    assert "roadmap" in module.__doc__.lower()


# ---------------------------------------------------------------------------
# Attribution — a hard rule (`plan.md` §5), enforced rather than remembered
# ---------------------------------------------------------------------------


@parametrised
def test_a_credited_provider_appears_in_credits(provider: Provider) -> None:
    """`Provider.credit` and `CREDITS.md` must not drift apart.

    Attribution is a hard rule, and up to R1.4 nothing checked it: a plugin
    could name an upstream project in its metadata while `CREDITS.md` said
    nothing, and the omission would only surface if a human noticed. Two
    providers set `credit` today — gmapsapiscanner (MIT) and enumerate-iam
    (GPL-3.0) — and for the second, attribution is not merely courtesy.
    """
    if provider.credit is None:
        return

    credits_text = (REPO_ROOT / "CREDITS.md").read_text(encoding="utf-8")

    assert provider.credit in credits_text, (
        f"{provider.name} credits {provider.credit!r}, which CREDITS.md does "
        "not mention. Attribution is a hard rule (plan.md §5)."
    )


@parametrised
def test_a_credited_provider_says_so_in_its_own_source(provider: Provider) -> None:
    """`CLAUDE.md` requires an inline credit header on any derived provider."""
    if provider.credit is None:
        return

    module = inspect.getmodule(type(provider))
    assert module is not None
    assert module.__doc__ is not None

    assert provider.credit in module.__doc__


# ---------------------------------------------------------------------------
# `detect` — pure, strict, and agreeing with the shipped rule set
# ---------------------------------------------------------------------------


@parametrised
def test_detect_is_pure(provider: Provider) -> None:
    """Detection ordering decides what gets probed, so it must not vary."""
    samples = ["", "not-a-key", "x" * 64]

    for sample in samples:
        assert len({provider.detect(sample) for _ in range(5)}) == 1


@parametrised
def test_detect_claims_nothing_for_obvious_non_keys(provider: Provider) -> None:
    """Returning a small nonzero score costs a probe against a stranger's API.

    `Provider.detect` asks for `0.0` — "definitely not mine" — rather than a
    hedge, because the registry treats any positive confidence as a candidate
    worth spending authentication traffic on.
    """
    for sample in ("", "hello world", "1234", "https://example.invalid"):
        assert provider.detect(sample) == 0.0, sample


@parametrised
def test_detect_returns_a_confidence_in_range(provider: Provider) -> None:
    for sample in ("", "sk-" + "x" * 40, "AIza" + "0" * 35):
        assert 0.0 <= provider.detect(sample) <= 1.0


@parametrised
def test_every_provider_has_a_detection_rule(provider: Provider) -> None:
    """A plugin nothing routes to can never run.

    The rule set may legitimately run *ahead* of the plugins — recognising a key
    keyreach cannot yet enumerate is still useful — but the reverse is a plugin
    that is installed and unreachable.
    """
    named = {rule.provider for rule in default_detector.rules()}

    assert provider.name in named


# ---------------------------------------------------------------------------
# The probe tables
# ---------------------------------------------------------------------------


def probe_tables() -> Iterator[tuple[str, tuple[object, ...]]]:
    """Every provider module that declares a `PROBES` table, with its name."""
    for provider in PROVIDERS:
        module = inspect.getmodule(type(provider))
        probes = getattr(module, "PROBES", None)
        if probes is not None:
            yield provider.name, tuple(probes)


PROBE_TABLES = list(probe_tables())


def test_every_provider_declares_its_probes_as_a_table() -> None:
    """The one structural convention all four plugins share, made explicit.

    Not a base class — see this module's docstring — but a stated expectation,
    so a plugin that inlines its endpoints is a visible choice rather than an
    accident. It is also what **R2.8** will migrate to YAML.
    """
    assert len(PROBE_TABLES) == len(PROVIDERS)


@pytest.mark.parametrize(
    ("name", "probes"), PROBE_TABLES, ids=[name for name, _ in PROBE_TABLES]
)
def test_probes_are_uniquely_named(name: str, probes: tuple[object, ...]) -> None:
    """Two probes sharing a service name produce two capabilities a reader
    cannot tell apart."""
    del name
    services = [getattr(probe, "service") for probe in probes]  # noqa: B009

    assert len(services) == len(set(services))


@pytest.mark.parametrize(
    ("name", "probes"), PROBE_TABLES, ids=[name for name, _ in PROBE_TABLES]
)
def test_every_probe_cites_a_vendor_page(name: str, probes: tuple[object, ...]) -> None:
    """Auditability: a probe nobody can trace to a vendor page cannot be checked.

    The URL reaches the report as the capability's `resource_ref`, so a
    recipient verifies the endpoint against the vendor's own docs rather than
    taking keyreach's word for what it called.
    """
    del name
    for probe in probes:
        source = getattr(probe, "source")  # noqa: B009

        assert source.startswith("https://"), probe


@pytest.mark.parametrize(
    ("name", "probes"), PROBE_TABLES, ids=[name for name, _ in PROBE_TABLES]
)
def test_risk_weights_are_declared_in_range(
    name: str, probes: tuple[object, ...]
) -> None:
    del name
    for probe in probes:
        assert 0 <= getattr(probe, "risk_weight") <= 100, probe  # noqa: B009


# ---------------------------------------------------------------------------
# The `ProbeContext` surface — the thing R1.3 changed
# ---------------------------------------------------------------------------

#: Everything a plugin may use. Written out so that widening it is a deliberate,
#: reviewed edit to this list rather than a member that appears in a provider
#: pull request and is never discussed.
#:
#: `now`, `protect` and `aggressive` were added in R1.3 for AWS, and R1.4's
#: verdict is that all three are generic rather than AWS-specific: `protect` is
#: needed by any composite credential, `now` by any signed-request provider, and
#: `aggressive` was required by `plan.md` §11 from the start. See
#: `implementation_plan.md` §4.2.
#:
#: R1.4 justified `protect` by naming a provider that did not exist yet —
#: Twilio's `AccountSid:AuthToken`. R1.6 shipped Twilio, Razorpay and Telegram,
#: all three of which need it, and needed nothing else added here. A prediction
#: that an interface member was generic, later checked against the providers it
#: was predicted for.
PROBE_CONTEXT_SURFACE = frozenset(
    {
        "aggressive",
        "delay",
        "gather",
        "get",
        "head",
        "key",
        "mask",
        "masked_key",
        "now",
        "post",
        "protect",
        "timeout",
    }
)


def test_the_probe_context_surface_is_exactly_what_is_documented() -> None:
    """The interface a plugin sees, pinned.

    R1.3 was the first item to widen this, and it widened it three times in one
    pull request. That is fine when argued and recorded, and invisible when not
    — so it is now impossible to add a member without editing this list.
    """
    # Built from an instance, not the class: `aggressive` is set in __init__,
    # so `dir(ProbeContext)` alone would miss exactly the member most likely to
    # be added carelessly.
    context = ProbeContext(ProbeClient(), "a-key-long-enough-to-register")
    public = {name for name in dir(context) if not name.startswith("_")}

    assert public == PROBE_CONTEXT_SURFACE


def test_the_provider_contract_is_three_methods_and_metadata() -> None:
    """`implementation_plan.md` §4: that is the whole contract, deliberately.

    Adding a provider should be roughly a thirty-minute contribution, and the
    surface is small to keep it that way. A fourth required method would be a
    change to what contributing costs.
    """
    required = {
        name
        for name, member in inspect.getmembers(Provider)
        if getattr(member, "__isabstractmethod__", False)
    }

    assert required == {"detect", "validate", "enumerate"}


# ---------------------------------------------------------------------------
# The finding this checkpoint was created by
# ---------------------------------------------------------------------------

_ONE_REQUEST_CLAIM = re.compile(r"one request (?:here )?(?:and )?not two")


@parametrised
def test_no_plugin_repeats_the_claim_r1_4_disproved(provider: Provider) -> None:
    """A regression guard for a documentation bug, which is still a bug.

    Every plugin used to say its validation endpoint cost "one request, not
    two", because it doubled as a capability probe. R1.4 counted the requests:
    all four made it twice. It is one request now because `ProbeClient` caches
    repeated idempotent GETs for a run — so the claim is true again, but for a
    reason no plugin can take credit for. The wording is banned rather than
    corrected in place, so the next plugin cannot reintroduce the reasoning.
    """
    module = inspect.getmodule(type(provider))
    assert module is not None

    source = Path(inspect.getfile(type(provider))).read_text(encoding="utf-8")
    offending = [
        line
        for line in source.splitlines()
        if _ONE_REQUEST_CLAIM.search(line) and "was false" not in line
    ]

    assert offending == [], offending
