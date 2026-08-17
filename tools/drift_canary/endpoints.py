"""Probe-endpoint drift verification (``implementation_plan.md`` §13.3, items 2-3).

§13.3 names two things a probe can silently stop meaning: the endpoint can
stop existing at all (the ``404``-versus-``401`` distinction this repository
already applies by hand — R2.4 found three of Bitbucket's endpoints had
become ``404`` after Atlassian deprecated them), or it can start answering
with a documented deprecation notice while still technically working. Both
are checked here, against every probe a **declarative** provider
(``keyreach/core/probes.py``, roadmap R2.8) declares — see this package's
``__init__.py`` for why hand-written ``.py`` plugins are not (yet) covered.

**No real key is used, or needed.** A ``.yml`` provider's ``liveness``
vocabulary already states, as data, which statuses mean "the endpoint exists
but this key doesn't work" (``unauthorized``, ``live_but_refused``,
``rate_limited``) — that is the entire response a placeholder credential
should ever produce, since a probe never distinguishes *which* invalid key
it is. Anything outside that vocabulary — most importantly a ``404`` — is
not something an invalid-but-real key would ever produce either, and is
reported.

**Deprecation is read from the response, not from a vendor's prose.**
Atlassian marks a deprecated endpoint in its own OpenAPI specification (R2.4
found this by reading it), but a specification is not something this canary
can generically diff against every vendor's schema. RFC 8594's
``Deprecation`` and ``Sunset`` response headers are the vendor-agnostic
runtime signal for the same fact, and are checked on every response
regardless of its status code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from keyreach.core.probes import YamlProvider
from keyreach.core.provider import Provider
from keyreach.core.registry import default_registry
from tools.drift_canary.base import Fetch, Finding

#: Cannot collide with a real credential — no live key is ever needed to
#: learn whether an endpoint still exists or still means what it used to.
PLACEHOLDER_KEY = "keyreach-drift-canary-0000000000000000"

#: The §13.3 distinction: an endpoint that no longer exists at all, versus
#: one that exists and simply refused a bad credential.
_HTTP_NOT_FOUND = 404

#: RFC 8594. Checked case-insensitively since header casing is a transport
#: detail, not a signal.
_DEPRECATION_HEADERS = frozenset({"deprecation", "sunset"})


def _carries_deprecation_signal(headers: Mapping[str, str]) -> bool:
    return any(name.lower() in _DEPRECATION_HEADERS for name in headers)


def check(fetch: Fetch, providers: Iterable[Provider] | None = None) -> list[Finding]:
    """Verify every declarative provider's probes still exist and still work.

    ``providers`` defaults to the real registry's full set; tests pass a
    small synthetic list instead so a check does not need a fixture package
    on disk just to prove one branch of the status-code logic.
    """
    providers = providers if providers is not None else default_registry.providers()

    findings: list[Finding] = []
    for provider in providers:
        if isinstance(provider, YamlProvider):
            findings.extend(_check_provider(provider, fetch))
    return findings


def _check_provider(provider: YamlProvider, fetch: Fetch) -> list[Finding]:
    spec = provider.spec
    headers = {
        name: value.format(key=PLACEHOLDER_KEY)
        for name, value in spec.auth.headers.items()
    }
    healthy_statuses = {
        *spec.liveness.unauthorized_statuses,
        *spec.liveness.live_but_refused_statuses,
        *spec.liveness.rate_limited_statuses,
    }

    findings: list[Finding] = []
    for probe in spec.probes:
        subject = f"{provider.name} / {probe.service}"
        result = fetch(probe.url, headers)

        if result.error is not None:
            findings.append(
                Finding(
                    "endpoint-unreachable",
                    subject,
                    f"GET {probe.url} failed: {result.error}",
                    probe.url,
                )
            )
            continue

        if result.status == _HTTP_NOT_FOUND:
            findings.append(
                Finding(
                    "endpoint-missing",
                    subject,
                    f"GET {probe.url} returned 404 — it may have moved or "
                    "been removed",
                    probe.url,
                )
            )
        elif result.status not in healthy_statuses:
            findings.append(
                Finding(
                    "endpoint-unexpected-status",
                    subject,
                    f"GET {probe.url} returned {result.status}, which "
                    f"{provider.name}'s declared liveness statuses "
                    f"{sorted(healthy_statuses)} do not account for",
                    probe.url,
                )
            )

        if _carries_deprecation_signal(result.headers):
            findings.append(
                Finding(
                    "endpoint-deprecated",
                    subject,
                    f"GET {probe.url} response carries a Deprecation/Sunset "
                    "header (RFC 8594)",
                    probe.url,
                )
            )
    return findings
