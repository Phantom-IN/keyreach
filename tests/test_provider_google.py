"""Google `AIza` provider tests (roadmap R1.1).

R1.1's acceptance criterion: "a test ``AIza`` key yields a capability map incl.
any Gemini exposure, scored with rationale". That runs end to end below, through
the real engine and real cassettes.

The tests that matter most are the ones about *not* inventing capabilities. A
scanner that over-reports is worse than one that reports nothing: the recipient
checks the first claim, finds it false, and stops reading. Two cases here would
each produce a false capability if handled naively — the Maps Platform answering
``REQUEST_DENIED`` with HTTP 200, and a restricted key that is live but reaches
nothing.

**On the fixtures.** They are constructed from Google's published response
shapes, not recorded from a live key — keyreach's own rules forbid holding one,
and probing somebody else's would be unauthorised. That is a real limitation:
they prove the parsing and the decision rules, not that Google still answers this
way. Provider API drift is a known structural risk (`plan.md` §12) and roadmap
**R2.10** is the answer to it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from keyreach.core.detect import Detector, default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, RecordMode
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.google import (
    PROBES,
    VALIDATE_URL,
    GoogleProvider,
    _error_info,
    _project,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal — a joined `AIza` key
#: matches keyreach's own detector and GitHub push protection, and the second
#: would reject the push (see `tools/guardrails/no_secrets.py`).
KEY = "AIza" + "0" * 35
NOT_A_KEY = "AIza" + "0" * 10


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
    )
    return asyncio.run(engine.run(key))


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    """`CLAUDE.md` asks every plugin to assert this itself.

    The registry would reject a bad name or category anyway, but failing in the
    plugin's own test names the plugin instead of failing a shared fixture.
    """
    validate_provider(GoogleProvider(), origin="keyreach.providers.google")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "google" in [provider.name for provider in registry.providers()]


def test_it_credits_the_prior_art_it_was_built_from() -> None:
    """Attribution is a hard rule, not a courtesy (`plan.md` §5.6)."""
    assert GoogleProvider().credit == "gmapsapiscanner"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(KEY, 0.99, id="well-formed"),
        pytest.param(NOT_A_KEY, 0.0, id="too-short"),
        pytest.param("AIza" + "0" * 36, 0.0, id="too-long"),
        pytest.param("BIza" + "0" * 35, 0.0, id="wrong-prefix"),
        pytest.param("AIza" + "!" * 35, 0.0, id="wrong-charset"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + "AIza" + "0" * 35, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert GoogleProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = GoogleProvider()

    assert {provider.detect(KEY) for _ in range(5)} == {0.99}


def test_the_plugin_and_the_rule_set_agree_on_the_key_format() -> None:
    """Two places describe an `AIza` key. They must not drift apart.

    `detect()` decides which provider gets probed; the rule set decides what the
    report calls the key. If they disagreed, keyreach could name a key "google"
    and then decline to probe it — or the reverse.
    """
    matched = [
        match.provider
        for match in default_detector.detect(KEY)
        if match.provider is not None
    ]

    assert matched == ["google"]
    assert GoogleProvider().detect(KEY) > 0.0

    for candidate in (NOT_A_KEY, "BIza" + "0" * 35):
        assert GoogleProvider().detect(candidate) == 0.0
        assert [
            m.provider for m in default_detector.detect(candidate) if m.provider
        ] == []


# ---------------------------------------------------------------------------
# The happy path — R1.1's acceptance criterion
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_scored_capability_map_including_gemini() -> None:
    """R1.1, stated as the roadmap states it."""
    result = run("google_valid")

    assert result.valid
    assert [capability.service for capability in result.capabilities] == [
        "Gemini Cached Content",
        "Gemini Files",
        "Gemini Models",
        "Geocoding API",
    ]
    assert result.score.severity is Severity.HIGH
    assert result.score.rationale
    assert any("Gemini Files" in line for line in result.score.rationale)


def test_the_gemini_files_exposure_drives_the_band() -> None:
    """Uploaded documents are what makes this a data finding, not a billing one."""
    files = next(
        c for c in run("google_valid").capabilities if c.service == "Gemini Files"
    )

    assert files.data_sensitive
    assert files.access is AccessLevel.READ


def test_every_capability_is_read_only() -> None:
    """An API key cannot write through these endpoints, and must not claim to."""
    assert all(c.access is AccessLevel.READ for c in run("google_valid").capabilities)


# ---------------------------------------------------------------------------
# Not inventing capabilities
# ---------------------------------------------------------------------------


def test_a_maps_denial_arriving_as_http_200_is_not_a_capability() -> None:
    """The trap this provider is most likely to fall into.

    Maps Platform web services answer `REQUEST_DENIED` inside a 200 response.
    Trusting the status code would report Places access for every key, including
    keys with none — and the first claim a triager checks would be false.
    """
    services = [c.service for c in run("google_valid").capabilities]

    assert "Places API (Find Place)" not in services
    # Proves the fixture really does deny it at HTTP 200, so this test cannot
    # pass because the request merely failed.
    recorded = json.loads((FIXTURES / "google_valid.json").read_text(encoding="utf-8"))
    places = next(
        i for i in recorded["interactions"] if "findplacefromtext" in i["url"]
    )

    assert places["status_code"] == 200
    assert "REQUEST_DENIED" in places["body"]


def test_a_rest_api_failure_is_not_a_capability() -> None:
    assert "Roads API" not in [c.service for c in run("google_valid").capabilities]


def test_a_restricted_key_is_live_but_reaches_nothing() -> None:
    """Live and blocked is a different finding from dead, and from exposed."""
    result = run("google_restricted")

    assert result.valid
    assert result.capabilities == ()
    assert result.score.severity is Severity.INFO

    note = result.outcomes[0].validation.note
    assert "referrer" in note
    assert "lower bound" in note


def test_the_gemini_model_list_does_not_claim_inference() -> None:
    """keyreach never calls a model, so it cannot claim the key could.

    Google key restrictions can be scoped to individual methods, so reaching
    `models.list` does not establish `generateContent`. Marking this capability
    `incurs_cost` would be a guess dressed as a finding.
    """
    models = next(
        c for c in run("google_valid").capabilities if c.service == "Gemini Models"
    )

    assert not models.incurs_cost
    assert "not tested" in models.detail


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_key_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("google_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "rejected this key as invalid" in result.outcomes[0].validation.note


def test_a_disabled_api_still_means_the_key_is_live() -> None:
    """`SERVICE_DISABLED` refuses the request, not the key.

    Collapsing it into "invalid" would under-report a live, exposed key — the
    more dangerous direction to be wrong in.
    """
    result = run("google_maps_only")

    assert result.valid
    assert "not enabled" in result.outcomes[0].validation.note


def test_the_project_number_is_recovered_from_the_error() -> None:
    """An exposed key that names its own project tells the recipient where to look."""
    identity = run("google_maps_only").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "projects/402168891234"


def test_a_maps_only_key_reports_billing_exposure_without_gemini() -> None:
    result = run("google_maps_only")
    services = [c.service for c in result.capabilities]

    assert services == ["Geocoding API", "Places API (Find Place)", "Roads API"]
    assert all(c.incurs_cost for c in result.capabilities)
    assert not any("Gemini" in service for service in services)


# ---------------------------------------------------------------------------
# Evidence: proves access without becoming a copy of the data
# ---------------------------------------------------------------------------


def test_evidence_never_contains_the_raw_key() -> None:
    for capability in run("google_valid").capabilities:
        assert KEY not in capability.evidence
        assert "<key>" in capability.evidence


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    """A report gets pasted into a ticket. It must not carry the data with it.

    The fixture's uploaded files have recognisable names; the evidence proving
    keyreach could list them must say how many there were, not what they were.
    """
    files = next(
        c for c in run("google_valid").capabilities if c.service == "Gemini Files"
    )

    assert "2 files listed" in files.evidence
    assert "quarterly-report.pdf" not in files.evidence
    assert "customer-list.csv" not in files.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("google_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert KEY not in capability.poc


def test_no_committed_fixture_contains_a_key() -> None:
    """The guarantee that makes committing cassettes acceptable at all."""
    for name in ("valid", "invalid", "restricted", "maps_only"):
        text = (FIXTURES / f"google_{name}.json").read_text(encoding="utf-8")

        assert KEY not in text
        assert "AIza" not in text


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    """Auditability: a probe nobody can trace to a vendor page cannot be checked.

    The same URL reaches the report as the capability's `resource_ref`, so a
    recipient can verify the endpoint against Google's own docs rather than
    taking keyreach's word for what it called.
    """
    refs = {c.service: c.resource_ref for c in run("google_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        if probe.service in refs:
            assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_validation_reuses_a_probe_endpoint() -> None:
    """One request, not two: validation is also the cheapest capability probe."""
    assert VALIDATE_URL in [probe.url for probe in PROBES]


def test_only_billable_probes_are_flagged_as_costly() -> None:
    """`incurs_cost` drives severity, so it must mean what it says.

    The Gemini list endpoints are free metadata reads; the Maps Platform calls
    are billed to the key's owner.
    """
    costly = {probe.service for probe in PROBES if probe.incurs_cost}

    assert costly == {"Places API (Find Place)", "Geocoding API", "Roads API"}


# ---------------------------------------------------------------------------
# Error parsing, which reads third-party payloads and must not raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(None, id="not-json"),
        pytest.param("a string", id="scalar"),
        pytest.param({}, id="empty"),
        pytest.param({"error": "oops"}, id="error-not-a-mapping"),
        pytest.param({"error": {}}, id="no-details"),
        pytest.param({"error": {"details": "x"}}, id="details-not-a-list"),
        pytest.param({"error": {"details": [{"@type": "other"}]}}, id="no-errorinfo"),
        pytest.param({"error": {"details": ["x"]}}, id="detail-not-a-mapping"),
    ],
)
def test_error_parsing_degrades_instead_of_raising(payload: object) -> None:
    """A maintenance page must not crash a probe."""
    assert _error_info(payload) == {}


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette.

    The four committed cassettes cover the outcomes worth shipping fixtures for.
    These are the remaining branches of Google's error vocabulary — reason codes
    keyreach must interpret but which do not warrant a whole recorded scenario.
    """
    from keyreach.core.http import ProbeResponse  # noqa: PLC0415

    class _Stub:
        """Minimal ProbeContext stand-in: `validate` only ever calls `get`."""

        async def get(self, url: str, *, params: object = None) -> ProbeResponse:
            del url, params
            return ProbeResponse(
                method="GET",
                url=f"{VALIDATE_URL}?key=<key>",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(GoogleProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def google_error(reason: str, code: int = 403) -> dict[str, object]:
    return {
        "error": {
            "code": code,
            "message": "refused",
            "status": "PERMISSION_DENIED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": reason,
                    "domain": "googleapis.com",
                }
            ],
        }
    }


@pytest.mark.parametrize(
    ("reason", "phrase"),
    [
        pytest.param("API_KEY_IP_ADDRESS_BLOCKED", "IP address", id="ip"),
        pytest.param("API_KEY_ANDROID_APP_BLOCKED", "Android app", id="android"),
        pytest.param("API_KEY_IOS_APP_BLOCKED", "iOS app", id="ios"),
        pytest.param("API_KEY_SERVICE_BLOCKED", "API restriction", id="service"),
    ],
)
def test_every_application_restriction_reads_as_live_but_blocked(
    reason: str, phrase: str
) -> None:
    """All four restriction types mean the same thing: the key works elsewhere."""
    result = validate_against(403, google_error(reason))

    assert result.valid  # type: ignore[attr-defined]
    assert phrase in result.note  # type: ignore[attr-defined]


def test_an_unrecognised_reason_still_reports_the_key_as_live() -> None:
    """Google adds reason codes. An unknown one is not evidence the key is dead."""
    result = validate_against(429, google_error("RATE_LIMIT_EXCEEDED", code=429))

    assert result.valid  # type: ignore[attr-defined]
    assert "RATE_LIMIT_EXCEEDED" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    """Neither "valid" nor "invalid" is honest here, so the note carries it."""
    result = validate_against(500, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_service_disabled_error_without_a_project_still_validates() -> None:
    """The project number is a bonus, not a requirement."""
    result = validate_against(403, google_error("SERVICE_DISABLED"))

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


def test_a_gemini_list_with_no_collection_key_is_still_a_capability() -> None:
    """An account with zero uploaded files returns `{}`, not an error.

    Access is proven by the 200; the evidence should say the collection was
    empty rather than claim a count it never saw.
    """
    from keyreach.core.http import ProbeResponse  # noqa: PLC0415
    from keyreach.providers.google import _summary  # noqa: PLC0415

    empty = ProbeResponse(method="GET", url="u", status_code=200, text="{}")
    files_probe = next(p for p in PROBES if p.service == "Gemini Files")

    assert _summary(files_probe, empty) == "no files present"


def test_a_non_json_success_body_summarises_without_raising() -> None:
    from keyreach.core.http import ProbeResponse  # noqa: PLC0415
    from keyreach.providers.google import _summary  # noqa: PLC0415

    html = ProbeResponse(method="GET", url="u", status_code=200, text="<html/>")
    maps_probe = next(p for p in PROBES if p.service == "Geocoding API")

    assert _summary(maps_probe, html) == "request accepted"


def test_a_maps_response_that_is_not_json_is_not_a_capability() -> None:
    """A proxy interstitial returns 200 and HTML. That is not Maps access."""
    from keyreach.core.http import ProbeResponse  # noqa: PLC0415
    from keyreach.providers.google import _succeeded  # noqa: PLC0415

    html = ProbeResponse(method="GET", url="u", status_code=200, text="<html/>")
    maps_probe = next(p for p in PROBES if p.service == "Geocoding API")

    assert not _succeeded(maps_probe, html)


@pytest.mark.parametrize(
    "info",
    [
        pytest.param({}, id="no-metadata"),
        pytest.param({"metadata": "x"}, id="metadata-not-a-mapping"),
        pytest.param({"metadata": {}}, id="no-consumer"),
        pytest.param({"metadata": {"consumer": ""}}, id="empty-consumer"),
        pytest.param({"metadata": {"consumer": 7}}, id="consumer-not-a-string"),
    ],
)
def test_project_extraction_returns_none_when_absent(info: dict[str, object]) -> None:
    assert _project(info) is None


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first, second = run("google_valid"), run("google_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("google_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_detection_rules_still_load_from_the_shipped_file() -> None:
    """Guards against a rule edit that breaks the file the plugin relies on."""
    rules = Detector().rules()

    assert any(rule.provider == "google" for rule in rules)
