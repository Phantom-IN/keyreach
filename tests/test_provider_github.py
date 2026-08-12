"""GitHub provider tests (roadmap R1.6).

This is the first plugin that reports a **write** without performing one, so the
tests that matter are the ones policing where that claim comes from.

``test_write_access_is_read_out_of_the_documented_scope_header`` shows the
mechanism. ``test_a_scope_does_not_elevate_a_resource_it_does_not_cover`` is the
one that keeps it honest: a token holding ``repo`` can push code and cannot add
an organization member, so the organization capability stays ``read`` in the
same run where the repository capability is ``write``. And
``test_a_fine_grained_token_claims_only_the_read_it_confirmed`` covers the case
where GitHub sends no header at all — deliberately the weaker finding.

**On the fixtures.** They are constructed from GitHub's published response
shapes, not recorded from a live token; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.github import (
    API_VERSION,
    PROBES,
    SCOPES_HEADER,
    GitHubProvider,
    _identity,
    _scopes_from,
    _summary,
    access_for,
    is_fine_grained,
    scopes_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal (`tools/guardrails/no_secrets.py`).
CLASSIC = "ghp_" + "N0rthw1nd" + "A" * 27
FINE_GRAINED = "github_" + "pat_" + "N0rthw1nd" + "A" * 13 + "_" + "B" * 20


def run(fixture: str, key: str = CLASSIC) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
    )
    return asyncio.run(engine.run(key))


def response_with(scopes: str | None) -> ProbeResponse:
    headers = {} if scopes is None else {SCOPES_HEADER: scopes}
    return ProbeResponse(method="GET", url="u", status_code=200, headers=headers)


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(GitHubProvider(), origin="keyreach.providers.github")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "github" in [provider.name for provider in registry.providers()]


def test_it_is_a_devtools_provider() -> None:
    assert GitHubProvider().category == "devtools"


def test_it_claims_no_prior_art() -> None:
    assert GitHubProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param(CLASSIC, 0.99, id="classic-personal"),
        pytest.param("gho_" + "A" * 36, 0.99, id="oauth"),
        pytest.param("ghs_" + "A" * 36, 0.99, id="server-to-server"),
        pytest.param(FINE_GRAINED, 0.99, id="fine-grained"),
        pytest.param("ghx_" + "A" * 36, 0.0, id="unknown-letter"),
        pytest.param("ghp_" + "A" * 35, 0.0, id="too-short"),
        pytest.param("", 0.0, id="empty"),
        pytest.param("prefix" + CLASSIC, 0.0, id="not-anchored-at-start"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str, expected: float) -> None:
    assert GitHubProvider().detect(candidate) == expected


def test_detect_is_pure() -> None:
    provider = GitHubProvider()

    assert {provider.detect(CLASSIC) for _ in range(5)} == {0.99}


@pytest.mark.parametrize("key", [CLASSIC, FINE_GRAINED])
def test_the_plugin_and_the_rule_set_agree_on_the_token_format(key: str) -> None:
    """Two places describe a GitHub token. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["github"]
    assert GitHubProvider().detect(key) > 0.0


def test_the_two_token_families_are_told_apart_by_prefix() -> None:
    assert is_fine_grained(FINE_GRAINED)
    assert not is_fine_grained(CLASSIC)


def test_validation_reuses_a_probe_endpoint() -> None:
    assert validation_probe() in PROBES


# ---------------------------------------------------------------------------
# Scopes — the mechanism this plugin exists for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        pytest.param(None, None, id="absent-means-undescribed"),
        pytest.param("", frozenset(), id="empty-means-no-scopes"),
        pytest.param("repo", frozenset({"repo"}), id="one"),
        pytest.param(
            "read:org, repo, user",
            frozenset({"read:org", "repo", "user"}),
            id="documented-spacing",
        ),
        pytest.param("repo,,gist", frozenset({"repo", "gist"}), id="empty-entry"),
    ],
)
def test_scope_parsing_reads_the_documented_header(
    header: str | None, expected: frozenset[str] | None
) -> None:
    assert scopes_of(response_with(header)) == expected


def test_an_absent_header_and_an_empty_one_are_different_answers() -> None:
    """Collapsing them would give a fine-grained token a scopeless token's verdict."""
    assert scopes_of(response_with(None)) is None
    assert scopes_of(response_with("")) is not None


def test_write_access_is_read_out_of_the_documented_scope_header() -> None:
    repositories = next(p for p in PROBES if p.service == "GitHub Repositories")

    assert access_for(repositories, frozenset({"repo"})) is AccessLevel.WRITE
    assert access_for(repositories, frozenset({"delete_repo"})) is AccessLevel.ADMIN
    assert access_for(repositories, frozenset({"read:org"})) is AccessLevel.READ
    assert access_for(repositories, None) is AccessLevel.READ


def test_the_scope_list_is_taken_in_probe_order_not_arrival_order() -> None:
    """Probes run concurrently, so "the first response" must mean a fixed one."""
    responses = [response_with(None), response_with("gist"), response_with("repo")]

    assert _scopes_from(responses) == frozenset({"gist"})
    assert _scopes_from([response_with(None)]) is None


# ---------------------------------------------------------------------------
# The findings this provider exists to produce
# ---------------------------------------------------------------------------


def test_a_classic_token_with_repo_scope_is_critical() -> None:
    """Write access to private source code, established without writing."""
    result = run("github_valid")

    assert result.valid
    assert result.score.severity is Severity.CRITICAL

    repositories = next(
        c for c in result.capabilities if c.service == "GitHub Repositories"
    )
    assert repositories.access is AccessLevel.WRITE
    assert repositories.data_sensitive
    assert "The token holds repo" in repositories.detail
    assert "No write was attempted" in repositories.detail


def test_a_scope_does_not_elevate_a_resource_it_does_not_cover() -> None:
    """The over-reach a token-wide access level would produce, refused.

    The same token holds `repo`, which grants nothing over organization
    membership, so the organization capability stays a read in the very run
    where the repository capability is a write.
    """
    capabilities = {c.service: c for c in run("github_valid").capabilities}

    assert capabilities["GitHub Repositories"].access is AccessLevel.WRITE
    assert capabilities["GitHub Organizations"].access is AccessLevel.READ
    assert capabilities["GitHub Gists"].access is AccessLevel.READ
    assert "no more than read" in capabilities["GitHub Organizations"].detail


def test_the_account_and_its_scopes_are_named() -> None:
    """The scope list is what decides whether this is "can read" or "can push"."""
    identity = run("github_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "northwind-ops"
    assert identity.owner == "Northwind Ops"
    assert identity.plan_or_tier == "team"
    assert identity.extra == {"scopes": "read:org, repo, user"}


def test_a_fine_grained_token_claims_only_the_read_it_confirmed() -> None:
    """Deliberately the weaker finding: GitHub describes no scopes for these."""
    result = run("github_fine_grained", FINE_GRAINED)

    assert result.valid
    assert result.score.severity is Severity.HIGH
    assert all(c.access is AccessLevel.READ for c in result.capabilities)
    assert all("fine-grained token" in c.detail for c in result.capabilities)

    identity = result.outcomes[0].validation.identity
    assert identity is not None
    assert identity.extra == {}


def test_a_resource_a_fine_grained_token_cannot_reach_is_dropped() -> None:
    services = [
        c.service for c in run("github_fine_grained", FINE_GRAINED).capabilities
    ]

    assert "GitHub Email Addresses" not in services


def test_no_capability_claims_spend() -> None:
    """A GitHub token can burn Actions minutes; keyreach does not run a workflow."""
    assert not any(c.incurs_cost for c in run("github_valid").capabilities)


def test_the_api_version_is_pinned() -> None:
    """Following the newest default would let a GitHub release change output."""
    assert API_VERSION == "2022-11-28"

    poc = run("github_valid").capabilities[0].poc
    assert poc is not None
    assert f"X-GitHub-Api-Version: {API_VERSION}" in poc


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_invalid_token_is_reported_as_invalid_and_not_enumerated() -> None:
    result = run("github_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "Bad credentials" in result.outcomes[0].validation.note


def validate_against(status: int, payload: object) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://api.github.com/user",
                status_code=status,
                text=json.dumps(payload),
            )

    return asyncio.run(GitHubProvider().validate(CLASSIC, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_response_means_live_but_refused() -> None:
    """An IP allow list produces this. Calling it invalid retires a live token."""
    result = validate_against(403, {"message": "Resource protected by IP allow list"})

    assert result.valid  # type: ignore[attr-defined]
    assert "lower bound" in result.note  # type: ignore[attr-defined]
    assert "IP allow list" in result.note  # type: ignore[attr-defined]


def test_a_forbidden_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(403, {"unexpected": "shape"})

    assert result.valid  # type: ignore[attr-defined]
    assert "The token is live" in result.note  # type: ignore[attr-defined]


def test_a_rate_limit_still_means_the_token_is_live() -> None:
    result = validate_against(429, {"message": "Too many requests"})

    assert result.valid  # type: ignore[attr-defined]
    assert "--delay" in result.note  # type: ignore[attr-defined]


def test_an_unauthorised_response_without_a_message_still_reads_cleanly() -> None:
    result = validate_against(401, {"unexpected": "shape"})

    assert not result.valid  # type: ignore[attr-defined]
    assert result.note.endswith("this token")  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, {"message": "Server error"})

    assert not result.valid  # type: ignore[attr-defined]
    assert "Server error" in result.note  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_non_object_body_does_not_break_validation() -> None:
    """GitHub answers some errors with an array. That must not raise."""
    result = validate_against(500, ["unexpected"])

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_a_body_without_a_login_yields_no_identity() -> None:
    result = validate_against(200, {"id": 1})

    assert result.valid  # type: ignore[attr-defined]
    assert result.identity is None  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("<html/>", id="not-json"),
        pytest.param("[]", id="list"),
        pytest.param("null", id="null"),
    ],
)
def test_identity_parsing_degrades_instead_of_raising(body: str) -> None:
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _identity(response) is None


def test_a_token_with_no_scopes_at_all_says_so() -> None:
    """An empty header is a fact about the token, and it is reported as one."""
    response = ProbeResponse(
        method="GET",
        url="u",
        status_code=200,
        headers={SCOPES_HEADER: ""},
        text='{"login":"northwind-ops","plan":"not-an-object"}',
    )
    identity = _identity(response)

    assert identity is not None
    assert identity.extra == {"scopes": "none"}
    assert identity.plan_or_tier is None


# ---------------------------------------------------------------------------
# Evidence, determinism and hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<html/>", "request accepted", id="not-json"),
        pytest.param('{"login":"x"}', "request accepted", id="an-object"),
        pytest.param("[]", "private repositories: none present", id="empty"),
        pytest.param("[1]", "private repositories: 1 listed", id="one"),
        pytest.param("[1,2]", "private repositories: 2 listed", id="many"),
    ],
)
def test_the_evidence_summary_survives_any_body(body: str, expected: str) -> None:
    repositories = next(p for p in PROBES if p.service == "GitHub Repositories")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(repositories, response) == expected


def test_evidence_counts_items_and_does_not_quote_them() -> None:
    repositories = next(
        c
        for c in run("github_valid").capabilities
        if c.service == "GitHub Repositories"
    )

    assert "private repositories: 1 listed" in repositories.evidence
    assert "northwind/billing" not in repositories.evidence


def test_the_proof_of_concept_is_read_only_and_masked() -> None:
    for capability in run("github_valid").capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("curl -s ")
        assert "<key>" in capability.poc
        assert CLASSIC not in capability.poc


def test_repeated_runs_are_identical() -> None:
    first, second = run("github_valid"), run("github_valid")

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("github_valid").capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {c.service: c.resource_ref for c in run("github_valid").capabilities}

    for probe in PROBES:
        assert probe.source.startswith("https://")
        assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    services = [probe.service for probe in PROBES]

    assert len(services) == len(set(services))


def test_no_committed_fixture_contains_a_token() -> None:
    for name in ("valid", "fine_grained", "invalid"):
        text = (FIXTURES / f"github_{name}.json").read_text(encoding="utf-8")

        assert CLASSIC not in text
        assert FINE_GRAINED not in text
