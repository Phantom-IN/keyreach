"""GitLab provider tests (roadmap R2.4).

Two things carry the weight here.

**The rule's citation was wrong, and R2.3's discipline is what found it.**
keyreach has shipped `glpat-` since R0.5, sourced to GitLab's personal-access-
token guide. That page no longer names any prefix — it says only that tokens
"inherit the default prefix setting". The prefix *is* documented, on GitLab's
token-prefix table, so unlike Mailgun in R2.3 and npm in this item the rule
survives; only its `source` was wrong.
``test_the_rule_cites_a_page_that_actually_documents_the_prefix`` pins the
corrected citation, because a rule that points at the wrong page is a rule
nobody can re-verify, which is the whole failure mode.

**Access comes from GitLab's own statement of the token's scopes.**
``/personal_access_tokens/self`` returns them, so `write` and `admin` are read
off a documented sentence rather than a push keyreach made.
``test_a_scope_over_one_resource_does_not_elevate_another`` keeps that honest,
and ``test_api_and_the_admin_scopes_apply_everywhere_because_gitlab_says_so``
records the two exceptions and why they are exceptions.

**On the fixtures.** Every path was verified against GitLab's live API, and the
invalid-token body is the response that API actually returned, verbatim. The
success bodies are constructed from GitLab's documented shapes; drift is roadmap
**R2.10**.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    RecordMode,
)
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.gitlab import (
    ADMIN_SCOPES,
    API,
    API_SCOPE,
    CONFIDENCE,
    PROBES,
    SELF_URL,
    GitLabProvider,
    _detail,
    _identity,
    _Probe,
    _summary,
    access_for,
    is_active,
    message_of,
    scopes_of,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
KEY = "glpat" + "-" + "N0rthw1ndG1tL4b0000000"


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="gitlab",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str, url: str = SELF_URL) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


def probe(service: str) -> _Probe:
    return next(item for item in PROBES if item.service == service)


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(GitLabProvider(), origin="keyreach.providers.gitlab")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "gitlab" in [provider.name for provider in registry.providers()]


def test_it_is_a_devtools_provider() -> None:
    assert GitLabProvider().category == "devtools"


def test_it_claims_no_prior_art() -> None:
    assert GitLabProvider().credit is None


# ---------------------------------------------------------------------------
# Detection, and the citation R2.4 corrected
# ---------------------------------------------------------------------------


def test_it_claims_a_documented_token() -> None:
    assert GitLabProvider().detect(KEY) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-key",
        "glpat-short",
        # GitLab's deploy and runner tokens are different prefixes and are not
        # claimed here.
        "gldt-" + "a" * 24,
        "glrt-" + "a" * 24,
        "ghp_" + "a" * 36,
    ],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert GitLabProvider().detect(sample) == 0.0


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "gitlab-pat")

    assert re.match(rule["pattern"], KEY)
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "gitlab"


def test_the_rule_cites_a_page_that_actually_documents_the_prefix() -> None:
    """R2.4 re-verified the citation and found it pointed at the wrong page.

    GitLab documents `glpat-` on its token-prefix table. The personal-access-
    token guide the rule used to cite says only that tokens "inherit the default
    prefix setting configured for personal access tokens" — true, and not a
    format. A rule pointing at a page that does not support it cannot be
    re-verified, which is the failure R2.3 found at Mailgun; here the rule was
    right and only its citation was wrong, which is the cheaper half of it.
    """
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "gitlab-pat")

    assert rule["source"] == "https://docs.gitlab.com/security/tokens/"
    assert "personal_access_tokens" not in rule["source"]


def test_the_detector_routes_the_token_to_gitlab() -> None:
    assert [match.provider for match in default_detector.detect(KEY)] == ["gitlab"]


# ---------------------------------------------------------------------------
# The scope model
# ---------------------------------------------------------------------------


def test_api_and_the_admin_scopes_apply_everywhere_because_gitlab_says_so() -> None:
    """The two documented exceptions to per-resource matching.

    GitLab documents `api` as "complete read and write access to the API" and
    `sudo` as acting "as any user in the system", so both legitimately reach
    every capability. Everything else is matched per resource.
    """
    assert API_SCOPE == "api"
    assert frozenset({"admin_mode", "sudo"}) == ADMIN_SCOPES

    for item in PROBES:
        assert access_for(item, frozenset({API_SCOPE})) is AccessLevel.WRITE
        assert access_for(item, frozenset({"sudo"})) is AccessLevel.ADMIN
        assert access_for(item, frozenset({"admin_mode"})) is AccessLevel.ADMIN


def test_a_scope_over_one_resource_does_not_elevate_another() -> None:
    """`write_repository` pushes code; it does not administer a group."""
    scopes = frozenset({"read_api", "write_repository"})

    assert access_for(probe("GitLab Projects"), scopes) is AccessLevel.WRITE
    assert access_for(probe("GitLab Groups"), scopes) is AccessLevel.READ
    assert access_for(probe("GitLab Account"), scopes) is AccessLevel.READ


def test_read_scopes_never_raise_the_floor() -> None:
    read_only = frozenset({"read_api", "read_registry", "read_repository", "read_user"})

    for item in PROBES:
        assert access_for(item, read_only) is AccessLevel.READ


def test_no_scope_information_means_no_claim_either_way() -> None:
    """`None` scopes is "not determined", which is not "no write access"."""
    assert access_for(PROBES[0], None) is AccessLevel.READ
    assert access_for(PROBES[0], frozenset()) is AccessLevel.READ


@pytest.mark.parametrize(
    "body", ['{"scopes":"not a list"}', "[]", "<html>bad gateway</html>"]
)
def test_a_body_without_a_scope_list_yields_no_scopes(body: str) -> None:
    assert scopes_of(response(200, body)) is None


def test_a_refused_introspection_yields_no_scopes() -> None:
    assert scopes_of(response(403, '{"scopes":["api"]}')) is None


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_token_is_mapped() -> None:
    result = run("gitlab_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "GitLab Account",
        "GitLab Groups",
        "GitLab Projects",
    ]


def test_the_introspection_endpoint_is_read_once_for_the_whole_run() -> None:
    """`validate` and `enumerate` both need it; R1.4's cache makes that one call."""

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "gitlab_valid.json"), mode=RecordMode.REPLAY
        )
        async with client:
            context = ProbeContext(client, KEY)
            provider = GitLabProvider()
            await provider.validate(KEY, context)
            after_validate = client.requests_made
            await provider.enumerate(KEY, context)
            return after_validate, client.requests_made

    introspections, total = asyncio.run(measure())

    assert introspections == 1
    assert total == 1 + len(PROBES)


def test_a_write_scope_is_gitlabs_statement_not_a_push() -> None:
    projects = capability(run("gitlab_valid"), "GitLab Projects")

    assert projects.access is AccessLevel.WRITE
    assert projects.data_sensitive
    assert "No write was performed" in projects.detail


def test_the_token_record_is_the_identity() -> None:
    """The credential's own name and id — what the recipient revokes."""
    identity = validation(run("gitlab_valid")).identity

    assert identity is not None
    assert identity.account == "9900001"
    assert identity.owner == "ci-deploy"
    assert identity.extra["user_id"] == "410022"


def test_a_read_only_token_produces_only_reads() -> None:
    result = run("gitlab_read_only")

    assert {item.access for item in result.capabilities} == {AccessLevel.READ}
    assert "no scope granting write" in capability(result, "GitLab Groups").detail


def test_a_sudo_token_is_admin_everywhere() -> None:
    """ "Perform API actions as any user in the system" reaches everything."""
    result = run("gitlab_admin")

    assert {item.access for item in result.capabilities} == {AccessLevel.ADMIN}
    assert "as any user in the system" in capability(result, "GitLab Groups").detail


def test_an_inactive_token_is_reported_as_gitlab_describes_it() -> None:
    """GitLab answered, so the token authenticates — and it says it is inactive."""
    verdict = validation(run("gitlab_inactive"))

    assert verdict.valid
    assert verdict.note is not None
    assert "marks it inactive" in verdict.note


def test_a_rejected_token_says_only_gitlab_dot_com_was_probed() -> None:
    """Self-managed instances are not reachable, and a reader must not conclude
    the token is dead."""
    verdict = validation(run("gitlab_invalid"))

    assert not verdict.valid
    assert verdict.note is not None
    assert "401 Unauthorized" in verdict.note
    assert "self-managed instance" in verdict.note


def test_the_token_never_appears_in_any_output() -> None:
    for item in run("gitlab_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("gitlab_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("gitlab_valid"), run("gitlab_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic introspection response."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return response(status, body)

    return asyncio.run(GitLabProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_forbidden_introspection_leaves_scopes_undetermined() -> None:
    verdict = validate_against(403, '{"message":"403 Forbidden"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "lower bound" in verdict.note


def test_a_rate_limited_request_still_means_the_token_reached_gitlab() -> None:
    verdict = validate_against(429, '{"message":"Retry later"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"error":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_body_that_is_not_an_object_is_not_a_message() -> None:
    """Defensive parsing: an HTML error page must not read as a message."""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""
    assert is_active(response(200, "<html>x</html>")) is None
    assert is_active(response(200, '{"active":"yes"}')) is None


def test_a_record_naming_no_token_is_no_identity() -> None:
    assert _identity(response(200, '{"revoked":false}')) is None


def test_an_identity_omits_fields_gitlab_did_not_send() -> None:
    identity = _identity(response(200, '{"id":1,"name":"t"}'))

    assert identity is not None
    assert identity.extra == {}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("[]", "none present"),
        ('{"not":"a list"}', "request accepted"),
    ],
)
def test_a_listing_summary_carries_a_count_and_nothing_else(
    body: str, expected: str
) -> None:
    listing = probe("GitLab Groups")

    assert expected in _summary(listing, response(200, body, url=f"{API}/groups"))


def test_a_non_listing_probe_reports_only_that_it_was_accepted() -> None:
    assert _summary(probe("GitLab Account"), response(200, "{}")) == "request accepted"


def test_a_capability_with_no_scope_information_says_so_in_its_detail() -> None:
    """Reached when GitLab refuses introspection but answers the probes.

    Silence would read as "no write access"; this says the question was not
    answered, which is the difference `AccessLevel.UNKNOWN` exists to protect
    everywhere else.
    """

    assert "neither confirmed nor ruled out" in _detail(probe("GitLab Groups"), None)
