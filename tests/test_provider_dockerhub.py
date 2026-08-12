"""Docker Hub provider tests (roadmap R2.4).

Three things carry the weight here.

**Docker publishes its token prefixes in exactly one place, and it is not the
page about tokens.** The prose access-token pages give three permission levels
and no format. The OpenAPI specification examples both prefixes.
``test_the_rule_cites_the_specification_not_the_prose_page`` pins the citation,
because this item withdrew npm's rule for having no source at all and corrected
GitLab's for having the wrong one — a rule sourced to a page that does not
support it is the failure mode all three share.

**The prefix decides which endpoints exist.** Docker's specification says the
``identifier`` is a username for a personal token and an organization name for
an organization token, so ``test_the_wrong_kinds_endpoints_are_never_probed``
keeps keyreach from spending authentication traffic on paths that would 404 by
construction.

**A bare token is recognised and deliberately not probed.**
``test_a_token_with_no_identifier_is_answered_without_a_request`` — guessing a
username would produce a rejection that says nothing about whether the token is
live, which is a confident wrong verdict rather than a missing one.

**On the fixtures.** Every path was verified against Docker's live API, and the
invalid-credential body is the response that API actually returned, verbatim.
The success bodies are constructed from the schemas in Docker's own
specification; drift is roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

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
from keyreach.providers.dockerhub import (
    CONFIDENCE,
    HUB,
    PROBES,
    TOKEN_URL,
    Credential,
    DockerHubProvider,
    Kind,
    _summary,
    access_token,
    kind_of,
    message_of,
    parse_credential,
    probes_for,
    token_body,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Sequence

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
PAT = "dckr" + "_pat_" + "N0rthw1ndD0ckerHub00000"
OAT = "dckr" + "_oat_" + "N0rthw1ndD0ckerHub00000"
PERSONAL = "northwind:" + PAT
ORGANIZATION = "northwind-inc:" + OAT


def run(fixture: str, key: str = PERSONAL) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="dockerhub",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(status: int, body: str, url: str = TOKEN_URL) -> ProbeResponse:
    return ProbeResponse(
        method="POST",
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(DockerHubProvider(), origin="keyreach.providers.dockerhub")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "dockerhub" in [provider.name for provider in registry.providers()]


def test_it_is_a_devtools_provider() -> None:
    assert DockerHubProvider().category == "devtools"


def test_it_claims_no_prior_art() -> None:
    assert DockerHubProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sample", [PERSONAL, ORGANIZATION, PAT, OAT])
def test_it_claims_both_documented_prefixes_with_or_without_an_identifier(
    sample: str,
) -> None:
    assert DockerHubProvider().detect(sample) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    [
        "",
        "not-a-key",
        "dckr_pat_short",
        # A prefix Docker does not publish.
        "dckr_xyz_" + "a" * 24,
        "ghp_" + "a" * 36,
    ],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert DockerHubProvider().detect(sample) == 0.0


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "dockerhub-access-token")

    for sample in (PERSONAL, ORGANIZATION, PAT, OAT):
        assert re.match(rule["pattern"], sample), sample
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "dockerhub"


def test_the_rule_cites_the_specification_not_the_prose_page() -> None:
    """Docker's prose token pages document three permission levels and no format.

    The OpenAPI specification examples `dckr_pat_…` as the auth request's secret
    and `dckr_oat_…` as an organization token's value. That is the only place
    Docker publishes either, so it is the only citation that can be re-verified.
    """
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "dockerhub-access-token")

    assert rule["source"] == "https://docs.docker.com/reference/api/hub/latest/"


def test_the_detector_routes_the_credential_to_dockerhub() -> None:
    assert [match.provider for match in default_detector.detect(PERSONAL)] == [
        "dockerhub"
    ]


# ---------------------------------------------------------------------------
# The credential, and the two halves Docker requires
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (PERSONAL, Credential("northwind", PAT)),
        (ORGANIZATION, Credential("northwind-inc", OAT)),
        # A bare token names no account, so it is not a usable credential.
        (PAT, None),
        (":" + PAT, None),
        ("northwind:", None),
        ("northwind:not-a-docker-token", None),
    ],
)
def test_the_credential_is_split_on_the_last_colon(
    key: str, expected: Credential | None
) -> None:
    """Docker's identifiers are usernames and organization names, which cannot
    contain a colon; nothing published rules one out of the token."""
    assert parse_credential(key) == expected


@pytest.mark.parametrize(
    ("token", "kind"),
    [(PAT, Kind.PERSONAL), (OAT, Kind.ORGANIZATION)],
)
def test_the_kind_comes_from_the_documented_prefix(token: str, kind: Kind) -> None:
    assert kind_of(token) is kind


def test_the_exchange_body_is_the_documented_shape_and_is_stable() -> None:
    """Keyed by body in the per-run cache since R2.1, so the bytes must not vary."""
    body = token_body(Credential("northwind", PAT))

    assert json.loads(body) == {"identifier": "northwind", "secret": PAT}
    assert body == token_body(Credential("northwind", PAT))


# ---------------------------------------------------------------------------
# Probe routing
# ---------------------------------------------------------------------------


def test_each_probe_belongs_to_a_kind_or_to_both() -> None:
    personal = {probe.service for probe in probes_for(Kind.PERSONAL)}
    organization = {probe.service for probe in probes_for(Kind.ORGANIZATION)}

    assert personal | organization == {probe.service for probe in PROBES}
    # Repositories are namespaced, so both kinds reach them.
    assert personal & organization == {"Docker Hub Repositories"}


def test_the_wrong_kinds_endpoints_are_never_probed() -> None:
    """Docker says the identifier is a username for a PAT and an org for an OAT.

    Probing `/v2/orgs/<username>/members` would 404 by construction — wasted
    authentication traffic against somebody's production service, which
    `plan.md` §11 counts as a real cost.
    """

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "dockerhub_personal.json"),
            mode=RecordMode.REPLAY,
        )
        async with client:
            context = ProbeContext(client, PERSONAL)
            provider = DockerHubProvider()
            await provider.validate(PERSONAL, context)
            after_validate = client.requests_made
            await provider.enumerate(PERSONAL, context)
            return after_validate, client.requests_made

    mints, total = asyncio.run(measure())

    assert mints == 1
    assert total == 1 + len(probes_for(Kind.PERSONAL))
    assert len(probes_for(Kind.PERSONAL)) < len(PROBES)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_personal_token_maps_its_own_namespace() -> None:
    result = run("dockerhub_personal")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Docker Hub Personal Tokens",
        "Docker Hub Repositories",
    ]


def test_an_organization_token_maps_the_organization() -> None:
    result = run("dockerhub_organization", key=ORGANIZATION)

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Docker Hub Organization Members",
        "Docker Hub Organization Settings",
        "Docker Hub Organization Tokens",
        "Docker Hub Repositories",
    ]


def test_the_identifier_and_kind_are_the_identity() -> None:
    """Docker's specification publishes no "who am I" endpoint, so nothing is
    read to learn this — it is already in the credential."""
    identity = validation(run("dockerhub_organization", key=ORGANIZATION)).identity

    assert identity is not None
    assert identity.account == "northwind-inc"
    assert identity.extra == {"token_type": "organization"}


def test_no_capability_claims_a_write_docker_cannot_attribute_to_this_token() -> None:
    """Docker documents four PAT scopes and no endpoint that says which apply.

    The vocabulary exists and is not attributable, so keyreach reports what it
    proved and names the gap rather than leaving it silent — the same position
    Mailgun's plugin takes in R2.3.
    """
    capabilities = run("dockerhub_personal").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("repo:admin" in item.detail for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)


def test_a_token_with_no_identifier_is_answered_without_a_request() -> None:
    """Guessing a username would produce a rejection that says nothing."""
    result = run("dockerhub_invalid", key=PAT)
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "no request was made" in verdict.note
    assert "'<identifier>:<token>'" in verdict.note
    assert result.capabilities == ()


def test_a_rejected_credential_says_the_identifier_might_be_the_problem() -> None:
    """Docker rejects a wrong username and a dead token identically."""
    verdict = validation(run("dockerhub_invalid"))

    assert not verdict.valid
    assert verdict.note is not None
    assert "unauthorized" in verdict.note
    assert "check the name before concluding the token is revoked" in verdict.note


def test_neither_half_of_the_credential_appears_in_any_output() -> None:
    """`ctx.protect` is seeded with the token as well as the pasted pair."""
    for item in run("dockerhub_personal").capabilities:
        assert PAT not in item.evidence
        assert PERSONAL not in item.evidence
        assert item.poc is not None
        assert PAT not in item.poc


def test_the_proof_of_concept_shows_the_exchange_and_reads_nothing_else() -> None:
    for item in run("dockerhub_personal").capabilities:
        assert item.poc is not None
        # The one POST in the reproduction is the documented token exchange.
        assert item.poc.count("-X POST") == 1
        assert TOKEN_URL in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("dockerhub_personal"), run("dockerhub_personal")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


class _Stub:
    """A context that answers the exchange with one synthetic response."""

    def __init__(self, status: int, body: str) -> None:
        self._status = status
        self._body = body

    async def post(
        self,
        url: str,
        *,
        content: object = None,
        params: object = None,
        headers: object = None,
        read_only_post: bool = False,
    ) -> ProbeResponse:
        del url, content, params, headers, read_only_post
        return response(self._status, self._body)

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        return response(self._status, self._body, url=url)

    async def gather(
        self, awaitables: Sequence[Awaitable[ProbeResponse]]
    ) -> list[ProbeResponse]:
        return [await item for item in awaitables]

    def protect(self, secret: str) -> None:
        del secret

    def mask(self, text: str) -> str:
        return text

    @property
    def key(self) -> str:
        return PERSONAL


def validate_against(status: int, body: str) -> ValidationResult:
    return asyncio.run(
        DockerHubProvider().validate(PERSONAL, _Stub(status, body))  # type: ignore[arg-type]
    )


def test_a_rate_limited_exchange_still_means_the_credential_reached_docker() -> None:
    verdict = validate_against(429, '{"message":"too many requests"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"detail":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_a_200_carrying_no_token_is_not_a_successful_exchange() -> None:
    """Docker's success is the `access_token` field, not the status."""
    verdict = validate_against(200, "{}")

    assert not verdict.valid


def test_enumerate_claims_nothing_when_the_exchange_yields_no_token() -> None:
    capabilities = asyncio.run(
        DockerHubProvider().enumerate(PERSONAL, _Stub(200, "{}"))  # type: ignore[arg-type]
    )

    assert capabilities == []


def test_a_body_that_is_not_an_object_is_not_a_message() -> None:
    """Defensive parsing: an HTML error page must not read as a message."""
    assert message_of(response(502, "<html>bad gateway</html>")) == ""
    assert access_token(response(200, "<html>x</html>")) == ""


@pytest.mark.parametrize(
    ("service", "body", "expected"),
    [
        ("Docker Hub Repositories", '{"results":[]}', "none present"),
        ("Docker Hub Repositories", '{"count":0}', "request accepted"),
        # `/v2/orgs/{name}/members` returns a bare array, not an object.
        ("Docker Hub Organization Members", "[]", "none present"),
        ("Docker Hub Organization Members", '{"not":"a list"}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    service: str, body: str, expected: str
) -> None:
    probe = next(item for item in PROBES if item.service == service)

    assert expected in _summary(probe, response(200, body, url=f"{HUB}/v2/x"))
