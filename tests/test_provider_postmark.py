"""Postmark provider tests (roadmap R2.3).

The thing worth reading here is **kind discovery**.

Postmark has two token types with two very different blast radii, they look
identical, and Postmark publishes no format for either. So the plugin asks:
both headers are tried, and Postmark's refusal names the one it wanted — "…a
valid Server token" against "…a valid Account token".
``test_a_server_token_is_recognised_by_which_header_postmark_accepts`` and its
account counterpart run that end to end, and
``test_the_wrong_kinds_endpoints_are_never_probed`` pins the restraint: once the
kind is known, the other table's endpoints are not authentication traffic worth
spending against a stranger's service.

``test_the_servers_other_tokens_are_counted_and_never_printed`` covers the
second finding. ``GET /server`` returns the server's other API tokens. The count
is what a recipient needs — it says how many more credentials this one leak
exposed — and the tokens themselves never reach the report.

**On the fixtures.** Every path was verified against Postmark's live API, and
both refusal bodies are the responses that API actually returned, verbatim. The
success bodies are constructed from Postmark's documented shapes; drift is
roadmap **R2.10**.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

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
from keyreach.providers.postmark import (
    API,
    HEADERS,
    PROBES,
    Kind,
    PostmarkProvider,
    _identity,
    _summary,
    headers_for,
    message_of,
    probes_for,
    validation_probe,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Sequence

FIXTURES = Path(__file__).parent / "fixtures"

#: Postmark tokens are UUID-shaped in practice and undocumented in form, so this
#: is a placeholder rather than a claim about the format.
TOKEN = "00000000-0000-4000-8000-0000000000ff"  # noqa: S105 - a placeholder

SEND = "Postmark Email Send"


def run(fixture: str, key: str = TOKEN) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="postmark",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(PostmarkProvider(), origin="keyreach.providers.postmark")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "postmark" in [provider.name for provider in registry.providers()]


def test_it_is_an_email_provider() -> None:
    assert PostmarkProvider().category == "email"


def test_it_claims_no_prior_art() -> None:
    assert PostmarkProvider().credit is None


def test_it_is_not_a_detection_candidate() -> None:
    """Postmark publishes no format for either token type."""
    assert PostmarkProvider().detectable is False


@pytest.mark.parametrize(
    "sample",
    [TOKEN, "", "not-a-key", "00000000-0000-0000-0000-000000000000", "x" * 64],
)
def test_detect_claims_nothing_at_all(sample: str) -> None:
    """A UUID rule would claim every UUID on the internet.

    The same argument that kept Coinbase out in R2.1, met again in a different
    industry.
    """
    assert PostmarkProvider().detect(sample) == 0.0


# ---------------------------------------------------------------------------
# The two kinds of token
# ---------------------------------------------------------------------------


def test_each_kind_has_its_own_documented_header() -> None:
    assert HEADERS == {
        Kind.SERVER: "X-Postmark-Server-Token",
        Kind.ACCOUNT: "X-Postmark-Account-Token",
    }
    assert headers_for(Kind.SERVER, TOKEN) == {
        "X-Postmark-Server-Token": TOKEN,
        # Not decoration: without it the bounce endpoint answers 409 about
        # Content-Type, a refusal that has nothing to do with the credential
        # and would otherwise read as one.
        "Accept": "application/json",
    }


def test_every_probe_belongs_to_exactly_one_kind() -> None:
    server = {probe.service for probe in probes_for(Kind.SERVER)}
    account = {probe.service for probe in probes_for(Kind.ACCOUNT)}

    assert server | account == {probe.service for probe in PROBES}
    assert not server & account


def test_the_two_liveness_endpoints_are_one_character_apart() -> None:
    """`/server` and `/servers` are how Postmark names the token type it wanted.

    Picking the liveness probe by anything but its name — "the one with no
    paging parameters", say — breaks silently the moment a probe table gains a
    parameter, which is how the first draft of this plugin got it wrong.
    """
    assert validation_probe(Kind.SERVER).url == f"{API}/server"
    assert validation_probe(Kind.ACCOUNT).url == f"{API}/servers"


def test_account_endpoints_are_admin_and_server_endpoints_are_write() -> None:
    """Postmark's own sentences, not an inference from what a read returned.

    Every Servers API operation — including create and delete — is documented as
    requiring the account token, "only accessible by the account owner". Edit
    Server and the send endpoint require the server token.
    """
    assert {probe.access for probe in probes_for(Kind.ACCOUNT)} == {AccessLevel.ADMIN}
    assert {probe.access for probe in probes_for(Kind.SERVER)} == {AccessLevel.WRITE}


def test_a_body_that_is_not_an_object_is_not_a_message() -> None:
    """Defensive parsing: an HTML error page must not read as a message."""
    html = ProbeResponse(
        method="GET",
        url=f"{API}/server",
        status_code=502,
        headers={},
        text="<html>bad gateway</html>",
    )

    assert message_of(html) == ""


# ---------------------------------------------------------------------------
# Kind discovery, end to end
# ---------------------------------------------------------------------------


def test_a_server_token_is_recognised_by_which_header_postmark_accepts() -> None:
    result = run("postmark_server")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.identity is not None
    assert verdict.identity.extra["token_type"] == "server"  # noqa: S105 - a kind
    assert verdict.identity.extra["server"] == "northwind-transactional"


def test_an_account_token_is_recognised_by_which_header_postmark_accepts() -> None:
    result = run("postmark_account")
    verdict = validation(result)

    assert verdict.valid
    assert verdict.identity is not None
    assert verdict.identity.extra["token_type"] == "account"  # noqa: S105 - a kind


def test_the_wrong_kinds_endpoints_are_never_probed() -> None:
    """Once the kind is known, the other table is not worth a request.

    Both liveness endpoints are tried — that is how the kind is discovered — but
    the losing kind's remaining probes are never sent. For a server token that
    is two requests saved against somebody's production service, and the count
    is measured rather than asserted.
    """

    async def measure() -> tuple[int, int]:
        client = ProbeClient(
            cassette=Cassette(FIXTURES / "postmark_server.json"),
            mode=RecordMode.REPLAY,
        )
        async with client:
            context = ProbeContext(client, TOKEN)
            provider = PostmarkProvider()
            await provider.validate(TOKEN, context)
            after_validate = client.requests_made
            await provider.enumerate(TOKEN, context)
            return after_validate, client.requests_made

    discovery, total = asyncio.run(measure())

    # One request per kind to discover which this is...
    assert discovery == len(Kind)
    # ...and then only the server probes, with the two already-made calls served
    # from R1.4's per-run cache.
    assert total == len(Kind) + len(probes_for(Kind.SERVER)) - 1


def test_a_server_token_maps_the_server_and_its_mail() -> None:
    result = run("postmark_server")

    assert [item.service for item in result.capabilities] == [
        "Postmark Bounces",
        SEND,
        "Postmark Message Streams",
        "Postmark Server",
    ]


def test_no_probe_reaches_a_path_the_ai_ban_forbids() -> None:
    """The guardrail cost this plugin a probe, and that is the correct outcome.

    Postmark's outbound-mail search sits under the same lowercase path as an
    inference endpoint `ai_ban` forbids, and nothing in a line of source
    separates an email vendor's sent-mail archive from a model endpoint — only
    the host does, and `ai_ban` bans paths rather than hosts on purpose. The
    probe was dropped and the bounce list carries the recipient-data finding.
    Restoring it would fail `ai_ban`, which is the point.
    """
    assert [probe.service for probe in PROBES if "outbound" in probe.url] == []
    assert "Postmark Bounces" in [probe.service for probe in PROBES]


def test_an_account_token_maps_the_whole_account_as_admin() -> None:
    result = run("postmark_account")

    assert [item.service for item in result.capabilities] == [
        "Postmark Domains",
        "Postmark Sender Signatures",
        "Postmark Servers",
    ]
    assert {item.access for item in result.capabilities} == {AccessLevel.ADMIN}
    assert SEND not in [item.service for item in result.capabilities]


def test_the_servers_other_tokens_are_counted_and_never_printed() -> None:
    """The count is the finding; the tokens are not keyreach's to republish."""
    server = capability(run("postmark_server"), "Postmark Server")

    assert "2 API tokens on it" in server.evidence
    assert "ApiTokens" not in server.evidence


def test_the_send_capability_is_derived_and_nothing_was_sent() -> None:
    send = capability(run("postmark_server"), SEND)

    assert send.access is AccessLevel.WRITE
    assert send.incurs_cost
    assert "No message was sent" in send.detail
    assert send.poc is not None
    assert send.poc.startswith("curl -s")


def test_a_token_postmark_takes_neither_way_is_reported_as_rejected() -> None:
    result = run("postmark_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note is not None
    assert "neither a server token nor an account token" in verdict.note
    # Both refusals are quoted, so a reader can see both were genuinely tried.
    assert "valid Server token" in verdict.note
    assert "valid Account token" in verdict.note
    assert result.capabilities == ()


def test_the_token_never_appears_in_any_output() -> None:
    for fixture in ("postmark_server", "postmark_account"):
        for item in run(fixture).capabilities:
            assert TOKEN not in item.evidence
            assert item.poc is not None
            assert TOKEN not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("postmark_server").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("postmark_server"), run("postmark_server")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def response(status: int, body: str, url: str = f"{API}/server") -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=url,
        status_code=status,
        headers={"content-type": "application/json"},
        text=body,
    )


class _Stub:
    """A context that answers every probe with the same synthetic response."""

    def __init__(self, status: int, body: str) -> None:
        self._status = status
        self._body = body

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        return response(self._status, self._body, url=url)

    async def gather(
        self, awaitables: Sequence[Awaitable[ProbeResponse]]
    ) -> list[ProbeResponse]:
        return [await item for item in awaitables]


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic response for both kinds."""
    return asyncio.run(
        PostmarkProvider().validate(TOKEN, _Stub(status, body))  # type: ignore[arg-type]
    )


def test_a_rate_limited_request_still_means_the_token_reached_postmark() -> None:
    verdict = validate_against(429, '{"ErrorCode":0,"Message":"Rate limit exceeded"}')

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, '{"ErrorCode":0,"Message":"internal error"}')

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


def test_enumerate_claims_nothing_when_neither_header_is_accepted() -> None:
    """`validate` stops the run first; this is the belt to that pair of braces."""
    refused = _Stub(
        401,
        '{"ErrorCode":10,"Message":"Request does not contain a valid Server token."}',
    )
    capabilities = asyncio.run(
        PostmarkProvider().enumerate(TOKEN, refused)  # type: ignore[arg-type]
    )

    assert capabilities == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # `/server` carries no collection, so the count is of its API tokens.
        ('{"Name":"x"}', "request accepted"),
        ('{"ApiTokens":[]}', "0 API tokens on it"),
    ],
)
def test_the_server_summary_counts_tokens_when_there_are_any(
    body: str, expected: str
) -> None:

    probe = next(p for p in PROBES if p.service == "Postmark Server")

    assert expected in _summary(probe, response(200, body))


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"TotalCount":0}', "request accepted"),
        ('{"Bounces":[]}', "none present"),
    ],
)
def test_a_list_summary_carries_a_count_and_nothing_else(
    body: str, expected: str
) -> None:

    probe = next(p for p in PROBES if p.service == "Postmark Bounces")

    assert expected in _summary(probe, response(200, body))


def test_an_identity_omits_a_server_name_postmark_did_not_send() -> None:

    identity = _identity(Kind.ACCOUNT, response(200, '{"TotalCount":6}'))

    assert identity.extra == {"token_type": "account"}
