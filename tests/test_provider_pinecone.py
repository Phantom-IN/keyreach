"""Pinecone provider tests (roadmap R2.5).

Two things carry the weight here.

**The prefix is published in one place, and it is not the page about keys.**
Pinecone's authentication page and its key-management guide both show only
``YOUR_API_KEY``; ``pc config set-api-key pcsk_abc123`` appears in the CLI
command reference. ``test_the_rule_cites_the_page_that_carries_the_prefix``
pins that citation — and the page was read rather than trusted to a search
result, because R2.4 found a search engine confidently reporting an npm token
format the cited page did not carry.

**Pinecone's rejection body is plain text.** ``Invalid API key``, with no JSON
envelope at all — verified against the live API and recorded verbatim in the
fixture. ``test_a_plain_text_rejection_is_quoted_and_an_html_page_is_not``
covers both halves: the message reaches the note, and a proxy's error page does
not get mistaken for one.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.pinecone import (
    API,
    API_VERSION,
    CONFIDENCE,
    PROBES,
    PineconeProvider,
    _summary,
    message_of,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "keyreach" / "patterns" / "detection_rules.yml"

#: Composed from parts, never written as one literal
#: (`tools/guardrails/no_secrets.py`).
KEY = "pcsk" + "_" + "N0rthw1ndP1neconeKey0000"


def run(fixture: str, key: str = KEY) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        force_provider="pinecone",
    )
    return asyncio.run(engine.run(key))


def capability(result: EngineResult, service: str) -> Capability:
    return next(item for item in result.capabilities if item.service == service)


def validation(result: EngineResult) -> ValidationResult:
    return result.outcomes[0].validation


def response(
    status: int,
    body: str,
    url: str = f"{API}/indexes",
    content_type: str = "text/plain",
) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=url,
        status_code=status,
        headers={"content-type": content_type},
        text=body,
    )


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    validate_provider(PineconeProvider(), origin="keyreach.providers.pinecone")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "pinecone" in [provider.name for provider in registry.providers()]


def test_it_is_a_database_provider() -> None:
    """R2.5 opens the `database` category, which `core/registry.py` allows."""
    assert PineconeProvider().category == "database"


def test_it_claims_no_prior_art() -> None:
    assert PineconeProvider().credit is None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_it_claims_a_documented_key() -> None:
    assert PineconeProvider().detect(KEY) == CONFIDENCE


@pytest.mark.parametrize(
    "sample",
    ["", "not-a-key", "pcsk_short", "sk-" + "a" * 40, "pc_" + "a" * 30],
)
def test_it_claims_nothing_else(sample: str) -> None:
    assert PineconeProvider().detect(sample) == 0.0


def test_the_shipped_rule_and_the_plugin_agree() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "pinecone-api-key")

    assert re.match(rule["pattern"], KEY)
    assert rule["confidence"] == CONFIDENCE
    assert rule["provider"] == "pinecone"


def test_the_rule_cites_the_page_that_carries_the_prefix() -> None:
    """Pinecone's key-management guide and auth page both show only a placeholder.

    `pc config set-api-key pcsk_abc123` is in the CLI command reference, which
    is therefore the only citation that can be re-verified.
    """
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    rule = next(item for item in rules if item["id"] == "pinecone-api-key")

    assert rule["source"] == "https://docs.pinecone.io/reference/cli/command-reference"


def test_the_detector_routes_the_key_to_pinecone() -> None:
    assert [match.provider for match in default_detector.detect(KEY)] == ["pinecone"]


# ---------------------------------------------------------------------------
# Probe table hygiene
# ---------------------------------------------------------------------------


def test_every_probe_is_under_the_documented_api_base() -> None:
    for probe in PROBES:
        assert probe.url.startswith(API)


def test_validation_uses_the_endpoint_pinecones_own_example_calls() -> None:
    assert validation_probe() in PROBES
    assert validation_probe().url == f"{API}/indexes"


def test_every_request_pins_the_api_version() -> None:
    """A future default must not change what keyreach reads."""
    poc = capability(run("pinecone_valid"), "Pinecone Indexes").poc

    assert poc is not None
    assert f"X-Pinecone-Api-Version: {API_VERSION}" in poc


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_a_live_key_yields_a_capability_map() -> None:
    result = run("pinecone_valid")

    assert result.valid
    assert [item.service for item in result.capabilities] == [
        "Pinecone Assistants",
        "Pinecone Backups",
        "Pinecone Collections",
        "Pinecone Indexes",
    ]


def test_the_index_list_is_counted_and_no_name_is_printed() -> None:
    indexes = capability(run("pinecone_valid"), "Pinecone Indexes")

    assert indexes.data_sensitive
    assert "indexes: 1 listed" in indexes.evidence
    assert "northwind-docs" not in indexes.evidence


def test_an_empty_collection_reads_as_none_present() -> None:
    assert (
        "none present" in capability(run("pinecone_valid"), "Pinecone Backups").evidence
    )


def test_no_capability_claims_a_write_pinecone_cannot_attribute() -> None:
    """A key that lists indexes can probably write them; Pinecone does not say so."""
    capabilities = run("pinecone_valid").capabilities

    assert capabilities
    assert all(item.access is AccessLevel.READ for item in capabilities)
    assert all("undetermined" in item.detail for item in capabilities)
    assert all("does not upsert a vector" in item.detail for item in capabilities)


def test_no_identity_is_invented() -> None:
    """Pinecone publishes no endpoint naming the project a key belongs to."""
    assert validation(run("pinecone_valid")).identity is None


def test_a_plain_text_rejection_is_quoted_and_an_html_page_is_not() -> None:
    """Pinecone answers a bad key with the bare bytes `Invalid API key`.

    A plugin that only parsed JSON would drop the one useful sentence; a plugin
    that quoted any body would put a proxy's HTML in the report.
    """
    assert message_of(response(401, "Invalid API key")) == "Invalid API key"
    assert message_of(response(502, "<html>\n<body>bad gateway</body>\n</html>")) == ""
    assert message_of(response(502, "x" * 500)) == ""
    assert (
        message_of(
            response(
                400,
                '{"error":{"message":"index not found"}}',
                content_type="application/json",
            )
        )
        == "index not found"
    )
    # An `error` object whose `message` is not a string is not a message either.
    assert message_of(response(400, '{"error":{"message":42}}')) == (
        '{"error":{"message":42}}'
    )


def test_a_rejected_key_quotes_what_pinecone_actually_said() -> None:
    result = run("pinecone_invalid")
    verdict = validation(result)

    assert not verdict.valid
    assert verdict.note == "Pinecone did not accept this key (Invalid API key)"
    assert result.capabilities == ()


def test_the_key_never_appears_in_any_output() -> None:
    for item in run("pinecone_valid").capabilities:
        assert KEY not in item.evidence
        assert item.poc is not None
        assert KEY not in item.poc


def test_the_proof_of_concept_is_read_only() -> None:
    for item in run("pinecone_valid").capabilities:
        assert item.poc is not None
        assert item.poc.startswith("curl -s")
        assert " -X " not in item.poc


def test_two_runs_agree_byte_for_byte() -> None:
    first, second = run("pinecone_valid"), run("pinecone_valid")

    assert [item.model_dump() for item in first.capabilities] == [
        item.model_dump() for item in second.capabilities
    ]


# ---------------------------------------------------------------------------
# Direct unit coverage for the branches a cassette cannot reach cheaply
# ---------------------------------------------------------------------------


def validate_against(status: int, body: str) -> ValidationResult:
    """Drive `validate()` against one synthetic response."""

    class _Stub:
        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return response(status, body)

    return asyncio.run(PineconeProvider().validate(KEY, _Stub()))  # type: ignore[arg-type]


def test_a_rate_limited_request_still_means_the_key_reached_pinecone() -> None:
    verdict = validate_against(429, "Too many requests")

    assert verdict.valid
    assert verdict.note is not None
    assert "--delay" in verdict.note


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    verdict = validate_against(500, "internal error")

    assert not verdict.valid
    assert verdict.note is not None
    assert "internal error" in verdict.note
    assert "not established either way" in verdict.note


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"indexes":[]}', "none present"),
        ('{"nothing":true}', "request accepted"),
    ],
)
def test_the_evidence_summary_carries_a_count_and_nothing_else(
    body: str, expected: str
) -> None:
    assert expected in _summary(validation_probe(), response(200, body))
