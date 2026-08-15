"""The declarative probe runner itself (roadmap R2.8).

`tests/test_provider_npm.py` and `tests/test_provider_pinecone.py` prove that
two real, migrated providers behave the way their old hand-written plugins
did. This module is the complement: it exercises `keyreach/core/probes.py` in
isolation, with synthetic specs built for the purpose, so every branch of the
runner's own parsing, cross-field validation and response-interpretation logic
is covered by something that says *why*, not just by two vendors that happen
to hit it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from keyreach.core.http import (
    Cassette,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    RecordMode,
)
from keyreach.core.models import AccessLevel, Capability, ValidationResult
from keyreach.core.probes import (
    ProbeSpecError,
    ProviderSpec,
    YamlProvider,
    _detail,
    _dotted,
    _message_of,
    _summary,
    load_provider_spec,
    load_yaml_provider,
)


def _probe(**overrides: Any) -> dict[str, Any]:
    base = {
        "service": "Widget List",
        "url": "https://api.example.invalid/widgets",
        "collection": "widgets",
        "noun": "widgets",
        "detail": "Can list the account's widgets",
        "access": "read",
        "risk_weight": 50,
        "data_sensitive": False,
        "incurs_cost": False,
        "source": "https://docs.example.invalid/widgets",
    }
    base.update(overrides)
    return base


def _spec(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "example",
        "category": "devtools",
        "docs_url": "https://docs.example.invalid/",
        "rotation_guide_url": "https://docs.example.invalid/rotate",
        "credit": None,
        "detectable": True,
        "description": "An example provider for roadmap R2.8's own tests.",
        "detect": {"pattern": "^ex_[A-Za-z0-9]{10,}$", "confidence": 0.9},
        "auth": {"headers": {"Authorization": "Bearer {key}"}},
        "error_fields": ["message"],
        "liveness": {
            "probe": "Widget List",
            "notes": {
                "unauthorized": "example did not accept this key{message_suffix}",
                "rate_limited": "rate limited{message_suffix}",
                "unparseable": "could not be interpreted{message_suffix}",
            },
        },
        "probes": [_probe()],
    }
    base.update(overrides)
    return base


def write_spec(path: Path, document: Any) -> Path:
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def response(
    status: int,
    body: str,
    *,
    url: str = "https://api.example.invalid/widgets",
    content_type: str = "application/json",
) -> ProbeResponse:
    return ProbeResponse(
        method="GET",
        url=url,
        status_code=status,
        headers={"content-type": content_type},
        text=body,
    )


# ---------------------------------------------------------------------------
# Loading — the happy path and every way a spec file can be wrong
# ---------------------------------------------------------------------------


def test_a_well_formed_spec_loads(tmp_path: Path) -> None:
    path = write_spec(tmp_path / "example.yml", _spec())

    spec = load_provider_spec(path)

    assert spec.name == "example"
    assert spec.probes[0].service == "Widget List"


def test_a_missing_file_is_a_probe_spec_error(tmp_path: Path) -> None:
    with pytest.raises(ProbeSpecError, match="could not read"):
        load_provider_spec(tmp_path / "nope.yml")


def test_invalid_yaml_is_a_probe_spec_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.yml"
    path.write_text("name: [unterminated", encoding="utf-8")

    with pytest.raises(ProbeSpecError, match="not valid YAML"):
        load_provider_spec(path)


def test_a_non_mapping_document_is_a_probe_spec_error(tmp_path: Path) -> None:
    path = tmp_path / "list.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(ProbeSpecError, match="must be a mapping"):
        load_provider_spec(path)


def test_a_spec_missing_a_required_field_is_a_probe_spec_error(tmp_path: Path) -> None:
    document = _spec()
    del document["docs_url"]
    path = write_spec(tmp_path / "incomplete.yml", document)

    with pytest.raises(ProbeSpecError, match="does not satisfy the provider spec"):
        load_provider_spec(path)


def test_an_invalid_detect_pattern_is_a_probe_spec_error(tmp_path: Path) -> None:
    document = _spec(detect={"pattern": "(unclosed", "confidence": 0.9})
    path = write_spec(tmp_path / "bad_pattern.yml", document)

    with pytest.raises(ProbeSpecError, match="invalid detect pattern"):
        load_provider_spec(path)


def test_load_yaml_provider_wraps_the_spec_and_remembers_its_path(
    tmp_path: Path,
) -> None:
    path = write_spec(tmp_path / "example.yml", _spec())

    provider = load_yaml_provider(path)

    assert isinstance(provider, YamlProvider)
    assert provider.name == "example"
    assert provider.source_path == path


# ---------------------------------------------------------------------------
# Cross-field validation
# ---------------------------------------------------------------------------


def test_a_detectable_provider_must_declare_a_detect_pattern() -> None:
    document = _spec()
    del document["detect"]

    with pytest.raises(ValidationError, match="must declare a `detect` pattern"):
        ProviderSpec.model_validate(document)


def test_an_undetectable_provider_may_not_declare_a_detect_pattern() -> None:
    document = _spec(detectable=False)

    with pytest.raises(ValidationError, match="meaningless when detectable is false"):
        ProviderSpec.model_validate(document)


def test_probe_services_must_be_unique() -> None:
    document = _spec(probes=[_probe(), _probe()])

    with pytest.raises(ValidationError, match="must be unique"):
        ProviderSpec.model_validate(document)


def test_the_liveness_probe_must_reference_a_declared_probe() -> None:
    document = _spec()
    document["liveness"]["probe"] = "Nonexistent Endpoint"

    with pytest.raises(ValidationError, match="is not one of the declared probes"):
        ProviderSpec.model_validate(document)


def test_a_probe_source_must_be_an_https_url() -> None:
    document = _spec(probes=[_probe(source="http://docs.example.invalid/widgets")])

    with pytest.raises(ValidationError, match="must start with https://"):
        ProviderSpec.model_validate(document)


def test_live_but_refused_statuses_need_a_matching_note() -> None:
    document = _spec()
    document["liveness"]["live_but_refused_statuses"] = [403]

    with pytest.raises(ValidationError, match="live_but_refused_statuses is set"):
        ProviderSpec.model_validate(document)


def test_a_status_cannot_appear_in_two_liveness_buckets() -> None:
    document = _spec()
    document["liveness"]["live_but_refused_statuses"] = [401]
    document["liveness"]["notes"]["live_but_refused"] = "refused{message_suffix}"

    with pytest.raises(ValidationError, match="can only mean one thing"):
        ProviderSpec.model_validate(document)


def test_probes_require_at_least_one_entry() -> None:
    document = _spec(probes=[])

    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(document)


def test_a_spec_rejects_unknown_fields() -> None:
    document = _spec()
    document["unexpected"] = "surprise"

    with pytest.raises(ValidationError):
        ProviderSpec.model_validate(document)


# ---------------------------------------------------------------------------
# Response interpretation
# ---------------------------------------------------------------------------


def test_dotted_resolves_a_nested_path() -> None:
    payload = {"error": {"message": "nope"}}

    assert _dotted(payload, "error.message") == "nope"


def test_dotted_resolves_a_flat_path() -> None:
    assert _dotted({"message": "nope"}, "message") == "nope"


def test_dotted_returns_none_for_a_missing_path() -> None:
    assert _dotted({"error": {}}, "error.message") is None


def test_dotted_returns_none_when_an_intermediate_value_is_not_a_mapping() -> None:
    assert _dotted({"error": "just a string"}, "error.message") is None


def test_message_of_tries_fields_in_declared_order() -> None:
    spec = ProviderSpec.model_validate(_spec(error_fields=["error", "message"]))

    assert _message_of(spec, response(401, '{"message": "fallback"}')) == "fallback"
    assert (
        _message_of(spec, response(401, '{"error": "first", "message": "second"}'))
        == "first"
    )


def test_message_of_ignores_a_non_string_field() -> None:
    spec = ProviderSpec.model_validate(_spec(error_fields=["error"]))

    assert _message_of(spec, response(401, '{"error": 42}')) == ""


def test_message_of_returns_empty_with_no_plain_text_fallback() -> None:
    spec = ProviderSpec.model_validate(_spec(plain_text_fallback=False))

    assert _message_of(spec, response(401, "Invalid API key")) == ""


def test_message_of_falls_back_to_a_short_single_line_body() -> None:
    spec = ProviderSpec.model_validate(_spec(plain_text_fallback=True))

    assert _message_of(spec, response(401, "Invalid API key")) == "Invalid API key"


def test_message_of_plain_text_fallback_rejects_multiline_bodies() -> None:
    spec = ProviderSpec.model_validate(_spec(plain_text_fallback=True))

    assert _message_of(spec, response(502, "line one\nline two")) == ""


def test_message_of_plain_text_fallback_rejects_long_bodies() -> None:
    spec = ProviderSpec.model_validate(_spec(plain_text_fallback=True))

    assert _message_of(spec, response(502, "x" * 201)) == ""


def test_summary_reads_the_whole_body_when_collection_is_unset() -> None:
    probe = next(
        p
        for p in ProviderSpec.model_validate(
            _spec(probes=[_probe(collection=None)])
        ).probes
    )

    assert _summary(probe, response(200, "[]")) == "widgets: none present"
    assert _summary(probe, response(200, '[{"id": 1}]')) == "widgets: 1 listed"
    assert _summary(probe, response(200, '{"not": "a list"}')) == "request accepted"


def test_summary_reads_the_named_collection() -> None:
    probe = ProviderSpec.model_validate(_spec()).probes[0]

    assert _summary(probe, response(200, '{"widgets": []}')) == "widgets: none present"
    assert _summary(probe, response(200, '{"widgets": [1, 2]}')) == "widgets: 2 listed"
    assert _summary(probe, response(200, "{}")) == "request accepted"


def test_detail_appends_the_scope_statement_when_set() -> None:
    spec = ProviderSpec.model_validate(_spec(scope_statement="write is undetermined"))

    assert _detail(spec, spec.probes[0]) == (
        "Can list the account's widgets. write is undetermined"
    )


def test_detail_is_unchanged_with_no_scope_statement() -> None:
    spec = ProviderSpec.model_validate(_spec())

    assert _detail(spec, spec.probes[0]) == "Can list the account's widgets"


# ---------------------------------------------------------------------------
# YamlProvider end to end, against a synthetic spec
# ---------------------------------------------------------------------------


def test_detect_returns_zero_with_no_pattern(tmp_path: Path) -> None:
    document = _spec(detectable=False)
    del document["detect"]
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", document))

    assert provider.detect("anything") == 0.0


def test_detect_matches_the_declared_pattern(tmp_path: Path) -> None:
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", _spec()))

    assert provider.detect("ex_abcdefghij") == pytest.approx(0.9)
    assert provider.detect("nope") == 0.0


def test_repr_names_the_provider_and_its_source(tmp_path: Path) -> None:
    path = write_spec(tmp_path / "spec.yml", _spec())
    provider = load_yaml_provider(path)

    text = repr(provider)

    assert "example" in text
    assert "spec.yml" in text


class _CassetteContext:
    """A minimal stand-in for `ProbeContext`, driven from a status/body map."""

    def __init__(self, answers: dict[str, tuple[int, str]]) -> None:
        self._answers = answers
        self.key = "ex_abcdefghijklmnop"

    def mask(self, text: str) -> str:
        return text.replace(self.key, "<key>")

    async def get(
        self, url: str, *, params: object = None, headers: object = None
    ) -> ProbeResponse:
        del params, headers
        status, body = self._answers[url]
        return response(status, body, url=url)

    async def gather(self, awaitables: list[Any]) -> list[Any]:
        return list(await asyncio.gather(*awaitables))


def test_enumerate_returns_a_capability_for_a_successful_probe(tmp_path: Path) -> None:
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", _spec()))
    ctx = _CassetteContext(
        {"https://api.example.invalid/widgets": (200, '{"widgets": ["a"]}')}
    )

    capabilities = asyncio.run(provider.enumerate(ctx.key, ctx))  # type: ignore[arg-type]

    assert len(capabilities) == 1
    assert capabilities[0].access is AccessLevel.READ
    assert capabilities[0].evidence.endswith("widgets: 1 listed")
    assert capabilities[0].poc is not None
    assert "Bearer <key>" in capabilities[0].poc


def test_enumerate_drops_a_failed_probe(tmp_path: Path) -> None:
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", _spec()))
    ctx = _CassetteContext({"https://api.example.invalid/widgets": (403, "")})

    capabilities = asyncio.run(provider.enumerate(ctx.key, ctx))  # type: ignore[arg-type]

    assert capabilities == []


@pytest.mark.parametrize(
    ("status", "body", "expect_valid", "note_fragment"),
    [
        (200, "{}", True, None),
        (401, "", False, "did not accept"),
        (429, "", True, "rate limited"),
        (418, "", False, "could not be interpreted"),
    ],
)
def test_validate_classifies_every_status_bucket(
    tmp_path: Path,
    status: int,
    body: str,
    expect_valid: bool,
    note_fragment: str | None,
) -> None:
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", _spec()))
    ctx = _CassetteContext({"https://api.example.invalid/widgets": (status, body)})

    result = asyncio.run(provider.validate(ctx.key, ctx))  # type: ignore[arg-type]

    assert result.valid is expect_valid
    if note_fragment is not None:
        assert result.note is not None
        assert note_fragment in result.note


def test_validate_classifies_live_but_refused_when_declared(tmp_path: Path) -> None:
    document = _spec()
    document["liveness"]["live_but_refused_statuses"] = [403]
    document["liveness"]["notes"]["live_but_refused"] = "refused{message_suffix}"
    provider = load_yaml_provider(write_spec(tmp_path / "spec.yml", document))
    ctx = _CassetteContext({"https://api.example.invalid/widgets": (403, "")})

    result = asyncio.run(provider.validate(ctx.key, ctx))  # type: ignore[arg-type]

    assert result.valid is True
    assert result.note == "refused"


def test_the_real_probe_context_surface_is_enough_for_a_yaml_provider(
    tmp_path: Path,
) -> None:
    """`YamlProvider` must work against the real `ProbeContext`, not only the
    stub above — same discipline `test_provider_contract.py` holds every
    other plugin to.
    """
    path = write_spec(tmp_path / "spec.yml", _spec())
    provider = load_yaml_provider(path)
    cassette_path = tmp_path / "cassette.json"
    cassette_path.write_text(
        '{"interactions": [{"method": "GET", '
        '"url": "https://api.example.invalid/widgets", "status_code": 200, '
        '"headers": {}, "body": "{\\"widgets\\": []}"}]}',
        encoding="utf-8",
    )
    client = ProbeClient(
        cassette=Cassette(cassette_path),
        mode=RecordMode.REPLAY,
    )

    async def _run() -> tuple[ValidationResult, list[Capability]]:
        async with client:
            context = ProbeContext(client, "ex_abcdefghijklmnop")
            validation = await provider.validate(context.key, context)
            capabilities = await provider.enumerate(context.key, context)
            return validation, capabilities

    validation, capabilities = asyncio.run(_run())

    assert validation.valid is True
    assert len(capabilities) == 1
