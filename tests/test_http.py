"""HTTP layer tests (roadmap R0.6).

R0.6's acceptance criteria are three properties of this module, and each has a
section below:

* probes run only through ``ProbeContext``
* non-idempotent methods are default-denied
* keys are masked in recordings

Every secret in this file is synthetic and composed from parts rather than
written as a literal, for the reason documented at the top of
``tests/test_detect.py``: a structurally valid key literal trips secret scanners
even when the value is worthless.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from keyreach.core.http import (
    DEFAULT_CONCURRENCY,
    IDEMPOTENT_METHODS,
    REDACTED_PLACEHOLDER,
    RETRY_DELAYS,
    RETRY_STATUSES,
    Cassette,
    CassetteError,
    ProbeClient,
    ProbeContext,
    ProbeResponse,
    ProbeTransportError,
    ReadOnlyViolationError,
    RecordMode,
    Redactor,
    mask_key,
)

SECRET = "sk-" + "live" + "-" + "abcdefghijklmnopqrstuvwxyz012345"
OTHER_SECRET = "AIza" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"

API = "https://api.example.invalid/v1/whoami"


def responder(
    status: int = 200,
    body: str = '{"ok": true}',
    headers: dict[str, str] | None = None,
) -> httpx.MockTransport:
    """A transport that always answers the same way."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body, headers=headers or {})

    return httpx.MockTransport(handle)


def client(**kwargs: object) -> ProbeClient:
    kwargs.setdefault("redactor", Redactor([SECRET]))
    kwargs.setdefault("transport", responder())
    return ProbeClient(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------


def test_mask_preserves_prefix_and_suffix_and_length() -> None:
    """The documented fingerprint shape (see models.Report.key_fingerprint)."""
    masked = mask_key(OTHER_SECRET)

    assert masked.startswith("AIza")
    assert masked.endswith(OTHER_SECRET[-3:])
    assert len(masked) == len(OTHER_SECRET)
    assert OTHER_SECRET not in masked


@pytest.mark.parametrize("key", ["", "a", "short", "elevenchars"])
def test_short_keys_are_masked_completely(key: str) -> None:
    """A prefix-plus-suffix on a short token would disclose most of it."""
    masked = mask_key(key)

    assert set(masked) <= {"*"}
    assert len(masked) == len(key)


def test_mask_is_deterministic() -> None:
    assert mask_key(SECRET) == mask_key(SECRET)


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


def test_redactor_replaces_the_secret_anywhere_in_text() -> None:
    redacted = Redactor([SECRET]).redact(f"GET /v1?key={SECRET} failed for {SECRET}")

    assert SECRET not in redacted
    assert redacted.count(REDACTED_PLACEHOLDER) == 2


def test_redactor_handles_percent_encoded_secrets() -> None:
    """A key in a query string is URL-encoded by the client.

    Matching only the raw value would let the encoded form through — into a
    cassette that then gets committed.
    """
    secret = "sk-" + "a/b+c" + "=" * 2 + "defghijklmnop"
    redacted = Redactor([secret]).redact(
        "https://x.invalid/?k=sk-a%2Fb%2Bc%3D%3Ddefghijklmnop"
    )

    assert "%2F" not in redacted


def test_redactor_ignores_values_too_short_to_be_secrets() -> None:
    """Redacting a 3-character string would corrupt unrelated output."""
    assert Redactor(["abc"]).redact("abcdef") == "abcdef"


def test_redactor_replaces_longest_secret_first() -> None:
    """A secret containing another must not be left partially recognisable."""
    outer = SECRET + "-extended-suffix"
    redacted = Redactor([SECRET, outer]).redact(outer)

    assert SECRET not in redacted


def test_credential_headers_are_dropped_wholesale() -> None:
    """Covers credentials keyreach was never told about.

    The redactor only knows the key under test. A second bearer token or a
    session cookie has no registered secret, so pattern replacement would miss
    it entirely.
    """
    redacted = Redactor([SECRET]).redact_headers(
        {
            "Authorization": "Bearer an-unrelated-token-we-never-registered",
            "Cookie": "session=somethingsecret",
            "Content-Type": "application/json",
        }
    )

    assert redacted["authorization"] == "<redacted>"
    assert redacted["cookie"] == "<redacted>"
    assert redacted["content-type"] == "application/json"


def test_header_names_are_lower_cased() -> None:
    """Servers disagree about header casing; a provider lookup must not.

    Preserving the server's casing would also reshuffle cassettes between
    recordings against different endpoints.
    """
    redacted = Redactor().redact_headers({"Content-Type": "application/json"})

    assert list(redacted) == ["content-type"]


def test_redacted_headers_are_sorted() -> None:
    """Header order from a server is not reproducible; ours must be."""
    redacted = Redactor().redact_headers({"z": "1", "a": "2", "m": "3"})

    assert list(redacted) == ["a", "m", "z"]


def test_unmask_disables_redaction() -> None:
    """`--unmask` is explicit opt-in, and must actually work."""
    assert Redactor([SECRET], unmask=True).redact(SECRET) == SECRET


# --------------------------------------------------------------------------
# Read-only guard — R0.6 acceptance criterion
# --------------------------------------------------------------------------


@pytest.mark.parametrize("method", sorted(IDEMPOTENT_METHODS))
def test_idempotent_methods_are_allowed(method: str) -> None:
    ProbeClient.check_method(method)


def test_post_is_denied_by_default() -> None:
    with pytest.raises(ReadOnlyViolationError, match="denied by default"):
        ProbeClient.check_method("POST")


def test_post_is_allowed_only_with_an_explicit_annotation() -> None:
    """The RPC-style-read escape hatch (implementation_plan.md §6)."""
    ProbeClient.check_method("POST", read_only_post=True)


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_write_methods_are_never_permitted(method: str) -> None:
    """Not even with the annotation — there is no read-shaped PUT or DELETE."""
    with pytest.raises(ReadOnlyViolationError, match="never permitted"):
        ProbeClient.check_method(method, read_only_post=True)


def test_method_check_is_case_insensitive() -> None:
    ProbeClient.check_method("get")
    with pytest.raises(ReadOnlyViolationError):
        ProbeClient.check_method("delete")


async def test_context_post_is_denied_by_default() -> None:
    """The guard applies through the surface providers actually use."""
    async with client() as probe_client:
        context = ProbeContext(probe_client, SECRET)

        with pytest.raises(ReadOnlyViolationError):
            await context.post(API)


async def test_context_post_succeeds_when_annotated() -> None:
    async with client() as probe_client:
        context = ProbeContext(probe_client, SECRET)
        response = await context.post(API, read_only_post=True)

    assert response.status_code == 200


async def test_denied_request_never_reaches_the_transport() -> None:
    """The guard must refuse before any socket work, not after."""
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200)

    async with client(transport=httpx.MockTransport(handle)) as probe_client:
        context = ProbeContext(probe_client, SECRET)
        with pytest.raises(ReadOnlyViolationError):
            await context.post(API)

    assert seen == []


# --------------------------------------------------------------------------
# Requests through ProbeContext
# --------------------------------------------------------------------------


async def test_get_returns_a_redacted_response() -> None:
    async with client(transport=responder(body=f'{{"key": "{SECRET}"}}')) as c:
        context = ProbeContext(c, SECRET)
        response = await context.get(API, params={"key": SECRET})

    assert SECRET not in response.url
    assert SECRET not in response.text
    assert REDACTED_PLACEHOLDER in response.url


async def test_response_body_echoing_the_key_is_redacted() -> None:
    """Providers really do echo the key back in error messages."""
    body = json.dumps({"error": f"invalid key {SECRET}"})
    async with client(transport=responder(status=401, body=body)) as c:
        context = ProbeContext(c, SECRET)
        response = await context.get(API)

    assert SECRET not in response.text
    assert response.json_body()["error"].endswith(REDACTED_PLACEHOLDER)


async def test_response_headers_are_redacted() -> None:
    async with client(transport=responder(headers={"X-Echo": SECRET})) as c:
        context = ProbeContext(c, SECRET)
        response = await context.get(API)

    assert SECRET not in response.headers["x-echo"]


def test_probe_response_helpers() -> None:
    response = ProbeResponse(method="GET", url=API, status_code=200, text='{"a": 1}')

    assert response.ok
    assert response.json_body() == {"a": 1}
    assert response.evidence("1 item") == f"GET {API} -> 200, 1 item"
    assert response.evidence() == f"GET {API} -> 200"


def test_probe_response_json_or_none_tolerates_non_json() -> None:
    """Probed endpoints return HTML error pages and empty bodies too."""
    response = ProbeResponse(
        method="GET", url=API, status_code=503, text="<html>down</html>"
    )

    assert response.json_or_none() is None
    assert not response.ok


async def test_context_exposes_the_masked_key_not_the_raw_one() -> None:
    async with client() as c:
        context = ProbeContext(c, SECRET)

        assert context.masked_key == mask_key(SECRET)
        assert context.key == SECRET
        assert SECRET not in repr(context)


async def test_context_masked_key_honours_unmask() -> None:
    async with client(redactor=Redactor([SECRET], unmask=True)) as c:
        assert ProbeContext(c, SECRET).masked_key == SECRET


async def test_context_registers_its_key_for_redaction() -> None:
    """A context built with a key the redactor did not know still redacts it."""
    async with client(redactor=Redactor()) as c:
        context = ProbeContext(c, SECRET)

        assert context.mask(f"saw {SECRET}") == f"saw {REDACTED_PLACEHOLDER}"


async def test_gather_preserves_input_order_not_completion_order() -> None:
    """Completion order depends on network timing and is not reproducible."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=request.url.params.get("n", ""))

    async with client(transport=httpx.MockTransport(handle)) as c:
        context = ProbeContext(c, SECRET)
        results = await context.gather(
            [context.get(API, params={"n": str(n)}) for n in range(8)]
        )

    assert [r.text for r in results] == [str(n) for n in range(8)]


async def test_client_must_be_used_as_a_context_manager() -> None:
    with pytest.raises(ProbeTransportError, match="context manager"):
        await client().request("GET", API)


# --------------------------------------------------------------------------
# Retry and pacing
# --------------------------------------------------------------------------


async def test_retries_are_bounded_and_then_give_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503)

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", no_sleep)

    async with client(transport=httpx.MockTransport(handle)) as c:
        response = await ProbeContext(c, SECRET).get(API)

    assert len(attempts) == len(RETRY_DELAYS) + 1
    assert response.status_code == 503


async def test_a_transient_failure_is_retried_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200 if len(calls) > 1 else 429)

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", no_sleep)

    async with client(transport=httpx.MockTransport(handle)) as c:
        response = await ProbeContext(c, SECRET).get(API)

    assert len(calls) == 2
    assert response.status_code == 200


async def test_transport_errors_are_retried_then_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", no_sleep)

    async with client(transport=httpx.MockTransport(handle)) as c:
        with pytest.raises(ProbeTransportError, match="failed after"):
            await ProbeContext(c, SECRET).get(API)


async def test_transport_error_message_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An error string reaches the report; it must not carry the key."""

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", no_sleep)

    async with client(transport=httpx.MockTransport(handle)) as c:
        with pytest.raises(ProbeTransportError) as caught:
            await ProbeContext(c, SECRET).get(API, params={"key": SECRET})

    assert SECRET not in str(caught.value)


def test_retry_schedule_is_fixed_and_not_jittered() -> None:
    """Jitter is standard advice, and would make a run irreproducible."""
    assert tuple(sorted(RETRY_DELAYS)) == RETRY_DELAYS
    assert all(delay > 0 for delay in RETRY_DELAYS)
    assert 429 in RETRY_STATUSES


async def test_delay_paces_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def record_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", record_sleep)

    async with client(delay=0.25) as c:
        context = ProbeContext(c, SECRET)
        await context.gather([context.get(API) for _ in range(3)])

    assert slept == [0.25, 0.25, 0.25]


async def test_no_delay_means_no_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def record_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("keyreach.core.http.asyncio.sleep", record_sleep)

    async with client() as c:
        await ProbeContext(c, SECRET).get(API)

    assert slept == []


def test_default_concurrency_is_conservative() -> None:
    """Every probe is traffic against somebody's production service."""
    assert 1 <= DEFAULT_CONCURRENCY <= 10


# --------------------------------------------------------------------------
# Cassettes — R0.6 acceptance criterion: keys masked in recordings
# --------------------------------------------------------------------------


async def test_recording_masks_the_key_in_the_saved_cassette(
    tmp_path: Path,
) -> None:
    """The criterion that makes committing fixtures safe at all."""
    cassette_path = tmp_path / "run.json"
    body = json.dumps({"echo": SECRET})

    async with client(
        transport=responder(body=body),
        cassette=Cassette(cassette_path),
        mode=RecordMode.RECORD,
    ) as c:
        await ProbeContext(c, SECRET).get(
            API, params={"key": SECRET}, headers={"Authorization": f"Bearer {SECRET}"}
        )

    raw = cassette_path.read_text(encoding="utf-8")

    assert SECRET not in raw
    assert REDACTED_PLACEHOLDER in raw


async def test_recorded_cassette_replays_without_any_network(
    tmp_path: Path,
) -> None:
    """Replay must not open a socket — that is what lets CI run without keys."""
    cassette_path = tmp_path / "run.json"

    async with client(
        transport=responder(body='{"account": "acct_1"}'),
        cassette=Cassette(cassette_path),
        mode=RecordMode.RECORD,
    ) as c:
        recorded = await ProbeContext(c, SECRET).get(API, params={"key": SECRET})

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError("replay mode must not touch the network")

    async with ProbeClient(
        redactor=Redactor([SECRET]),
        transport=httpx.MockTransport(explode),
        cassette=Cassette(cassette_path),
        mode=RecordMode.REPLAY,
    ) as c:
        replayed = await ProbeContext(c, SECRET).get(API, params={"key": SECRET})

    assert replayed == recorded


async def test_a_cassette_replays_against_a_different_key(tmp_path: Path) -> None:
    """The property that makes committed fixtures reusable.

    Recording and lookup both redact the URL, so the recorded key is a mask of
    the same shape — and a contributor re-running the suite with their own
    throwaway key still hits the recording.
    """
    cassette_path = tmp_path / "run.json"
    recorded_key = "sk-" + "test" + "-" + "a" * 32
    replay_key = "sk-" + "test" + "-" + "b" * 32

    async with ProbeClient(
        redactor=Redactor([recorded_key]),
        transport=responder(),
        cassette=Cassette(cassette_path),
        mode=RecordMode.RECORD,
    ) as c:
        await ProbeContext(c, recorded_key).get(API, params={"key": recorded_key})

    async with ProbeClient(
        redactor=Redactor([replay_key]),
        cassette=Cassette(cassette_path),
        mode=RecordMode.REPLAY,
    ) as c:
        response = await ProbeContext(c, replay_key).get(
            API, params={"key": replay_key}
        )

    assert response.status_code == 200


async def test_missing_recording_fails_loudly(tmp_path: Path) -> None:
    """Silently returning nothing would look like a provider with no access."""
    cassette_path = tmp_path / "run.json"
    Cassette(cassette_path).save()

    async with ProbeClient(
        redactor=Redactor([SECRET]),
        cassette=Cassette(cassette_path),
        mode=RecordMode.REPLAY,
    ) as c:
        with pytest.raises(CassetteError, match="no recorded interaction"):
            await ProbeContext(c, SECRET).get(API)


def test_cassette_is_written_deterministically(tmp_path: Path) -> None:
    """Re-recording must produce a readable diff, not a reshuffled file."""
    path = tmp_path / "c.json"

    first = Cassette(path)
    for n in (3, 1, 2):
        first.record(
            ProbeResponse(method="GET", url=f"{API}/{n}", status_code=200, text="")
        )
    first.save()
    written = path.read_text(encoding="utf-8")

    second = Cassette(path)
    for n in (2, 3, 1):  # inserted in a different order
        second.record(
            ProbeResponse(method="GET", url=f"{API}/{n}", status_code=200, text="")
        )
    second.save()

    assert path.read_text(encoding="utf-8") == written


def test_cassette_contains_no_timestamp(tmp_path: Path) -> None:
    """A cassette that changed on every recording is useless as a fixture."""
    path = tmp_path / "c.json"
    cassette = Cassette(path)
    cassette.record(ProbeResponse(method="GET", url=API, status_code=200, text=""))
    cassette.save()

    document = json.loads(path.read_text(encoding="utf-8"))

    assert set(document) == {"version", "interactions"}


def test_cassette_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    saved = Cassette(path)
    saved.record(
        ProbeResponse(
            method="GET", url=API, status_code=204, text="", headers={"a": "b"}
        )
    )
    saved.save()

    loaded = Cassette(path)
    loaded.load()
    found = loaded.find("GET", API)

    assert len(loaded) == 1
    assert found is not None
    assert found.status_code == 204
    assert found.headers == {"a": "b"}
    assert loaded.find("GET", "https://other.invalid") is None


def test_duplicate_interactions_are_rejected(tmp_path: Path) -> None:
    """Read-only probes are idempotent, so two answers means a bad recording."""
    path = tmp_path / "c.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "interactions": [
                    {"method": "GET", "url": API, "status_code": 200, "body": "a"},
                    {"method": "GET", "url": API, "status_code": 500, "body": "b"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CassetteError, match="twice"):
        Cassette(path).load()


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("not json at all", "not valid JSON"),
        ('["a"]', "must be a mapping"),
        ('{"version": 1}', "must be a mapping"),
    ],
)
def test_malformed_cassette_is_rejected(tmp_path: Path, body: str, match: str) -> None:
    path = tmp_path / "c.json"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(CassetteError, match=match):
        Cassette(path).load()


def test_missing_cassette_file_is_reported_clearly(tmp_path: Path) -> None:
    with pytest.raises(CassetteError, match="could not read"):
        Cassette(tmp_path / "absent.json").load()


def test_record_mode_requires_a_cassette() -> None:
    with pytest.raises(CassetteError, match="requires a cassette"):
        ProbeClient(mode=RecordMode.RECORD)


def test_cassette_repr_is_informative(tmp_path: Path) -> None:
    cassette = Cassette(tmp_path / "c.json")

    assert "c.json" in repr(cassette)
    assert "interactions=0" in repr(cassette)


async def test_head_is_available_and_guarded() -> None:
    """HEAD is idempotent, so it is part of the read-only surface."""
    async with client() as c:
        response = await ProbeContext(c, SECRET).head(API)

    assert response.method == "HEAD"
    assert response.ok


async def test_context_exposes_pacing_configuration() -> None:
    """Providers may need to know the delay to size their own probe budget."""
    async with client(delay=0.5, timeout=7.0) as c:
        context = ProbeContext(c, SECRET)

        assert context.delay == 0.5
        assert context.timeout == 7.0


def test_redactor_is_callable() -> None:
    """`redactor(text)` reads better than `redactor.redact(text)` at call sites."""
    redactor = Redactor([SECRET])

    assert redactor(f"saw {SECRET}") == redactor.redact(f"saw {SECRET}")
