"""The only place in keyreach that opens a socket.

Every provider probe goes through :class:`ProbeContext`, which wraps
:class:`ProbeClient`. Concentrating all I/O here is what makes keyreach's
guarantees enforceable rather than aspirational — a plugin cannot forget to mask
a key, cannot accidentally issue a write, and cannot bypass the cassette layer,
because it never touches the network itself (``implementation_plan.md`` §6).

Four properties are enforced at this boundary:

* **Read-only by default.** Non-idempotent methods are refused. ``POST`` is
  available only when a probe explicitly declares ``read_only_post=True``, for
  the RPC-style APIs whose *read* endpoints require POST. Everything else —
  PUT, PATCH, DELETE — has no code path at all.
* **Redaction.** The key is masked in recorded requests, in evidence strings,
  and in anything a response echoes back. The full secret surfaces only when
  ``unmask`` is set.
* **Record/replay.** Probes can run against a JSON cassette instead of the
  network, so tests and CI never need a live key.
* **Bounded, deterministic rate limiting and retry.** A fixed retry schedule,
  never jittered — jitter would make a run irreproducible, which is the one
  thing keyreach cannot trade away.

Note on clocks: this module reads time for pacing and sleeps between retries.
That is not a determinism violation. ``plan.md`` §1 forbids time-dependent
*verdicts*; how long a probe waited never reaches a capability, a severity, or a
report.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Final, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

#: Leading characters left visible. Enough to recognise the provider prefix
#: (`AIza`, `sk-a`, `AKIA`) without materially narrowing the search space.
MASK_PREFIX: Final = 4

#: Trailing characters left visible, so a recipient can correlate the finding
#: with a specific key in their provider dashboard without ever seeing it.
MASK_SUFFIX: Final = 3

#: Below this length a key is masked completely. Showing 7 of 11 characters
#: would reveal most of a short token.
MASK_MIN_LENGTH: Final = 12

#: Shortest value worth registering for redaction. Below this a "secret" is
#: generic enough that replacing it would corrupt unrelated output — redacting
#: every occurrence of "abc" would mangle the report, not protect anything.
MIN_REDACTABLE_LENGTH: Final = 8


def mask_key(key: str) -> str:
    """Mask a secret for display, e.g. ``AIza****...****3xY``.

    Keeps the length visible through the asterisk run, which is useful when
    triaging (formats have characteristic lengths) and does not narrow a brute
    force in any practical way.

    Short keys are masked completely rather than partially: the point of a
    fingerprint is to identify a key without disclosing it, and on a short token
    a prefix-plus-suffix would disclose most of it.
    """
    if not key:
        return ""
    if len(key) < MASK_MIN_LENGTH:
        return "*" * len(key)
    hidden = len(key) - MASK_PREFIX - MASK_SUFFIX
    return f"{key[:MASK_PREFIX]}{'*' * hidden}{key[-MASK_SUFFIX:]}"


#: What a secret is replaced with in URLs, headers, bodies and cassettes.
#:
#: Deliberately a fixed placeholder rather than :func:`mask_key`. The display
#: mask preserves the key's first four and last three characters, which is
#: useful in a report header where a recipient wants to identify *which* key —
#: but it makes every derived string key-specific. A cassette recorded with one
#: key would then never match a run using another, so committed fixtures would
#: only work for whoever recorded them, and re-recording would churn the diff.
#:
#: Using a constant makes recordings key-agnostic and leaks strictly less. The
#: report still shows a real fingerprint via ``mask_key``, in the one place that
#: correlation actually helps.
REDACTED_PLACEHOLDER: Final = "<key>"


class Redactor:
    """Replaces known secrets with a fixed placeholder, everywhere.

    Applied to URLs, headers, request bodies, response bodies and cassettes. A
    key can appear in any of them: as a query parameter, a bearer token, a form
    field, or echoed back by an API error message.

    Percent-encoded forms are redacted too. A key carried in a query string is
    URL-encoded by the HTTP client, so matching only the raw value would let the
    encoded one through — into a cassette that then gets committed.
    """

    def __init__(self, secrets: Iterable[str] = (), *, unmask: bool = False) -> None:
        self._unmask = unmask
        self._replacements: dict[str, str] = {}
        for secret in secrets:
            self.add(secret)

    def add(self, secret: str) -> None:
        """Register a secret. Short values are ignored as too generic to redact."""
        if not secret or len(secret) < MIN_REDACTABLE_LENGTH:
            return
        self._replacements[secret] = REDACTED_PLACEHOLDER
        encoded = quote(secret, safe="")
        if encoded != secret:
            self._replacements[encoded] = REDACTED_PLACEHOLDER

    def __call__(self, text: str) -> str:
        return self.redact(text)

    def redact(self, text: str) -> str:
        """Replace every registered secret in ``text`` with its mask."""
        if self._unmask or not text:
            return text
        # Longest first, so a secret that contains another is not partially
        # replaced and left recognisable.
        for secret in sorted(self._replacements, key=len, reverse=True):
            text = text.replace(secret, self._replacements[secret])
        return text

    def redact_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        """Redact header values, and drop credential headers entirely.

        Authorization and API-key headers are replaced wholesale rather than
        pattern-matched. A bearer token that keyreach was not told about — a
        session cookie, a second credential — would otherwise survive into a
        cassette because the redactor has no secret registered for it.

        Names are lower-cased and the result sorted. HTTP header names are
        case-insensitive and servers disagree about casing, so preserving it
        would make a provider's header lookup depend on which server answered,
        and would reshuffle cassettes between recordings.
        """
        redacted: dict[str, str] = {}
        for name, value in headers.items():
            lowered = name.lower()
            if lowered in _CREDENTIAL_HEADERS:
                redacted[lowered] = "<redacted>"
            else:
                redacted[lowered] = self.redact(value)
        return dict(sorted(redacted.items()))

    @property
    def unmask(self) -> bool:
        return self._unmask


#: Headers whose value is a credential by definition. Redacted wholesale.
_CREDENTIAL_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-goog-api-key",
        "private-token",
    }
)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ProbeError(Exception):
    """Base class for probe failures."""


class ReadOnlyViolationError(ProbeError):
    """A probe attempted a method that could change state."""


class CassetteError(ProbeError):
    """A cassette is missing, malformed, or has no recording for a request."""


class ProbeTransportError(ProbeError):
    """The request could not be completed — DNS, TLS, timeout, connection."""


# --------------------------------------------------------------------------
# Requests and responses
# --------------------------------------------------------------------------

#: Methods that cannot change server state, and are therefore always allowed.
IDEMPOTENT_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Fixed retry schedule, in seconds. Deliberately not jittered: jitter is the
#: standard advice for thundering herds, but it makes a run irreproducible, and
#: keyreach probes a handful of endpoints rather than hammering a fleet.
RETRY_DELAYS: Final[tuple[float, ...]] = (1.0, 2.0, 4.0)

#: Status codes worth retrying — rate limiting and transient server faults.
RETRY_STATUSES: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

#: Default per-request timeout in seconds.
DEFAULT_TIMEOUT: Final = 15.0

#: Default cap on concurrent probes. Small on purpose: every probe is
#: authentication traffic against somebody's production service (``plan.md``
#: §11), and keyreach is not a load generator.
DEFAULT_CONCURRENCY: Final = 5


#: Bounds of the 2xx success range.
_HTTP_OK_MIN: Final = 200
_HTTP_OK_EXCLUSIVE_MAX: Final = 300


def _utc_now() -> datetime:
    """The default clock. Injectable so a test never depends on the real one."""
    return datetime.now(tz=UTC)


class ProbeResponse(BaseModel):
    """A response, already redacted.

    Everything a provider can read here has been through the redactor, so a
    plugin cannot accidentally copy a raw key into a capability's evidence.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str
    url: str = Field(description="Request URL, with secrets masked.")
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    text: str = Field(default="", description="Response body, with secrets masked.")

    @property
    def ok(self) -> bool:
        return _HTTP_OK_MIN <= self.status_code < _HTTP_OK_EXCLUSIVE_MAX

    def json_body(self) -> Any:
        """Parse the body as JSON, or raise ``ValueError``.

        Named ``json_body`` rather than ``json`` because ``BaseModel.json`` is
        pydantic's own (deprecated) serializer. Overriding it would mean the
        same call returned parsed response data here and a serialized model
        everywhere else — a quiet trap for anyone who assumed either.
        """
        return json.loads(self.text)

    def json_or_none(self) -> Any | None:
        """Parse the body as JSON, or return ``None`` if it is not JSON.

        Providers probe endpoints that return HTML error pages and empty bodies
        as readily as JSON, and a detection path should not raise because a
        server returned a maintenance page.
        """
        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None

    def evidence(self, summary: str | None = None) -> str:
        """Build a masked evidence string proving this capability.

        Evidence is what a triager on the receiving end checks, so it records
        the request that was made and what came back. Already redacted, because
        every field on this model is.
        """
        line = f"{self.method} {self.url} -> {self.status_code}"
        return f"{line}, {summary}" if summary else line


class _Interaction(BaseModel):
    """One recorded request/response pair in a cassette."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str
    url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""


class RecordMode(StrEnum):
    """How the client interacts with a cassette."""

    OFF = "off"
    """No cassette. Requests go to the network."""

    RECORD = "record"
    """Requests go to the network and are written to the cassette, redacted."""

    REPLAY = "replay"
    """Requests are served from the cassette. No socket is ever opened."""


class Cassette:
    """A recorded set of HTTP interactions, stored as deterministic JSON.

    Interactions are keyed by ``(method, redacted URL)``. The URL is redacted on
    both sides — when recording and when looking up — and redaction substitutes
    a fixed placeholder, so a cassette recorded with one key replays against
    any other. That is what lets fixtures be committed at all: the recorded URL
    contains ``<key>``, never a secret and never a key-specific mask.

    Duplicate keys are rejected rather than silently overwritten. keyreach's
    probes are read-only and therefore idempotent, so two different responses
    for the same request means the cassette was recorded incorrectly.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._interactions: dict[tuple[str, str], _Interaction] = {}

    def __len__(self) -> int:
        return len(self._interactions)

    def __repr__(self) -> str:
        return f"<Cassette path={self.path.name!r} interactions={len(self)}>"

    @staticmethod
    def _key(method: str, url: str) -> tuple[str, str]:
        return (method.upper(), url)

    def load(self) -> None:
        """Read the cassette from disk."""
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"could not read cassette {self.path}: {exc}"
            raise CassetteError(msg) from exc

        try:
            document = json.loads(raw)
        except ValueError as exc:
            msg = f"cassette {self.path} is not valid JSON: {exc}"
            raise CassetteError(msg) from exc

        if not isinstance(document, dict) or "interactions" not in document:
            msg = f"cassette {self.path} must be a mapping with an 'interactions' list"
            raise CassetteError(msg)

        self._interactions = {}
        for entry in document["interactions"]:
            interaction = _Interaction.model_validate(entry)
            key = self._key(interaction.method, interaction.url)
            if key in self._interactions:
                msg = (
                    f"cassette {self.path} records {key[0]} {key[1]} twice. "
                    "keyreach's probes are read-only and idempotent, so a "
                    "duplicate means the cassette was recorded incorrectly."
                )
                raise CassetteError(msg)
            self._interactions[key] = interaction

    def find(self, method: str, url: str) -> ProbeResponse | None:
        interaction = self._interactions.get(self._key(method, url))
        if interaction is None:
            return None
        return ProbeResponse(
            method=interaction.method,
            url=interaction.url,
            status_code=interaction.status_code,
            headers=dict(interaction.headers),
            text=interaction.body,
        )

    def record(self, response: ProbeResponse) -> None:
        """Add an interaction. Must already be redacted."""
        interaction = _Interaction(
            method=response.method,
            url=response.url,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
        )
        self._interactions[self._key(interaction.method, interaction.url)] = interaction

    def save(self) -> None:
        """Write the cassette deterministically.

        Interactions are sorted by ``(method, url)`` so re-recording produces a
        readable diff instead of a reshuffled file, and no timestamp is written
        — a cassette that changed every time it was recorded would be useless as
        a fixture.
        """
        ordered = [
            self._interactions[key].model_dump() for key in sorted(self._interactions)
        ]
        document = {"version": 1, "interactions": ordered}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class ProbeClient:
    """The rate-limited, recordable, redacting, read-only-guarded HTTP client.

    Providers never construct one of these; the engine does, and hands each
    provider a :class:`ProbeContext` bound to the key under test.
    """

    def __init__(  # noqa: PLR0913 - keyword-only client configuration; a
        # config object would hide these behind an extra indirection for no gain
        self,
        *,
        redactor: Redactor | None = None,
        delay: float = 0.0,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        cassette: Cassette | None = None,
        mode: RecordMode = RecordMode.OFF,
        transport: httpx.AsyncBaseTransport | None = None,
        user_agent: str = "keyreach",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.redactor = redactor if redactor is not None else Redactor()
        self.delay = delay
        self.timeout = timeout
        self.mode = mode
        self.cassette = cassette
        self._clock = clock if clock is not None else _utc_now
        self._semaphore = asyncio.Semaphore(concurrency)
        self._pace_lock = asyncio.Lock()
        self._user_agent = user_agent
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

        #: Responses already fetched this run, keyed exactly as a cassette is —
        #: ``(method, redacted URL)``. Added in R1.4, which measured what every
        #: provider was actually doing and found all four fetching their
        #: validation endpoint **twice**: once in ``validate`` and again in
        #: ``enumerate``, where the same endpoint doubles as a capability probe.
        #: Each plugin's docstring claimed "one request, not two"; none of them
        #: was true.
        #:
        #: Caching here rather than threading the validation response into
        #: ``enumerate`` keeps the ``Provider`` signature untouched and fixes it
        #: for every provider at once, including ones not written yet. It is
        #: sound for exactly the reason the cassette layer already assumes:
        #: keyreach's probes are idempotent reads, so two identical requests in
        #: one run must produce the same answer — ``Cassette.load`` rejects a
        #: recording that says otherwise.
        #:
        #: **Only idempotent methods.** A ``read_only_post`` probe is a read by
        #: argument and review, not by HTTP semantics, and this cache will not
        #: assume otherwise.
        self._responses: dict[tuple[str, str], ProbeResponse] = {}

        #: Requests that actually reached the network or the cassette, as
        #: opposed to being served from the cache above. `plan.md` §11 asks for
        #: minimal probe counts; this is the number that claim is about, and
        #: R1.5 can show it to the user.
        self.requests_made = 0

        if mode is not RecordMode.OFF and cassette is None:
            msg = f"record mode {mode.value!r} requires a cassette"
            raise CassetteError(msg)

    def now(self) -> datetime:
        """Current UTC time, for request signing only.

        Added in R1.3, because AWS SigV4 requires a request timestamp within a
        few minutes of the server's clock and there is no way to authenticate to
        AWS without one. It lives here rather than in the provider because
        nondeterminism control belongs to the engine, never to a plugin
        (``CLAUDE.md``, "Architecture at a glance") — the engine owns one clock
        for the whole run and a test can pin it.

        Reading it is not a determinism violation, on exactly the grounds set
        out at the top of this module for pacing: ``plan.md`` §1 forbids
        time-dependent *verdicts*, and a signature timestamp reaches a request
        header and nothing else. It is never part of a cassette key, a
        capability, a severity, or a report.
        """
        return self._clock()

    async def __aenter__(self) -> ProbeClient:
        if self.mode is RecordMode.REPLAY:
            # No client is created at all in replay mode. Not opening a socket
            # is a stronger guarantee than intending not to use one.
            if self.cassette is not None:  # pragma: no branch - __init__ guards
                self.cassette.load()
            return self
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            transport=self._transport,
            follow_redirects=False,
            headers={"User-Agent": self._user_agent},
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self.mode is RecordMode.RECORD and self.cassette is not None:
            self.cassette.save()

    # ------------------------------------------------------------- guarding

    @staticmethod
    def check_method(method: str, *, read_only_post: bool = False) -> None:
        """Enforce the read-only guard. Default-deny.

        ``POST`` is permitted only with an explicit ``read_only_post=True``,
        which exists for RPC-style APIs whose read endpoints require POST. The
        flag is deliberately verbose and greppable: the ``read_only`` CI check
        (roadmap R0.9) scans for exactly this, and every use is meant to be
        argued for in review.

        PUT, PATCH and DELETE are refused unconditionally. keyreach has no
        reason to issue one, ever.
        """
        upper = method.upper()
        if upper in IDEMPOTENT_METHODS:
            return
        if upper == "POST" and read_only_post:
            return
        if upper == "POST":
            msg = (
                "POST is denied by default. If this endpoint is genuinely a "
                "read operation on an RPC-style API, pass read_only_post=True "
                "and justify it in review (implementation_plan.md §6)."
            )
            raise ReadOnlyViolationError(msg)
        msg = (
            f"{upper} is never permitted. keyreach is read-only by design and "
            "ships no write, delete, or spend capability (plan.md §4)."
        )
        raise ReadOnlyViolationError(msg)

    # -------------------------------------------------------------- request

    async def request(  # noqa: PLR0913 - mirrors the HTTP request surface
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        content: str | None = None,
        read_only_post: bool = False,
    ) -> ProbeResponse:
        """Issue one guarded, redacted, optionally recorded request."""
        self.check_method(method, read_only_post=read_only_post)
        upper = method.upper()

        # Build the real target once, then redact it for every purpose other
        # than actually sending it.
        #
        # The two-branch form matters. `httpx.URL(url, params=None)` does not
        # mean "leave the query alone" — it means "set the query to nothing",
        # so a probe URL that already carried `?a=b` would be sent without it.
        # No shipped provider does that today (they all pass a bare URL plus a
        # params mapping), which is why this went unnoticed until R1.4 measured
        # request counts and found three distinct URLs collapsing into one.
        target = str(httpx.URL(url, params=dict(params)) if params else httpx.URL(url))
        redacted_url = self.redactor.redact(target)

        # Idempotent requests are answered once per run. See `_responses`.
        cacheable = upper in IDEMPOTENT_METHODS
        if cacheable and (cached := self._responses.get((upper, redacted_url))):
            return cached

        if self.mode is RecordMode.REPLAY:
            probe_response = self._replay(upper, redacted_url)
        else:
            async with self._semaphore:
                response = await self._send(upper, target, headers, content)

            probe_response = ProbeResponse(
                method=upper,
                url=redacted_url,
                status_code=response.status_code,
                headers=self.redactor.redact_headers(dict(response.headers)),
                text=self.redactor.redact(response.text),
            )

            if self.mode is RecordMode.RECORD and self.cassette is not None:
                self.cassette.record(probe_response)

        # Counted whether the answer came from a socket or a cassette, so a
        # replayed test measures the same probe count a real run would make.
        self.requests_made += 1

        if cacheable:
            self._responses[(upper, redacted_url)] = probe_response

        return probe_response

    def _replay(self, method: str, redacted_url: str) -> ProbeResponse:
        if self.cassette is None:  # pragma: no cover - guarded in __init__
            msg = "replay mode requires a cassette"
            raise CassetteError(msg)
        found = self.cassette.find(method, redacted_url)
        if found is None:
            msg = (
                f"no recorded interaction for {method} {redacted_url} in "
                f"{self.cassette.path.name}. Re-record the cassette, or check "
                "the probe URL against what was recorded."
            )
            raise CassetteError(msg)
        return found

    async def _send(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str] | None,
        content: str | None,
    ) -> httpx.Response:
        """Send with pacing and a fixed retry schedule."""
        if self._client is None:
            msg = "ProbeClient must be used as an async context manager"
            raise ProbeTransportError(msg)

        last_error: Exception | None = None
        # One attempt, plus one per configured retry delay.
        for attempt in range(len(RETRY_DELAYS) + 1):
            if attempt:
                await asyncio.sleep(RETRY_DELAYS[attempt - 1])

            await self._pace()
            try:
                response = await self._client.request(
                    method,
                    target,
                    headers=dict(headers) if headers else None,
                    content=content,
                )
            except httpx.HTTPError as exc:
                last_error = exc
                continue

            if response.status_code in RETRY_STATUSES and attempt < len(RETRY_DELAYS):
                continue
            return response

        msg = (
            f"{method} {self.redactor.redact(target)} failed after "
            f"{len(RETRY_DELAYS) + 1} attempts: {last_error}"
        )
        raise ProbeTransportError(msg) from last_error

    async def _pace(self) -> None:
        """Space requests by ``delay``.

        Holding the lock across the wait serialises probes whenever a delay is
        set, which is the point: ``--delay`` exists so a user can stay under a
        provider's rate limit and out of its alerting, and concurrent probes
        spaced "on average" would defeat that.
        """
        if self.delay <= 0:
            return
        async with self._pace_lock:
            await asyncio.sleep(self.delay)


# --------------------------------------------------------------------------
# ProbeContext
# --------------------------------------------------------------------------


class ProbeContext:
    """The only HTTP surface a provider plugin ever sees.

    Bound to one key. Providers call :meth:`get`, :meth:`head` and — rarely, and
    only with justification — :meth:`post`; everything else about the request
    (redaction, pacing, retry, recording, the read-only guard) is handled
    underneath and cannot be opted out of.
    """

    def __init__(
        self, client: ProbeClient, key: str, *, aggressive: bool = False
    ) -> None:
        self._client = client
        self._key = key
        #: Opt-in noisy enumeration (``plan.md`` §11). **Never** default true.
        #: A provider reads this to decide whether to run probes that are
        #: read-only but loud enough to trip a defender's alerting; R1.5 surfaces
        #: it as ``--aggressive``, behind an explicit warning.
        self.aggressive = aggressive
        client.redactor.add(key)

    def __repr__(self) -> str:
        return f"<ProbeContext key={self.masked_key!r} aggressive={self.aggressive}>"

    @property
    def masked_key(self) -> str:
        """The key as it may be shown: masked, unless ``--unmask`` was passed."""
        return self._key if self._client.redactor.unmask else mask_key(self._key)

    @property
    def key(self) -> str:
        """The raw key, for building the request itself. Never put this in output."""
        return self._key

    @property
    def delay(self) -> float:
        return self._client.delay

    @property
    def timeout(self) -> float:
        return self._client.timeout

    def mask(self, text: str) -> str:
        """Redact any known secret in ``text``. Use before writing evidence."""
        return self._client.redactor.redact(text)

    def protect(self, secret: str) -> None:
        """Register a further secret for redaction.

        Added in R1.3. Some credentials are **composite**: an AWS credential is
        an access key id, a secret access key and sometimes a session token,
        pasted as one string. The redactor is seeded with the whole string, so
        a provider that splits it must register the parts — otherwise a response
        body echoing back just the access key id would sail through masked
        output that was only ever looking for the concatenation.

        Values shorter than :data:`MIN_REDACTABLE_LENGTH` are ignored, exactly
        as in :meth:`Redactor.add`: replacing a three-character "secret"
        everywhere would corrupt the report rather than protect anything.
        """
        self._client.redactor.add(secret)

    def now(self) -> datetime:
        """Current UTC time, for request signing only. See :meth:`ProbeClient.now`.

        A provider must not read the clock itself (``CLAUDE.md``). This is the
        one sanctioned route, it exists for AWS SigV4, and what it returns must
        never reach a capability, a severity, or a report.
        """
        return self._client.now()

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ProbeResponse:
        return await self._client.request("GET", url, params=params, headers=headers)

    async def head(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ProbeResponse:
        return await self._client.request("HEAD", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        *,
        content: str | None = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        read_only_post: bool = False,
    ) -> ProbeResponse:
        """POST, permitted only for genuine read operations.

        Raises :class:`ReadOnlyViolationError` unless ``read_only_post=True``.
        Use it only where a provider's *read* endpoint requires POST, and say so
        in the pull request — the flag is a request for review, not a switch.
        """
        return await self._client.request(
            "POST",
            url,
            params=params,
            headers=headers,
            content=content,
            read_only_post=read_only_post,
        )

    async def gather(self, awaitables: Sequence[Awaitable[T]]) -> list[T]:
        """Run probes concurrently, returning results in **input order**.

        Concurrency is bounded by the client's semaphore. Results are returned
        in the order the awaitables were given, never the order they finished —
        completion order depends on network timing and would make a run
        irreproducible (``implementation_plan.md`` §6).
        """
        return list(await asyncio.gather(*awaitables))
