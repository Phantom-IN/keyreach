"""Shared plumbing for the drift canary (roadmap R2.10).

``implementation_plan.md`` §10 and §13.3 specify a scheduled check, not a
pipeline stage: it does not analyse a key, so it is not held to
``CLAUDE.md``'s determinism or read-only-through-``ProbeContext`` rules the
way ``keyreach/providers/*`` is. There is no key here at all — every request
below carries either no credential (checking a vendor documentation page
still resolves) or a placeholder no real key ever equals
(:data:`tools.drift_canary.endpoints.PLACEHOLDER_KEY`, checking a declarative
probe endpoint still exists). ``ProbeContext`` exists to protect a *real*
secret in flight, mask it in recordings, and replay a cassette instead of
touching the network in tests; nothing here is a real secret, and the whole
point of a scheduled canary is that it *does* touch the live network.

That is also why this package imports ``httpx`` directly rather than going
through ``ProbeContext``, and why ``pyproject.toml``'s
``[tool.ruff.lint.flake8-tidy-imports.banned-api]`` carries a matching
``per-file-ignores`` entry for it: this is the second and only other place
keyreach reaches the network outside ``keyreach/core/http.py``, and it is
exempt for the opposite reason that file is the one exception to the ban —
``core/http.py`` is where a real key is sent; this one is where no key ever
is.

Every request is a plain ``GET``, matching the read-only spirit of
``plan.md`` §11 even though ``tools/`` sits outside the guardrails
(``tools/guardrails/network_isolation.py``, ``read_only.py``) that enforce it
for plugins.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, NamedTuple, Protocol

import httpx

#: Generous but bounded — a hung vendor page must not hang a scheduled job
#: forever.
TIMEOUT: Final = 15.0

#: Identifies the request in a vendor's access logs as what it is, with a
#: link back to the project rather than an anonymous scraper.
USER_AGENT: Final = (
    "keyreach-drift-canary/1.0 (+https://github.com/Phantom-IN/keyreach)"
)


class Finding(NamedTuple):
    """One thing the canary could not confirm still holds.

    ``check`` names which check produced it — ``source-unreachable``,
    ``source-format-missing``, ``endpoint-unreachable``, ``endpoint-missing``,
    ``endpoint-unexpected-status`` or ``endpoint-deprecated`` — matching the
    three things ``implementation_plan.md`` §13.3 says the canary has to
    verify.
    """

    check: str
    subject: str
    message: str
    url: str

    def render(self) -> str:
        return f"- **{self.subject}** (`{self.check}`): {self.message}"


@dataclass(frozen=True)
class FetchResult:
    """One HTTP response, or the reason there wasn't one.

    ``error`` is set instead of raising: a canary that crashes on the first
    vendor page that times out reports nothing about the other rules and
    endpoints it had not gotten to yet.
    """

    status: int
    text: str
    headers: Mapping[str, str]
    error: str | None = None


class Fetch(Protocol):
    """A GET, real or stubbed.

    Both checks in this package depend on this protocol, not on ``httpx``
    directly, so a test supplies a deterministic stub instead of reaching the
    network — this repository's test suite makes no live network calls, and
    the canary's own tests are no exception.
    """

    def __call__(
        self, url: str, headers: Mapping[str, str] | None
    ) -> FetchResult: ...  # pragma: no cover - structural typing only, never called


def live_fetch(url: str, headers: Mapping[str, str] | None = None) -> FetchResult:
    """A real, read-only GET.

    Used only by ``python -m tools.drift_canary``, i.e. the scheduled
    workflow; every test injects a stub conforming to :class:`Fetch` instead.
    """
    request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
    try:
        response = httpx.get(
            url,
            headers=request_headers,
            follow_redirects=True,
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return FetchResult(status=0, text="", headers={}, error=str(exc))
    return FetchResult(
        status=response.status_code,
        text=response.text,
        headers=response.headers,
    )
