"""The drift canary (roadmap R2.10).

No real network call is made anywhere in this module — `Fetch` is a
protocol precisely so every check can be proven against a stub instead of
the live Internet, matching this repository's rule that the test suite makes
no live network calls. `test_leading_literals_matches_every_active_rule` is
the exception to "synthetic only": it is pinned against the real, packaged
`detection_rules.yml`, so a rule's pattern changing without updating this
table fails loudly here rather than only in the next scheduled run.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from keyreach.core.detect import DetectionRule, default_detector
from keyreach.core.http import ProbeContext
from keyreach.core.models import ValidationResult
from keyreach.core.probes import ProviderSpec, YamlProvider
from keyreach.core.provider import Provider
from tools.drift_canary import endpoints, sources
from tools.drift_canary.__main__ import main, render
from tools.drift_canary.base import FetchResult, Finding, live_fetch
from tools.drift_canary.sources import leading_literals

# ---------------------------------------------------------------------------
# base.py
# ---------------------------------------------------------------------------


def test_finding_renders_as_a_markdown_bullet() -> None:
    finding = Finding(
        "endpoint-missing", "npm / npm Tokens", "returned 404", "https://x.invalid"
    )
    assert (
        finding.render() == "- **npm / npm Tokens** (`endpoint-missing`): returned 404"
    )


def test_live_fetch_returns_the_response_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_get(url: str, **kwargs: Any) -> httpx.Response:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return httpx.Response(200, text="hello", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)

    result = live_fetch("https://docs.example.invalid/", headers={"X-Extra": "1"})

    assert result == FetchResult(status=200, text="hello", headers=result.headers)
    assert result.error is None
    assert captured["url"] == "https://docs.example.invalid/"
    # The caller's headers survive alongside the canary's own User-Agent.
    assert captured["kwargs"]["headers"]["X-Extra"] == "1"
    assert "keyreach-drift-canary" in captured["kwargs"]["headers"]["User-Agent"]
    assert captured["kwargs"]["follow_redirects"] is True


def test_live_fetch_reports_a_transport_error_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get(url: str, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = live_fetch("https://docs.example.invalid/")

    assert result.status == 0
    assert result.text == ""
    assert result.error == "connection refused"


# ---------------------------------------------------------------------------
# sources.py — leading_literals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        # Plain literal run, stopped by a character class.
        ("^AIza[0-9A-Za-z_-]{35}$", ("AIza",)),
        # Mandatory leading alternation, no prefix or suffix.
        ("^(AKIA|ASIA)[0-9A-Z]{16}$", ("AKIA", "ASIA")),
        # Literal prefix + mandatory alternation + literal suffix, composed.
        ("^sk_(live|test)_[0-9A-Za-z]{24,}$", ("sk_live_", "sk_test_")),
        # Non-capturing mandatory alternation behaves the same as capturing.
        ("^dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}$", ("dckr_pat_", "dckr_oat_")),
        # An optional group contributes nothing that MUST appear — skipped.
        ("^(?:[a-z]{20}:)?sb_secret_[A-Za-z0-9_-]{20,}$", ("sb_secret_",)),
        # A negative lookahead names what this rule's value is NOT, never an
        # alternative of its own prefix.
        ("^sk-(?!admin-|ant-)[A-Za-z0-9_-]{20,}$", ("sk-",)),
        # A positive lookahead is excluded the same way.
        ("^sk-(?=live)[A-Za-z0-9_-]{20,}$", ("sk-",)),
        # An escaped metacharacter is a literal character, not a stop sign.
        (r"^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$", ("SG.",)),
        # A leading character class yields no literal at all.
        ("^[0-9a-f]{40}$", ()),
        # A short leading run (below MIN_LITERAL_LENGTH) is not trustworthy
        # enough to assert against a page's prose.
        ("^AC[0-9a-f]{32}$", ()),
        # A character class right after a short prefix: the prefix alone is
        # still too short, and the class is not expanded.
        ("^gh[pousr]_[A-Za-z0-9]{36}$", ()),
        # No leading ^ at all — the function still works on the bare pattern.
        ("dop_v1_[0-9a-f]{64}", ("dop_v1_",)),
        # A pattern that is just "^": an empty body, nothing to read.
        ("^", ()),
        # A mandatory alternation with nothing after it: the suffix scan
        # starts exactly at the end of the string.
        ("(a|b)", ("a", "b")),
        # A mandatory alternation whose alternatives are not plain literals
        # (one carries a character class) is not trustworthy either — fall
        # back to whatever literal prefix came before the group.
        ("prefix(c[d]|e)f", ("prefix",)),
        # An unbalanced group (unparseable, even though the caller only ever
        # passes patterns that already compiled as regexes) is a best-effort
        # miss, not a crash.
        ("ab(cd", ()),
        # A nested parenthesis inside the leading group: finding the TRUE
        # outer close still works, and the inner content is correctly seen
        # as non-plain (it contains parens itself).
        ("prefix(a(b)|c)suffix", ("prefix",)),
    ],
)
def test_leading_literals(pattern: str, expected: tuple[str, ...]) -> None:
    assert leading_literals(pattern) == expected


#: Pinned against the real, packaged detection_rules.yml (roadmap R2.3, R2.4:
#: both withdrawn rules were caught by a human re-reading a vendor page, and
#: this table is what a future contributor changing a pattern trips over
#: before the next scheduled canary run would.
EXPECTED_LITERALS_BY_RULE_ID = {
    "anthropic-api-key": ("sk-ant-",),
    "aws-access-key-id": ("AKIA", "ASIA", "ABIA", "ACCA"),
    "aws-credential-pair": ("AKIA", "ASIA", "ABIA", "ACCA"),
    "digitalocean-pat": ("dop_v1_",),
    "dockerhub-access-token": ("dckr_pat_", "dckr_oat_"),
    "generic-jwt": (),
    "github-fine-grained-pat": ("github_pat_",),
    "github-token": (),
    "gitlab-pat": ("glpat-",),
    "google-api-key": ("AIza",),
    "grafana-cloud-access-policy-token": ("glc_",),
    "mailchimp-api-key": (),
    "newrelic-user-key": ("NRAK-",),
    "openai-admin-key": ("sk-admin-",),
    "openai-api-key": ("sk-",),
    "openai-project-key": ("sk-proj-",),
    "openai-service-account-key": ("sk-svcacct-",),
    "paystack-secret-key": ("sk_live_", "sk_test_"),
    "pinecone-api-key": ("pcsk_",),
    "pypi-api-token": ("pypi-",),
    "razorpay-key-id": ("rzp_live_", "rzp_test_"),
    "razorpay-key-pair": ("rzp_live_", "rzp_test_"),
    "resend-api-key": ("re_",),
    "sendgrid-api-key": ("SG.",),
    "slack-token": ("xox",),
    "stripe-restricted-key": ("rk_live_", "rk_test_"),
    "stripe-secret-key": ("sk_live_", "sk_test_"),
    "supabase-publishable-key": ("sb_publishable_",),
    "supabase-secret-key": ("sb_secret_",),
    "telegram-bot-token": (),
    "twilio-account-sid": (),
    "twilio-api-key-sid": (),
    "twilio-credential-pair": (),
}


def test_leading_literals_matches_every_active_rule() -> None:
    rules = default_detector.rules()
    assert {rule.id for rule in rules} == set(EXPECTED_LITERALS_BY_RULE_ID)
    for rule in rules:
        assert (
            leading_literals(rule.pattern) == EXPECTED_LITERALS_BY_RULE_ID[rule.id]
        ), rule.id


# ---------------------------------------------------------------------------
# sources.py — check()
# ---------------------------------------------------------------------------


def _rule(**overrides: Any) -> DetectionRule:
    base: dict[str, Any] = {
        "id": "example-key",
        "provider": "example",
        "description": "Example key",
        "pattern": "^ex_[A-Za-z0-9]{20,}$",
        "confidence": 0.9,
        "source": "https://docs.example.invalid/keys",
    }
    base.update(overrides)
    return DetectionRule.model_validate(base)


class _StubFetch:
    """Records every call and answers from a fixed table keyed by URL."""

    def __init__(self, answers: dict[str, FetchResult]) -> None:
        self._answers = answers
        self.calls: list[str] = []

    def __call__(self, url: str, headers: Mapping[str, str] | None) -> FetchResult:
        self.calls.append(url)
        return self._answers[url]


def test_sources_check_reports_nothing_when_the_page_still_documents_the_format() -> (
    None
):
    rule = _rule(pattern="^ex_[A-Za-z0-9]{20,}$")
    fetch = _StubFetch({rule.source: FetchResult(200, "keys look like ex_...", {})})

    assert sources.check(fetch, [rule]) == []


def test_sources_check_reports_every_rule_sharing_an_unreachable_source() -> None:
    a = _rule(id="a", source="https://docs.example.invalid/gone")
    b = _rule(id="b", source="https://docs.example.invalid/gone")
    fetch = _StubFetch({a.source: FetchResult(404, "not found", {})})

    findings = sources.check(fetch, [a, b])

    assert {f.subject for f in findings} == {"a", "b"}
    assert all(f.check == "source-unreachable" for f in findings)
    assert fetch.calls == [a.source]  # fetched once, not once per rule


def test_sources_check_reports_a_fetch_error_the_same_way_as_an_unreachable_status() -> (
    None
):
    rule = _rule(source="https://docs.example.invalid/timeout")
    fetch = _StubFetch({rule.source: FetchResult(0, "", {}, error="timed out")})

    findings = sources.check(fetch, [rule])

    assert len(findings) == 1
    assert findings[0].check == "source-unreachable"
    assert "timed out" in findings[0].message


def test_sources_check_reports_when_the_literal_has_left_the_page() -> None:
    rule = _rule(pattern="^ex_live_[A-Za-z0-9]{20,}$")
    fetch = _StubFetch(
        {rule.source: FetchResult(200, "we no longer publish a prefix", {})}
    )

    findings = sources.check(fetch, [rule])

    assert len(findings) == 1
    assert findings[0].check == "source-format-missing"
    assert findings[0].subject == rule.id


def test_sources_check_skips_the_content_check_when_no_literal_is_extractable() -> None:
    rule = _rule(pattern="^[0-9a-f]{40}$")  # leading_literals() -> ()
    fetch = _StubFetch({rule.source: FetchResult(200, "anything at all", {})})

    assert sources.check(fetch, [rule]) == []


def test_sources_check_uses_the_real_rule_set_by_default() -> None:
    calls: list[str] = []

    def fetch(url: str, headers: Mapping[str, str] | None) -> FetchResult:
        calls.append(url)
        return FetchResult(200, "irrelevant to this test", {})

    sources.check(fetch)

    # Every unique source is fetched once, regardless of how many rules share
    # it (Anthropic's and OpenAI's several key families, AWS's two rules).
    assert len(calls) == len({rule.source for rule in default_detector.rules()})
    assert len(calls) < len(default_detector.rules())


# ---------------------------------------------------------------------------
# endpoints.py — check()
# ---------------------------------------------------------------------------


def _endpoint_spec(**overrides: Any) -> ProviderSpec:
    base: dict[str, Any] = {
        "name": "example",
        "category": "devtools",
        "docs_url": "https://docs.example.invalid/",
        "rotation_guide_url": "https://docs.example.invalid/rotate",
        "detectable": False,
        "description": "An example provider for the drift-canary's own tests.",
        "auth": {"headers": {"Authorization": "Bearer {key}"}},
        "liveness": {
            "probe": "Widget List",
            "unauthorized_statuses": [401],
            "notes": {
                "unauthorized": "did not accept this key{message_suffix}",
                "rate_limited": "rate limited{message_suffix}",
                "unparseable": "could not be interpreted{message_suffix}",
            },
        },
        "probes": [
            {
                "service": "Widget List",
                "url": "https://api.example.invalid/widgets",
                "noun": "widgets",
                "detail": "Can list the account's widgets",
                "access": "read",
                "risk_weight": 50,
                "source": "https://docs.example.invalid/widgets",
            },
        ],
    }
    base.update(overrides)
    return ProviderSpec.model_validate(base)


def _yaml_provider(**overrides: Any) -> YamlProvider:
    return YamlProvider(_endpoint_spec(**overrides), Path("<test>"))


class _EndpointFetch:
    def __init__(self, answers: dict[str, FetchResult]) -> None:
        self._answers = answers
        self.calls: list[str] = []

    def __call__(self, url: str, headers: Mapping[str, str] | None) -> FetchResult:
        self.calls.append(url)
        return self._answers[url]


def test_endpoints_check_reports_nothing_when_the_probe_answers_unauthorized() -> None:
    provider = _yaml_provider()
    url = provider.spec.probes[0].url
    fetch = _EndpointFetch({url: FetchResult(401, "", {})})

    assert endpoints.check(fetch, [provider]) == []


def test_endpoints_check_reports_a_404_as_endpoint_missing() -> None:
    provider = _yaml_provider()
    url = provider.spec.probes[0].url
    fetch = _EndpointFetch({url: FetchResult(404, "", {})})

    findings = endpoints.check(fetch, [provider])

    assert len(findings) == 1
    assert findings[0].check == "endpoint-missing"
    assert findings[0].subject == "example / Widget List"


def test_endpoints_check_reports_a_status_outside_the_liveness_vocabulary() -> None:
    provider = _yaml_provider()
    url = provider.spec.probes[0].url
    fetch = _EndpointFetch({url: FetchResult(500, "", {})})

    findings = endpoints.check(fetch, [provider])

    assert len(findings) == 1
    assert findings[0].check == "endpoint-unexpected-status"
    assert "500" in findings[0].message


def test_endpoints_check_reports_a_deprecation_header_even_on_a_healthy_status() -> (
    None
):
    provider = _yaml_provider()
    url = provider.spec.probes[0].url
    fetch = _EndpointFetch(
        {
            url: FetchResult(
                401, "", httpx.Headers({"Sunset": "Wed, 01 Jan 2027 00:00:00 GMT"})
            )
        }
    )

    findings = endpoints.check(fetch, [provider])

    assert len(findings) == 1
    assert findings[0].check == "endpoint-deprecated"


def test_endpoints_check_reports_a_fetch_error() -> None:
    provider = _yaml_provider()
    url = provider.spec.probes[0].url
    fetch = _EndpointFetch({url: FetchResult(0, "", {}, error="connection reset")})

    findings = endpoints.check(fetch, [provider])

    assert len(findings) == 1
    assert findings[0].check == "endpoint-unreachable"
    assert "connection reset" in findings[0].message


class _NonYamlProvider(Provider):
    """A hand-written plugin: out of scope for this check (see __init__.py)."""

    name = "non-yaml"
    category = "generic"
    docs_url = "https://docs.example.invalid/"

    def detect(self, key: str) -> float:
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        return ValidationResult(valid=False)

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Any]:
        return []


def test_endpoints_check_ignores_hand_written_providers() -> None:
    fetch = _EndpointFetch({})

    assert endpoints.check(fetch, [_NonYamlProvider()]) == []
    assert fetch.calls == []


def test_endpoints_check_uses_the_real_registry_by_default() -> None:
    """npm (2 probes) and Pinecone (4 probes) are the only YAML providers
    today (roadmap R2.8) — every probe from both is fetched by default."""
    calls: list[str] = []

    def fetch(url: str, headers: Mapping[str, str] | None) -> FetchResult:
        calls.append(url)
        return FetchResult(401, "", {})

    endpoints.check(fetch)

    assert len(calls) == 6


# ---------------------------------------------------------------------------
# __main__.py
# ---------------------------------------------------------------------------


def test_render_with_no_findings() -> None:
    assert render([]) == "## keyreach drift-canary: 0 findings\n"


def test_render_pluralises_correctly_and_lists_every_finding() -> None:
    findings = [
        Finding(
            "endpoint-missing", "npm / Tokens", "returned 404", "https://x.invalid"
        ),
    ]
    text = render(findings)
    assert text.startswith("## keyreach drift-canary: 1 finding\n")
    assert "- **npm / Tokens** (`endpoint-missing`): returned 404" in text


def test_main_returns_zero_and_prints_ok_when_nothing_drifted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sources, "check", lambda fetch: [])
    monkeypatch.setattr(endpoints, "check", lambda fetch: [])

    assert main() == 0
    assert capsys.readouterr().out.strip() == "drift-canary: ok"


def test_main_returns_one_and_prints_the_report_when_something_drifted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    finding = Finding(
        "endpoint-missing", "npm / Tokens", "returned 404", "https://x.invalid"
    )
    monkeypatch.setattr(sources, "check", lambda fetch: [finding])
    monkeypatch.setattr(endpoints, "check", lambda fetch: [])

    assert main() == 1
    out = capsys.readouterr().out
    assert "1 finding" in out
    assert "npm / Tokens" in out
