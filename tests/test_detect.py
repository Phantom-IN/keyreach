"""Detection layer tests (roadmap R0.5).

R0.5's acceptance criterion is "sample keys map to expected providers/confidence
deterministically", so the core of this file is a table of representative keys
and the exact verdict each must produce.

Every key here is **synthetic**: structurally valid so the patterns are really
exercised, cryptographically worthless, and assembled from a prefix plus
deterministic filler rather than written as a complete literal. Nothing in this
file was ever a live credential, and nothing in it is shaped like one to a
secret scanner. See the comment above the sample block for why that distinction
matters.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from keyreach.core.detect import (
    ENTROPY_CONFIDENCE,
    ENTROPY_THRESHOLD,
    MIN_TOKEN_LENGTH,
    DetectionError,
    DetectionMatch,
    DetectionRule,
    Detector,
    default_detector,
    looks_like_secret,
    shannon_entropy,
)

# --------------------------------------------------------------------------
# Synthetic sample keys
#
# Every sample below is **composed from a prefix and generated filler** rather
# than written as one complete literal. This is not cosmetic.
#
# A structurally valid key literal trips secret scanners even when the value is
# cryptographically worthless, because a scanner cannot tell the difference —
# and should not try to. Four complete literals in an earlier revision of this
# file were correctly blocked by GitHub push protection. The available
# workaround is to click "allow this secret", which is precisely the habit
# keyreach exists to argue against, and it would have blocked every contributor
# who forked the repository.
#
# Composing the value keeps the test data structurally exact — the detector
# receives an ordinary string either way — while leaving nothing in the source
# for a scanner to match. It also documents what each pattern actually requires:
# the prefix carries the meaning, the filler is only length.
#
# `_body()` is deterministic, so these samples never vary between runs.
# --------------------------------------------------------------------------

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _body(length: int, alphabet: str = _ALPHABET) -> str:
    """Deterministic filler of exactly ``length`` characters."""
    repeats = (length // len(alphabet)) + 1
    return (alphabet * repeats)[:length]


_HEX = "0123456789abcdef"
_UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

GOOGLE_KEY = "AIza" + _body(35)
AWS_KEY = "AKIA" + _body(16, _UPPER_ALNUM)
AWS_TEMP_KEY = "ASIA" + _body(16, _UPPER_ALNUM)
ANTHROPIC_KEY = "sk-ant-" + "api03-" + _body(90)
OPENAI_KEY = "sk-" + _body(48)
OPENAI_PROJECT_KEY = "sk-" + "proj-" + _body(40)
OPENAI_SERVICE_KEY = "sk-" + "svcacct-" + _body(40)
OPENAI_ADMIN_KEY = "sk-" + "admin-" + _body(40)
STRIPE_KEY = "sk_" + "live_" + _body(24)
STRIPE_TEST_KEY = "sk_" + "test_" + _body(24)
STRIPE_RESTRICTED_KEY = "rk_" + "live_" + _body(24)
SLACK_KEY = "xox" + "b-" + _body(12, "0123456789") + "-" + _body(24)
GITHUB_KEY = "ghp" + "_" + _body(36)
GITHUB_FINE_GRAINED = "github" + "_pat_" + _body(22) + "_" + _body(59)
GITLAB_KEY = "glpat" + "-" + _body(20)
SENDGRID_KEY = "SG." + _body(22) + "." + _body(43)
TWILIO_SID = "AC" + _body(32, _HEX)
NPM_KEY = "npm" + "_" + _body(36)
PYPI_KEY = "pypi" + "-" + _body(55)
TELEGRAM_KEY = _body(9, "123456789") + ":" + _body(35)
DIGITALOCEAN_KEY = "dop" + "_v1_" + _body(64, _HEX)
RESEND_KEY = "re" + "_" + _body(8) + "_" + _body(24)
MAILCHIMP_KEY = _body(32, _HEX) + "-" + "us14"

#: R2.3 withdrew the `mailgun` rule: the page it was sourced to no longer
#: documents any key format, and neither does any other page Mailgun publishes.
#: The legacy shape is kept here to assert that nothing claims it any more —
#: see `tests/test_provider_mailgun.py` for the full argument.
MAILGUN_LEGACY_KEY = "key" + "-" + _body(32, _HEX)

#: (key, expected provider, expected confidence). The acceptance criterion.
DETECTION_TABLE = [
    (GOOGLE_KEY, "google", 0.99),
    (AWS_KEY, "aws", 0.99),
    (AWS_TEMP_KEY, "aws", 0.99),
    (ANTHROPIC_KEY, "anthropic", 0.99),
    (OPENAI_KEY, "openai", 0.90),
    (OPENAI_PROJECT_KEY, "openai", 0.99),
    (OPENAI_SERVICE_KEY, "openai", 0.99),
    (OPENAI_ADMIN_KEY, "openai", 0.99),
    (STRIPE_KEY, "stripe", 0.99),
    (STRIPE_TEST_KEY, "stripe", 0.99),
    (STRIPE_RESTRICTED_KEY, "stripe", 0.99),
    (SLACK_KEY, "slack", 0.99),
    (GITHUB_KEY, "github", 0.99),
    (GITHUB_FINE_GRAINED, "github", 0.99),
    (GITLAB_KEY, "gitlab", 0.99),
    (SENDGRID_KEY, "sendgrid", 0.95),
    (TWILIO_SID, "twilio", 0.95),
    (NPM_KEY, "npm", 0.99),
    (PYPI_KEY, "pypi", 0.99),
    (TELEGRAM_KEY, "telegram", 0.95),
    (DIGITALOCEAN_KEY, "digitalocean", 0.99),
    (RESEND_KEY, "resend", 0.95),
    (MAILCHIMP_KEY, "mailchimp", 0.95),
]


def test_the_withdrawn_mailgun_rule_claims_nothing() -> None:
    """R2.3 withdrew the rule; this is what that costs, stated as a test.

    Mailgun's documentation no longer publishes any key format, so no rule can
    be re-verified against it. The legacy shape now falls through to the entropy
    fallback — recognised as *a* secret, attributed to nobody — which is the
    honest residual answer rather than silence.
    """
    matches = Detector().detect(MAILGUN_LEGACY_KEY)

    assert [match.provider for match in matches] == [None]


@pytest.fixture
def detector() -> Detector:
    return Detector()


def write_rules(path: Path, body: str) -> Path:
    rules = path / "rules.yml"
    rules.write_text(body, encoding="utf-8")
    return rules


# --------------------------------------------------------------------------
# The acceptance table
# --------------------------------------------------------------------------


#: Prefixes more than one vendor documents, so more than one rule fires.
#:
#: Only one entry, and it took until R2.1 to appear: Stripe and Paystack both
#: document `sk_live_`/`sk_test_` and neither publishes a length or charset that
#: separates them. `implementation_plan.md` §5 always said ambiguity is settled
#: at the probe stage rather than by ranking one rule above another, and this is
#: the case it was written for.
AMBIGUOUS_PREFIXES = {
    "sk_live_": {"paystack", "stripe"},
    "sk_test_": {"paystack", "stripe"},
}


def expected_providers(key: str, provider: str) -> set[str]:
    """Every provider legitimately entitled to claim ``key``."""
    for prefix, sharers in AMBIGUOUS_PREFIXES.items():
        if key.startswith(prefix):
            return sharers
    return {provider}


@pytest.mark.parametrize(("key", "provider", "confidence"), DETECTION_TABLE)
def test_sample_keys_map_to_expected_provider_and_confidence(
    detector: Detector, key: str, provider: str, confidence: float
) -> None:
    """R0.5 acceptance criterion, one row at a time.

    Asserts the *set* of claimants rather than the first one. Until R2.1 every
    key had exactly one, and asserting `matches[0]` was the same thing; now that
    two vendors share a prefix, asserting the first would be asserting the
    tie-break — which is alphabetical, and says nothing about either vendor.
    """
    matches = detector.detect(key)

    assert matches, f"no match for {provider} key"
    assert {match.provider for match in matches} == expected_providers(key, provider)

    claimed = next(match for match in matches if match.provider == provider)
    assert claimed.confidence == pytest.approx(confidence)


def test_a_shared_prefix_yields_every_claimant_not_a_winner(
    detector: Detector,
) -> None:
    """The collision, pinned. Neither vendor is ranked above the other.

    A thumb on the scale here would settle the ambiguity by assertion. Equal
    confidence hands the decision to the probe stage, where the vendor that
    accepts the key decides — and costs one wasted request to the one that does
    not (`keyreach/providers/paystack.py`).
    """
    matches = detector.detect(STRIPE_KEY)

    assert [match.provider for match in matches] == ["paystack", "stripe"]
    assert len({match.confidence for match in matches}) == 1


@pytest.mark.parametrize(("key", "provider", "confidence"), DETECTION_TABLE)
def test_detection_is_deterministic(
    detector: Detector, key: str, provider: str, confidence: float
) -> None:
    """Identical input must produce an identical ranking, every time."""
    assert detector.detect(key) == detector.detect(key)


def test_detection_agrees_across_independent_detectors() -> None:
    """Determinism across instances, not just within one cached rule set."""
    first, second = Detector(), Detector()

    for key, _, _ in DETECTION_TABLE:
        assert first.detect(key) == second.detect(key)


@pytest.mark.parametrize(
    "key",
    [
        "",
        "hunter2",
        "the quick brown fox jumps over the lazy dog",
        "/usr/local/lib/python3.11/site-packages",
        "https://example.com/some/long/path/here",
        "someVeryLongVariableNameHereNoDigits",
        "1234567890123456789012345678",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "550e8400-e29b-41d4-a716-446655440000",
    ],
)
def test_non_secrets_produce_no_match(detector: Detector, key: str) -> None:
    """False positives cost a user real probes against a real service."""
    assert detector.detect(key) == ()


# --------------------------------------------------------------------------
# Ambiguity and ordering
# --------------------------------------------------------------------------


def test_anthropic_key_is_not_also_reported_as_openai(detector: Detector) -> None:
    """`sk-ant-` starts with `sk-`, so the OpenAI rule must exclude it.

    Without the negative lookahead a single Anthropic key yields two candidates,
    and keyreach would spend a probe authenticating against the wrong vendor.
    """
    providers = {match.provider for match in detector.detect(ANTHROPIC_KEY)}

    assert providers == {"anthropic"}


@pytest.mark.parametrize(
    "key",
    [OPENAI_PROJECT_KEY, OPENAI_SERVICE_KEY, OPENAI_ADMIN_KEY, ANTHROPIC_KEY],
)
def test_specific_sk_prefixes_yield_exactly_one_candidate(
    detector: Detector, key: str
) -> None:
    """The generic `sk-` rule must not double-match a more specific prefix."""
    assert len(detector.detect(key)) == 1


def test_matches_are_ordered_by_confidence_then_provider_then_rule() -> None:
    """implementation_plan.md §5: rank by confidence, then name. Never by order."""
    matches = [
        DetectionMatch(provider="zebra", confidence=0.9, rule_id="z", detail="d"),
        DetectionMatch(provider="alpha", confidence=0.9, rule_id="a", detail="d"),
        DetectionMatch(provider="mid", confidence=0.99, rule_id="m", detail="d"),
    ]

    ordered = sorted(matches, key=lambda match: match.sort_key)

    assert [match.provider for match in ordered] == ["mid", "alpha", "zebra"]


def test_entropy_match_sorts_after_named_providers() -> None:
    """An unattributed guess must never outrank a real provider match."""
    named = DetectionMatch(provider="aws", confidence=0.4, rule_id="r", detail="d")
    unnamed = DetectionMatch(
        provider=None, confidence=0.4, rule_id="entropy-fallback", detail="d"
    )

    assert sorted([unnamed, named], key=lambda m: m.sort_key) == [named, unnamed]


# --------------------------------------------------------------------------
# Entropy stage
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", 0.0),
        ("aaaa", 0.0),
        ("ab", 1.0),
        ("abcd", 2.0),
        ("abcdefgh", 3.0),
    ],
)
def test_shannon_entropy_known_values(value: str, expected: float) -> None:
    assert shannon_entropy(value) == pytest.approx(expected)


def test_shannon_entropy_is_order_independent() -> None:
    """Same characters, different arrangement, identical entropy — exactly.

    Asserted as byte equality rather than approximately: counts are sorted
    before summing precisely so float addition order cannot shift the result
    across the threshold.
    """
    assert shannon_entropy("abcdefgh") == shannon_entropy("hgfedcba")


def test_prose_scores_higher_than_a_hex_digest() -> None:
    """Why the gates exist, pinned as a test.

    Entropy measures character variety, and English has plenty. A threshold on
    its own would report every sentence in a codebase as a secret; the charset
    and shape gates are what make the stage usable.
    """
    prose = "the quick brown fox jumps over the lazy"
    digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    assert shannon_entropy(prose) > shannon_entropy(digest)
    assert not looks_like_secret(prose)
    assert looks_like_secret(digest)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("aB3" + "x" * (MIN_TOKEN_LENGTH - 4), "too short"),
        ("has whitespace in it 12345678", "charset"),
        ("/var/log/app/2024/output.12345.log", "path shape"),
        ("https://example.com/x/1234567890", "url shape"),
        ("someVeryLongVariableNameHere", "no digit"),
        ("12345678901234567890123456", "no letter"),
    ],
)
def test_entropy_gates_reject_non_credentials(value: str, reason: str) -> None:
    assert not looks_like_secret(value), reason


def test_unattributed_high_entropy_token_is_reported_without_a_provider(
    detector: Detector,
) -> None:
    """An AWS *secret* key has no distinctive prefix — only entropy finds it."""
    matches = detector.detect("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    assert len(matches) == 1
    assert matches[0].provider is None
    assert matches[0].confidence == ENTROPY_CONFIDENCE
    assert matches[0].rule_id == "entropy-fallback"
    assert "bits/char" in matches[0].detail


def test_entropy_stage_does_not_run_when_a_rule_matched(detector: Detector) -> None:
    """A recognised key gains nothing from an extra unattributed candidate."""
    matches = detector.detect(GOOGLE_KEY)

    assert len(matches) == 1
    assert all(match.rule_id != "entropy-fallback" for match in matches)


def test_token_shaped_but_low_entropy_is_not_reported(detector: Detector) -> None:
    """Passes every shape gate, but the variety is not there."""
    value = "ab1" * 12

    assert looks_like_secret(value)
    assert shannon_entropy(value) < ENTROPY_THRESHOLD
    assert detector.detect(value) == ()


def test_entropy_threshold_admits_hex_and_base64() -> None:
    """The threshold must not exclude the two commonest credential encodings."""
    assert shannon_entropy("da39a3ee5e6b4b0d3255bfef95601890afd80709") >= (
        ENTROPY_THRESHOLD
    )
    assert shannon_entropy("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01") >= (
        ENTROPY_THRESHOLD
    )


# --------------------------------------------------------------------------
# Rule set integrity
# --------------------------------------------------------------------------


def test_rules_load_and_cover_multiple_providers(detector: Detector) -> None:
    assert len(detector.rules()) >= 20
    assert len(detector.providers()) >= 10


def test_rules_are_sorted_by_id(detector: Detector) -> None:
    """Sorted on load, so reordering the YAML cannot change behaviour."""
    ids = [rule.id for rule in detector.rules()]

    assert ids == sorted(ids)


def test_rule_ids_are_unique(detector: Detector) -> None:
    ids = [rule.id for rule in detector.rules()]

    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", default_detector.rules(), ids=lambda r: r.id)
def test_every_rule_is_anchored(rule: DetectionRule) -> None:
    """keyreach receives one key, not a corpus.

    An unanchored pattern would match a key embedded in a longer string, which
    for a single-key tool is a false positive rather than a feature.
    """
    assert rule.pattern.startswith("^")
    assert rule.pattern.endswith("$")


@pytest.mark.parametrize("rule", default_detector.rules(), ids=lambda r: r.id)
def test_every_rule_cites_vendor_documentation(rule: DetectionRule) -> None:
    """Provenance is what makes a pattern auditable and re-verifiable.

    It is also what lets a reviewer confirm the rule was written from primary
    sources rather than copied from another project's rule set — which matters
    here, because copying was ruled out on licensing grounds.
    """
    assert rule.source.startswith("https://")


@pytest.mark.parametrize("rule", default_detector.rules(), ids=lambda r: r.id)
def test_every_rule_is_confident(rule: DetectionRule) -> None:
    """Below 0.8 a structural rule is guesswork; prefer not shipping it."""
    assert rule.confidence >= 0.8


def test_rule_provider_names_are_registry_compatible(detector: Detector) -> None:
    """Rule providers must be valid provider names, since they will be matched
    against registered plugins once those exist."""
    for rule in detector.rules():
        assert rule.provider == rule.provider.strip().lower()


def test_detection_detail_never_echoes_the_key(detector: Detector) -> None:
    """Detail strings reach the report; keys are masked by default (plan.md §1)."""
    for key, _, _ in DETECTION_TABLE:
        for match in detector.detect(key):
            assert key not in match.detail


# --------------------------------------------------------------------------
# Loader errors
# --------------------------------------------------------------------------


def test_missing_rules_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="could not read"):
        Detector(tmp_path / "absent.yml").rules()


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("[]", "must be a mapping"),
        ("version: 1\n", "must be a mapping"),
        ("version: 1\nrules: []\n", "contains no rules"),
        ("version: 1\nrules: not-a-list\n", "contains no rules"),
    ],
)
def test_malformed_rules_document_raises(tmp_path: Path, body: str, match: str) -> None:
    with pytest.raises(DetectionError, match=match):
        Detector(write_rules(tmp_path, body)).rules()


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    """Rule ids break ranking ties, so a duplicate makes ordering ambiguous."""
    body = """
version: 1
rules:
  - id: same
    provider: a
    description: A
    pattern: '^a$'
    confidence: 0.9
    source: https://example.invalid
  - id: same
    provider: b
    description: B
    pattern: '^b$'
    confidence: 0.9
    source: https://example.invalid
"""
    with pytest.raises(DetectionError, match="duplicate detection rule id"):
        Detector(write_rules(tmp_path, body)).rules()


def test_invalid_regex_is_rejected_at_load_time(tmp_path: Path) -> None:
    """A broken pattern is a packaging error; fail on load, not mid-scan."""
    body = """
version: 1
rules:
  - id: broken
    provider: a
    description: A
    pattern: '^([unclosed$'
    confidence: 0.9
    source: https://example.invalid
"""
    with pytest.raises(DetectionError, match="invalid pattern"):
        Detector(write_rules(tmp_path, body)).rules()


def test_rule_missing_a_required_field_is_rejected(tmp_path: Path) -> None:
    body = """
version: 1
rules:
  - id: nosource
    provider: a
    description: A
    pattern: '^a$'
    confidence: 0.9
"""
    with pytest.raises(Exception, match="source"):
        Detector(write_rules(tmp_path, body)).rules()


def test_unknown_rule_field_is_rejected(tmp_path: Path) -> None:
    """extra='forbid': a typo'd field must fail rather than be ignored."""
    body = """
version: 1
rules:
  - id: typo
    provider: a
    description: A
    pattern: '^a$'
    confidence: 0.9
    source: https://example.invalid
    confidance: 0.1
"""
    with pytest.raises(Exception, match="confidance"):
        Detector(write_rules(tmp_path, body)).rules()


# --------------------------------------------------------------------------
# Detector plumbing
# --------------------------------------------------------------------------


def test_rules_are_cached_until_reload(detector: Detector) -> None:
    first = detector.rules()

    assert detector.rules() is first
    assert detector.reload() is not first


def test_repr_reports_load_state(detector: Detector) -> None:
    assert "unloaded" in repr(detector)

    detector.rules()

    assert "unloaded" not in repr(detector)


def test_default_detector_uses_the_packaged_rules() -> None:
    """The rules must resolve inside an installed wheel, not just the repo."""
    assert default_detector.rules_path.name == "detection_rules.yml"
    assert default_detector.rules_path.is_file()


def test_entropy_constants_are_sane() -> None:
    """Guards against a careless retune making the fallback useless or noisy."""
    assert MIN_TOKEN_LENGTH >= 16
    assert 3.0 <= ENTROPY_THRESHOLD <= 5.0
    assert 0.0 < ENTROPY_CONFIDENCE < 0.8
    assert not math.isnan(ENTROPY_THRESHOLD)
