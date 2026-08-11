"""AWS provider tests (roadmap R1.3).

R1.3's acceptance criterion: "default run is minimal/read-only; aggressive mode
gated". Both halves run end to end below, against **one** cassette that records
every probe including the aggressive ones — so the default run leaving six
recorded responses untouched is a fact about the gate, not about the fixture.

Three things here carry most of the weight:

* ``test_the_signature_matches_the_reference_implementation`` — keyreach signs
  AWS requests itself, and a signer that is subtly wrong fails in the worst
  possible way: AWS answers ``SignatureDoesNotMatch``, which this plugin reports
  as "the secret does not match the ID". A confident, wrong verdict. The vectors
  are pinned from AWS's own reference implementation.
* ``test_root_credentials_are_reported_as_administrative`` — the finding this
  provider exists to get right.
* ``test_aggressive_probes_do_not_run_by_default`` — ``plan.md`` §11 in one
  assertion.

**On the fixtures.** They are constructed from AWS's published XML response
shapes, not recorded from a live credential — keyreach's own rules forbid
holding one, and probing somebody else's would be unauthorised. They prove the
parsing and the decision rules, not that AWS still answers this way. Provider
drift is a known structural risk (`plan.md` §12); roadmap **R2.10** is the
answer to it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from keyreach.core.detect import default_detector
from keyreach.core.engine import Engine, EngineResult
from keyreach.core.http import Cassette, ProbeResponse, RecordMode
from keyreach.core.models import AccessLevel, Severity
from keyreach.core.registry import ProviderRegistry, validate_provider
from keyreach.providers.aws import (
    PROBES,
    SAFE_PARAM_CHARS,
    AWSProvider,
    Credential,
    _count_tag,
    _identity,
    _is_root,
    _Mode,
    _summary,
    _uri_encode,
    _xml_value,
    parse_credential,
    probes_for,
    sign,
    validation_probe,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Composed from parts, never written as one literal — a joined AWS credential
#: matches keyreach's own detector and GitHub push protection, and the second
#: would reject the push (see `tools/guardrails/no_secrets.py`). The values are
#: AWS's own documentation examples.
ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
TEMP_KEY_ID = "ASIA" + "IOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
SESSION_TOKEN = "FQoGZXIvYXdzEBYaDEXAMPLESESSIONTOKEN" + "/////wEXAMPLE="

KEY = f"{ACCESS_KEY_ID}:{SECRET}"
TEMP_KEY = f"{TEMP_KEY_ID}:{SECRET}:{SESSION_TOKEN}"

#: A clock pinned for every run, proving nothing time-dependent reaches output.
FIXED_CLOCK = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)


def run(fixture: str, key: str = KEY, *, aggressive: bool = False) -> EngineResult:
    """One full pipeline run against a committed cassette. Opens no socket."""
    engine = Engine(
        registry=ProviderRegistry("keyreach.providers"),
        cassette=Cassette(FIXTURES / f"{fixture}.json"),
        mode=RecordMode.REPLAY,
        aggressive=aggressive,
        clock=lambda: FIXED_CLOCK,
    )
    return asyncio.run(engine.run(key))


def services(result: EngineResult) -> list[str]:
    return [capability.service for capability in result.capabilities]


# ---------------------------------------------------------------------------
# Plugin metadata and discovery
# ---------------------------------------------------------------------------


def test_metadata_satisfies_the_registry() -> None:
    """`CLAUDE.md` asks every plugin to assert this itself."""
    validate_provider(AWSProvider(), origin="keyreach.providers.aws")


def test_the_registry_discovers_it() -> None:
    registry = ProviderRegistry("keyreach.providers")

    assert "aws" in [provider.name for provider in registry.providers()]


def test_it_credits_the_prior_art_it_was_built_from() -> None:
    """Attribution is a hard rule, not a courtesy (`plan.md` §5.6)."""
    assert AWSProvider().credit == "enumerate-iam"


# ---------------------------------------------------------------------------
# The credential format — the decision this provider turns on
# ---------------------------------------------------------------------------


def test_a_joined_credential_is_split_into_its_parts() -> None:
    credential = parse_credential(KEY)

    assert credential is not None
    assert credential.access_key_id == ACCESS_KEY_ID
    assert credential.secret_access_key == SECRET
    assert credential.session_token is None


def test_a_temporary_credential_carries_its_session_token() -> None:
    credential = parse_credential(TEMP_KEY)

    assert credential is not None
    assert credential.access_key_id == TEMP_KEY_ID
    assert credential.session_token == SESSION_TOKEN


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(ACCESS_KEY_ID, id="bare-access-key-id"),
        pytest.param(f"{ACCESS_KEY_ID}:short", id="secret-too-short"),
        pytest.param(f"NOPE{'A' * 16}:{SECRET}", id="wrong-prefix"),
        pytest.param(f"{ACCESS_KEY_ID}:{SECRET}:x", id="session-token-too-short"),
        pytest.param("", id="empty"),
    ],
)
def test_anything_that_cannot_sign_is_not_a_credential(candidate: str) -> None:
    """An access key ID alone cannot authenticate, however much it looks like one."""
    assert parse_credential(candidate) is None


def test_a_bare_access_key_id_is_still_detected() -> None:
    """Recognising one in a leak is useful even though it cannot be probed."""
    assert AWSProvider().detect(ACCESS_KEY_ID) == 0.99


def test_a_bare_access_key_id_says_what_is_missing_rather_than_dead() -> None:
    """The failure mode this avoids: reporting a live credential as invalid.

    keyreach cannot probe an access key ID on its own, and saying "not valid"
    would read as "this key is dead" — which is both wrong and the more
    dangerous direction to be wrong in.
    """
    result = run("aws_invalid", ACCESS_KEY_ID)
    note = result.outcomes[0].validation.note

    assert not result.valid
    assert "cannot authenticate on its own" in note
    assert "secret access key" in note


@pytest.mark.parametrize("key", [KEY, TEMP_KEY, ACCESS_KEY_ID])
def test_the_plugin_and_the_rule_set_agree_on_the_credential_format(key: str) -> None:
    """Two places describe an AWS credential. They must not drift apart."""
    matched = [
        match.provider
        for match in default_detector.detect(key)
        if match.provider is not None
    ]

    assert matched == ["aws"]
    assert AWSProvider().detect(key) > 0.0


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param("AKIA" + "lowercase12345678", id="lowercase-body"),
        pytest.param("AKIA" + "SHORT", id="too-short"),
        pytest.param("prefix" + ACCESS_KEY_ID, id="not-anchored-at-start"),
        pytest.param("", id="empty"),
    ],
)
def test_detect_is_a_strict_structural_match(candidate: str) -> None:
    assert AWSProvider().detect(candidate) == 0.0


def test_detect_is_pure() -> None:
    provider = AWSProvider()

    assert {provider.detect(KEY) for _ in range(5)} == {0.99}


# ---------------------------------------------------------------------------
# SigV4 — verified against AWS's own reference implementation
# ---------------------------------------------------------------------------

#: Vectors produced by **botocore** (AWS's own SigV4 implementation, Apache-2.0)
#: in a throwaway environment during R1.3, and pinned here. botocore is not a
#: keyreach dependency and no code was taken from it; these are computed facts,
#: which is what lets CI check the signer without installing AWS's SDK.
#:
#: All twelve probes were checked this way, for both long-term and temporary
#: credentials — 24 comparisons, all matching. These four cover the branches:
#: with and without a session token, with and without `x-amz-content-sha256`,
#: and with and without query parameters.
SIGNATURE_VECTORS = [
    pytest.param(
        "20260811T192249Z",
        "sts.amazonaws.com",
        "sts",
        {"Action": "GetCallerIdentity", "Version": "2011-06-15"},
        False,
        None,
        "5e369eeb90d06cd8c7189c297999ab5c7470e4f16adcf64b93dc719d787a0459",
        id="long-term-credential",
    ),
    pytest.param(
        "20260811T192249Z",
        "sts.amazonaws.com",
        "sts",
        {"Action": "GetCallerIdentity", "Version": "2011-06-15"},
        False,
        SESSION_TOKEN,
        "c2dea4a412416b8ed42cbb3ef55647125e646773cfb626530ef55bc92a403c67",
        id="temporary-credential",
    ),
    pytest.param(
        "20260811T192249Z",
        "s3.amazonaws.com",
        "s3",
        {},
        True,
        None,
        "d20394fca25af6ca25d92327f1183e9cf0eff06ce9b66cfee88065269b51ccb7",
        id="s3-signs-the-payload-header",
    ),
    pytest.param(
        "20260811T192249Z",
        "iam.amazonaws.com",
        "iam",
        {"Action": "ListUsers", "Version": "2010-05-08"},
        False,
        None,
        "e564f9e78cb546cb40deb396dfdb8b62be3e505377f341be776f069eda8972fb",
        id="iam-query-protocol",
    ),
]


@pytest.mark.parametrize(
    ("stamp", "host", "service", "params", "payload_header", "token", "expected"),
    SIGNATURE_VECTORS,
)
def test_the_signature_matches_the_reference_implementation(  # noqa: PLR0917
    stamp: str,
    host: str,
    service: str,
    params: dict[str, str],
    payload_header: bool,
    token: str | None,
    expected: str,
) -> None:
    """A subtly wrong signer produces a confident, wrong verdict.

    AWS answers a bad signature with `SignatureDoesNotMatch`, which this plugin
    reports as "the ID is real; the pair is not". Every live credential would be
    reported that way, and the report would be wrong in the direction nobody
    checks. Hence a pinned vector rather than a round-trip through the plugin.
    """
    credential = Credential(
        access_key_id=TEMP_KEY_ID if token else ACCESS_KEY_ID,
        secret_access_key=SECRET,
        session_token=token,
    )
    when = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)

    headers = sign(
        credential,
        host=host,
        region="us-east-1",
        service=service,
        params=params,
        now=when,
        sign_payload_header=payload_header,
    )

    assert headers["authorization"].endswith(f"Signature={expected}")


def test_the_signature_never_travels_in_the_url() -> None:
    """Which is what makes an AWS cassette committable at all.

    Header-borne signing means the recorded URL carries no credential material
    and no timestamp, so a fixture recorded once replays for anyone, forever.
    """
    headers = sign(
        Credential(access_key_id=ACCESS_KEY_ID, secret_access_key=SECRET),
        host="sts.amazonaws.com",
        region="us-east-1",
        service="sts",
        params={"Action": "GetCallerIdentity"},
        now=FIXED_CLOCK,
    )

    assert set(headers) == {"authorization", "x-amz-date"}
    assert "host" not in headers


def test_a_session_token_is_signed_not_merely_attached() -> None:
    """AWS requires the token inside the signature for these services."""
    headers = sign(
        Credential(
            access_key_id=TEMP_KEY_ID,
            secret_access_key=SECRET,
            session_token=SESSION_TOKEN,
        ),
        host="sts.amazonaws.com",
        region="us-east-1",
        service="sts",
        params={},
        now=FIXED_CLOCK,
    )

    assert headers["x-amz-security-token"] == SESSION_TOKEN
    assert "x-amz-security-token" in headers["authorization"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("AZaz09-._~", "AZaz09-._~", id="unreserved-untouched"),
        pytest.param("a b", "a%20b", id="space-is-percent-twenty-not-plus"),
        pytest.param("/eng/", "%2Feng%2F", id="slash-encoded"),
        pytest.param("a+b", "a%2Bb", id="plus-encoded"),
        pytest.param("é", "%C3%A9", id="multibyte"),
    ],
)
def test_uri_encode_follows_aws_rules_not_the_usual_ones(
    raw: str, expected: str
) -> None:
    """AWS's `UriEncode` is stricter than ordinary URL quoting, and says so."""
    assert _uri_encode(raw) == expected


def test_every_probe_parameter_avoids_the_encoding_trap() -> None:
    """The invariant behind `SAFE_PARAM_CHARS`, enforced rather than trusted.

    keyreach signs the parameter dict while the HTTP layer encodes that same
    dict into the URL, and the two disagree about the space character: `httpx`
    writes `+`, AWS demands `%20`. A parameter containing a space would be
    signed one way and sent another, AWS would answer `SignatureDoesNotMatch`,
    and keyreach would report a live credential as a mismatched pair. Every
    parameter is alphanumeric today; this fails the day one is not.
    """
    for probe in PROBES:
        for name, value in probe.params.items():
            assert SAFE_PARAM_CHARS.match(name), f"{probe.service}: {name}"
            assert SAFE_PARAM_CHARS.match(value), f"{probe.service}: {value}"


# ---------------------------------------------------------------------------
# The aggressive gate — R1.3's acceptance criterion
# ---------------------------------------------------------------------------


def test_aggressive_probes_do_not_run_by_default() -> None:
    """`plan.md` §11, in one assertion.

    The cassette records all twelve probes, so every aggressive response is
    sitting there available. The default run must still not produce them —
    which makes this a test of the gate rather than of the fixture.
    """
    default = services(run("aws_valid"))

    assert "Amazon EC2 Instances (us-east-1)" not in default
    assert "AWS IAM Users" not in default
    assert len(default) == 5


def test_the_gate_opens_only_when_asked() -> None:
    default = run("aws_valid")
    opted_in = run("aws_valid", aggressive=True)

    assert set(services(default)) < set(services(opted_in))
    assert "Amazon EC2 Instances (us-east-1)" in services(opted_in)
    assert "Amazon RDS Instances (us-east-1)" in services(opted_in)


def test_an_aggressive_finding_says_how_it_was_found() -> None:
    """A reader should be able to tell which findings cost a sweep."""
    ec2 = next(
        capability
        for capability in run("aws_valid", aggressive=True).capabilities
        if capability.service == "Amazon EC2 Instances (us-east-1)"
    )

    assert "opt-in aggressive enumeration" in ec2.detail


def test_default_findings_are_not_marked_as_aggressive() -> None:
    for capability in run("aws_valid").capabilities:
        assert "aggressive" not in capability.detail


def test_the_default_probe_set_is_about_the_caller_itself() -> None:
    """Minimal means minimal: six requests, all about this credential."""
    default = probes_for(aggressive=False)

    assert len(default) == 6
    assert all(probe.mode is _Mode.DEFAULT for probe in default)
    assert {probe.service for probe in default} < {
        probe.service for probe in probes_for(aggressive=True)
    }


def test_validation_reuses_a_probe_endpoint() -> None:
    """One request, not two: validation is also the cheapest capability probe."""
    assert validation_probe() in probes_for(aggressive=False)


# ---------------------------------------------------------------------------
# Root credentials — a documented rule, not an inference
# ---------------------------------------------------------------------------


def test_root_credentials_are_reported_as_administrative() -> None:
    """AWS documents root as unrestricted and unconstrainable by IAM policy.

    So the ARN establishes administrative access by the vendor's own access
    model, exactly as Anthropic's unscoped admin keys did in R1.2 — not by
    inferring a write from a read. Every other capability here stays READ.
    """
    result = run("aws_root")
    root = next(
        capability
        for capability in result.capabilities
        if capability.service == "AWS Account (root credentials)"
    )

    assert result.score.severity is Severity.CRITICAL
    assert root.access is AccessLevel.ADMIN
    assert root.data_sensitive
    assert "no IAM policy can constrain" in root.detail


def test_a_non_root_credential_gets_no_root_capability() -> None:
    assert "AWS Account (root credentials)" not in services(run("aws_valid"))


def test_every_other_capability_is_read() -> None:
    """Reading IAM does not establish writing it, and keyreach will not claim it."""
    for capability in run("aws_valid", aggressive=True).capabilities:
        assert capability.access is AccessLevel.READ


@pytest.mark.parametrize(
    ("arn", "expected"),
    [
        pytest.param("arn:aws:iam::123456789012:root", True, id="root"),
        pytest.param("arn:aws:iam::123456789012:user/root-cause", False, id="user"),
        pytest.param("arn:aws:sts::123456789012:assumed-role/a/b", False, id="role"),
    ],
)
def test_root_is_recognised_by_the_arn_suffix(arn: str, expected: bool) -> None:
    assert _is_root(f"<Arn>{arn}</Arn>") is expected


def test_a_response_without_an_arn_is_not_root() -> None:
    assert _is_root("<Account>123456789012</Account>") is False


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_the_account_and_principal_are_recovered() -> None:
    """An exposed credential that names its own account and principal."""
    identity = run("aws_valid").outcomes[0].validation.identity

    assert identity is not None
    assert identity.account == "123456789012"
    assert identity.owner == "arn:aws:iam::123456789012:user/deploy-bot"
    assert identity.extra == {"user_id": "AIDACKCEVSQ6C2EXAMPLE"}


def test_an_identity_without_a_user_id_still_reports_the_account() -> None:
    identity = _identity("<Account>123456789012</Account>")

    assert identity is not None
    assert identity.account == "123456789012"
    assert identity.extra == {}


def test_an_unrecognisable_body_yields_no_identity() -> None:
    assert _identity("<html/>") is None


# ---------------------------------------------------------------------------
# Reading XML without parsing it
# ---------------------------------------------------------------------------


def test_a_value_is_read_without_an_xml_parser() -> None:
    """keyreach never hands a stranger's document to `xml.etree`.

    That parser is documented as vulnerable to billion-laughs and
    quadratic-blowup inputs, and everything keyreach needs from an AWS response
    is one element's text or a count of a repeated tag.
    """
    assert _xml_value("<Code>AccessDenied</Code>", "Code") == "AccessDenied"
    assert _xml_value("<Other>x</Other>", "Code") is None


def test_a_tag_count_does_not_match_a_longer_tag_that_starts_the_same() -> None:
    """`<Buckets>` wraps `<Bucket>`, and counting both would double the number.

    The evidence line is a claim about how much the credential reached. Getting
    it wrong by one is the kind of small error that makes a triager stop
    believing the larger ones.
    """
    body = "<Buckets><Bucket><Name>a</Name></Bucket><Bucket><Name>b</Name></Bucket></Buckets>"

    assert _count_tag(body, "Bucket") == 2


def test_a_tag_with_attributes_is_still_counted() -> None:
    assert _count_tag('<item id="1"/><item id="2"/>', "item") == 2


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param("<Buckets></Buckets>", "buckets: none present", id="empty"),
        pytest.param("<Bucket>a</Bucket>", "buckets: 1 listed", id="one"),
        pytest.param(
            "<Bucket>a</Bucket><Bucket>b</Bucket>", "buckets: 2 listed", id="many"
        ),
    ],
)
def test_the_evidence_summary_counts_without_quoting(body: str, expected: str) -> None:
    buckets = next(probe for probe in PROBES if probe.service == "Amazon S3 Buckets")
    response = ProbeResponse(method="GET", url="u", status_code=200, text=body)

    assert _summary(buckets, response) == expected


def test_a_probe_with_nothing_to_count_still_proves_access() -> None:
    identity_probe = validation_probe()
    response = ProbeResponse(method="GET", url="u", status_code=200, text="<x/>")

    assert _summary(identity_probe, response) == "request accepted"


def test_evidence_does_not_carry_the_infrastructure_it_found() -> None:
    """A report gets pasted into a ticket. It must not become an inventory."""
    buckets = next(
        capability
        for capability in run("aws_valid").capabilities
        if capability.service == "Amazon S3 Buckets"
    )

    assert "buckets: 3 listed" in buckets.evidence
    assert "northwind-db-backups" not in buckets.evidence


# ---------------------------------------------------------------------------
# Masking a composite credential
# ---------------------------------------------------------------------------


def test_the_secret_never_appears_in_any_output() -> None:
    result = run("aws_valid", aggressive=True)
    rendered = result.model_dump_json()

    assert SECRET not in rendered
    assert KEY not in rendered


def test_the_access_key_id_alone_is_redacted_too() -> None:
    """The reason `ProbeContext.protect` exists.

    The redactor is seeded with the whole pasted string. `iam:ListAccessKeys`
    echoes back just the access key ID, which that seed would not have masked —
    so the provider registers the parsed parts as well.
    """
    keys = next(
        capability
        for capability in run("aws_valid").capabilities
        if capability.service == "AWS IAM Access Keys"
    )
    recorded = (FIXTURES / "aws_valid.json").read_text(encoding="utf-8")

    assert ACCESS_KEY_ID not in keys.evidence
    assert ACCESS_KEY_ID not in recorded
    assert "&lt;key&gt;" in recorded


def test_the_proof_of_concept_carries_no_credential_at_all() -> None:
    """Reproduction is an AWS CLI command, which reads ambient credentials.

    A signed `curl` would have to embed either the secret or a signature that
    expires in minutes. The CLI equivalent is read-only, obvious to a reviewer,
    and carries nothing.
    """
    for capability in run("aws_valid", aggressive=True).capabilities:
        assert capability.poc is not None
        assert capability.poc.startswith("aws ")
        assert SECRET not in capability.poc
        assert ACCESS_KEY_ID not in capability.poc


def test_no_committed_fixture_contains_a_credential() -> None:
    for name in ("valid", "invalid", "root"):
        text = (FIXTURES / f"aws_{name}.json").read_text(encoding="utf-8")

        assert SECRET not in text
        assert ACCESS_KEY_ID not in text


# ---------------------------------------------------------------------------
# Validation outcomes
# ---------------------------------------------------------------------------


def test_an_unknown_access_key_id_is_reported_as_invalid() -> None:
    result = run("aws_invalid")

    assert not result.valid
    assert result.capabilities == ()
    assert "does not accept this access key ID" in result.outcomes[0].validation.note


def validate_against(status: int, body: str, key: str = KEY) -> object:
    """Drive `validate()` against one synthetic response, without a cassette."""

    class _Stub:
        """Minimal ProbeContext stand-in for the branches cassettes do not cover."""

        aggressive = False

        def protect(self, secret: str) -> None:
            del secret

        def now(self) -> datetime:
            return FIXED_CLOCK

        async def get(
            self, url: str, *, params: object = None, headers: object = None
        ) -> ProbeResponse:
            del url, params, headers
            return ProbeResponse(
                method="GET",
                url="https://sts.amazonaws.com/",
                status_code=status,
                text=body,
            )

    return asyncio.run(AWSProvider().validate(key, _Stub()))  # type: ignore[arg-type]


def aws_error(code: str) -> str:
    return (
        f"<ErrorResponse><Error><Code>{code}</Code>"
        "<Message>refused</Message></Error></ErrorResponse>"
    )


def test_a_wrong_secret_is_distinguished_from_an_unknown_id() -> None:
    """AWS tells you which it is, and the difference matters to the recipient.

    "This ID is real but you have the wrong secret" says the credential exists
    and is worth hunting for; "AWS has never heard of this ID" does not.
    """
    result = validate_against(403, aws_error("SignatureDoesNotMatch"))

    assert not result.valid  # type: ignore[attr-defined]
    assert "The ID is real; the pair is not" in result.note  # type: ignore[attr-defined]


def test_a_deactivated_key_is_reported_as_not_accepted() -> None:
    result = validate_against(403, aws_error("InvalidClientTokenId.Inactive"))

    assert not result.valid  # type: ignore[attr-defined]
    assert "Inactive" in result.note  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "code", ["ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired"]
)
def test_expired_temporary_credentials_say_they_were_real(code: str) -> None:
    """Expired is not the same as fake, and the role behind it still matters."""
    result = validate_against(403, aws_error(code), TEMP_KEY)

    assert not result.valid  # type: ignore[attr-defined]
    assert "expired" in result.note  # type: ignore[attr-defined]
    assert "still worth checking" in result.note  # type: ignore[attr-defined]


def test_an_explicit_deny_still_means_the_credential_is_live() -> None:
    """AWS documents GetCallerIdentity as needing no permissions at all.

    So a refusal here is an explicit deny in a policy, not a missing grant —
    and the credential behind it is live.
    """
    result = validate_against(403, aws_error("AccessDenied"))

    assert result.valid  # type: ignore[attr-defined]
    assert "explicit deny" in result.note  # type: ignore[attr-defined]


def test_an_uninterpretable_response_says_so_rather_than_guessing() -> None:
    result = validate_against(500, "<html>gateway</html>")

    assert not result.valid  # type: ignore[attr-defined]
    assert "not established either way" in result.note  # type: ignore[attr-defined]


def test_enumerate_returns_nothing_without_a_usable_credential() -> None:
    """Unreachable through the engine, because enumeration follows validation.

    Asserted directly rather than waved through with a `pragma: no cover`: the
    guard is what stops a bare access key ID from reaching the signer.
    """

    class _Stub:
        aggressive = False

    found = asyncio.run(AWSProvider().enumerate(ACCESS_KEY_ID, _Stub()))  # type: ignore[arg-type]

    assert found == []


# ---------------------------------------------------------------------------
# Probe table
# ---------------------------------------------------------------------------


def test_every_probe_cites_the_documentation_it_came_from() -> None:
    refs = {
        capability.service: capability.resource_ref
        for capability in run("aws_valid", aggressive=True).capabilities
    }

    for probe in PROBES:
        assert probe.source.startswith("https://")
        if probe.service in refs:
            assert refs[probe.service] == probe.source


def test_probes_are_uniquely_named() -> None:
    names = [probe.service for probe in PROBES]

    assert len(names) == len(set(names))


def test_only_s3_signs_the_payload_header() -> None:
    """S3 requires `x-amz-content-sha256`; the Query services neither need it nor
    expect it."""
    signing = {probe.signing_service for probe in PROBES if probe.signs_payload_header}

    assert signing == {"s3"}


def test_every_probe_reads_and_none_writes() -> None:
    """`read_only` enforces this statically; the probe table asserts its own."""
    for probe in PROBES:
        action = probe.params.get("Action", "ListBuckets")
        assert action.startswith(("Get", "List", "Describe")), probe.service


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_repeated_runs_are_identical() -> None:
    first = run("aws_valid", aggressive=True)
    second = run("aws_valid", aggressive=True)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_the_signing_clock_never_reaches_the_output() -> None:
    """Two runs an hour apart sign differently and report identically.

    That is the whole justification for letting a plugin see a clock at all: the
    timestamp reaches a request header and stops there.
    """
    engine_kwargs = {
        "registry": ProviderRegistry("keyreach.providers"),
        "cassette": Cassette(FIXTURES / "aws_valid.json"),
        "mode": RecordMode.REPLAY,
    }
    early = Engine(**engine_kwargs, clock=lambda: FIXED_CLOCK)  # type: ignore[arg-type]
    later = Engine(
        **engine_kwargs,  # type: ignore[arg-type]
        clock=lambda: datetime(2031, 12, 25, 23, 59, 59, tzinfo=UTC),
    )

    assert (
        asyncio.run(early.run(KEY)).model_dump_json()
        == asyncio.run(later.run(KEY)).model_dump_json()
    )


def test_capabilities_are_stably_sorted() -> None:
    capabilities = run("aws_valid", aggressive=True).capabilities

    assert list(capabilities) == sorted(capabilities, key=lambda c: c.sort_key)
