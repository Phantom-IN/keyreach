"""AWS access keys (``AKIA…`` / ``ASIA…``) — roadmap R1.3.

Blueprint credit: **enumerate-iam** (Andrés Riancho), **GPL-3.0** — license
verified from the upstream repository on 2026-08-12 and recorded in
``CREDITS.md`` and ``THIRD_PARTY_LICENSES.md``. It is copyleft, so
``CLAUDE.md`` rule 5 forbids copying any of it into this Apache-2.0 project:
unlike the MIT-licensed gmapsapiscanner behind ``google.py``, "nothing was
copied" here is a requirement rather than a preference. What keyreach took is the
*idea* that an AWS credential's permissions can be mapped by attempting
read-only calls. Every endpoint, API version, error code and success rule below
was written from AWS's own documentation, and each probe cites its source page.
enumerate-iam is noisy by design — thousands of attempts — which is exactly why
that style of enumeration is opt-in here (``plan.md`` §11).

**An AWS key is not one string.** Every other provider keyreach supports
authenticates with a single secret. AWS needs an access key id *and* a secret
access key, plus a session token for temporary (``ASIA``) credentials, and it
signs every request with SigV4 — there is no bearer-token path and no
unauthenticated identity endpoint. So this plugin accepts a **colon-joined**
credential::

    AKIA<16 chars>:<40-character secret access key>
    ASIA<16 chars>:<40-character secret access key>:<session token>

(Written with placeholders rather than AWS's documentation example, because a
complete key-shaped literal here would trip keyreach's own ``no_secrets``
guardrail — which is the correct behaviour, and worth demonstrating in the one
module most likely to tempt someone into writing one.)

A colon cannot appear in either part (both are base64 alphabets), so the split is
unambiguous. A **bare access key id** is still detected and reported — recognising
one in a leak is useful — but it cannot be probed, and ``validate`` says so
rather than reporting a live credential as dead.

**SigV4 is implemented here, from the specification.** Signing is pure given a
timestamp, so ``_signature`` is directly testable; the one impure input comes
from ``ctx.now()``, because AWS rejects a request whose timestamp is minutes
stale and there is no way to authenticate without one. That timestamp reaches a
request header and nothing else — never a cassette key, a capability, or a
report (see ``core/http.py``).

**Root credentials are the finding this plugin exists to get right.** AWS
documents that the root user has complete, unrestricted access to every service
and resource in the account and that its access cannot be constrained by IAM
policy. So an ARN ending ``:root`` establishes administrative access by AWS's own
access model rather than by inference, and keyreach records it as ``ADMIN``. Every
other probe here is a ``Get``/``List``/``Describe`` and is recorded as ``READ``:
being able to read IAM does not establish being able to write it.

**Two limits, stated up front because both understate rather than overstate.**

* **Regional services are probed in ``us-east-1`` only.** A key with EC2
  instances solely in ``eu-west-1`` produces no EC2 capability. Sweeping every
  region would multiply probe count by thirty against somebody's production
  account, which ``plan.md`` §11 rules out.
* **Services with JSON-RPC-only APIs are not probed at all** — DynamoDB, Secrets
  Manager, KMS, Lambda invoke and the rest accept only ``POST``, and keyreach
  default-denies ``POST`` (``implementation_plan.md`` §6). Reading a secret out
  of Secrets Manager would be the single most valuable AWS capability to report,
  and it is out of reach by a rule this project is not willing to bend. The
  Query-protocol services below are the ones a ``GET`` can reach.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field

from keyreach.core.models import AccessLevel, Capability, Identity, ValidationResult
from keyreach.core.provider import ProbeContext, Provider

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from keyreach.core.http import ProbeResponse

# --------------------------------------------------------------------------
# Credential format
# --------------------------------------------------------------------------
#
# Deliberately identical to the two `aws-*` rules in
# `keyreach/patterns/detection_rules.yml`. `tests/test_provider_aws.py` asserts
# the two agree, so the plugin and the rule set cannot drift apart and disagree
# about what an AWS credential looks like.
# Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html

#: Access key id: a documented four-character prefix plus 16 uppercase
#: alphanumerics. `AKIA` long-term, `ASIA` temporary, `ABIA`/`ACCA` service-specific.
_ID_PATTERN: Final = "(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"

#: Secret access key: 40 characters of base64. Never anchored on its own — a
#: 40-character base64 string is far too generic to claim as an AWS secret, and
#: it is only recognised here as the second field of a joined credential.
_SECRET_PATTERN: Final = "[A-Za-z0-9/+=]{40}"  # noqa: S105 - a shape, not a secret

#: Session token, present only for temporary credentials. Long and variable.
_TOKEN_PATTERN: Final = "[A-Za-z0-9/+=]{20,}"  # noqa: S105 - a shape, not a token

_BARE_ID_RE: Final = re.compile(f"^{_ID_PATTERN}$")
_PAIR_RE: Final = re.compile(
    f"^(?P<id>{_ID_PATTERN}):(?P<secret>{_SECRET_PATTERN})"
    f"(?::(?P<token>{_TOKEN_PATTERN}))?$"
)

#: Confidence for a structural match. The prefix and length are distinctive and
#: documented; not 1.0 because a string can look like a credential without being
#: one, and only a probe settles that.
_DETECT_CONFIDENCE: Final = 0.99


class Credential(BaseModel):
    """A parsed AWS credential. Immutable, and never rendered."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


def parse_credential(key: str) -> Credential | None:
    """Split a colon-joined credential, or ``None`` if it is not one.

    Returns ``None`` for a bare access key id too: an id alone cannot sign a
    request, so it is not a credential this plugin can use, however much it looks
    like one.
    """
    matched = _PAIR_RE.match(key)
    if matched is None:
        return None
    return Credential(
        access_key_id=matched.group("id"),
        secret_access_key=matched.group("secret"),
        session_token=matched.group("token"),
    )


# --------------------------------------------------------------------------
# SigV4
# --------------------------------------------------------------------------
#
# Implemented from AWS's published specification:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
#
# `_signature` is a pure function of its arguments including `now`, so it is
# tested against a fixed vector rather than against a live service. The vector in
# `tests/test_provider_aws.py` was produced by AWS's own reference implementation
# (botocore, Apache-2.0) in a throwaway environment and pinned; botocore is not a
# dependency of keyreach and no code was taken from it.

ALGORITHM: Final = "AWS4-HMAC-SHA256"

#: Hex SHA-256 of the empty string — the payload hash for every request here,
#: since all of them are GETs with no body.
EMPTY_PAYLOAD_SHA256: Final = hashlib.sha256(b"").hexdigest()

#: Characters AWS's `UriEncode` leaves alone. Everything else is percent-encoded
#: with **uppercase** hex, which is stricter than the usual URL quoting and is
#: why this is written out rather than delegated.
_UNRESERVED: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _uri_encode(value: str) -> str:
    """AWS's ``UriEncode``: percent-encode everything but the unreserved set."""
    return "".join(
        (
            character
            if character in _UNRESERVED
            else "".join(f"%{byte:02X}" for byte in character.encode("utf-8"))
        )
        for character in value
    )


#: Characters a probe parameter may contain, and the reason there is a rule.
#:
#: keyreach signs the parameter *dict*, while the HTTP layer encodes that same
#: dict into the URL — and the two encoders disagree about the space character.
#: ``httpx`` writes ``+``; AWS's ``UriEncode`` requires ``%20`` and says so
#: explicitly. A probe parameter containing a space would therefore be signed one
#: way and sent another, and AWS would reject the request with
#: ``SignatureDoesNotMatch`` — which this plugin reports as "the secret does not
#: match the ID", a confident and completely wrong verdict.
#:
#: Every parameter in the table below is alphanumeric today, so the two encoders
#: cannot diverge. ``tests/test_provider_aws.py`` enforces that rather than
#: trusting it: the day somebody adds a filter value with a space in it, the
#: test fails instead of the report lying.
SAFE_PARAM_CHARS: Final = re.compile(r"^[A-Za-z0-9._-]+$")


def _canonical_query(params: Mapping[str, str]) -> str:
    """Query parameters, encoded then sorted by name, as SigV4 requires."""
    return "&".join(
        f"{_uri_encode(name)}={_uri_encode(value)}"
        for name, value in sorted(params.items())
    )


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    """The four-step derived key. The secret itself never signs anything."""
    date_key = _hmac(f"AWS4{secret}".encode(), datestamp)
    region_key = _hmac(date_key, region)
    service_key = _hmac(region_key, service)
    return _hmac(service_key, "aws4_request")


def sign(  # noqa: PLR0913 - every argument is part of the signature's input;
    # bundling them into an object would hide what the signature covers
    credential: Credential,
    *,
    host: str,
    region: str,
    service: str,
    params: Mapping[str, str],
    now: datetime,
    payload_sha256: str = EMPTY_PAYLOAD_SHA256,
    sign_payload_header: bool = False,
) -> dict[str, str]:
    """Build the SigV4 headers for a ``GET`` against ``host``.

    ``sign_payload_header`` adds ``x-amz-content-sha256``, which S3 requires and
    the Query-protocol services neither need nor expect.

    The returned mapping is headers only — the signature never goes in the URL,
    so a cassette recorded for this request is keyed on a URL containing no
    credential material at all.
    """
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    headers = {"host": host, "x-amz-date": amz_date}
    if sign_payload_header:
        headers["x-amz-content-sha256"] = payload_sha256
    if credential.session_token:
        # AWS requires the session token inside the signature for these
        # services, not merely alongside it.
        headers["x-amz-security-token"] = credential.session_token

    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    canonical_request = "\n".join(
        [
            "GET",
            "/",
            _canonical_query(params),
            canonical_headers,
            signed_headers,
            payload_sha256,
        ]
    )

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(credential.secret_access_key, datestamp, region, service),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{ALGORITHM} Credential={credential.access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    # Host is set by the transport from the URL; sending it again would risk a
    # mismatch with what was signed.
    return {name: value for name, value in headers.items() if name != "host"} | {
        "authorization": authorization
    }


# --------------------------------------------------------------------------
# AWS's error vocabulary
# --------------------------------------------------------------------------
#
# Errors arrive as XML carrying a machine-readable <Code>. Branching on the code
# rather than the human-readable <Message> is what keeps this deterministic.
# Source: https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html

#: The access key id is not one AWS will accept — never issued, deleted, or
#: belonging to a user who has since been deactivated. Membership tests only.
_UNKNOWN_ID_CODES: Final[frozenset[str]] = frozenset(
    {"InvalidClientTokenId", "InvalidClientTokenId.Inactive"}
)

#: The id is real; the secret used to sign is not the one AWS holds. A precise
#: and useful distinction: it confirms the id exists.
_CODE_BAD_SIGNATURE: Final = "SignatureDoesNotMatch"

#: Temporary credentials that have aged out. The key was real; it is over.
_EXPIRED_CODES: Final[frozenset[str]] = frozenset(
    {"ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired"}
)


def _xml_value(body: str, tag: str) -> str | None:
    """The text of the first ``<tag>`` element, or ``None``.

    **keyreach does not run an XML parser over a provider's response.**
    ``xml.etree.ElementTree`` is documented as vulnerable to billion-laughs and
    quadratic-blowup inputs, and a tool built to be pointed at hostile
    infrastructure should not hand a stranger's document to it. Everything
    keyreach needs from an AWS response is one element's text or a count of a
    repeated tag, and both are reachable without parsing anything.
    """
    found = re.search(f"<{tag}>([^<]*)</{tag}>", body)
    return found.group(1) if found else None


def _count_tag(body: str, tag: str) -> int:
    """How many ``<tag>`` elements the body contains."""
    return len(re.findall(f"<{tag}[ >]", body))


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

#: IAM and STS are global services, signed against ``us-east-1`` whatever the
#: caller's region. Source: https://docs.aws.amazon.com/general/latest/gr/rande.html
GLOBAL_REGION: Final = "us-east-1"

#: The single region regional services are probed in. See the module docstring:
#: sweeping thirty regions is thirty times the authentication traffic against
#: somebody's production account.
PROBE_REGION: Final = "us-east-1"

#: ARN suffix that identifies the account root user. AWS documents root as
#: having complete access to every resource, not constrainable by IAM policy.
#: Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
ROOT_ARN_SUFFIX: Final = ":root"


class _Mode(StrEnum):
    """Whether a probe runs by default or only under an explicit opt-in."""

    DEFAULT = "default"
    """Minimal, quiet, and about the caller itself."""

    AGGRESSIVE = "aggressive"
    """Still read-only, but broad enough to look like reconnaissance."""


class _Probe(BaseModel):
    """One read-only capability probe, with the documentation it came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: _Mode
    service: str = Field(description="Display name, and the capability's service.")
    host: str
    region: str
    signing_service: str
    params: dict[str, str] = Field(default_factory=dict)
    item_tag: str | None = Field(
        default=None, description="Repeated XML tag counted for the evidence line."
    )
    noun: str = ""
    detail: str
    risk_weight: int = Field(ge=0, le=100)
    data_sensitive: bool = False
    poc: str = Field(description="Read-only AWS CLI equivalent, carrying no secret.")
    source: str = Field(description="Vendor documentation URL for this endpoint.")

    @property
    def url(self) -> str:
        return f"https://{self.host}/"

    @property
    def signs_payload_header(self) -> bool:
        """S3 requires ``x-amz-content-sha256``; the Query services do not."""
        return self.signing_service == "s3"


_IAM_VERSION: Final = "2010-05-08"
_IAM_DOCS: Final = (
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html"
)


def _iam(action: str) -> dict[str, str]:
    return {"Action": action, "Version": _IAM_VERSION}


#: Every probe, in a fixed order. The six defaults are all about the caller
#: itself — who am I, what are my own keys, what does this account look like —
#: which is the minimum that makes an exposed AWS credential reportable. The six
#: aggressive ones ask other services whether they will answer, which is the
#: enumerate-iam idea in miniature and is gated behind an explicit opt-in.
PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(
        mode=_Mode.DEFAULT,
        service="AWS STS Caller Identity",
        host="sts.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="sts",
        params={"Action": "GetCallerIdentity", "Version": "2011-06-15"},
        detail="Can authenticate to AWS and identify its own principal",
        risk_weight=30,
        poc="aws sts get-caller-identity",
        source="https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html",
    ),
    _Probe(
        mode=_Mode.DEFAULT,
        service="AWS IAM Caller User",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("GetUser"),
        detail="Can read its own IAM user record",
        risk_weight=55,
        poc="aws iam get-user",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html",
    ),
    _Probe(
        mode=_Mode.DEFAULT,
        service="AWS IAM Access Keys",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("ListAccessKeys"),
        item_tag="member",
        noun="access keys",
        detail="Can list its own IAM user's access keys and their status",
        risk_weight=70,
        poc="aws iam list-access-keys",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html",
    ),
    _Probe(
        mode=_Mode.DEFAULT,
        service="AWS IAM Account Aliases",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("ListAccountAliases"),
        item_tag="member",
        noun="account aliases",
        detail="Can read the account alias, which usually names the organisation",
        risk_weight=45,
        poc="aws iam list-account-aliases",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccountAliases.html",
    ),
    _Probe(
        mode=_Mode.DEFAULT,
        service="AWS IAM Account Summary",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("GetAccountSummary"),
        item_tag="entry",
        noun="summary entries",
        detail="Can read account-wide IAM posture: user, role, policy and MFA counts",
        risk_weight=75,
        poc="aws iam get-account-summary",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",
    ),
    _Probe(
        mode=_Mode.DEFAULT,
        service="Amazon S3 Buckets",
        host="s3.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="s3",
        item_tag="Bucket",
        noun="buckets",
        detail="Can list every S3 bucket in the account",
        risk_weight=85,
        # Bucket names alone map the account's storage, and are the starting
        # point for reading whatever is in them.
        data_sensitive=True,
        poc="aws s3api list-buckets",
        source="https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="AWS IAM Users",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("ListUsers"),
        item_tag="member",
        noun="IAM users",
        detail="Can list every IAM user in the account",
        risk_weight=85,
        # Names, paths and ARNs of real people, and a map of who to target next.
        data_sensitive=True,
        poc="aws iam list-users",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="AWS IAM Roles",
        host="iam.amazonaws.com",
        region=GLOBAL_REGION,
        signing_service="iam",
        params=_iam("ListRoles"),
        item_tag="member",
        noun="IAM roles",
        detail="Can list every IAM role in the account, with its trust policy",
        risk_weight=85,
        poc="aws iam list-roles",
        source="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRoles.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="Amazon EC2 Instances (us-east-1)",
        host="ec2.us-east-1.amazonaws.com",
        region=PROBE_REGION,
        signing_service="ec2",
        params={
            "Action": "DescribeInstances",
            "Version": "2016-11-15",
            "MaxResults": "5",
        },
        item_tag="instanceId",
        noun="instances",
        detail="Can describe EC2 instances in us-east-1",
        risk_weight=80,
        # Instance ids, private and public addresses, and tags that routinely
        # name the environment and its owner.
        data_sensitive=True,
        poc="aws ec2 describe-instances --region us-east-1 --max-results 5",
        source="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="Amazon RDS Instances (us-east-1)",
        host="rds.us-east-1.amazonaws.com",
        region=PROBE_REGION,
        signing_service="rds",
        params={
            "Action": "DescribeDBInstances",
            "Version": "2014-10-31",
            "MaxRecords": "20",
        },
        item_tag="DBInstance",
        noun="database instances",
        detail="Can describe RDS database instances in us-east-1",
        risk_weight=85,
        # Endpoints, engine versions and master usernames — the shape of the
        # account's databases, short of their contents.
        data_sensitive=True,
        poc="aws rds describe-db-instances --region us-east-1",
        source="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="Amazon SNS Topics (us-east-1)",
        host="sns.us-east-1.amazonaws.com",
        region=PROBE_REGION,
        signing_service="sns",
        params={"Action": "ListTopics", "Version": "2010-03-31"},
        item_tag="TopicArn",
        noun="topics",
        detail="Can list SNS topics in us-east-1",
        risk_weight=60,
        poc="aws sns list-topics --region us-east-1",
        source="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html",
    ),
    _Probe(
        mode=_Mode.AGGRESSIVE,
        service="Amazon SQS Queues (us-east-1)",
        host="sqs.us-east-1.amazonaws.com",
        region=PROBE_REGION,
        signing_service="sqs",
        params={"Action": "ListQueues", "Version": "2012-11-05"},
        item_tag="QueueUrl",
        noun="queues",
        detail="Can list SQS queues in us-east-1",
        risk_weight=60,
        poc="aws sqs list-queues --region us-east-1",
        source="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListQueues.html",
    ),
)

#: The probe whose endpoint doubles as the liveness check.
#:
#: R1.4 measured this and found the claim that used to sit here — "one request,
#: and not two" — was false: naming the same endpoint twice made the request
#: twice, once in ``validate`` and again in ``enumerate``. It is one request now
#: because ``ProbeClient`` answers a repeated idempotent GET from a per-run
#: cache, not because of anything this line does.
#:
#: AWS documents that ``GetCallerIdentity`` needs no permissions at all,
#: which makes it the one call that separates "not a credential" from
#: "no access".
VALIDATE_SERVICE: Final = "AWS STS Caller Identity"


def probes_for(*, aggressive: bool) -> tuple[_Probe, ...]:
    """The probes this run may make, in declaration order."""
    return tuple(
        probe
        for probe in PROBES
        if probe.mode is _Mode.DEFAULT
        or (aggressive and probe.mode is _Mode.AGGRESSIVE)
    )


def validation_probe() -> _Probe:
    return next(probe for probe in PROBES if probe.service == VALIDATE_SERVICE)


def _summary(probe: _Probe, response: ProbeResponse) -> str:
    """A benign one-line summary proving access, with no data in it.

    Counts, never contents. The evidence has to convince a triager that the
    credential reached real infrastructure without the report itself becoming an
    inventory of that infrastructure.
    """
    if probe.item_tag is None:
        return "request accepted"
    found = _count_tag(response.text, probe.item_tag)
    if found == 0:
        return f"{probe.noun}: none present"
    # Noun first, count second, so the line stays grammatical at every count.
    return f"{probe.noun}: {found} listed"


def _identity(body: str) -> Identity | None:
    """Account, principal ARN and user id, from a ``GetCallerIdentity`` body.

    An exposed credential that names its own account and principal tells the
    recipient exactly which account to audit and which identity to disable,
    which is most of what a disclosure report is for.
    """
    account = _xml_value(body, "Account")
    arn = _xml_value(body, "Arn")
    if not account and not arn:
        return None
    user_id = _xml_value(body, "UserId")
    return Identity(
        account=account,
        owner=arn,
        extra={"user_id": user_id} if user_id else {},
    )


def _is_root(body: str) -> bool:
    arn = _xml_value(body, "Arn")
    return bool(arn) and arn.endswith(ROOT_ARN_SUFFIX)  # type: ignore[union-attr]


def _root_capability(response: ProbeResponse) -> Capability:
    """The one capability here that is not a probe result but a documented rule.

    AWS states that the root user has complete access to every service and
    resource in the account, and that root access cannot be restricted by IAM
    policy. So an ARN ending ``:root`` establishes administrative access by the
    vendor's own access model — the same standard applied to Anthropic's
    unscoped admin keys in R1.2 — rather than by inferring a write from a read.
    """
    return Capability(
        service="AWS Account (root credentials)",
        access=AccessLevel.ADMIN,
        detail=(
            "Root credentials: unrestricted access to every service and "
            "resource in the account, which no IAM policy can constrain"
        ),
        evidence=response.evidence("caller ARN identifies the account root user"),
        risk_weight=100,
        data_sensitive=True,
        poc="aws sts get-caller-identity",
        resource_ref="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
    )


def _rejection(code: str) -> ValidationResult | None:
    """The outcomes that mean AWS did not accept the credential, or ``None``.

    Split out of :meth:`AWSProvider.validate` so neither half is a wall of
    branches. All three say "not usable", and each says something different
    about *why* — an ID AWS has never heard of, an ID it knows paired with the
    wrong secret, and a session that has simply aged out. Collapsing them into
    one message would throw away the most useful sentence in the report.
    """
    if code in _UNKNOWN_ID_CODES:
        return ValidationResult(
            valid=False, note=f"AWS does not accept this access key ID ({code})"
        )

    if code == _CODE_BAD_SIGNATURE:
        return ValidationResult(
            valid=False,
            note=(
                "AWS recognises this access key ID but the secret access key "
                "does not match it. The ID is real; the pair is not"
            ),
        )

    if code in _EXPIRED_CODES:
        return ValidationResult(
            valid=False,
            note=(
                "These are temporary credentials and their session has expired "
                f"({code}). They were real, and the role they came from is "
                "still worth checking"
            ),
        )

    return None


class AWSProvider(Provider):
    """AWS access keys — STS, IAM, S3, and an opt-in cross-service sweep."""

    name = "aws"
    category = "cloud"
    docs_url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    rotation_guide_url = (
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
        "id_credentials_access-keys.html#Using_RotateAccessKey"
    )
    credit = "enumerate-iam"

    def detect(self, key: str) -> float:
        """Pure structural match on a joined credential, or a bare access key id."""
        if _PAIR_RE.match(key) or _BARE_ID_RE.match(key):
            return _DETECT_CONFIDENCE
        return 0.0

    async def validate(self, key: str, ctx: ProbeContext) -> ValidationResult:
        """One signed read against ``sts:GetCallerIdentity``.

        AWS documents that this call requires no permissions whatsoever, so it
        cleanly separates "not a credential" from "a credential with no access" —
        which is exactly the distinction a report must not blur.
        """
        credential = _credential_for(key, ctx)
        if credential is None:
            return ValidationResult(
                valid=False,
                note=(
                    "An AWS access key ID cannot authenticate on its own — AWS "
                    "signs every request with the secret access key. Re-run with "
                    "the pair joined by a colon, "
                    "'AKIA…:<secret access key>', adding ':<session token>' for "
                    "a temporary ASIA credential"
                ),
            )

        probe = validation_probe()
        response = await _request(probe, credential, ctx)
        if response.ok:
            return ValidationResult(valid=True, identity=_identity(response.text))

        code = _xml_value(response.text, "Code") or ""

        rejected = _rejection(code)
        if rejected is not None:
            return rejected

        if code:
            return ValidationResult(
                valid=True,
                note=(
                    f"The credential is live; AWS refused this request ({code}). "
                    "GetCallerIdentity needs no permissions, so this is an "
                    "explicit deny rather than a missing one"
                ),
            )

        return ValidationResult(
            valid=False,
            note=(
                "AWS's response could not be interpreted, so this credential's "
                "validity was not established either way"
            ),
        )

    async def enumerate(self, key: str, ctx: ProbeContext) -> list[Capability]:
        """Probe concurrently; keep what answered. Aggressive probes only on request."""
        credential = _credential_for(key, ctx)
        if credential is None:  # pragma: no cover - enumerate runs only if valid
            return []

        selected = probes_for(aggressive=ctx.aggressive)
        responses = await ctx.gather(
            [_request(probe, credential, ctx) for probe in selected]
        )

        capabilities = [
            Capability(
                service=probe.service,
                # READ throughout. Reading IAM does not establish writing it, and
                # keyreach never confirms a write. The single exception is root,
                # added below from a documented AWS rule rather than a probe.
                access=AccessLevel.READ,
                detail=_detail(probe),
                evidence=response.evidence(_summary(probe, response)),
                risk_weight=probe.risk_weight,
                data_sensitive=probe.data_sensitive,
                poc=probe.poc,
                resource_ref=probe.source,
            )
            for probe, response in zip(selected, responses, strict=True)
            if response.ok
        ]

        identity = next(
            (
                response
                for probe, response in zip(selected, responses, strict=True)
                if probe.service == VALIDATE_SERVICE and response.ok
            ),
            None,
        )
        if identity is not None and _is_root(identity.text):
            capabilities.append(_root_capability(identity))

        return sorted(capabilities, key=lambda capability: capability.sort_key)


def _detail(probe: _Probe) -> str:
    """The capability detail, marked when it came from an opt-in probe.

    A reader of the report should be able to tell which findings cost a quiet
    handful of requests and which came from a sweep the operator chose to run
    (``plan.md`` §11).
    """
    if probe.mode is _Mode.AGGRESSIVE:
        return f"{probe.detail} (found by opt-in aggressive enumeration)"
    return probe.detail


def _credential_for(key: str, ctx: ProbeContext) -> Credential | None:
    """Parse the credential and register its parts for redaction.

    The redactor is seeded with the whole pasted string, which would not mask a
    response body echoing back only the access key ID. Registering the parts is
    what makes "masked by default" true for a composite credential.
    """
    credential = parse_credential(key)
    if credential is None:
        return None
    ctx.protect(credential.secret_access_key)
    ctx.protect(credential.access_key_id)
    if credential.session_token:
        ctx.protect(credential.session_token)
    return credential


async def _request(
    probe: _Probe, credential: Credential, ctx: ProbeContext
) -> ProbeResponse:
    """Sign and issue one probe. The only place the credential meets a request."""
    headers = sign(
        credential,
        host=probe.host,
        region=probe.region,
        service=probe.signing_service,
        params=probe.params,
        now=ctx.now(),
        sign_payload_header=probe.signs_payload_header,
    )
    return await ctx.get(probe.url, params=probe.params or None, headers=headers)
