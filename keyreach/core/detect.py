"""Deterministic key detection: which provider does this key belong to?

Two stages, in fixed order (``implementation_plan.md`` §5):

1. **Structural match.** Anchored regexes over vendor prefixes and lengths,
   loaded from ``keyreach/patterns/detection_rules.yml``. High confidence.
2. **Entropy fallback.** For a token no rule claims, a deterministic
   Shannon-entropy test decides whether it even looks like a secret. Low
   confidence, and it never names a provider — it cannot.

Both stages are pure functions of the key. No network, no clock, no randomness,
and no model — if a rule cannot decide, keyreach says so rather than guessing
(``plan.md`` §1). Results are ordered by an explicit key, so the same input
always produces the same ranking.

Detection deliberately does **not** pick a winner. A key that matches two
providers returns two candidates; the ambiguity is resolved at the enumerate
stage, where a probe can actually settle it.

**On the entropy stage.** Shannon entropy alone is a poor secret detector — an
English sentence scores higher than a hex digest, because entropy measures
character variety and prose has plenty. It is only useful behind gates that
first establish "this is token-shaped at all": length, charset, and a few
deterministic context rules. The gates do most of the work; the threshold
handles the rest. The approach is learned from detect-secrets and re-implemented
here (see ``CREDITS.md``).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------
# Entropy stage tuning
#
# Every constant below is a deliberate, auditable choice rather than a tuned
# magic number, because each one decides whether an unrecognised string is
# reported as a possible secret.
# --------------------------------------------------------------------------

#: Minimum length before a token is considered at all. Below this, entropy is
#: too noisy to mean anything, and short high-entropy strings are overwhelmingly
#: identifiers rather than credentials.
MIN_TOKEN_LENGTH: Final = 20

#: Shannon entropy, in bits per character, at or above which a token-shaped
#: string is reported as a possible secret. A 40-character hex digest measures
#: about 3.7 and random base64 about 4.7, so this admits both while excluding
#: low-variety strings such as UUIDs (about 3.4).
ENTROPY_THRESHOLD: Final = 3.5

#: Confidence attached to every entropy hit. Flat on purpose: the entropy stage
#: establishes only "this looks like a secret", never which provider issued it,
#: so a varying score would imply a precision the signal does not have. The
#: measured entropy is reported in ``DetectionMatch.detail`` for auditability.
ENTROPY_CONFIDENCE: Final = 0.30

#: Characters a credential may plausibly consist of: base64, base64url, hex, and
#: the common separators. Anything else — whitespace, quotes, most punctuation —
#: means the input is prose or structured text, not a bare key.
_TOKEN_CHARSET: Final = re.compile(r"^[A-Za-z0-9+/=_.\-]+$")

_HAS_DIGIT: Final = re.compile(r"[0-9]")
_HAS_LETTER: Final = re.compile(r"[A-Za-z]")

#: Rules file shipped inside the package.
RULES_FILENAME: Final = "detection_rules.yml"


class DetectionError(Exception):
    """The detection rule set could not be loaded or is invalid."""


class DetectionRule(BaseModel):
    """One structural pattern that identifies a provider's key format."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, description="Stable, unique rule identifier.")
    provider: str = Field(min_length=1, description="Provider this key belongs to.")
    description: str = Field(min_length=1, description="Human-readable format name.")
    pattern: str = Field(min_length=1, description="Anchored regular expression.")
    confidence: float = Field(ge=0.0, le=1.0, description="Match confidence.")
    source: str = Field(
        min_length=1,
        description=(
            "URL of the vendor documentation this format came from. Required, "
            "because it is what makes the rule auditable and re-verifiable."
        ),
    )

    def matches(self, key: str) -> bool:
        return _compiled(self.pattern).search(key) is not None


class DetectionMatch(BaseModel):
    """A candidate provider for a key, with the evidence that produced it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str | None = Field(
        description=(
            "Provider name, or null when the entropy stage matched — that stage "
            "can establish that a string looks like a secret, never whose it is."
        )
    )
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str = Field(min_length=1, description="Rule that produced this match.")
    detail: str = Field(min_length=1, description="Why this matched, for the report.")

    @property
    def sort_key(self) -> tuple[float, str, str]:
        """Ordering key: most confident first, then by provider, then rule id.

        Confidence is negated so a plain ascending sort puts the strongest
        candidate first. Ties break on names rather than on discovery order,
        which is what keeps repeated runs identical
        (``implementation_plan.md`` §5).
        """
        return (-self.confidence, self.provider or "~", self.rule_id)


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    """Compile and cache a rule's regex.

    Cached because ``detect`` runs every rule against every key, and a batch run
    (``-f keys.txt``) would otherwise recompile the whole rule set per key.
    """
    try:
        return re.compile(pattern)
    except re.error as exc:  # pragma: no cover - guarded by load-time validation
        msg = f"invalid detection pattern {pattern!r}: {exc}"
        raise DetectionError(msg) from exc


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character.

    Returns ``0.0`` for the empty string and for any string of a single repeated
    character.

    Counts are sorted before summing. Floating-point addition is not
    associative, so summing in a different order can change the last bits of the
    result — and a value that lands either side of the threshold would flip a
    verdict. Sorting removes that possibility rather than relying on
    ``Counter`` preserving insertion order.
    """
    if not value:
        return 0.0

    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in sorted(Counter(value).values())
    )


def looks_like_secret(key: str) -> bool:
    """Whether ``key`` is token-shaped enough for entropy to mean anything.

    The gates matter more than the threshold. Without them, entropy alone
    reports ordinary English text — which scores *higher* than a hex digest —
    and every file path in a codebase.

    Rejects, in order: anything too short; anything outside the credential
    charset (catching prose, URLs and quoted strings); path- and URL-shaped
    strings; anything with no digit (which excludes long identifiers such as
    ``someVeryLongVariableNameHere``); and anything with no letter (numeric IDs).
    """
    if len(key) < MIN_TOKEN_LENGTH:
        return False
    if not _TOKEN_CHARSET.match(key):
        return False
    if key.startswith("/") or "://" in key:
        return False
    if not _HAS_DIGIT.search(key):
        return False
    return bool(_HAS_LETTER.search(key))


def _default_rules_path() -> Path:
    return Path(str(resources.files("keyreach.patterns") / RULES_FILENAME))


class Detector:
    """Loads detection rules and ranks providers for a key.

    Rules load once and are cached. Pass ``rules_path`` to load an alternative
    rule set — tests use it rather than mutating shared state.
    """

    def __init__(self, rules_path: Path | None = None) -> None:
        self._rules_path = rules_path
        self._rules: tuple[DetectionRule, ...] | None = None

    def __repr__(self) -> str:
        loaded = "unloaded" if self._rules is None else str(len(self._rules))
        return f"<Detector rules={loaded}>"

    @property
    def rules_path(self) -> Path:
        return (
            self._rules_path if self._rules_path is not None else _default_rules_path()
        )

    def rules(self) -> tuple[DetectionRule, ...]:
        """Every rule, sorted by id. Cached after the first call."""
        if self._rules is None:
            self._rules = self._load()
        return self._rules

    def reload(self) -> tuple[DetectionRule, ...]:
        self._rules = None
        return self.rules()

    def _load(self) -> tuple[DetectionRule, ...]:
        path = self.rules_path
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"could not read detection rules at {path}: {exc}"
            raise DetectionError(msg) from exc

        document: Any = yaml.safe_load(raw)
        if not isinstance(document, dict) or "rules" not in document:
            msg = f"{path} must be a mapping containing a 'rules' list"
            raise DetectionError(msg)

        entries = document["rules"]
        if not isinstance(entries, list) or not entries:
            msg = f"{path} contains no rules"
            raise DetectionError(msg)

        rules: list[DetectionRule] = []
        seen: set[str] = set()
        for entry in entries:
            rule = DetectionRule.model_validate(entry)

            if rule.id in seen:
                msg = (
                    f"duplicate detection rule id {rule.id!r} in {path}. "
                    "Rule ids break ranking ties, so they must be unique."
                )
                raise DetectionError(msg)
            seen.add(rule.id)

            # Compile now rather than on first use: a malformed regex is a
            # packaging error, and it should surface when the rules load rather
            # than midway through a scan.
            try:
                re.compile(rule.pattern)
            except re.error as exc:
                msg = f"rule {rule.id!r} has an invalid pattern: {exc}"
                raise DetectionError(msg) from exc

            rules.append(rule)

        # Sorted by id, not by file order, so a reordered YAML file cannot
        # change behaviour.
        return tuple(sorted(rules, key=lambda rule: rule.id))

    # ------------------------------------------------------------- detection

    def detect(self, key: str) -> tuple[DetectionMatch, ...]:
        """Rank the providers that could have issued ``key``.

        Returns every candidate, most confident first, rather than choosing
        between them — a key matching two providers is a real situation, and it
        is settled at the enumerate stage where a probe can decide.

        The entropy stage runs **only** when no structural rule matched. A
        recognised key gains nothing from being told it also has high entropy,
        and reporting both would clutter the ranking with a candidate that names
        no provider.
        """
        matches = [
            DetectionMatch(
                provider=rule.provider,
                confidence=rule.confidence,
                rule_id=rule.id,
                detail=f"matched {rule.description} pattern",
            )
            for rule in self.rules()
            if rule.matches(key)
        ]

        if not matches:
            fallback = self._entropy_match(key)
            if fallback is not None:
                matches.append(fallback)

        return tuple(sorted(matches, key=lambda match: match.sort_key))

    @staticmethod
    def _entropy_match(key: str) -> DetectionMatch | None:
        if not looks_like_secret(key):
            return None

        entropy = shannon_entropy(key)
        if entropy < ENTROPY_THRESHOLD:
            return None

        return DetectionMatch(
            provider=None,
            confidence=ENTROPY_CONFIDENCE,
            rule_id="entropy-fallback",
            detail=(
                f"no known key format matched; {len(key)} characters at "
                f"{entropy:.2f} bits/char is consistent with a secret"
            ),
        )

    def providers(self) -> tuple[str, ...]:
        """Distinct provider names covered by the rule set, sorted."""
        return tuple(sorted({rule.provider for rule in self.rules()}))


#: Shared detector over the packaged rules. Tests build their own rather than
#: mutating this, so there is no global state to reset.
default_detector: Final = Detector()
