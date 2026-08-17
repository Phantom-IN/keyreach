"""Detection-rule source verification (``implementation_plan.md`` §13.3, item 1).

R2.3 withdrew the Mailgun rule and R2.4 withdrew npm's for the same reason:
both cited a vendor page that had stopped documenting any key format at all,
and nothing short of a human opening the URL noticed. This module is that
human, automated: for every active rule in ``detection_rules.yml``, fetch its
``source`` and check two things — the page still resolves, and it still
contains the format the rule claims.

**"Still contains the format" means a literal substring check, deliberately,
not a re-implementation of the rule's regex against page text.** A vendor
page is prose, not a test fixture; the only thing that can be checked
cheaply and without false alarms is whether the fixed part of the format —
the prefix every key of that shape starts with — still appears somewhere on
the page. :func:`leading_literals` reads that fixed part out of a rule's
pattern.

**It is a best-effort reading of the pattern's leading structure, not a
general regex-to-literal expander, and it says so by returning nothing
rather than guessing.** It handles exactly the shapes this repository's
rules actually use, found by walking ``detection_rules.yml`` while writing
this: a plain literal run, an optional group to skip over entirely
(``(?:...)?``, e.g. Supabase's project-ref prefix), and one mandatory
alternation group of plain literals with an optional literal suffix
(``sk_(live|test)_``, ``dckr_(?:pat|oat)_``) — composing the two turns
Stripe's, Paystack's, Razorpay's and Docker Hub's patterns into their real,
exact prefixes rather than the few characters before the first
metacharacter. A negative lookahead (``(?!admin-|ant-|proj-|svcacct-)``,
OpenAI's plain-key rule excluding its own siblings' prefixes) is recognised
and *not* treated as alternatives — those name formats a **different** rule
claims, and folding them in would have this rule fail the moment any of
them, rather than its own prefix, left the page. A leading character class
(GitHub's ``gh[pousr]_``, npm's hex digest, the generic JWT rule sourced to
an RFC rather than a vendor) yields no literal at all rather than a
wrong one — those rules get the resolves-at-all check only, which is
recorded in this module's own test suite rather than left silent.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Final

from keyreach.core.detect import DetectionRule, default_detector
from tools.drift_canary.base import Fetch, Finding

#: Below this, a literal is common enough (Twilio's "AC", GitHub's "gh") that
#: checking for it on a page proves nothing — it will always be there. Rules
#: that only clear this via a short leading run are not checked for content,
#: only for whether their source still resolves at all.
MIN_LITERAL_LENGTH: Final = 3

#: Regex metacharacters that end a literal run. ``(`` is handled separately —
#: it may introduce a group worth reading through, not just a stop sign.
_METACHARS: Final = frozenset(".^$*+?{}[]\\|()")

#: Any status at or above this means the page itself is gone, not merely
#: that its content changed.
_HTTP_ERROR_THRESHOLD: Final = 400


def _is_plain_literal(fragment: str) -> bool:
    return len(fragment) > 0 and not any(char in _METACHARS for char in fragment)


def _matching_paren(body: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(body)):
        if body[index] == "(":
            depth += 1
        elif body[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    msg = f"unbalanced parenthesis in {body!r}"
    raise ValueError(msg)


def _literal_run(body: str, start: int) -> tuple[str, int]:
    """The longest literal prefix of ``body[start:]``, honouring ``\\x`` escapes."""
    literal = ""
    index = start
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            literal += body[index + 1]
            index += 2
            continue
        if char in _METACHARS:
            break
        literal += char
        index += 1
    return literal, index


def leading_literals(pattern: str) -> tuple[str, ...]:
    """Fixed substrings guaranteed to appear in any key this pattern matches.

    Returns one or more candidate literals — more than one only when the
    pattern's prefix is a mandatory alternation (``sk_(live|test)_`` yields
    both ``sk_live_`` and ``sk_test_``) — or an empty tuple when no reliable
    literal could be read out. See the module docstring for exactly which
    shapes are handled and why the rest are left alone rather than guessed.
    """
    body = pattern[1:] if pattern.startswith("^") else pattern
    prefix = ""
    pos = 0
    try:
        while pos < len(body):
            if body[pos] == "(":
                close = _matching_paren(body, pos)
                inner = body[pos + 1 : close]
                after = body[close + 1 : close + 2]
                if after == "?":
                    # An optional group contributes nothing that MUST appear
                    # in every match — skip over it and its quantifier.
                    pos = close + 2
                    continue
                if inner.startswith(("?!", "?=")):
                    # A lookaround names what this rule's value is NOT (or a
                    # different assertion entirely) — never alternatives of
                    # its own prefix.
                    break
                candidate = inner[2:] if inner.startswith("?:") else inner
                alternatives = candidate.split("|")
                if not all(_is_plain_literal(alt) for alt in alternatives):
                    break
                suffix, _ = _literal_run(body, close + 1)
                return tuple(f"{prefix}{alt}{suffix}" for alt in alternatives)
            run, next_pos = _literal_run(body, pos)
            prefix += run
            if next_pos == pos:
                break
            pos = next_pos
    except ValueError:
        pass  # An unbalanced group in a pattern that still compiles: best effort.

    return (prefix,) if len(prefix) >= MIN_LITERAL_LENGTH else ()


def check(fetch: Fetch, rules: Iterable[DetectionRule] | None = None) -> list[Finding]:
    """Verify every active rule's ``source`` still resolves and still documents it.

    ``rules`` defaults to the real, packaged rule set; tests pass a small
    synthetic list instead so a check does not need a rules file on disk
    just to prove one branch of the source-verification logic.
    """
    rules = rules if rules is not None else default_detector.rules()

    rules_by_source: dict[str, list[str]] = defaultdict(list)
    patterns_by_id: dict[str, str] = {}
    for rule in rules:
        rules_by_source[rule.source].append(rule.id)
        patterns_by_id[rule.id] = rule.pattern

    findings: list[Finding] = []
    for source in sorted(rules_by_source):
        rule_ids = rules_by_source[source]
        result = fetch(source, None)

        if result.error is not None or result.status >= _HTTP_ERROR_THRESHOLD:
            status = result.error or f"HTTP {result.status}"
            findings.extend(
                Finding(
                    "source-unreachable",
                    rule_id,
                    f"{source} did not resolve ({status}); this rule cannot "
                    "be re-verified against it",
                    source,
                )
                for rule_id in rule_ids
            )
            continue

        for rule_id in rule_ids:
            literals = leading_literals(patterns_by_id[rule_id])
            if not literals or any(literal in result.text for literal in literals):
                continue
            findings.append(
                Finding(
                    "source-format-missing",
                    rule_id,
                    f"none of {literals!r} appear on {source} anymore — "
                    "re-verify the format this rule claims",
                    source,
                )
            )
    return findings
