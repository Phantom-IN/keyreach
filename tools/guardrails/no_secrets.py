"""``no_secrets`` — keyreach, pointed at its own repository.

A tool that identifies API keys must not commit a string that looks like one.
GitHub push protection enforces this on the remote, but only *after* the commit
exists, and its offered remedy is a click-through "allow this secret" link —
precisely the habit a security tool must not teach its contributors. Catching it
locally means the fix is "compose the sample from parts", made before the commit
exists.

This has blocked a push twice: R0.5 and R0.8. The R0.8 case is the reason the
enumerator in ``base.py`` includes untracked files.

Only rule-based matches count. The entropy stage deliberately reports anything
token-shaped, which in a repository full of hashes, cassettes and golden reports
would be noise; push protection likewise only recognises documented vendor
formats.
"""

from __future__ import annotations

import re
from typing import Final

from keyreach.core.detect import default_detector
from tools.guardrails.base import Violation, read_text, repo_files

#: Characters a credential may contain. Splitting on everything else recovers
#: candidate tokens from prose, code, JSON and YAML without parsing any of them.
_TOKEN_SPLIT: Final = re.compile(r"[^A-Za-z0-9_.\-+/=]+")

#: The rule file states patterns such as `^sk_(live|test)_[0-9A-Za-z]{24,}$`.
#: Those are regexes, not keys, and no anchored rule matches one — but the file
#: is exempt anyway so that adding a detection rule can never be blocked by the
#: rule it adds.
_EXEMPT: Final = frozenset({"keyreach/patterns/detection_rules.yml"})


def findings_for(path: str) -> list[Violation]:
    source = read_text(path)
    if source is None:
        return []

    violations: list[Violation] = []
    for number, line in enumerate(source.splitlines(), start=1):
        for token in _TOKEN_SPLIT.split(line):
            violations.extend(
                Violation(
                    path,
                    number,
                    f"contains a string matching detection rule "
                    f"{match.rule_id!r} ({match.provider}). Compose test "
                    'samples from parts — "sk_" + "live_" + body — so neither '
                    "keyreach nor GitHub push protection matches them.",
                )
                for match in default_detector.detect(token)
                if match.provider is not None
            )
    return violations


def check() -> list[Violation]:
    return [
        violation
        for path in repo_files()
        if path not in _EXEMPT
        for violation in findings_for(path)
    ]


def main() -> int:
    from tools.guardrails.base import report  # noqa: PLC0415 - CLI entry only

    return report("no_secrets", check())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
