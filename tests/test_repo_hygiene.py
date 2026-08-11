"""keyreach, pointed at its own repository.

A tool that identifies API keys should not commit a string that looks like one.
GitHub's push protection enforces this on the remote, but it enforces it *after*
a contributor has written the commit — and its only offered remedy is a
click-through "allow this secret" link, which is precisely the habit a security
tool must not teach. Catching it in the suite means the fix is "compose the
sample from parts", made before the commit exists.

This has bitten twice. In R0.5 a Stripe-shaped test sample blocked a push; in
R0.8 another one did, past an ad-hoc scan that enumerated files with
``git ls-files``. That lists **tracked** files only, so every newly added file —
exactly the ones most likely to hold a fresh literal — was silently skipped, and
the scan reported a clean result it had not earned. The file list below includes
untracked-but-not-ignored files for that reason, and the check lives here, run by
``pytest``, instead of in a snippet somebody has to remember to paste.

Only rule-based matches count. The entropy stage deliberately reports anything
token-shaped, which in a repository full of hashes and base64 fixtures would be
noise; push protection likewise only recognises documented vendor formats.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Final

import pytest

from keyreach.core.detect import default_detector

REPO_ROOT: Final = Path(__file__).resolve().parent.parent

#: Characters a credential may contain. Splitting on everything else recovers
#: candidate tokens from prose, code and JSON alike without needing to know the
#: file's syntax.
_TOKEN_SPLIT: Final = re.compile(r"[^A-Za-z0-9_.\-+/=]+")

#: The rule file states patterns like `^sk_(live|test)_[0-9A-Za-z]{24,}$`. Those
#: are regexes, not keys, and no anchored rule matches one — but the file is
#: exempt anyway so that adding a rule can never be blocked by the rule it adds.
_EXEMPT: Final = frozenset({"keyreach/patterns/detection_rules.yml"})


#: ``--cached`` alone is what made the R0.8 scan useless: it lists tracked files
#: only, so a pull request's new files were all invisible to it. ``--others
#: --exclude-standard`` adds them while still honouring ``.gitignore``, keeping
#: the virtualenv and build artifacts out.
_GIT_LS: Final = (
    "git",
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
)


def _repo_files() -> list[str]:
    """Every file a commit could carry: tracked plus untracked-not-ignored."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no input
        _GIT_LS,
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return sorted(line for line in completed.stdout.splitlines() if line)


def _findings(relative: str) -> list[str]:
    path = REPO_ROOT / relative
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Binary or unreadable: a key cannot be committed as text here, and
        # `detect-private-key` in pre-commit covers key files themselves.
        return []

    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for token in _TOKEN_SPLIT.split(line):
            for match in default_detector.detect(token):
                if match.provider is not None:
                    found.append(f"{relative}:{number} matches {match.rule_id}")
    return found


def test_an_untracked_file_is_scanned() -> None:
    """The R0.8 bug, pinned end to end.

    Plants a secret-shaped literal in a file that is new and unstaged — the
    state every file in a pull request passes through — and asserts both that
    the file list sees it and that the scan reports it. If someone simplifies
    ``_repo_files`` back to plain ``git ls-files``, this fails; the main scan
    would keep passing while covering none of a PR's new files.
    """
    planted = REPO_ROOT / "tests" / "_planted_secret_probe.txt"
    planted.write_text("token = " + "sk_" + "live_" + "c" * 24 + "\n", encoding="utf-8")
    try:
        relative = "tests/_planted_secret_probe.txt"

        assert relative in _repo_files()
        assert _findings(relative)
    finally:
        planted.unlink()


def test_no_file_contains_a_provider_shaped_secret() -> None:
    """keyreach's own detector over every file a commit could carry.

    A failure here is almost always a test sample written as a literal. Compose
    it from parts instead — ``"sk_" + "live_" + body`` — which keeps the test
    readable and stops both this check and GitHub's from matching it.
    """
    findings = [
        finding
        for relative in _repo_files()
        if relative not in _EXEMPT
        for finding in _findings(relative)
    ]

    assert findings == []


@pytest.mark.parametrize(
    "sample",
    [
        pytest.param("sk_" + "live_" + "a" * 24, id="stripe"),
        pytest.param("AIza" + "b" * 35, id="google"),
        pytest.param("xox" + "b-" + "1" * 20, id="slack"),
    ],
)
def test_the_scan_would_catch_a_planted_secret(sample: str) -> None:
    """Proves the scan can fail. A checker that never fires guarantees nothing.

    These samples are themselves composed from parts, for the same reason the
    scan exists — the assertion is that the detector names a provider for each.
    """
    matches = default_detector.detect(sample)

    assert any(match.provider is not None for match in matches), sample
