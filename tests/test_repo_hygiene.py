"""keyreach, pointed at its own repository (roadmap R0.8, moved in R0.9).

The scan itself now lives in ``tools/guardrails/no_secrets.py`` so that CI, the
pre-commit hook and this test all run one implementation. What remains here is
the assertion — and, more importantly, the proof that the check can *fail*.

Why it exists: a tool that identifies API keys must not commit a string that
looks like one. GitHub push protection catches it on the remote, after the
commit exists, and offers a click-through "allow this secret" link — the exact
habit a security tool must not teach. This has blocked a push twice, in R0.5 and
R0.8.
"""

from __future__ import annotations

import pytest

from keyreach.core.detect import default_detector
from tools.guardrails.base import REPO_ROOT, repo_files
from tools.guardrails.no_secrets import check, findings_for


def test_no_file_contains_a_provider_shaped_secret() -> None:
    """A failure here is almost always a test sample written as a literal.

    Compose it from parts — ``"sk_" + "live_" + body`` — which keeps the test
    readable and stops both this check and GitHub's from matching it.
    """
    assert [violation.render() for violation in check()] == []


def test_an_untracked_file_is_scanned() -> None:
    """The R0.8 bug, pinned end to end.

    Plants a secret-shaped literal in a file that is new and unstaged — the
    state every file in a pull request passes through — and asserts both that
    the enumerator sees it and that the scan reports it. An earlier version of
    this scan used plain ``git ls-files``, which lists tracked files only, so it
    examined none of a pull request's new files while reporting success.
    """
    planted = REPO_ROOT / "tests" / "_planted_secret_probe.txt"
    planted.write_text("token = " + "sk_" + "live_" + "c" * 24 + "\n", encoding="utf-8")
    try:
        relative = "tests/_planted_secret_probe.txt"

        assert relative in repo_files()
        assert findings_for(relative)
    finally:
        planted.unlink()


@pytest.mark.parametrize(
    "sample",
    [
        pytest.param("sk_" + "live_" + "a" * 24, id="stripe"),
        pytest.param("AIza" + "b" * 35, id="google"),
        pytest.param("xox" + "b-" + "1" * 20, id="slack"),
    ],
)
def test_the_scan_would_catch_a_planted_secret(sample: str) -> None:
    """Positive controls. A checker that never fires guarantees nothing.

    These samples are themselves composed from parts, for the same reason the
    scan exists.
    """
    matches = default_detector.detect(sample)

    assert any(match.provider is not None for match in matches), sample
