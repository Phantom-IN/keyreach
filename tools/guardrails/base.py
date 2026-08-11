"""Shared plumbing for the guardrail checks.

Every check is a pure function from the repository's files to a list of
:class:`Violation`. That shape is deliberate and is the main lesson carried over
from R0.8, where an ad-hoc secret scan silently examined the wrong set of files
and reported a clean result it had not earned:

* **A check returns findings; it does not print and exit.** So a test can plant
  a violation and assert the check reports it. A guardrail nobody has seen fail
  guarantees nothing.
* **One file enumerator, used by all of them.** ``git ls-files --cached
  --others --exclude-standard`` — tracked *and* untracked-but-not-ignored. The
  R0.8 version used plain ``git ls-files``, which lists tracked files only, so
  every file a pull request adds was invisible to it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Final, NamedTuple

REPO_ROOT: Final = Path(__file__).resolve().parent.parent.parent

#: Tracked plus untracked-but-not-ignored. See the module docstring for why
#: ``--others`` is not optional here.
_GIT_LS: Final = (
    "git",
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
)


class Violation(NamedTuple):
    """One rule breach, located precisely enough to fix without searching."""

    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


def repo_files(*, suffixes: tuple[str, ...] | None = None) -> list[str]:
    """Every file a commit could carry, repo-relative and sorted.

    ``suffixes`` filters by extension (``(".py",)``). Sorted so a failure lists
    violations in the same order on every machine.
    """
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no input
        _GIT_LS,
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    paths = sorted(line for line in completed.stdout.splitlines() if line)
    if suffixes is None:
        return paths
    return [path for path in paths if path.endswith(suffixes)]


def read_text(path: str) -> str | None:
    """File contents, or ``None`` if it is binary or unreadable.

    A guardrail that crashes on an image is a guardrail people switch off.
    """
    try:
        return (REPO_ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def report(name: str, violations: list[Violation]) -> int:
    """Print a check's result and return its exit code.

    Uses GitHub's ``::error file=…,line=…`` annotation format so a failure is
    attached to the offending line in the pull-request diff rather than buried
    in a log nobody opens.
    """
    if not violations:
        print(f"{name}: ok")  # noqa: T201 - a CLI check, not user-facing output
        return 0

    for violation in violations:
        print(  # noqa: T201
            f"::error file={violation.path},line={violation.line}::"
            f"{violation.message}"
        )
    plural = "" if len(violations) == 1 else "s"
    print(f"\n{name}: {len(violations)} violation{plural}")  # noqa: T201
    return 1
