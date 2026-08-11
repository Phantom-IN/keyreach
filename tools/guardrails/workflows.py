"""``workflows`` — the CI definition itself must be valid before it can gate anything.

This check exists because of a specific failure. R0.9 shipped a ``ci.yml``
containing ``join(needs.*.result, " ")``. GitHub's expression language has **no
double-quoted string literal**, so that is not a runtime error in one step — it
is a *workflow parse* error, and GitHub rejects the entire file. Every job
silently fails to exist, and the whole run reports one annotation with no
context. Nothing in the repository could have caught it, because the suite that
would have caught it runs *inside* the workflow that failed to parse.

That is a circular dependency, and the only way out of it is a check that runs
before push: this module is a pre-commit hook, like the other guardrails.

Scope is deliberately narrow. This is not a reimplementation of ``actionlint``,
which is far more thorough and would be the right tool if a Go binary were
acceptable in the toolchain. It checks the things that break a workflow *whole*:

* the YAML parses at all;
* every ``${{ }}`` expression uses GitHub's syntax, not Python's or Bash's;
* every ``needs:`` names a job that exists — a typo there yields a workflow that
  parses and then never runs the job you thought was blocking;
* every job declares ``runs-on``.
"""

from __future__ import annotations

import re
from typing import Any, Final

import yaml

from tools.guardrails.base import Violation, read_text, repo_files

WORKFLOW_PREFIX: Final = ".github/workflows/"

#: The body of a `${{ ... }}` expression.
_EXPRESSION: Final = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

#: GitHub expressions quote strings with `'`. A `"` inside an expression is a
#: parse error for the whole file, which is what makes it worth a rule of its
#: own rather than being left to review.
_DOUBLE_QUOTE: Final = re.compile(r'"')


def workflow_files() -> list[str]:
    return [
        path
        for path in repo_files(suffixes=(".yml", ".yaml"))
        if path.startswith(WORKFLOW_PREFIX)
    ]


def _check_expressions(path: str, source: str) -> list[Violation]:
    violations: list[Violation] = []
    for match in _EXPRESSION.finditer(source):
        body = match.group(1)
        if not _DOUBLE_QUOTE.search(body):
            continue
        line = source.count("\n", 0, match.start()) + 1
        violations.append(
            Violation(
                path,
                line,
                f"expression {{{{{body.strip()}}}}} uses a double-quoted "
                "string. GitHub expressions only support single quotes, and "
                "this rejects the entire workflow file, not just this step.",
            )
        )
    return violations


def _check_structure(path: str, source: str) -> list[Violation]:
    try:
        document: Any = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        return [Violation(path, 1, f"unparseable YAML: {exc}")]

    if not isinstance(document, dict):
        return [Violation(path, 1, "workflow is not a mapping")]

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [Violation(path, 1, "workflow declares no jobs")]

    violations: list[Violation] = []
    for name, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            violations.append(Violation(path, 1, f"job {name!r} is not a mapping"))
            continue
        if "runs-on" not in job and "uses" not in job:
            violations.append(
                Violation(path, 1, f"job {name!r} declares neither runs-on nor uses")
            )
        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        violations.extend(
            Violation(
                path,
                1,
                f"job {name!r} needs {required!r}, which is not a job in this "
                "workflow. The dependency is silently never satisfied.",
            )
            for required in needs
            if required not in jobs
        )
    return violations


def check() -> list[Violation]:
    violations: list[Violation] = []
    for path in workflow_files():
        source = read_text(path)
        if source is None:
            continue
        violations.extend(_check_expressions(path, source))
        violations.extend(_check_structure(path, source))
    return violations


def main() -> int:
    from tools.guardrails.base import report  # noqa: PLC0415 - CLI entry only

    return report("workflows", check())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
