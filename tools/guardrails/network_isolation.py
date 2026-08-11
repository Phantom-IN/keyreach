"""``network_isolation`` — provider plugins never touch the network directly.

Probes go through ``ProbeContext``, which is where rate limiting, cassette
record/replay, redaction and the read-only guard live (``CLAUDE.md``, hard rule
6). A plugin that opens its own socket bypasses all four at once: it would leak
an unmasked key into a log, make a write nobody reviewed, and produce a test
that needs a live credential.

**Deliberately an independent implementation, not a wrapper around ruff.** The
repo also bans these imports through ruff's ``flake8-tidy-imports`` rule, and in
R0.6 that rule was found to have been *silently inert since R0.2* — ``TID`` was
missing from the ``select`` list, so the configuration was parsed and ignored,
and three pull requests had claimed it was enforcing. Two mechanisms that share
an implementation share its failure. These two now agree only by testing the
same property, which is the point.

This check is also stricter in two ways ruff's is not: it walks the AST, so an
import inside a function body is caught, and it resolves
``importlib.import_module("httpx")``, which no import-based linter sees.
"""

from __future__ import annotations

import ast
from typing import Final

from tools.guardrails.ai_ban import _dynamic_import_roots
from tools.guardrails.base import Violation, read_text, repo_files

#: Anything that can open a socket. ``urllib``/``http`` are in the standard
#: library and therefore always available — a plugin author reaching for one
#: would not even have to add a dependency.
BANNED_IMPORTS: Final = frozenset(
    {
        "aiohttp",
        "http",
        "httpcore",
        "httplib2",
        "httpx",
        "requests",
        "socket",
        "ssl",
        "urllib",
        "urllib3",
        "websocket",
        "websockets",
    }
)

#: Directories held to the rule. The test fixture provider packages are included
#: on purpose: a fixture that may do what a real plugin may not is a fixture
#: that stops proving anything.
GUARDED_PREFIXES: Final = (
    "keyreach/providers/",
    "tests/cassette_providers/",
    "tests/dummy_providers/",
    "tests/broken_providers/",
    "tests/misbehaving_providers/",
)


def guarded_files() -> list[str]:
    return [
        path
        for path in repo_files(suffixes=(".py",))
        if path.startswith(GUARDED_PREFIXES)
    ]


def _imports(tree: ast.AST) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(
                (alias.name.split(".")[0], node.lineno) for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module.split(".")[0], node.lineno))
        elif isinstance(node, ast.Call):
            found.extend(_dynamic_import_roots(node))
    return found


def check() -> list[Violation]:
    violations: list[Violation] = []
    for path in guarded_files():
        source = read_text(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:  # pragma: no cover - repo must parse
            violations.append(Violation(path, exc.lineno or 1, f"syntax error: {exc}"))
            continue
        violations.extend(
            Violation(
                path,
                line,
                f"imports {root!r} directly. Provider plugins must probe "
                "through ProbeContext, which is the only place that rate "
                "limits, records, redacts and enforces read-only.",
            )
            for root, line in _imports(tree)
            if root in BANNED_IMPORTS
        )
    return violations


def main() -> int:
    from tools.guardrails.base import report  # noqa: PLC0415 - CLI entry only

    return report("network_isolation", check())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
