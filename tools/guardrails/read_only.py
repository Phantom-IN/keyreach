"""``read_only`` — no probe may write, delete, or spend.

keyreach runs against keys somebody else owns, often in production. A probe that
modifies anything turns a disclosure into an incident, and no bug bounty
programme's authorisation covers it (``plan.md`` §11).

The HTTP layer default-denies non-idempotent methods at run time. This is the
static half: it catches the call before it exists, in review, where the cost of
being wrong is a comment rather than a write against a stranger's account.

Three rules, applied to provider plugins and to the declarative probe files:

* ``put``, ``patch`` and ``delete`` are never permitted. ``ProbeContext`` does
  not expose them, so reaching one means reaching past the context entirely.
* ``post`` requires an explicit ``read_only_post=True``. Some RPC-style APIs
  answer read queries only over POST; the keyword is verbose and greppable
  precisely so every use is argued in review rather than waved through.
* ``request`` is not for plugins. It is the escape hatch on the client, and a
  plugin calling it is choosing its own method — often from a variable, which no
  static check can evaluate.

Scoped to plugin code. ``core/http.py`` names every method because implementing
the guard requires naming what it denies, and its tests exercise the denials.
"""

from __future__ import annotations

import ast
from typing import Final

import yaml

from tools.guardrails.base import Violation, read_text, repo_files
from tools.guardrails.network_isolation import GUARDED_PREFIXES

#: Never permitted, under any annotation.
FORBIDDEN_METHODS: Final = frozenset({"put", "patch", "delete"})

#: Permitted only with `read_only_post=True`.
CONDITIONAL_METHODS: Final = frozenset({"post"})

#: The client's escape hatch; not part of the plugin surface.
RESERVED_METHODS: Final = frozenset({"request"})

#: HTTP verbs a declarative probe may specify (``implementation_plan.md`` §8).
IDEMPOTENT_VERBS: Final = frozenset({"GET", "HEAD", "OPTIONS"})

_PROBE_SUFFIXES: Final = (".yml", ".yaml")


def _call_name(node: ast.Call) -> str | None:
    """The attribute being called, e.g. ``ctx.post(...)`` → ``post``.

    Attribute calls only. A bare ``post(...)`` is a local function, not a probe,
    and flagging it would train people to rename things to appease the checker.
    """
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_annotated_read_only(node: ast.Call) -> bool:
    return any(
        keyword.arg == "read_only_post"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _check_python(path: str) -> list[Violation]:
    source = read_text(path)
    if source is None:
        return []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:  # pragma: no cover - repo must parse
        return [Violation(path, exc.lineno or 1, f"syntax error: {exc}")]

    violations: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in FORBIDDEN_METHODS:
            violations.append(
                Violation(
                    path,
                    node.lineno,
                    f"calls .{name}(). Probes are read-only: no writes, "
                    "deletes or spend, ever (plan.md §11).",
                )
            )
        elif name in CONDITIONAL_METHODS and not _is_annotated_read_only(node):
            violations.append(
                Violation(
                    path,
                    node.lineno,
                    f"calls .{name}() without read_only_post=True. POST is "
                    "default-denied; annotate it only for an API whose *read* "
                    "endpoint requires POST, and justify it in review.",
                )
            )
        elif name in RESERVED_METHODS:
            violations.append(
                Violation(
                    path,
                    node.lineno,
                    "calls .request(). Plugins use the named read-only helpers "
                    "on ProbeContext so the method is visible to this check.",
                )
            )
    return violations


def _walk_yaml(node: object) -> list[str]:
    """Every ``method:`` value anywhere in a parsed probe document."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "method" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_walk_yaml(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_yaml(item))
    return found


def _check_yaml(path: str) -> list[Violation]:
    source = read_text(path)
    if source is None:
        return []
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:  # pragma: no cover - repo YAML must parse
        return [Violation(path, 1, f"unparseable YAML: {exc}")]

    return [
        Violation(
            path,
            1,
            f"declares method {method!r}. Declarative probes are read-only; "
            f"permitted verbs are {sorted(IDEMPOTENT_VERBS)}.",
        )
        for method in _walk_yaml(document)
        if method.upper() not in IDEMPOTENT_VERBS
    ]


def guarded_files() -> list[str]:
    return [
        path
        for path in repo_files(suffixes=(".py", *_PROBE_SUFFIXES))
        if path.startswith(GUARDED_PREFIXES)
    ]


def check() -> list[Violation]:
    violations: list[Violation] = []
    for path in guarded_files():
        if path.endswith(_PROBE_SUFFIXES):
            violations.extend(_check_yaml(path))
        else:
            violations.extend(_check_python(path))
    return violations


def main() -> int:
    from tools.guardrails.base import report  # noqa: PLC0415 - CLI entry only

    return report("read_only", check())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
