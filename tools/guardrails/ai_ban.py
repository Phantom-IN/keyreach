"""``ai_ban`` — keyreach must contain no AI/LLM anywhere (``plan.md`` §1).

Three independent checks, because there are three ways a model could get in:

1. **Declared dependencies.** Any AI/LLM SDK in ``pyproject.toml``, runtime or
   dev. ``tests/test_packaging.py`` already asserts this; it is repeated here so
   the guardrail is complete on its own and does not silently pass if that test
   is deleted.
2. **Imports.** Any Python file importing such an SDK — including inside a
   function, and including ``importlib.import_module("openai")``, which no
   import-based linter would see.
3. **Inference endpoints.** Any source file containing the path of a
   text-generation, embedding or image-generation endpoint.

**Why endpoints and not hostnames.** ``implementation_plan.md`` §11 originally
said "grep source for known model API hostnames too". That rule would make
roadmap items R1.1 and R1.2 impossible: enumerating what an exposed OpenAI or
Gemini key can reach *is the product*, and doing it means writing
``https://api.openai.com/v1/models`` into a provider plugin. The distinction
that actually matters is not which host is named but what is asked of it —
listing models is a read-only capability probe, calling the chat completions
endpoint is inference. So the ban is on the second, and ``test_guardrails.py``
pins both halves: the allowed URL must pass and the banned one must fail.

**Why the paths carry no API version.** They did until R1.2, and that made the
check blind to the convention every provider plugin in this repository follows.
A plugin declares a base constant — ``API = "https://api.openai.com/v1"`` — and
composes probes from it, so the string on the line that would call a model is
``f"{API}/chat/completions"``. Matching ``/v1/chat/completions`` never sees it.
This was found by planting exactly that line while building R1.2 and watching
``ai_ban`` report a clean repository, which is the third time a check in this
repo has been believed to work and did not (``CLAUDE.md`` hard rule 7). The
fragments are now version-independent and matched with a trailing boundary, so
``/complete`` does not also fire on a path ending ``/completed``.

Note the shape of the rule this protects. keyreach sends a user's key to that
key's *own* provider, read-only. It must never send a key, a response, or a
capability map to a model — that would be a credential leak, and it would
destroy the reproducibility every verdict depends on.
"""

from __future__ import annotations

import ast
import re
import tomllib
from typing import Final

from tools.guardrails.base import REPO_ROOT, Violation, read_text, repo_files

#: Import roots of AI/LLM SDKs and local-inference runtimes. Matched against the
#: first component of an imported module, so ``langchain.chains`` is caught by
#: ``langchain``.
BANNED_IMPORTS: Final = frozenset(
    {
        "ai21",
        "anthropic",
        "autogen",
        "cohere",
        "crewai",
        "dspy",
        "guidance",
        "haystack",
        "huggingface_hub",
        "instructor",
        "keras",
        "langchain",
        "langchain_community",
        "langchain_core",
        "litellm",
        "llama_cpp",
        "llama_index",
        "mistralai",
        "ollama",
        "openai",
        "replicate",
        "semantic_kernel",
        "sentence_transformers",
        "tensorflow",
        "together",
        "torch",
        "transformers",
        "vertexai",
    }
)

#: Distribution names, normalised. A dependency is banned when its normalised
#: name equals one of these or begins with one followed by a separator, which
#: catches the whole `langchain-*` and `llama-index-*` families.
BANNED_DISTRIBUTIONS: Final = frozenset(
    {
        "ai21",
        "anthropic",
        "cohere",
        "crewai",
        "dspy",
        "dspy-ai",
        "farm-haystack",
        "google-cloud-aiplatform",
        "google-genai",
        "google-generativeai",
        "guidance",
        "haystack-ai",
        "huggingface-hub",
        "instructor",
        "keras",
        "langchain",
        "litellm",
        "llama-cpp-python",
        "llama-index",
        "mistralai",
        "ollama",
        "openai",
        "pyautogen",
        "replicate",
        "semantic-kernel",
        "sentence-transformers",
        "tensorflow",
        "together",
        "torch",
        "transformers",
    }
)

#: Inference endpoints. Reaching one of these means *calling a model*, which is
#: what `plan.md` §1 forbids — as opposed to naming a provider's host, which a
#: capability probe legitimately does.
#:
#: Written **without** an API version prefix, because provider plugins compose
#: URLs from a base constant and a version-qualified fragment would never appear
#: on the line that matters. See the module docstring.
BANNED_ENDPOINTS: Final = (
    "/chat/completions",
    "/completions",
    "/responses",
    "/messages",
    "/complete",
    "/embeddings",
    "/images/generations",
    "/audio/speech",
    "/audio/transcriptions",
    ":generateContent",
    ":streamGenerateContent",
    ":embedContent",
)

#: The fragments above, each required to end at a path boundary. Without the
#: lookahead, `/complete` would fire on a perfectly innocent path ending
#: `/completed`, and a guardrail that cries wolf is one people start disabling.
#: A following `/` still matches, so a sub-resource of a banned endpoint — the
#: Anthropic message-batches path, for instance — is caught rather than excused.
_ENDPOINT_RE: Final = re.compile(
    "(?:" + "|".join(re.escape(path) for path in BANNED_ENDPOINTS) + r")(?![\w-])"
)

#: This module lists the banned strings, so it necessarily contains them, as
#: does the test that proves each one fires. Kept to exactly these two files:
#: a broader exemption would be a hole in the rule rather than a footnote to it.
_ENDPOINT_EXEMPT: Final = frozenset(
    {
        "tools/guardrails/ai_ban.py",
        "tests/test_guardrails.py",
    }
)

#: Source, not prose. Markdown is excluded because the planning documents
#: discuss inference endpoints by name — describing what keyreach must not do is
#: how the rule gets written down in the first place.
_SOURCE_SUFFIXES: Final = (".py", ".yml", ".yaml", ".toml", ".j2", ".json")

_SEPARATORS: Final = re.compile(r"[-_.]+")


def _normalise(name: str) -> str:
    return _SEPARATORS.sub("-", name.strip().lower())


def _requirement_name(requirement: str) -> str:
    """The distribution name from a PEP 508 requirement string."""
    return _normalise(re.split(r"[<>=!~\[;\s]", requirement, maxsplit=1)[0])


def _is_banned_distribution(requirement: str) -> bool:
    name = _requirement_name(requirement)
    return any(
        name == banned or name.startswith(f"{banned}-")
        for banned in BANNED_DISTRIBUTIONS
    )


def check_dependencies() -> list[Violation]:
    """No AI/LLM SDK in any declared dependency group."""
    pyproject = REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project", {})

    groups: list[tuple[str, list[str]]] = [
        ("dependencies", list(project.get("dependencies", [])))
    ]
    for extra, requirements in project.get("optional-dependencies", {}).items():
        groups.append((f"optional-dependencies.{extra}", list(requirements)))

    return [
        Violation(
            "pyproject.toml",
            1,
            f"{group} declares {requirement!r}, an AI/LLM dependency. "
            "keyreach must contain no AI/LLM anywhere (plan.md §1).",
        )
        for group, requirements in groups
        for requirement in requirements
        if _is_banned_distribution(requirement)
    ]


def _imported_roots(tree: ast.AST) -> list[tuple[str, int]]:
    """Every module root imported anywhere in a file, with its line number.

    Walks the whole tree rather than reading top-level statements, so an import
    hidden inside a function or a ``try`` block is caught too.
    """
    roots: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend(
                (alias.name.split(".")[0], node.lineno) for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.append((node.module.split(".")[0], node.lineno))
        elif isinstance(node, ast.Call):
            roots.extend(_dynamic_import_roots(node))
    return roots


def _dynamic_import_roots(node: ast.Call) -> list[tuple[str, int]]:
    """Roots imported through ``importlib.import_module`` or ``__import__``.

    A string passed to one of these is invisible to every import-based linter,
    which makes it the obvious way to smuggle an SDK past a checker that only
    reads ``import`` statements.
    """
    name = None
    if isinstance(node.func, ast.Name):
        name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        name = node.func.attr
    if name not in {"import_module", "__import__"}:
        return []
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return []
    value = node.args[0].value
    if not isinstance(value, str):
        return []
    return [(value.split(".")[0], node.lineno)]


def check_imports() -> list[Violation]:
    """No Python file imports an AI/LLM SDK, however indirectly."""
    violations: list[Violation] = []
    for path in repo_files(suffixes=(".py",)):
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
                f"imports {root!r}, an AI/LLM library. keyreach is rule-based "
                "and must contain no AI/LLM anywhere (plan.md §1).",
            )
            for root, line in _imported_roots(tree)
            if root in BANNED_IMPORTS
        )
    return violations


def check_endpoints() -> list[Violation]:
    """No source file reaches a model-inference endpoint.

    Naming a provider's host is fine and necessary; asking that host to run a
    model is not. See the module docstring.
    """
    violations: list[Violation] = []
    for path in repo_files(suffixes=_SOURCE_SUFFIXES):
        if path in _ENDPOINT_EXEMPT:
            continue
        source = read_text(path)
        if source is None:
            continue
        for number, line in enumerate(source.splitlines(), start=1):
            violations.extend(
                Violation(
                    path,
                    number,
                    f"references the model-inference endpoint {found.group()!r}. "
                    "keyreach probes providers read-only; it never calls a "
                    "model (plan.md §1).",
                )
                for found in _ENDPOINT_RE.finditer(line)
            )
    return violations


def check() -> list[Violation]:
    return check_dependencies() + check_imports() + check_endpoints()


def main() -> int:
    from tools.guardrails.base import report  # noqa: PLC0415 - CLI entry only

    return report("ai_ban", check())


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
